//! Executing a plan (SPEC §5.7, §9.9) — owned by WP6.
//!
//! Order: type-change groups (their local deletes) → directories → transfers and index-only
//! puts, with periodic commits → deletes, unless a transfer failed → the re-observation pass
//! and the final commit. Everything that touches the index or `state.db` happens here; the
//! transfer layer only moves bytes.
//!
//! **Base rows and durability** (§5.7 step 3b). A base row says "this local entry is in sync
//! with that remote version" — or, once it is forgotten, "there was nothing here". Whatever
//! the row rests on must survive a power loss before the row is written, or the row outlives
//! it and the next run reads the difference as something the user did. So every writer of base
//! state on the download side waits for a barrier: downloads for the two barriers of their
//! batch (`Exec::downloaded`), and `RecordBase`, `SetLocalMeta`, `MkdirLocal` and the forgetting
//! after a local delete for [`settle`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;

use super::plan::{Action, Plan, SkipReason};
use super::{Direction, Mode, Summary, SyncRequest, blocking, canonical_root};
use crate::backend::Backend;
use crate::consts::{
    COMMIT_INTERVAL, COMMIT_MAX_OPS, DOWNLOAD_BATCH_FILES, LEDGER_DL_WARN, LEDGER_WARN,
    RACY_WINDOW, UPLOAD_BATCH_FILES,
};
use crate::error::{BackendError, QuotaKind, SyncError, TransferError};
use crate::index::Vault;
use crate::path;
use crate::state::LedgerDir;
use crate::transfer::{
    DownloadItem, Downloaded, LocalExpect, TransferCtx, UploadEvent, UploadSource,
    check_target_safe, download_group, drafts_for, durable, lstat_sig, materialize_empties,
    move_aside, upload_batch,
};
use crate::types::{
    BaseEffect, BaseEffectKind, BaseRow, BlobId, BlobRec, Entry, EntryKind, OpDraft, Stamp, StatSig,
};
use crate::ui::{Event, Ui};
use crate::util;

/// Index-only drafts are staged in slices of this size.
const STAGE_SLICE: usize = 1024;

/// `RecordBase` rows are made durable and written in slices of this size: a run that is
/// interrupted keeps the slices that are done.
const RECORD_SLICE: usize = 4096;

/// Why no further work is launched.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Stop {
    Quota(QuotaKind),
    RateLimited,
    Interrupted,
}

/// What the planner knows about one upload source.
struct UploadFact {
    rel: String,
    key: String,
    base: Option<Stamp>,
    conflict: bool,
}

/// The `Del`s of an upload-side type-change group, staged with the group's first `Put`.
struct UpGroup {
    dels: Vec<OpDraft>,
    staged: bool,
}

/// What a download is for, by local path.
struct DownloadFact {
    key: String,
    stamp: Stamp,
    hash: [u8; 32],
    size: u64,
    clen: u64,
}

type Fetched = Vec<(DownloadItem, Result<Downloaded, TransferError>)>;

/// Outcome of removing one local entry (§5.7 step 4).
enum Gone {
    Deleted,
    Absent,
    /// The entry is not what the plan saw.
    Changed,
    Unsafe,
    /// A directory that is not empty stays.
    Kept,
    Failed(String),
}

enum MkdirError {
    Unsafe,
    Collision,
    Io(std::io::Error),
}

struct Exec<'a, B: Backend> {
    vault: &'a Vault<B>,
    pair: i64,
    req: &'a SyncRequest,
    ui: &'a Ui,
    cancel: tokio_util::sync::CancellationToken,
    root: PathBuf,
    summary: Summary,
    stop: Option<Stop>,
    staged_ops: usize,
    last_commit: Instant,
    up_groups: Vec<UpGroup>,
    /// Remote path of a group's `then` action → index into `up_groups`.
    group_of: HashMap<String, usize>,
    /// Base rows of files this run wrote, for the re-observation pass.
    written: Vec<BaseRow>,
    last_local_write: Option<Instant>,
    /// Directories the plan wants to exist — created by this run, or holding content that
    /// faces a remote empty-directory marker (`Plan.keep_dirs`): never pruned.
    wanted_dirs: HashSet<String>,
}

/// §5.7. Ends at its final `commit()`; does NOT resolve conflicts, compact or clean up
/// (`Vault::finish_mutation` does, once, in the CLI layer).
pub async fn execute<B: Backend>(
    vault: &Vault<B>,
    pair: i64,
    req: &SyncRequest,
    plan: Plan,
    ui: &crate::ui::Ui,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<Summary, SyncError> {
    let started = Instant::now();
    if req.opts.dry_run {
        return Ok(dry_run(req, &plan, ui));
    }
    let (root, _) = canonical_root(&req.local_root)?;
    let mut exec = Exec {
        vault,
        pair,
        req,
        ui,
        cancel,
        root,
        summary: Summary::default(),
        stop: None,
        staged_ops: 0,
        last_commit: Instant::now(),
        up_groups: Vec::new(),
        group_of: HashMap::new(),
        written: Vec::new(),
        last_local_write: None,
        wanted_dirs: HashSet::new(),
    };
    exec.run(plan).await?;

    // Whatever stopped the run, what completed is published (§5.7, §6.5).
    let committed = exec.commit().await;
    match exec.stop {
        Some(Stop::Quota(kind)) => return Err(BackendError::QuotaExceeded(kind).into()),
        Some(Stop::RateLimited) => return Err(BackendError::RateLimited.into()),
        _ => committed?,
    }
    if exec.stop == Some(Stop::Interrupted) || exec.cancel.is_cancelled() {
        return Err(SyncError::Interrupted);
    }
    let mut summary = exec.summary;
    summary.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(summary)
}

/// `-n`: the plan as events and counts; nothing is touched.
fn dry_run(req: &SyncRequest, plan: &Plan, ui: &Ui) -> Summary {
    let mut s = Summary {
        dry_run: true,
        ..Summary::default()
    };
    let show = |action: &str, path: &str, size: Option<u64>, note: Option<String>| {
        ui.event(&Event::Plan {
            action: action.to_string(),
            path: path.to_string(),
            size,
            note,
        });
    };
    for action in &plan.actions {
        match action {
            Action::Upload {
                rel,
                size,
                conflict,
                ..
            } => {
                s.uploaded += 1;
                s.bytes_up += size;
                if *conflict {
                    s.conflicts += 1;
                    let note = "both changed; the remote version will be kept as a conflict copy";
                    show("keep", rel, Some(*size), Some(note.into()));
                } else {
                    show("upload", rel, Some(*size), None);
                }
            }
            Action::Reuse { rel, from, .. } => {
                s.reused += 1;
                let note = format!("(same content as {})", from.path);
                show("reuse", rel, None, Some(note));
            }
            Action::MkdirRemote { rel, .. } | Action::MkdirLocal { rel, .. } => {
                s.dirs_created += 1;
                show("mkdir", rel, None, None)
            }
            Action::SetRemoteMeta { rel, .. } | Action::SetLocalMeta { rel, .. } => {
                s.meta_updates += 1;
                show("meta", rel, None, None);
            }
            Action::DelRemote {
                key, remote_path, ..
            } => {
                s.deleted_remote += 1;
                let rel = path::strip_prefix(remote_path, &req.remote_prefix).unwrap_or(key);
                show("delete", rel, None, None);
            }
            Action::Download {
                rel,
                head,
                keep_local,
                ..
            } => {
                s.downloaded += 1;
                s.bytes_down += head.entry.size;
                if *keep_local {
                    s.conflicts += 1;
                    let note = "both changed; the local version will be moved aside";
                    show("keep", rel, Some(head.entry.size), Some(note.into()));
                } else {
                    show("download", rel, Some(head.entry.size), None);
                }
            }
            Action::DelLocal { rel, is_dir, .. } => {
                s.deleted_local += 1;
                show(if *is_dir { "rmdir" } else { "delete" }, rel, None, None);
            }
            Action::RecordBase { .. } | Action::ForgetBase { .. } => {}
            Action::Skip { rel, reason, .. } => {
                if !unreported(req.mode, reason) {
                    ui.event(&Event::Skip {
                        path: rel.clone(),
                        reason: reason.to_string(),
                    });
                    s.skipped.push((rel.clone(), reason.clone()));
                }
            }
        }
    }
    s
}

/// `copy` leaves entries that exist only at the destination alone by definition: they are no
/// shortfall of the run and do not make it "partial".
fn unreported(mode: Mode, reason: &SkipReason) -> bool {
    mode == Mode::Copy && matches!(reason, SkipReason::LocalOnly | SkipReason::RemoteOnly)
}

// ---------------------------------------------------------------------------------------------
// Local file-system steps (synchronous; called through `blocking`)
// ---------------------------------------------------------------------------------------------

/// What a base row for the entry at `root/rel` rests on (§5.7 step 3b): every directory from
/// the one that holds the entry up to the root — their entries are what makes it exist — and,
/// with `own`, the entry itself: a file's content and attributes.
fn chain(root: &Path, rel: &str, own: bool) -> Vec<PathBuf> {
    let target = root.join(rel);
    let above = target.ancestors().skip(1);
    let dirs = above.take_while(|dir| dir.starts_with(root));
    let own = own.then(|| target.clone());
    own.into_iter().chain(dirs.map(Path::to_path_buf)).collect()
}

/// The directory the entry at `root/rel` was removed from — or, where that went as well, the
/// nearest one above it that is still there: the removal is a change of that directory.
fn removed_from(root: &Path, rel: &str) -> PathBuf {
    let target = root.join(rel);
    let above = target.ancestors().skip(1);
    let mut dirs = above.take_while(|dir| dir.starts_with(root));
    let there = dirs.find(|dir| std::fs::symlink_metadata(dir).is_ok_and(|md| md.is_dir()));
    there.unwrap_or(root).to_path_buf()
}

/// The barrier in front of base rows that are not written for a download batch (§5.7 step
/// 3b). `needs[i]` names what entry `i` rests on — nothing, if there is no row to write for
/// it. Each path is synced once. The answer has, for every entry, why its row must **not** be
/// written: one of its paths could not be made durable, or the barrier as a whole failed.
fn settle(needs: &[Vec<PathBuf>]) -> Vec<Option<String>> {
    let mut at: HashMap<&Path, usize> = HashMap::new();
    let mut paths: Vec<&Path> = Vec::new();
    for path in needs.iter().flatten() {
        at.entry(path).or_insert_with(|| {
            paths.push(path);
            paths.len() - 1
        });
    }
    if paths.is_empty() {
        return needs.iter().map(|_| None).collect();
    }
    let failed: HashMap<usize, String> = match durable::make_durable(&paths) {
        Ok(failed) => {
            let named = failed.into_iter().map(|(i, e)| {
                let text = format!("{} could not be flushed to disk: {e}", paths[i].display());
                (i, text)
            });
            named.collect()
        }
        Err(e) => {
            let text = format!("could not be flushed to disk: {e}");
            let all = needs.iter().map(|n| (!n.is_empty()).then(|| text.clone()));
            return all.collect();
        }
    };
    let verdict = |needed: &Vec<PathBuf>| {
        let mut broken = needed.iter().filter_map(|p| failed.get(&at[p.as_path()]));
        broken.next().cloned()
    };
    needs.iter().map(verdict).collect()
}

/// §5.7 step 4: `lstat` must equal what the plan saw; then `unlink` (directories: `rmdir`).
fn remove_local(root: &Path, rel: &str, expect: &StatSig, is_dir: bool) -> Gone {
    if check_target_safe(root, rel).is_err() {
        return Gone::Unsafe;
    }
    let target = root.join(rel);
    let md = match std::fs::symlink_metadata(&target) {
        Ok(md) => md,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Gone::Absent;
        }
        Err(e) => return Gone::Failed(e.to_string()),
    };
    if is_dir {
        return match md.is_dir() {
            true if std::fs::remove_dir(&target).is_ok() => Gone::Deleted,
            true => Gone::Kept,
            false => Gone::Changed,
        };
    }
    if !md.is_file() || StatSig::from_metadata(&md) != *expect {
        return Gone::Changed;
    }
    match std::fs::remove_file(&target) {
        Ok(()) => Gone::Deleted,
        Err(e) => Gone::Failed(e.to_string()),
    }
}

/// Plain `rmdir` of every directory that the removal of `rels` may have emptied, deepest
/// first; a directory that is not empty simply stays.
fn prune_dirs(root: &Path, rels: &[String], keep: &HashSet<String>) {
    let mut dirs: Vec<&str> = rels.iter().flat_map(|rel| path::ancestors(rel)).collect();
    dirs.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    dirs.dedup();
    for dir in dirs {
        if !keep.contains(dir) {
            let _ = std::fs::remove_dir(root.join(dir));
        }
    }
}

/// Whether the parent directory lists an entry with exactly the target's name bytes; if not,
/// what `lstat` found is another spelling that the file system folds onto ours (§5.7 step 3).
fn listed_exactly(target: &Path) -> std::io::Result<bool> {
    let (Some(dir), Some(name)) = (target.parent(), target.file_name()) else {
        return Ok(true);
    };
    for entry in std::fs::read_dir(dir)? {
        if entry?.file_name() == name {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Creates `root/rel` level by level; every existing level must be a real directory.
fn create_dirs(root: &Path, rel: &str) -> Result<(), MkdirError> {
    std::fs::create_dir_all(root).map_err(MkdirError::Io)?;
    let mut dir = root.to_path_buf();
    for name in rel.split('/') {
        dir.push(name);
        match std::fs::symlink_metadata(&dir) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => return Err(MkdirError::Unsafe),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match std::fs::create_dir(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() => {}
                Err(e) => return Err(MkdirError::Io(e)),
            },
            Err(e) => return Err(MkdirError::Io(e)),
        }
    }
    Ok(())
}

/// `MkdirLocal`: removes exactly the entry the plan expects in the way (the expected file),
/// moves an unexpected file aside when the plan expects nothing, and creates the directory.
/// Returns the directory's signature and when it was taken.
fn make_local_dir(
    root: &Path,
    rel: &str,
    expect: LocalExpect,
) -> Result<(StatSig, i64), MkdirError> {
    check_target_safe(root, rel).map_err(|_| MkdirError::Unsafe)?;
    let target = root.join(rel);
    match std::fs::symlink_metadata(&target) {
        Ok(md) if md.is_dir() => {}
        Ok(md) if md.is_file() => {
            match expect {
                LocalExpect::File(sig) if StatSig::from_metadata(&md) == sig => {
                    std::fs::remove_file(&target).map_err(MkdirError::Io)?;
                }
                LocalExpect::Absent => {
                    if !listed_exactly(&target).map_err(MkdirError::Io)? {
                        return Err(MkdirError::Collision);
                    }
                    move_aside(&target, util::now_ms()).map_err(MkdirError::Io)?;
                }
                _ => return Err(MkdirError::Unsafe),
            }
            create_dirs(root, rel)?;
        }
        Ok(_) => return Err(MkdirError::Unsafe),
        Err(_) => create_dirs(root, rel)?,
    }
    let observed_ns = util::now_ns();
    match lstat_sig(&target).map_err(MkdirError::Io)? {
        Some(sig) => Ok((sig, observed_ns)),
        None => Err(MkdirError::Unsafe),
    }
}

/// `SetLocalMeta`: the file must still be what the plan saw (`None` otherwise); sets the
/// mtime and the exec bits, returns the new signature and when it was taken.
fn set_local_meta(
    root: &Path,
    rel: &str,
    expect: &StatSig,
    entry: &Entry,
) -> std::io::Result<Option<(StatSig, i64)>> {
    use std::os::unix::fs::PermissionsExt;
    if check_target_safe(root, rel).is_err() {
        return Ok(None);
    }
    let target = root.join(rel);
    match std::fs::symlink_metadata(&target) {
        Ok(md) if md.is_file() && StatSig::from_metadata(&md) == *expect => {}
        _ => return Ok(None),
    }
    let mode = expect.mode & 0o7777;
    // x follows r, as `chmod +x` does under the usual umask.
    let wanted = if entry.exec {
        mode | 0o100 | ((mode & 0o044) >> 2)
    } else {
        mode & !0o111
    };
    if wanted != mode {
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(wanted))?;
    }
    let mtime = filetime::FileTime::from_unix_time(
        entry.mtime_ns.div_euclid(1_000_000_000),
        entry.mtime_ns.rem_euclid(1_000_000_000) as u32,
    );
    filetime::set_file_mtime(&target, mtime)?;
    let observed_ns = util::now_ns();
    Ok(lstat_sig(&target)?.map(|sig| (sig, observed_ns)))
}

fn dir_row(key: String, rel: String, sig: StatSig, observed_ns: i64, stamp: Stamp) -> BaseRow {
    BaseRow {
        key,
        rel,
        kind: EntryKind::Dir,
        sig,
        hash: [0; 32],
        remote_stamp: stamp,
        observed_ns,
    }
}

/// Which kind of download work finished: a slice of zero-length files (there is one such
/// lane, its slices follow one another), or the files of a blob.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Lane {
    Empties,
    Blob,
}

async fn fetch_group<B: Backend>(
    cx: TransferCtx<B>,
    blob: BlobId,
    rec: Option<BlobRec>,
    items: Vec<DownloadItem>,
) -> (Lane, Fetched) {
    let fetched = match rec {
        Some(rec) => download_group(&cx, &rec, items).await,
        None => items
            .into_iter()
            .map(|item| (item, Err(TransferError::BlobMissing(blob.hex()))))
            .collect(),
    };
    (Lane::Blob, fetched)
}

async fn fetch_empties(
    items: Vec<DownloadItem>,
    cancel: tokio_util::sync::CancellationToken,
) -> (Lane, Fetched) {
    (Lane::Empties, materialize_empties(items, &cancel).await)
}

impl<B: Backend> Exec<'_, B> {
    fn halted(&self) -> bool {
        self.stop.is_some() || self.cancel.is_cancelled()
    }

    fn skip(&mut self, rel: String, reason: SkipReason) {
        if unreported(self.req.mode, &reason) {
            tracing::debug!("{rel}: {reason}");
            return;
        }
        self.ui.event(&Event::Skip {
            path: rel.clone(),
            reason: reason.to_string(),
        });
        self.summary.skipped.push((rel, reason));
    }

    fn fail(&mut self, rel: String, error: String) {
        self.ui.warn(&format!("{rel}: {error}"));
        self.summary.failed.push((rel, error));
    }

    fn done(&self, action: &str, rel: &str, bytes: u64) {
        self.ui.event(&Event::Done {
            action: action.to_string(),
            path: rel.to_string(),
            bytes,
        });
    }

    fn cx(&self, progress: crate::ui::Progress) -> TransferCtx<B> {
        TransferCtx {
            backend: self.vault.backend().clone(),
            keys: self.vault.keys().clone(),
            device: self.vault.device_id(),
            progress,
            cancel: self.cancel.clone(),
        }
    }

    async fn commit(&mut self) -> Result<(), SyncError> {
        self.staged_ops = 0;
        self.last_commit = Instant::now();
        self.vault.commit().await?;
        Ok(())
    }

    /// Stages durably and commits per §5.6 (every `COMMIT_INTERVAL` or `COMMIT_MAX_OPS`).
    async fn stage(&mut self, drafts: Vec<OpDraft>) -> Result<(), SyncError> {
        if drafts.is_empty() {
            return Ok(());
        }
        self.staged_ops += drafts.len();
        self.vault.stage(drafts)?;
        if self.staged_ops >= COMMIT_MAX_OPS || self.last_commit.elapsed() >= COMMIT_INTERVAL {
            self.commit().await?;
        }
        Ok(())
    }

    /// The `Del`s of the type-change group that `remote_path` starts, if it is the group's
    /// first successful `Put`: they go into the same `stage()` call and so into the same
    /// segment (§5.5.1).
    fn group_dels(&mut self, remote_path: &str, drafts: &mut Vec<OpDraft>) {
        let Some(&g) = self.group_of.get(remote_path) else {
            return;
        };
        let group = &mut self.up_groups[g];
        if !std::mem::replace(&mut group.staged, true) {
            self.summary.deleted_remote += group.dels.len() as u64;
            drafts.append(&mut group.dels);
        }
    }

    fn del_draft(&self, key: String, remote_path: String, base: Stamp) -> OpDraft {
        OpDraft::Del {
            path: remote_path,
            base,
            effect: Some(BaseEffect {
                pair: self.pair,
                rel: key.clone(),
                key,
                kind: BaseEffectKind::Forget,
            }),
        }
    }

    fn set_effect(
        &self,
        key: &str,
        rel: &str,
        sig: StatSig,
        hash: [u8; 32],
        observed_ns: i64,
        kind: EntryKind,
    ) -> Option<BaseEffect> {
        Some(BaseEffect {
            pair: self.pair,
            key: key.to_string(),
            rel: rel.to_string(),
            kind: BaseEffectKind::Set {
                sig,
                hash,
                observed_ns,
                kind,
            },
        })
    }

    /// Applies the outcomes of local removals — which come here behind their barrier
    /// (`remove_locals`) — and forgets the rows of what is gone; returns the paths that are
    /// gone and whether every entry is gone.
    fn removed(
        &mut self,
        outcomes: Vec<(String, String, bool, Gone)>,
    ) -> Result<(Vec<String>, bool), SyncError> {
        let (mut gone, mut forget, mut all) = (Vec::new(), Vec::new(), true);
        for (key, rel, is_dir, outcome) in outcomes {
            match outcome {
                Gone::Deleted => {
                    self.summary.deleted_local += 1;
                    self.done(if is_dir { "rmdir" } else { "delete" }, &rel, 0);
                    forget.push(key);
                    gone.push(rel);
                }
                Gone::Absent => {
                    forget.push(key);
                    gone.push(rel);
                }
                Gone::Changed => {
                    all = false;
                    self.skip(rel, SkipReason::LocalChanged);
                }
                Gone::Unsafe => {
                    all = false;
                    self.skip(rel, SkipReason::UnsafeTarget);
                }
                Gone::Kept => all = false,
                Gone::Failed(e) => {
                    all = false;
                    self.fail(rel, e);
                }
            }
        }
        self.vault.db().base_forget(self.pair, &forget)?;
        Ok((gone, all))
    }

    async fn remove_locals(
        &mut self,
        dels: Vec<(String, String, StatSig, bool)>,
    ) -> Result<(Vec<String>, bool), SyncError> {
        let root = self.root.clone();
        let outcomes = blocking(move || {
            let mut outcomes: Vec<_> = dels
                .into_iter()
                .map(|(key, rel, expect, is_dir)| {
                    let outcome = remove_local(&root, &rel, &expect, is_dir);
                    (key, rel, is_dir, outcome)
                })
                .collect();
            // The row is forgotten only once the entry is durably gone. A file that a power
            // loss brings back without its row would be a new file, and the next upload would
            // publish again what was deleted in the vault (row 4).
            let needs = outcomes.iter().map(|(_, rel, _, outcome)| match outcome {
                Gone::Deleted | Gone::Absent => vec![removed_from(&root, rel)],
                _ => Vec::new(),
            });
            let verdicts = settle(&needs.collect::<Vec<_>>());
            for ((_, _, _, outcome), verdict) in outcomes.iter_mut().zip(verdicts) {
                if let Some(error) = verdict {
                    *outcome = Gone::Failed(error);
                }
            }
            Ok(outcomes)
        })
        .await?;
        self.removed(outcomes)
    }

    async fn run(&mut self, plan: Plan) -> Result<(), SyncError> {
        let up = self.req.direction == Direction::Up;
        self.wanted_dirs.extend(plan.keep_dirs);
        let mut slots: Vec<Option<Action>> = plan.actions.into_iter().map(Some).collect();

        // --- step 0: type-change groups
        for group in plan.groups {
            if up {
                let dels: Vec<OpDraft> = group
                    .first
                    .iter()
                    .filter_map(|&i| match slots[i].take() {
                        Some(Action::DelRemote {
                            key,
                            remote_path,
                            base,
                        }) => Some(self.del_draft(key, remote_path, base)),
                        other => {
                            slots[i] = other;
                            None
                        }
                    })
                    .collect();
                for &i in &group.then {
                    if let Some(
                        Action::Upload { remote_path, .. }
                        | Action::Reuse { remote_path, .. }
                        | Action::MkdirRemote { remote_path, .. },
                    ) = &slots[i]
                    {
                        self.group_of
                            .insert(remote_path.clone(), self.up_groups.len());
                    }
                }
                self.up_groups.push(UpGroup {
                    dels,
                    staged: false,
                });
                continue;
            }
            let dels: Vec<(String, String, StatSig, bool)> = group
                .first
                .iter()
                .filter_map(|&i| match slots[i].take() {
                    Some(Action::DelLocal {
                        key,
                        rel,
                        expect_local,
                        is_dir,
                    }) => Some((key, rel, expect_local, is_dir)),
                    other => {
                        slots[i] = other;
                        None
                    }
                })
                .collect();
            let (gone, mut cleared) = self.remove_locals(dels).await?;
            // A directory that must become a file goes once it is empty; local-only files
            // keep it, and then nothing of the new type may arrive.
            let dirs: Vec<String> = group
                .then
                .iter()
                .filter_map(|&i| match &slots[i] {
                    Some(Action::Download {
                        rel,
                        expect_local: LocalExpect::EmptyDir,
                        ..
                    }) => Some(rel.clone()),
                    _ => None,
                })
                .collect();
            let root = self.root.clone();
            cleared &= blocking(move || {
                prune_dirs(&root, &gone, &HashSet::new());
                Ok(dirs.iter().all(|rel| {
                    let dir = root.join(rel);
                    std::fs::remove_dir(&dir).is_ok() || std::fs::symlink_metadata(&dir).is_err()
                }))
            })
            .await?;
            if !cleared {
                for &i in &group.then {
                    if let Some(Action::Download { rel, .. } | Action::MkdirLocal { rel, .. }) =
                        slots[i].take()
                    {
                        self.skip(rel, SkipReason::UnsafeTarget);
                    }
                }
            }
        }

        // --- sort the rest by phase
        let (mut mkdir_local, mut mkdir_remote) = (Vec::new(), Vec::new());
        let (mut uploads, mut index_puts, mut dels_remote) = (Vec::new(), Vec::new(), Vec::new());
        let (mut downloads, mut metas_local, mut dels_local) = (Vec::new(), Vec::new(), Vec::new());
        let (mut records, mut forgets) = (Vec::new(), Vec::new());
        for action in slots.into_iter().flatten() {
            match action {
                Action::Skip { rel, reason, .. } => self.skip(rel, reason),
                Action::RecordBase {
                    key,
                    rel,
                    sig,
                    observed_ns,
                    hash,
                    kind,
                    remote_stamp,
                } => records.push(BaseRow {
                    key,
                    rel,
                    kind,
                    sig,
                    hash,
                    remote_stamp,
                    observed_ns,
                }),
                Action::ForgetBase { key } => forgets.push(key),
                a @ Action::MkdirLocal { .. } => mkdir_local.push(a),
                a @ Action::MkdirRemote { .. } => mkdir_remote.push(a),
                a @ Action::Upload { .. } => uploads.push(a),
                a @ (Action::Reuse { .. } | Action::SetRemoteMeta { .. }) => index_puts.push(a),
                a @ Action::DelRemote { .. } => dels_remote.push(a),
                a @ Action::Download { .. } => downloads.push(a),
                a @ Action::SetLocalMeta { .. } => metas_local.push(a),
                a @ Action::DelLocal { .. } => dels_local.push(a),
            }
        }
        self.record_bases(records).await?;
        self.vault.db().base_forget(self.pair, &forgets)?;

        // --- step 1: directories
        self.mkdir_locals(mkdir_local).await?;
        self.mkdir_remotes(mkdir_remote).await?;

        // --- step 2: transfers and index-only puts
        self.index_puts(index_puts).await?;
        self.uploads(uploads).await?;
        self.set_local_metas(metas_local).await?;
        self.downloads(downloads).await?;

        // --- step 3: deletes, only if no transfer failed
        let deletes = dels_remote.len() + dels_local.len();
        if !self.summary.failed.is_empty() || self.halted() {
            if deletes > 0 {
                self.summary.deletes_suppressed = true;
                self.ui.warn(&format!(
                    "{deletes} deletes were not carried out because the run did not complete"
                ));
            }
        } else {
            self.delete_remotes(dels_remote).await?;
            self.delete_locals(dels_local).await?;
        }

        // --- step 4: re-observation
        self.reobserve().await
    }

    /// `RecordBase` (§5.5.1 rows 1, 3 and 6; §5.7 step 3b). A row that only refreshes what
    /// its predecessor says — same kind, content and remote version; a new signature or
    /// observation time — is written at once: it claims nothing new. Every other row — an
    /// entry that was found equal to the remote one — waits until the entry is durable: the
    /// file itself and the directories from the root down to it. That is the row a file gets
    /// that an earlier run put in place and could not report (a failed rename barrier, a
    /// killed process), and without the barrier it could outlive the rename.
    async fn record_bases(&mut self, records: Vec<BaseRow>) -> Result<(), SyncError> {
        if records.is_empty() {
            return Ok(());
        }
        let db = self.vault.db().clone();
        let known: HashMap<String, (EntryKind, [u8; 32], Stamp)> = db
            .base_all(self.pair)?
            .into_iter()
            .map(|row| (row.key, (row.kind, row.hash, row.remote_stamp)))
            .collect();
        let (refreshed, mut fresh): (Vec<BaseRow>, Vec<BaseRow>) = records
            .into_iter()
            .partition(|row| known.get(&row.key) == Some(&(row.kind, row.hash, row.remote_stamp)));
        drop(known);
        db.base_put(self.pair, &refreshed)?;
        while !fresh.is_empty() && !self.halted() {
            let rest = fresh.split_off(fresh.len().min(RECORD_SLICE));
            let (slice, root) = (std::mem::replace(&mut fresh, rest), self.root.clone());
            let (slice, verdicts) = blocking(move || {
                let needs = slice
                    .iter()
                    .map(|row| chain(&root, &row.rel, row.kind == EntryKind::File));
                let verdicts = settle(&needs.collect::<Vec<_>>());
                Ok((slice, verdicts))
            })
            .await?;
            let mut rows = Vec::with_capacity(slice.len());
            for (row, verdict) in slice.into_iter().zip(verdicts) {
                match verdict {
                    None => rows.push(row),
                    Some(error) => self.fail(row.rel, error),
                }
            }
            db.base_put(self.pair, &rows)?;
        }
        Ok(())
    }

    // --- step 1

    async fn mkdir_locals(&mut self, actions: Vec<Action>) -> Result<(), SyncError> {
        if actions.is_empty() {
            return Ok(());
        }
        let root = self.root.clone();
        let made = blocking(move || {
            let mut made: Vec<_> = actions
                .into_iter()
                .filter_map(|a| match a {
                    Action::MkdirLocal {
                        key,
                        rel,
                        head,
                        expect_local,
                    } => {
                        let result = make_local_dir(&root, &rel, expect_local);
                        Some((key, rel, head.stamp, result))
                    }
                    _ => None,
                })
                .collect();
            // A directory exists by its entry in the directory above, and that one by its
            // own, up to the root. A row for a directory that a power loss takes back would
            // read as "removed here", and `sync` would delete the marker in the vault (row 8)
            // — and no later download makes an empty directory durable in passing.
            let needs = made.iter().map(|(_, rel, _, result)| match result {
                Ok(_) => chain(&root, rel, false),
                Err(_) => Vec::new(),
            });
            let verdicts = settle(&needs.collect::<Vec<_>>());
            for ((_, _, _, result), verdict) in made.iter_mut().zip(verdicts) {
                if let Some(error) = verdict {
                    *result = Err(MkdirError::Io(std::io::Error::other(error)));
                }
            }
            Ok(made)
        })
        .await?;
        let mut rows = Vec::new();
        for (key, rel, stamp, result) in made {
            self.wanted_dirs.insert(rel.clone());
            match result {
                Ok((sig, observed_ns)) => {
                    self.summary.dirs_created += 1;
                    self.done("mkdir", &rel, 0);
                    rows.push(dir_row(key, rel, sig, observed_ns, stamp));
                }
                Err(MkdirError::Unsafe) => self.skip(rel, SkipReason::UnsafeTarget),
                Err(MkdirError::Collision) => self.skip(rel, SkipReason::KeyCollision),
                Err(MkdirError::Io(e)) => self.fail(rel, e.to_string()),
            }
        }
        self.vault.db().base_put(self.pair, &rows)?;
        Ok(())
    }

    async fn mkdir_remotes(&mut self, actions: Vec<Action>) -> Result<(), SyncError> {
        let mut drafts = Vec::new();
        for action in actions {
            let Action::MkdirRemote {
                rel,
                key,
                remote_path,
                base,
            } = action
            else {
                continue;
            };
            if let Err(e) = path::validate(&remote_path) {
                self.fail(rel, e.to_string());
                continue;
            }
            let observed_ns = util::now_ns();
            let sig = match std::fs::symlink_metadata(self.root.join(&rel)) {
                Ok(md) if md.is_dir() => StatSig::from_metadata(&md),
                _ => {
                    self.skip(rel, SkipReason::ChangedDuringUpload);
                    continue;
                }
            };
            self.group_dels(&remote_path, &mut drafts);
            drafts.push(OpDraft::Put {
                path: remote_path,
                entry: Entry::dir(),
                base,
                origin: None,
                effect: self.set_effect(&key, &rel, sig, [0; 32], observed_ns, EntryKind::Dir),
            });
            self.summary.dirs_created += 1;
            self.done("mkdir", &rel, 0);
            if drafts.len() >= STAGE_SLICE {
                self.stage(std::mem::take(&mut drafts)).await?;
            }
        }
        self.stage(drafts).await
    }

    // --- step 2, upload side

    /// `Reuse` and `SetRemoteMeta`: index-only, zero bytes sent.
    async fn index_puts(&mut self, actions: Vec<Action>) -> Result<(), SyncError> {
        let mut drafts = Vec::new();
        for action in actions {
            match action {
                Action::Reuse {
                    rel,
                    key,
                    remote_path,
                    base,
                    from,
                    sig,
                    observed_ns,
                    hash,
                } => {
                    if let Err(e) = path::validate(&remote_path) {
                        self.fail(rel, e.to_string());
                        continue;
                    }
                    self.group_dels(&remote_path, &mut drafts);
                    drafts.push(OpDraft::Put {
                        path: remote_path,
                        entry: Entry {
                            kind: EntryKind::File,
                            size: from.entry.size,
                            mtime_ns: sig.mtime_ns,
                            exec: sig.is_exec(),
                            hash,
                            loc: from.entry.loc,
                        },
                        base,
                        origin: None,
                        effect: self.set_effect(
                            &key,
                            &rel,
                            sig,
                            hash,
                            observed_ns,
                            EntryKind::File,
                        ),
                    });
                    self.summary.reused += 1;
                    self.done("reuse", &rel, 0);
                }
                Action::SetRemoteMeta {
                    rel,
                    key,
                    remote_path,
                    base,
                    entry,
                    sig,
                    observed_ns,
                } => {
                    let effect =
                        self.set_effect(&key, &rel, sig, entry.hash, observed_ns, entry.kind);
                    drafts.push(OpDraft::Put {
                        path: remote_path,
                        entry,
                        base: Some(base),
                        origin: None,
                        effect,
                    });
                    self.summary.meta_updates += 1;
                    self.done("meta", &rel, 0);
                }
                _ => {}
            }
            if drafts.len() >= STAGE_SLICE {
                self.stage(std::mem::take(&mut drafts)).await?;
            }
        }
        self.stage(drafts).await
    }

    fn upload_failed(&mut self, rel: String, error: TransferError) -> Result<(), SyncError> {
        match error {
            // The file keeps changing: skipped this run, not a failure (§5.7).
            TransferError::SourceChanged(_) => self.skip(rel, SkipReason::ChangedDuringUpload),
            TransferError::Cancelled => {
                self.stop.get_or_insert(Stop::Interrupted);
            }
            TransferError::Backend(BackendError::QuotaExceeded(kind)) => {
                self.stop.get_or_insert(Stop::Quota(kind));
                self.summary.failed.push((rel, error.to_string()));
            }
            TransferError::Backend(BackendError::RateLimited) => {
                if self.stop.is_none() {
                    // The 750 GB/day cap has no error of its own; the ledger tells (§6.5).
                    let sent = self
                        .vault
                        .db()
                        .ledger_sum_24h(util::now_ms(), LedgerDir::Up)?;
                    self.stop = Some(if sent >= LEDGER_WARN {
                        Stop::Quota(QuotaKind::DailyUpload)
                    } else {
                        Stop::RateLimited
                    });
                }
                self.summary.failed.push((rel, error.to_string()));
            }
            e => self.fail(rel, e.to_string()),
        }
        Ok(())
    }

    async fn uploads(&mut self, actions: Vec<Action>) -> Result<(), SyncError> {
        let mut facts: HashMap<String, UploadFact> = HashMap::new();
        let mut sources: Vec<(UploadSource, u64)> = Vec::new();
        for action in actions {
            let Action::Upload {
                rel,
                key,
                remote_path,
                base,
                size,
                conflict,
            } = action
            else {
                continue;
            };
            if let Err(e) = path::validate(&remote_path) {
                self.fail(rel, e.to_string());
                continue;
            }
            let source = UploadSource {
                abs: self.root.join(&rel),
                remote_path: remote_path.clone(),
            };
            sources.push((source, size));
            let fact = UploadFact {
                rel,
                key,
                base,
                conflict,
            };
            facts.insert(remote_path, fact);
        }
        if sources.is_empty() || self.halted() {
            return Ok(());
        }
        sources.sort_by(|a, b| a.0.remote_path.cmp(&b.0.remote_path));
        let db = self.vault.db().clone();
        if db.ledger_sum_24h(util::now_ms(), LedgerDir::Up)? >= LEDGER_WARN {
            self.ui
                .warn("close to Google's 750 GB/day upload limit; uploads may stop until tomorrow");
        }
        let total: u64 = sources.iter().map(|(_, size)| size).sum();
        let progress = self
            .ui
            .transfer_progress("Uploading", total, sources.len() as u64);
        let transfers = self.req.opts.transfers.max(1);
        let pair = self.pair;
        let mut sources = sources.into_iter().map(|(source, _)| source);
        loop {
            let slice: Vec<UploadSource> = sources.by_ref().take(UPLOAD_BATCH_FILES).collect();
            if slice.is_empty() || self.halted() {
                break;
            }
            let folder = self.vault.data_folder().await?;
            let mut events = upload_batch(self.cx(progress.clone()), folder, slice, transfers);
            while let Some(event) = events.recv().await {
                let up = match event {
                    UploadEvent::Blob(up) => up,
                    UploadEvent::Failed(source, error) => {
                        let rel = match facts.get(&source.remote_path) {
                            Some(fact) => fact.rel.clone(),
                            None => source.remote_path,
                        };
                        self.upload_failed(rel, error)?;
                        continue;
                    }
                };
                if let Some(blob) = &up.blob {
                    self.vault.note_blob_created()?;
                    db.ledger_add(util::now_ms(), LedgerDir::Up, blob.clen)?;
                }
                let mut drafts = drafts_for(&up, &|remote_path| match facts.get(remote_path) {
                    Some(f) => (f.base, Some((pair, f.key.clone(), f.rel.clone()))),
                    None => (None, None),
                });
                for file in &up.files {
                    self.group_dels(&file.remote_path, &mut drafts);
                }
                self.stage(drafts).await?;
                for file in &up.files {
                    self.summary.uploaded += 1;
                    self.summary.bytes_up += file.entry.size;
                    if let Some(fact) = facts.get(&file.remote_path) {
                        self.summary.conflicts += u64::from(fact.conflict);
                        self.done("upload", &fact.rel, file.entry.size);
                    }
                }
            }
        }
        progress.finish();
        Ok(())
    }

    // --- step 2, download side

    async fn set_local_metas(&mut self, actions: Vec<Action>) -> Result<(), SyncError> {
        if actions.is_empty() {
            return Ok(());
        }
        let root = self.root.clone();
        let set = blocking(move || {
            let mut set: Vec<_> = actions
                .into_iter()
                .filter_map(|a| match a {
                    Action::SetLocalMeta {
                        key,
                        rel,
                        head,
                        expect_local,
                    } => {
                        let result = set_local_meta(&root, &rel, &expect_local, &head.entry);
                        Some((key, rel, head, result))
                    }
                    _ => None,
                })
                .collect();
            // The new mtime and mode are attributes of the file: they are durable before a
            // row says they are there. A row over an mtime that fell back would make the next
            // upload push the old one as a change made here (§5.5.1 row 1).
            let needs = set.iter().map(|(_, rel, _, result)| match result {
                Ok(Some(_)) => vec![root.join(rel)],
                _ => Vec::new(),
            });
            let verdicts = settle(&needs.collect::<Vec<_>>());
            for ((_, _, _, result), verdict) in set.iter_mut().zip(verdicts) {
                if let Some(error) = verdict {
                    *result = Err(std::io::Error::other(error));
                }
            }
            Ok(set)
        })
        .await?;
        let mut rows = Vec::new();
        for (key, rel, head, result) in set {
            match result {
                Ok(Some((sig, observed_ns))) => {
                    self.summary.meta_updates += 1;
                    self.done("meta", &rel, 0);
                    rows.push(BaseRow {
                        key,
                        rel,
                        kind: EntryKind::File,
                        sig,
                        hash: head.entry.hash,
                        remote_stamp: head.stamp,
                        observed_ns,
                    });
                }
                Ok(None) => self.skip(rel, SkipReason::LocalChanged),
                Err(e) => self.fail(rel, e.to_string()),
            }
        }
        if !rows.is_empty() {
            self.vault.db().base_put(self.pair, &rows)?;
            self.last_local_write = Some(Instant::now());
            self.written.extend(rows);
        }
        Ok(())
    }

    /// Applies one group's results: base rows (§5.7 step 3), counters, skips and failures.
    ///
    /// The base rows of downloads are written here and nowhere earlier, and an `Ok` reaches
    /// this function only out of `download_group` / `materialize_empties`, which release it
    /// behind the two barriers of its batch: the file's content was durable before it was
    /// renamed, and the rename is durable now. Such a row can therefore never outlive the file
    /// it describes. (The other writers of base rows on this side wait for `settle`.)
    fn downloaded(
        &mut self,
        fetched: Fetched,
        facts: &HashMap<String, DownloadFact>,
    ) -> Result<(), SyncError> {
        let mut rows = Vec::new();
        let mut cipher_bytes = 0;
        for (item, result) in fetched {
            let rel = item.rel;
            let Some(fact) = facts.get(&rel) else {
                continue;
            };
            match result {
                Ok(done) => {
                    self.summary.downloaded += 1;
                    self.summary.bytes_down += fact.size;
                    cipher_bytes += fact.clen;
                    if let Some(aside) = &done.moved_aside {
                        self.summary.conflicts += 1;
                        self.ui.warn(&format!(
                            "{rel}: the local version was kept as {}",
                            aside.file_name().unwrap_or_default().to_string_lossy()
                        ));
                    }
                    self.done("download", &rel, fact.size);
                    rows.push(BaseRow {
                        key: fact.key.clone(),
                        rel,
                        kind: EntryKind::File,
                        sig: done.sig,
                        hash: fact.hash,
                        remote_stamp: fact.stamp,
                        observed_ns: done.observed_ns,
                    });
                }
                Err(TransferError::UnsafeTarget(_)) => self.skip(rel, SkipReason::UnsafeTarget),
                Err(TransferError::TargetCollision(_)) => self.skip(rel, SkipReason::KeyCollision),
                Err(TransferError::Cancelled) => {
                    self.stop.get_or_insert(Stop::Interrupted);
                }
                Err(TransferError::Backend(BackendError::QuotaExceeded(kind))) => {
                    self.stop.get_or_insert(Stop::Quota(kind));
                    let error = BackendError::QuotaExceeded(kind).to_string();
                    self.summary.failed.push((rel, error));
                }
                // The backend gave up after its own retries (§6.5): no further group is
                // started against an API that asks the client to stop.
                Err(TransferError::Backend(BackendError::RateLimited)) => {
                    self.stop.get_or_insert(Stop::RateLimited);
                    let error = BackendError::RateLimited.to_string();
                    self.summary.failed.push((rel, error));
                }
                Err(e) => self.fail(rel, e.to_string()),
            }
        }
        if !rows.is_empty() {
            let db = self.vault.db();
            db.base_put(self.pair, &rows)?;
            if cipher_bytes > 0 {
                db.ledger_add(util::now_ms(), LedgerDir::Down, cipher_bytes)?;
            }
            self.last_local_write = Some(Instant::now());
            self.written.extend(rows);
        }
        Ok(())
    }

    async fn downloads(&mut self, actions: Vec<Action>) -> Result<(), SyncError> {
        let mut facts: HashMap<String, DownloadFact> = HashMap::new();
        let mut groups: BTreeMap<BlobId, Vec<DownloadItem>> = BTreeMap::new();
        let mut empties: Vec<DownloadItem> = Vec::new();
        let mut total = 0;
        for action in actions {
            let Action::Download {
                key,
                rel,
                head,
                expect_local,
                keep_local,
            } = action
            else {
                continue;
            };
            let fact = DownloadFact {
                key,
                stamp: head.stamp,
                hash: head.entry.hash,
                size: head.entry.size,
                clen: head.entry.loc.as_ref().map_or(0, |loc| loc.clen),
            };
            total += fact.size;
            let blob = head.entry.loc.as_ref().map(|loc| loc.blob);
            let item = DownloadItem {
                head,
                root: self.root.clone(),
                rel: rel.clone(),
                // Row 7: the transfer layer moves an entry it does not expect aside.
                expect_local: if keep_local {
                    LocalExpect::Absent
                } else {
                    expect_local
                },
            };
            facts.insert(rel, fact);
            match blob {
                Some(blob) => groups.entry(blob).or_default().push(item),
                None => empties.push(item),
            }
        }
        if facts.is_empty() || self.halted() {
            return Ok(());
        }
        let db = self.vault.db().clone();
        if db.ledger_sum_24h(util::now_ms(), LedgerDir::Down)? >= LEDGER_DL_WARN {
            self.ui.warn(
                "close to Google's daily download allowance; downloads may stop until tomorrow",
            );
        }
        let progress = self
            .ui
            .transfer_progress("Downloading", total, facts.len() as u64);
        let streams = 2 * self.req.opts.transfers.max(1);
        let mut running = FuturesUnordered::new();
        // Zero-length files go in slices of one batch each, one slice at a time beside the
        // blobs: their base rows are written slice by slice, not all at the end.
        let mut empties = empties.into_iter();
        let mut empties_idle = true;
        let mut waiting = groups.into_iter();
        loop {
            if empties_idle && !self.halted() {
                let slice: Vec<DownloadItem> =
                    empties.by_ref().take(DOWNLOAD_BATCH_FILES).collect();
                if !slice.is_empty() {
                    empties_idle = false;
                    let slice = fetch_empties(slice, self.cancel.clone());
                    running.push(futures_util::future::Either::Left(slice));
                }
            }
            while running.len() < streams + usize::from(!empties_idle) && !self.halted() {
                let Some((blob, items)) = waiting.next() else {
                    break;
                };
                let rec = self.vault.blob(&blob)?;
                let group = fetch_group(self.cx(progress.clone()), blob, rec, items);
                running.push(futures_util::future::Either::Right(group));
            }
            let Some((lane, fetched)) = running.next().await else {
                break;
            };
            empties_idle |= lane == Lane::Empties;
            self.downloaded(fetched, &facts)?;
        }
        progress.finish();
        Ok(())
    }

    // --- step 3

    async fn delete_remotes(&mut self, actions: Vec<Action>) -> Result<(), SyncError> {
        if actions.is_empty() {
            return Ok(());
        }
        let mut drafts = Vec::new();
        for action in actions {
            if let Action::DelRemote {
                key,
                remote_path,
                base,
            } = action
            {
                let rel = path::strip_prefix(&remote_path, &self.req.remote_prefix)
                    .unwrap_or(&key)
                    .to_string();
                self.done("delete", &rel, 0);
                self.summary.deleted_remote += 1;
                drafts.push(self.del_draft(key, remote_path, base));
            }
        }
        for slice in drafts.chunks(COMMIT_MAX_OPS) {
            self.vault.stage(slice.to_vec())?;
            self.commit().await?;
        }
        Ok(())
    }

    async fn delete_locals(&mut self, actions: Vec<Action>) -> Result<(), SyncError> {
        if actions.is_empty() {
            return Ok(());
        }
        // Files first, then directories from the deepest up.
        let mut dels: Vec<(String, String, StatSig, bool)> = actions
            .into_iter()
            .filter_map(|a| match a {
                Action::DelLocal {
                    key,
                    rel,
                    expect_local,
                    is_dir,
                } => Some((key, rel, expect_local, is_dir)),
                _ => None,
            })
            .collect();
        dels.sort_by(|a, b| {
            (a.3, std::cmp::Reverse(a.1.len())).cmp(&(b.3, std::cmp::Reverse(b.1.len())))
        });
        let (gone, _) = self.remove_locals(dels).await?;
        let (root, keep) = (self.root.clone(), self.wanted_dirs.clone());
        blocking(move || {
            prune_dirs(&root, &gone, &keep);
            Ok(())
        })
        .await
    }

    // --- step 4

    /// §5.7 step 5: a file this run wrote is born untrusted (its ctime ≈ its observation). Once
    /// `RACY_WINDOW` has passed, files whose signature is unchanged get a fresh observation,
    /// so the next sync does not hash them again.
    async fn reobserve(&mut self) -> Result<(), SyncError> {
        let Some(last) = self.last_local_write else {
            return Ok(());
        };
        if self.halted() {
            return Ok(());
        }
        let wait = (RACY_WINDOW + Duration::from_millis(20)).saturating_sub(last.elapsed());
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = self.cancel.cancelled() => return Ok(()),
        }
        let (root, rows) = (self.root.clone(), std::mem::take(&mut self.written));
        let fresh: Vec<BaseRow> = blocking(move || {
            Ok(rows
                .into_iter()
                .filter_map(|mut row| {
                    let observed_ns = util::now_ns();
                    let sig = lstat_sig(&root.join(&row.rel)).ok()??;
                    (sig == row.sig).then(|| {
                        row.observed_ns = observed_ns;
                        row
                    })
                })
                .collect())
        })
        .await?;
        self.vault.db().base_put(self.pair, &fresh)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::backend::MemBackend;
    use crate::crypto::{KdfParams, Keyring, MasterKey, Passphrase};
    use crate::format::{KeyfilePayload, seal_keyfile};
    use crate::index::CreateParams;
    use crate::state::Db;
    use crate::sync::SyncOpts;
    use crate::transfer::durable;

    const VAULT: [u8; 16] = [0x37; 16];

    async fn vault(cache: &Path) -> Vault<MemBackend> {
        let backend = MemBackend::new();
        let keys = Keyring::new(VAULT, vec![(1, MasterKey::generate())], 1).unwrap();
        let keyfile = seal_keyfile(
            &KeyfilePayload::from_keyring(&keys, 1, "a", backend.now_ms()),
            &Passphrase::from_input("correct horse battery staple"),
            KdfParams {
                m_kib: 8192,
                t: 1,
                p: 1,
            },
        )
        .unwrap();
        let params = CreateParams {
            vault_id: VAULT,
            vault_name: "gclone".into(),
            device_name: "dev".into(),
            cache_dir: cache.to_path_buf(),
            machine_fp: Some([0; 32]),
            keyfile,
        };
        let db = Db::open_in_memory().unwrap();
        let created = Vault::create(Arc::new(backend), db, keys, params).await;
        created.unwrap().0
    }

    async fn run(vault: &Vault<MemBackend>, direction: Direction, root: &Path) -> Summary {
        let req = SyncRequest {
            direction,
            mode: Mode::Sync,
            local_root: root.to_path_buf(),
            remote_prefix: String::new(),
            own_dirs: Vec::new(),
            opts: SyncOpts {
                dry_run: false,
                checksum: false,
                force: false,
                excludes: Vec::new(),
                max_delete: None,
                assume_yes: false,
                transfers: 2,
                reset_pair: false,
                keep_pair: false,
            },
        };
        vault.refresh().await.unwrap();
        vault.commit().await.unwrap();
        let ui = Ui::silent();
        let done = crate::sync::run(vault, &req, &ui, CancellationToken::new()).await;
        done.unwrap()
    }

    /// The file rows of every pair of this database.
    fn file_rows(db: &Db) -> usize {
        let rows = (1..=8).flat_map(|pair| db.base_all(pair).unwrap());
        rows.filter(|row| row.kind == EntryKind::File).count()
    }

    fn files_under(dir: &Path) -> usize {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return 0;
        };
        entries
            .map(|e| e.unwrap())
            .map(|e| match e.file_type().unwrap().is_dir() {
                true => files_under(&e.path()),
                false => 1,
            })
            .sum()
    }

    /// Uploads `files` from a source tree; returns the vault and an empty place to download to.
    async fn uploaded(tmp: &Path, files: &[(&str, &[u8])]) -> (Vault<MemBackend>, PathBuf) {
        let vault = vault(&tmp.join("cache")).await;
        let src = tmp.join("src");
        for (rel, data) in files {
            let path = src.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, data).unwrap();
        }
        let up = run(&vault, Direction::Up, &src).await;
        assert_eq!(up.uploaded, files.len() as u64);
        assert_eq!(file_rows(vault.db()), files.len());
        (vault, tmp.join("dst"))
    }

    /// The invariant of §5.7 step 3, seen from the executor: while a barrier of a download is
    /// still to come, `state.db` holds no base row for a file behind it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn base_rows_are_written_only_behind_the_barriers() {
        let files: [(&str, &[u8]); 3] = [
            ("a.txt", b"alpha"),
            ("d/b.txt", b"bravo bravo"),
            ("d/e/c.txt", b"charlie"),
        ];
        let empties: [(&str, &[u8]); 2] = [("empty", b""), ("d/none", b"")];
        // Files with content come out of one blob, empty ones need none: either way one
        // batch, so every barrier of the run comes before every base row of the run.
        for files in [&files[..], &empties[..]] {
            let tmp = tempfile::tempdir().unwrap();
            let tmp = tmp.path().canonicalize().unwrap();
            let (vault, dst) = uploaded(&tmp, files).await;
            let seen = Arc::new(Mutex::new(Vec::new()));
            let (log, db, place) = (seen.clone(), vault.db().clone(), dst.clone());
            let _guard = durable::hook::observe(&dst, move |_| {
                let state = (file_rows(&db), files_under(&place));
                log.lock().unwrap().push(state);
                Ok(())
            });
            let down = run(&vault, Direction::Down, &dst).await;
            assert_eq!(down.downloaded, files.len() as u64);
            assert!(down.failed.is_empty(), "{:?}", down.failed);

            let n = files.len();
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 2, "content barrier, rename barrier");
            for (rows, _) in seen.iter() {
                assert_eq!(
                    *rows, n,
                    "only the upload's rows at a barrier of the download"
                );
            }
            assert_eq!(seen[1].1, n, "the rename barrier comes after the renames");
            assert_eq!(
                file_rows(vault.db()),
                2 * n,
                "rows once the barriers are behind"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_barrier_leaves_no_base_row() {
        let files: [(&str, &[u8]); 3] = [
            ("a.txt", b"alpha"),
            ("d/b.txt", b"bravo bravo"),
            ("d/e/c.txt", b"charlie"),
        ];
        // `fail` = which barrier is refused: the content's (1) or the renames' (2).
        for fail in [1, 2] {
            let tmp = tempfile::tempdir().unwrap();
            let tmp = tmp.path().canonicalize().unwrap();
            let (vault, dst) = uploaded(&tmp, &files).await;
            let calls = Arc::new(Mutex::new(0));
            let count = calls.clone();
            let guard = durable::hook::observe(&dst, move |_| {
                let mut count = count.lock().unwrap();
                *count += 1;
                match *count == fail {
                    true => Err(std::io::Error::other("the drive said no")),
                    false => Ok(()),
                }
            });
            let down = run(&vault, Direction::Down, &dst).await;
            assert_eq!(down.downloaded, 0);
            assert_eq!(down.failed.len(), 3, "{:?}", down.failed);
            assert!(
                down.failed
                    .iter()
                    .all(|(_, e)| e.contains("the drive said no"))
            );
            assert_eq!(
                file_rows(vault.db()),
                3,
                "no row for a file of the failed batch"
            );
            assert_eq!(*calls.lock().unwrap(), fail);
            // After a refused content barrier nothing was renamed (and the partial files are
            // gone); after a refused rename barrier the files are there, unrecorded.
            assert_eq!(files_under(&dst), [0, 3][fail - 1]);
            drop(guard);

            // The next run finds what is there: missing files are fetched, files that arrived
            // without a row are recognised by their content — nothing is taken for an edit.
            let again = run(&vault, Direction::Down, &dst).await;
            assert!(again.failed.is_empty() && again.skipped.is_empty());
            assert_eq!(again.downloaded, [3, 0][fail - 1]);
            assert_eq!(file_rows(vault.db()), 6);
            for (rel, data) in files {
                assert_eq!(std::fs::read(dst.join(rel)).unwrap(), data);
            }
        }
    }

    // --- §5.7 step 3b: the writers of base state beside the download batches

    type Barriers = Arc<Mutex<Vec<(usize, Vec<PathBuf>)>>>;

    /// Records, for every barrier under `dir`, `count(db)` at that moment and the paths; the
    /// `fail`-th barrier (counted from 1) is refused.
    fn watch(
        dir: &Path,
        db: &Db,
        count: fn(&Db) -> usize,
        fail: Option<usize>,
    ) -> (durable::hook::Guard, Barriers) {
        let seen: Barriers = Arc::new(Mutex::new(Vec::new()));
        let (log, db) = (seen.clone(), db.clone());
        let guard = durable::hook::observe(dir, move |paths| {
            let mut log = log.lock().unwrap();
            log.push((count(&db), paths.iter().map(|p| p.to_path_buf()).collect()));
            match fail == Some(log.len()) {
                true => Err(std::io::Error::other("the drive said no")),
                false => Ok(()),
            }
        });
        (guard, seen)
    }

    fn dir_rows(db: &Db) -> usize {
        let rows = (1..=8).flat_map(|pair| db.base_all(pair).unwrap());
        rows.filter(|row| row.kind == EntryKind::Dir).count()
    }

    fn sorted(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
        paths.sort();
        paths
    }

    const TREE: [(&str, &[u8]); 3] = [
        ("a.txt", b"alpha"),
        ("d/b.txt", b"bravo bravo"),
        ("d/e/c.txt", b"charlie"),
    ];

    /// Puts the files of `TREE` where a download would, without telling `state.db`: what a
    /// run leaves behind that renamed them and was killed, or whose rename barrier failed.
    fn place(dst: &Path) {
        for (rel, data) in TREE {
            let path = dst.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, data).unwrap();
        }
    }

    #[test]
    fn a_row_rests_on_the_entry_and_on_the_directories_above_it() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        place(&root);
        let p = |rel: &str| root.join(rel);
        assert_eq!(
            chain(&root, "d/e/c.txt", true),
            [p("d/e/c.txt"), p("d/e"), p("d"), root.clone()]
        );
        assert_eq!(chain(&root, "d/e", false), [p("d"), root.clone()]);
        assert_eq!(chain(&root, "a.txt", false), std::slice::from_ref(&root));
        // A removal is a change of the directory it happened in — or of the nearest one
        // that is left.
        assert_eq!(removed_from(&root, "d/e/c.txt"), p("d/e"));
        assert_eq!(removed_from(&root, "d/gone/deeper/f"), p("d"));
        assert_eq!(removed_from(&root, "a.txt/under-a-file"), root);
        assert_eq!(removed_from(&root, "top"), root);

        // Each path is synced once; an entry fails with the first of its paths that does,
        // an entry that needs nothing never fails.
        let synced = Arc::new(Mutex::new(Vec::new()));
        let log = synced.clone();
        let _barriers = durable::hook::observe(&root, move |paths| {
            let paths = paths.iter().map(|p| p.to_path_buf());
            log.lock().unwrap().push(sorted(paths.collect()));
            Ok(())
        });
        let needs = [
            chain(&root, "a.txt", true),
            Vec::new(),
            chain(&root, "d/b.txt", true),
            chain(&root, "d/missing", true),
            chain(&root, "d/e/c.txt", true),
        ];
        let verdicts = settle(&needs);
        let failed: Vec<bool> = verdicts.iter().map(Option::is_some).collect();
        assert_eq!(failed, [false, false, false, true, false]);
        assert!(verdicts[3].as_ref().unwrap().contains("d/missing"));
        let all = ["", "a.txt", "d", "d/b.txt", "d/e", "d/e/c.txt", "d/missing"];
        assert_eq!(*synced.lock().unwrap(), [sorted(all.map(p).to_vec())]);
        let bad = p("d");
        let _files = durable::hook::observe_files(&root, move |path, _| match path == bad {
            true => Err(std::io::Error::other("this directory does not sync")),
            false => Ok(()),
        });
        let failed: Vec<bool> = settle(&needs).iter().map(Option::is_some).collect();
        assert_eq!(failed, [false, false, true, true, true]);
        // Nothing to sync: no barrier at all.
        assert_eq!(settle(&[Vec::new(), Vec::new()]), [None, None]);
        assert_eq!(synced.lock().unwrap().len(), 2);
    }

    /// §17.16, `RecordBase`: files that are in place without a row — renamed by a run that
    /// could not report them — are recorded by content, and that row, too, is written only
    /// behind a barrier over the file and its directories up to the root.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_row_recorded_by_content_waits_for_its_barrier() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp = tmp.path().canonicalize().unwrap();
        let (vault, dst) = uploaded(&tmp, &TREE).await;
        place(&dst);
        let (guard, seen) = watch(&dst, vault.db(), file_rows, None);
        let down = run(&vault, Direction::Down, &dst).await;
        assert_eq!(down.downloaded, 0);
        assert!(down.failed.is_empty(), "{:?}", down.failed);
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 1, "one barrier for the recorded rows");
            assert_eq!(seen[0].0, 3, "only the upload's rows while it stands");
            let expect = ["", "a.txt", "d", "d/b.txt", "d/e", "d/e/c.txt"].map(|rel| dst.join(rel));
            assert_eq!(sorted(seen[0].1.clone()), sorted(expect.to_vec()));
        }
        assert_eq!(file_rows(vault.db()), 6);
        drop(guard);

        // The barrier is refused: no row, and the run says so.
        let (vault, dst) = uploaded(&tmp.join("refused"), &TREE).await;
        place(&dst);
        let (guard, _) = watch(&dst, vault.db(), file_rows, Some(1));
        let down = run(&vault, Direction::Down, &dst).await;
        assert_eq!(down.failed.len(), 3, "{:?}", down.failed);
        assert!(
            down.failed
                .iter()
                .all(|(_, e)| e.contains("the drive said no"))
        );
        assert_eq!(file_rows(vault.db()), 3);
        drop(guard);

        // One directory cannot be made durable: the rows below it are not written, the
        // row beside it is — and the next run writes the rest.
        let bad = dst.join("d");
        let guard = durable::hook::observe_files(&dst, move |path, _| match path == bad {
            true => Err(std::io::Error::other("this directory does not sync")),
            false => Ok(()),
        });
        let down = run(&vault, Direction::Down, &dst).await;
        let mut failed: Vec<&str> = down.failed.iter().map(|(rel, _)| rel.as_str()).collect();
        failed.sort_unstable();
        assert_eq!(failed, ["d/b.txt", "d/e/c.txt"], "{:?}", down.failed);
        assert_eq!(file_rows(vault.db()), 4);
        drop(guard);
        let again = run(&vault, Direction::Down, &dst).await;
        assert!(again.failed.is_empty() && again.skipped.is_empty());
        assert_eq!((again.downloaded, file_rows(vault.db())), (0, 6));
    }

    /// A row that only refreshes its predecessor — same content, same remote version, a new
    /// signature — claims nothing new and needs no barrier.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refreshed_row_needs_no_barrier() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp = tmp.path().canonicalize().unwrap();
        let (vault, dst) = uploaded(&tmp, &TREE).await;
        let down = run(&vault, Direction::Down, &dst).await;
        assert_eq!(down.downloaded, 3);

        // The same bytes again, the same mtime: only the inode's change time moves.
        let file = dst.join("d/b.txt");
        let md = std::fs::metadata(&file).unwrap();
        let mtime = filetime::FileTime::from_last_modification_time(&md);
        std::fs::write(&file, TREE[1].1).unwrap();
        filetime::set_file_mtime(&file, mtime).unwrap();
        let sig = lstat_sig(&file).unwrap().unwrap();
        let recorded = |db: &Db| {
            let rows = (1..=8).flat_map(|pair| db.base_all(pair).unwrap());
            rows.filter(|row| row.sig == sig).count()
        };
        assert_eq!(recorded(vault.db()), 0);

        let (_guard, seen) = watch(&dst, vault.db(), file_rows, None);
        let again = run(&vault, Direction::Down, &dst).await;
        assert_eq!((again.downloaded, again.hashed), (0, 1));
        assert!(again.failed.is_empty() && again.skipped.is_empty());
        assert_eq!(recorded(vault.db()), 1, "the row has the new signature");
        assert!(
            seen.lock().unwrap().is_empty(),
            "{:?}",
            seen.lock().unwrap()
        );
    }

    /// §17.16, `SetLocalMeta`: the row over a new mtime is written once the mtime is durable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_row_over_a_new_mtime_waits_for_its_barrier() {
        const NEW_NS: i64 = 1_650_000_000_000_000_000;
        fn with_new_mtime(db: &Db) -> usize {
            let rows = (1..=8).flat_map(|pair| db.base_all(pair).unwrap());
            rows.filter(|row| row.sig.mtime_ns == NEW_NS).count()
        }
        let mtime_ns = |path: &Path| lstat_sig(path).unwrap().unwrap().mtime_ns;

        // `fail`: the barrier is refused.
        for fail in [None, Some(1)] {
            let tmp = tempfile::tempdir().unwrap();
            let tmp = tmp.path().canonicalize().unwrap();
            let (vault, dst) = uploaded(&tmp, &TREE).await;
            let down = run(&vault, Direction::Down, &dst).await;
            assert_eq!(down.downloaded, 3);
            // Another device (the source tree) gives one file a new mtime.
            let new = filetime::FileTime::from_unix_time(NEW_NS / 1_000_000_000, 0);
            filetime::set_file_mtime(tmp.join("src/d/b.txt"), new).unwrap();
            let up = run(&vault, Direction::Up, &tmp.join("src")).await;
            assert_eq!((up.meta_updates, up.uploaded), (1, 0));
            assert_eq!(with_new_mtime(vault.db()), 1, "the source's row");

            let file = dst.join("d/b.txt");
            let (guard, seen) = watch(&dst, vault.db(), with_new_mtime, fail);
            let down = run(&vault, Direction::Down, &dst).await;
            {
                let seen = seen.lock().unwrap();
                assert_eq!(seen.len(), 1);
                // The barrier names the file whose attributes changed, and stands between
                // the change and the row.
                assert_eq!(seen[0], (1, vec![file.clone()]));
            }
            assert_eq!(mtime_ns(&file), NEW_NS);
            drop(guard);
            match fail {
                None => {
                    assert_eq!(down.meta_updates, 1);
                    assert!(down.failed.is_empty(), "{:?}", down.failed);
                    assert_eq!(with_new_mtime(vault.db()), 2);
                }
                Some(_) => {
                    assert_eq!(down.failed.len(), 1, "{:?}", down.failed);
                    assert_eq!(down.failed[0].0, "d/b.txt");
                    assert!(down.failed[0].1.contains("the drive said no"));
                    assert_eq!(with_new_mtime(vault.db()), 1, "no row over the new mtime");
                    // The next run finds the file as it should be and records it — and the
                    // source is never told that its mtime "changed back".
                    let again = run(&vault, Direction::Down, &dst).await;
                    assert!(again.failed.is_empty() && again.skipped.is_empty());
                    assert_eq!(with_new_mtime(vault.db()), 2);
                    let up = run(&vault, Direction::Up, &dst).await;
                    assert_eq!((up.meta_updates, up.uploaded), (0, 0));
                }
            }
        }
    }

    /// §17.16, `MkdirLocal`: the row of a created directory is written once the directory —
    /// its entry in each directory up to the root — is durable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_row_for_a_created_directory_waits_for_its_barrier() {
        for fail in [None, Some(1)] {
            let tmp = tempfile::tempdir().unwrap();
            let tmp = tmp.path().canonicalize().unwrap();
            let (vault, dst) = uploaded(&tmp, &TREE[..1]).await;
            std::fs::create_dir_all(tmp.join("src/e/empty")).unwrap();
            let up = run(&vault, Direction::Up, &tmp.join("src")).await;
            assert_eq!(up.dirs_created, 1);
            assert_eq!(dir_rows(vault.db()), 1, "the source's row");

            let (guard, seen) = watch(&dst, vault.db(), dir_rows, fail);
            let down = run(&vault, Direction::Down, &dst).await;
            assert_eq!(down.downloaded, 1);
            assert!(dst.join("e/empty").is_dir());
            {
                // The directory's own barrier comes first: the directories its entry and
                // its parent's entry live in.
                let seen = seen.lock().unwrap();
                assert_eq!(
                    seen.len(),
                    3,
                    "the directory; the file's content and rename"
                );
                assert_eq!(seen[0].0, 1, "no row while the barrier stands");
                assert_eq!(sorted(seen[0].1.clone()), [dst.clone(), dst.join("e")]);
            }
            drop(guard);
            match fail {
                None => {
                    assert!(down.failed.is_empty(), "{:?}", down.failed);
                    assert_eq!(dir_rows(vault.db()), 2);
                }
                Some(_) => {
                    assert_eq!(down.failed.len(), 1, "{:?}", down.failed);
                    assert_eq!(down.failed[0].0, "e/empty");
                    assert!(down.failed[0].1.contains("the drive said no"));
                    assert_eq!(dir_rows(vault.db()), 1, "no row for the directory");
                    // Without a row the directory is not "removed here" if it is lost: an
                    // upload from this tree leaves the marker alone.
                    std::fs::remove_dir(dst.join("e/empty")).unwrap();
                    let up = run(&vault, Direction::Up, &dst).await;
                    assert_eq!(up.deleted_remote, 0);
                    let again = run(&vault, Direction::Down, &dst).await;
                    assert!(again.failed.is_empty(), "{:?}", again.failed);
                    assert_eq!(dir_rows(vault.db()), 2);
                    assert!(dst.join("e/empty").is_dir());
                }
            }
        }
    }

    /// §17.16, `DelLocal`: a row is forgotten once the removal is durable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_row_is_forgotten_behind_the_barrier_of_the_removal() {
        for fail in [None, Some(1)] {
            let tmp = tempfile::tempdir().unwrap();
            let tmp = tmp.path().canonicalize().unwrap();
            let (vault, dst) = uploaded(&tmp, &TREE).await;
            let down = run(&vault, Direction::Down, &dst).await;
            assert_eq!(down.downloaded, 3);
            std::fs::remove_file(tmp.join("src/d/b.txt")).unwrap();
            let up = run(&vault, Direction::Up, &tmp.join("src")).await;
            assert_eq!(up.deleted_remote, 1);
            assert_eq!(file_rows(vault.db()), 5);

            let (guard, seen) = watch(&dst, vault.db(), file_rows, fail);
            let down = run(&vault, Direction::Down, &dst).await;
            assert!(!dst.join("d/b.txt").exists());
            {
                // The removal happened in `d`; the row is still there while the barrier
                // stands.
                let seen = seen.lock().unwrap();
                assert_eq!(*seen, [(5, vec![dst.join("d")])]);
            }
            drop(guard);
            match fail {
                None => {
                    assert_eq!(down.deleted_local, 1);
                    assert!(down.failed.is_empty(), "{:?}", down.failed);
                    assert_eq!(file_rows(vault.db()), 4);
                }
                Some(_) => {
                    assert_eq!(down.failed.len(), 1, "{:?}", down.failed);
                    assert_eq!(down.failed[0].0, "d/b.txt");
                    assert!(down.failed[0].1.contains("the drive said no"));
                    assert_eq!(file_rows(vault.db()), 5, "the row is kept");
                    // With its row a file that comes back is not a new one: nothing is
                    // published from here. And a run that finds it gone forgets the row.
                    std::fs::write(dst.join("d/b.txt"), TREE[1].1).unwrap();
                    let up = run(&vault, Direction::Up, &dst).await;
                    assert_eq!(up.uploaded + up.reused, 0);
                    std::fs::remove_file(dst.join("d/b.txt")).unwrap();
                    let again = run(&vault, Direction::Down, &dst).await;
                    assert!(again.failed.is_empty(), "{:?}", again.failed);
                    assert_eq!(file_rows(vault.db()), 4);
                }
            }
        }
    }
}

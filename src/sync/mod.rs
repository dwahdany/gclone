//! Sync engine (SPEC §5.1, §5.4, §5.5, §5.7, §5.9, §9.9) — owned by WP6.

use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::backend::Backend;
use crate::error::{GuardKind, IndexError, SyncError};
use crate::index::Vault;
use crate::path;
use crate::state::PairIdentity;
use crate::types::EntryKind;

pub mod check;
pub mod exec;
pub mod gc;
pub mod plan;
pub mod remote_ops;
pub mod scan;

pub use check::*;
pub use exec::execute;
pub use gc::*;
pub use plan::*;
pub use scan::*;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    Up,
    Down,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Copy,
    Sync,
}

#[derive(Clone, Debug)]
pub struct SyncOpts {
    pub dry_run: bool,
    pub checksum: bool,
    pub force: bool,
    pub excludes: Vec<String>,
    pub max_delete: Option<u64>,
    pub assume_yes: bool,
    pub transfers: usize,
    pub reset_pair: bool,
    pub keep_pair: bool,
}

#[derive(Clone, Debug)]
pub struct SyncRequest {
    pub direction: Direction,
    pub mode: Mode,
    pub local_root: std::path::PathBuf,
    pub remote_prefix: String,
    /// gclone's own directories — the configuration directory, the state root, the directory
    /// of a directory vault (§5.5.3, §8.1). Where they lie under the local root they are not
    /// synced, in either direction; a local root inside one of them is refused.
    pub own_dirs: Vec<std::path::PathBuf>,
    pub opts: SyncOpts,
}

#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub uploaded: u64,
    pub downloaded: u64,
    pub reused: u64,
    pub meta_updates: u64,
    /// Empty directories created (`MkdirRemote` / `MkdirLocal`).
    pub dirs_created: u64,
    pub deleted_remote: u64,
    pub deleted_local: u64,
    pub conflicts: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// Files BLAKE3-hashed.
    pub hashed: u64,
    pub skipped: Vec<(String, SkipReason)>,
    pub failed: Vec<(String, String)>,
    pub deletes_suppressed: bool,
    pub dry_run: bool,
    pub elapsed_ms: u64,
}

impl Summary {
    /// 0 or 6 (partial: something was skipped or failed, §7.2).
    pub fn exit_code(&self) -> i32 {
        if self.failed.is_empty() && self.skipped.is_empty() && !self.deletes_suppressed {
            0
        } else {
            6
        }
    }
}

/// Blocking file-system work with owned inputs, off the async threads.
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, SyncError> + Send + 'static,
) -> Result<T, SyncError> {
    match tokio::task::spawn_blocking(f).await {
        Ok(out) => out,
        Err(e) => match e.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            Err(_) => Err(SyncError::Interrupted),
        },
    }
}

/// The sync root as the pair table names it: absolute and, when it exists, canonical.
pub(crate) fn canonical_root(given: &Path) -> Result<(PathBuf, bool), SyncError> {
    match std::fs::canonicalize(given) {
        Ok(root) => Ok((root, true)),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            // Canonical as far as it exists: the missing tail is appended as given.
            let abs = std::path::absolute(given)?;
            let mut tail = Vec::new();
            let mut at = abs.as_path();
            loop {
                if let Ok(real) = std::fs::canonicalize(at) {
                    let mut root = real;
                    root.extend(tail.iter().rev());
                    return Ok((root, false));
                }
                match (at.parent(), at.file_name()) {
                    (Some(parent), Some(name)) => {
                        tail.push(name.to_os_string());
                        at = parent;
                    }
                    _ => return Ok((abs, false)),
                }
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// gclone's own directories as paths relative to `root` (§5.5.3). `Err(Usage)` when the root
/// is one of them or lies inside one: a sync would upload the keys and the live `state.db`,
/// and a download would replace them under the running process.
fn own_dirs_under(root: &Path, own_dirs: &[PathBuf]) -> Result<Vec<String>, SyncError> {
    let mut rels = Vec::new();
    for dir in own_dirs {
        let (dir, _) = canonical_root(dir)?;
        if root.starts_with(&dir) {
            return Err(SyncError::Usage(format!(
                "{} is inside {}, where gclone keeps its own files; it cannot be synced",
                root.display(),
                dir.display()
            )));
        }
        // A name that is not UTF-8 is never synced anyway (§5.4).
        if let Ok(rel) = dir.strip_prefix(root)
            && let Some(rel) = rel.to_str()
        {
            rels.push(rel.to_string());
        }
    }
    rels.sort();
    rels.dedup();
    Ok(rels)
}

/// A remote path to read from that has no entry at or under it (and is not the vault root).
/// Reading from it finds nothing, which must not look like success (§5.5.1).
pub(crate) fn no_such_remote(prefix: &str, what: &str) -> SyncError {
    SyncError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!(":{prefix}: no such {what} in the vault (gclone ls shows what is there)"),
    ))
}

/// The local argument names a file: `copy` / `sync` transfer the contents of a directory.
pub(crate) fn not_a_directory(root: &Path) -> String {
    format!(
        "{} is not a directory: copy and sync transfer the contents of a directory, not a \
         single file (one file out of the vault: gclone cat :PATH > FILE)",
        root.display()
    )
}

/// G6: answers a changed root identity. `Ok(true)` = the pair's base rows are to be dropped.
fn settle_identity(req: &SyncRequest, root: &Path, ui: &crate::ui::Ui) -> Result<bool, SyncError> {
    if req.opts.reset_pair {
        return Ok(true);
    }
    if req.opts.keep_pair {
        return Ok(false);
    }
    let shown = if req.remote_prefix.is_empty() {
        ":".to_string()
    } else {
        format!(":{}", req.remote_prefix)
    };
    let question = format!(
        "Local root {} is not the directory last synced with {shown} (it was replaced, \
         restored, or its file system has no stable inode numbers).",
        root.display()
    );
    let options = [
        "It is the same directory: keep the sync state (--keep-pair)",
        "It is another directory: start over; nothing is deleted or overwritten (--reset-pair)",
        "Stop",
    ];
    match ui.choose(&question, &options) {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(SyncError::Guard(GuardKind::RootChanged)),
    }
}

/// The caller has already refreshed and settled (`open_ctx`, §9.10) and calls
/// `Vault::finish_mutation` afterwards. Up with `vault.outbox_stuck()` →
/// `Err(Index(OutboxStuck))` before any work. Then: pair identity (G6) → scan + resolve_hashes
/// (one `spawn_blocking`) → remote_rows + reuse_index → plan → guards (may ask via ui) → execute.
pub async fn run<B: Backend>(
    vault: &Vault<B>,
    req: &SyncRequest,
    ui: &crate::ui::Ui,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<Summary, SyncError> {
    let started = Instant::now();
    let up = req.direction == Direction::Up;
    let opts = &req.opts;
    if up && let Some(cause) = vault.outbox_stuck() {
        return Err(IndexError::OutboxStuck(cause).into());
    }
    if opts.reset_pair && opts.keep_pair {
        return Err(SyncError::Usage(
            "--reset-pair and --keep-pair exclude each other".into(),
        ));
    }
    if !req.remote_prefix.is_empty() {
        path::validate(&req.remote_prefix)
            .map_err(|e| SyncError::Usage(format!(":{}: {e}", req.remote_prefix)))?;
        // The prefix is a directory to sync with. Where it is a file, or lies under one, an
        // upload would make the index move that file to a conflict name (§5.2.3 rule 2) and a
        // download would find nothing; the planner sees type changes only below the prefix.
        let at_and_above =
            std::iter::once(req.remote_prefix.as_str()).chain(path::ancestors(&req.remote_prefix));
        for p in at_and_above {
            if vault
                .head(p)?
                .is_some_and(|h| h.entry.kind == EntryKind::File)
            {
                return Err(SyncError::Usage(format!(
                    ":{p} is a file, not a directory (copy and sync work on directories)"
                )));
            }
        }
    }

    // A download from a path that does not exist would find nothing and report success — a
    // typo in a restore must not look like a restore. It is refused unless this pair has synced
    // before (then the remote directory was removed, and `sync` carries that out; below).
    let remote_missing =
        !up && !req.remote_prefix.is_empty() && !vault.exists_dir(&req.remote_prefix)?;

    // --- the root and its identity (G6, before the scan)
    let (mut root, mut exists) = canonical_root(&req.local_root)?;
    if !exists && up && !opts.force {
        return Err(SyncError::Guard(GuardKind::EmptySource));
    }
    // Before anything is created: a root inside gclone's own directories is refused.
    own_dirs_under(&root, &req.own_dirs)?;
    if remote_missing && !exists {
        return Err(no_such_remote(&req.remote_prefix, "directory"));
    }
    if !exists && !up && !opts.dry_run {
        // The identity recorded for a new pair must be the real directory's.
        std::fs::create_dir_all(&root)?;
        (root, exists) = canonical_root(&root)?;
    }
    let root_name = root
        .to_str()
        .ok_or_else(|| SyncError::Usage(format!("{} is not valid UTF-8", root.display())))?
        .to_string();
    let own = own_dirs_under(&root, &req.own_dirs)?;
    let filter = Filter::new(&opts.excludes, &root)?;
    let (identity, fold_case) = {
        let root = root.clone();
        blocking(move || match std::fs::metadata(&root) {
            Ok(md) if md.is_dir() => Ok((
                Some(scan::root_identity(&md)),
                probe_fold_case(&root).unwrap_or(true),
            )),
            Ok(_) => Err(SyncError::Usage(not_a_directory(&root))),
            // Missing (dry run, or a forced upload from nowhere).
            Err(_) => Ok((None, scan::probe_fold_missing(&root))),
        })
        .await?
    };
    let filter = filter.with_own_dirs(&own, fold_case);
    if !own.is_empty() {
        ui.info(&format!(
            "note: gclone's own files are not synced: {}",
            own.join(", ")
        ));
    }

    let db = vault.db();
    let mut pair = 0;
    let mut base = Vec::new();
    if exists || !opts.dry_run {
        let (ino, birth_ns) = identity.unwrap_or((0, 0));
        let info = db.pair_open(&root_name, &req.remote_prefix, ino, birth_ns, fold_case)?;
        pair = info.id;
        let changed = info.identity == PairIdentity::Changed;
        // `--reset-pair` is honoured whatever the identity says: a tree that was damaged or
        // restored inside the same directory keeps its inode, and the flag promises a run
        // that deletes and overwrites nothing. `--keep-pair` with an unchanged identity asks
        // for what happens anyway.
        let reset = if opts.reset_pair {
            true
        } else if changed {
            settle_identity(req, &root, ui)?
        } else {
            false
        };
        if !opts.dry_run {
            if reset {
                db.pair_reset(pair, ino, birth_ns)?;
            } else if changed {
                db.pair_rebind(pair, ino, birth_ns)?;
            }
        }
        if !reset {
            base = db.base_all(pair)?;
        }
    }
    if remote_missing && base.is_empty() {
        return Err(no_such_remote(&req.remote_prefix, "directory"));
    }

    // --- both sides, the plan and its guards: one blocking step with owned inputs
    let remote = remote_rows_unfiltered(vault, &req.remote_prefix, fold_case)?;
    // Reuse is an upload-side shortcut; a download has no use for the content index.
    let reuse = if up {
        reuse_index(vault)?
    } else {
        ReuseIndex {
            by_content: Default::default(),
            sizes: Default::default(),
        }
    };
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    let (checksum, force, max_delete) = (opts.checksum, opts.force, opts.max_delete);
    let (direction, mode, prefix) = (req.direction, req.mode, req.remote_prefix.clone());
    let verbose = ui.verbose() > 0;
    let planned = {
        let root = root.clone();
        blocking(move || {
            let mut local = if exists {
                scan::scan_with(&root, &filter, fold_case)?
            } else {
                scan::missing_root(&root, fold_case)
            };
            // One answer per key (§5.5.3): what any spelling excludes is invisible on all
            // three inputs.
            let (mut remote, mut base) = (remote, base);
            hide_excluded(&filter, &mut local, &mut remote, &mut base);
            let remote_collisions = remote_collisions(&mut remote);
            let hashed =
                resolve_hashes(&mut local, &base, &remote, &reuse.sizes, checksum, threads)?;
            let mut notes = Vec::new();
            if verbose {
                // Spelling differences are not propagated (§5.1); both spellings stay.
                let spelled: std::collections::HashMap<&str, &str> = remote
                    .iter()
                    .map(|r| (r.key.as_str(), r.rel.as_str()))
                    .collect();
                for entry in &local.entries {
                    if let Some(rel) = spelled.get(entry.key.as_str())
                        && *rel != entry.rel
                    {
                        notes.push(format!(
                            "note: {} is spelled {rel} in the vault; both spellings are kept",
                            entry.rel
                        ));
                    }
                }
            }
            let input = PlanInput {
                direction,
                mode,
                force,
                remote_prefix: &prefix,
                local: &local,
                remote: &remote,
                remote_collisions: &remote_collisions,
                base: &base,
                reuse: &reuse.by_content,
            };
            let plan = plan(&input);
            let guard = check_guards(&plan, &input, max_delete);
            Ok((plan, guard, hashed, local.skipped, local.failed_dirs, notes))
        })
        .await?
    };
    let (plan, guard, hashed, skipped, failed_dirs, notes) = planned;
    if skipped.symlinks + skipped.special + skipped.non_utf8 > 0 {
        ui.info(&format!(
            "note: not synced: {} symlinks, {} special files, {} names that are not UTF-8",
            skipped.symlinks, skipped.special, skipped.non_utf8
        ));
    }
    for dir in &failed_dirs {
        let shown = if dir.is_empty() { "." } else { dir };
        ui.warn(&format!(
            "cannot read {shown}: nothing under it is deleted or overwritten"
        ));
    }
    for note in &notes {
        ui.info(note);
    }

    match guard {
        Ok(()) => {}
        Err(GuardKind::DeleteLimit { deletes, total }) => {
            if opts.dry_run {
                ui.warn(&format!(
                    "this run would delete {deletes} of {total} files and needs --yes"
                ));
            } else if !opts.assume_yes
                && !ui.confirm(&format!("Delete {deletes} of {total} files?"))
            {
                return Err(SyncError::Guard(GuardKind::DeleteLimit { deletes, total }));
            }
        }
        // An explicit --max-delete is a hard limit: neither --yes nor a terminal lifts it.
        Err(GuardKind::MaxDelete { deletes, limit }) if opts.dry_run => ui.warn(&format!(
            "this run would delete {deletes} files; --max-delete {limit} refuses that \
             (raise the limit to let it run)"
        )),
        Err(guard) => return Err(SyncError::Guard(guard)),
    }

    let mut summary = execute(vault, pair, req, plan, ui, cancel).await?;
    summary.hashed = hashed;
    summary.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(summary)
}

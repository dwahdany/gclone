//! The planner (SPEC §5.5, §9.9) — owned by WP6. Pure: no I/O, no closures over the vault.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Bound;

use super::scan::{LocalEntry, LocalScan, RemoteRow};
use super::{Direction, Mode};
use crate::consts::{MAX_DELETE_ABS, RACY_WINDOW_NS};
use crate::error::GuardKind;
use crate::path;
use crate::transfer::LocalExpect;
use crate::types::{BaseRow, Entry, EntryKind, Head, Stamp, StatSig};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkipReason {
    RemoteNewer,
    RemoteOnly,
    RemoteDeleted,
    LocalChanged,
    LocalOnly,
    ScanError,
    KeyCollision,
    ChangedDuringUpload,
    UnsafeTarget,
    Unsupported(String),
    Failed(String),
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SkipReason::RemoteNewer => "remote is newer; --force to overwrite",
            SkipReason::RemoteOnly => {
                "only in the vault and never synced here; kept (copy it down, or gclone rm)"
            }
            SkipReason::RemoteDeleted => "deleted on the remote; --force to upload again",
            SkipReason::LocalChanged => "changed locally; not overwritten",
            SkipReason::LocalOnly => {
                "only local and never synced; kept (copy it up, or delete it yourself)"
            }
            SkipReason::ScanError => "could not be read, or changed during the scan",
            SkipReason::KeyCollision => "names differ only by case or Unicode form",
            SkipReason::ChangedDuringUpload => "changed while it was uploaded",
            SkipReason::UnsafeTarget => "the target is not safe to replace",
            SkipReason::Unsupported(why) | SkipReason::Failed(why) => why,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Upload {
        rel: String,
        key: String,
        remote_path: String,
        base: Option<Stamp>,
        size: u64,
        conflict: bool,
    },
    Reuse {
        rel: String,
        key: String,
        remote_path: String,
        base: Option<Stamp>,
        from: Head,
        sig: StatSig,
        observed_ns: i64,
        hash: [u8; 32],
    },
    MkdirRemote {
        rel: String,
        key: String,
        remote_path: String,
        base: Option<Stamp>,
    },
    SetRemoteMeta {
        rel: String,
        key: String,
        remote_path: String,
        base: Stamp,
        entry: Entry,
        sig: StatSig,
        observed_ns: i64,
    },
    DelRemote {
        key: String,
        remote_path: String,
        base: Stamp,
    },
    /// `keep_local`: row 7 — move the local file aside first.
    Download {
        key: String,
        rel: String,
        head: Head,
        expect_local: LocalExpect,
        keep_local: bool,
    },
    MkdirLocal {
        key: String,
        rel: String,
        head: Head,
        expect_local: LocalExpect,
    },
    SetLocalMeta {
        key: String,
        rel: String,
        head: Head,
        expect_local: StatSig,
    },
    DelLocal {
        key: String,
        rel: String,
        expect_local: StatSig,
        is_dir: bool,
    },
    RecordBase {
        key: String,
        rel: String,
        sig: StatSig,
        observed_ns: i64,
        hash: [u8; 32],
        kind: EntryKind,
        remote_stamp: Stamp,
    },
    ForgetBase {
        key: String,
    },
    Skip {
        key: String,
        rel: String,
        reason: SkipReason,
    },
}

impl Action {
    pub fn key(&self) -> &str {
        match self {
            Action::Upload { key, .. }
            | Action::Reuse { key, .. }
            | Action::MkdirRemote { key, .. }
            | Action::SetRemoteMeta { key, .. }
            | Action::DelRemote { key, .. }
            | Action::Download { key, .. }
            | Action::MkdirLocal { key, .. }
            | Action::SetLocalMeta { key, .. }
            | Action::DelLocal { key, .. }
            | Action::RecordBase { key, .. }
            | Action::ForgetBase { key }
            | Action::Skip { key, .. } => key,
        }
    }

    /// `DelRemote` or `DelLocal` — what guard G4 counts.
    pub fn is_delete(&self) -> bool {
        matches!(self, Action::DelRemote { .. } | Action::DelLocal { .. })
    }
}

/// One file↔directory type change (§5.5.1): indices into `Plan.actions`. `first` must succeed
/// before `then` may run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeChange {
    pub first: Vec<usize>,
    pub then: Vec<usize>,
}

/// Plain data: `PlanInput` is `Send + Sync`.
pub struct PlanInput<'a> {
    pub direction: Direction,
    pub mode: Mode,
    pub force: bool,
    pub remote_prefix: &'a str,
    pub local: &'a LocalScan,
    pub remote: &'a [RemoteRow],
    pub remote_collisions: &'a [String],
    /// Already filtered by the `Filter`, §5.5.3.
    pub base: &'a [BaseRow],
    pub reuse: &'a HashMap<(u64, [u8; 32]), Head>,
}

#[derive(Clone, Debug, Default)]
pub struct Plan {
    /// Sorted by key.
    pub actions: Vec<Action>,
    pub groups: Vec<TypeChange>,
    pub deletes: u64,
    pub dest_total: u64,
    pub suspicious_reverts: usize,
    pub changed_local: usize,
    /// Local directories (as spelled locally) that hold content now and have a remote
    /// empty-directory marker: they stay when a delete of this run empties them (§5.7 step 3).
    pub keep_dirs: Vec<String>,
}

/// What the scan knows about a key's local side (§5.5 classification).
enum Local<'a> {
    Absent,
    Unknown(SkipReason),
    Same(&'a LocalEntry),
    Changed(&'a LocalEntry),
    New(&'a LocalEntry),
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Remote {
    Absent,
    Same,
    Changed,
    New,
}

/// Whether `key` is at or under one of `dirs` (comparison keys; `""` is the root).
fn at_or_under(key: &str, dirs: &[String]) -> bool {
    dirs.iter().any(|d| {
        d.is_empty()
            || key == d
            || (key.len() > d.len()
                && key.starts_with(d.as_str())
                && key.as_bytes()[d.len()] == b'/')
    })
}

/// Directory spellings that exist on one side, by comparison key.
fn dir_spellings<'a>(
    rows: impl Iterator<Item = (&'a str, &'a str, bool)>,
) -> HashMap<&'a str, &'a str> {
    let mut dirs: HashMap<&str, &str> = HashMap::new();
    for (key, rel, is_dir) in rows {
        // cmp_key works component by component, so ancestors correspond slash by slash.
        let cuts = key.match_indices('/').zip(rel.match_indices('/'));
        for ((k, _), (r, _)) in cuts {
            dirs.entry(&key[..k]).or_insert(&rel[..r]);
        }
        if is_dir {
            dirs.entry(key).or_insert(rel);
        }
    }
    dirs
}

/// `rel` with its ancestor directories in the spelling the destination already has (longest
/// key-prefix match, §5.5 "one spelling per key").
fn spell_like(rel: &str, key: &str, dirs: &HashMap<&str, &str>) -> String {
    let cuts: Vec<(usize, usize)> = key
        .match_indices('/')
        .zip(rel.match_indices('/'))
        .map(|((k, _), (r, _))| (k, r))
        .collect();
    for (k, r) in cuts.into_iter().rev() {
        if let Some(existing) = dirs.get(&key[..k]) {
            return format!("{existing}{}", &rel[r..]);
        }
    }
    rel.to_string()
}

struct Planner<'a> {
    input: &'a PlanInput<'a>,
    up: bool,
    sync: bool,
    remote_dirs: HashMap<&'a str, &'a str>,
    local_dirs: HashMap<&'a str, &'a str>,
}

impl<'a> Planner<'a> {
    /// The local file's content hash: taken by the scan, or the base row's when the signature
    /// proved the file unchanged.
    fn local_hash(l: &LocalEntry, b: Option<&BaseRow>) -> Option<[u8; 32]> {
        match l.kind {
            EntryKind::Dir => Some([0; 32]),
            EntryKind::File => l.hash.or_else(|| {
                b.filter(|b| b.kind == EntryKind::File && b.sig == l.sig && b.trusted())
                    .map(|b| b.hash)
            }),
        }
    }

    /// "Equal content" = same kind and `(size, hash)` equal.
    fn equal(l: &LocalEntry, b: Option<&BaseRow>, r: &RemoteRow) -> bool {
        l.kind == r.head.entry.kind
            && (l.kind == EntryKind::Dir
                || (l.sig.size == r.head.entry.size
                    && Self::local_hash(l, b) == Some(r.head.entry.hash)))
    }

    /// Row 1's meta test: exec differs or |Δmtime| ≥ 2 s. Files only.
    fn meta_differs(l: &LocalEntry, r: &RemoteRow) -> bool {
        let e = &r.head.entry;
        l.kind == EntryKind::File
            && e.kind == EntryKind::File
            && (l.sig.is_exec() != e.exec
                || l.sig.mtime_ns.abs_diff(e.mtime_ns) >= RACY_WINDOW_NS as u64)
    }

    /// Whether the local file's metadata changed since its base row was written. A row
    /// recorded for equal content (rows 3, 6) keeps a difference to the remote entry that this
    /// device never made; pushing it would be answered by the other device pushing its own,
    /// forever (§5.5.1 row 1).
    fn meta_changed(l: &LocalEntry, b: Option<&BaseRow>) -> bool {
        b.is_none_or(|b| {
            b.kind != EntryKind::File
                || l.sig.is_exec() != b.sig.is_exec()
                || l.sig.mtime_ns != b.sig.mtime_ns
        })
    }

    fn expect(l: Option<&LocalEntry>) -> LocalExpect {
        match l {
            None => LocalExpect::Absent,
            Some(l) if l.kind == EntryKind::Dir => LocalExpect::EmptyDir,
            Some(l) => LocalExpect::File(l.sig),
        }
    }

    fn upload(
        &self,
        l: &LocalEntry,
        b: Option<&BaseRow>,
        r: Option<&RemoteRow>,
        base: Option<Stamp>,
        conflict: bool,
    ) -> Action {
        let remote_path = match r {
            Some(r) => r.head.path.clone(),
            None => path::join(
                self.input.remote_prefix,
                &spell_like(&l.rel, &l.key, &self.remote_dirs),
            ),
        };
        // A Put under another spelling with base = R.stamp would supersede nothing and leave
        // both spellings in the index (§5.5).
        assert!(
            base.is_none() || r.is_some_and(|r| r.head.path == remote_path),
            "a Put with a base goes to the remote entry's own path"
        );
        let (rel, key) = (l.rel.clone(), l.key.clone());
        if l.kind == EntryKind::Dir {
            return Action::MkdirRemote {
                rel,
                key,
                remote_path,
                base,
            };
        }
        let reusable = Self::local_hash(l, b)
            .filter(|_| l.sig.size > 0)
            .and_then(|hash| Some((hash, self.input.reuse.get(&(l.sig.size, hash))?)));
        match reusable {
            Some((hash, from)) => Action::Reuse {
                rel,
                key,
                remote_path,
                base,
                from: from.clone(),
                sig: l.sig,
                observed_ns: l.observed_ns,
                hash,
            },
            None => Action::Upload {
                rel,
                key,
                remote_path,
                base,
                size: l.sig.size,
                conflict,
            },
        }
    }

    /// `keep`: the local entry is not known to be in sync — it is moved aside, never replaced.
    fn download(&self, l: Option<&LocalEntry>, r: &RemoteRow, keep: bool) -> Action {
        let rel = match l {
            Some(l) => l.rel.clone(),
            None => spell_like(&r.rel, &r.key, &self.local_dirs),
        };
        let (key, head) = (r.key.clone(), r.head.clone());
        let keep_local = keep && l.is_some_and(|l| l.kind == EntryKind::File);
        if r.head.entry.kind == EntryKind::Dir {
            return Action::MkdirLocal {
                key,
                rel,
                head,
                // `Absent` makes the executor move an unexpected file aside instead of
                // unlinking the expected one.
                expect_local: if keep_local {
                    LocalExpect::Absent
                } else {
                    Self::expect(l)
                },
            };
        }
        Action::Download {
            key,
            rel,
            head,
            expect_local: Self::expect(l),
            keep_local,
        }
    }

    fn record(l: &LocalEntry, b: Option<&BaseRow>, r: &RemoteRow) -> Action {
        Action::RecordBase {
            key: l.key.clone(),
            rel: l.rel.clone(),
            sig: l.sig,
            observed_ns: l.observed_ns,
            hash: Self::local_hash(l, b).unwrap_or([0; 32]),
            kind: l.kind,
            remote_stamp: r.head.stamp,
        }
    }

    fn skip(key: &str, rel: &str, reason: SkipReason) -> Action {
        Action::Skip {
            key: key.to_string(),
            rel: rel.to_string(),
            reason,
        }
    }

    /// §5.5.1, one key.
    fn decide(
        &self,
        key: &str,
        rel_hint: &str,
        local: Local<'_>,
        remote: Remote,
        r: Option<&RemoteRow>,
        b: Option<&BaseRow>,
    ) -> Option<Action> {
        let (up, sync, force) = (self.up, self.sync, self.input.force);
        let rel_of = |l: &LocalEntry| l.rel.clone();
        // `r` is present whenever `remote` is not `Absent`; the pairs below rely on it.
        let action = match (local, remote, r) {
            // row 13
            (Local::Unknown(reason), _, _) => Self::skip(key, rel_hint, reason),
            // row 1
            (Local::Same(l), Remote::Same, Some(r)) => {
                // Upward only a change made here is pushed; downward the remote entry is
                // the truth, whoever differs.
                if Self::meta_differs(l, r) && (!up || Self::meta_changed(l, b)) {
                    if up {
                        Action::SetRemoteMeta {
                            rel: rel_of(l),
                            key: l.key.clone(),
                            remote_path: r.head.path.clone(),
                            base: r.head.stamp,
                            entry: Entry {
                                mtime_ns: l.sig.mtime_ns,
                                exec: l.sig.is_exec(),
                                ..r.head.entry.clone()
                            },
                            sig: l.sig,
                            observed_ns: l.observed_ns,
                        }
                    } else {
                        Action::SetLocalMeta {
                            key: l.key.clone(),
                            rel: rel_of(l),
                            head: r.head.clone(),
                            expect_local: l.sig,
                        }
                    }
                } else if b
                    .is_some_and(|b| l.kind == EntryKind::File && (l.sig != b.sig || !b.trusted()))
                {
                    // "same" had to be established by hashing: refresh the row.
                    Self::record(l, b, r)
                } else {
                    return None;
                }
            }
            // row 2
            (Local::Changed(l), Remote::Same, Some(r)) => {
                if up {
                    self.upload(l, b, Some(r), Some(r.head.stamp), false)
                } else if force {
                    self.download(Some(l), r, false)
                } else {
                    Self::skip(key, &l.rel, SkipReason::LocalChanged)
                }
            }
            // row 3
            (Local::Same(l), Remote::Changed, Some(r)) => {
                if Self::equal(l, b, r) {
                    if !up && Self::meta_differs(l, r) {
                        Action::SetLocalMeta {
                            key: l.key.clone(),
                            rel: rel_of(l),
                            head: r.head.clone(),
                            expect_local: l.sig,
                        }
                    } else {
                        Self::record(l, b, r)
                    }
                } else if !up {
                    self.download(Some(l), r, false)
                } else if force {
                    self.upload(l, b, Some(r), Some(r.head.stamp), false)
                } else {
                    Self::skip(key, &l.rel, SkipReason::RemoteNewer)
                }
            }
            // row 4
            (Local::New(l), Remote::Absent, _) => {
                if up {
                    self.upload(l, b, None, None, false)
                } else {
                    Self::skip(key, &l.rel, SkipReason::LocalOnly)
                }
            }
            // rows 6 and 7
            (Local::New(l) | Local::Changed(l), Remote::New | Remote::Changed, Some(r)) => {
                if Self::equal(l, b, r) {
                    Self::record(l, b, r)
                } else if up {
                    self.upload(l, b, Some(r), b.map(|b| b.remote_stamp), true)
                } else {
                    self.download(Some(l), r, true)
                }
            }
            // rows 5, 8 and 10
            (Local::Absent, Remote::New | Remote::Same | Remote::Changed, Some(r)) => {
                if !up {
                    self.download(None, r, false)
                } else if remote == Remote::New {
                    Self::skip(key, &r.rel, SkipReason::RemoteOnly)
                } else if remote == Remote::Changed {
                    Self::skip(key, &r.rel, SkipReason::RemoteNewer)
                } else if sync {
                    Action::DelRemote {
                        key: key.to_string(),
                        remote_path: r.head.path.clone(),
                        base: r.head.stamp,
                    }
                } else {
                    return None;
                }
            }
            // row 9
            (Local::Same(l), Remote::Absent, _) => {
                if !up {
                    if !sync {
                        return None;
                    }
                    Action::DelLocal {
                        key: l.key.clone(),
                        rel: rel_of(l),
                        expect_local: l.sig,
                        is_dir: l.kind == EntryKind::Dir,
                    }
                } else if force {
                    self.upload(l, b, None, None, false)
                } else {
                    Self::skip(key, &l.rel, SkipReason::RemoteDeleted)
                }
            }
            // row 11
            (Local::Changed(l), Remote::Absent, _) => {
                if up {
                    self.upload(l, b, None, None, false)
                } else {
                    Self::skip(key, &l.rel, SkipReason::LocalChanged)
                }
            }
            // row 12
            (Local::Absent, Remote::Absent, _) => {
                b?;
                Action::ForgetBase {
                    key: key.to_string(),
                }
            }
            // `New` means "no base row", which makes the remote side `New` or `Absent`; the
            // remaining pairs cannot be built from one (L, R, B) triple.
            (Local::New(_), Remote::Same, _)
            | (Local::Same(_), Remote::New, _)
            | (_, Remote::Same | Remote::Changed | Remote::New, None) => return None,
        };
        Some(action)
    }
}

/// §5.5 exactly; asserts `base.is_some() ⇒ remote_path == R.path`.
pub fn plan(input: &PlanInput<'_>) -> Plan {
    let fold = input.local.fold_case;
    let up = input.direction == Direction::Up;
    let locals: BTreeMap<&str, &LocalEntry> = input
        .local
        .entries
        .iter()
        .map(|e| (e.key.as_str(), e))
        .collect();
    let remotes: BTreeMap<&str, &RemoteRow> =
        input.remote.iter().map(|r| (r.key.as_str(), r)).collect();
    let bases: BTreeMap<&str, &BaseRow> = input.base.iter().map(|b| (b.key.as_str(), b)).collect();
    let collisions: BTreeSet<&str> = input
        .local
        .collisions
        .iter()
        .chain(input.remote_collisions)
        .map(String::as_str)
        .collect();
    let keys: BTreeSet<&str> = locals
        .keys()
        .chain(remotes.keys())
        .chain(bases.keys())
        .chain(collisions.iter())
        .copied()
        .collect();
    let as_keys = |rels: &[String]| -> Vec<String> {
        rels.iter().map(|rel| path::cmp_key(rel, fold)).collect()
    };
    let failed = as_keys(&input.local.failed_dirs);
    let unsupported = as_keys(&input.local.skipped_paths);

    let planner = Planner {
        input,
        up,
        sync: input.mode == Mode::Sync,
        remote_dirs: dir_spellings(input.remote.iter().map(|r| {
            (
                r.key.as_str(),
                r.rel.as_str(),
                r.head.entry.kind == EntryKind::Dir,
            )
        })),
        local_dirs: dir_spellings(
            input
                .local
                .entries
                .iter()
                .map(|e| (e.key.as_str(), e.rel.as_str(), e.kind == EntryKind::Dir)),
        ),
    };

    let mut out = Plan {
        dest_total: if up {
            input.remote.len() as u64
        } else {
            input.local.entries.len() as u64
        },
        ..Plan::default()
    };
    // Local empty directories whose remote side has entries under it, with the position their
    // action would take in `out.actions` (sorted by key).
    let mut emptied: Vec<(usize, &LocalEntry)> = Vec::new();
    for &key in &keys {
        let (l, r, b) = (
            locals.get(key).copied(),
            remotes.get(key).copied(),
            bases.get(key).copied(),
        );
        // The spelling to report the key under: local first.
        let rel_hint = l
            .map(|l| l.rel.as_str())
            .or(b.map(|b| b.rel.as_str()))
            .or(r.map(|r| r.rel.as_str()))
            .unwrap_or(key);
        // G5: never pick one of two spellings silently.
        if collisions.contains(key) {
            out.actions
                .push(Planner::skip(key, rel_hint, SkipReason::KeyCollision));
            continue;
        }
        // A directory is an entry only while it is empty, so an empty-directory entry on one
        // side can face a directory that merely has content on the other: both sides have
        // the directory, and nothing is to be done for the marker.
        if let (None, Some(r)) = (l, r)
            && r.head.entry.kind == EntryKind::Dir
            && has_under(&locals, key)
        {
            // Remembered as a synced directory, so that removing it locally later deletes
            // the marker (row 8). A directory row is compared by kind only; it has no
            // signature worth recording.
            let rel = planner.local_dirs.get(key).copied().unwrap_or(&r.rel);
            // The remote says the directory exists: a delete of this run that empties it must
            // not take the directory with it — the next upload would read that as the user
            // removing it and delete the marker for every device.
            out.keep_dirs.push(rel.to_string());
            if !b.is_some_and(|b| b.kind == EntryKind::Dir && b.remote_stamp == r.head.stamp) {
                out.actions.push(Action::RecordBase {
                    key: key.to_string(),
                    rel: rel.to_string(),
                    sig: StatSig {
                        size: 0,
                        mtime_ns: 0,
                        ctime_ns: 0,
                        ino: 0,
                        mode: 0o040000,
                    },
                    observed_ns: 0,
                    hash: [0; 32],
                    kind: EntryKind::Dir,
                    remote_stamp: r.head.stamp,
                });
            }
            continue;
        }
        if let (Some(l), None) = (l, r)
            && l.kind == EntryKind::Dir
            && has_under(&remotes, key)
        {
            // Unless this very run deletes everything the remote has under it (decided below,
            // once those keys are planned): then the remote directory would vanish with its
            // last entry while the local one lives on, empty.
            if up && planner.sync && !at_or_under(key, &failed) && !l.changed_during_scan {
                emptied.push((out.actions.len(), l));
            }
            continue;
        }
        let local = if at_or_under(key, &failed) || l.is_some_and(|l| l.changed_during_scan) {
            Local::Unknown(SkipReason::ScanError)
        } else if b.is_some() && at_or_under(key, &unsupported) {
            Local::Unknown(SkipReason::Unsupported(
                "replaced by a symlink or a special file".into(),
            ))
        } else {
            match (l, b) {
                (None, _) => Local::Absent,
                (Some(l), None) => Local::New(l),
                (Some(l), Some(b)) if l.kind != b.kind => Local::Changed(l),
                (Some(l), Some(_)) if l.kind == EntryKind::Dir => Local::Same(l),
                (Some(l), Some(b)) => match Planner::local_hash(l, Some(b)) {
                    Some(hash) if hash == b.hash => Local::Same(l),
                    Some(_) => Local::Changed(l),
                    // Neither hashed nor vouched for by a trusted signature.
                    None => Local::Unknown(SkipReason::ScanError),
                },
            }
        };
        let remote = match (r, b) {
            (None, _) => Remote::Absent,
            (Some(_), None) => Remote::New,
            (Some(r), Some(b)) if r.head.stamp == b.remote_stamp => Remote::Same,
            (Some(_), Some(_)) => Remote::Changed,
        };
        if let (Local::Changed(l), Some(b)) = (&local, b)
            && l.kind == EntryKind::File
            && b.kind == EntryKind::File
        {
            out.changed_local += 1;
            if l.sig.mtime_ns < b.sig.mtime_ns {
                out.suspicious_reverts += 1;
            }
        }
        out.actions
            .extend(planner.decide(key, rel_hint, local, remote, r, b));
    }

    // A local directory that this upload empties remotely — every remote entry under it is a
    // `DelRemote` of this plan — gets its marker in the same run. Without it the vault would
    // lose the directory, the other devices would prune theirs, and only the next upload would
    // bring it back (as a new directory, which a download here in between reports as "only
    // local"). If the deletes are suppressed (§5.7 step 3) the marker merely faces content.
    let markers: Vec<(usize, Action)> = {
        let deleted: HashSet<&str> = out
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::DelRemote { key, .. } => Some(key.as_str()),
                _ => None,
            })
            .collect();
        emptied
            .into_iter()
            .filter(|(_, l)| {
                let prefix = format!("{}/", l.key);
                remotes
                    .range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
                    .take_while(|(k, _)| k.starts_with(&prefix))
                    .all(|(k, _)| deleted.contains(k))
            })
            .map(|(at, l)| (at, planner.upload(l, None, None, None, false)))
            .collect()
    };
    // Back to front: the positions were taken before any of these insertions.
    for (at, action) in markers.into_iter().rev() {
        out.actions.insert(at, action);
    }

    type_changes(input, &locals, &remotes, &mut out);
    out.deletes = out.actions.iter().filter(|a| a.is_delete()).count() as u64;
    out
}

/// Whether `map` has a key under `key/`.
fn has_under<T>(map: &BTreeMap<&str, T>, key: &str) -> bool {
    let prefix = format!("{key}/");
    map.range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
        .next()
        .is_some_and(|(k, _)| k.starts_with(&prefix))
}

/// §5.5.1 "Type changes": every key that is a file on one side while the other side has
/// entries under it becomes an ordered group, or — where the old type cannot be removed
/// completely — a set of skips.
fn type_changes(
    input: &PlanInput<'_>,
    locals: &BTreeMap<&str, &LocalEntry>,
    remotes: &BTreeMap<&str, &RemoteRow>,
    out: &mut Plan,
) {
    let up = input.direction == Direction::Up;
    let index: HashMap<String, usize> = out
        .actions
        .iter()
        .enumerate()
        .map(|(i, a)| (a.key().to_string(), i))
        .collect();
    fn under<'m, T>(map: &'m BTreeMap<&str, T>, key: &str) -> Vec<&'m str> {
        let prefix = format!("{key}/");
        map.range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
            .take_while(|(k, _)| k.starts_with(&prefix))
            .map(|(k, _)| *k)
            .collect()
    }
    // (keys of the old type at the destination, keys of the new type coming from the source)
    let mut changes: Vec<(Vec<&str>, Vec<&str>, bool)> = Vec::new();
    for (&key, l) in locals {
        if l.kind != EntryKind::File {
            continue;
        }
        let children = under(remotes, key);
        if !children.is_empty() {
            changes.push(if up {
                (children, vec![key], false)
            } else {
                (vec![key], children, false)
            });
        }
    }
    for (&key, r) in remotes {
        if r.head.entry.kind != EntryKind::File {
            continue;
        }
        let children = under(locals, key);
        if !children.is_empty() {
            changes.push(if up {
                (vec![key], children, false)
            } else {
                // The local directory itself goes once its children are gone.
                (children, vec![key], true)
            });
        }
    }

    let mut claimed: HashSet<usize> = HashSet::new();
    for (old, new, replaces_dir) in changes {
        let then: Vec<usize> = new
            .iter()
            .filter_map(|k| index.get(*k).copied())
            .filter(|&i| {
                matches!(
                    (&out.actions[i], up),
                    (
                        Action::Upload { .. } | Action::Reuse { .. } | Action::MkdirRemote { .. },
                        true
                    ) | (Action::Download { .. } | Action::MkdirLocal { .. }, false)
                )
            })
            .collect();
        if then.is_empty() {
            continue;
        }
        let refuse = |out: &mut Plan, reason: SkipReason| {
            for &i in &then {
                let (key, rel) = match &out.actions[i] {
                    Action::Upload { key, rel, .. }
                    | Action::Reuse { key, rel, .. }
                    | Action::MkdirRemote { key, rel, .. }
                    | Action::Download { key, rel, .. }
                    | Action::MkdirLocal { key, rel, .. } => (key.clone(), rel.clone()),
                    _ => continue,
                };
                out.actions[i] = Action::Skip {
                    key,
                    rel,
                    reason: reason.clone(),
                };
            }
        };
        if input.mode == Mode::Copy {
            // copy cannot delete the old type.
            refuse(out, SkipReason::Unsupported("type change: use sync".into()));
            continue;
        }
        // The new type may only arrive once every entry of the old type is being deleted.
        let first: Vec<usize> = old
            .iter()
            .filter_map(|k| index.get(*k).copied())
            .filter(|&i| out.actions[i].is_delete())
            .collect();
        let overlap = first.iter().chain(&then).any(|i| claimed.contains(i));
        if first.len() != old.len() || overlap {
            refuse(out, SkipReason::UnsafeTarget);
            continue;
        }
        if replaces_dir {
            for &i in &then {
                if let Action::Download { expect_local, .. } = &mut out.actions[i] {
                    *expect_local = LocalExpect::EmptyDir;
                }
            }
        }
        claimed.extend(first.iter().chain(&then));
        out.groups.push(TypeChange { first, then });
    }
}

/// G2–G4. G4 → `DeleteLimit` for the default thresholds (the caller may confirm), `MaxDelete`
/// for an explicit `max_delete` (a hard limit: no confirmation). G2 and G3 judge the local tree
/// as a **source**, so they apply to uploads only, and `--force` overrides them.
pub fn check_guards(
    plan: &Plan,
    input: &PlanInput<'_>,
    max_delete: Option<u64>,
) -> Result<(), GuardKind> {
    if input.direction == Direction::Up && !input.force {
        let local = input.local;
        if local.root_missing || (local.entries.is_empty() && !input.base.is_empty()) {
            return Err(GuardKind::EmptySource);
        }
        if plan.changed_local >= 10 && 2 * plan.suspicious_reverts > plan.changed_local {
            return Err(GuardKind::RevertedTree {
                suspicious: plan.suspicious_reverts,
            });
        }
    }
    let (deletes, total) = (plan.deletes, plan.dest_total);
    match max_delete {
        // An explicit limit is a hard one: the caller must not offer a confirmation.
        Some(limit) if deletes > limit => Err(GuardKind::MaxDelete { deletes, limit }),
        Some(_) => Ok(()),
        None if deletes > MAX_DELETE_ABS || (deletes >= 10 && 4 * deletes > total) => {
            Err(GuardKind::DeleteLimit { deletes, total })
        }
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::scan::{Filter, SkipCounts, filter_base};
    use super::*;
    use crate::test_prng::{Prng, for_each_seed};
    use crate::types::{BlobId, DeviceId, Loc};
    use Direction::{Down, Up};
    use Mode::{Copy, Sync};

    const S: i64 = 1_000_000_000;

    fn stamp(lamport: u64) -> Stamp {
        Stamp {
            lamport,
            device: DeviceId([7; 8]),
            idx: 0,
        }
    }

    fn hash(content: &str) -> [u8; 32] {
        *blake3::hash(content.as_bytes()).as_bytes()
    }

    fn sig(size: u64, mtime_s: i64) -> StatSig {
        StatSig {
            size,
            mtime_ns: mtime_s * S,
            ctime_ns: mtime_s * S,
            ino: 42,
            mode: 0o100644,
        }
    }

    /// A hashed local file; `mtime_s` distinguishes signatures.
    fn lfile(rel: &str, content: &str, mtime_s: i64) -> LocalEntry {
        LocalEntry {
            rel: rel.to_string(),
            key: rel.to_string(),
            kind: EntryKind::File,
            sig: sig(content.len() as u64, mtime_s),
            observed_ns: (mtime_s + 100) * S,
            hash: Some(hash(content)),
            changed_during_scan: false,
        }
    }

    fn ldir(rel: &str) -> LocalEntry {
        LocalEntry {
            kind: EntryKind::Dir,
            hash: None,
            sig: StatSig {
                mode: 0o040755,
                ..sig(64, 1000)
            },
            ..lfile(rel, "", 1000)
        }
    }

    fn entry(content: &str, mtime_s: i64) -> Entry {
        Entry {
            kind: EntryKind::File,
            size: content.len() as u64,
            mtime_ns: mtime_s * S,
            exec: false,
            hash: hash(content),
            loc: (!content.is_empty()).then(|| Loc {
                blob: BlobId([3; 16]),
                off: 0,
                clen: content.len() as u64 + 76,
                salt: [1; 16],
                chunk_log2: 16,
                epoch: 1,
                suite: 1,
                flags: 0,
            }),
        }
    }

    fn rrow(rel: &str, e: Entry, lamport: u64) -> RemoteRow {
        RemoteRow {
            rel: rel.to_string(),
            key: rel.to_string(),
            head: Head {
                path: rel.to_string(),
                stamp: stamp(lamport),
                entry: e,
                origin: None,
                winner: true,
            },
        }
    }

    fn rfile(rel: &str, content: &str, mtime_s: i64, lamport: u64) -> RemoteRow {
        rrow(rel, entry(content, mtime_s), lamport)
    }

    fn rdir(rel: &str, lamport: u64) -> RemoteRow {
        rrow(rel, Entry::dir(), lamport)
    }

    /// A trusted base row for a file with `content` last seen with mtime `mtime_s`.
    fn brow(rel: &str, content: &str, mtime_s: i64, lamport: u64) -> BaseRow {
        BaseRow {
            key: rel.to_string(),
            rel: rel.to_string(),
            kind: EntryKind::File,
            sig: sig(content.len() as u64, mtime_s),
            hash: hash(content),
            remote_stamp: stamp(lamport),
            observed_ns: (mtime_s + 100) * S,
        }
    }

    fn bdir(rel: &str, lamport: u64) -> BaseRow {
        BaseRow {
            kind: EntryKind::Dir,
            sig: ldir(rel).sig,
            hash: [0; 32],
            ..brow(rel, "", 1000, lamport)
        }
    }

    #[derive(Default)]
    struct World {
        fold: bool,
        prefix: String,
        local: Vec<LocalEntry>,
        remote: Vec<RemoteRow>,
        base: Vec<BaseRow>,
        failed_dirs: Vec<String>,
        skipped_paths: Vec<String>,
        local_collisions: Vec<String>,
        remote_collisions: Vec<String>,
        reuse: HashMap<(u64, [u8; 32]), Head>,
        root_missing: bool,
    }

    impl World {
        fn scan(&self) -> LocalScan {
            let mut entries = self.local.clone();
            entries.sort_by(|a, b| a.key.cmp(&b.key));
            LocalScan {
                root: "/nowhere".into(),
                root_ino: 1,
                root_birth_ns: 1,
                fold_case: self.fold,
                entries,
                failed_dirs: self.failed_dirs.clone(),
                skipped_paths: self.skipped_paths.clone(),
                collisions: self.local_collisions.clone(),
                excluded: Vec::new(),
                skipped: SkipCounts::default(),
                root_missing: self.root_missing,
            }
        }

        fn with<T>(
            &self,
            d: Direction,
            m: Mode,
            force: bool,
            f: impl FnOnce(&PlanInput<'_>) -> T,
        ) -> T {
            let scan = self.scan();
            let mut remote = self.remote.clone();
            remote.sort_by(|a, b| a.key.cmp(&b.key));
            let mut base = self.base.clone();
            base.sort_by(|a, b| a.key.cmp(&b.key));
            f(&PlanInput {
                direction: d,
                mode: m,
                force,
                remote_prefix: &self.prefix,
                local: &scan,
                remote: &remote,
                remote_collisions: &self.remote_collisions,
                base: &base,
                reuse: &self.reuse,
            })
        }

        fn plan(&self, d: Direction, m: Mode, force: bool) -> Plan {
            self.with(d, m, force, plan)
        }

        fn guards(
            &self,
            d: Direction,
            m: Mode,
            force: bool,
            max: Option<u64>,
        ) -> Result<(), GuardKind> {
            self.with(d, m, force, |input| check_guards(&plan(input), input, max))
        }
    }

    fn st(s: &Option<Stamp>) -> String {
        s.map_or("-".to_string(), |s| s.lamport.to_string())
    }

    fn expect(e: &LocalExpect) -> &'static str {
        match e {
            LocalExpect::Absent => "absent",
            LocalExpect::File(_) => "file",
            LocalExpect::EmptyDir => "emptydir",
        }
    }

    /// One action as a short line, so a decision table reads like the one in the spec.
    fn shape(a: &Action) -> String {
        match a {
            Action::Upload {
                remote_path,
                base,
                conflict,
                ..
            } => format!(
                "upload {remote_path} base={}{}",
                st(base),
                if *conflict { " conflict" } else { "" }
            ),
            Action::Reuse {
                remote_path,
                base,
                from,
                ..
            } => format!("reuse {remote_path} base={} from={}", st(base), from.path),
            Action::MkdirRemote {
                remote_path, base, ..
            } => format!("mkdir-remote {remote_path} base={}", st(base)),
            Action::SetRemoteMeta {
                remote_path, base, ..
            } => format!("meta-remote {remote_path} base={}", base.lamport),
            Action::DelRemote {
                remote_path, base, ..
            } => format!("del-remote {remote_path} base={}", base.lamport),
            Action::Download {
                rel,
                expect_local,
                keep_local,
                ..
            } => format!(
                "download {rel} expect={}{}",
                expect(expect_local),
                if *keep_local { " keep" } else { "" }
            ),
            Action::MkdirLocal {
                rel, expect_local, ..
            } => format!("mkdir-local {rel} expect={}", expect(expect_local)),
            Action::SetLocalMeta { rel, .. } => format!("meta-local {rel}"),
            Action::DelLocal { rel, is_dir, .. } => {
                format!("del-local {rel}{}", if *is_dir { " dir" } else { "" })
            }
            Action::RecordBase {
                rel, remote_stamp, ..
            } => format!("record {rel} stamp={}", remote_stamp.lamport),
            Action::ForgetBase { key } => format!("forget {key}"),
            Action::Skip { rel, reason, .. } => format!("skip {rel} {reason:?}"),
        }
    }

    fn shapes(p: &Plan) -> Vec<String> {
        p.actions.iter().map(shape).collect()
    }

    const ALL: [(Direction, Mode, bool); 8] = [
        (Up, Copy, false),
        (Up, Copy, true),
        (Up, Sync, false),
        (Up, Sync, true),
        (Down, Copy, false),
        (Down, Copy, true),
        (Down, Sync, false),
        (Down, Sync, true),
    ];

    /// Asserts the single-key outcome for every direction × mode × force.
    fn row(name: &str, w: &World, want: impl Fn(Direction, Mode, bool) -> &'static str) {
        for (d, m, force) in ALL {
            let got = shapes(&w.plan(d, m, force));
            let want = want(d, m, force);
            let want: Vec<String> = if want.is_empty() {
                Vec::new()
            } else {
                vec![want.to_string()]
            };
            assert_eq!(got, want, "{name}: {d:?} {m:?} force={force}");
        }
    }

    // The fixtures of the single-key table: base = content "base" at mtime 1000 s, stamp 5.
    fn l_same() -> LocalEntry {
        LocalEntry {
            hash: None,
            ..lfile("f", "base", 1000)
        }
    }
    fn l_changed() -> LocalEntry {
        lfile("f", "local edit", 2000)
    }
    fn l_new() -> LocalEntry {
        lfile("f", "local new", 2000)
    }
    fn base() -> BaseRow {
        brow("f", "base", 1000, 5)
    }
    fn r_same() -> RemoteRow {
        rfile("f", "base", 1000, 5)
    }
    fn r_changed() -> RemoteRow {
        rfile("f", "remote edit", 3000, 9)
    }
    fn r_new() -> RemoteRow {
        rfile("f", "remote new", 3000, 9)
    }

    fn world(l: Option<LocalEntry>, r: Option<RemoteRow>, b: Option<BaseRow>) -> World {
        World {
            local: l.into_iter().collect(),
            remote: r.into_iter().collect(),
            base: b.into_iter().collect(),
            ..World::default()
        }
    }

    #[test]
    fn row_1_same_same() {
        row(
            "in sync",
            &world(Some(l_same()), Some(r_same()), Some(base())),
            |_, _, _| "",
        );
        // "same" established by hashing (the signature moved, the content did not): the row is
        // refreshed, in both directions and modes.
        let touched = lfile("f", "base", 1001);
        row(
            "refresh after a re-hash",
            &world(Some(touched), Some(r_same()), Some(base())),
            |_, _, _| "record f stamp=5",
        );
        // An untrusted row (observed inside the racy window) with an equal signature.
        let racy = BaseRow {
            observed_ns: 1001 * S,
            ..base()
        };
        row(
            "refresh of a racy row",
            &world(
                Some(lfile("f", "base", 1000)),
                Some(r_same()),
                Some(racy.clone()),
            ),
            |_, _, _| "record f stamp=5",
        );
        // An untrusted row whose file was not hashed is not taken on trust.
        row(
            "racy row without a hash",
            &world(Some(l_same()), Some(r_same()), Some(racy)),
            |_, _, _| "skip f ScanError",
        );
        // --checksum on a trusted, unchanged file: nothing to record.
        row(
            "checksum, unchanged",
            &world(Some(lfile("f", "base", 1000)), Some(r_same()), Some(base())),
            |_, _, _| "",
        );
    }

    #[test]
    fn row_1_meta_only() {
        // The local file was touched (mtime +2 s or more): same content, new mtime.
        let touched = lfile("f", "base", 1002);
        let w = world(Some(touched), Some(r_same()), Some(base()));
        row("mtime differs by 2 s", &w, |d, _, _| match d {
            Up => "meta-remote f base=5",
            Down => "meta-local f",
        });
        let p = w.plan(Up, Sync, false);
        let Action::SetRemoteMeta { entry, sig, .. } = &p.actions[0] else {
            panic!()
        };
        assert_eq!(entry.mtime_ns, 1002 * S);
        assert_eq!(entry.loc, r_same().head.entry.loc, "index-only: same data");
        assert_eq!(sig.mtime_ns, 1002 * S);
        // Less than 2 s apart: only the base row is refreshed.
        let near = lfile("f", "base", 1001);
        assert_eq!(
            shapes(&world(Some(near), Some(r_same()), Some(base())).plan(Up, Sync, false)),
            ["record f stamp=5"]
        );
        // The exec bit alone.
        let mut exec = l_same();
        exec.sig.mode = 0o100755;
        exec.hash = Some(hash("base"));
        let w = world(Some(exec), Some(r_same()), Some(base()));
        row("exec differs", &w, |d, _, _| match d {
            Up => "meta-remote f base=5",
            Down => "meta-local f",
        });
        let Action::SetRemoteMeta { entry, .. } = &w.plan(Up, Copy, false).actions[0] else {
            panic!()
        };
        assert!(entry.exec);
    }

    #[test]
    fn row_1_pushes_only_metadata_that_changed_here() {
        // The base row was recorded for equal content (rows 3 and 6) while the remote entry
        // carried another mtime, and the local file is still as that row saw it. Upward
        // nothing is pushed: the difference is not this device's change, and a second
        // uploader in the same position would push its own mtime back, run after run.
        // Downward the local file takes the remote metadata, which ends the difference.
        let theirs = rfile("f", "base", 3000, 5);
        let w = world(Some(l_same()), Some(theirs.clone()), Some(base()));
        row("recorded with another mtime", &w, |d, _, _| match d {
            Up => "",
            Down => "meta-local f",
        });
        // The same with a row that had to be confirmed by hashing: refreshed, not pushed.
        let racy = BaseRow {
            observed_ns: 1001 * S,
            ..base()
        };
        let hashed = lfile("f", "base", 1000);
        let w = world(Some(hashed), Some(theirs.clone()), Some(racy));
        row("recorded with another mtime, racy", &w, |d, _, _| match d {
            Up => "record f stamp=5",
            Down => "meta-local f",
        });
        // The exec bit likewise.
        let mut theirs_exec = r_same();
        theirs_exec.head.entry.exec = true;
        let w = world(Some(l_same()), Some(theirs_exec), Some(base()));
        row("recorded with another exec bit", &w, |d, _, _| match d {
            Up => "",
            Down => "meta-local f",
        });
        // A touch after that is this device's change again and goes up.
        let touched = lfile("f", "base", 1500);
        let w = world(Some(touched), Some(theirs), Some(base()));
        row("touched since", &w, |d, _, _| match d {
            Up => "meta-remote f base=5",
            Down => "meta-local f",
        });
    }

    #[test]
    fn row_2_changed_same() {
        row(
            "local edit",
            &world(Some(l_changed()), Some(r_same()), Some(base())),
            |d, _, force| match (d, force) {
                (Up, _) => "upload f base=5",
                (Down, false) => "skip f LocalChanged",
                (Down, true) => "download f expect=file",
            },
        );
    }

    #[test]
    fn row_3_same_changed() {
        row(
            "remote edit",
            &world(Some(l_same()), Some(r_changed()), Some(base())),
            |d, _, force| match (d, force) {
                (Up, false) => "skip f RemoteNewer",
                (Up, true) => "upload f base=9",
                (Down, _) => "download f expect=file",
            },
        );
        // Equal content under a new stamp (another device re-uploaded the same bytes).
        let same_bytes = rfile("f", "base", 1000, 9);
        row(
            "remote changed, equal content",
            &world(Some(l_same()), Some(same_bytes), Some(base())),
            |_, _, _| "record f stamp=9",
        );
        // … with a different mtime: DOWN sets it locally, UP only records.
        let same_bytes_later = rfile("f", "base", 5000, 9);
        row(
            "remote changed, equal content, other mtime",
            &world(Some(l_same()), Some(same_bytes_later), Some(base())),
            |d, _, _| match d {
                Up => "record f stamp=9",
                Down => "meta-local f",
            },
        );
    }

    #[test]
    fn row_4_new_absent() {
        row(
            "local only",
            &world(Some(l_new()), None, None),
            |d, _, _| match d {
                Up => "upload f base=-",
                Down => "skip f LocalOnly",
            },
        );
    }

    #[test]
    fn row_5_absent_new() {
        row(
            "remote only",
            &world(None, Some(r_new()), None),
            |d, _, _| match d {
                Up => "skip f RemoteOnly",
                Down => "download f expect=absent",
            },
        );
    }

    #[test]
    fn row_6_both_changed_equal_content() {
        row(
            "new/new equal",
            &world(
                Some(lfile("f", "twin", 2000)),
                Some(rfile("f", "twin", 3000, 9)),
                None,
            ),
            |_, _, _| "record f stamp=9",
        );
        row(
            "changed/changed equal",
            &world(
                Some(lfile("f", "twin", 2000)),
                Some(rfile("f", "twin", 3000, 9)),
                Some(base()),
            ),
            |_, _, _| "record f stamp=9",
        );
        let p = world(
            Some(lfile("f", "twin", 2000)),
            Some(rfile("f", "twin", 3000, 9)),
            None,
        )
        .plan(Up, Copy, false);
        let Action::RecordBase {
            sig, hash: h, kind, ..
        } = &p.actions[0]
        else {
            panic!()
        };
        assert_eq!(
            (sig.mtime_ns, *h, *kind),
            (2000 * S, hash("twin"), EntryKind::File)
        );
    }

    #[test]
    fn row_7_both_changed_different() {
        row(
            "new/new different",
            &world(Some(l_new()), Some(r_new()), None),
            |d, _, _| match d {
                Up => "upload f base=- conflict",
                Down => "download f expect=file keep",
            },
        );
        // With a base row the Put names the stamp this device last saw — not R's — so the
        // index keeps both versions.
        row(
            "changed/changed different",
            &world(Some(l_changed()), Some(r_changed()), Some(base())),
            |d, _, _| match d {
                Up => "upload f base=5 conflict",
                Down => "download f expect=file keep",
            },
        );
        // A new local file that was not hashed is never taken for equal.
        let unhashed = LocalEntry {
            hash: None,
            ..lfile("f", "remote new", 2000)
        };
        assert_eq!(
            shapes(&world(Some(unhashed), Some(r_new()), None).plan(Down, Sync, true)),
            ["download f expect=file keep"]
        );
    }

    #[test]
    fn row_8_absent_same() {
        row(
            "deleted locally",
            &world(None, Some(r_same()), Some(base())),
            |d, m, _| match (d, m) {
                (Up, Sync) => "del-remote f base=5",
                (Up, Copy) => "",
                (Down, _) => "download f expect=absent",
            },
        );
    }

    #[test]
    fn row_9_same_absent() {
        row(
            "deleted remotely",
            &world(Some(l_same()), None, Some(base())),
            |d, m, force| match (d, m, force) {
                (Up, _, false) => "skip f RemoteDeleted",
                (Up, _, true) => "upload f base=-",
                (Down, Sync, _) => "del-local f",
                (Down, Copy, _) => "",
            },
        );
        let p = world(Some(l_same()), None, Some(base())).plan(Down, Sync, false);
        let Action::DelLocal { expect_local, .. } = &p.actions[0] else {
            panic!()
        };
        assert_eq!(*expect_local, l_same().sig);
    }

    #[test]
    fn row_10_absent_changed() {
        row(
            "deleted locally, changed remotely",
            &world(None, Some(r_changed()), Some(base())),
            |d, _, _| match d {
                Up => "skip f RemoteNewer",
                Down => "download f expect=absent",
            },
        );
    }

    #[test]
    fn row_11_changed_absent() {
        row(
            "changed locally, deleted remotely",
            &world(Some(l_changed()), None, Some(base())),
            |d, _, _| match d {
                Up => "upload f base=-",
                Down => "skip f LocalChanged",
            },
        );
    }

    #[test]
    fn row_12_absent_absent() {
        row(
            "gone on both sides",
            &world(None, None, Some(base())),
            |_, _, _| "forget f",
        );
    }

    #[test]
    fn row_13_unknown() {
        // Under a directory that could not be read: whatever the other side says.
        for (r, b) in [
            (Some(r_same()), Some(base())),
            (Some(r_changed()), Some(base())),
            (None, Some(base())),
            (Some(r_new()), None),
        ] {
            let mut w = world(None, r, b);
            w.failed_dirs = vec![String::new()];
            row("unreadable root", &w, |_, _, _| "skip f ScanError");
        }
        let mut w = world(
            None,
            Some(rfile("d/f", "base", 1000, 5)),
            Some(brow("d/f", "base", 1000, 5)),
        );
        w.failed_dirs = vec!["d".into()];
        row("unreadable directory", &w, |_, _, _| "skip d/f ScanError");
        w.failed_dirs = vec!["dx".into()];
        assert_eq!(shapes(&w.plan(Up, Sync, false)), ["del-remote d/f base=5"]);

        // Changed while it was hashed.
        let mut moving = l_changed();
        moving.changed_during_scan = true;
        row(
            "changed during the scan",
            &world(Some(moving), Some(r_same()), Some(base())),
            |_, _, _| "skip f ScanError",
        );

        // A synced file replaced by a FIFO, a synced directory replaced by a symlink.
        let mut w = world(None, Some(r_same()), Some(base()));
        w.skipped_paths = vec!["f".into()];
        row(
            "replaced by a special file",
            &w,
            |_, _, _| "skip f Unsupported(\"replaced by a symlink or a special file\")",
        );
        let mut w = World {
            remote: vec![
                rfile("d/a", "base", 1000, 5),
                rfile("d/sub/b", "base", 1000, 6),
            ],
            base: vec![
                brow("d/a", "base", 1000, 5),
                brow("d/sub/b", "base", 1000, 6),
            ],
            skipped_paths: vec!["d".into()],
            ..World::default()
        };
        for (d, m, force) in ALL {
            let p = w.plan(d, m, force);
            assert_eq!(p.deletes, 0);
            assert!(p.actions.iter().all(|a| matches!(
                a,
                Action::Skip {
                    reason: SkipReason::Unsupported(_),
                    ..
                }
            )));
            assert_eq!(p.actions.len(), 2);
        }
        // Without a base row the key is simply absent locally (§5.5 classification).
        w.base.clear();
        assert_eq!(
            shapes(&w.plan(Up, Sync, false)),
            ["skip d/a RemoteOnly", "skip d/sub/b RemoteOnly"]
        );
    }

    #[test]
    fn dir_rows() {
        // row 4 / 5 for empty directories
        row(
            "new local dir",
            &world(Some(ldir("f")), None, None),
            |d, _, _| match d {
                Up => "mkdir-remote f base=-",
                Down => "skip f LocalOnly",
            },
        );
        row(
            "new remote dir",
            &world(None, Some(rdir("f", 9)), None),
            |d, _, _| match d {
                Up => "skip f RemoteOnly",
                Down => "mkdir-local f expect=absent",
            },
        );
        // rows 1 and 6: a directory equals a directory
        row(
            "dir in sync",
            &world(Some(ldir("f")), Some(rdir("f", 5)), Some(bdir("f", 5))),
            |_, _, _| "",
        );
        row(
            "dir on both sides, first sync",
            &world(Some(ldir("f")), Some(rdir("f", 9)), None),
            |_, _, _| "record f stamp=9",
        );
        // rows 8 / 9: DelRemote / RmdirLocal (never recursive)
        row(
            "dir removed locally",
            &world(None, Some(rdir("f", 5)), Some(bdir("f", 5))),
            |d, m, _| match (d, m) {
                (Up, Sync) => "del-remote f base=5",
                (Up, Copy) => "",
                (Down, _) => "mkdir-local f expect=absent",
            },
        );
        row(
            "dir removed remotely",
            &world(Some(ldir("f")), None, Some(bdir("f", 5))),
            |d, m, force| match (d, m, force) {
                (Up, _, false) => "skip f RemoteDeleted",
                (Up, _, true) => "mkdir-remote f base=-",
                (Down, Sync, _) => "del-local f dir",
                (Down, Copy, _) => "",
            },
        );
    }

    #[test]
    fn an_empty_directory_marker_faces_a_directory_with_content() {
        // Remote has the marker `d`; locally `d` has a file, so it is no entry.
        let mut w = World {
            local: vec![lfile("d/new", "n", 1)],
            remote: vec![rdir("d", 5)],
            ..World::default()
        };
        for (d, m, force) in ALL {
            let want = match d {
                Up => ["record d stamp=5", "upload d/new base=-"],
                Down => ["record d stamp=5", "skip d/new LocalOnly"],
            };
            let p = w.plan(d, m, force);
            assert_eq!(shapes(&p), want);
            // The directory must outlive its content: the remote says it exists.
            assert_eq!(p.keep_dirs, ["d"]);
        }
        // Once the marker is remembered nothing more is done for it — in particular it is
        // not deleted while the directory lives on (row 8 does not apply) …
        w.base = vec![bdir("d", 5)];
        assert_eq!(shapes(&w.plan(Up, Sync, false)), ["upload d/new base=-"]);
        // The last synced file under it was deleted remotely: the file goes, and the
        // executor is told to leave the emptied directory, which the marker still names.
        let emptied = World {
            local: vec![l_same_at("d/a"), l_same_at("d/e/b"), l_same_at("other/c")],
            remote: vec![rdir("d", 5)],
            base: vec![
                bdir("d", 5),
                brow("d/a", "base", 1000, 5),
                brow("d/e/b", "base", 1000, 5),
                brow("other/c", "base", 1000, 5),
            ],
            ..World::default()
        };
        let p = emptied.plan(Down, Sync, false);
        assert_eq!(p.deletes, 3, "{:?}", shapes(&p));
        assert_eq!(p.keep_dirs, ["d"]);
        // … until the directory is gone locally.
        w.local.clear();
        assert!(w.plan(Up, Sync, true).keep_dirs.is_empty());
        assert_eq!(shapes(&w.plan(Up, Sync, true)), ["del-remote d base=5"]);
        assert_eq!(
            shapes(&w.plan(Down, Sync, false)),
            ["mkdir-local d expect=absent"]
        );
        // Local empty directory, remote content under it.
        let w = World {
            local: vec![ldir("d")],
            remote: vec![rfile("d/x", "x", 1, 5)],
            base: vec![bdir("d", 4)],
            ..World::default()
        };
        row("local marker, remote content", &w, |d, _, _| match d {
            Up => "skip d/x RemoteOnly",
            Down => "download d/x expect=absent",
        });
    }

    #[test]
    fn a_directory_emptied_by_the_upload_gets_its_marker_in_the_same_run() {
        // `d/e/f` and `d/g` were synced and are gone locally; `d` is left, empty.
        let mut w = World {
            local: vec![ldir("d"), l_same_at("other")],
            remote: vec![
                rfile("d/e/f", "base", 1000, 5),
                rfile("d/g", "base", 1000, 5),
                rfile("other", "base", 1000, 5),
            ],
            base: vec![
                brow("d/e/f", "base", 1000, 5),
                brow("d/g", "base", 1000, 5),
                brow("other", "base", 1000, 5),
            ],
            ..World::default()
        };
        let p = w.plan(Up, Sync, false);
        assert_eq!(
            shapes(&p),
            [
                "mkdir-remote d base=-",
                "del-remote d/e/f base=5",
                "del-remote d/g base=5"
            ]
        );
        check_structure(&w, &p, Up);
        // copy deletes nothing, so the remote directory keeps its content: no marker.
        assert!(shapes(&w.plan(Up, Copy, false)).is_empty());
        // A download brings the files back instead.
        assert_eq!(
            shapes(&w.plan(Down, Sync, false)),
            ["download d/e/f expect=absent", "download d/g expect=absent"]
        );
        // One remote entry under it stays (never synced here): the directory lives on remotely.
        w.remote.push(rfile("d/theirs", "t", 1, 6));
        assert_eq!(
            shapes(&w.plan(Up, Sync, false)),
            [
                "del-remote d/e/f base=5",
                "del-remote d/g base=5",
                "skip d/theirs RemoteOnly"
            ]
        );
    }

    #[test]
    fn type_change_within_one_key() {
        // Remote Dir, local file that was in sync as a file → the directory replaces exactly
        // that file; the other way round the empty directory is replaced.
        row(
            "file → remote dir",
            &world(Some(l_same()), Some(rdir("f", 9)), Some(base())),
            |d, _, force| match (d, force) {
                (Up, false) => "skip f RemoteNewer",
                (Up, true) => "upload f base=9",
                (Down, _) => "mkdir-local f expect=file",
            },
        );
        row(
            "empty dir → remote file",
            &world(Some(ldir("f")), Some(r_changed()), Some(bdir("f", 5))),
            |d, _, force| match (d, force) {
                (Up, false) => "skip f RemoteNewer",
                (Up, true) => "mkdir-remote f base=9",
                (Down, _) => "download f expect=emptydir",
            },
        );
        // The local side changed type and the remote did not.
        row(
            "local file became an empty dir",
            &world(Some(ldir("f")), Some(r_same()), Some(base())),
            |d, _, force| match (d, force) {
                (Up, _) => "mkdir-remote f base=5",
                (Down, false) => "skip f LocalChanged",
                (Down, true) => "download f expect=emptydir",
            },
        );
        row(
            "local empty dir became a file",
            &world(Some(l_new()), Some(rdir("f", 5)), Some(bdir("f", 5))),
            |d, _, force| match (d, force) {
                (Up, _) => "upload f base=5",
                (Down, false) => "skip f LocalChanged",
                (Down, true) => "mkdir-local f expect=file",
            },
        );
        // Unsynced on both sides: nothing local is ever unlinked — a file is moved aside
        // (expect = absent tells the executor so), a directory is only ever rmdir'ed.
        row(
            "new file vs new remote dir",
            &world(Some(l_new()), Some(rdir("f", 9)), None),
            |d, _, _| match d {
                Up => "upload f base=- conflict",
                Down => "mkdir-local f expect=absent",
            },
        );
        row(
            "new dir vs new remote file",
            &world(Some(ldir("f")), Some(r_new()), None),
            |d, _, _| match d {
                Up => "mkdir-remote f base=-",
                Down => "download f expect=emptydir",
            },
        );
    }

    #[test]
    fn reuse_selection() {
        let donor = rfile("elsewhere/x", "local new", 1, 3).head;
        let mut w = world(Some(l_new()), None, None);
        w.reuse.insert((9, hash("local new")), donor.clone());
        let p = w.plan(Up, Copy, false);
        assert_eq!(shapes(&p), ["reuse f base=- from=elsewhere/x"]);
        let Action::Reuse {
            from, sig, hash: h, ..
        } = &p.actions[0]
        else {
            panic!()
        };
        assert_eq!((from, sig.size, *h), (&donor, 9, hash("local new")));
        // Not downward, not for another size or hash, not without a hash, not for empty files.
        assert_eq!(shapes(&w.plan(Down, Copy, false)), ["skip f LocalOnly"]);
        w.local = vec![lfile("f", "local neW", 2000)];
        assert_eq!(shapes(&w.plan(Up, Copy, false)), ["upload f base=-"]);
        w.local = vec![LocalEntry {
            hash: None,
            ..l_new()
        }];
        assert_eq!(shapes(&w.plan(Up, Copy, false)), ["upload f base=-"]);
        w.local = vec![lfile("f", "", 2000)];
        w.reuse.insert((0, hash("")), donor.clone());
        assert_eq!(shapes(&w.plan(Up, Copy, false)), ["upload f base=-"]);

        // Every row that uploads can reuse: row 2 keeps its base, row 3/9 with --force use the
        // hash of the base row for an unhashed, unchanged file.
        let mut w = world(Some(l_changed()), Some(r_same()), Some(base()));
        w.reuse.insert((10, hash("local edit")), donor.clone());
        assert_eq!(
            shapes(&w.plan(Up, Sync, false)),
            ["reuse f base=5 from=elsewhere/x"]
        );
        let mut w = world(Some(l_same()), None, Some(base()));
        w.reuse.insert((4, hash("base")), donor);
        assert_eq!(
            shapes(&w.plan(Up, Sync, true)),
            ["reuse f base=- from=elsewhere/x"]
        );
    }

    #[test]
    fn remote_prefix_and_paths() {
        let mut w = World {
            prefix: "Photos/2026".into(),
            local: vec![
                lfile("new.jpg", "n", 1),
                lfile("old.jpg", "local edit", 2000),
            ],
            remote: vec![RemoteRow {
                head: Head {
                    path: "Photos/2026/old.jpg".into(),
                    ..rfile("old.jpg", "base", 1000, 5).head
                },
                ..rfile("old.jpg", "base", 1000, 5)
            }],
            base: vec![brow("old.jpg", "base", 1000, 5)],
            ..World::default()
        };
        assert_eq!(
            shapes(&w.plan(Up, Sync, false)),
            [
                "upload Photos/2026/new.jpg base=-",
                "upload Photos/2026/old.jpg base=5"
            ]
        );
        w.local.clear();
        assert_eq!(
            shapes(&w.plan(Up, Sync, false)),
            ["del-remote Photos/2026/old.jpg base=5"]
        );
        assert_eq!(
            shapes(&w.plan(Down, Sync, false)),
            ["download old.jpg expect=absent"]
        );
    }

    // --- spelling (§5.5 "one spelling per key")

    const NFC: &str = "caf\u{e9}.txt";
    const NFD: &str = "cafe\u{301}.txt";

    fn keyed(mut e: LocalEntry, fold: bool) -> LocalEntry {
        e.key = path::cmp_key(&e.rel, fold);
        e
    }
    fn rkeyed(mut r: RemoteRow, fold: bool) -> RemoteRow {
        r.key = path::cmp_key(&r.rel, fold);
        r
    }
    fn bkeyed(mut b: BaseRow, fold: bool) -> BaseRow {
        b.key = path::cmp_key(&b.rel, fold);
        b
    }

    #[test]
    fn nfc_local_and_nfd_remote_are_one_key() {
        // Local NFC file, remote NFD twin, case-sensitive file system.
        let w = World {
            local: vec![keyed(lfile(NFC, "local edit", 2000), false)],
            remote: vec![rkeyed(rfile(NFD, "base", 1000, 5), false)],
            base: vec![bkeyed(brow(NFC, "base", 1000, 5), false)],
            ..World::default()
        };
        // Modified locally, synced up: one remote path — R's.
        assert_eq!(
            shapes(&w.plan(Up, Sync, false)),
            [format!("upload {NFD} base=5")]
        );
        // Modified remotely, synced down: the existing local file is replaced.
        let w = World {
            local: vec![keyed(l_same_at(NFC), false)],
            remote: vec![rkeyed(rfile(NFD, "remote edit", 3000, 9), false)],
            base: vec![bkeyed(brow(NFC, "base", 1000, 5), false)],
            ..World::default()
        };
        assert_eq!(
            shapes(&w.plan(Down, Sync, false)),
            [format!("download {NFC} expect=file")]
        );
        // Deleted locally: the remote twin is deleted under its own spelling.
        let w = World {
            remote: vec![rkeyed(rfile(NFD, "base", 1000, 5), false)],
            base: vec![bkeyed(brow(NFC, "base", 1000, 5), false)],
            ..World::default()
        };
        assert_eq!(
            shapes(&w.plan(Up, Sync, false)),
            [format!("del-remote {NFD} base=5")]
        );
    }

    fn l_same_at(rel: &str) -> LocalEntry {
        LocalEntry {
            hash: None,
            ..lfile(rel, "base", 1000)
        }
    }

    #[test]
    fn new_entries_take_the_destinations_directory_spelling() {
        // New local file under `Foo/` while the index has `foo/…` (folding file system).
        let w = World {
            fold: true,
            prefix: "P".into(),
            local: vec![
                keyed(l_same_at("Foo/a"), true),
                keyed(lfile("Foo/new", "n", 1), true),
                keyed(lfile("Foo/Sub/Deep/x", "n", 1), true),
                keyed(lfile("Other/y", "n", 1), true),
            ],
            remote: vec![
                rkeyed(
                    RemoteRow {
                        head: Head {
                            path: "P/foo/a".into(),
                            ..rfile("foo/a", "base", 1000, 5).head
                        },
                        ..rfile("foo/a", "base", 1000, 5)
                    },
                    true,
                ),
                rkeyed(rfile("foo/sub/z", "base", 1000, 6), true),
            ],
            base: vec![bkeyed(brow("Foo/a", "base", 1000, 5), true)],
            ..World::default()
        };
        assert_eq!(
            shapes(&w.plan(Up, Copy, false)),
            [
                "upload P/foo/new base=-",
                "upload P/foo/sub/Deep/x base=-",
                "skip foo/sub/z RemoteOnly",
                "upload P/Other/y base=-",
            ]
        );
        // Downward the existing local directory spelling wins the same way; `foo/a` and
        // `Foo/a` are one key, so nothing is downloaded and deleted in pairs.
        for mode in [Copy, Sync] {
            let p = w.plan(Down, mode, false);
            assert_eq!(
                shapes(&p),
                [
                    "skip Foo/new LocalOnly",
                    "skip Foo/Sub/Deep/x LocalOnly",
                    "download Foo/Sub/z expect=absent",
                    "skip Other/y LocalOnly",
                ]
            );
            assert_eq!(p.deletes, 0);
        }
        // An empty remote directory fixes the spelling of what goes under it, too.
        let w = World {
            fold: true,
            local: vec![keyed(lfile("DOCS/a", "n", 1), true)],
            remote: vec![rkeyed(rdir("Docs", 4), true)],
            ..World::default()
        };
        assert_eq!(
            shapes(&w.plan(Up, Copy, false)),
            ["record DOCS stamp=4", "upload Docs/a base=-"]
        );
    }

    #[test]
    fn case_twins_never_plan_a_download_and_delete_pair() {
        // remote foo/a, local Foo/a, in sync: one key, nothing to do in any mode.
        let w = World {
            fold: true,
            local: vec![keyed(l_same_at("Foo/a"), true)],
            remote: vec![rkeyed(rfile("foo/a", "base", 1000, 5), true)],
            base: vec![bkeyed(brow("Foo/a", "base", 1000, 5), true)],
            ..World::default()
        };
        for (d, m, force) in ALL {
            assert_eq!(shapes(&w.plan(d, m, force)), Vec::<String>::new());
        }
        // The same tree on a case-sensitive file system is two different keys.
        let w = World {
            fold: false,
            local: vec![l_same_at("Foo/a")],
            remote: vec![rfile("foo/a", "base", 1000, 5)],
            base: vec![brow("Foo/a", "base", 1000, 5)],
            ..World::default()
        };
        assert_eq!(
            shapes(&w.plan(Down, Sync, false)),
            ["del-local Foo/a", "download foo/a expect=absent"]
        );
    }

    // --- type changes across keys (§5.5.1)

    /// Local: `p` was a synced directory with two files and is now a file.
    fn dir_became_file() -> World {
        World {
            local: vec![lfile("p", "now a file", 2000), lfile("q", "q", 1)],
            remote: vec![
                rfile("p/a", "base", 1000, 5),
                rfile("p/sub/b", "base", 1000, 6),
                rfile("q", "q", 1, 7),
            ],
            base: vec![
                brow("p/a", "base", 1000, 5),
                brow("p/sub/b", "base", 1000, 6),
                brow("q", "q", 1, 7),
            ],
            ..World::default()
        }
    }

    /// Local: `p` was a synced file and is now a directory with two files.
    fn file_became_dir() -> World {
        World {
            local: vec![lfile("p/a", "a", 2000), lfile("p/sub/b", "b", 2000)],
            remote: vec![rfile("p", "base", 1000, 5)],
            base: vec![brow("p", "base", 1000, 5)],
            ..World::default()
        }
    }

    #[test]
    fn type_change_up_is_one_ordered_group() {
        let p = dir_became_file().plan(Up, Sync, false);
        assert_eq!(
            shapes(&p),
            [
                "upload p base=-",
                "del-remote p/a base=5",
                "del-remote p/sub/b base=6"
            ]
        );
        assert_eq!(
            p.groups,
            [TypeChange {
                first: vec![1, 2],
                then: vec![0]
            }]
        );
        assert_eq!(p.deletes, 2, "G4 counts the group's deletes");

        let p = file_became_dir().plan(Up, Sync, false);
        assert_eq!(
            shapes(&p),
            [
                "del-remote p base=5",
                "upload p/a base=-",
                "upload p/sub/b base=-"
            ]
        );
        assert_eq!(
            p.groups,
            [TypeChange {
                first: vec![0],
                then: vec![1, 2]
            }]
        );
    }

    #[test]
    fn type_change_down_is_one_ordered_group() {
        // Remote: the directory `p/` was replaced by a file `p` (seen from a device that
        // still has the directory).
        let w = World {
            local: vec![l_same_at("p/a"), l_same_at("p/sub/b")],
            remote: vec![rfile("p", "remote new", 3000, 9)],
            base: vec![
                brow("p/a", "base", 1000, 5),
                brow("p/sub/b", "base", 1000, 6),
            ],
            ..World::default()
        };
        let p = w.plan(Down, Sync, false);
        assert_eq!(
            shapes(&p),
            [
                "download p expect=emptydir",
                "del-local p/a",
                "del-local p/sub/b"
            ]
        );
        assert_eq!(
            p.groups,
            [TypeChange {
                first: vec![1, 2],
                then: vec![0]
            }]
        );
        // Remote: the file `p` was replaced by a directory.
        let w = World {
            local: vec![l_same_at("p")],
            remote: vec![rfile("p/a", "x", 3000, 9), rdir("p/empty", 9)],
            base: vec![brow("p", "base", 1000, 5)],
            ..World::default()
        };
        let p = w.plan(Down, Sync, false);
        assert_eq!(
            shapes(&p),
            [
                "del-local p",
                "download p/a expect=absent",
                "mkdir-local p/empty expect=absent"
            ]
        );
        assert_eq!(
            p.groups,
            [TypeChange {
                first: vec![0],
                then: vec![1, 2]
            }]
        );
    }

    #[test]
    fn copy_skips_a_type_change() {
        for (w, d, want) in [
            (
                dir_became_file(),
                Up,
                vec!["skip p Unsupported(\"type change: use sync\")"],
            ),
            (
                file_became_dir(),
                Up,
                vec![
                    "skip p/a Unsupported(\"type change: use sync\")",
                    "skip p/sub/b Unsupported(\"type change: use sync\")",
                ],
            ),
        ] {
            let p = w.plan(d, Copy, false);
            assert_eq!(shapes(&p), want);
            assert!(p.groups.is_empty());
            assert_eq!(p.deletes, 0);
        }
        let w = World {
            local: vec![l_same_at("p")],
            remote: vec![rfile("p/a", "x", 3000, 9)],
            base: vec![brow("p", "base", 1000, 5)],
            ..World::default()
        };
        assert_eq!(
            shapes(&w.plan(Down, Copy, true)),
            ["skip p/a Unsupported(\"type change: use sync\")"]
        );
    }

    #[test]
    fn a_type_change_that_cannot_remove_the_old_type_is_skipped() {
        // UP: another device added p/new, which this device has not seen: the directory
        // cannot go, so the file is not uploaded; the known children are still deleted.
        let mut w = dir_became_file();
        w.remote.push(rfile("p/new", "n", 1, 8));
        let p = w.plan(Up, Sync, false);
        assert_eq!(
            shapes(&p),
            [
                "skip p UnsafeTarget",
                "del-remote p/a base=5",
                "skip p/new RemoteOnly",
                "del-remote p/sub/b base=6"
            ]
        );
        assert!(p.groups.is_empty());

        // DOWN: a local-only file inside the old directory keeps it.
        let w = World {
            local: vec![l_same_at("p/a"), lfile("p/mine", "m", 1)],
            remote: vec![rfile("p", "remote new", 3000, 9), rfile("q", "q", 1, 7)],
            base: vec![brow("p/a", "base", 1000, 5), brow("q", "q", 1, 7)],
            ..World::default()
        };
        let p = w.plan(Down, Sync, false);
        assert_eq!(
            shapes(&p),
            [
                "skip p UnsafeTarget",
                "del-local p/a",
                "skip p/mine LocalOnly",
                "download q expect=absent"
            ]
        );
        assert!(p.groups.is_empty());

        // DOWN: the local file that is in the way was edited.
        let w = World {
            local: vec![lfile("p", "local edit", 2000)],
            remote: vec![rfile("p/a", "x", 3000, 9)],
            base: vec![brow("p", "base", 1000, 5)],
            ..World::default()
        };
        assert_eq!(
            shapes(&w.plan(Down, Sync, false)),
            ["skip p LocalChanged", "skip p/a UnsafeTarget"]
        );
    }

    // --- guards (§5.5.2)

    /// `total` synced files of which the first `gone` vanished on the source side.
    fn deletions(d: Direction, total: usize, gone: usize) -> World {
        let name = |i: usize| format!("f{i:04}");
        let all = || (0..total).map(name);
        let kept = || (gone..total).map(name);
        World {
            local: if d == Up { kept() } else { all() }
                .map(|n| l_same_at(&n))
                .collect(),
            remote: if d == Up { all() } else { kept() }
                .map(|n| rfile(&n, "base", 1000, 5))
                .collect(),
            base: all().map(|n| brow(&n, "base", 1000, 5)).collect(),
            ..World::default()
        }
    }

    #[test]
    fn g4_delete_guard() {
        for d in [Up, Down] {
            let limit = |total, gone, max| deletions(d, total, gone).guards(d, Sync, false, max);
            // 101 deletes trip whatever the total; 100 of many pass.
            assert_eq!(
                limit(10_000, 101, None),
                Err(GuardKind::DeleteLimit {
                    deletes: 101,
                    total: 10_000
                })
            );
            assert_eq!(limit(10_000, 100, None), Ok(()));
            // 10 of 30 trips (4·10 > 30); 9 of 30 passes; 10 of 40 passes.
            assert_eq!(
                limit(30, 10, None),
                Err(GuardKind::DeleteLimit {
                    deletes: 10,
                    total: 30
                })
            );
            assert_eq!(limit(30, 9, None), Ok(()));
            assert_eq!(limit(40, 10, None), Ok(()));
            // --max-delete replaces both tests, and what it refuses is a kind of its own: the
            // caller may confirm a `DeleteLimit`, never a `MaxDelete`.
            assert_eq!(limit(30, 10, Some(10)), Ok(()));
            assert_eq!(
                limit(30, 10, Some(9)),
                Err(GuardKind::MaxDelete {
                    deletes: 10,
                    limit: 9
                })
            );
            assert_eq!(limit(10_000, 500, Some(500)), Ok(()));
            assert!(limit(30, 1, Some(0)).is_err());
            // --force does not override G4; copy never trips it.
            assert!(deletions(d, 30, 10).guards(d, Sync, true, None).is_err());
            assert_eq!(deletions(d, 30, 10).guards(d, Copy, false, None), Ok(()));
            let p = deletions(d, 30, 10).plan(d, Sync, false);
            assert_eq!((p.deletes, p.dest_total), (10, 30));
        }
        // The deletes of a type-change group count.
        let mut w = dir_became_file();
        w.base.truncate(2);
        w.remote.truncate(2);
        w.local.truncate(1);
        assert!(w.guards(Up, Sync, false, Some(1)).is_err());
        assert_eq!(w.guards(Up, Sync, false, Some(2)), Ok(()));
    }

    #[test]
    fn g1_nothing_unknown_is_ever_deleted() {
        // Everything synced; then one directory becomes unreadable and another one is
        // replaced by a symlink: their keys are missing from the scan.
        let files = [
            "ok/a",
            "locked/b",
            "locked/deep/c",
            "linked/d",
            "linked/sub/e",
        ];
        let mut w = World {
            local: vec![l_same_at("ok/a")],
            remote: files.iter().map(|f| rfile(f, "base", 1000, 5)).collect(),
            base: files.iter().map(|f| brow(f, "base", 1000, 5)).collect(),
            failed_dirs: vec!["locked".into()],
            skipped_paths: vec!["linked".into()],
            ..World::default()
        };
        for (d, m, force) in ALL {
            let p = w.plan(d, m, force);
            assert_eq!(p.deletes, 0, "{d:?} {m:?} {force}");
            assert_eq!(p.actions.len(), 4);
            assert!(p.actions.iter().all(|a| matches!(a, Action::Skip { .. })));
        }
        // The same tree without the scan problems deletes four files remotely.
        w.failed_dirs.clear();
        w.skipped_paths.clear();
        assert_eq!(w.plan(Up, Sync, false).deletes, 4);
        // Remote deletions are not carried out locally under an unreadable directory either.
        let w = World {
            local: vec![l_same_at("locked/b")],
            base: vec![brow("locked/b", "base", 1000, 5)],
            failed_dirs: vec!["locked".into()],
            ..World::default()
        };
        assert_eq!(
            shapes(&w.plan(Down, Sync, false)),
            ["skip locked/b ScanError"]
        );
    }

    #[test]
    fn g2_empty_or_missing_source() {
        let synced = World {
            remote: vec![r_same()],
            base: vec![base()],
            ..World::default()
        };
        assert_eq!(
            synced.guards(Up, Sync, false, None),
            Err(GuardKind::EmptySource)
        );
        assert_eq!(
            synced.guards(Up, Copy, false, None),
            Err(GuardKind::EmptySource)
        );
        // --force overrides G2 (the delete guard still judges the deletes).
        assert_eq!(synced.guards(Up, Sync, true, None), Ok(()));
        // An empty root that never synced anything is just empty.
        let fresh = World {
            remote: vec![r_same()],
            ..World::default()
        };
        assert_eq!(fresh.guards(Up, Sync, false, None), Ok(()));
        // A missing root is refused even without base rows.
        let missing = World {
            root_missing: true,
            ..World::default()
        };
        assert_eq!(
            missing.guards(Up, Sync, false, None),
            Err(GuardKind::EmptySource)
        );
        assert_eq!(missing.guards(Up, Sync, true, None), Ok(()));
        // Downward the local tree is the destination: an empty one is simply filled.
        assert_eq!(synced.guards(Down, Sync, false, None), Ok(()));
        assert_eq!(missing.guards(Down, Sync, false, None), Ok(()));
    }

    #[test]
    fn g3_reverted_tree() {
        // `changed` files with an mtime older than the one last synced look restored.
        let build = |older: usize, newer: usize| {
            let mut w = World::default();
            for i in 0..older + newer {
                let name = format!("f{i:02}");
                let mtime = if i < older { 500 } else { 2000 };
                w.local.push(lfile(&name, "other content", mtime));
                w.remote.push(rfile(&name, "base", 1000, 5));
                w.base.push(brow(&name, "base", 1000, 5));
            }
            w
        };
        assert_eq!(
            build(6, 4).guards(Up, Sync, false, None),
            Err(GuardKind::RevertedTree { suspicious: 6 })
        );
        let p = build(6, 4).plan(Up, Sync, false);
        assert_eq!((p.changed_local, p.suspicious_reverts), (10, 6));
        // Exactly half is not "more than half"; fewer than 10 changed files never trip.
        assert_eq!(build(5, 5).guards(Up, Sync, false, None), Ok(()));
        assert_eq!(build(9, 0).guards(Up, Sync, false, None), Ok(()));
        assert!(build(10, 0).guards(Up, Copy, false, None).is_err());
        // --force overrides; downloads do not upload the old files.
        assert_eq!(build(10, 0).guards(Up, Sync, true, None), Ok(()));
        assert_eq!(build(10, 0).guards(Down, Sync, false, None), Ok(()));
    }

    #[test]
    fn g5_collisions_are_skipped_on_both_sides() {
        let w = World {
            local: vec![l_new()],
            remote: vec![r_same()],
            base: vec![
                base(),
                brow("twin", "base", 1000, 5),
                brow("gone", "base", 1000, 5),
            ],
            // `twin` collides locally (its entries are dropped by the scan), `gone` remotely.
            local_collisions: vec!["twin".into()],
            remote_collisions: vec!["gone".into(), "unseen".into()],
            ..World::default()
        };
        for (d, m, force) in ALL {
            let got = shapes(&w.plan(d, m, force));
            assert_eq!(got.len(), 4, "{got:?}");
            assert_eq!(got[1], "skip gone KeyCollision");
            assert_eq!(got[2], "skip twin KeyCollision");
            assert_eq!(got[3], "skip unseen KeyCollision");
            assert_eq!(w.plan(d, m, force).deletes, 0);
        }
    }

    // --- seeded invariants (§12.1, §13 item 2)

    const NAMES: [&str; 14] = [
        "a",
        "b.txt",
        "c.tmp",
        "d/e",
        "d/f.tmp",
        "d/g/h",
        "node_modules/x.js",
        "node_modules/y/z.js",
        "src/node_modules/w.js",
        "src/main.rs",
        "x/y/secret/k",
        "x/y/secret",
        "x/y/public",
        "d",
    ];

    fn random_world(rng: &mut Prng, with_base: bool) -> World {
        let mut w = World::default();
        let contents = ["one", "two", "three"];
        for name in NAMES {
            // A path cannot be a file and a directory on one side.
            let blocked = |paths: Vec<&str>| {
                paths.iter().any(|p| {
                    path::strip_prefix(name, p).is_some() || path::strip_prefix(p, name).is_some()
                })
            };
            let base_content = *rng.pick(&contents);
            let b = with_base && rng.chance(2, 3);
            if rng.chance(2, 3) && !blocked(w.local.iter().map(|e| e.rel.as_str()).collect()) {
                w.local.push(match rng.below(4) {
                    0 if b => l_same_at(name),
                    1 => LocalEntry {
                        hash: Some(hash(base_content)),
                        ..lfile(name, base_content, 1000 + rng.below(3) as i64)
                    },
                    2 => ldir(name),
                    _ => lfile(name, rng.pick(&contents), 2000),
                });
            }
            if rng.chance(2, 3) && !blocked(w.remote.iter().map(|r| r.rel.as_str()).collect()) {
                let lamport = if rng.bool() { 5 } else { 9 };
                w.remote.push(match rng.below(4) {
                    0 => rdir(name, lamport),
                    1 => rfile(name, base_content, 1000, lamport),
                    _ => rfile(name, rng.pick(&contents), 3000, lamport),
                });
            }
            if b {
                w.base.push(if rng.chance(1, 5) {
                    bdir(name, 5)
                } else {
                    BaseRow {
                        sig: sig(4, 1000),
                        ..brow(name, base_content, 1000, 5)
                    }
                });
                // An unhashed "same" entry must carry the row's signature.
                if let Some(l) = w
                    .local
                    .iter_mut()
                    .find(|l| l.rel == name && l.hash.is_none())
                    && l.kind == EntryKind::File
                {
                    l.sig = sig(4, 1000);
                }
            }
        }
        if rng.chance(1, 4) {
            w.failed_dirs
                .push((*rng.pick(&["d", "x/y", ""])).to_string());
        }
        if rng.chance(1, 4) {
            w.skipped_paths
                .push((*rng.pick(&["d", "a", "x"])).to_string());
        }
        if rng.chance(1, 5) {
            let key = (*rng.pick(&NAMES)).to_string();
            w.local.retain(|l| l.rel != key);
            w.local_collisions.push(key);
        }
        for r in &w.remote {
            if r.head.entry.loc.is_some() && rng.chance(1, 3) {
                w.reuse
                    .entry((r.head.entry.size, r.head.entry.hash))
                    .or_insert_with(|| r.head.clone());
            }
        }
        w
    }

    fn remote_target(a: &Action) -> Option<(&str, Option<Stamp>)> {
        match a {
            Action::Upload {
                remote_path, base, ..
            }
            | Action::Reuse {
                remote_path, base, ..
            }
            | Action::MkdirRemote {
                remote_path, base, ..
            } => Some((remote_path, *base)),
            Action::SetRemoteMeta {
                remote_path, base, ..
            }
            | Action::DelRemote {
                remote_path, base, ..
            } => Some((remote_path, Some(*base))),
            _ => None,
        }
    }

    fn check_structure(w: &World, p: &Plan, d: Direction) {
        // No two actions touch one key, and the actions are sorted by key.
        assert!(
            p.actions.windows(2).all(|w| w[0].key() < w[1].key()),
            "{:?}",
            shapes(p)
        );
        // base.is_some() ⇒ remote_path == R.path
        for a in &p.actions {
            if let Some((remote_path, Some(_))) = remote_target(a) {
                let r = w.remote.iter().find(|r| r.key == a.key());
                assert_eq!(
                    r.map(|r| r.head.path.as_str()),
                    Some(remote_path),
                    "{}",
                    shape(a)
                );
            }
            // Direction: nothing remote is written by a download run and vice versa.
            let writes_remote = remote_target(a).is_some();
            let writes_local = matches!(
                a,
                Action::Download { .. }
                    | Action::MkdirLocal { .. }
                    | Action::SetLocalMeta { .. }
                    | Action::DelLocal { .. }
            );
            assert!(!(d == Up && writes_local) && !(d == Down && writes_remote));
        }
        assert_eq!(
            p.deletes,
            p.actions.iter().filter(|a| a.is_delete()).count() as u64
        );
        // Groups: valid, disjoint, deletes first.
        let mut seen = HashSet::new();
        for g in &p.groups {
            assert!(!g.then.is_empty() && !g.first.is_empty());
            for &i in g.first.iter().chain(&g.then) {
                assert!(seen.insert(i), "an action belongs to one group");
            }
            assert!(g.first.iter().all(|&i| p.actions[i].is_delete()));
            assert!(g.then.iter().all(|&i| !p.actions[i].is_delete()));
        }
    }

    #[test]
    fn invariant_structure_holds_for_random_inputs() {
        for_each_seed("plan_structure", 400, |rng| {
            let with_base = rng.bool();
            let w = random_world(rng, with_base);
            for (d, m, force) in ALL {
                check_structure(&w, &w.plan(d, m, force), d);
            }
        });
    }

    #[test]
    fn invariant_first_sync_never_deletes_or_overwrites() {
        for_each_seed("plan_first_sync", 400, |rng| {
            let w = random_world(rng, false);
            for (d, m, force) in ALL {
                let p = w.plan(d, m, force);
                assert_eq!(p.deletes, 0);
                assert!(p.groups.is_empty());
                for a in &p.actions {
                    match a {
                        // Nothing remote is superseded …
                        Action::Upload { base, .. }
                        | Action::Reuse { base, .. }
                        | Action::MkdirRemote { base, .. } => assert_eq!(*base, None),
                        // … and no local file is replaced or unlinked: an existing file is
                        // moved aside, an existing directory is only ever rmdir'ed.
                        Action::Download {
                            expect_local,
                            keep_local,
                            ..
                        } => assert!(
                            *keep_local || !matches!(expect_local, LocalExpect::File(_)),
                            "{}",
                            shape(a)
                        ),
                        Action::MkdirLocal { expect_local, .. } => {
                            assert_eq!(*expect_local, LocalExpect::Absent)
                        }
                        Action::RecordBase { .. } | Action::Skip { .. } => {}
                        other => panic!("first sync planned {}", shape(other)),
                    }
                }
            }
        });
    }

    #[test]
    fn invariant_copy_never_deletes() {
        for_each_seed("plan_copy", 400, |rng| {
            let w = random_world(rng, true);
            for d in [Up, Down] {
                for force in [false, true] {
                    let p = w.plan(d, Copy, force);
                    assert_eq!(p.deletes, 0, "{:?}", shapes(&p));
                    assert!(p.groups.is_empty());
                }
            }
        });
    }

    #[test]
    fn invariant_excluded_keys_yield_no_actions() {
        // A directory pattern, a glob and a nested path; applied — by the one `Filter` — to
        // local entries, remote rows and base rows, as `sync::run` does. The `!` patterns
        // re-include paths under ignored directories: without effect, on every input.
        let patterns = [
            "node_modules/",
            "*.tmp",
            "/x/y/secret",
            "!node_modules/y/z.js",
            "!node_modules/y/",
            "!x/y/secret/k",
        ]
        .map(String::from);
        let filter = Filter::new(&patterns, std::path::Path::new("/no/such/root")).unwrap();
        let is_excluded = |rel: &str| filter.excluded(rel, false) || filter.excluded(rel, true);
        for_each_seed("plan_excluded", 400, |rng| {
            let with_base = rng.bool();
            let mut w = random_world(rng, with_base);
            let unfiltered = w.plan(Up, Sync, false).actions.len();
            w.local
                .retain(|l| !filter.excluded(&l.rel, l.kind == EntryKind::Dir));
            w.remote
                .retain(|r| !filter.excluded(&r.rel, r.head.entry.kind == EntryKind::Dir));
            w.base = filter_base(std::mem::take(&mut w.base), &filter);
            w.local_collisions.retain(|k| !is_excluded(k));
            for (d, m, force) in ALL {
                let p = w.plan(d, m, force);
                for a in &p.actions {
                    assert!(!is_excluded(a.key()), "{with_base}: {}", shape(a));
                }
                check_structure(&w, &p, d);
            }
            // The filter only ever removes work.
            assert!(w.plan(Up, Sync, false).actions.len() <= unfiltered);
        });
        for name in [
            "c.tmp",
            "d/f.tmp",
            "node_modules/x.js",
            "node_modules/y/z.js",
            "src/node_modules/w.js",
            "x/y/secret/k",
            "x/y/secret",
        ] {
            assert!(is_excluded(name), "{name}");
        }
        for name in ["a", "b.txt", "d/e", "src/main.rs", "x/y/public", "d"] {
            assert!(!is_excluded(name), "{name}");
        }
    }

    #[test]
    fn adding_an_exclude_deletes_nothing_on_either_side() {
        // Everything in sync; then `node_modules/` is excluded. Without the filter on the
        // base rows, the hidden local files would look deleted (row 8) or the hidden remote
        // rows deleted remotely (row 9).
        let files = ["a", "node_modules/x.js", "node_modules/y/z.js"];
        let mut w = World {
            local: files.iter().map(|f| l_same_at(f)).collect(),
            remote: files.iter().map(|f| rfile(f, "base", 1000, 5)).collect(),
            base: files.iter().map(|f| brow(f, "base", 1000, 5)).collect(),
            ..World::default()
        };
        let filter = Filter::new(
            &["node_modules/".to_string()],
            std::path::Path::new("/no/such"),
        )
        .unwrap();
        w.local.retain(|l| !filter.excluded(&l.rel, false));
        w.remote.retain(|r| !filter.excluded(&r.rel, false));
        w.base = filter_base(std::mem::take(&mut w.base), &filter);
        for (d, m, force) in ALL {
            assert!(w.plan(d, m, force).actions.is_empty());
        }
    }

    #[test]
    fn plan_input_is_plain_data() {
        fn assert_send_sync<T: Send + std::marker::Sync>() {}
        assert_send_sync::<PlanInput<'_>>();
        assert_send_sync::<Plan>();
    }
}

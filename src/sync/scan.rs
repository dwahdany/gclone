//! Local scan, filters, remote rows, hash resolution (SPEC §5.1, §5.4, §5.5.3, §9.9) — owned
//! by WP6.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::backend::Backend;
use crate::consts::{IGNORE_FILE, PARTIAL_PREFIX, PARTIAL_STALE, PROBE_PREFIX};
use crate::error::{SyncError, TransferError};
use crate::index::Vault;
use crate::path;
use crate::transfer::hash_file;
use crate::types::{BaseRow, EntryKind, Head, StatSig};
use crate::util;

/// One `ignore::gitignore::Gitignore` rooted at the local root, plus gclone's own directories
/// where they lie under that root (§5.5.3).
#[derive(Clone, Debug)]
pub struct Filter {
    gi: ignore::gitignore::Gitignore,
    /// gclone's own directories under the root: `(comparison key, number of components)`.
    own: Vec<(String, usize)>,
    fold_case: bool,
}

impl Filter {
    /// Reads `<local_root>/.gcloneignore` if present.
    pub fn new(excludes: &[String], local_root: &std::path::Path) -> Result<Filter, SyncError> {
        let mut builder = ignore::gitignore::GitignoreBuilder::new(local_root);
        let ignore_file = local_root.join(IGNORE_FILE);
        if ignore_file.is_file()
            && let Some(e) = builder.add(&ignore_file)
        {
            return Err(SyncError::Usage(format!(
                "cannot use {}: {e}",
                ignore_file.display()
            )));
        }
        for glob in excludes {
            builder
                .add_line(None, glob)
                .map_err(|e| SyncError::Usage(format!("bad --exclude pattern {glob:?}: {e}")))?;
        }
        let gi = builder
            .build()
            .map_err(|e| SyncError::Usage(format!("bad exclude patterns: {e}")))?;
        Ok(Filter {
            gi,
            own: Vec::new(),
            fold_case: false,
        })
    }

    /// Adds gclone's own directories (root-relative: the configuration directory, the state
    /// root, the directory of a directory vault — §5.5.3, §8.1). They are excluded like the
    /// reserved names, whatever the patterns say, and compared by key: `fold_case` is the
    /// root's.
    pub fn with_own_dirs(mut self, rels: &[String], fold_case: bool) -> Filter {
        self.fold_case = fold_case;
        self.own = rels
            .iter()
            .filter(|rel| !rel.is_empty())
            .map(|rel| (path::cmp_key(rel, fold_case), rel.split('/').count()))
            .collect();
        self
    }

    /// Whether the `depth` leading components `prefix` name one of gclone's own directories.
    fn is_own(&self, prefix: &str, depth: usize) -> bool {
        self.own.iter().any(|(_, d)| *d == depth) && {
            let key = path::cmp_key(prefix, self.fold_case);
            self.own.iter().any(|(k, d)| *d == depth && *k == key)
        }
    }

    /// The shortest leading part of `rel` that is excluded, §5.5.3: the ancestors are asked
    /// from the top down, each as a directory, and only when none of them is ignored the path
    /// itself. That is exactly what the walker does — it prunes an ignored directory and never
    /// looks at what is inside — so a `!` pattern cannot bring back anything under an ignored
    /// directory, on any side (as in git). The names gclone reserves for itself locally
    /// (`.gclone-partial-*`, `.gclone-probe-*`, §5.1) and gclone's own directories are
    /// excluded on every side too, so a remote entry of that name can never turn into a
    /// download that the next scan ignores.
    pub fn excluded_at<'r>(&self, rel: &'r str, is_dir: bool) -> Option<&'r str> {
        if rel.is_empty() {
            return None;
        }
        let (mut start, mut depth) = (0, 0);
        loop {
            let end = rel[start..].find('/').map_or(rel.len(), |i| start + i);
            let last = end == rel.len();
            let prefix = &rel[..end];
            depth += 1;
            if path::is_ignored_local_name(&rel[start..end])
                || self.is_own(prefix, depth)
                || self.gi.matched(prefix, is_dir || !last).is_ignore()
            {
                return Some(prefix);
            }
            if last {
                return None;
            }
            start = end + 1;
        }
    }

    /// [`Filter::excluded_at`] as a yes/no — applied to local entries, remote rows and base
    /// rows alike.
    pub fn excluded(&self, rel: &str, is_dir: bool) -> bool {
        self.excluded_at(rel, is_dir).is_some()
    }
}

/// The base rows of a pair that the filter leaves visible (§5.5.3), judged by their own
/// spelling; `sync::run` uses [`hide_excluded`], which judges by key.
pub fn filter_base(base: Vec<BaseRow>, filter: &Filter) -> Vec<BaseRow> {
    base.into_iter()
        .filter(|row| !filter.excluded(&row.rel, row.kind == EntryKind::Dir))
        .collect()
}

#[derive(Clone, Debug)]
pub struct LocalEntry {
    pub rel: String,
    pub key: String,
    pub kind: EntryKind,
    pub sig: StatSig,
    pub observed_ns: i64,
    pub hash: Option<[u8; 32]>,
    pub changed_during_scan: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SkipCounts {
    pub symlinks: u64,
    pub special: u64,
    pub non_utf8: u64,
}

#[derive(Clone, Debug)]
pub struct LocalScan {
    pub root: std::path::PathBuf,
    pub root_ino: u64,
    /// 0 if unavailable.
    pub root_birth_ns: i64,
    pub fold_case: bool,
    /// Sorted by key.
    pub entries: Vec<LocalEntry>,
    pub failed_dirs: Vec<String>,
    /// Symlinks + special files, rel.
    pub skipped_paths: Vec<String>,
    /// Keys.
    pub collisions: Vec<String>,
    /// What the filter pruned: root-relative paths as spelled on disk; nothing under a pruned
    /// directory was looked at (§5.5.3).
    pub excluded: Vec<String>,
    pub skipped: SkipCounts,
    pub root_missing: bool,
}

// ---------------------------------------------------------------------------------------------
// Root identity and the fold probe (§5.1, §5.5)
// ---------------------------------------------------------------------------------------------

/// The pair identity of a root directory: `(st_ino, birth time in ns)`; the birth time is 0
/// where the file system does not report one. `st_dev` is deliberately not part of it (§5.5).
pub(crate) fn root_identity(md: &std::fs::Metadata) -> (u64, i64) {
    let birth_ns = md
        .created()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_nanos()).ok())
        .unwrap_or(0);
    (md.ino(), birth_ns)
}

#[cfg(target_os = "macos")]
fn probe_pathconf(dir: &Path) -> Option<bool> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: `c` is a valid NUL-terminated path; pathconf only reads it.
    match unsafe { libc::pathconf(c.as_ptr(), libc::_PC_CASE_SENSITIVE) } {
        1 => Some(false),
        0 => Some(true),
        _ => None,
    }
}

#[cfg(not(target_os = "macos"))]
fn probe_pathconf(_dir: &Path) -> Option<bool> {
    None
}

/// The name with every cased letter swapped, or `None` if it has none. Only letters whose
/// other case is a single character are swapped.
fn swap_case(name: &str) -> Option<String> {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        let mut upper = c.to_uppercase();
        let mut lower = c.to_lowercase();
        let swapped = match (upper.next(), upper.next(), lower.next(), lower.next()) {
            (Some(u), None, _, _) if u != c => u,
            (_, _, Some(l), None) if l != c => l,
            _ => c,
        };
        out.push(swapped);
    }
    (out != name).then_some(out)
}

/// Writable roots: create a probe file and look for it under its upper-cased name.
fn probe_by_file(dir: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::OpenOptionsExt;
    let name = format!("{PROBE_PREFIX}{}", util::hex(&util::random::<4>()));
    let probe = dir.join(&name);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe)?;
    let ino = file.metadata().map(|md| md.ino());
    let other = std::fs::symlink_metadata(dir.join(name.to_uppercase()));
    let _ = std::fs::remove_file(&probe);
    Ok(matches!((ino, other), (Ok(a), Ok(b)) if a == b.ino()))
}

/// Read-only roots: an existing entry (or the directory's own name, through its parent) under
/// a case-swapped spelling. `None` when there is nothing to compare.
fn probe_by_entries(dir: &Path) -> Option<bool> {
    let same = |a: &Path, b: &Path| -> Option<bool> {
        let a = std::fs::symlink_metadata(a).ok()?;
        match std::fs::symlink_metadata(b) {
            Ok(b) => Some(a.ino() == b.ino() && a.dev() == b.dev()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
            Err(_) => None,
        }
    };
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(swapped) = name.to_str().and_then(swap_case) else {
                continue;
            };
            if let Some(fold) = same(&entry.path(), &dir.join(swapped)) {
                return Some(fold);
            }
        }
    }
    let swapped = dir.file_name()?.to_str().and_then(swap_case)?;
    same(dir, &dir.parent()?.join(swapped))
}

/// §5.1; works on read-only roots. `true` = the file system of `root` folds case. With nothing
/// to compare the answer is `true` (more collision skips, never an overwrite).
pub fn probe_fold_case(root: &std::path::Path) -> std::io::Result<bool> {
    if let Some(fold) = probe_pathconf(root) {
        return Ok(fold);
    }
    match probe_by_file(root) {
        Ok(fold) => Ok(fold),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            Ok(probe_by_entries(root).unwrap_or(true))
        }
        Err(e) => Err(e),
    }
}

/// The fold answer for a root that does not exist yet: asked of its nearest existing ancestor,
/// without writing there.
pub(crate) fn probe_fold_missing(root: &Path) -> bool {
    let Some(dir) = root.ancestors().skip(1).find(|a| a.is_dir()) else {
        return true;
    };
    probe_pathconf(dir)
        .or_else(|| probe_by_entries(dir))
        .unwrap_or(true)
}

// ---------------------------------------------------------------------------------------------
// The walk (§5.4)
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct Found {
    files: Vec<(String, StatSig, i64)>,
    dirs: Vec<(String, StatSig, i64)>,
    failed: Vec<String>,
    skipped_paths: Vec<String>,
    symlinks: u64,
    special: u64,
}

/// One walker thread's findings, merged into the shared result when the thread ends.
struct Collector {
    local: Found,
    shared: Arc<Mutex<Found>>,
}

impl Drop for Collector {
    fn drop(&mut self) {
        let mut all = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        let mine = std::mem::take(&mut self.local);
        all.files.extend(mine.files);
        all.dirs.extend(mine.dirs);
        all.failed.extend(mine.failed);
        all.skipped_paths.extend(mine.skipped_paths);
        all.symlinks += mine.symlinks;
        all.special += mine.special;
    }
}

/// The root-relative path of `p` as UTF-8; `None` for a non-UTF-8 name.
fn rel_of<'a>(root: &Path, p: &'a Path) -> Option<&'a str> {
    p.strip_prefix(root).ok()?.to_str()
}

/// The paths an `ignore` error is about.
fn error_paths(e: &ignore::Error, out: &mut Vec<PathBuf>) -> bool {
    match e {
        ignore::Error::Partial(errs) => {
            let mut all = true;
            for e in errs {
                all &= error_paths(e, out);
            }
            all
        }
        ignore::Error::WithLineNumber { err, .. } | ignore::Error::WithDepth { err, .. } => {
            error_paths(err, out)
        }
        ignore::Error::WithPath { path, .. } => {
            out.push(path.clone());
            true
        }
        ignore::Error::Loop { child, .. } => {
            out.push(child.clone());
            true
        }
        _ => false,
    }
}

impl Collector {
    /// A failed `readdir`/`lstat`: everything at or under the path is unknown (§5.4). An error
    /// that names no path makes the whole tree unknown.
    fn fail(&mut self, root: &Path, e: &ignore::Error) {
        let mut paths = Vec::new();
        let located = error_paths(e, &mut paths);
        for p in &paths {
            // A non-UTF-8 name inside the root is never synced, so its error concerns nothing.
            match p.strip_prefix(root) {
                Ok(rel) => {
                    if let Some(rel) = rel.to_str() {
                        self.local.failed.push(rel.to_string());
                    }
                }
                Err(_) => self.local.failed.push(String::new()),
            }
        }
        if !located {
            self.local.failed.push(String::new());
        }
    }

    fn visit(&mut self, root: &Path, result: Result<ignore::DirEntry, ignore::Error>) {
        let entry = match result {
            Ok(entry) => entry,
            Err(e) => return self.fail(root, &e),
        };
        if entry.depth() == 0 {
            return;
        }
        let Some(rel) = rel_of(root, entry.path()) else {
            return;
        };
        let Some(file_type) = entry.file_type() else {
            return;
        };
        if file_type.is_symlink() {
            self.local.symlinks += 1;
            self.local.skipped_paths.push(rel.to_string());
            return;
        }
        if !file_type.is_dir() && !file_type.is_file() {
            self.local.special += 1;
            self.local.skipped_paths.push(rel.to_string());
            return;
        }
        let observed_ns = util::now_ns();
        let md = match entry.metadata() {
            Ok(md) => md,
            Err(_) => {
                self.local.failed.push(rel.to_string());
                return;
            }
        };
        let found = (rel.to_string(), StatSig::from_metadata(&md), observed_ns);
        // The type may have changed between readdir and lstat; lstat decides.
        if md.is_dir() {
            self.local.dirs.push(found);
        } else if md.is_file() {
            self.local.files.push(found);
        } else if md.file_type().is_symlink() {
            self.local.symlinks += 1;
            self.local.skipped_paths.push(found.0);
        } else {
            self.local.special += 1;
            self.local.skipped_paths.push(found.0);
        }
    }
}

/// Removes a `.gclone-partial-*` file that no running download can still own (§5.4).
fn remove_stale_partial(entry: &ignore::DirEntry) {
    if let Ok(md) = entry.metadata() {
        sweep_partial(entry.path(), &md, SystemTime::now());
    }
}

/// [`remove_stale_partial`] at a given time.
fn sweep_partial(path: &Path, md: &std::fs::Metadata, now: SystemTime) {
    if md.is_file() && partial_is_stale(md, now) {
        let _ = std::fs::remove_file(path);
    }
}

/// Nothing was done to the file for `PARTIAL_STALE`: neither to its content nor to the inode.
///
/// The mtime alone does not tell. A download sets it to the time of the file that is being
/// restored — years back, as a rule — as soon as the file is complete, and the file then
/// waits under its partial name for the rename of its batch (§5.7 step 3a). The ctime cannot
/// be set by anybody: creating the file, writing it, `fchmod` and `futimens` all move it to
/// "now", so a file some download is still working on is never old by it.
fn partial_is_stale(md: &std::fs::Metadata, now: SystemTime) -> bool {
    let changed = match u32::try_from(md.ctime_nsec()) {
        Ok(nanos) if md.ctime() >= 0 => {
            UNIX_EPOCH + std::time::Duration::new(md.ctime() as u64, nanos)
        }
        // A ctime before 1970 says nothing.
        _ => return false,
    };
    let Ok(modified) = md.modified() else {
        return false;
    };
    now.duration_since(changed.max(modified))
        .is_ok_and(|age| age > PARTIAL_STALE)
}

/// The scan of a root that does not exist.
pub(crate) fn missing_root(root: &Path, fold_case: bool) -> LocalScan {
    LocalScan {
        root_missing: true,
        ..empty_scan(root, fold_case)
    }
}

fn empty_scan(root: &Path, fold_case: bool) -> LocalScan {
    LocalScan {
        root: root.to_path_buf(),
        root_ino: 0,
        root_birth_ns: 0,
        fold_case,
        entries: Vec::new(),
        failed_dirs: Vec::new(),
        skipped_paths: Vec::new(),
        collisions: Vec::new(),
        excluded: Vec::new(),
        skipped: SkipCounts::default(),
        root_missing: false,
    }
}

/// Synchronous (parallel walker inside). A root that does not exist yields an empty scan with
/// `root_missing`.
pub fn scan(root: &std::path::Path, filter: &Filter) -> Result<LocalScan, SyncError> {
    match std::fs::metadata(root) {
        Ok(md) if md.is_dir() => {
            let fold_case = probe_fold_case(root).unwrap_or(true);
            scan_with(root, filter, fold_case)
        }
        Ok(_) => Err(SyncError::Usage(super::not_a_directory(root))),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(missing_root(root, probe_fold_missing(root)))
        }
        Err(e) => Err(e.into()),
    }
}

/// [`scan`] with the fold answer already known (one probe per sync root, §5.1).
pub(crate) fn scan_with(
    root: &Path,
    filter: &Filter,
    fold_case: bool,
) -> Result<LocalScan, SyncError> {
    let md = std::fs::metadata(root)?;
    let (root_ino, root_birth_ns) = root_identity(&md);
    let shared = Arc::new(Mutex::new(Found::default()));
    let non_utf8 = Arc::new(AtomicU64::new(0));
    let pruned = Arc::new(Mutex::new(Vec::new()));

    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .standard_filters(false)
        .hidden(false)
        .follow_links(false);
    {
        let (root, filter, non_utf8) = (root.to_path_buf(), filter.clone(), non_utf8.clone());
        let pruned = pruned.clone();
        builder.filter_entry(move |entry| {
            if entry.depth() == 0 {
                return true;
            }
            let Some(rel) = rel_of(&root, entry.path()) else {
                non_utf8.fetch_add(1, Ordering::Relaxed);
                return false;
            };
            let name = path::file_name(rel);
            if path::is_ignored_local_name(name) {
                if name.starts_with(PARTIAL_PREFIX) {
                    remove_stale_partial(entry);
                }
                return false;
            }
            let is_dir = entry.file_type().is_some_and(|t| t.is_dir());
            if filter.excluded(rel, is_dir) {
                pruned
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(rel.to_string());
                return false;
            }
            true
        });
    }
    builder.build_parallel().run(|| {
        let mut collector = Collector {
            local: Found::default(),
            shared: shared.clone(),
        };
        let root = root.to_path_buf();
        Box::new(move |result| {
            collector.visit(&root, result);
            ignore::WalkState::Continue
        })
    });

    let found = std::mem::take(&mut *shared.lock().unwrap_or_else(|e| e.into_inner()));
    let mut failed_dirs = found.failed;
    failed_dirs.sort();
    failed_dirs.dedup();
    let mut skipped_paths = found.skipped_paths;
    skipped_paths.sort();
    let mut excluded = std::mem::take(&mut *pruned.lock().unwrap_or_else(|e| e.into_inner()));
    excluded.sort();

    // A directory is an entry only if it ends up with no included children (§5.4). A directory
    // that holds something unreadable is not known to be empty.
    let mut occupied: HashSet<&str> = HashSet::new();
    let failed: HashSet<&str> = failed_dirs.iter().map(String::as_str).collect();
    let children = found
        .files
        .iter()
        .map(|(rel, ..)| rel.as_str())
        .chain(failed_dirs.iter().map(String::as_str));
    for rel in children {
        for dir in path::ancestors(rel) {
            if !occupied.insert(dir) {
                break;
            }
        }
    }
    let leaf_dirs: Vec<&(String, StatSig, i64)> = found
        .dirs
        .iter()
        .filter(|(rel, ..)| !occupied.contains(rel.as_str()) && !failed.contains(rel.as_str()))
        .collect();
    let mut with_subdir: HashSet<&str> = HashSet::new();
    for (rel, ..) in &leaf_dirs {
        with_subdir.extend(path::ancestors(rel));
    }

    let entry = |(rel, sig, observed_ns): &(String, StatSig, i64), kind| LocalEntry {
        key: path::cmp_key(rel, fold_case),
        rel: rel.clone(),
        kind,
        sig: *sig,
        observed_ns: *observed_ns,
        hash: None,
        changed_during_scan: false,
    };
    let mut entries: Vec<LocalEntry> = found
        .files
        .iter()
        .map(|f| entry(f, EntryKind::File))
        .chain(
            leaf_dirs
                .iter()
                .filter(|(rel, ..)| !with_subdir.contains(rel.as_str()))
                .map(|d| entry(d, EntryKind::Dir)),
        )
        .collect();
    entries.sort_by(|a, b| a.key.cmp(&b.key).then_with(|| a.rel.cmp(&b.rel)));
    let collisions = drop_collisions(&mut entries, |e| &e.key);

    Ok(LocalScan {
        root: root.to_path_buf(),
        root_ino,
        root_birth_ns,
        fold_case,
        entries,
        failed_dirs,
        skipped_paths,
        collisions,
        excluded,
        skipped: SkipCounts {
            symlinks: found.symlinks,
            special: found.special,
            non_utf8: non_utf8.load(Ordering::Relaxed),
        },
        root_missing: false,
    })
}

/// Removes every entry whose key occurs more than once in the key-sorted `rows` and returns
/// those keys (§5.1: both are skipped, never one picked silently).
fn drop_collisions<T>(rows: &mut Vec<T>, key: impl Fn(&T) -> &String) -> Vec<String> {
    let mut collisions: Vec<String> = Vec::new();
    for pair in rows.windows(2) {
        if key(&pair[0]) == key(&pair[1]) && collisions.last() != Some(key(&pair[0])) {
            collisions.push(key(&pair[0]).clone());
        }
    }
    if !collisions.is_empty() {
        let dup: HashSet<&String> = collisions.iter().collect();
        rows.retain(|row| !dup.contains(key(row)));
    }
    collisions
}

// ---------------------------------------------------------------------------------------------
// The remote side
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct RemoteRow {
    pub rel: String,
    pub key: String,
    pub head: Head,
}

/// Every winner under `prefix`, sorted by key; nothing is filtered and collisions are still
/// in. A head at the prefix itself is not a row.
pub fn remote_rows_unfiltered<B: Backend>(
    vault: &Vault<B>,
    prefix: &str,
    fold_case: bool,
) -> Result<Vec<RemoteRow>, SyncError> {
    let mut rows: Vec<RemoteRow> = Vec::new();
    for head in vault.walk(prefix)? {
        let Some(rel) = path::strip_prefix(&head.path, prefix).filter(|rel| !rel.is_empty()) else {
            continue;
        };
        rows.push(RemoteRow {
            key: path::cmp_key(rel, fold_case),
            rel: rel.to_string(),
            head,
        });
    }
    rows.sort_by(|a, b| a.key.cmp(&b.key).then_with(|| a.rel.cmp(&b.rel)));
    Ok(rows)
}

/// Removes the rows whose key occurs more than once and returns those keys (G5).
pub fn remote_collisions(rows: &mut Vec<RemoteRow>) -> Vec<String> {
    drop_collisions(rows, |r| &r.key)
}

/// `(rows, collisions)`: the winners under `prefix` that the filter leaves visible, sorted by
/// key. A head at the prefix itself is not a row. Each row is judged by its own spelling;
/// `sync::run` uses [`remote_rows_unfiltered`] and [`hide_excluded`], which judge by key.
pub fn remote_rows<B: Backend>(
    vault: &Vault<B>,
    prefix: &str,
    filter: &Filter,
    fold_case: bool,
) -> Result<(Vec<RemoteRow>, Vec<String>), SyncError> {
    let mut rows = remote_rows_unfiltered(vault, prefix, fold_case)?;
    rows.retain(|row| !filter.excluded(&row.rel, row.head.entry.kind == EntryKind::Dir));
    let collisions = remote_collisions(&mut rows);
    Ok((rows, collisions))
}

/// §5.5.3, "one answer per key": the planner joins its three inputs by comparison key, while
/// a pattern matches one spelling. A key is therefore excluded as soon as **any** of its
/// spellings is — the local one (what the walker pruned), the remote row's or the base row's,
/// each with its ancestor directories — and is then removed from all three inputs together
/// with everything under it. Without this a pattern that matches only the remote spelling
/// hides the remote row while its local twin and base row stay, which plans a local delete
/// (row 9).
///
/// `remote` and `base` come in unfiltered; `local` is a scan made with the same `filter`.
pub fn hide_excluded(
    filter: &Filter,
    local: &mut LocalScan,
    remote: &mut Vec<RemoteRow>,
    base: &mut Vec<BaseRow>,
) {
    let fold = local.fold_case;
    let mut hidden: HashSet<String> = local
        .excluded
        .iter()
        .map(|rel| path::cmp_key(rel, fold))
        .collect();
    {
        // Rows arrive grouped by directory, so the same excluded prefix repeats: one key
        // computation per run of equal prefixes.
        let mut last: Option<&str> = None;
        let rows = remote
            .iter()
            .map(|r| (r.rel.as_str(), r.head.entry.kind))
            .chain(base.iter().map(|b| (b.rel.as_str(), b.kind)));
        for (rel, kind) in rows {
            if let Some(prefix) = filter.excluded_at(rel, kind == EntryKind::Dir)
                && last != Some(prefix)
            {
                hidden.insert(path::cmp_key(prefix, fold));
                last = Some(prefix);
            }
        }
    }
    if hidden.is_empty() {
        return;
    }
    let is_hidden =
        |key: &str| hidden.contains(key) || path::ancestors(key).any(|a| hidden.contains(a));
    local.entries.retain(|e| !is_hidden(&e.key));
    local.collisions.retain(|key| !is_hidden(key));
    remote.retain(|r| !is_hidden(&r.key));
    base.retain(|b| !is_hidden(&b.key));
}

/// Built once per run from `vault.walk("")`: live winners that have a `loc`, by content, and
/// the set of their sizes.
pub struct ReuseIndex {
    pub by_content: HashMap<(u64, [u8; 32]), Head>,
    pub sizes: HashSet<u64>,
}

pub fn reuse_index<B: Backend>(vault: &Vault<B>) -> Result<ReuseIndex, SyncError> {
    let mut index = ReuseIndex {
        by_content: HashMap::new(),
        sizes: HashSet::new(),
    };
    for head in vault.walk("")? {
        if head.entry.kind != EntryKind::File || head.entry.loc.is_none() {
            continue;
        }
        index.sizes.insert(head.entry.size);
        index
            .by_content
            .entry((head.entry.size, head.entry.hash))
            .or_insert(head);
    }
    Ok(index)
}

// ---------------------------------------------------------------------------------------------
// Hash resolution (§5.4)
// ---------------------------------------------------------------------------------------------

/// Fills `LocalEntry.hash` (and refreshes sig/observed_ns) where §5.4 requires it; synchronous,
/// `threads` scoped threads. Returns the number of files hashed. A file that changes while it
/// is read, or cannot be read, is marked `changed_during_scan`.
pub fn resolve_hashes(
    scan: &mut LocalScan,
    base: &[BaseRow],
    remote: &[RemoteRow],
    sizes: &HashSet<u64>,
    checksum: bool,
    threads: usize,
) -> Result<u64, SyncError> {
    let base: HashMap<&str, &BaseRow> = base.iter().map(|b| (b.key.as_str(), b)).collect();
    let remote: HashSet<&str> = remote.iter().map(|r| r.key.as_str()).collect();
    let wanted: Vec<usize> = scan
        .entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.kind == EntryKind::File)
        .filter(|(_, e)| {
            checksum
                || match base.get(e.key.as_str()) {
                    Some(row) => e.sig != row.sig || !row.trusted(),
                    None => remote.contains(e.key.as_str()) || sizes.contains(&e.sig.size),
                }
        })
        .map(|(i, _)| i)
        .collect();
    if wanted.is_empty() {
        return Ok(0);
    }

    type Hashed = Result<(StatSig, i64, [u8; 32]), TransferError>;
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<(usize, Hashed)>> = Mutex::new(Vec::with_capacity(wanted.len()));
    let (root, entries) = (&scan.root, &scan.entries);
    std::thread::scope(|scope| {
        for _ in 0..threads.clamp(1, wanted.len()) {
            scope.spawn(|| {
                loop {
                    let Some(&i) = wanted.get(next.fetch_add(1, Ordering::Relaxed)) else {
                        return;
                    };
                    let hashed = hash_file(&root.join(&entries[i].rel));
                    results
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push((i, hashed));
                }
            });
        }
    });

    let mut count = 0;
    for (i, hashed) in results.into_inner().unwrap_or_else(|e| e.into_inner()) {
        let entry = &mut scan.entries[i];
        match hashed {
            Ok((sig, observed_ns, hash)) => {
                entry.sig = sig;
                entry.observed_ns = observed_ns;
                entry.hash = Some(hash);
                count += 1;
            }
            Err(e) => {
                tracing::debug!("{}: not hashed: {e}", entry.rel);
                entry.changed_during_scan = true;
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    fn no_filter(root: &Path) -> Filter {
        Filter::new(&[], root).unwrap()
    }

    fn rels(scan: &LocalScan) -> Vec<(&str, EntryKind)> {
        scan.entries
            .iter()
            .map(|e| (e.rel.as_str(), e.kind))
            .collect()
    }

    fn write(root: &Path, rel: &str, data: &[u8]) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    #[test]
    fn files_and_only_empty_directories_are_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "a.txt", b"a");
        write(root, "d/b.txt", b"bb");
        std::fs::create_dir_all(root.join("empty/inner")).unwrap();
        std::fs::create_dir_all(root.join("d/hollow")).unwrap();
        let scan = scan(root, &no_filter(root)).unwrap();
        let mut got = rels(&scan);
        got.sort_by(|a, b| a.0.cmp(b.0));
        assert_eq!(
            got,
            vec![
                ("a.txt", EntryKind::File),
                ("d/b.txt", EntryKind::File),
                ("d/hollow", EntryKind::Dir),
                ("empty/inner", EntryKind::Dir),
            ]
        );
        assert!(!scan.root_missing);
        assert_ne!(scan.root_ino, 0);
        let sizes: Vec<u64> = scan
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .map(|e| e.sig.size)
            .collect();
        assert_eq!(sizes, vec![1, 2]);
        assert!(scan.entries.windows(2).all(|w| w[0].key < w[1].key));
        assert!(scan.entries.iter().all(|e| e.hash.is_none()));
    }

    #[test]
    fn symlinks_fifos_and_non_utf8_names_are_skipped_and_counted() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "real/file", b"x");
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        std::os::unix::fs::symlink("nowhere", root.join("real/dangling")).unwrap();
        let fifo = std::ffi::CString::new(root.join("pipe").as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let odd = root.join(std::ffi::OsStr::from_bytes(b"odd-\xff-name"));
        // Some file systems (APFS) refuse names that are not UTF-8; the count is then 0.
        let odd_created = std::fs::write(&odd, b"y").is_ok();

        let scan = scan(root, &no_filter(root)).unwrap();
        assert_eq!(rels(&scan), vec![("real/file", EntryKind::File)]);
        assert_eq!(scan.skipped.symlinks, 2);
        assert_eq!(scan.skipped.special, 1);
        assert_eq!(scan.skipped.non_utf8, u64::from(odd_created));
        assert_eq!(scan.skipped_paths, vec!["link", "pipe", "real/dangling"]);
        assert!(scan.failed_dirs.is_empty());
    }

    #[test]
    fn a_directory_that_holds_only_a_symlink_is_an_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir(root.join("d")).unwrap();
        std::os::unix::fs::symlink("x", root.join("d/link")).unwrap();
        let scan = scan(root, &no_filter(root)).unwrap();
        assert_eq!(rels(&scan), vec![("d", EntryKind::Dir)]);
        assert_eq!(scan.skipped_paths, vec!["d/link"]);
    }

    #[test]
    fn an_unreadable_subdirectory_is_a_failed_dir_and_not_an_empty_one() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "ok/a", b"a");
        write(root, "outer/locked/secret", b"s");
        let locked = root.join("outer/locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable_anyway = std::fs::read_dir(&locked).is_ok();
        let scan = scan(root, &no_filter(root));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        if readable_anyway {
            return; // running as root: permissions do not bind
        }
        let scan = scan.unwrap();
        assert_eq!(scan.failed_dirs, vec!["outer/locked"]);
        // Neither the locked directory nor its parent is reported as an empty directory.
        assert_eq!(rels(&scan), vec![("ok/a", EntryKind::File)]);
    }

    #[test]
    fn excludes_and_the_ignore_file_prune_files_and_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, ".gcloneignore", b"*.tmp\n/build/\n");
        write(root, "keep.txt", b"k");
        write(root, "x.tmp", b"t");
        write(root, "sub/y.tmp", b"t");
        write(root, "build/out.o", b"o");
        write(root, "sub/build/kept.o", b"o");
        write(root, "node_modules/a/b.js", b"j");
        write(root, "sub/node_modules/c.js", b"j");
        let filter = Filter::new(&["node_modules/".to_string()], root).unwrap();
        let scan = scan(root, &filter).unwrap();
        let mut got = rels(&scan);
        got.sort_by(|a, b| a.0.cmp(b.0));
        assert_eq!(
            got,
            vec![
                (".gcloneignore", EntryKind::File),
                ("keep.txt", EntryKind::File),
                ("sub/build/kept.o", EntryKind::File),
            ]
        );
        // The same function decides for remote and base rows.
        assert!(filter.excluded("node_modules/a/b.js", false));
        assert!(filter.excluded("node_modules", true));
        assert!(!filter.excluded("node_modules", false));
        assert!(filter.excluded("sub/node_modules/deep/c.js", false));
        assert!(filter.excluded("build/out.o", false));
        assert!(!filter.excluded("sub/build/kept.o", false));
        assert!(filter.excluded("a/b/c.tmp", false));
        assert!(!filter.excluded("keep.txt", false));
        assert!(!filter.excluded("", true));
        assert!(matches!(
            Filter::new(&["x[z-a]".to_string()], root),
            Err(SyncError::Usage(_))
        ));
    }

    #[test]
    fn a_negation_under_an_ignored_directory_brings_nothing_back_on_any_side() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            ".gcloneignore",
            b"build/\n!build/keep.txt\n!build/sub/\n*.o\n!important/\n!important/x.o\n\
              /logs/*\n!/logs/keep.log\n",
        );
        let files = [
            "build/junk.o",
            "build/keep.txt",
            "build/sub/deep.txt",
            "important/x.o",
            "important/y.o",
            "logs/a.log",
            "logs/keep.log",
            "src/a.rs",
        ];
        for rel in files {
            write(root, rel, b"x");
        }
        let filter = Filter::new(&[], root).unwrap();
        let scan = scan(root, &filter).unwrap();
        let mut seen: Vec<&str> = scan.entries.iter().map(|e| e.rel.as_str()).collect();
        seen.sort();
        // `build` is ignored as a directory, so the walker never looks inside and the two
        // re-includes under it do nothing (as in git); a re-include next to a glob works.
        assert_eq!(
            seen,
            [
                ".gcloneignore",
                "important/x.o",
                "logs/keep.log",
                "src/a.rs"
            ]
        );
        // Remote rows and base rows get exactly the walker's answer.
        for rel in files {
            assert_eq!(filter.excluded(rel, false), !seen.contains(&rel), "{rel}");
        }
        assert_eq!(
            filter.excluded_at("build/sub/deep.txt", false),
            Some("build")
        );
        assert_eq!(filter.excluded_at("build/sub", true), Some("build"));
        assert_eq!(filter.excluded_at("logs/a.log", false), Some("logs/a.log"));
        assert_eq!(filter.excluded_at("logs/keep.log", false), None);
        assert_eq!(scan.excluded, ["build", "important/y.o", "logs/a.log"]);
    }

    #[test]
    fn own_directories_are_excluded_by_key_on_every_side() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, ".config/gclone/config.json", b"{}");
        write(root, ".local/state/gclone/secrets.json", b"{}");
        write(root, ".local/state/gclone/ab/state.db", b"db");
        write(root, ".local/state/other/x", b"x");
        write(root, "Documents/n", b"n");
        let own = [
            ".config/gclone".to_string(),
            ".local/state/gclone".to_string(),
        ];
        // A pattern cannot bring them back.
        let filter = Filter::new(&["!.config/gclone/".to_string()], root)
            .unwrap()
            .with_own_dirs(&own, true);
        let scan = scan_with(root, &filter, true).unwrap();
        let mut got = rels(&scan);
        got.sort_by(|a, b| a.0.cmp(b.0));
        // `.config` holds nothing else: it counts as an empty directory, like any directory
        // whose content is excluded.
        assert_eq!(
            got,
            vec![
                (".config", EntryKind::Dir),
                (".local/state/other/x", EntryKind::File),
                ("Documents/n", EntryKind::File),
            ]
        );
        assert_eq!(scan.excluded, [".config/gclone", ".local/state/gclone"]);
        assert!(filter.excluded(".config/gclone", true));
        assert!(filter.excluded(".config/gclone/config.json", false));
        assert_eq!(
            filter.excluded_at(".local/state/gclone/ab/state.db", false),
            Some(".local/state/gclone")
        );
        assert!(!filter.excluded(".config", true));
        assert!(!filter.excluded(".config/gclone-other/x", false));
        assert!(!filter.excluded(".local/state/other/x", false));
        assert!(!filter.excluded("gclone", true));
        // Compared by key: under a folding root another spelling is the same directory.
        assert!(filter.excluded(".Config/GCLONE/config.json", false));
        let exact = no_filter(root).with_own_dirs(&own, false);
        assert!(exact.excluded(".config/gclone/config.json", false));
        assert!(!exact.excluded(".Config/GCLONE/config.json", false));
    }

    #[test]
    fn a_key_excluded_under_any_spelling_is_hidden_on_all_three_inputs() {
        // A folding root: local `cache/x` and remote `Cache/x` are one key, `Logs/a` and
        // `logs/a` another.
        let root = Path::new("/no/such/root");
        let local = |rel: &str| LocalEntry {
            rel: rel.to_string(),
            key: path::cmp_key(rel, true),
            kind: EntryKind::File,
            sig: StatSig {
                size: 1,
                mtime_ns: 0,
                ctime_ns: 0,
                ino: 1,
                mode: 0o100644,
            },
            observed_ns: 0,
            hash: None,
            changed_during_scan: false,
        };
        let remote = |rel: &str| RemoteRow {
            rel: rel.to_string(),
            key: path::cmp_key(rel, true),
            ..remote_row(rel)
        };
        let world = || {
            let mut scan = empty_scan(root, true);
            scan.entries = ["cache/sub/y", "cache/x", "keep", "Logs/a"]
                .map(local)
                .to_vec();
            let base: Vec<BaseRow> = scan
                .entries
                .iter()
                .map(|e| base_row(e, [0; 32], 0))
                .collect();
            let remote = ["Cache/sub/y", "Cache/x", "keep", "logs/a"]
                .map(remote)
                .to_vec();
            (scan, remote, base)
        };
        fn keys(l: &LocalScan, r: &[RemoteRow], b: &[BaseRow]) -> [Vec<String>; 3] {
            [
                l.entries.iter().map(|e| e.key.clone()).collect(),
                r.iter().map(|r| r.key.clone()).collect(),
                b.iter().map(|b| b.key.clone()).collect(),
            ]
        }
        let rest = || ["keep", "logs/a"].map(String::from).to_vec();

        // The pattern matches the remote spelling only: the walker pruned nothing, and by
        // spelling alone the local file and its base row would face a missing remote row —
        // a local delete (row 9).
        let filter = Filter::new(&["Cache/".to_string()], root).unwrap();
        assert!(!filter.excluded("cache/x", false));
        let (mut l, mut r, mut b) = world();
        l.collisions = vec!["cache/twin".to_string(), "other".to_string()];
        hide_excluded(&filter, &mut l, &mut r, &mut b);
        assert_eq!(keys(&l, &r, &b), [rest(), rest(), rest()]);
        assert_eq!(l.collisions, ["other"]);

        // The pattern matches the local spelling only: the walker pruned `cache`, and the
        // remote rows go with it.
        let filter = Filter::new(&["cache/".to_string()], root).unwrap();
        assert!(!filter.excluded("Cache/x", false));
        let (mut l, mut r, mut b) = world();
        l.entries.retain(|e| !e.rel.starts_with("cache/"));
        l.excluded = vec!["cache".to_string()];
        hide_excluded(&filter, &mut l, &mut r, &mut b);
        assert_eq!(keys(&l, &r, &b), [rest(), rest(), rest()]);

        // The base row's spelling alone (the local file is gone, the remote twin is spelled
        // differently): no remote delete (row 8) for a key the pattern names.
        let filter = Filter::new(&["Logs/".to_string()], root).unwrap();
        let (mut l, mut r, mut b) = world();
        l.entries.retain(|e| e.rel != "Logs/a");
        hide_excluded(&filter, &mut l, &mut r, &mut b);
        let rest: Vec<String> = ["cache/sub/y", "cache/x", "keep"]
            .map(String::from)
            .to_vec();
        assert_eq!(keys(&l, &r, &b), [rest.clone(), rest.clone(), rest]);

        // Nothing excluded: nothing hidden.
        let (mut l, mut r, mut b) = world();
        hide_excluded(&no_filter(root), &mut l, &mut r, &mut b);
        assert_eq!((l.entries.len(), r.len(), b.len()), (4, 4, 4));
    }

    #[test]
    fn reserved_names_are_invisible_and_a_partial_file_in_use_is_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "a", b"a");
        write(root, ".gclone-partial-0badf00d", b"fresh");
        write(root, "sub/.gclone-partial-deadbeef", b"staged");
        write(root, ".gclone-probe-12345678", b"");
        // What a download does to a file that is complete and waits for its batch (§5.7 step
        // 3a): the mtime of the file it will be — here two days back, usually years.
        let old =
            filetime::FileTime::from_unix_time((util::now_ms() / 1000) as i64 - 2 * 86_400, 0);
        filetime::set_file_mtime(root.join("sub/.gclone-partial-deadbeef"), old).unwrap();
        let filter = no_filter(root);
        let scan = scan(root, &filter).unwrap();
        // `sub` holds nothing that is synced: it counts as an empty directory.
        let mut got = rels(&scan);
        got.sort_by(|a, b| a.0.cmp(b.0));
        assert_eq!(got, vec![("a", EntryKind::File), ("sub", EntryKind::Dir)]);
        assert!(root.join(".gclone-partial-0badf00d").exists());
        assert!(
            root.join("sub/.gclone-partial-deadbeef").exists(),
            "an old mtime alone does not make a partial file stale"
        );
        assert!(filter.excluded("sub/.gclone-partial-ffff0000", false));
        assert!(filter.excluded(".gclone-probe-1/x", false));
    }

    #[test]
    fn a_partial_file_is_stale_a_day_after_the_last_thing_done_to_it() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, ".gclone-partial-00000001", b"left behind");
        write(root, ".gclone-partial-00000002", b"left behind, old mtime");
        std::fs::create_dir(root.join(".gclone-partial-00000003")).unwrap();
        let path = |n: u32| root.join(format!(".gclone-partial-0000000{n}"));
        let old = filetime::FileTime::from_unix_time(1_600_000_000, 0);
        filetime::set_file_mtime(path(2), old).unwrap();
        let md = |n: u32| std::fs::symlink_metadata(path(n)).unwrap();
        let now = SystemTime::now();
        let later = |secs: u64| now + std::time::Duration::from_secs(secs);

        // Its inode changed a moment ago — whatever the mtime says.
        for n in [1, 2] {
            assert!(!partial_is_stale(&md(n), now));
            assert!(!partial_is_stale(
                &md(n),
                later(PARTIAL_STALE.as_secs() - 60)
            ));
            assert!(partial_is_stale(
                &md(n),
                later(PARTIAL_STALE.as_secs() + 60)
            ));
        }
        // An mtime in the future (a clock that was set back) keeps the file as well.
        let ahead = filetime::FileTime::from_system_time(later(3 * 86_400));
        filetime::set_file_mtime(path(1), ahead).unwrap();
        assert!(!partial_is_stale(&md(1), later(2 * 86_400)));
        assert!(partial_is_stale(&md(1), later(5 * 86_400)));

        // The sweep removes stale files, and files only.
        sweep_partial(&path(2), &md(2), later(60));
        sweep_partial(&path(3), &md(3), later(2 * 86_400));
        assert!(path(2).exists() && path(3).exists());
        sweep_partial(&path(2), &md(2), later(2 * 86_400));
        assert!(!path(2).exists());
    }

    #[test]
    fn nfc_and_nfd_twins_collide_and_both_are_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "plain", b"p");
        write(root, "caf\u{e9}", b"nfc");
        write(root, "cafe\u{301}", b"nfd");
        let names = std::fs::read_dir(root).unwrap().count();
        let scan = scan(root, &no_filter(root)).unwrap();
        if names == 2 {
            // The file system normalises names itself (APFS): there is one file, no collision.
            assert_eq!(scan.entries.len(), 2);
            assert!(scan.collisions.is_empty());
        } else {
            assert_eq!(rels(&scan), vec![("plain", EntryKind::File)]);
            assert_eq!(scan.collisions, vec!["caf\u{e9}".to_string()]);
        }
        // The rule itself, independent of what the file system allows.
        let mut rows = vec![
            ("a".to_string(), 1),
            ("b".to_string(), 2),
            ("b".to_string(), 3),
            ("b".to_string(), 4),
            ("c".to_string(), 5),
        ];
        let dropped = drop_collisions(&mut rows, |r| &r.0);
        assert_eq!(dropped, vec!["b".to_string()]);
        assert_eq!(rows, vec![("a".to_string(), 1), ("c".to_string(), 5)]);
    }

    #[test]
    fn case_twins_collide_under_a_folding_key() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "Foo/a", b"1");
        write(root, "other", b"2");
        let folded = scan_with(root, &no_filter(root), true).unwrap();
        assert_eq!(
            folded.entries.iter().map(|e| &e.key).collect::<Vec<_>>(),
            vec!["foo/a", "other"]
        );
        assert_eq!(folded.entries[0].rel, "Foo/a");
        let exact = scan_with(root, &no_filter(root), false).unwrap();
        assert_eq!(exact.entries[0].key, "Foo/a");
    }

    #[test]
    fn a_missing_root_is_reported_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("not/there");
        let scan = scan(&root, &no_filter(&root)).unwrap();
        assert!(scan.root_missing);
        assert!(scan.entries.is_empty());
        write(tmp.path(), "file", b"x");
        let file_root = tmp.path().join("file");
        assert!(matches!(
            super::scan(&file_root, &no_filter(&file_root)),
            Err(SyncError::Usage(_))
        ));
    }

    #[test]
    fn root_identity_is_inode_and_birth_time_only() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let (md_a, md_b) = (
            std::fs::metadata(&a).unwrap(),
            std::fs::metadata(&b).unwrap(),
        );
        // Same device, different directories: the identity differs although st_dev is equal,
        // and it is stable across calls.
        assert_eq!(md_a.dev(), md_b.dev());
        assert_ne!(root_identity(&md_a), root_identity(&md_b));
        assert_eq!(
            root_identity(&md_a),
            root_identity(&std::fs::metadata(&a).unwrap())
        );
        assert_eq!(root_identity(&md_a).0, md_a.ino());
        let scan = scan(&a, &no_filter(&a)).unwrap();
        assert_eq!((scan.root_ino, scan.root_birth_ns), root_identity(&md_a));
    }

    #[test]
    fn swap_case_swaps_single_character_cases_only() {
        assert_eq!(swap_case("aBc").as_deref(), Some("AbC"));
        assert_eq!(swap_case("123-_"), None);
        assert_eq!(swap_case("\u{e9}").as_deref(), Some("\u{c9}"));
        // 'ß' upper-cases to two letters: left alone.
        assert_eq!(swap_case("\u{df}"), None);
        assert_eq!(swap_case("\u{df}x").as_deref(), Some("\u{df}X"));
    }

    #[test]
    fn probe_fold_case_agrees_on_writable_and_read_only_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("Root");
        std::fs::create_dir(&root).unwrap();
        write(&root, "Entry.txt", b"x");
        let by_file = probe_by_file(&root).unwrap();
        let writable = probe_fold_case(&root).unwrap();
        assert_eq!(writable, by_file);
        // The file system tells the truth about itself.
        let folds = root.join("ENTRY.TXT").exists();
        assert_eq!(writable, folds);
        assert!(std::fs::read_dir(&root).unwrap().all(|e| {
            !e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(PROBE_PREFIX)
        }));

        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o555)).unwrap();
        let read_only = probe_fold_case(&root);
        let by_entries = probe_by_entries(&root);
        // An empty read-only directory is judged through its own name in its parent.
        let empty = tmp.path().join("Empty");
        std::fs::create_dir(&empty).unwrap();
        std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o555)).unwrap();
        let by_own_name = probe_by_entries(&empty);
        let empty_read_only = probe_fold_case(&empty);
        for dir in [&root, &empty] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(read_only.unwrap(), folds);
        assert_eq!(by_entries, Some(folds));
        assert_eq!(by_own_name, Some(folds));
        assert_eq!(empty_read_only.unwrap(), folds);
        assert_eq!(probe_fold_missing(&tmp.path().join("Not/There")), folds);
    }

    fn base_row(e: &LocalEntry, hash: [u8; 32], observed_ns: i64) -> BaseRow {
        BaseRow {
            key: e.key.clone(),
            rel: e.rel.clone(),
            kind: e.kind,
            sig: e.sig,
            hash,
            remote_stamp: crate::types::Stamp {
                lamport: 1,
                device: crate::types::DeviceId([1; 8]),
                idx: 0,
            },
            observed_ns,
        }
    }

    fn remote_row(key: &str) -> RemoteRow {
        RemoteRow {
            rel: key.to_string(),
            key: key.to_string(),
            head: Head {
                path: key.to_string(),
                stamp: crate::types::Stamp {
                    lamport: 1,
                    device: crate::types::DeviceId([1; 8]),
                    idx: 0,
                },
                entry: crate::types::Entry::empty_file(0, false),
                origin: None,
                winner: true,
            },
        }
    }

    #[test]
    fn resolve_hashes_follows_the_four_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for name in ["trusted", "racy", "touched", "twin", "sized", "lonely"] {
            write(root, name, name.as_bytes());
        }
        std::fs::create_dir(root.join("dir")).unwrap();
        let filter = no_filter(root);
        let fresh = scan(root, &filter).unwrap();
        let by_name = |name: &str| fresh.entries.iter().find(|e| e.rel == name).unwrap();
        let far = i64::MAX;
        let hash_of = |name: &str| *blake3::hash(name.as_bytes()).as_bytes();
        let mut touched = base_row(by_name("touched"), hash_of("touched"), far);
        touched.sig.mtime_ns -= 5;
        let base = vec![
            // (a) signature equal and trusted: not hashed
            base_row(by_name("trusted"), hash_of("trusted"), far),
            // (a) signature equal but observed inside the racy window: hashed
            base_row(
                by_name("racy"),
                hash_of("racy"),
                by_name("racy").sig.mtime_ns,
            ),
            // (a) signature differs: hashed
            touched,
        ];
        // (b) no base row, a remote entry at the key: hashed
        let remote = vec![remote_row("twin")];
        // (c) no remote entry, a live index entry of the same size: hashed
        let sizes: HashSet<u64> = [by_name("sized").sig.size].into();
        assert_ne!(by_name("sized").sig.size, by_name("lonely").sig.size);

        let mut scan = fresh.clone();
        let n = resolve_hashes(&mut scan, &base, &remote, &sizes, false, 3).unwrap();
        assert_eq!(n, 4);
        for e in &scan.entries {
            let expect = matches!(e.rel.as_str(), "racy" | "touched" | "twin" | "sized");
            assert_eq!(e.hash.is_some(), expect, "{}", e.rel);
            if let Some(h) = e.hash {
                assert_eq!(h, hash_of(&e.rel));
                assert!(e.observed_ns >= by_name(&e.rel).observed_ns);
            }
            assert!(!e.changed_during_scan);
        }

        // (d) --checksum: every file, never a directory
        let mut scan = fresh.clone();
        let n = resolve_hashes(&mut scan, &base, &remote, &sizes, true, 1).unwrap();
        assert_eq!(n, 6);
        assert!(
            scan.entries
                .iter()
                .all(|e| e.hash.is_some() == (e.kind == EntryKind::File))
        );

        // A file that cannot be read any more is marked, not hashed and not an error.
        let mut scan = fresh.clone();
        std::fs::remove_file(root.join("twin")).unwrap();
        let n = resolve_hashes(&mut scan, &base, &remote, &sizes, false, 2).unwrap();
        assert_eq!(n, 3);
        let twin = scan.entries.iter().find(|e| e.rel == "twin").unwrap();
        assert!(twin.changed_during_scan && twin.hash.is_none());
    }
}

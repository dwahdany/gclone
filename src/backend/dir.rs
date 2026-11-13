//! Directory backend (SPEC §9.5) — owned by WP2.
//!
//! Objects are plain files `<root>/<folder path>/<name>`. Ids are mapped through
//! `<root>/.gclone-dir-ids.json` (id → relative path). An object without a map entry (a web
//! download / Takeout copy has no map at all) gets the handle `p:<relative path>` from
//! `list`/`find_by_name`/`stat`; ids recorded elsewhere give `NotFound` and callers resolve by
//! name. `Handle::top()` is `<root>` itself: `list(top)` lists it, and top-level objects report
//! `parent = Handle::top()`. Trash = move under `<root>/.trash/`; delete = remove from there.
//! md5 computed on demand. `created_ms` = file mtime.
//!
//! Details this file settles:
//! - **Names.** A name starting with `.` is never an object: the map, the trash, the spool
//!   directory and whatever a file manager drops into a copied vault (`.DS_Store`, `._x`) stay
//!   invisible, and `put`/`create_folder` refuse such names (as well as empty names and `/`).
//!   Symlinks and special files are not objects either.
//! - **One name, one object.** Unlike Drive, a directory cannot hold two objects of one name.
//!   A new id whose path is taken *adopts* what is there when that is unambiguous — a file or
//!   folder no id is bound to (a copied vault, a crash before the map was written), or an empty
//!   folder — and is refused with `Fatal { status: 409, reason: "nameConflict" }` otherwise.
//! - **The map is a journal**: one JSON record per line, appended (and fsynced) per change, so a
//!   put costs O(1) however large the vault is. It is rewritten compactly on `open` once it is
//!   mostly history. File records carry size, mtime and md5, so the md5 is recomputed only for
//!   files the map does not know or that changed since.
//! - **Trash.** A trashed object moves to `.trash/<slot>/<name>`, a folder with its content,
//!   which is thereby trashed too and no longer listed. `untrash` moves it back to where it came
//!   from. A `p:` handle keeps naming its object across trash and untrash.
//! - **Several processes** may work on one directory: changes take an advisory lock on the
//!   root, and every call first reads what others appended to the journal.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Bound;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use futures_util::StreamExt;
use md5::Digest;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

use super::{
    Backend, ByteStream, Handle, ObjMeta, PartReader, PutBody, Quota, bad_request, check_small,
    not_downloadable,
};
use crate::error::BackendError;
use crate::util;

const IDS_FILE: &str = ".gclone-dir-ids.json";
const TRASH_DIR: &str = ".trash";
const SPOOL_DIR: &str = ".gclone-tmp";
const PATH_HANDLE: &str = "p:";
/// Spool files older than this were left behind by a crash.
const SPOOL_STALE_MS: u64 = 24 * 3600 * 1000;
const GET_CHUNK: usize = 256 * 1024;

/// (size, mtime in ns, md5): the md5 is valid while size and mtime are unchanged.
type Sig = (u64, i64, [u8; 16]);

/// One line of the journal. Paths are relative to the root, `/`-separated, and name where the
/// object is *now* (inside `.trash/<slot>/` for trashed ones).
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Rec {
    /// `id` names the object at `path`.
    Bind {
        id: String,
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sig: Option<SigRec>,
    },
    /// Whatever was at or below `from` is now at or below `to`.
    Move { from: String, to: String },
    /// Trash slot `n` holds the object that lived at `orig`; `None` frees the slot.
    Slot { n: u64, orig: Option<String> },
    /// Nothing is left at or below `path`.
    Drop { path: String },
}

#[derive(Serialize, Deserialize)]
struct SigRec {
    size: u64,
    mtime_ns: i64,
    md5: String,
}

fn bind(id: &Handle, path: &str, sig: Option<Sig>) -> Rec {
    Rec::Bind {
        id: id.0.clone(),
        path: path.to_string(),
        sig: sig.map(|(size, mtime_ns, md5)| SigRec {
            size,
            mtime_ns,
            md5: util::hex(&md5),
        }),
    }
}

#[derive(Default)]
struct Known {
    /// Usually one; a folder adopted under a second id has several.
    ids: Vec<String>,
    sig: Option<Sig>,
}

/// The journal replayed, plus caches.
#[derive(Default)]
struct IdMap {
    by_id: HashMap<String, String>,
    paths: BTreeMap<String, Known>,
    /// Trash slot → the path its object was trashed from.
    slots: BTreeMap<u64, String>,
    /// How far the journal file has been read.
    pos: Option<Pos>,
    records: usize,
    /// name → live paths, for `find_by_name`; dropped whenever the tree may have changed.
    names: Option<HashMap<String, Vec<String>>>,
}

/// A position in the journal: the file (by inode), the bytes consumed, and the last of them —
/// which tell the same file grown from another file that got the same inode.
struct Pos {
    ino: u64,
    at: u64,
    last: Vec<u8>,
}

impl Pos {
    const LAST: usize = 32;

    /// Nothing was appended since.
    fn at(&self, md: &Metadata) -> bool {
        self.ino == md.ino() && self.at == md.len()
    }
}

impl IdMap {
    /// The known paths at or below `path`.
    fn below(&self, path: &str) -> Vec<String> {
        self.paths
            .range::<str, _>((Bound::Included(path), Bound::Unbounded))
            .map(|(k, _)| k)
            .take_while(|k| k.starts_with(path))
            .filter(|k| at_or_below(k, path))
            .cloned()
            .collect()
    }

    fn is_bound(&self, path: &str) -> bool {
        self.paths.get(path).is_some_and(|k| !k.ids.is_empty())
    }

    /// A `Drop` for bindings that outlived their object, to be journaled before `path` is
    /// given to a new one.
    fn vacate(&self, path: &str) -> Option<Rec> {
        self.below(path)
            .iter()
            .any(|p| self.is_bound(p))
            .then(|| Rec::Drop {
                path: path.to_string(),
            })
    }

    fn apply(&mut self, rec: Rec) {
        self.records += 1;
        match rec {
            Rec::Bind { id, path, sig } => {
                if let Some(old) = self.by_id.insert(id.clone(), path.clone())
                    && old != path
                    && let Some(known) = self.paths.get_mut(&old)
                {
                    known.ids.retain(|i| *i != id);
                }
                let known = self.paths.entry(path).or_default();
                if !known.ids.contains(&id) {
                    known.ids.push(id);
                }
                if let Some(sig) = sig
                    && let Some(md5) = util::unhex(&sig.md5).and_then(|b| b.try_into().ok())
                {
                    known.sig = Some((sig.size, sig.mtime_ns, md5));
                }
            }
            Rec::Move { from, to } => {
                for key in self.below(&from) {
                    let Some(known) = self.paths.remove(&key) else {
                        continue;
                    };
                    let moved = format!("{to}{}", &key[from.len()..]);
                    for id in &known.ids {
                        self.by_id.insert(id.clone(), moved.clone());
                    }
                    self.paths.insert(moved, known);
                }
            }
            Rec::Slot {
                n,
                orig: Some(orig),
            } => {
                self.slots.insert(n, orig);
            }
            Rec::Slot { n, orig: None } => {
                self.slots.remove(&n);
            }
            Rec::Drop { path } => {
                for key in self.below(&path) {
                    for id in self.paths.remove(&key).map(|k| k.ids).unwrap_or_default() {
                        self.by_id.remove(&id);
                    }
                }
            }
        }
    }
}

// --- relative paths

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// (directory, name); the directory of a top-level path is `""`.
fn split(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn at_or_below(path: &str, top: &str) -> bool {
    path.strip_prefix(top)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

fn in_trash(path: &str) -> bool {
    path.starts_with(TRASH_DIR) && path[TRASH_DIR.len()..].starts_with('/')
}

fn slot_dir(n: u64) -> String {
    format!("{TRASH_DIR}/{n}")
}

/// The slot of `.trash/<slot>/<name>` — the object that was trashed itself, not its content.
fn slot_root(path: &str) -> Option<u64> {
    let (slot, name) = path
        .strip_prefix(TRASH_DIR)?
        .strip_prefix('/')?
        .split_once('/')?;
    if name.contains('/') {
        return None;
    }
    slot.parse().ok()
}

fn is_object_name(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('.') && !name.contains(['/', '\0'])
}

/// The path of a `p:` handle: object names all the way, optionally inside a trash slot.
fn is_object_path(path: &str) -> bool {
    let rest = if in_trash(path) {
        match path[TRASH_DIR.len() + 1..].split_once('/') {
            Some((slot, rest)) if slot.parse::<u64>().is_ok() => rest,
            _ => return false,
        }
    } else {
        path
    };
    rest.split('/').all(is_object_name)
}

fn check_name(name: &str) -> Result<(), BackendError> {
    if is_object_name(name) {
        return Ok(());
    }
    Err(bad_request(format!(
        "a directory vault cannot store an object named {name:?}"
    )))
}

fn check_id(id: &Handle) -> Result<(), BackendError> {
    if id.is_top() || id.0.starts_with(PATH_HANDLE) {
        return Err(bad_request(format!(
            "{:?} cannot be used as an object id",
            id.0
        )));
    }
    Ok(())
}

fn name_taken(path: &str) -> BackendError {
    BackendError::Fatal {
        status: 409,
        reason: "nameConflict".into(),
        message: format!(
            "{path} already exists in the directory vault, which cannot hold two objects of one name"
        ),
    }
}

fn no_folder(what: &str) -> BackendError {
    BackendError::Fatal {
        status: 404,
        reason: "notFound".into(),
        message: format!("{what} does not exist"),
    }
}

// --- file metadata

fn mtime_ns(md: &Metadata) -> i64 {
    md.mtime()
        .saturating_mul(1_000_000_000)
        .saturating_add(md.mtime_nsec())
}

fn created_ms(md: &Metadata) -> u64 {
    // A folder's mtime moves with every child; its birth time does not (where the file system
    // records one).
    let born = md.is_dir().then(|| md.created().ok()).flatten();
    match born.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()) {
        Some(d) => d.as_millis() as u64,
        None => (mtime_ns(md) / 1_000_000).max(0) as u64,
    }
}

fn file_md5(path: &Path) -> io::Result<[u8; 16]> {
    let mut file = File::open(path)?;
    let mut hasher = md5::Md5::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match file.read(&mut buf)? {
            0 => return Ok(hasher.finalize().into()),
            n => hasher.update(&buf[..n]),
        }
    }
}

/// Puts the spooled file under its final name without ever replacing an existing one.
fn link_new(spooled: &Path, dest: &Path) -> io::Result<()> {
    match fs::hard_link(spooled, dest) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(e),
        // No hard links here (FAT, some network shares). The caller holds the lock and has
        // just seen the name free.
        Err(_) => fs::rename(spooled, dest),
    }
}

/// An object body on its way in: written to the spool directory, removed again unless
/// `commit` links it into place.
struct Spool {
    path: PathBuf,
    file: File,
    md5: md5::Md5,
}

impl Spool {
    fn create(dir: &Inner) -> io::Result<Spool> {
        let spool_dir = dir.abs(SPOOL_DIR);
        fs::create_dir_all(&spool_dir)?;
        let path = spool_dir.join(util::hex(&util::random::<8>()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Spool {
            path,
            file,
            md5: md5::Md5::new(),
        })
    }

    fn write(&mut self, part: &[u8]) -> io::Result<()> {
        self.file.write_all(part)?;
        self.md5.update(part);
        Ok(())
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// An object's meta; `todo` names the file whose md5 still has to be read (done without the
/// state lock: it can take a while).
struct Item {
    meta: ObjMeta,
    todo: Option<(String, u64, i64)>,
}

struct Inner {
    root: PathBuf,
    state: Mutex<IdMap>,
}

impl Inner {
    fn abs(&self, rel: &str) -> PathBuf {
        if rel.is_empty() {
            self.root.clone()
        } else {
            self.root.join(rel)
        }
    }

    fn state(&self) -> MutexGuard<'_, IdMap> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The file or directory at `rel`, if any. Symlinks and special files do not count.
    fn lstat(&self, rel: &str) -> io::Result<Option<Metadata>> {
        let md = if rel.is_empty() {
            fs::metadata(&self.root)
        } else {
            fs::symlink_metadata(self.root.join(rel))
        };
        match md {
            Ok(md) => Ok(Some(md).filter(|md| md.is_file() || md.is_dir())),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    // --- journal

    /// Brings `map` up to date with the journal file (other processes append to it).
    fn sync(&self, map: &mut IdMap) -> io::Result<()> {
        let path = self.abs(IDS_FILE);
        match fs::metadata(&path) {
            Ok(md) if map.pos.as_ref().is_some_and(|p| p.at(&md)) => return Ok(()),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if map.pos.is_some() {
                    *map = IdMap::default();
                }
                return Ok(());
            }
            Err(e) => return Err(e),
        }
        let mut file = File::open(&path)?;
        let md = file.metadata()?;
        // Continue after the last record read — if the file still is the one read so far (a
        // compaction replaces it, and inode numbers get reused).
        let mut tail = Vec::new();
        let mut from = 0;
        let mut skip = 0;
        if let Some(pos) = map
            .pos
            .as_ref()
            .filter(|p| p.ino == md.ino() && p.at < md.len())
        {
            file.seek(SeekFrom::Start(pos.at - pos.last.len() as u64))?;
            file.read_to_end(&mut tail)?;
            if tail.starts_with(&pos.last) {
                (from, skip) = (pos.at, pos.last.len());
            }
        }
        if from == 0 {
            *map = IdMap::default();
            tail.clear();
            file.seek(SeekFrom::Start(0))?;
            file.read_to_end(&mut tail)?;
        }
        // A last line without its newline is still being written (or was torn by a crash).
        let end = tail
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(skip, |i| i + 1);
        // Lines that do not parse (torn, or written by a newer gclone) are skipped: the map is
        // a hint, and an object without an entry is still reachable by name.
        for line in tail[skip..end].split(|b| *b == b'\n') {
            if let Ok(rec) = serde_json::from_slice::<Rec>(line) {
                map.apply(rec);
            }
        }
        if end > skip {
            map.names = None;
        }
        map.pos = Some(Pos {
            ino: md.ino(),
            at: from + (end - skip) as u64,
            last: tail[end.saturating_sub(Pos::LAST)..end].to_vec(),
        });
        Ok(())
    }

    /// State lock, cross-process lock, fresh map — what every change starts with.
    fn exclusive(&self) -> io::Result<(MutexGuard<'_, IdMap>, Option<File>)> {
        let mut map = self.state();
        // Advisory and best effort: a file system without locks still works for one process.
        let lock = File::open(&self.root).ok().filter(|f| f.lock().is_ok());
        self.sync(&mut map)?;
        map.names = None;
        Ok((map, lock))
    }

    /// Appends `recs` durably, then applies them to `map`. Call with [`exclusive`] held.
    fn append(&self, map: &mut IdMap, recs: Vec<Rec>) -> io::Result<()> {
        if recs.is_empty() {
            return Ok(());
        }
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.abs(IDS_FILE))?;
        let mut buf = Vec::new();
        if file.metadata()?.len() > map.pos.as_ref().map_or(0, |p| p.at) {
            // Whatever follows the last complete line is a torn record: end it.
            buf.push(b'\n');
        }
        for rec in &recs {
            serde_json::to_writer(&mut buf, rec)?;
            buf.push(b'\n');
        }
        file.write_all(&buf)?;
        file.sync_data()?;
        // Reading our own lines back keeps `map` equal to a replay of the file.
        self.sync(map)
    }

    /// Rewrites a journal that is mostly history as one record per live binding.
    fn compact(&self) -> io::Result<()> {
        let (mut map, _lock) = self.exclusive()?;
        if map.records <= 2 * (map.by_id.len() + map.slots.len()) + 64 {
            return Ok(());
        }
        let mut recs = Vec::new();
        for (n, orig) in &map.slots {
            recs.push(Rec::Slot {
                n: *n,
                orig: Some(orig.clone()),
            });
        }
        for (path, known) in &map.paths {
            if known.ids.is_empty() || self.lstat(path)?.is_none() {
                continue;
            }
            let mut sig = known.sig;
            for id in &known.ids {
                recs.push(bind(&Handle(id.clone()), path, sig.take()));
            }
        }
        let mut buf = Vec::new();
        for rec in &recs {
            serde_json::to_writer(&mut buf, rec)?;
            buf.push(b'\n');
        }
        util::write_atomic(&self.abs(IDS_FILE), &buf, 0o644)?;
        self.sync(&mut map)
    }

    /// On `open`, best effort (the directory may be read-only).
    fn housekeeping(&self) {
        let _ = self.compact();
        let Ok(spool) = fs::read_dir(self.abs(SPOOL_DIR)) else {
            return;
        };
        let now = util::now_ms();
        for entry in spool.flatten() {
            let stale = entry
                .metadata()
                .is_ok_and(|md| now.saturating_sub(created_ms(&md)) > SPOOL_STALE_MS);
            if stale {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    // --- handles

    /// Where the object once at `rel` is now: there, or inside the newest trash slot that
    /// took it (or a folder above it) away.
    fn locate(&self, map: &IdMap, rel: &str) -> io::Result<Option<(String, Metadata)>> {
        if let Some(md) = self.lstat(rel)? {
            return Ok(Some((rel.to_string(), md)));
        }
        for (n, orig) in map.slots.iter().rev() {
            if !at_or_below(rel, orig) {
                continue;
            }
            let (_, name) = split(orig);
            let moved = format!("{}/{name}{}", slot_dir(*n), &rel[orig.len()..]);
            if let Some(md) = self.lstat(&moved)? {
                return Ok(Some((moved, md)));
            }
        }
        Ok(None)
    }

    fn resolve(&self, map: &IdMap, h: &Handle) -> io::Result<Option<(String, Metadata)>> {
        if h.is_top() {
            return Ok(self.lstat("")?.map(|md| (String::new(), md)));
        }
        if let Some(path) = map.by_id.get(&h.0) {
            return Ok(self.lstat(path)?.map(|md| (path.clone(), md)));
        }
        match h.0.strip_prefix(PATH_HANDLE) {
            Some(rel) if is_object_path(rel) => self.locate(map, rel),
            _ => Ok(None),
        }
    }

    fn handle_of(&self, map: &IdMap, path: &str) -> Handle {
        if path.is_empty() {
            return Handle::top();
        }
        match map.paths.get(path).and_then(|k| k.ids.first()) {
            Some(id) => Handle(id.clone()),
            None => Handle(format!("{PATH_HANDLE}{path}")),
        }
    }

    fn describe(&self, map: &IdMap, path: &str, md: &Metadata) -> io::Result<Item> {
        if path.is_empty() {
            return Ok(Item {
                meta: ObjMeta::top(created_ms(md)),
                todo: None,
            });
        }
        let (dir, name) = split(path);
        let parent = match slot_root(path) {
            // A trashed object still belongs to the folder it was trashed from.
            Some(n) => match map.slots.get(&n).map(|orig| split(orig).0) {
                Some(from) => match self.locate(map, from)? {
                    Some((from, _)) => self.handle_of(map, &from),
                    None => Handle(format!("{PATH_HANDLE}{from}")),
                },
                None => Handle::top(),
            },
            None => self.handle_of(map, dir),
        };
        let mut meta = ObjMeta {
            handle: self.handle_of(map, path),
            name: name.to_string(),
            parent,
            size: 0,
            md5: None,
            created_ms: created_ms(md),
            is_folder: md.is_dir(),
            trashed: in_trash(path),
        };
        let mut todo = None;
        if md.is_file() {
            let (size, mtime) = (md.len(), mtime_ns(md));
            meta.size = size;
            match map.paths.get(path).and_then(|k| k.sig) {
                Some((s, m, md5)) if s == size && m == mtime => meta.md5 = Some(md5),
                _ => todo = Some((path.to_string(), size, mtime)),
            }
        }
        Ok(Item { meta, todo })
    }

    /// Fills in the md5s still missing. Objects that vanished meanwhile are left out.
    fn finish(&self, items: Vec<Item>) -> Result<Vec<ObjMeta>, BackendError> {
        let mut out = Vec::with_capacity(items.len());
        for Item { mut meta, todo } in items {
            if let Some((path, size, mtime)) = todo {
                match file_md5(&self.abs(&path)) {
                    Ok(md5) => {
                        meta.md5 = Some(md5);
                        self.state().paths.entry(path).or_default().sig = Some((size, mtime, md5));
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            out.push(meta);
        }
        Ok(out)
    }

    /// The objects directly inside `dir`: (name, metadata).
    fn children(&self, dir: &str) -> io::Result<Vec<(String, Metadata)>> {
        let entries = match fs::read_dir(self.abs(dir)) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if !is_object_name(&name) {
                continue;
            }
            match entry.metadata() {
                Ok(md) if md.is_file() || md.is_dir() => out.push((name, md)),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// name → paths of every live object.
    fn walk_names(&self) -> io::Result<HashMap<String, Vec<String>>> {
        let mut names: HashMap<String, Vec<String>> = HashMap::new();
        let mut dirs = vec![String::new()];
        while let Some(dir) = dirs.pop() {
            for (name, md) in self.children(&dir)? {
                let path = join(&dir, &name);
                if md.is_dir() {
                    dirs.push(path.clone());
                }
                names.entry(name).or_default().push(path);
            }
        }
        Ok(names)
    }

    /// Bytes of all files below `dir`; `all` also counts what is not an object.
    fn tree_size(&self, dir: &Path, all: bool) -> io::Result<u64> {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let mut total = 0;
        for entry in entries {
            let entry = entry?;
            if !all && !entry.file_name().to_str().is_some_and(is_object_name) {
                continue;
            }
            match entry.metadata() {
                Ok(md) if md.is_dir() => total += self.tree_size(&entry.path(), all)?,
                Ok(md) if md.is_file() => total += md.len(),
                _ => {}
            }
        }
        Ok(total)
    }

    // --- operations (blocking)

    /// The directory a new object goes into.
    fn parent_dir(&self, map: &IdMap, parent: &Handle) -> Result<String, BackendError> {
        match self.resolve(map, parent)? {
            Some((dir, md)) if md.is_dir() => Ok(dir),
            _ => Err(no_folder(&format!("parent folder {}", parent.0))),
        }
    }

    fn create_folder(&self, id: &Handle, parent: &Handle, name: &str) -> Result<(), BackendError> {
        check_id(id)?;
        check_name(name)?;
        let (mut map, _lock) = self.exclusive()?;
        if let Some((_, md)) = self.resolve(&map, id)? {
            return if md.is_dir() {
                Ok(())
            } else {
                Err(BackendError::AlreadyExists)
            };
        }
        let path = join(&self.parent_dir(&map, parent)?, name);
        match self.lstat(&path)? {
            Some(md) if md.is_dir() => {
                if map.is_bound(&path) && !self.children(&path)?.is_empty() {
                    return Err(name_taken(&path));
                }
                self.append(&mut map, vec![bind(id, &path, None)])?;
            }
            Some(_) => return Err(name_taken(&path)),
            None => {
                fs::create_dir(self.abs(&path))?;
                let mut recs: Vec<Rec> = map.vacate(&path).into_iter().collect();
                recs.push(bind(id, &path, None));
                if let Err(e) = self.append(&mut map, recs) {
                    let _ = fs::remove_dir(self.abs(&path));
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }

    /// The meta of the object `id` already names, after checking the arguments of a `put`.
    fn existing(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
    ) -> Result<Option<ObjMeta>, BackendError> {
        check_id(id)?;
        check_name(name)?;
        let item = {
            let mut map = self.state();
            self.sync(&mut map)?;
            match self.resolve(&map, id)? {
                Some((path, md)) => self.describe(&map, &path, &md)?,
                None => {
                    self.parent_dir(&map, parent)?;
                    return Ok(None);
                }
            }
        };
        Ok(self.finish(vec![item])?.pop().map(|meta| ObjMeta {
            handle: id.clone(),
            ..meta
        }))
    }

    /// Makes the spooled body the object `id`, unless `id` got an object meanwhile.
    fn commit(
        &self,
        spool: Spool,
        id: &Handle,
        parent: &Handle,
        name: &str,
    ) -> Result<ObjMeta, BackendError> {
        spool.file.sync_all()?;
        let md5: [u8; 16] = spool.md5.clone().finalize().into();
        let item = {
            let (mut map, _lock) = self.exclusive()?;
            if let Some((path, md)) = self.resolve(&map, id)? {
                self.describe(&map, &path, &md)?
            } else {
                let path = join(&self.parent_dir(&map, parent)?, name);
                let md = match self.lstat(&path)? {
                    // A file no id knows (copied vault, or a crash before the map was
                    // written): `id` adopts it; the caller compares size and md5.
                    Some(md) if md.is_file() && !map.is_bound(&path) => {
                        self.append(&mut map, vec![bind(id, &path, None)])?;
                        md
                    }
                    Some(_) => return Err(name_taken(&path)),
                    None => {
                        let dest = self.abs(&path);
                        link_new(&spool.path, &dest)?;
                        let stored = fs::symlink_metadata(&dest).and_then(|md| {
                            let sig = (md.len(), mtime_ns(&md), md5);
                            let mut recs: Vec<Rec> = map.vacate(&path).into_iter().collect();
                            recs.push(bind(id, &path, Some(sig)));
                            self.append(&mut map, recs).map(|()| md)
                        });
                        match stored {
                            Ok(md) => md,
                            Err(e) => {
                                // Not recorded: the object must not exist either.
                                let _ = fs::remove_file(&dest);
                                return Err(e.into());
                            }
                        }
                    }
                };
                self.describe(&map, &path, &md)?
            }
        };
        match self.finish(vec![item])?.pop() {
            Some(meta) => Ok(ObjMeta {
                handle: id.clone(),
                ..meta
            }),
            None => Err(io::Error::other("the object vanished while it was stored").into()),
        }
    }

    /// The file positioned at the start of the (clamped) range, and the number of bytes to read.
    fn open_range(
        &self,
        h: &Handle,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<(File, u64), BackendError> {
        let (path, md) = {
            let mut map = self.state();
            self.sync(&mut map)?;
            self.resolve(&map, h)?.ok_or(BackendError::NotFound)?
        };
        if md.is_dir() {
            return Err(not_downloadable());
        }
        let mut file = match File::open(self.abs(&path)) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(BackendError::NotFound),
            Err(e) => return Err(e.into()),
        };
        let len = file.metadata()?.len();
        let (start, end) = match range {
            Some(r) => (r.start.min(len), r.end.min(len)),
            None => (0, len),
        };
        file.seek(SeekFrom::Start(start))?;
        Ok((file, end.saturating_sub(start)))
    }

    fn stat(&self, h: &Handle) -> Result<Option<ObjMeta>, BackendError> {
        let item = {
            let mut map = self.state();
            self.sync(&mut map)?;
            match self.resolve(&map, h)? {
                Some((path, md)) => self.describe(&map, &path, &md)?,
                None => return Ok(None),
            }
        };
        // `h` may be one of several handles of the object; answer with the one asked for.
        Ok(self.finish(vec![item])?.pop().map(|meta| ObjMeta {
            handle: h.clone(),
            ..meta
        }))
    }

    fn list(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        let items = {
            let mut map = self.state();
            self.sync(&mut map)?;
            let dir = match self.resolve(&map, parent)? {
                // What is inside a trashed folder is trashed.
                Some((dir, md)) if md.is_dir() && !in_trash(&dir) => dir,
                _ => return Ok(Vec::new()),
            };
            let mut items = Vec::new();
            for (name, md) in self.children(&dir)? {
                items.push(self.describe(&map, &join(&dir, &name), &md)?);
            }
            items
        };
        let mut out = self.finish(items)?;
        for meta in &mut out {
            meta.parent = parent.clone();
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// The objects that were trashed out of `parent` (each sits in a slot of its own).
    fn list_trashed(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        let items = {
            let mut map = self.state();
            self.sync(&mut map)?;
            let dir = match self.resolve(&map, parent)? {
                Some((dir, md)) if md.is_dir() && !in_trash(&dir) => dir,
                _ => return Ok(Vec::new()),
            };
            let mut items = Vec::new();
            for (n, orig) in &map.slots {
                let (from, name) = split(orig);
                if from != dir {
                    continue;
                }
                let path = format!("{}/{name}", slot_dir(*n));
                if let Some(md) = self.lstat(&path)? {
                    items.push(self.describe(&map, &path, &md)?);
                }
            }
            items
        };
        let mut out = self.finish(items)?;
        for meta in &mut out {
            meta.parent = parent.clone();
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn find_by_name(&self, name: &str) -> Result<Vec<ObjMeta>, BackendError> {
        let items = {
            let mut map = self.state();
            self.sync(&mut map)?;
            if map.names.is_none() {
                map.names = Some(self.walk_names()?);
            }
            let mut paths = map
                .names
                .as_ref()
                .and_then(|names| names.get(name))
                .cloned()
                .unwrap_or_default();
            paths.sort();
            let mut items = Vec::new();
            for path in paths {
                if let Some(md) = self.lstat(&path)? {
                    items.push(self.describe(&map, &path, &md)?);
                }
            }
            items
        };
        self.finish(items)
    }

    fn trash(&self, h: &Handle) -> Result<(), BackendError> {
        if h.is_top() {
            return Err(bad_request("the top level cannot be trashed"));
        }
        let (mut map, _lock) = self.exclusive()?;
        let (path, _) = self.resolve(&map, h)?.ok_or(BackendError::NotFound)?;
        if in_trash(&path) {
            return Ok(());
        }
        fs::create_dir_all(self.abs(TRASH_DIR))?;
        let mut n = map.slots.keys().next_back().map_or(1, |last| last + 1);
        // A slot directory the journal does not know (the map was lost) is not reused.
        while let Err(e) = fs::create_dir(self.abs(&slot_dir(n))) {
            if e.kind() != io::ErrorKind::AlreadyExists {
                return Err(e.into());
            }
            n += 1;
        }
        let to = format!("{}/{}", slot_dir(n), split(&path).1);
        // Journal first, undone if the move fails: at every instant the object is reachable.
        let recs = vec![
            Rec::Slot {
                n,
                orig: Some(path.clone()),
            },
            Rec::Move {
                from: path.clone(),
                to: to.clone(),
            },
        ];
        self.append(&mut map, recs)?;
        if let Err(e) = fs::rename(self.abs(&path), self.abs(&to)) {
            let undo = vec![
                Rec::Move { from: to, to: path },
                Rec::Slot { n, orig: None },
            ];
            let _ = self.append(&mut map, undo);
            let _ = fs::remove_dir(self.abs(&slot_dir(n)));
            return Err(e.into());
        }
        Ok(())
    }

    fn untrash(&self, h: &Handle) -> Result<(), BackendError> {
        let (mut map, _lock) = self.exclusive()?;
        let (path, _) = self.resolve(&map, h)?.ok_or(BackendError::NotFound)?;
        // Live, or trashed only through a folder above it: nothing of its own to undo.
        let Some(n) = slot_root(&path) else {
            return Ok(());
        };
        let Some(orig) = map.slots.get(&n).cloned() else {
            return Err(no_folder("the place this object was trashed from"));
        };
        let (from, name) = split(&orig);
        let dir = match self.locate(&map, from)? {
            Some((dir, md)) if md.is_dir() => dir,
            _ => return Err(no_folder(&format!("the folder {from}"))),
        };
        let dest = join(&dir, name);
        if fs::symlink_metadata(self.abs(&dest)).is_ok() {
            return Err(name_taken(&dest));
        }
        // Move first, undone if the journal fails (see `trash`).
        fs::rename(self.abs(&path), self.abs(&dest))?;
        let mut recs: Vec<Rec> = map.vacate(&dest).into_iter().collect();
        recs.push(Rec::Move {
            from: path.clone(),
            to: dest.clone(),
        });
        recs.push(Rec::Slot { n, orig: None });
        if let Err(e) = self.append(&mut map, recs) {
            let _ = fs::rename(self.abs(&dest), self.abs(&path));
            return Err(e.into());
        }
        let _ = fs::remove_dir(self.abs(&slot_dir(n)));
        Ok(())
    }

    fn delete(&self, h: &Handle) -> Result<(), BackendError> {
        if h.is_top() {
            return Err(bad_request("the top level cannot be deleted"));
        }
        let (mut map, _lock) = self.exclusive()?;
        let (path, md) = self.resolve(&map, h)?.ok_or(BackendError::NotFound)?;
        if md.is_dir() {
            fs::remove_dir_all(self.abs(&path))?;
        } else {
            fs::remove_file(self.abs(&path))?;
        }
        // If the journal write fails the bindings merely outlive the object: they resolve to
        // nothing and are dropped when the path is used again or the journal is compacted.
        let mut recs: Vec<Rec> = map.vacate(&path).into_iter().collect();
        if let Some(n) = slot_root(&path) {
            let _ = fs::remove_dir(self.abs(&slot_dir(n)));
            if map.slots.contains_key(&n) {
                recs.push(Rec::Slot { n, orig: None });
            }
        }
        self.append(&mut map, recs)?;
        Ok(())
    }

    fn about(&self) -> Result<Quota, BackendError> {
        let live = self.tree_size(&self.root, false)?;
        let trashed = self.tree_size(&self.abs(TRASH_DIR), true)?;
        Ok(Quota {
            limit: None,
            usage: live + trashed,
            usage_in_trash: trashed,
            account: None,
        })
    }
}

/// Clones share one view of the directory.
#[derive(Clone)]
pub struct DirBackend {
    inner: Arc<Inner>,
}

impl DirBackend {
    /// `root` must be an existing directory; nothing is written to it before the first change.
    pub fn open(root: &std::path::Path) -> Result<Self, BackendError> {
        let named = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", root.display()));
        if !fs::metadata(root).map_err(named)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{} is not a directory", root.display()),
            )
            .into());
        }
        let inner = Inner {
            root: root.to_path_buf(),
            state: Mutex::default(),
        };
        inner.sync(&mut inner.state()).map_err(named)?;
        inner.housekeeping();
        Ok(DirBackend {
            inner: Arc::new(inner),
        })
    }

    pub fn root(&self) -> &std::path::Path {
        &self.inner.root
    }

    /// Runs the blocking file work of one call off the async threads.
    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Inner) -> Result<T, BackendError> + Send + 'static,
    ) -> Result<T, BackendError> {
        let inner = self.inner.clone();
        match tokio::task::spawn_blocking(move || f(&inner)).await {
            Ok(result) => result,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => Err(io::Error::other(e).into()),
        }
    }
}

impl Backend for DirBackend {
    async fn new_ids(&self, n: usize) -> Result<Vec<Handle>, BackendError> {
        Ok((0..n)
            .map(|_| Handle(util::hex(&util::random::<16>())))
            .collect())
    }

    async fn create_folder(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
    ) -> Result<(), BackendError> {
        let (id, parent, name) = (id.clone(), parent.clone(), name.to_string());
        self.run(move |dir| dir.create_folder(&id, &parent, &name))
            .await
    }

    async fn put(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
        body: PutBody,
    ) -> Result<ObjMeta, BackendError> {
        let (id, parent, name) = (id.clone(), parent.clone(), name.to_string());
        if let PutBody::Small(data) = &body {
            check_small(data.len())?;
        }
        let args = (id.clone(), parent.clone(), name.clone());
        let begun = self.run(move |dir| {
            Ok(match dir.existing(&args.0, &args.1, &args.2)? {
                Some(meta) => Err(meta),
                None => Ok(Spool::create(dir)?),
            })
        });
        let mut spool = match begun.await? {
            Ok(spool) => spool,
            Err(existing) => return Ok(existing),
        };
        // The spool travels through the blocking closures; wherever the put ends early it is
        // dropped, which removes the file.
        match body {
            PutBody::Small(data) => {
                spool = self
                    .run(move |_| spool.write(&data).map(|()| spool).map_err(Into::into))
                    .await?;
            }
            PutBody::Stream { total, parts } => {
                let mut reader = PartReader::new(total, parts);
                while let Some(part) = reader.next().await? {
                    spool = self
                        .run(move |_| spool.write(&part).map(|()| spool).map_err(Into::into))
                        .await?;
                }
            }
        }
        self.run(move |dir| dir.commit(spool, &id, &parent, &name))
            .await
    }

    async fn get(
        &self,
        h: &Handle,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<ByteStream, BackendError> {
        let h = h.clone();
        let (file, len) = self.run(move |dir| dir.open_range(&h, range)).await?;
        let reader = tokio::fs::File::from_std(file).take(len);
        let stream = tokio_util::io::ReaderStream::with_capacity(reader, GET_CHUNK);
        Ok(Box::pin(
            stream.map(|chunk| chunk.map_err(BackendError::Io)),
        ))
    }

    async fn stat(&self, h: &Handle) -> Result<Option<ObjMeta>, BackendError> {
        let h = h.clone();
        self.run(move |dir| dir.stat(&h)).await
    }

    async fn list(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        let parent = parent.clone();
        self.run(move |dir| dir.list(&parent)).await
    }

    async fn list_trashed(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        let parent = parent.clone();
        self.run(move |dir| dir.list_trashed(&parent)).await
    }

    async fn find_by_name(&self, name: &str) -> Result<Vec<ObjMeta>, BackendError> {
        let name = name.to_string();
        self.run(move |dir| dir.find_by_name(&name)).await
    }

    async fn trash(&self, h: &Handle) -> Result<(), BackendError> {
        let h = h.clone();
        self.run(move |dir| dir.trash(&h)).await
    }

    async fn untrash(&self, h: &Handle) -> Result<(), BackendError> {
        let h = h.clone();
        self.run(move |dir| dir.untrash(&h)).await
    }

    async fn delete(&self, h: &Handle) -> Result<(), BackendError> {
        let h = h.clone();
        self.run(move |dir| dir.delete(&h)).await
    }

    async fn about(&self) -> Result<Quota, BackendError> {
        self.run(|dir| dir.about()).await
    }

    fn now_ms(&self) -> u64 {
        util::now_ms()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(json: &str) -> Rec {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn path_rules() {
        assert_eq!(join("", "a"), "a");
        assert_eq!(join("a/b", "c"), "a/b/c");
        assert_eq!(split("a/b/c"), ("a/b", "c"));
        assert_eq!(split("c"), ("", "c"));

        assert!(at_or_below("a/b", "a/b"));
        assert!(at_or_below("a/b/c", "a/b"));
        assert!(!at_or_below("a/bc", "a/b"));
        assert!(!at_or_below("a", "a/b"));

        assert!(in_trash(".trash/3/x"));
        assert!(!in_trash(".trash"));
        assert!(!in_trash(".trashed/x"));
        assert!(!in_trash("a/.trash/x"));

        assert_eq!(slot_root(".trash/3/x"), Some(3));
        assert_eq!(slot_root(".trash/3/x/y"), None);
        assert_eq!(slot_root(".trash/3"), None);
        assert_eq!(slot_root(".trash/n/x"), None);
        assert_eq!(slot_root("a/b/c"), None);

        for ok in ["a", "a/b", "a b/c.d", ".trash/7/x", ".trash/7/x/y"] {
            assert!(is_object_path(ok), "{ok}");
        }
        for bad in [
            "",
            "/a",
            "a/",
            "a//b",
            ".",
            "..",
            "a/../b",
            "a/.b",
            ".trash",
            ".trash/7",
            ".trash/x/y",
            ".trash/7/.x",
            ".gclone-dir-ids.json",
            ".gclone-tmp/abc",
            "a\0b",
        ] {
            assert!(!is_object_path(bad), "{bad:?}");
        }
    }

    #[test]
    fn journal_replay() {
        let mut map = IdMap::default();
        let sig = r#"{"size":3,"mtime_ns":5,"md5":"000102030405060708090a0b0c0d0e0f"}"#;
        for line in [
            r#"{"op":"bind","id":"F","path":"f"}"#.to_string(),
            r#"{"op":"bind","id":"F2","path":"f"}"#.to_string(),
            format!(r#"{{"op":"bind","id":"X","path":"f/x","sig":{sig}}}"#),
            r#"{"op":"bind","id":"Y","path":"f-other/y"}"#.to_string(),
            r#"{"op":"bind","id":"Z","path":"fz"}"#.to_string(),
        ] {
            map.apply(rec(&line));
        }
        assert_eq!(map.by_id["X"], "f/x");
        assert_eq!(map.paths["f"].ids, ["F", "F2"]);
        assert_eq!(map.paths["f/x"].sig.unwrap().0, 3);
        assert_eq!(map.below("f"), ["f", "f/x"]);
        assert!(map.is_bound("f/x") && !map.is_bound("f/nope"));

        // Trash `f`: everything at or below it moves, its neighbours stay.
        map.apply(rec(r#"{"op":"slot","n":4,"orig":"f"}"#));
        map.apply(rec(r#"{"op":"move","from":"f","to":".trash/4/f"}"#));
        assert_eq!(map.by_id["F"], ".trash/4/f");
        assert_eq!(map.by_id["F2"], ".trash/4/f");
        assert_eq!(map.by_id["X"], ".trash/4/f/x");
        assert_eq!(map.by_id["Y"], "f-other/y");
        assert_eq!(map.by_id["Z"], "fz");
        assert_eq!(map.paths[".trash/4/f/x"].sig.unwrap().2[15], 0x0f);
        assert_eq!(map.slots[&4], "f");
        assert!(map.vacate("f").is_none());
        assert!(map.vacate(".trash/4/f").is_some());
        // Replaying a move is harmless (records are read back after every append).
        map.apply(rec(r#"{"op":"move","from":"f","to":".trash/4/f"}"#));
        assert_eq!(map.by_id.len(), 5);

        // Rebinding an id takes it away from its old path.
        map.apply(rec(r#"{"op":"bind","id":"Z","path":"elsewhere"}"#));
        assert!(!map.is_bound("fz"));
        assert_eq!(map.by_id["Z"], "elsewhere");

        // Untrash, then delete the folder.
        map.apply(rec(r#"{"op":"move","from":".trash/4/f","to":"f"}"#));
        map.apply(rec(r#"{"op":"slot","n":4,"orig":null}"#));
        assert_eq!(map.by_id["X"], "f/x");
        assert!(map.slots.is_empty());
        map.apply(rec(r#"{"op":"drop","path":"f"}"#));
        let mut left: Vec<&String> = map.by_id.keys().collect();
        left.sort();
        assert_eq!(left, ["Y", "Z"]);
        assert_eq!(map.records, 12);

        // Records round-trip through their JSON form.
        let line = serde_json::to_string(&bind(&Handle("I".into()), "p/q", Some((1, 2, [7; 16]))))
            .unwrap();
        assert_eq!(
            line,
            r#"{"op":"bind","id":"I","path":"p/q","sig":{"size":1,"mtime_ns":2,"md5":"07070707070707070707070707070707"}}"#
        );
        assert_eq!(
            serde_json::to_string(&bind(&Handle("I".into()), "p", None)).unwrap(),
            r#"{"op":"bind","id":"I","path":"p"}"#
        );
        assert!(serde_json::from_str::<Rec>(r#"{"op":"later","x":1}"#).is_err());
    }
}

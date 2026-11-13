//! A stateless, read-only replica: the newest accepted snapshot ⊕ every listed segment it does
//! not cover, applied in causal order (SPEC §5.2.2, §5.3) into the in-memory `MemIndex` — and
//! the viewer's queries over it. No rollback marks, no cache, no clock: `removed_ms` is the
//! store's creation time of each segment object, handed in by the caller — or the writer's
//! own `created_ms` where that is later (`removal_time`).
//!
//! What the answers look like — the JSON shapes, the order of a listing, how a search matches —
//! is `rules` (the main crate's `src/web/rules.rs`), so this viewer and `gclone web` agree by
//! construction; the rows come from here.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::Serialize;

use crate::crypto::{Keyring, ciphertext_len};
use crate::error::{CryptoError, IndexError};
use crate::format::{
    IndexName, Op, SegmentV1, blob_name, open_segment, open_snapshot, parse_index_name,
};
use crate::index::{MemIndex, apply_segment, causal_order, check_snapshot_format, removal_time};
use crate::types::{BlobId, BlobRec, CoveredSeg, DeviceId, EntryKind, Head, SegRef};
use crate::web::rules::{
    self, EntryJson, InfoJson, LIST_PAGE, LIST_PAGE_MAX, ListJson, RefreshState, RowView,
    SEARCH_HITS, SEARCH_HITS_MAX, SearchJson, SortOrder,
};
use crate::{Code, Error, Result, util};

/// Full identity of a segment: `(device, seq, BLAKE3(object))`.
type SegKey = (DeviceId, u64, [u8; 32]);

fn short(key: &SegKey) -> CoveredSeg {
    CoveredSeg {
        device: key.0,
        seq: key.1,
        h4: [key.2[0], key.2[1], key.2[2], key.2[3]],
    }
}

/// What `finish` reports: how far the index got, and what it still waits for.
#[derive(Serialize, Default, Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The snapshot the index is based on.
    pub snapshot: Option<String>,
    /// Segments applied since the last `reset` (or since the vault was opened).
    pub applied: u64,
    /// Names of segments in hand that wait for a reference none of the others satisfies.
    pub blocked: Vec<String>,
    /// Those references: `[device, seq, hash, file_id]`. With a non-empty `file_id` the object
    /// can be fetched by id (a listing may lag behind); one with an empty id cannot.
    pub missing: Vec<(String, u64, String, String)>,
    /// Objects that were handed in and refused as damaged: `"<name>: <why>"`.
    pub corrupt: Vec<String>,
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    /// Conflict losers (heads that are not the winner of their path).
    pub conflicts: u64,
    /// The head fingerprint (§2.6), as `gclone status` prints it.
    pub head: String,
    pub vault_name: String,
}

/// What opens one file and nothing else (design §5): where its ciphertext is, and the key of
/// that one stream. `key` and `header` are base64url; a zero-length file has neither, and no
/// location — there is nothing to fetch. It carries a key: like every key type of the tree it
/// has no `Debug`, so that no log line or panic message can print one.
#[derive(Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub v: u32,
    /// The file's name (the last component of its path): what it is served as.
    pub name: String,
    pub size: u64,
    /// The blob object: its id at the store (the fast way) and its name (the portable way).
    pub file_id: String,
    pub blob_name: String,
    /// Where the file's stream starts in the blob (at its 60-byte header) and how long it is.
    pub off: u64,
    pub clen: u64,
    pub chunk_log2: u8,
    pub key: Option<String>,
    pub header: Option<String>,
}

pub const TICKET_VERSION: u32 = 1;

/// A segment in hand: the segment and `BLAKE3(object)`, as `causal_order` takes them.
type InHand = (SegmentV1, [u8; 32]);

fn key_of(seg: &InHand) -> SegKey {
    (seg.0.device, seg.0.seq, seg.1)
}

/// What else is kept about a segment in hand, at the same index.
struct Origin {
    created_ms: u64,
    name: String,
}

/// An entry of a directory, as `Vault::list` of the main crate yields it.
pub struct ListRow<'a> {
    pub name: &'a str,
    pub is_dir: bool,
    /// `None` for a directory that exists only through what is under it.
    pub head: Option<&'a Head>,
}

impl RowView for ListRow<'_> {
    fn name(&self) -> &str {
        self.name
    }
    fn tie(&self) -> &str {
        self.name
    }
    fn is_dir(&self) -> bool {
        self.is_dir
    }
    fn head(&self) -> Option<&Head> {
        self.head
    }
}

/// A match of a search, as `Vault::search` of the main crate yields it.
pub struct SearchRow<'a> {
    pub path: String,
    pub is_dir: bool,
    /// `None` for directories.
    pub head: Option<&'a Head>,
}

impl RowView for SearchRow<'_> {
    fn name(&self) -> &str {
        crate::path::file_name(&self.path)
    }
    fn tie(&self) -> &str {
        &self.path
    }
    fn is_dir(&self) -> bool {
        self.is_dir
    }
    fn head(&self) -> Option<&Head> {
        self.head
    }
}

pub struct Reader {
    keys: Keyring,
    mem: MemIndex,
    base: Option<String>,
    /// The base snapshot's coverage set.
    covered: BTreeSet<CoveredSeg>,
    /// Per device the greatest `(seq, hash)` applied or covered: the head fingerprint's input.
    hw: BTreeMap<DeviceId, (u64, [u8; 32])>,
    /// Segments in hand that are not applied yet, and (same index) where they came from.
    pending: Vec<InHand>,
    origins: Vec<Origin>,
    applied: HashSet<SegKey>,
    /// The same set by the identity a name carries, for `needed_segments`.
    applied_short: HashSet<CoveredSeg>,
    applied_count: u64,
    /// `name → why`, for objects refused as damaged.
    corrupt: BTreeMap<String, String>,
    /// Per known device the time it was last seen alive, as the SQL replica keeps it
    /// (`devices.last_ms`): a snapshot's `first_ms` — for the snapshot's writer its `created_ms` —
    /// raised by every applied segment.
    last_seen: BTreeMap<DeviceId, u64>,
    // The view, rebuilt by `finish`.
    /// Winners, sorted by path.
    winners: Vec<Head>,
    blobs: BTreeMap<BlobId, BlobRec>,
    conflicts: u64,
    files: u64,
    dirs: u64,
    bytes: u64,
    last_change: Option<(u64, String)>,
}

fn raise(hw: &mut BTreeMap<DeviceId, (u64, [u8; 32])>, device: DeviceId, seq: u64, hash: [u8; 32]) {
    let mark = hw.entry(device).or_insert((seq, hash));
    if (seq, hash) > *mark {
        *mark = (seq, hash);
    }
}

fn bad_input(what: impl Into<String>) -> Error {
    Error::new(Code::BadInput, what)
}

/// An optional count that crossed the JS boundary: absent means `default`; anything that is
/// not a whole number up to `max` is refused with the local viewer's sentence.
fn count(value: Option<f64>, name: &str, default: usize, max: usize) -> Result<usize> {
    let Some(value) = value else {
        return Ok(default);
    };
    match crate::integer(value, name) {
        Ok(n) if n <= max as u64 => Ok(n as usize),
        _ => Err(bad_input(rules::not_a_number(name, max))),
    }
}

impl Reader {
    pub fn new(keys: Keyring) -> Self {
        Reader {
            keys,
            mem: MemIndex::default(),
            base: None,
            covered: BTreeSet::new(),
            hw: BTreeMap::new(),
            pending: Vec::new(),
            origins: Vec::new(),
            applied: HashSet::new(),
            applied_short: HashSet::new(),
            applied_count: 0,
            corrupt: BTreeMap::new(),
            last_seen: BTreeMap::new(),
            winners: Vec::new(),
            blobs: BTreeMap::new(),
            conflicts: 0,
            files: 0,
            dirs: 0,
            bytes: 0,
            last_change: None,
        }
    }

    pub fn keys(&self) -> &Keyring {
        &self.keys
    }

    /// Forgets the index — the snapshot, every segment, everything refused — and keeps the keys.
    pub fn reset(&mut self) {
        *self = Reader::new(self.keys.clone());
    }

    // -----------------------------------------------------------------------------------------
    // Loading
    // -----------------------------------------------------------------------------------------

    /// Every snapshot name of a listing, newest first: the greatest lamport, then the greatest
    /// name (the order the CLI tries them in). Names are unauthenticated hints; a name listed
    /// twice comes back twice.
    pub fn snapshot_candidates(names: &[String]) -> Vec<String> {
        let mut snaps: Vec<&String> = names
            .iter()
            .filter(|n| matches!(parse_index_name(n), Some(IndexName::Snapshot { .. })))
            .collect();
        // `c-<lamport:016x>-…`: the name's order is the lamport's.
        snaps.sort_by(|a, b| b.cmp(a));
        snaps.into_iter().cloned().collect()
    }

    /// §4.6 acceptance and the format gate, then the snapshot becomes the base. `Ok(false)`:
    /// the object is damaged (recorded) — try the next candidate. `needs-newer`: the object,
    /// or the vault it describes, is of a format this build does not read — stop.
    pub fn load_snapshot(&mut self, name: &str, bytes: &[u8]) -> Result<bool> {
        if self.base.is_some() || self.applied_count > 0 || !self.pending.is_empty() {
            return Err(bad_input(
                "load_snapshot comes before every segment, and once: call reset() first",
            ));
        }
        let snap = match open_snapshot(&self.keys, name, bytes) {
            Ok((snap, _)) => snap,
            Err(e) => {
                if let Some(what) = e.newer_format() {
                    return Err(newer(format!("index object {name}: {what}")));
                }
                self.corrupt.insert(name.to_owned(), e.to_string());
                return Ok(false);
            }
        };
        check_snapshot_format(&snap).map_err(|_| {
            newer(format!(
                "snapshot {name} holds a vault of format {}",
                snap.vault_format
            ))
        })?;
        self.mem = MemIndex::load_snapshot(&snap);
        self.covered = snap.covered.iter().copied().collect();
        for tip in &snap.covers {
            raise(&mut self.hw, tip.device, tip.seq, tip.hash);
        }
        self.last_seen = snap.devices.iter().map(|d| (d.id, d.first_ms)).collect();
        // `refresh::set_base` of the SQL replica: the snapshot's writer was alive at the
        // snapshot's time. Without it a reader that starts from a snapshot — this one, on
        // every visit — names the device that joined last as the vault's last change.
        if let Some(seen) = self.last_seen.get_mut(&snap.device) {
            *seen = (*seen).max(snap.created_ms);
        }
        self.corrupt.remove(name);
        self.base = Some(name.to_owned());
        Ok(true)
    }

    /// Whether the segment with this identity needs no (further) download.
    fn settled(&self, id: &CoveredSeg) -> bool {
        self.covered.contains(id)
            || self.applied_short.contains(id)
            || self.pending.iter().any(|p| short(&key_of(p)) == *id)
    }

    /// The listed segments that have to be fetched: not covered by the base, not in hand, not
    /// applied. Over an unchanged listing, after `finish`, that is nothing.
    pub fn needed_segments(&self, names: &[String]) -> Vec<String> {
        names
            .iter()
            .filter(|n| match parse_index_name(n) {
                Some(IndexName::Segment { device, seq, h8 }) => !self.settled(&CoveredSeg {
                    device,
                    seq,
                    h4: h8,
                }),
                _ => false,
            })
            .cloned()
            .collect()
    }

    /// Takes a segment object in hand. `created_ms`: the store's creation time of the object
    /// (the time its deletions are dated with); `None` when the store did not say — the
    /// segment's own claim is used then, as the CLI does. `Ok(false)`: the object is damaged
    /// (recorded). `needs-newer`: it is of a format this build does not read.
    pub fn add_segment(
        &mut self,
        name: &str,
        bytes: &[u8],
        created_ms: Option<u64>,
    ) -> Result<bool> {
        match open_segment(&self.keys, name, bytes) {
            Ok((seg, hash)) => {
                let key = (seg.device, seg.seq, hash);
                let inert = self.applied.contains(&key)
                    || self.covered.contains(&short(&key))
                    || self.pending.iter().any(|p| key_of(p) == key);
                if !inert {
                    self.origins.push(Origin {
                        created_ms: created_ms.unwrap_or(seg.created_ms),
                        name: name.to_owned(),
                    });
                    self.pending.push((seg, hash));
                }
                self.corrupt.remove(name);
                Ok(true)
            }
            Err(e) => {
                if let Some(what) = e.newer_format() {
                    return Err(newer(format!("index object {name}: {what}")));
                }
                // A second object under the name of a segment that is already here (a store
                // may list two) is not that segment being damaged.
                let duplicate = match parse_index_name(name) {
                    Some(IndexName::Segment { device, seq, h8 }) => self.settled(&CoveredSeg {
                        device,
                        seq,
                        h4: h8,
                    }),
                    _ => false,
                };
                if !duplicate {
                    self.corrupt.insert(name.to_owned(), e.to_string());
                }
                Ok(false)
            }
        }
    }

    /// Applies what is applicable now, in causal order; what stays blocked is reported with
    /// the references it waits for. May be called again after more segments were added.
    /// `needs-newer`: a segment declares a vault format this build does not read — nothing of
    /// that segment was applied, and the load has to stop.
    pub fn finish(&mut self) -> Result<Report> {
        let (order, blocked) = {
            let (covered, applied) = (&self.covered, &self.applied);
            let satisfied = |r: &SegRef| {
                covered.contains(&r.covered()) || applied.contains(&(r.device, r.seq, r.hash))
            };
            causal_order(&self.pending, &satisfied)
        };
        let mut done = vec![false; self.pending.len()];
        let mut failed = None;
        for &i in &order {
            let (seg, origin) = (&self.pending[i].0, &self.origins[i]);
            let created_ms = origin.created_ms;
            // As the CLI's replica does (`index::commit::apply_and_record`).
            match apply_segment(&mut self.mem, seg, removal_time(seg, created_ms)) {
                Ok(_) => {}
                Err(IndexError::NeedsNewerGclone) => {
                    failed = Some(newer(format!(
                        "segment {} declares a newer vault format",
                        origin.name
                    )));
                    break;
                }
                Err(e) => {
                    // Cannot happen for an accepted segment (the one other failure is a
                    // segment of more than 2^32 ops); refused like any damaged object.
                    self.corrupt.insert(origin.name.clone(), e.to_string());
                    done[i] = true;
                    continue;
                }
            }
            let key = key_of(&self.pending[i]);
            self.applied.insert(key);
            self.applied_short.insert(short(&key));
            raise(&mut self.hw, key.0, key.1, key.2);
            self.applied_count += 1;
            // `devices.last_ms` of the SQL replica: a `Device` op is an upsert with this
            // time; the writer of an applied segment was alive at this time, if it is known.
            for op in &seg.ops {
                if let Op::Device { id, .. } = op {
                    let seen = self.last_seen.entry(*id).or_insert(created_ms);
                    *seen = (*seen).max(created_ms);
                }
            }
            if let Some(seen) = self.last_seen.get_mut(&key.0) {
                *seen = (*seen).max(created_ms);
            }
            done[i] = true;
        }

        let mut missing = Vec::new();
        if failed.is_none() {
            let in_hand: HashSet<SegKey> = self.pending.iter().map(key_of).collect();
            for &i in &blocked {
                let seg = &self.pending[i].0;
                for r in seg.prev.iter().chain(&seg.seen) {
                    let key = (r.device, r.seq, r.hash);
                    if !self.covered.contains(&r.covered())
                        && !self.applied.contains(&key)
                        && !in_hand.contains(&key)
                    {
                        missing.push((
                            r.device.hex(),
                            r.seq,
                            util::hex(&r.hash),
                            r.file_id.clone(),
                        ));
                    }
                }
            }
            missing.sort();
            missing.dedup();
        }
        let blocked_names: Vec<String> = blocked
            .iter()
            .map(|&i| self.origins[i].name.clone())
            .collect();
        // What was applied (or refused) leaves the hand, whatever happened after it.
        let mut left = done.iter().map(|done| !done);
        self.pending.retain(|_| left.next().unwrap_or(true));
        let mut left = done.iter().map(|done| !done);
        self.origins.retain(|_| left.next().unwrap_or(true));
        self.rebuild_view();
        if let Some(e) = failed {
            return Err(e);
        }
        Ok(Report {
            snapshot: self.base.clone(),
            applied: self.applied_count,
            blocked: blocked_names,
            missing,
            corrupt: self
                .corrupt
                .iter()
                .map(|(name, why)| format!("{name}: {why}"))
                .collect(),
            files: self.files,
            dirs: self.dirs,
            bytes: self.bytes,
            conflicts: self.conflicts,
            head: self.head_fingerprint(),
            vault_name: self.mem.vault().1.to_owned(),
        })
    }

    fn rebuild_view(&mut self) {
        let all = self.mem.all_heads();
        self.conflicts = all.iter().filter(|h| !h.winner).count() as u64;
        self.winners = all.into_iter().filter(|h| h.winner).collect();
        self.blobs = self.mem.blobs().into_iter().map(|b| (b.id, b)).collect();
        (self.files, self.dirs, self.bytes) = (0, 0, 0);
        for h in &self.winners {
            match h.entry.kind {
                EntryKind::File => {
                    self.files += 1;
                    self.bytes += h.entry.size;
                }
                EntryKind::Dir => self.dirs += 1,
            }
        }
        // `SELECT name, last_ms FROM devices ORDER BY last_ms DESC, id LIMIT 1`.
        let names: BTreeMap<DeviceId, String> = self
            .mem
            .devices()
            .into_iter()
            .map(|d| (d.id, d.name))
            .collect();
        self.last_change = self
            .last_seen
            .iter()
            .filter_map(|(id, ms)| Some((*ms, std::cmp::Reverse(*id), names.get(id)?)))
            .max()
            .map(|(ms, _, name)| (ms, name.clone()));
    }

    /// §2.6: the value `gclone status` prints on a device that has applied the same journal.
    pub fn head_fingerprint(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(b"gclone/v1/head");
        for (device, (seq, hash)) in &self.hw {
            h.update(&device.0);
            h.update(&seq.to_be_bytes());
            h.update(hash);
        }
        let code = util::crockford_encode(&h.finalize().as_bytes()[..5]);
        format!("{}-{}", &code[..4], &code[4..])
    }

    // -----------------------------------------------------------------------------------------
    // Queries (over the view of the last `finish`)
    // -----------------------------------------------------------------------------------------

    /// Index of the first winner whose path is not below `from`.
    fn first_at(&self, from: &str) -> usize {
        self.winners.partition_point(|h| h.path.as_str() < from)
    }

    /// The winner at `path`.
    pub fn head(&self, path: &str) -> Option<&Head> {
        self.winners
            .get(self.first_at(path))
            .filter(|h| h.path == path)
    }

    /// A directory head at `path`, or any winner under `path/`. The root always exists.
    pub fn exists_dir(&self, path: &str) -> bool {
        if path.is_empty() {
            return true;
        }
        if self
            .head(path)
            .is_some_and(|h| h.entry.kind == EntryKind::Dir)
        {
            return true;
        }
        // `'/' + 1 == '0'`: the paths under `path/` are those between the two.
        let (lo, hi) = (format!("{path}/"), format!("{path}0"));
        self.winners
            .get(
                self.winners
                    .partition_point(|h| h.path.as_str() <= lo.as_str()),
            )
            .is_some_and(|h| h.path.as_str() < hi.as_str())
    }

    /// The direct children of `dir` (`""` = the root), implied directories included, by name:
    /// what `Vault::list` of the main crate returns. One seek per child; subtrees are skipped.
    pub fn list_rows(&self, dir: &str) -> Vec<ListRow<'_>> {
        let lo = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        let mut rows: BTreeMap<&str, ListRow<'_>> = BTreeMap::new();
        // Paths strictly after `lo` (`dir/` itself is no path).
        let mut i = self
            .winners
            .partition_point(|h| h.path.as_str() <= lo.as_str());
        while let Some(h) = self.winners.get(i).filter(|h| h.path.starts_with(&lo)) {
            let rel = &h.path[lo.len()..];
            let (name, direct) = match rel.split_once('/') {
                Some((name, _)) => (name, false),
                None => (rel, true),
            };
            let row = rows.entry(name).or_insert(ListRow {
                name,
                is_dir: false,
                head: None,
            });
            if direct {
                row.is_dir |= h.entry.kind == EntryKind::Dir;
                row.head = Some(h);
                i += 1;
            } else {
                row.is_dir = true;
                // The first path after the subtree.
                i = self.first_at(&format!("{lo}{name}0"));
            }
        }
        rows.into_values().collect()
    }

    /// `list` of the viewer's API: `path` (`""` = the root), `sort` (`name`, `size`, `mtime`),
    /// `order` (`asc`, `desc`), `offset`, `limit` — absent means the local viewer's default.
    pub fn list(
        &self,
        path: &str,
        sort: Option<&str>,
        order: Option<&str>,
        offset: Option<f64>,
        limit: Option<f64>,
    ) -> Result<ListJson> {
        let path = rules::dir_path(Some(path)).map_err(bad_input)?;
        let by = SortOrder::parse(sort, order).map_err(bad_input)?;
        let offset = count(offset, "offset", 0, usize::MAX)?;
        let limit = count(limit, "limit", LIST_PAGE, LIST_PAGE_MAX)?;
        if limit == 0 {
            return Err(bad_input(rules::LIMIT_IS_ZERO));
        }
        if !self.exists_dir(&path) {
            return Err(Error::new(Code::NotFound, rules::no_folder(&path)));
        }
        let rows = self.list_rows(&path);
        Ok(rules::list_json(path, rows, by, offset, limit))
    }

    /// `stat` of the viewer's API: the entry at `path`, with its path.
    pub fn stat(&self, path: &str) -> Result<EntryJson> {
        let path = rules::entry_path(Some(path)).map_err(bad_input)?;
        let name = crate::path::file_name(&path);
        match (self.head(&path), self.exists_dir(&path)) {
            (_, true) => Ok(EntryJson::new(name, Some(path.clone()), true, None)),
            (Some(head), false) => Ok(EntryJson::new(name, Some(path.clone()), false, Some(head))),
            (None, false) => Err(Error::new(Code::NotFound, rules::no_file(&path))),
        }
    }

    /// The matches of a search, as `Vault::search` of the main crate returns them: files and
    /// directories whose name contains `needle`, in the order found, at most `limit`.
    pub fn search_rows(&self, needle: &str, limit: usize) -> (Vec<SearchRow<'_>>, bool) {
        let rows = self.winners.iter().map(|h| {
            Ok::<_, std::convert::Infallible>((h.path.as_str(), h.entry.kind == EntryKind::Dir))
        });
        let (found, more) = match rules::search_paths(rows, needle, limit) {
            Ok(found) => found,
            Err(never) => match never {},
        };
        let hits = found
            .into_iter()
            .map(|(path, is_dir)| SearchRow {
                head: if is_dir { None } else { self.head(&path) },
                path,
                is_dir,
            })
            .collect();
        (hits, more)
    }

    /// `search` of the viewer's API.
    pub fn search(
        &self,
        q: &str,
        limit: Option<f64>,
        sort: Option<&str>,
        order: Option<&str>,
    ) -> Result<SearchJson> {
        let q = q.trim().to_owned();
        let limit = count(limit, "limit", SEARCH_HITS, SEARCH_HITS_MAX)?;
        let by = SortOrder::parse(sort, order).map_err(bad_input)?;
        let (hits, more) = self.search_rows(&q, limit);
        Ok(rules::search_json(q, hits, more, by))
    }

    /// `info` (and the answer to `refresh`) of the viewer's API. `vault` is the name the index
    /// carries — empty until a `VaultInit` was applied.
    pub fn info(&self, refresh: RefreshState) -> InfoJson {
        InfoJson {
            vault: self.mem.vault().1.to_owned(),
            backend: "drive",
            device: "this browser".to_owned(),
            version: env!("CARGO_PKG_VERSION"),
            read_only: true,
            files: self.files,
            bytes: self.bytes,
            last_change_ms: self.last_change.as_ref().map(|c| c.0),
            last_change_by: self.last_change.as_ref().map(|c| c.1.clone()),
            refresh,
            head: Some(self.head_fingerprint()),
        }
    }

    /// The ticket of the file at `path`, after the checks of the CLI's reader
    /// (`transfer::download::data_member`), in its order: the entry is a file; its stream is
    /// one this build reads and its key epoch is held; its blob is in the index; its length
    /// and its location agree; the location lies inside the blob.
    pub fn ticket(&self, path: &str) -> Result<Ticket> {
        let path = rules::entry_path(Some(path)).map_err(bad_input)?;
        let name = crate::path::file_name(&path).to_owned();
        let entry = match self.head(&path) {
            Some(head) if head.entry.kind == EntryKind::File => &head.entry,
            Some(_) => return Err(Error::new(Code::NotAFile, format!("{path:?} is a folder."))),
            None if self.exists_dir(&path) => {
                return Err(Error::new(Code::NotAFile, format!("{path:?} is a folder.")));
            }
            None => return Err(Error::new(Code::NotFound, rules::no_file(&path))),
        };
        let corrupt = |what: &str| Error::new(Code::Corrupt, format!("{path:?}: {what}"));
        let Some(loc) = &entry.loc else {
            return if entry.size == 0 {
                Ok(Ticket {
                    v: TICKET_VERSION,
                    name,
                    size: 0,
                    file_id: String::new(),
                    blob_name: String::new(),
                    off: 0,
                    clen: 0,
                    chunk_log2: 0,
                    key: None,
                    header: None,
                })
            } else {
                Err(corrupt("the entry has no content location"))
            };
        };
        let opener = self.keys.data_opener(loc).map_err(|e| match e {
            CryptoError::Unsupported(_) | CryptoError::UnknownEpoch(_) => {
                newer(format!("{path:?}: {e}"))
            }
            e => corrupt(&e.to_string()),
        })?;
        let Some(blob) = self.blobs.get(&loc.blob) else {
            return Err(corrupt(&format!("blob {} is not in the index", loc.blob)));
        };
        if entry.size == 0 || loc.clen != ciphertext_len(entry.size, loc.chunk_log2) {
            return Err(corrupt("the entry's length and location disagree"));
        }
        if loc
            .off
            .checked_add(loc.clen)
            .is_none_or(|end| end > blob.clen)
        {
            return Err(corrupt("the entry's location is outside the blob"));
        }
        let (key, header) = opener.export_ticket();
        Ok(Ticket {
            v: TICKET_VERSION,
            name,
            size: entry.size,
            file_id: blob.file_id.clone(),
            blob_name: blob_name(&blob.id),
            off: loc.off,
            clen: loc.clen,
            chunk_log2: loc.chunk_log2,
            key: Some(util::b64url(key.as_slice())),
            header: Some(util::b64url(&header)),
        })
    }
}

fn newer(what: String) -> Error {
    Error::new(
        Code::NeedsNewer,
        format!("this vault needs a newer viewer ({what})"),
    )
}

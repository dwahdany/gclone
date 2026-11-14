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
use crate::types::{CoveredSeg, DeviceId, Entry, EntryKind, Head, SegRef};
use crate::web::past::{self, History, MemSource, Resolved};
use crate::web::rules::{
    self, DeletedJson, EntryJson, InfoJson, LIST_PAGE, LIST_PAGE_MAX, ListJson, RefreshState,
    RowView, SEARCH_HITS, SEARCH_HITS_MAX, SearchJson, SortOrder, TimelineJson, VersionsJson,
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
    /// What the questions about the past derive once per state of the index (`past`): built
    /// by the first of them, dropped by `finish`.
    history: Option<History>,
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
            history: None,
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
        // The index changed: what was derived from it is void.
        self.history = None;
        // The heads come by `(path, stamp, hash)`: the last head of a path is its winner.
        // Borrowed, one at a time — no second copy of every head on the way.
        let mut winners: Vec<Head> = Vec::new();
        self.conflicts = 0;
        for (path, stamp, entry, origin) in self.mem.heads_iter() {
            let head = |path: String| Head {
                path,
                stamp: *stamp,
                entry: entry.clone(),
                origin: origin.copied(),
                winner: true,
            };
            match winners.last_mut().filter(|w| w.path == path) {
                Some(loser) => {
                    self.conflicts += 1;
                    *loser = head(std::mem::take(&mut loser.path));
                }
                None => winners.push(head(path.to_owned())),
            }
        }
        winners.shrink_to_fit();
        self.winners = winners;
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
        self.last_change = self
            .last_seen
            .iter()
            .filter_map(|(id, ms)| Some((*ms, std::cmp::Reverse(*id), self.mem.device_name(id)?)))
            .max()
            .map(|(ms, _, name)| (ms, name.to_owned()));
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
        let entry = match self.head(&path) {
            Some(head) if head.entry.kind == EntryKind::File => &head.entry,
            Some(_) => return Err(Error::new(Code::NotAFile, format!("{path:?} is a folder."))),
            None if self.exists_dir(&path) => {
                return Err(Error::new(Code::NotAFile, format!("{path:?} is a folder.")));
            }
            None => return Err(Error::new(Code::NotFound, rules::no_file(&path))),
        };
        self.mint(&path, entry)
    }

    /// The ticket of one version of the file at `path` — the one the id `v` names
    /// (`past::resolve`: a file head, or a removed version inside the restore window at
    /// `now`) — after the same checks, by the same code. Without `v`: [`Reader::ticket`].
    pub fn ticket_of(&self, path: &str, v: Option<&str>, now: Option<f64>) -> Result<Ticket> {
        let Some(v) = v else {
            return self.ticket(path);
        };
        let path = rules::entry_path(Some(path)).map_err(bad_input)?;
        let v = rules::parse_v(v).map_err(bad_input)?;
        let now = now_of(now)?;
        let not_kept = || Error::new(Code::NotFound, rules::NOT_KEPT);
        let found = match past::resolve(&mut MemSource(&self.mem), &path, v, now) {
            Ok(found) => found,
            Err(never) => match never {},
        };
        let Resolved::One(ver) = found else {
            return Err(not_kept());
        };
        let entry = self
            .mem
            .version(&path, &ver.stamp, &ver.hash)
            .ok_or_else(not_kept)?;
        self.mint(&path, entry)
    }

    /// The ticket of a file entry of `path`: every check, whichever version it is.
    fn mint(&self, path: &str, entry: &Entry) -> Result<Ticket> {
        let name = crate::path::file_name(path).to_owned();
        if entry.kind != EntryKind::File {
            return Err(Error::new(Code::NotAFile, format!("{path:?} is a folder.")));
        }
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
        let Some(blob) = self.mem.blob(&loc.blob) else {
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

    // -----------------------------------------------------------------------------------------
    // The past (`web::past`, the main crate's `src/web/past.rs`): the same questions for an
    // earlier moment, the versions of a file, what was deleted, the timeline. This module
    // reads no clock: `now` — milliseconds since 1970 — comes from the caller.
    // -----------------------------------------------------------------------------------------

    /// The index as a source of history, and what is derived from it once (built here by the
    /// first question, or again when `now` went back behind the floor it was built with).
    fn past(&mut self, now: u64) -> (ViewSource<'_>, &History) {
        if !self.history.as_ref().is_some_and(|h| h.serves(now)) {
            self.history = None;
        }
        let mem = &self.mem;
        let history = self
            .history
            .get_or_insert_with(|| History::of_mem(mem, now));
        // Without conflicts the winners are all the heads there are.
        let winners = (self.conflicts == 0).then_some(self.winners.as_slice());
        (ViewSource { mem, winners }, history)
    }

    /// `list` for the moment `at` (moved into the window and echoed): the folder as it was.
    /// A folder that did not exist then is no error: `absent`, with the nearest that did.
    #[allow(clippy::too_many_arguments)]
    pub fn list_at(
        &mut self,
        path: &str,
        sort: Option<&str>,
        order: Option<&str>,
        offset: Option<f64>,
        limit: Option<f64>,
        at: f64,
        now: Option<f64>,
    ) -> Result<ListJson> {
        let path = rules::dir_path(Some(path)).map_err(bad_input)?;
        let by = SortOrder::parse(sort, order).map_err(bad_input)?;
        let offset = count(offset, "offset", 0, usize::MAX)?;
        let limit = count(limit, "limit", LIST_PAGE, LIST_PAGE_MAX)?;
        if limit == 0 {
            return Err(bad_input(rules::LIMIT_IS_ZERO));
        }
        let (at, t, now) = moment_of(at, now)?;
        let (mut src, history) = self.past(now);
        let listing = infallible(past::list_at(&mut src, history, &path, t));
        Ok(past::list_answer(path, listing, by, offset, limit, at))
    }

    /// `stat` for the moment `at`, or of the version `v` (not both): the entry with the id of
    /// the version shown.
    pub fn stat_at(
        &mut self,
        path: &str,
        at: Option<f64>,
        v: Option<&str>,
        now: Option<f64>,
    ) -> Result<EntryJson> {
        let path = rules::entry_path(Some(path)).map_err(bad_input)?;
        let row = match (at, v) {
            (Some(_), Some(_)) => return Err(bad_input(rules::AT_OR_V)),
            (None, None) => return self.stat(&path),
            (None, Some(v)) => {
                let v = rules::parse_v(v).map_err(bad_input)?;
                let now = now_of(now)?;
                infallible(past::stat_version(&mut MemSource(&self.mem), &path, v, now))
                    .ok_or_else(|| Error::new(Code::NotFound, rules::NOT_KEPT))?
            }
            (Some(at), None) => {
                let (_, t, now) = moment_of(at, now)?;
                let (mut src, history) = self.past(now);
                infallible(past::stat_at(&mut src, history, &path, t))
                    .ok_or_else(|| Error::new(Code::NotFound, rules::not_then(&path)))?
            }
        };
        Ok(row.json())
    }

    /// `search` for the moment `at`.
    pub fn search_at(
        &mut self,
        q: &str,
        limit: Option<f64>,
        sort: Option<&str>,
        order: Option<&str>,
        at: f64,
        now: Option<f64>,
    ) -> Result<SearchJson> {
        let q = q.trim().to_owned();
        let limit = count(limit, "limit", SEARCH_HITS, SEARCH_HITS_MAX)?;
        let by = SortOrder::parse(sort, order).map_err(bad_input)?;
        let (at, t, now) = moment_of(at, now)?;
        let (mut src, history) = self.past(now);
        let (hits, more) = infallible(past::search_at(&mut src, history, &q, limit, t));
        Ok(past::search_answer(q, hits, more, by, at))
    }

    /// `versions`: the versions of one file that are kept; `at` marks the one of that moment.
    pub fn versions(
        &mut self,
        path: &str,
        at: Option<f64>,
        now: Option<f64>,
    ) -> Result<VersionsJson> {
        let path = rules::entry_path(Some(path)).map_err(bad_input)?;
        let (t, now) = match at {
            Some(at) => {
                let (_, t, now) = moment_of(at, now)?;
                (Some(t), now)
            }
            None => (None, now_of(now)?),
        };
        let (mut src, history) = self.past(now);
        Ok(infallible(past::versions(&mut src, history, &path, t, now)))
    }

    /// `deleted`: what was deleted from a folder and is kept, in pages like a listing.
    pub fn deleted(
        &self,
        path: &str,
        sort: Option<&str>,
        order: Option<&str>,
        offset: Option<f64>,
        limit: Option<f64>,
        now: Option<f64>,
    ) -> Result<DeletedJson> {
        let path = rules::dir_path(Some(path)).map_err(bad_input)?;
        let by = SortOrder::parse(sort, order).map_err(bad_input)?;
        let offset = count(offset, "offset", 0, usize::MAX)?;
        let limit = count(limit, "limit", LIST_PAGE, LIST_PAGE_MAX)?;
        if limit == 0 {
            return Err(bad_input(rules::LIMIT_IS_ZERO));
        }
        let now = now_of(now)?;
        match infallible(past::deleted(&mut MemSource(&self.mem), &path, now)) {
            Some(found) => Ok(past::deleted_json(path, found, by, offset, limit)),
            None => Err(Error::new(Code::NotFound, rules::no_folder(&path))),
        }
    }

    /// `timeline`: the moments inside the window at which the vault changed.
    pub fn timeline(&mut self, now: Option<f64>) -> Result<TimelineJson> {
        let now = now_of(now)?;
        let (src, history) = self.past(now);
        Ok(past::timeline(&src, history, now))
    }
}

/// The index as `web::past` reads it: the in-memory index, and — for the one pass over
/// everything that a search of the past makes — the view's winners in place of the index's
/// heads, when they are the same heads (no conflict loser): the rows a search of the present
/// reads, laid out side by side.
struct ViewSource<'a> {
    mem: &'a MemIndex,
    winners: Option<&'a [Head]>,
}

impl past::Source for ViewSource<'_> {
    type Err = std::convert::Infallible;

    fn heads_from(&mut self, from: &str, hi: Option<&str>) -> PastRows {
        MemSource(self.mem).heads_from(from, hi)
    }

    fn removed_from(&mut self, from: &str, hi: Option<&str>) -> PastRows {
        MemSource(self.mem).removed_from(from, hi)
    }

    fn device_name(&self, id: &DeviceId) -> Option<String> {
        self.mem.device_name(id).map(str::to_owned)
    }

    fn walk(
        &mut self,
        from: &str,
        hi: Option<&str>,
        visit: &mut dyn FnMut(&past::Group) -> bool,
    ) -> std::result::Result<(), Self::Err> {
        let (Some(winners), true, None) = (self.winners, from.is_empty(), hi) else {
            return MemSource(self.mem).walk(from, hi, visit);
        };
        // Each winner is a path of its own: one comparison per path decides which side is next.
        use std::cmp::Ordering;
        let mut heads = winners.iter().peekable();
        let mut removed = self.mem.removed_range("", None).peekable();
        let mut group = past::Group::default();
        loop {
            let next = match (heads.peek(), removed.peek()) {
                (None, None) => return Ok(()),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (Some(head), Some(gone)) => head.path.as_str().cmp(gone.0),
            };
            group.heads.clear();
            group.removed.clear();
            match (next, heads.peek(), removed.peek()) {
                (Ordering::Greater, _, Some(gone)) => {
                    group.path.clear();
                    group.path.push_str(gone.0);
                }
                (_, Some(head), _) => {
                    group.path.clone_from(&head.path);
                    group
                        .heads
                        .push(past::Ver::of(&head.stamp, &head.entry, None));
                    heads.next();
                }
                _ => return Ok(()),
            }
            if next != Ordering::Less {
                while let Some((_, stamp, entry, ms, by)) =
                    removed.next_if(|gone| gone.0 == group.path)
                {
                    group
                        .removed
                        .push(past::Ver::of(stamp, entry, Some((*by, ms))));
                }
                if group.removed.len() > 1 {
                    past::by_removal(&mut group.removed);
                }
            }
            if !visit(&group) {
                return Ok(());
            }
        }
    }
}

/// What a source over the in-memory index answers: it cannot fail.
type PastRows = std::result::Result<Option<past::PathVers>, std::convert::Infallible>;

/// The in-memory index never fails to answer.
fn infallible<T>(answer: std::result::Result<T, std::convert::Infallible>) -> T {
    match answer {
        Ok(value) => value,
        Err(never) => match never {},
    }
}

/// "Now" of a question about the past: required, a whole number of milliseconds.
fn now_of(now: Option<f64>) -> Result<u64> {
    match now {
        Some(now) => crate::integer(now, "now"),
        None => Err(bad_input("now is missing")),
    }
}

/// `at` of a call: `(the value to echo, the moment it stands for, now)`.
fn moment_of(at: f64, now: Option<f64>) -> Result<(u64, u64, u64)> {
    let now = now_of(now)?;
    let at = crate::integer(at, "at").map_err(|_| bad_input(rules::BAD_TIME))?;
    let at = past::clamp_at(at, now);
    Ok((at, past::moment(at, now), now))
}

fn newer(what: String) -> Error {
    Error::new(
        Code::NeedsNewer,
        format!("this vault needs a newer viewer ({what})"),
    )
}

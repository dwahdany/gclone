//! The merge rule (SPEC §5.2.2, §9.7) — owned by WP4. Pure and generic, so it is
//! property-testable without SQLite.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet};

use crate::consts::HISTORY_KEEP_MS;
use crate::error::{FormatError, IndexError, StateError};
use crate::format::{DeviceRec, HeadRec, Op, RemovedRec, SUPPORTED_FORMAT, SegmentV1, SnapshotV1};
use crate::types::{
    BlobId, BlobRec, CoveredSeg, DeviceId, Entry, Head, RemovedVersion, SegRef, Stamp,
};

/// Every method is fallible: the production implementation is a SQLite transaction; `MemIndex`
/// always returns `Ok`.
pub trait HeadStore {
    fn heads(&self, path: &str) -> Result<Vec<Head>, StateError>;

    /// §5.2.2 `supersede`: moves every head `(path, stamp)` to `removed` with `(removed_ms, by)`;
    /// for an existing `removed` row `(path, stamp)` whose recorded `by` is greater, replaces
    /// `(removed_ms, by)`. Returns the number of heads moved.
    ///
    /// Fork twins can supersede under one `by` stamp with different `removed_ms`: the smaller
    /// `(by, removed_ms)` pair is the one recorded, so the result never depends on the order.
    fn supersede(
        &mut self,
        path: &str,
        stamp: &Stamp,
        removed_ms: u64,
        by: Stamp,
    ) -> Result<usize, StateError>;

    /// Then recompute winner flags.
    fn insert_head(
        &mut self,
        path: &str,
        stamp: Stamp,
        entry: &Entry,
        origin: Option<Stamp>,
    ) -> Result<(), StateError>;

    fn upsert_blob(&mut self, rec: &BlobRec) -> Result<(), StateError>;

    fn upsert_device(&mut self, id: DeviceId, name: &str, seen_ms: u64) -> Result<(), StateError>;

    fn set_vault(&mut self, format: u16, name: &str) -> Result<(), StateError>;
}

/// Total order used when two versions collide on `(path, stamp, entry.hash)` — possible only
/// for fork twins (§5.2.2): the one that encodes smaller is kept, whatever the arrival order.
pub(crate) fn rank(entry: &Entry, origin: Option<&Stamp>) -> Vec<u8> {
    postcard::to_stdvec(&(entry, origin)).unwrap_or_default()
}

/// `(path, stamp, entry.hash)`: the full identity of a version (§5.2.2).
type VersionKey = (String, Stamp, [u8; 32]);

const STAMP_MIN: Stamp = Stamp {
    lamport: 0,
    device: DeviceId([0; 8]),
    idx: 0,
};
const STAMP_MAX: Stamp = Stamp {
    lamport: u64::MAX,
    device: DeviceId([0xff; 8]),
    idx: u32::MAX,
};

/// BTreeMaps; implements `HeadStore`; derives `Eq` for convergence tests.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct MemIndex {
    heads: BTreeMap<VersionKey, (Entry, Option<Stamp>)>,
    removed: BTreeMap<VersionKey, (Entry, u64, Stamp)>,
    blobs: BTreeMap<BlobId, BlobRec>,
    /// `id → (name, first_ms)`.
    devices: BTreeMap<DeviceId, (String, u64)>,
    vault_format: u16,
    vault_name: String,
}

fn path_range(path: &str) -> std::ops::RangeInclusive<VersionKey> {
    (path.to_owned(), STAMP_MIN, [0; 32])..=(path.to_owned(), STAMP_MAX, [0xff; 32])
}

impl MemIndex {
    /// The visible tree: per path the head with the greatest `(stamp, entry.hash)`.
    pub fn winners(&self) -> Vec<Head> {
        self.all_heads().into_iter().filter(|h| h.winner).collect()
    }

    /// Winners and conflict losers, sorted by `(path, stamp, entry.hash)`.
    pub fn all_heads(&self) -> Vec<Head> {
        let mut out: Vec<Head> = Vec::with_capacity(self.heads.len());
        for ((path, stamp, _), (entry, origin)) in &self.heads {
            // The map is sorted, so the last head of a path is its winner.
            if let Some(prev) = out.last_mut().filter(|p| p.path == *path) {
                prev.winner = false;
            }
            out.push(Head {
                path: path.clone(),
                stamp: *stamp,
                entry: entry.clone(),
                origin: *origin,
                winner: true,
            });
        }
        out
    }

    /// Sorted by `(path, stamp, entry.hash)`.
    pub fn removed(&self) -> Vec<RemovedVersion> {
        self.removed
            .iter()
            .map(
                |((path, stamp, _), (entry, removed_ms, by))| RemovedVersion {
                    path: path.clone(),
                    stamp: *stamp,
                    entry: entry.clone(),
                    removed_ms: *removed_ms,
                    by: *by,
                },
            )
            .collect()
    }

    /// Sorted by id.
    pub fn blobs(&self) -> Vec<BlobRec> {
        self.blobs.values().cloned().collect()
    }

    /// Sorted by id.
    pub fn devices(&self) -> Vec<DeviceRec> {
        self.devices
            .iter()
            .map(|(id, (name, first_ms))| DeviceRec {
                id: *id,
                name: name.clone(),
                first_ms: *first_ms,
            })
            .collect()
    }

    /// `(format, name)` of the last applied `VaultInit` (0 and `""` before one).
    pub fn vault(&self) -> (u16, &str) {
        (self.vault_format, &self.vault_name)
    }

    /// The snapshot of this state: all heads, the versions removed within `HISTORY_KEEP` of
    /// `now_ms`, and the blobs those two reference (§4.6).
    pub fn to_snapshot(
        &self,
        vault_id: [u8; 16],
        device: DeviceId,
        lamport: u64,
        mut covers: Vec<SegRef>,
        mut covered: Vec<CoveredSeg>,
        now_ms: u64,
    ) -> SnapshotV1 {
        covers.sort_by_key(|r| r.device);
        covered.sort();
        covered.dedup();
        let heads: Vec<HeadRec> = self
            .heads
            .iter()
            .map(|((path, stamp, _), (entry, origin))| HeadRec {
                path: path.clone(),
                stamp: *stamp,
                entry: entry.clone(),
                origin: *origin,
            })
            .collect();
        let removed: Vec<RemovedRec> = self
            .removed
            .iter()
            .filter(|(_, (_, removed_ms, _))| now_ms.saturating_sub(*removed_ms) < HISTORY_KEEP_MS)
            .map(|((path, stamp, _), (entry, removed_ms, by))| RemovedRec {
                path: path.clone(),
                stamp: *stamp,
                entry: entry.clone(),
                removed_ms: *removed_ms,
                by: *by,
            })
            .collect();
        let referenced: BTreeSet<BlobId> = heads
            .iter()
            .map(|h| &h.entry)
            .chain(removed.iter().map(|r| &r.entry))
            .filter_map(|e| e.loc.as_ref().map(|l| l.blob))
            .collect();
        SnapshotV1 {
            vault_id,
            device,
            lamport,
            created_ms: now_ms,
            vault_format: self.vault_format,
            vault_name: self.vault_name.clone(),
            covers,
            covered,
            devices: self.devices(),
            blobs: referenced
                .iter()
                .filter_map(|id| self.blobs.get(id).cloned())
                .collect(),
            heads,
            removed,
        }
    }

    pub fn load_snapshot(s: &SnapshotV1) -> Self {
        let mut m = MemIndex {
            vault_format: s.vault_format,
            vault_name: s.vault_name.clone(),
            ..MemIndex::default()
        };
        for h in &s.heads {
            m.put_head(&h.path, h.stamp, &h.entry, h.origin);
        }
        for r in &s.removed {
            m.removed.insert(
                (r.path.clone(), r.stamp, r.entry.hash),
                (r.entry.clone(), r.removed_ms, r.by),
            );
        }
        for b in &s.blobs {
            m.blobs.insert(b.id, b.clone());
        }
        for d in &s.devices {
            m.devices.insert(d.id, (d.name.clone(), d.first_ms));
        }
        m
    }

    /// Fork twins may collide on the full key: the smaller encoding stays (order-independent).
    fn put_head(&mut self, path: &str, stamp: Stamp, entry: &Entry, origin: Option<Stamp>) {
        let key = (path.to_owned(), stamp, entry.hash);
        if let Some((old, old_origin)) = self.heads.get(&key)
            && rank(old, old_origin.as_ref()) <= rank(entry, origin.as_ref())
        {
            return;
        }
        self.heads.insert(key, (entry.clone(), origin));
    }
}

impl HeadStore for MemIndex {
    fn heads(&self, path: &str) -> Result<Vec<Head>, StateError> {
        let mut out: Vec<Head> = self
            .heads
            .range(path_range(path))
            .map(|((path, stamp, _), (entry, origin))| Head {
                path: path.clone(),
                stamp: *stamp,
                entry: entry.clone(),
                origin: *origin,
                winner: false,
            })
            .collect();
        if let Some(last) = out.last_mut() {
            last.winner = true;
        }
        Ok(out)
    }

    fn supersede(
        &mut self,
        path: &str,
        stamp: &Stamp,
        removed_ms: u64,
        by: Stamp,
    ) -> Result<usize, StateError> {
        let range = (path.to_owned(), *stamp, [0; 32])..=(path.to_owned(), *stamp, [0xff; 32]);
        for (_, (_, old_ms, old_by)) in self.removed.range_mut(range.clone()) {
            if (*old_by, *old_ms) > (by, removed_ms) {
                (*old_ms, *old_by) = (removed_ms, by);
            }
        }
        let keys: Vec<VersionKey> = self.heads.range(range).map(|(k, _)| k.clone()).collect();
        for key in &keys {
            let Some((entry, _)) = self.heads.remove(key) else {
                continue;
            };
            match self.removed.get_mut(key) {
                // Already min-ed above; only the entry of a fork twin may differ.
                Some((old, _, _)) => {
                    if rank(&entry, None) < rank(old, None) {
                        *old = entry;
                    }
                }
                None => {
                    self.removed.insert(key.clone(), (entry, removed_ms, by));
                }
            }
        }
        Ok(keys.len())
    }

    fn insert_head(
        &mut self,
        path: &str,
        stamp: Stamp,
        entry: &Entry,
        origin: Option<Stamp>,
    ) -> Result<(), StateError> {
        self.put_head(path, stamp, entry, origin);
        Ok(())
    }

    fn upsert_blob(&mut self, rec: &BlobRec) -> Result<(), StateError> {
        self.blobs.insert(rec.id, rec.clone());
        Ok(())
    }

    fn upsert_device(&mut self, id: DeviceId, name: &str, seen_ms: u64) -> Result<(), StateError> {
        let first_ms = self
            .devices
            .get(&id)
            .map_or(seen_ms, |(_, first)| (*first).min(seen_ms));
        self.devices.insert(id, (name.to_owned(), first_ms));
        Ok(())
    }

    fn set_vault(&mut self, format: u16, name: &str) -> Result<(), StateError> {
        self.vault_format = format;
        self.vault_name = name.to_owned();
        Ok(())
    }
}

#[derive(Default, Clone, Debug)]
pub struct ApplyStats {
    pub puts: u64,
    pub dels: u64,
    pub noop_dels: u64,
    pub new_conflicts: u64,
}

/// Applies every op of `seg` per §5.2.2; op `i` has the stamp `(seg.lamport, seg.device, i)`.
/// Storage errors propagate with `?`. A `VaultInit` of a newer format rejects the segment
/// before anything is written.
pub fn apply_segment<S: HeadStore>(
    store: &mut S,
    seg: &SegmentV1,
    removed_ms: u64,
) -> Result<ApplyStats, IndexError> {
    let too_new =
        |op: &Op| matches!(op, Op::VaultInit { format, .. } if *format > SUPPORTED_FORMAT);
    if seg.ops.iter().any(too_new) {
        return Err(IndexError::NeedsNewerGclone);
    }
    let mut stats = ApplyStats::default();
    for (i, op) in seg.ops.iter().enumerate() {
        let stamp = Stamp {
            lamport: seg.lamport,
            device: seg.device,
            idx: u32::try_from(i)
                .map_err(|_| FormatError::BadEntry("a segment with more than 2^32 ops".into()))?,
        };
        match op {
            Op::Put {
                path,
                entry,
                base,
                origin,
            } => {
                if let Some(base) = base {
                    store.supersede(path, base, removed_ms, stamp)?;
                }
                store.insert_head(path, stamp, entry, *origin)?;
                stats.puts += 1;
                if store.heads(path)?.len() > 1 {
                    stats.new_conflicts += 1;
                }
            }
            Op::Del { path, base } => {
                // No head (path, base): the deleter had not seen the current version, so a put
                // beats a concurrent delete.
                if store.supersede(path, base, removed_ms, stamp)? == 0 {
                    stats.noop_dels += 1;
                }
                stats.dels += 1;
            }
            Op::Blob(rec) => store.upsert_blob(rec)?,
            Op::Device { id, name } => store.upsert_device(*id, name, removed_ms)?,
            Op::VaultInit { format, name } => store.set_vault(*format, name)?,
        }
    }
    Ok(stats)
}

/// Returns `(applicable, in order; blocked)` as indices into `segs`.
///
/// A segment is applicable once its `prev` and every `seen` reference is satisfied — by
/// `satisfied` (what the replica already knows) or by a segment placed earlier in the order.
/// Among the segments that are ready, the smallest `(lamport, device, seq, hash)` goes first
/// (§5.3). Every causal order yields the same state (§5.2.2), so the choice only makes the
/// result reproducible. `blocked` keeps the input order.
pub fn causal_order(
    segs: &[(SegmentV1, [u8; 32])],
    satisfied: &dyn Fn(&SegRef) -> bool,
) -> (Vec<usize>, Vec<usize>) {
    type Key = (DeviceId, u64, [u8; 32]);
    let in_hand: HashSet<Key> = segs.iter().map(|(s, h)| (s.device, s.seq, *h)).collect();
    // Per segment: how many of its references still wait for a segment of this batch; `None`
    // when a reference can never be satisfied from here.
    let mut waiting: Vec<Option<usize>> = Vec::with_capacity(segs.len());
    let mut dependents: HashMap<Key, Vec<usize>> = HashMap::new();
    for (i, (seg, _)) in segs.iter().enumerate() {
        let mut count = Some(0);
        for r in seg.prev.iter().chain(&seg.seen).filter(|r| !satisfied(r)) {
            let key = (r.device, r.seq, r.hash);
            if in_hand.contains(&key) {
                dependents.entry(key).or_default().push(i);
                count = count.map(|n| n + 1);
            } else {
                count = None;
            }
        }
        waiting.push(count);
    }
    let rank = |i: usize| {
        let (seg, hash) = &segs[i];
        Reverse((seg.lamport, seg.device, seg.seq, *hash, i))
    };
    let mut ready: BinaryHeap<_> = (0..segs.len())
        .filter(|&i| waiting[i] == Some(0))
        .map(rank)
        .collect();
    let mut placed: HashSet<Key> = HashSet::new();
    let mut order = Vec::with_capacity(segs.len());
    while let Some(Reverse((_, device, seq, hash, i))) = ready.pop() {
        order.push(i);
        if !placed.insert((device, seq, hash)) {
            continue;
        }
        for d in dependents.remove(&(device, seq, hash)).unwrap_or_default() {
            if let Some(n) = waiting[d].as_mut() {
                *n -= 1;
                if *n == 0 {
                    ready.push(rank(d));
                }
            }
        }
    }
    let mut applicable = vec![false; segs.len()];
    for &i in &order {
        applicable[i] = true;
    }
    let blocked = (0..segs.len()).filter(|&i| !applicable[i]).collect();
    (order, blocked)
}

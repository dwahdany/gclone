//! Refresh (pull): listing, candidates, causal application, snapshots, presence (SPEC §5.3) —
//! owned by WP4. Private to `index`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use futures_util::{StreamExt, TryStreamExt};
use rusqlite::Connection;

use super::commit::{apply_and_record, raise_lamport, set_base_meta};
use super::{RefreshReport, Vault, blocking, cache_store, causal_order, not_visible, query};
use crate::backend::{Backend, Handle, ObjMeta, get_bounded, md5_of};
use crate::consts::{GAP_GRACE_MS, INDEX_PARALLEL_MAX};
use crate::crypto::Keyring;
use crate::error::{BackendError, FormatError, IndexError, StateError};
use crate::format::{
    IndexName, SUPPORTED_FORMAT, SegmentV1, SnapshotV1, open_segment, open_snapshot,
    parse_index_name, segment_name,
};
use crate::state::tables::{self, AppliedRow, Version};
use crate::types::{CoveredSeg, DeviceId, SegRef};

/// `open_segment` / `open_snapshot`: the acceptance rules of §4.6 over a whole object.
type Open<T> = fn(&Keyring, &str, &[u8]) -> Result<(T, [u8; 32]), FormatError>;

/// Full identity of a segment: `(device, seq, BLAKE3(object))`.
pub(super) type SegKey = (DeviceId, u64, [u8; 32]);

fn key_of(r: &SegRef) -> SegKey {
    (r.device, r.seq, r.hash)
}

fn covered_of(key: &SegKey) -> CoveredSeg {
    CoveredSeg {
        device: key.0,
        seq: key.1,
        h4: [key.2[0], key.2[1], key.2[2], key.2[3]],
    }
}

/// `sup ⊇ sub`, both sorted and unique (§4.6 rule 7).
pub(super) fn is_superset(sup: &[CoveredSeg], sub: &[CoveredSeg]) -> bool {
    sub.len() <= sup.len() && sub.iter().all(|c| sup.binary_search(c).is_ok())
}

/// An object that is simply not there (any more) — as opposed to a failure of the backend.
fn is_missing(e: &BackendError) -> bool {
    matches!(
        e,
        BackendError::NotFound | BackendError::AppNotAuthorized | BackendError::Fatal { .. }
    )
}

/// Where the bytes handed to [`Vault::accept`] come from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// The local index cache. It is never authoritative: a copy that does not open is dropped
    /// and the store is asked.
    Cache,
    /// The store, under a listed name. An accepted object goes into the cache.
    Listed,
    /// The store, by the id a reference carries.
    ById,
}

/// The listing of `index/`: names are unauthenticated hints, and one name may be listed for
/// several objects.
pub(super) struct Listed {
    pub segs: BTreeMap<String, Vec<ObjMeta>>,
    pub snaps: BTreeMap<String, Vec<ObjMeta>>,
}

impl Listed {
    pub(super) fn new(objects: Vec<ObjMeta>) -> Self {
        let mut listed = Listed {
            segs: BTreeMap::new(),
            snaps: BTreeMap::new(),
        };
        for m in objects.into_iter().filter(|m| !m.is_folder && !m.trashed) {
            let into = match parse_index_name(&m.name) {
                Some(IndexName::Segment { .. }) => &mut listed.segs,
                Some(IndexName::Snapshot { .. }) => &mut listed.snaps,
                None => continue,
            };
            into.entry(m.name.clone()).or_default().push(m);
        }
        listed
    }

    /// A fingerprint of the snapshots this listing shows (name, object id, size, md5), without
    /// the objects in `without`. `cleanup_index` uses it to tell whether anything it decides
    /// on has changed since its last complete pass (§5.6).
    pub(super) fn snapshots_fingerprint(&self, without: &HashSet<Handle>) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"gclone/v1/listed-snapshots");
        for (name, metas) in &self.snaps {
            let mut metas: Vec<&ObjMeta> = metas
                .iter()
                .filter(|m| !without.contains(&m.handle))
                .collect();
            metas.sort_by(|a, b| a.handle.0.cmp(&b.handle.0));
            for m in metas {
                for field in [name.as_bytes(), m.handle.0.as_bytes()] {
                    h.update(&(field.len() as u64).to_be_bytes());
                    h.update(field);
                }
                h.update(&m.size.to_be_bytes());
                h.update(&m.md5.unwrap_or_default());
            }
        }
        *h.finalize().as_bytes()
    }

    fn segment_identities(&self) -> HashSet<CoveredSeg> {
        self.segs
            .keys()
            .filter_map(|name| match parse_index_name(name) {
                Some(IndexName::Segment { device, seq, h8 }) => Some(CoveredSeg {
                    device,
                    seq,
                    h4: h8,
                }),
                _ => None,
            })
            .collect()
    }
}

/// An accepted index object with where it came from.
pub(super) struct Fetched<T> {
    pub body: T,
    pub hash: [u8; 32],
    pub size: u64,
    /// md5 of the accepted bytes.
    pub md5: [u8; 16],
    /// The listed object it was read from (or, for a cache hit, the listed object of that name).
    pub meta: Option<ObjMeta>,
    /// A listed object is known to hold exactly these bytes: it was downloaded, or its size and
    /// md5 are those of the cached copy. A cached copy alone says nothing about the remote.
    pub on_remote: bool,
}

/// Where an accepted, not yet applied segment lives.
#[derive(Clone)]
pub(super) struct CandInfo {
    pub name: String,
    pub file_id: String,
    pub created_ms: u64,
    pub size: u64,
}

/// Where a segment object lived when this replica last knew it.
#[derive(Clone)]
struct Place {
    file_id: String,
    /// The object's creation time on the server; `None` when only its id was on record (a tip
    /// of the base snapshot, a rollback mark, a segment of this device).
    created_ms: Option<u64>,
}

type PlaceRow = (String, String, Option<u64>);

fn remembered_load(c: &Connection) -> Result<HashMap<String, Place>, StateError> {
    let Some(bytes) = tables::meta_get(c, "remembered")? else {
        return Ok(HashMap::new());
    };
    let rows: Vec<PlaceRow> = postcard::from_bytes(&bytes)
        .map_err(|e| StateError::Corrupt(format!("cannot decode the remembered places: {e}")))?;
    Ok(rows
        .into_iter()
        .map(|(name, file_id, created_ms)| {
            (
                name,
                Place {
                    file_id,
                    created_ms,
                },
            )
        })
        .collect())
}

fn remembered_store(c: &Connection, places: &HashMap<String, Place>) -> Result<(), StateError> {
    if places.is_empty() {
        return tables::meta_del(c, "remembered");
    }
    let mut rows: Vec<PlaceRow> = places
        .iter()
        .map(|(name, p)| (name.clone(), p.file_id.clone(), p.created_ms))
        .collect();
    rows.sort();
    let bytes = postcard::to_stdvec(&rows)
        .map_err(|e| StateError::Corrupt(format!("cannot encode the remembered places: {e}")))?;
    tables::meta_set(c, "remembered", &bytes)
}

/// The ids this replica has on record for segments, by name: its own segments, the rollback
/// marks and the tips of the base snapshot.
fn recorded_ids(c: &Connection, me: DeviceId) -> Result<HashMap<String, String>, StateError> {
    let mut ids = HashMap::new();
    let refs = tables::hw_all(c)?
        .into_iter()
        .chain(tables::base_covers_all(c)?)
        .chain(
            tables::own_all(c)?
                .into_iter()
                .map(|(seq, hash, file_id)| SegRef {
                    device: me,
                    seq,
                    hash,
                    file_id,
                }),
        );
    for r in refs.filter(|r| !r.file_id.is_empty()) {
        ids.insert(segment_name(r.device, r.seq, &r.hash), r.file_id);
    }
    Ok(ids)
}

/// What the local replica knows (§5.3 "Definitions").
struct Known {
    applied: HashMap<SegKey, AppliedRow>,
    applied_h4: HashSet<CoveredSeg>,
    /// `base_covered`, sorted.
    covered: Vec<CoveredSeg>,
    hw: Vec<SegRef>,
    base_covers: Vec<SegRef>,
    base_name: Option<String>,
    base_id: Option<String>,
    /// Size and md5 of the base snapshot as this replica accepted it (md5: `None` in a
    /// `state.db` written before it was recorded).
    base_size: Option<u64>,
    base_md5: Option<Vec<u8>>,
    snap_checked: Option<String>,
}

impl Known {
    fn load(c: &Connection) -> Result<Known, StateError> {
        let rows = tables::applied_all(c)?;
        Ok(Known {
            applied_h4: rows.iter().map(|a| a.seg_ref().covered()).collect(),
            applied: rows
                .into_iter()
                .map(|a| ((a.dev, a.seq, a.hash), a))
                .collect(),
            covered: tables::base_covered_all(c)?,
            hw: tables::hw_all(c)?,
            base_covers: tables::base_covers_all(c)?,
            base_name: tables::meta_str(c, "base_snapshot_name")?,
            base_id: tables::meta_str(c, "base_snapshot_id")?,
            base_size: tables::meta_u64(c, "base_snapshot_size")?,
            base_md5: tables::meta_get(c, "base_snapshot_md5")?,
            snap_checked: tables::meta_str(c, "snap_checked")?,
        })
    }

    /// An identity is known iff it is in `applied` or its `(dev, seq, h4)` is in `base_covered`.
    fn has(&self, key: &SegKey) -> bool {
        self.applied.contains_key(key) || self.covered.binary_search(&covered_of(key)).is_ok()
    }

    /// The same for a listed name, which carries only `h4`.
    fn has_name(&self, c: &CoveredSeg) -> bool {
        self.applied_h4.contains(c) || self.covered.binary_search(c).is_ok()
    }

    fn is_empty(&self) -> bool {
        self.applied.is_empty() && self.covered.is_empty() && self.hw.is_empty()
    }
}

/// The verdicts of §5.3, collected (repair looks at them; refresh returns the first).
#[derive(Default)]
pub(super) struct Verdict {
    /// A rollback mark the replica itself does not satisfy: damaged or partly restored state.
    pub mark: Option<SegRef>,
    /// Names of the missing objects that blocked segments have waited for past `GAP_GRACE`.
    pub gap: Vec<String>,
    /// An applied segment or mark that the remote no longer holds.
    pub presence: Option<(DeviceId, u64)>,
}

impl Verdict {
    pub(super) fn into_result(self) -> Result<(), IndexError> {
        if let Some(mark) = self.mark {
            return Err(IndexError::Rollback {
                device: mark.device,
                seq: mark.seq,
            });
        }
        if !self.gap.is_empty() {
            return Err(IndexError::Gap { names: self.gap });
        }
        match self.presence {
            Some((device, seq)) => Err(IndexError::Rollback { device, seq }),
            None => Ok(()),
        }
    }
}

/// Everything one refresh found out.
pub(super) struct Pulled {
    pub report: RefreshReport,
    pub verdict: Verdict,
    pub listed: Listed,
    /// Accepted segments that are still blocked, with where they live.
    pub blocked: Vec<((SegmentV1, [u8; 32]), CandInfo)>,
    /// References no object satisfies, with the local time their oldest dependant was first seen.
    pub missing: Vec<(SegRef, u64)>,
}

struct Snap {
    body: Arc<SnapshotV1>,
    size: u64,
    md5: [u8; 16],
    file_id: String,
    /// See [`Fetched::on_remote`].
    on_remote: bool,
}

/// State of one refresh.
struct Pull<'a, B: Backend> {
    v: &'a Vault<B>,
    listed: Listed,
    report: RefreshReport,
    /// Candidates: accepted, not inert, not applied yet — two parallel vectors, because
    /// `causal_order` wants the segments as one slice.
    segs: Vec<(SegmentV1, [u8; 32])>,
    info: Vec<CandInfo>,
    /// Names that failed acceptance in this refresh.
    bad: HashSet<String>,
    /// Snapshots parsed in this refresh (`None`: failed acceptance).
    snaps: HashMap<String, Option<Snap>>,
    /// Where segments lived that this replica knew before a rebuild, by name. Kept in
    /// `meta.remembered` until they are applied again, so that a crash between the rebuild and
    /// the re-application does not lose it.
    remembered: HashMap<String, Place>,
    /// The sealed segment waiting in the outbox: `recover_outbox` applies it, nothing else.
    outbox: Option<SegKey>,
}

impl<B: Backend> Vault<B> {
    /// Acceptance (§4.6) off the async threads. An accepted `Listed` object also goes into the
    /// index cache there (the write is two fsyncs; eight of them run side by side).
    ///
    /// `None`: the object is corrupt and counts as missing. An object of the store whose
    /// content matches its name but whose *format* this build does not read is neither: it was
    /// written by a newer gclone, and treating it as missing would let this device carry on
    /// without it — `Err(UnsupportedObject)` (§4.6 "Unreadable is not corrupt").
    async fn accept<T: Send + 'static>(
        &self,
        name: &str,
        bytes: Vec<u8>,
        open: Open<T>,
        origin: Origin,
    ) -> Result<(Option<(T, [u8; 32])>, Vec<u8>), IndexError> {
        let (keys, name) = (self.keys.clone(), name.to_owned());
        let path = (origin == Origin::Listed).then(|| self.cache_path(&name));
        blocking(move || match open(&keys, &name, &bytes) {
            Ok(opened) => {
                if let Some(path) = path {
                    cache_store(&path, &bytes);
                }
                Ok((Some(opened), bytes))
            }
            Err(e) => match e.newer_format().filter(|_| origin != Origin::Cache) {
                Some(what) => Err(IndexError::UnsupportedObject { name, what }),
                None => {
                    tracing::warn!("corrupt index object {name}: {e}");
                    Ok((None, bytes))
                }
            },
        })
        .await
    }

    /// The bytes of one index object of the store, at most `object_max` of them (§4.6 rule 1):
    /// nothing in them is authenticated yet, so the object's own length must not decide how
    /// much memory is spent. `None`: gone, or too large (which counts as corrupt).
    async fn download(
        &self,
        name: &str,
        handle: &Handle,
        listed_size: Option<u64>,
    ) -> Result<Option<Vec<u8>>, IndexError> {
        let max = self.object_max;
        if listed_size.is_some_and(|size| size > max) {
            tracing::warn!("corrupt index object {name}: larger than the {max} bytes allowed");
            return Ok(None);
        }
        match get_bounded(&*self.backend, handle, max).await {
            Ok(Some(bytes)) => Ok(Some(bytes.into())),
            Ok(None) => {
                tracing::warn!("corrupt index object {name}: larger than the {max} bytes allowed");
                Ok(None)
            }
            Err(e) if is_missing(&e) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The accepted object `name` (§4.6): from the index cache, else from one of the objects
    /// listed under that name. `None` when nothing in hand passes acceptance.
    async fn fetch_object<T: Send + 'static>(
        &self,
        name: &str,
        metas: &[ObjMeta],
        open: Open<T>,
    ) -> Result<Option<Fetched<T>>, IndexError> {
        if let Some(bytes) = self.cache_read(name) {
            let (size, md5) = (bytes.len() as u64, md5_of(&bytes));
            let cached = self.accept(name, bytes, open, Origin::Cache).await?;
            if let (Some((body, hash)), _) = cached {
                let same = metas
                    .iter()
                    .find(|m| m.size == size && m.md5.is_none_or(|have| have == md5));
                return Ok(Some(Fetched {
                    body,
                    hash,
                    size,
                    md5,
                    meta: same.or(metas.first()).cloned(),
                    on_remote: same.is_some(),
                }));
            }
            let _ = std::fs::remove_file(self.cache_path(name));
        }
        for meta in metas {
            let Some(bytes) = self.download(name, &meta.handle, Some(meta.size)).await? else {
                continue;
            };
            let accepted = self.accept(name, bytes, open, Origin::Listed).await?;
            if let (Some((body, hash)), bytes) = accepted {
                return Ok(Some(Fetched {
                    body,
                    hash,
                    size: bytes.len() as u64,
                    md5: md5_of(&bytes),
                    meta: Some(meta.clone()),
                    on_remote: true,
                }));
            }
        }
        Ok(None)
    }

    pub(super) async fn fetch_segment(
        &self,
        name: &str,
        metas: &[ObjMeta],
    ) -> Result<Option<Fetched<SegmentV1>>, IndexError> {
        self.fetch_object(name, metas, open_segment).await
    }

    pub(super) async fn fetch_snapshot(
        &self,
        name: &str,
        metas: &[ObjMeta],
    ) -> Result<Option<Fetched<Arc<SnapshotV1>>>, IndexError> {
        let open = |keys: &Keyring, name: &str, bytes: &[u8]| {
            open_snapshot(keys, name, bytes).map(|(snap, hash)| (Arc::new(snap), hash))
        };
        self.fetch_object(name, metas, open).await
    }

    /// Un-trashed and still carrying its name, by id (list lag; §5.3 presence (c)).
    async fn stat_present(&self, file_id: &str, name: &str) -> Result<bool, IndexError> {
        if file_id.is_empty() {
            return Ok(false);
        }
        match self.backend.stat(&Handle(file_id.to_owned())).await {
            Ok(meta) => Ok(meta.is_some_and(|m| !m.trashed && !m.is_folder && m.name == name)),
            Err(e) if is_missing(&e) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// The creation time (server clock) of the object `file_id`, if the store still holds it
    /// under `name` — trashed or not.
    async fn stat_created(&self, file_id: &str, name: &str) -> Result<Option<u64>, IndexError> {
        if file_id.is_empty() {
            return Ok(None);
        }
        match self.backend.stat(&Handle(file_id.to_owned())).await {
            Ok(meta) => Ok(meta
                .filter(|m| !m.is_folder && m.name == name)
                .map(|m| m.created_ms)),
            Err(e) if is_missing(&e) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// §5.3 (includes `recover_outbox`; a stuck outbox is not an error).
    pub async fn refresh(&self) -> Result<RefreshReport, IndexError> {
        let _journal = self.journal.lock().await;
        let pulled = self.pull().await?;
        pulled.verdict.into_result()?;
        Ok(pulled.report)
    }

    /// The whole of §5.3 with the verdicts collected instead of returned.
    pub(super) async fn pull(&self) -> Result<Pulled, IndexError> {
        let index = &self.handles.index;
        let listed = Listed::new(self.backend.list(index).await.map_err(not_visible)?);
        *self.listed_snaps.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(listed.snapshots_fingerprint(&HashSet::new()));
        let mut known = self.db.read(Known::load)?;
        if listed.segs.is_empty() && listed.snaps.is_empty() && !known.is_empty() {
            for folder in [&self.handles.root, index] {
                match self.backend.stat(folder).await.map_err(not_visible)? {
                    None => return Err(IndexError::VaultMissing),
                    Some(m) if m.trashed => return Err(IndexError::VaultTrashed),
                    Some(_) => {}
                }
            }
        }

        let mut report = RefreshReport::default();
        // Before the clone check, so that a crash after the put is not mistaken for a clone.
        match self.recover_outbox().await {
            Ok(_) => {}
            Err(IndexError::Backend(e)) if e.is_temporary() => report.outbox_stuck = true,
            Err(e) => return Err(e),
        }
        report.rotated_device = self.check_machine()? | self.rotated.swap(false, Ordering::Relaxed);

        let outbox =
            self.db
                .read(tables::outbox_get)?
                .and_then(|row| match parse_index_name(&row.name) {
                    Some(IndexName::Segment { device, seq, .. }) => {
                        Some((device, seq, *blake3::hash(&row.bytes).as_bytes()))
                    }
                    _ => None,
                });
        let mut p = Pull {
            v: self,
            listed,
            report,
            segs: Vec::new(),
            info: Vec::new(),
            bad: HashSet::new(),
            snaps: HashMap::new(),
            remembered: self.db.read(remembered_load)?,
            outbox,
        };
        known = self.db.read(Known::load)?;
        p.gather(&known).await?;
        p.check_clone()?;

        let mut tried: HashSet<SegKey> = HashSet::new();
        let mut rebuilt = false;
        let mut unusable_news: Option<String>;
        loop {
            if p.apply_ready(&known).await? {
                known = self.db.read(Known::load)?;
                p.drop_inert(&known);
            }
            let unsatisfied = p.unsatisfied(&known);
            let news = p.snapshot_news(&known).await?;
            unusable_news = None;
            if unsatisfied.is_empty() && news.is_none() {
                break;
            }
            if let Some((name, snap)) = &news {
                // It covers nothing this replica lacks: follow it, or just remember it.
                if snap.body.covered.iter().all(|c| known.has_name(c)) {
                    if is_superset(&snap.body.covered, &known.covered) {
                        p.adopt(name, snap)?;
                    }
                    let lamport = snap.body.lamport;
                    self.db.txn(|c| {
                        raise_lamport(c, lamport)?;
                        tables::meta_set_str(c, "snap_checked", name)
                    })?;
                    known = self.db.read(Known::load)?;
                    continue;
                }
                unusable_news = Some(name.clone());
            }
            if !rebuilt {
                let mut wanted: HashSet<CoveredSeg> =
                    unsatisfied.iter().map(SegRef::covered).collect();
                if let Some((_, snap)) = &news {
                    wanted.extend(snap.body.covered.iter().filter(|c| !known.has_name(c)));
                }
                if let Some(name) = p.best_snapshot(&known, &wanted).await? {
                    p.rebuild(&name, &known).await?;
                    rebuilt = true;
                    known = self.db.read(Known::load)?;
                    p.drop_inert(&known);
                    p.gather(&known).await?;
                    p.check_clone()?;
                    continue;
                }
            }
            // List lag; objects trashed by a cleanup are still readable by id.
            if !p.fetch_references(&unsatisfied, &mut tried).await? {
                break;
            }
            p.check_clone()?;
        }
        if let Some(name) = unusable_news {
            tracing::warn!(
                "snapshot {name} covers index segments this device lacks but cannot be used yet"
            );
        }

        // `blocked` runs on the local clock: server-supplied times never feed a grace period.
        let now = self.now();
        let names: Vec<String> = p.info.iter().map(|i| i.name.clone()).collect();
        // What was applied again has its place in `applied`; only what still waits is remembered.
        let remembered = (!p.remembered.is_empty()).then(|| {
            p.remembered.retain(|name, _| names.contains(name));
            &p.remembered
        });
        let first_seen = self.db.txn(|c| {
            let old = tables::blocked_all(c)?;
            let rows: BTreeMap<String, u64> = names
                .iter()
                .map(|n| (n.clone(), old.get(n).copied().unwrap_or(now)))
                .collect();
            tables::blocked_replace(c, &rows)?;
            if let Some(places) = remembered {
                remembered_store(c, places)?;
            }
            Ok::<_, StateError>(rows)
        })?;
        if p.adopt_listed_ids(&known)? {
            known = self.db.read(Known::load)?;
        }

        let mut verdict = Verdict {
            mark: known.hw.iter().find(|m| !known.has(&key_of(m))).cloned(),
            ..Verdict::default()
        };
        // What the blocked segments wait for: references that nothing known or in hand satisfies.
        let in_hand: HashSet<SegKey> = p.segs.iter().map(|(s, h)| (s.device, s.seq, *h)).collect();
        let mut missing: BTreeMap<SegKey, (SegRef, u64)> = BTreeMap::new();
        let mut overdue = false;
        for ((seg, _), info) in p.segs.iter().zip(&p.info) {
            let since = first_seen.get(&info.name).copied().unwrap_or(now);
            let late = now.saturating_sub(since) >= GAP_GRACE_MS;
            overdue |= late;
            if !late {
                p.report.blocked_young += 1;
            }
            for r in seg.prev.iter().chain(&seg.seen) {
                let key = key_of(r);
                if known.has(&key) || in_hand.contains(&key) {
                    continue;
                }
                let slot = missing.entry(key).or_insert_with(|| (r.clone(), since));
                slot.1 = slot.1.min(since);
            }
        }
        if overdue {
            verdict.gap = missing
                .values()
                .filter(|(_, since)| now.saturating_sub(*since) >= GAP_GRACE_MS)
                .map(|(r, _)| segment_name(r.device, r.seq, &r.hash))
                .collect();
        }
        verdict.presence = p.presence(&known).await?;

        p.report.conflicts = self.db.read(query::conflict_count)?;
        p.report.corrupt_objects.sort();
        p.report.corrupt_objects.dedup();
        self.db.meta_set_u64("last_refresh_ms", now)?;
        Ok(Pulled {
            report: p.report,
            verdict,
            listed: p.listed,
            blocked: p.segs.into_iter().zip(p.info).collect(),
            missing: missing.into_values().collect(),
        })
    }
}

impl<B: Backend> Pull<'_, B> {
    fn has_candidate(&self, key: &SegKey) -> bool {
        self.segs.iter().any(|(s, h)| (s.device, s.seq, *h) == *key)
    }

    fn add_candidate(&mut self, seg: SegmentV1, hash: [u8; 32], info: CandInfo) {
        let key = (seg.device, seg.seq, hash);
        if Some(key) != self.outbox && !self.has_candidate(&key) {
            self.segs.push((seg, hash));
            self.info.push(info);
        }
    }

    /// cand = segments of L that are not inert ∪ cached segments that are not inert; fetched
    /// eight at a time, verified, and kept in the cache.
    async fn gather(&mut self, known: &Known) -> Result<(), IndexError> {
        let in_hand: HashSet<&str> = self.info.iter().map(|i| i.name.as_str()).collect();
        let wanted = |name: &str| match parse_index_name(name) {
            Some(IndexName::Segment { device, seq, h8 }) => {
                !known.has_name(&CoveredSeg {
                    device,
                    seq,
                    h4: h8,
                }) && !self.bad.contains(name)
                    && !in_hand.contains(name)
            }
            _ => false,
        };
        let mut jobs: Vec<(String, Vec<ObjMeta>)> = self
            .listed
            .segs
            .iter()
            .filter(|(name, _)| wanted(name))
            .map(|(name, metas)| (name.clone(), metas.clone()))
            .collect();
        if let Ok(dir) = std::fs::read_dir(&self.v.cache_dir) {
            let cached = dir
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|name| !self.listed.segs.contains_key(name) && wanted(name));
            jobs.extend(cached.map(|name| (name, Vec::new())));
        }

        // Eight at a time — but an object listed as large is fetched alone: what is in flight
        // is not authenticated yet, and eight objects of `INDEX_OBJECT_MAX` are not a bound.
        let (large, small): (Vec<_>, Vec<_>) = jobs
            .into_iter()
            .partition(|(_, metas)| metas.iter().any(|m| m.size > INDEX_PARALLEL_MAX));
        let v = self.v;
        let fetch = |(name, metas): (String, Vec<ObjMeta>)| async move {
            let found = v.fetch_segment(&name, &metas).await?;
            Ok::<_, IndexError>((name, !metas.is_empty(), found))
        };
        let fetched: Vec<(String, bool, Option<Fetched<SegmentV1>>)> =
            futures_util::stream::iter(small)
                .map(fetch)
                .buffer_unordered(8)
                .chain(
                    futures_util::stream::iter(large)
                        .map(fetch)
                        .buffer_unordered(1),
                )
                .try_collect()
                .await?;
        let mut recorded: Option<HashMap<String, String>> = None;
        for (name, was_listed, found) in fetched {
            let Some(f) = found else {
                self.bad.insert(name.clone());
                if was_listed {
                    self.report.corrupt_objects.push(name);
                }
                continue;
            };
            // A cached segment that is not listed (any more, or not yet) keeps the place this
            // replica knew: without its id the presence check could not look for the object
            // (§5.3 (c)) and this device's `seen` references and snapshot tips would hand the
            // other devices a reference they cannot fetch.
            let info = match (&f.meta, self.remembered.get(&name)) {
                (Some(m), _) => CandInfo {
                    name,
                    file_id: m.handle.0.clone(),
                    created_ms: m.created_ms,
                    size: f.size,
                },
                (
                    None,
                    Some(Place {
                        file_id,
                        created_ms: Some(created_ms),
                    }),
                ) => CandInfo {
                    name,
                    file_id: file_id.clone(),
                    created_ms: *created_ms,
                    size: f.size,
                },
                // Only its id is on record, if anything: the store has the creation time.
                (None, place) => {
                    let id = match place {
                        Some(place) => Some(place.file_id.clone()),
                        None => {
                            if recorded.is_none() {
                                let me = self.v.device_id();
                                recorded = Some(self.v.db.read(|c| recorded_ids(c, me))?);
                            }
                            recorded.as_ref().and_then(|ids| ids.get(&name).cloned())
                        }
                    };
                    let stored = match &id {
                        Some(id) => self.v.stat_created(id, &name).await?,
                        None => None,
                    };
                    match (id, stored) {
                        (Some(file_id), Some(created_ms)) => CandInfo {
                            name,
                            file_id,
                            created_ms,
                            size: f.size,
                        },
                        // Nothing on record, or that object is gone: the writer's clock.
                        _ => CandInfo {
                            name,
                            file_id: String::new(),
                            created_ms: f.body.created_ms,
                            size: f.size,
                        },
                    }
                }
            };
            self.add_candidate(f.body, f.hash, info);
        }
        Ok(())
    }

    /// An `applied` row without a file id — its segment was applied from the cache while the
    /// store showed no object for it — takes the id of the object the listing shows now.
    fn adopt_listed_ids(&self, known: &Known) -> Result<bool, IndexError> {
        let mut found: Vec<(SegKey, String)> = Vec::new();
        for row in known.applied.values().filter(|a| a.file_id.is_empty()) {
            let Some(metas) = self.listed.segs.get(&row.name) else {
                continue;
            };
            // The listed object must be the bytes this replica applied.
            let md5 = self.v.cache_read(&row.name).map(|bytes| md5_of(&bytes));
            let same = metas.iter().find(|m| {
                m.size == row.size
                    && m.md5
                        .is_none_or(|have| md5.is_none_or(|cached| cached == have))
            });
            if let Some(m) = same {
                found.push(((row.dev, row.seq, row.hash), m.handle.0.clone()));
            }
        }
        if found.is_empty() {
            return Ok(false);
        }
        self.v.db.txn(|c| {
            found.iter().try_for_each(|((dev, seq, hash), id)| {
                tables::applied_set_file_id(c, *dev, *seq, hash, id)
            })
        })?;
        Ok(true)
    }

    fn drop_inert(&mut self, known: &Known) {
        let keep: Vec<bool> = self
            .segs
            .iter()
            .map(|(s, h)| !known.has(&(s.device, s.seq, *h)))
            .collect();
        let mut flags = keep.iter();
        self.segs.retain(|_| flags.next().copied().unwrap_or(true));
        let mut flags = keep.iter();
        self.info.retain(|_| flags.next().copied().unwrap_or(true));
    }

    /// §5.3 rotation trigger: an accepted segment under this device's id that this replica never
    /// sealed — a clone of the state directory is publishing. A listed name alone never counts.
    fn check_clone(&mut self) -> Result<(), IndexError> {
        let me = self.v.device_id();
        if !self.segs.iter().any(|(s, _)| s.device == me) {
            return Ok(());
        }
        let own: HashSet<(u64, [u8; 32])> = self
            .v
            .db
            .read(tables::own_all)?
            .into_iter()
            .map(|(seq, hash, _)| (seq, hash))
            .collect();
        let foreign =
            |(s, h): &(SegmentV1, [u8; 32])| s.device == me && !own.contains(&(s.seq, *h));
        if self.segs.iter().any(foreign) {
            self.v.rotate_device_id(
                "another copy of this device's state directory has published index segments",
            )?;
            self.report.rotated_device = true;
        }
        Ok(())
    }

    /// Applies every applicable candidate — all rounds of the causal order — in ONE transaction.
    async fn apply_ready(&mut self, known: &Known) -> Result<bool, IndexError> {
        let (order, _) = causal_order(&self.segs, &|r| known.has(&key_of(r)));
        if order.is_empty() {
            return Ok(false);
        }
        let mut segs: Vec<Option<(SegmentV1, [u8; 32])>> = std::mem::take(&mut self.segs)
            .into_iter()
            .map(Some)
            .collect();
        let mut info: Vec<Option<CandInfo>> = std::mem::take(&mut self.info)
            .into_iter()
            .map(Some)
            .collect();
        let batch: Vec<((SegmentV1, [u8; 32]), CandInfo)> = order
            .iter()
            .filter_map(|&i| Some((segs[i].take()?, info[i].take()?)))
            .collect();
        self.segs = segs.into_iter().flatten().collect();
        self.info = info.into_iter().flatten().collect();

        let db = self.v.db.clone();
        let (applied, forks) = blocking(move || {
            db.txn(|c| {
                let mut forks = 0u64;
                for ((seg, hash), info) in &batch {
                    if tables::is_fork(c, seg.device, seg.seq, hash)? {
                        forks += 1;
                        tracing::warn!(
                            "device {} published two different segments with sequence number {} \
                             (a cloned state directory); both are applied",
                            seg.device,
                            seg.seq
                        );
                    }
                    let row = AppliedRow {
                        dev: seg.device,
                        seq: seg.seq,
                        hash: *hash,
                        file_id: info.file_id.clone(),
                        name: info.name.clone(),
                        lamport: seg.lamport,
                        created_ms: info.created_ms,
                        size: info.size,
                    };
                    apply_and_record(c, seg, &row)?;
                }
                Ok::<_, IndexError>((batch.len() as u64, forks))
            })
        })
        .await?;
        self.report.applied += applied;
        self.report.forks += forks;
        Ok(true)
    }

    /// U = unsatisfied prev/seen references of the candidates ∪ unsatisfied marks.
    fn unsatisfied(&self, known: &Known) -> Vec<SegRef> {
        let mut seen: BTreeSet<SegKey> = BTreeSet::new();
        self.segs
            .iter()
            .flat_map(|(s, _)| s.prev.iter().chain(&s.seen))
            .chain(&known.hw)
            .filter(|r| !known.has(&key_of(r)) && seen.insert(key_of(r)))
            .cloned()
            .collect()
    }

    /// The parsed snapshot listed under `name`, once per refresh.
    async fn snapshot(&mut self, name: &str) -> Result<Option<&Snap>, IndexError> {
        if !self.snaps.contains_key(name) {
            let metas = self.listed.snaps.get(name).cloned().unwrap_or_default();
            let snap = match self.v.fetch_snapshot(name, &metas).await? {
                Some(f) => Some(Snap {
                    body: f.body,
                    size: f.size,
                    md5: f.md5,
                    on_remote: f.on_remote,
                    file_id: f.meta.map(|m| m.handle.0).unwrap_or_default(),
                }),
                None => {
                    self.report.corrupt_objects.push(name.to_owned());
                    None
                }
            };
            self.snaps.insert(name.to_owned(), snap);
        }
        Ok(self.snaps.get(name).and_then(Option::as_ref))
    }

    /// Listed snapshot names, newest first (the name starts with the lamport in fixed-width hex).
    fn snapshot_names(&self) -> Vec<String> {
        self.listed.snaps.keys().rev().cloned().collect()
    }

    /// The accepted snapshot in L with the greatest inner lamport — unless it is the one checked
    /// last or the base snapshot.
    async fn snapshot_news(&mut self, known: &Known) -> Result<Option<(String, Snap)>, IndexError> {
        for name in self.snapshot_names() {
            if known.snap_checked.as_deref() == Some(&name)
                || known.base_name.as_deref() == Some(&name)
            {
                return Ok(None);
            }
            if let Some(snap) = self.snapshot(&name).await? {
                let snap = Snap {
                    body: snap.body.clone(),
                    size: snap.size,
                    md5: snap.md5,
                    file_id: snap.file_id.clone(),
                    on_remote: snap.on_remote,
                };
                return Ok(Some((name, snap)));
            }
        }
        Ok(None)
    }

    /// Whether the segment `name` is in hand (cache or listing) and passes acceptance.
    async fn available(&mut self, name: &str) -> Result<bool, IndexError> {
        if self.bad.contains(name) {
            return Ok(false);
        }
        if self.info.iter().any(|i| i.name == name) {
            return Ok(true);
        }
        let metas = self.listed.segs.get(name).cloned().unwrap_or_default();
        let found = self.v.fetch_segment(name, &metas).await?.is_some();
        if !found {
            self.bad.insert(name.to_owned());
        }
        Ok(found)
    }

    /// The first accepted listed snapshot, newest first, that is useful (covers something of
    /// `wanted`) and usable (everything this replica knows and it does not cover is available,
    /// so nothing is lost by rebuilding from it).
    async fn best_snapshot(
        &mut self,
        known: &Known,
        wanted: &HashSet<CoveredSeg>,
    ) -> Result<Option<String>, IndexError> {
        'names: for name in self.snapshot_names() {
            let Some(snap) = self.snapshot(&name).await? else {
                continue;
            };
            let body = snap.body.clone();
            let covers = |c: &CoveredSeg| body.covered.binary_search(c).is_ok();
            if !wanted.iter().any(covers) {
                continue;
            }
            let mut needed: BTreeSet<String> = BTreeSet::new();
            for row in known.applied.values() {
                if !covers(&row.seg_ref().covered()) {
                    needed.insert(row.name.clone());
                }
            }
            for c in known.covered.iter().filter(|c| !covers(c)) {
                // The name needs only the first four hash bytes.
                let mut hash = [0u8; 32];
                hash[..4].copy_from_slice(&c.h4);
                needed.insert(segment_name(c.device, c.seq, &hash));
            }
            for mark in known.hw.iter().filter(|m| !covers(&m.covered())) {
                needed.insert(segment_name(mark.device, mark.seq, &mark.hash));
            }
            for segment in &needed {
                if !self.available(segment).await? {
                    continue 'names;
                }
            }
            return Ok(Some(name));
        }
        Ok(None)
    }

    /// adopt(S): the base becomes S; the `applied` rows S covers go. Heads are untouched — the
    /// replica already contains everything S does.
    fn adopt(&mut self, name: &str, snap: &Snap) -> Result<(), IndexError> {
        let applied: Vec<SegKey> = self
            .v
            .db
            .read(tables::applied_all)?
            .iter()
            .map(|a| (a.dev, a.seq, a.hash))
            .collect();
        let body = &snap.body;
        self.v.db.txn(|c| {
            for key in &applied {
                if body.covered.binary_search(&covered_of(key)).is_ok() {
                    tables::applied_delete(c, key.0, key.1, &key.2)?;
                }
            }
            set_base(c, body, name, snap.size, &snap.md5, &snap.file_id)
        })?;
        self.report.adopted = Some(name.to_owned());
        Ok(())
    }

    /// rebuild_from(S): the replica's content is replaced by S in one transaction; whatever S
    /// does not cover is re-applied afterwards by the normal loop.
    async fn rebuild(&mut self, name: &str, known: &Known) -> Result<(), IndexError> {
        let Some(snap) = self.snaps.get(name).and_then(Option::as_ref) else {
            return Ok(());
        };
        // The rebuild replaces `applied` and the base tips and may raise the marks: remember
        // where those segments live.
        for row in known.applied.values().filter(|a| !a.file_id.is_empty()) {
            self.remembered.insert(
                row.name.clone(),
                Place {
                    file_id: row.file_id.clone(),
                    created_ms: Some(row.created_ms),
                },
            );
        }
        let tips = known.base_covers.iter().chain(&known.hw);
        for tip in tips.filter(|t| !t.file_id.is_empty()) {
            self.remembered
                .entry(segment_name(tip.device, tip.seq, &tip.hash))
                .or_insert_with(|| Place {
                    file_id: tip.file_id.clone(),
                    created_ms: None,
                });
        }
        let (db, body, name_owned) = (self.v.db.clone(), snap.body.clone(), name.to_owned());
        let (size, md5, file_id) = (snap.size, snap.md5, snap.file_id.clone());
        let remembered = self.remembered.clone();
        blocking(move || {
            db.txn(|c| {
                load_snapshot(c, &body)?;
                c.execute("DELETE FROM applied", [])
                    .map_err(StateError::from)?;
                set_base(c, &body, &name_owned, size, &md5, &file_id)?;
                tables::meta_set_str(c, "snap_checked", &name_owned)?;
                remembered_store(c, &remembered)?;
                Ok::<_, IndexError>(())
            })
        })
        .await?;
        self.report.rebuilt_from = Some(name.to_owned());
        Ok(())
    }

    /// For r in U − tried: fetch the object by the id the reference carries (or the object
    /// listed under its name) and make it a candidate if it is what the reference claims.
    async fn fetch_references(
        &mut self,
        unsatisfied: &[SegRef],
        tried: &mut HashSet<SegKey>,
    ) -> Result<bool, IndexError> {
        let mut added = false;
        for r in unsatisfied {
            let key = key_of(r);
            if !tried.insert(key) || self.has_candidate(&key) || Some(key) == self.outbox {
                continue;
            }
            let name = segment_name(r.device, r.seq, &r.hash);
            let mut found: Option<(SegmentV1, CandInfo)> = None;
            if !r.file_id.is_empty() {
                let handle = Handle(r.file_id.clone());
                if let Some(bytes) = self.v.download(&name, &handle, None).await? {
                    let opened = self
                        .v
                        .accept(&name, bytes, open_segment, Origin::ById)
                        .await?;
                    if let (Some((seg, hash)), bytes) = opened
                        && hash == r.hash
                    {
                        // A renamed object counts as missing (§4.6): it must be what the
                        // reference claims AND still stand under its name.
                        let meta = match self.v.backend.stat(&handle).await {
                            Ok(meta) => meta.filter(|m| m.name == name),
                            Err(e) if is_missing(&e) => None,
                            Err(e) => return Err(e.into()),
                        };
                        if let Some(meta) = meta {
                            self.v.cache_write(&name, &bytes);
                            let info = CandInfo {
                                name: name.clone(),
                                file_id: r.file_id.clone(),
                                created_ms: meta.created_ms,
                                size: bytes.len() as u64,
                            };
                            found = Some((seg, info));
                        }
                    }
                }
            }
            if found.is_none()
                && !self.bad.contains(&name)
                && let Some(metas) = self.listed.segs.get(&name)
                && let Some(f) = self.v.fetch_segment(&name, metas).await?
                && f.hash == r.hash
            {
                let info = CandInfo {
                    name: name.clone(),
                    file_id: f
                        .meta
                        .as_ref()
                        .map(|m| m.handle.0.clone())
                        .unwrap_or_default(),
                    created_ms: f.meta.as_ref().map_or(f.body.created_ms, |m| m.created_ms),
                    size: f.size,
                };
                found = Some((f.body, info));
            }
            if let Some((seg, info)) = found {
                self.add_candidate(seg, r.hash, info);
                added = true;
            }
        }
        Ok(added)
    }

    /// Whether an accepted snapshot that the remote really holds has `identity` in its `covered` set.
    async fn covered_remotely(&mut self, identity: &CoveredSeg) -> Result<bool, IndexError> {
        for name in self.snapshot_names() {
            if let Some(snap) = self.snapshot(&name).await?
                && snap.on_remote
                && snap.body.covered.binary_search(identity).is_ok()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// presence_check(): what this replica has seen must still be held by the remote for the
    /// other devices. Returns the first identity that is gone.
    async fn presence(&mut self, known: &Known) -> Result<Option<(DeviceId, u64)>, IndexError> {
        let listed = self.listed.segment_identities();
        let mut seen: BTreeMap<(DeviceId, u64, [u8; 4]), (String, String)> = BTreeMap::new();
        for row in known.applied.values() {
            let c = row.seg_ref().covered();
            seen.insert(
                (c.device, c.seq, c.h4),
                (row.file_id.clone(), row.name.clone()),
            );
        }
        for mark in &known.hw {
            let c = mark.covered();
            let place = seen.entry((c.device, c.seq, c.h4)).or_insert_with(|| {
                let name = segment_name(mark.device, mark.seq, &mark.hash);
                (mark.file_id.clone(), name)
            });
            // An `applied` row without an id must not hide the id the mark has.
            if place.0.is_empty() {
                place.0.clone_from(&mark.file_id);
            }
        }
        // Rule (b) without parsing anything: the base snapshot's coverage is in `base_covered`,
        // and the base counts as an accepted listed snapshot when the listing shows an object
        // of its name with the size and md5 this replica accepted. Without this, every mark
        // whose segment a cleanup has trashed — the tip of any device that has not written
        // since — made every refresh load and decode a whole snapshot.
        let base_listed = match (&known.base_name, known.base_size, &known.base_md5) {
            (Some(name), Some(size), Some(md5)) => {
                self.listed.snaps.get(name).is_some_and(|metas| {
                    metas
                        .iter()
                        .any(|m| m.size == size && m.md5.is_none_or(|have| have[..] == md5[..]))
                })
            }
            _ => false,
        };
        for ((device, seq, h4), (file_id, name)) in seen {
            let identity = CoveredSeg { device, seq, h4 };
            if listed.contains(&identity)
                || (base_listed && known.covered.binary_search(&identity).is_ok())
                || self.covered_remotely(&identity).await?
                || self.v.stat_present(&file_id, &name).await?
            {
                continue;
            }
            return Ok(Some((device, seq)));
        }

        // The base must still be on offer.
        let Some(base) = known
            .base_name
            .as_deref()
            .filter(|_| !known.covered.is_empty())
        else {
            return Ok(None);
        };
        if self.listed.snaps.contains_key(base) {
            return Ok(None);
        }
        for name in self.snapshot_names() {
            if let Some(snap) = self.snapshot(&name).await?
                && snap.on_remote
                && is_superset(&snap.body.covered, &known.covered)
            {
                return Ok(None);
            }
        }
        if self
            .v
            .stat_present(known.base_id.as_deref().unwrap_or(""), base)
            .await?
        {
            return Ok(None);
        }
        let tip = known.base_covers.iter().max_by_key(|t| (t.seq, t.device));
        Ok(Some(
            tip.map_or((self.v.device_id(), 0), |t| (t.device, t.seq)),
        ))
    }
}

/// base_covered := S.covered; base_covers := S.covers; base_snapshot_* := S; hw := max(hw,
/// S.covers); the lamport clock follows.
fn set_base(
    c: &Connection,
    snap: &SnapshotV1,
    name: &str,
    size: u64,
    md5: &[u8; 16],
    file_id: &str,
) -> Result<(), IndexError> {
    tables::base_covered_replace(c, &snap.covered)?;
    tables::base_covers_replace(c, &snap.covers)?;
    set_base_meta(c, name, snap.lamport, size, md5, file_id)?;
    for tip in &snap.covers {
        tables::hw_raise(c, tip)?;
    }
    raise_lamport(c, snap.lamport)?;
    Ok(())
}

/// Replaces heads, removed versions, devices and the blob rows without `trashed_ms` by the
/// content of `snap` (§5.3 rebuild_from). `applied`, the base tables and `hw` are the caller's.
pub(super) fn load_snapshot(c: &Connection, snap: &SnapshotV1) -> Result<(), IndexError> {
    if snap.vault_format > SUPPORTED_FORMAT {
        return Err(IndexError::NeedsNewerGclone);
    }
    c.execute_batch(
        "DELETE FROM heads; DELETE FROM removed; DELETE FROM devices; \
         DELETE FROM blobs WHERE trashed_ms IS NULL;",
    )
    .map_err(StateError::from)?;
    for h in &snap.heads {
        tables::head_insert(c, &h.path, &h.stamp, &h.entry, h.origin.as_ref(), false)?;
    }
    // The winner of a path is its greatest (stamp, hash); the snapshot's order is not trusted.
    c.execute(
        "UPDATE heads SET winner = NOT EXISTS (SELECT 1 FROM heads g WHERE g.path = heads.path \
           AND (g.st_l, g.st_d, g.st_i, g.hash) > (heads.st_l, heads.st_d, heads.st_i, heads.hash))",
        [],
    )
    .map_err(StateError::from)?;
    for r in &snap.removed {
        let version = Version {
            path: r.path.clone(),
            stamp: r.stamp,
            entry: r.entry.clone(),
            origin: None,
        };
        tables::removed_insert(c, &version, r.removed_ms, &r.by)?;
    }
    for b in &snap.blobs {
        tables::blob_upsert(c, b)?;
    }
    for d in &snap.devices {
        tables::device_upsert(c, d.id, &d.name, d.first_ms, d.first_ms)?;
    }
    tables::meta_set_u64(c, "vault_format", u64::from(snap.vault_format))?;
    tables::meta_set_str(c, "vault_name", &snap.vault_name)?;
    // No head of the old content is left: resolution rule 2 starts over (§5.2.3).
    tables::resolve_all_set(c)?;
    Ok(())
}

//! commit, outbox, snapshot writer, cleanup, `finish_mutation` (SPEC §5.6, §5.8) — owned by WP4.
//! Private to `index`.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::SystemTime;

use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt};
use rusqlite::Connection;

use super::refresh::{Listed, is_superset};
use super::{CommitReport, Vault, blocking, fresh_ids, put_retrying, query};
use crate::backend::{Backend, Handle, ObjMeta, md5_of};
use crate::consts::{
    CHUNK_LOG2_MAX, CHUNK_LOG2_MIN, COMPACT_MIN_BYTES, COMPACT_MIN_SEGMENTS, HISTORY_KEEP_MS,
    INDEX_CACHE_KEEP_MS, INDEX_TRASH_DELAY_MS, ORPHAN_GRACE_MS, SNAPSHOT_KEEP,
};
use crate::crypto::stream::checked_ciphertext_len;
use crate::error::{BackendError, FormatError, IndexError, StateError};
use crate::format::{
    IndexName, Op, SegmentV1, op_from_draft, open_segment, parse_index_name, seal_segment,
    seal_snapshot,
};
use crate::index::apply::{ApplyStats, apply_segment};
use crate::path;
use crate::state::tables::{self, AppliedRow, OutboxRow, SqlStore};
use crate::types::{
    BaseEffect, BaseEffectKind, BaseRow, BlobId, BlobRec, CoveredSeg, DeviceId, Entry, EntryKind,
    OpDraft, SegRef, Stamp,
};
use crate::util;

/// A temporary publish failure leaves the sealed segment in the outbox (§5.6).
fn stuck_error(e: IndexError) -> IndexError {
    match e {
        IndexError::Backend(b) if b.is_temporary() => IndexError::OutboxStuck(b.to_string()),
        e => e,
    }
}

/// What `seal_segment` would refuse (§4.6 rules 5–6), checked when the op is created so that
/// nothing unpublishable ever reaches `pending`.
fn check_draft(d: &OpDraft) -> Result<(), FormatError> {
    let (path, entry): (&str, Option<&Entry>) = match d {
        OpDraft::Put { path, entry, .. } => (path, Some(entry)),
        OpDraft::Del { path, .. } => (path, None),
        OpDraft::VaultInit { .. } | OpDraft::Device { .. } | OpDraft::Blob(_) => return Ok(()),
    };
    path::validate(path)?;
    let Some(entry) = entry else {
        return Ok(());
    };
    let well_formed = match &entry.loc {
        Some(loc) => {
            entry.kind == EntryKind::File
                && entry.size > 0
                && (CHUNK_LOG2_MIN..=CHUNK_LOG2_MAX).contains(&loc.chunk_log2)
                && checked_ciphertext_len(entry.size, loc.chunk_log2) == Some(loc.clen)
        }
        None => entry.kind == EntryKind::Dir || entry.size == 0,
    };
    if well_formed {
        Ok(())
    } else {
        Err(FormatError::BadEntry(format!(
            "{path}: size, kind and data location do not fit together"
        )))
    }
}

fn op_rank(d: &OpDraft) -> u8 {
    match d {
        OpDraft::VaultInit { .. } => 0,
        OpDraft::Device { .. } => 1,
        OpDraft::Blob(_) => 2,
        OpDraft::Put { .. } => 3,
        OpDraft::Del { .. } => 4,
    }
}

fn effect_of(d: &OpDraft) -> Option<BaseEffect> {
    match d {
        OpDraft::Put { effect, .. } | OpDraft::Del { effect, .. } => effect.clone(),
        _ => None,
    }
}

fn blob_of(d: &OpDraft) -> Option<BlobId> {
    match d {
        OpDraft::Blob(rec) => Some(rec.id),
        OpDraft::Put { entry, .. } => entry.loc.as_ref().map(|l| l.blob),
        _ => None,
    }
}

/// The draft an op of a sealed segment was made from, with its base effect.
fn draft_from_op(op: &Op, effect: Option<BaseEffect>) -> OpDraft {
    match op {
        Op::VaultInit { format, name } => OpDraft::VaultInit {
            format: *format,
            name: name.clone(),
        },
        Op::Device { id, name } => OpDraft::Device {
            id: *id,
            name: name.clone(),
        },
        Op::Blob(rec) => OpDraft::Blob(rec.clone()),
        Op::Put {
            path,
            entry,
            base,
            origin,
        } => OpDraft::Put {
            path: path.clone(),
            entry: entry.clone(),
            base: *base,
            origin: *origin,
            effect,
        },
        Op::Del { path, base } => OpDraft::Del {
            path: path.clone(),
            base: *base,
            effect,
        },
    }
}

/// What the store says about a blob that unpublished ops name (§5.8).
enum BlobState {
    /// Gone, not the object that was uploaded (size or md5 differ), or unknown to the replica.
    Unusable,
    /// Intact, but its `Blob` record is unpublished and it was created more than
    /// `ORPHAN_GRACE / 2` ago.
    Old(ObjMeta),
    Good(ObjMeta),
}

struct CheckedBlob {
    id: BlobId,
    /// The replica has the blob's record (as opposed to: it is among the unpublished ops).
    published: bool,
    state: BlobState,
}

/// What became of the outbox row.
#[derive(Default)]
struct Settled {
    published: bool,
    /// Ops dropped because the segment was withdrawn (§5.8).
    dropped: u64,
}

/// Per device the greatest `(seq, hash)` among `refs`.
pub(super) fn tips(refs: impl IntoIterator<Item = SegRef>) -> BTreeMap<DeviceId, SegRef> {
    let mut tips: BTreeMap<DeviceId, SegRef> = BTreeMap::new();
    for r in refs {
        match tips.get(&r.device) {
            Some(t) if (t.seq, t.hash) >= (r.seq, r.hash) => {}
            _ => {
                tips.insert(r.device, r);
            }
        }
    }
    tips
}

/// Applies `seg` (§5.2.2) and records it: `applied`, the rollback mark, the lamport clock and
/// the writer's last-seen time. One step of a transaction.
pub(super) fn apply_and_record(
    c: &Connection,
    seg: &SegmentV1,
    row: &AppliedRow,
) -> Result<ApplyStats, IndexError> {
    let stats = apply_segment(&mut SqlStore(c), seg, row.created_ms)?;
    tables::applied_insert(c, row)?;
    tables::hw_raise(c, &row.seg_ref())?;
    raise_lamport(c, seg.lamport)?;
    tables::device_seen(c, seg.device, row.created_ms)?;
    tables::touched_bound(c)?;
    Ok(stats)
}

pub(super) fn raise_lamport(c: &Connection, lamport: u64) -> Result<(), StateError> {
    if tables::meta_u64(c, "lamport")?.unwrap_or(0) < lamport {
        tables::meta_set_u64(c, "lamport", lamport)?;
    }
    Ok(())
}

impl<B: Backend> Vault<B> {
    fn set_stuck(&self, cause: Option<String>) {
        *self.stuck.lock().unwrap_or_else(|e| e.into_inner()) = cause;
    }

    /// `Some(cause)` while a sealed segment is unpublished.
    pub fn outbox_stuck(&self) -> Option<String> {
        if !self.db.read(tables::outbox_exists).unwrap_or(false) {
            return None;
        }
        let cause = self.stuck.lock().unwrap_or_else(|e| e.into_inner()).clone();
        Some(cause.unwrap_or_else(|| "a sealed index segment has not been published yet".into()))
    }

    /// Durable (`pending`), no network.
    pub fn stage(&self, drafts: Vec<OpDraft>) -> Result<(), IndexError> {
        for d in &drafts {
            check_draft(d)?;
        }
        let now = self.now();
        self.db.txn(|c| {
            drafts
                .iter()
                .try_for_each(|d| tables::pending_insert(c, d, now))
        })?;
        Ok(())
    }

    /// §5.6; `Err(OutboxStuck)` on a temporary publish failure.
    pub async fn commit(&self) -> Result<CommitReport, IndexError> {
        let _journal = self.journal.lock().await;
        self.commit_locked().await
    }

    /// stage + commit.
    pub async fn commit_ops(&self, drafts: Vec<OpDraft>) -> Result<CommitReport, IndexError> {
        self.stage(drafts)?;
        self.commit().await
    }

    pub(super) async fn commit_locked(&self) -> Result<CommitReport, IndexError> {
        if self.check_machine()? {
            self.rotated
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let (staged, outbox) = self
            .db
            .read(|c| Ok::<_, StateError>((tables::pending_all(c)?, tables::outbox_exists(c)?)))?;
        if staged.is_empty() {
            return Ok(CommitReport::default());
        }
        let mut dropped_ops = 0;
        let staged = if outbox {
            // A segment sealed by an earlier attempt: its blobs are checked again (§5.8), and
            // what cannot be published as sealed comes back as staged ops.
            dropped_ops += self.settle_outbox(true).await.map_err(stuck_error)?.dropped;
            self.db.read(tables::pending_all)?
        } else {
            staged
        };
        let (staged, dropped) = self.verify_pending_blobs(staged).await?;
        dropped_ops += dropped;
        if staged.is_empty() {
            return Ok(CommitReport {
                dropped_ops,
                ..CommitReport::default()
            });
        }

        let me = self.device_id();
        let mut drafts: Vec<&OpDraft> = staged.iter().map(|(_, d)| d).collect();
        drafts.sort_by_key(|d| op_rank(d));
        let names_me = |d: &&OpDraft| matches!(d, OpDraft::Device { id, .. } if *id == me);
        let self_announced = drafts.iter().any(names_me);
        let (seq, lamport, prev, seen, listed_here) = self.db.read(|c| {
            let others = tables::base_covers_all(c)?
                .into_iter()
                .chain(tables::applied_all(c)?.into_iter().map(|a| a.seg_ref()))
                .filter(|r| r.device != me);
            Ok::<_, StateError>((
                tables::meta_u64(c, "next_seq")?.unwrap_or(1),
                tables::meta_u64(c, "lamport")?.unwrap_or(0) + 1,
                tables::own_last(c)?.map(|(seq, hash, file_id)| SegRef {
                    device: me,
                    seq,
                    hash,
                    file_id,
                }),
                tips(others).into_values().collect::<Vec<SegRef>>(),
                query::devices_all(c)?.iter().any(|d| d.id == me),
            ))
        })?;

        let mut ops = Vec::with_capacity(drafts.len() + 1);
        let mut effects = Vec::with_capacity(drafts.len() + 1);
        if !listed_here && !self_announced {
            // A device id the vault has not heard of (first segment, or after a rotation).
            ops.push(Op::Device {
                id: me,
                name: self.device_name.clone(),
            });
            effects.push(None);
        }
        for d in drafts {
            ops.push(op_from_draft(d));
            effects.push(effect_of(d));
        }
        debug_assert!(
            {
                let mut paths = HashSet::new();
                ops.iter().all(|op| match op {
                    Op::Put { path, .. } => paths.insert(path),
                    _ => true,
                })
            },
            "one segment never contains two Puts for the same path (§5.2.2)"
        );
        let seg = SegmentV1 {
            vault_id: self.keys.vault_id(),
            device: me,
            seq,
            lamport,
            prev,
            seen,
            created_ms: util::now_ms(),
            host: util::hostname(),
            ops,
        };
        let sealed = seal_segment(&self.keys, &seg)?;
        let [id] = fresh_ids(&*self.backend).await?;
        let ids: Vec<i64> = staged.iter().map(|(id, _)| *id).collect();
        let row = OutboxRow {
            seq,
            name: sealed.name.clone(),
            file_id: id.0,
            bytes: sealed.bytes,
            effects,
        };
        self.db.txn(|c| {
            tables::outbox_put(c, &row)?;
            tables::own_insert(c, seq, &sealed.hash, &row.file_id)?;
            tables::pending_delete(c, &ids)
        })?;
        let report = CommitReport {
            segment: Some(sealed.name),
            ops: seg.ops.len() as u64,
            dropped_ops,
        };
        // Sealed a moment ago from ops whose blobs were just uploaded or just verified.
        self.settle_outbox(false).await.map_err(stuck_error)?;
        Ok(report)
    }

    /// §5.8: if `outbox` has a row, check the blobs it names, put it again (same id, same bytes)
    /// and finish the commit transaction. `Ok(true)` when a segment was published; `Ok(false)`
    /// when there was none, or when it was withdrawn (its ops are staged again). A failure
    /// leaves the row.
    pub(super) async fn recover_outbox(&self) -> Result<bool, IndexError> {
        Ok(self.settle_outbox(true).await?.published)
    }

    /// `verify`: the row was sealed by an earlier attempt — time has passed since its blobs
    /// were looked at.
    async fn settle_outbox(&self, verify: bool) -> Result<Settled, IndexError> {
        let Some(row) = self.db.read(tables::outbox_get)? else {
            self.set_stuck(None);
            return Ok(Settled::default());
        };
        let settled: Result<Settled, IndexError> = async {
            if verify && let Some(dropped) = self.withdraw_stale(&row).await? {
                return Ok(Settled {
                    published: false,
                    dropped,
                });
            }
            self.publish(row).await?;
            Ok(Settled {
                published: true,
                dropped: 0,
            })
        }
        .await;
        match settled {
            Ok(settled) => {
                self.set_stuck(None);
                Ok(settled)
            }
            Err(e) => {
                self.set_stuck(Some(e.to_string()));
                Err(e)
            }
        }
    }

    /// §5.8: a sealed segment that waited in the outbox — a full Drive, a crash, a device that
    /// was switched off — is published only if the blobs it names are still trustworthy. To
    /// every other device those blobs are unknown objects until the segment is public: an
    /// orphan sweep trashes them after `ORPHAN_GRACE`, a `gc` may collect an old blob that a
    /// sealed `restore` or `mv` reuses. Publishing the segment as sealed would then put heads
    /// on blobs that are in the trash or gone, and base rows that say the files are in sync.
    ///
    /// Trashed blobs are un-trashed. If a blob is missing, damaged or (its record unpublished)
    /// older than `ORPHAN_GRACE / 2`, the segment is withdrawn: the outbox row and its `own`
    /// row go, the ops that name such a blob are dropped with their base effects (the next
    /// sync uploads the files again) and the others are staged again. `Some(dropped ops)` then.
    ///
    /// Not withdrawn: a segment that is in the store already (the process died after the put).
    /// Other devices may have applied it; it is finished as sealed.
    async fn withdraw_stale(&self, row: &OutboxRow) -> Result<Option<u64>, IndexError> {
        let (seg, hash) = open_segment(&self.keys, &row.name, &row.bytes)?;
        let mut wanted: BTreeMap<BlobId, Option<BlobRec>> = BTreeMap::new();
        for op in &seg.ops {
            match op {
                Op::Blob(rec) => {
                    wanted.insert(rec.id, Some(rec.clone()));
                }
                Op::Put { entry, .. } => {
                    if let Some(loc) = &entry.loc {
                        wanted.entry(loc.blob).or_insert(None);
                    }
                }
                _ => {}
            }
        }
        if wanted.is_empty() {
            return Ok(None);
        }
        let checked = self.check_blobs(wanted).await?;
        let stale = checked
            .iter()
            .any(|b| !matches!(b.state, BlobState::Good(_)));
        if !stale || self.segment_stored(row).await? {
            let mut unusable = 0;
            for blob in &checked {
                match &blob.state {
                    BlobState::Good(meta) | BlobState::Old(meta) => {
                        self.untrash_blob(blob, meta).await?;
                    }
                    BlobState::Unusable => unusable += 1,
                }
            }
            if unusable > 0 {
                tracing::warn!(
                    "index segment {} is already in the vault, but {unusable} blob(s) it names \
                     are missing or damaged; run `gclone check`",
                    row.name
                );
            }
            return Ok(None);
        }

        let mut unusable: BTreeSet<BlobId> = BTreeSet::new();
        for blob in &checked {
            match &blob.state {
                BlobState::Good(meta) => self.untrash_blob(blob, meta).await?,
                BlobState::Old(_) | BlobState::Unusable => {
                    unusable.insert(blob.id);
                }
            }
        }
        let me = self.device_id();
        let mut kept: Vec<OpDraft> = Vec::new();
        let mut dropped = 0u64;
        for (i, op) in seg.ops.iter().enumerate() {
            // The announcement of a device id this replica has left since (a rotation): the
            // next segment announces the current one by itself.
            if matches!(op, Op::Device { id, .. } if *id == seg.device && seg.device != me) {
                continue;
            }
            let draft = draft_from_op(op, row.effects.get(i).cloned().flatten());
            if blob_of(&draft).is_some_and(|id| unusable.contains(&id)) {
                dropped += 1;
            } else {
                kept.push(draft);
            }
        }
        let now = self.now();
        self.db.txn(|c| {
            tables::outbox_clear(c)?;
            tables::own_delete(c, seg.seq, &hash)?;
            kept.iter()
                .try_for_each(|d| tables::pending_insert(c, d, now))
        })?;
        tracing::warn!(
            "the unpublished index segment {} was withdrawn: {} uploaded blob(s) it names are \
             missing, damaged or too old to trust. {dropped} change(s) were dropped — the files \
             are uploaded again by the next sync — and {} are staged again",
            row.name,
            unusable.len(),
            kept.len()
        );
        Ok(Some(dropped))
    }

    /// Whether the store holds the sealed segment of the outbox row under its id, byte for
    /// byte (trashed or not): then it was published and only the local half is missing.
    async fn segment_stored(&self, row: &OutboxRow) -> Result<bool, IndexError> {
        let meta = match self.backend.stat(&Handle(row.file_id.clone())).await {
            Ok(meta) => meta,
            Err(BackendError::NotFound) => None,
            Err(e) => return Err(e.into()),
        };
        Ok(meta.is_some_and(|m| {
            !m.is_folder
                && m.name == row.name
                && m.size == row.bytes.len() as u64
                && m.md5.is_none_or(|md5| md5 == md5_of(&row.bytes))
        }))
    }

    /// `stat`s every blob that unpublished ops name (§5.8). `wanted`: blob id → its record when
    /// the record itself is still unpublished (`None`: the replica must know the blob).
    async fn check_blobs(
        &self,
        wanted: BTreeMap<BlobId, Option<BlobRec>>,
    ) -> Result<Vec<CheckedBlob>, IndexError> {
        let now = self.backend.now_ms();
        let mut checked = Vec::with_capacity(wanted.len());
        for (id, unpublished) in wanted {
            let (rec, published) = match unpublished {
                Some(rec) => (Some(rec), false),
                None => (self.blob(&id)?, true),
            };
            let state = match rec {
                None => BlobState::Unusable,
                Some(rec) => match self.backend.stat(&Handle(rec.file_id.clone())).await? {
                    Some(m) if m.size != rec.clen || m.md5.is_some_and(|md5| md5 != rec.md5) => {
                        BlobState::Unusable
                    }
                    // Another device's orphan sweep may be about to trash an unreferenced blob
                    // this old: upload it again instead of trusting it.
                    Some(m)
                        if !published && now.saturating_sub(m.created_ms) > ORPHAN_GRACE_MS / 2 =>
                    {
                        BlobState::Old(m)
                    }
                    Some(m) => BlobState::Good(m),
                    None => BlobState::Unusable,
                },
            };
            checked.push(CheckedBlob {
                id,
                published,
                state,
            });
        }
        Ok(checked)
    }

    /// §5.9: wherever a `stat` of a referenced blob shows it trashed, it is un-trashed.
    async fn untrash_blob(&self, blob: &CheckedBlob, meta: &ObjMeta) -> Result<(), IndexError> {
        if meta.trashed {
            self.backend.untrash(&meta.handle).await?;
            if blob.published {
                self.set_blob_trashed(&blob.id, None)?;
            }
        }
        Ok(())
    }

    async fn publish(&self, row: OutboxRow) -> Result<(), IndexError> {
        let (seg, hash) = open_segment(&self.keys, &row.name, &row.bytes)?;
        let bytes = Bytes::from(row.bytes);
        let (id, meta) = put_retrying(
            &*self.backend,
            Handle(row.file_id),
            &self.handles.index,
            &row.name,
            &bytes,
            |id| {
                Ok(self.db.txn(|c| {
                    tables::outbox_set_file_id(c, &id.0)?;
                    tables::own_set_file_id(c, seg.seq, &hash, &id.0)
                })?)
            },
        )
        .await?;

        let applied = AppliedRow {
            dev: seg.device,
            seq: seg.seq,
            hash,
            file_id: id.0,
            name: row.name.clone(),
            lamport: seg.lamport,
            created_ms: meta.created_ms,
            size: bytes.len() as u64,
        };
        let me = self.device_id();
        self.db.txn(|c| {
            if !tables::is_known(c, seg.device, seg.seq, &hash)? {
                apply_and_record(c, &seg, &applied)?;
            }
            // A segment sealed before a device-id rotation no longer moves the sequence.
            if seg.device == me && tables::meta_u64(c, "next_seq")?.unwrap_or(1) <= seg.seq {
                tables::meta_set_u64(c, "next_seq", seg.seq + 1)?;
            }
            for (i, effect) in row.effects.iter().enumerate() {
                let Some(effect) = effect else { continue };
                match &effect.kind {
                    BaseEffectKind::Set {
                        sig,
                        hash,
                        observed_ns,
                        kind,
                    } => tables::base_upsert(
                        c,
                        effect.pair,
                        &BaseRow {
                            key: effect.key.clone(),
                            rel: effect.rel.clone(),
                            kind: *kind,
                            sig: *sig,
                            hash: *hash,
                            remote_stamp: Stamp {
                                lamport: seg.lamport,
                                device: seg.device,
                                idx: i as u32,
                            },
                            observed_ns: *observed_ns,
                        },
                    )?,
                    BaseEffectKind::Forget => tables::base_delete(c, effect.pair, &effect.key)?,
                }
            }
            tables::outbox_clear(c)?;
            Ok::<_, IndexError>(())
        })?;
        self.cache_write(&row.name, &bytes);
        Ok(())
    }

    /// §5.8: staged ops left by an earlier process are published only if their blobs are still
    /// trustworthy. Returns the ops to commit and the number dropped.
    async fn verify_pending_blobs(
        &self,
        staged: Vec<(i64, OpDraft)>,
    ) -> Result<(Vec<(i64, OpDraft)>, u64), IndexError> {
        let inherited = |(id, _): &&(i64, OpDraft)| *id <= self.inherited_pending;
        // blob id → its record when the record itself is still unpublished
        let mut wanted: BTreeMap<BlobId, Option<BlobRec>> = BTreeMap::new();
        for (_, d) in staged.iter().filter(inherited) {
            match d {
                OpDraft::Blob(rec) => {
                    wanted.insert(rec.id, Some(rec.clone()));
                }
                d => {
                    if let Some(id) = blob_of(d) {
                        wanted.entry(id).or_insert(None);
                    }
                }
            }
        }
        if wanted.is_empty() {
            return Ok((staged, 0));
        }
        let mut unusable: BTreeSet<BlobId> = BTreeSet::new();
        for blob in self.check_blobs(wanted).await? {
            match &blob.state {
                BlobState::Good(meta) => self.untrash_blob(&blob, meta).await?,
                BlobState::Old(_) | BlobState::Unusable => {
                    unusable.insert(blob.id);
                }
            }
        }
        if unusable.is_empty() {
            return Ok((staged, 0));
        }
        let (dropped, kept): (Vec<_>, Vec<_>) = staged
            .into_iter()
            .partition(|(_, d)| blob_of(d).is_some_and(|id| unusable.contains(&id)));
        let ids: Vec<i64> = dropped.iter().map(|(id, _)| *id).collect();
        self.db.txn(|c| tables::pending_delete(c, &ids))?;
        tracing::warn!(
            "dropped {} staged index changes of an interrupted run: {} uploaded blob(s) are \
             missing, damaged or too old to trust; the files are uploaded again by the next sync",
            dropped.len(),
            unusable.len()
        );
        Ok((kept, dropped.len() as u64))
    }

    pub async fn maybe_compact(&self) -> Result<Option<String>, IndexError> {
        let _journal = self.journal.lock().await;
        self.maybe_compact_locked().await
    }

    async fn maybe_compact_locked(&self) -> Result<Option<String>, IndexError> {
        let due = self.db.read(|c| {
            if tables::outbox_exists(c)?
                || !tables::blocked_all(c)?.is_empty()
                || query::conflict_count(c)? > 0
            {
                return Ok::<_, StateError>(false);
            }
            let (segments, bytes) = tables::applied_totals(c)?;
            let base_size = tables::meta_u64(c, "base_snapshot_size")?.unwrap_or(0);
            Ok(segments >= COMPACT_MIN_SEGMENTS || bytes > COMPACT_MIN_BYTES.max(base_size / 4))
        })?;
        if !due {
            return Ok(None);
        }
        self.write_snapshot_locked().await.map(Some)
    }

    pub async fn write_snapshot(&self) -> Result<String, IndexError> {
        let _journal = self.journal.lock().await;
        self.write_snapshot_locked().await
    }

    pub(super) async fn write_snapshot_locked(&self) -> Result<String, IndexError> {
        let now = self.backend.now_ms();
        let (db, keys, me) = (self.db.clone(), self.keys.clone(), self.device_id());
        let (sealed, covered, covers, lamport) = blocking(move || {
            let (state, applied, mut covered, base_covers, lamport) = db.read(|c| {
                Ok::<_, StateError>((
                    query::mem_index(c)?,
                    tables::applied_all(c)?,
                    tables::base_covered_all(c)?,
                    tables::base_covers_all(c)?,
                    // A snapshot takes a clock value of its own, so that "the newest snapshot"
                    // (greatest inner lamport, §5.3) is well defined for snapshots written in a row.
                    tables::meta_u64(c, "lamport")?.unwrap_or(0) + 1,
                ))
            })?;
            covered.extend(applied.iter().map(|a| a.seg_ref().covered()));
            covered.sort();
            covered.dedup();
            let covers: Vec<SegRef> = tips(
                base_covers
                    .into_iter()
                    .chain(applied.iter().map(AppliedRow::seg_ref)),
            )
            .into_values()
            .collect();
            let snap = state.to_snapshot(
                keys.vault_id(),
                me,
                lamport,
                covers.clone(),
                covered.clone(),
                now,
            );
            Ok((seal_snapshot(&keys, &snap)?, covered, covers, lamport))
        })
        .await?;

        let bytes = Bytes::from(sealed.bytes);
        let [id] = fresh_ids(&*self.backend).await?;
        let index = &self.handles.index;
        let (id, meta) =
            put_retrying(&*self.backend, id, index, &sealed.name, &bytes, |_| Ok(())).await?;
        self.db.txn(|c| {
            tables::base_covered_replace(c, &covered)?;
            tables::base_covers_replace(c, &covers)?;
            c.execute("DELETE FROM applied", [])?;
            c.execute(
                "DELETE FROM removed WHERE removed_ms <= ?",
                [tables::to_i(now.saturating_sub(HISTORY_KEEP_MS))?],
            )?;
            let size = bytes.len() as u64;
            let md5 = md5_of(&bytes);
            raise_lamport(c, lamport)?;
            set_base_meta(c, &sealed.name, lamport, size, &md5, &id.0)?;
            tables::meta_set_str(c, "last_snapshot_name", &sealed.name)?;
            tables::meta_set_str(c, "last_snapshot_id", &id.0)?;
            tables::meta_set_u64(c, "last_snapshot_size", size)?;
            tables::meta_set_u64(c, "last_snapshot_created_ms", meta.created_ms)?;
            tables::meta_set(c, "last_snapshot_md5", &md5)?;
            tables::meta_set_str(c, "snap_checked", &sealed.name)
        })?;
        self.cache_write(&sealed.name, &bytes);
        Ok(sealed.name)
    }

    /// Returns the number of objects trashed.
    pub async fn cleanup_index(&self) -> Result<u64, IndexError> {
        let _journal = self.journal.lock().await;
        self.cleanup_locked(false).await
    }

    /// `after_refresh`: the caller refreshed in this command (`finish_mutation`), so the
    /// snapshots that refresh saw listed may stand in for a listing of its own.
    ///
    /// A pass that ran to its end records what it cleaned up for and which snapshots were left
    /// listed (`meta.cleanup_done`). Until one of the two changes there is nothing new to
    /// decide — what a pass trashes is a function of the listed snapshots — and the pass is
    /// skipped: no snapshot is read and decoded again, command after command.
    async fn cleanup_locked(&self, after_refresh: bool) -> Result<u64, IndexError> {
        self.prune_cache();
        // Only the device that wrote snapshot S cleans up, and only once S has aged (§5.6).
        let last = self.db.read(|c| {
            let Some(name) = tables::meta_str(c, "last_snapshot_name")? else {
                return Ok::<_, StateError>(None);
            };
            Ok(Some((
                name,
                tables::meta_str(c, "last_snapshot_id")?.unwrap_or_default(),
                tables::meta_u64(c, "last_snapshot_size")?.unwrap_or(0),
                tables::meta_u64(c, "last_snapshot_created_ms")?.unwrap_or(u64::MAX),
                tables::meta_get(c, "last_snapshot_md5")?,
                tables::meta_get(c, "cleanup_done")?,
            )))
        })?;
        let Some((mine, id, size, created_ms, md5, done)) = last else {
            return Ok(0);
        };
        if self.backend.now_ms().saturating_sub(created_ms) < INDEX_TRASH_DELAY_MS {
            return Ok(0);
        }
        let is_done = |listed_snapshots: &[u8; 32]| {
            done.as_deref() == Some(&cleanup_key(&mine, listed_snapshots)[..])
        };
        let refreshed = *self.listed_snaps.lock().unwrap_or_else(|e| e.into_inner());
        if after_refresh && refreshed.is_some_and(|seen| is_done(&seen)) {
            return Ok(0);
        }
        let listed = Listed::new(self.backend.list(&self.handles.index).await?);
        if is_done(&listed.snapshots_fingerprint(&HashSet::new())) {
            return Ok(0);
        }
        // Whatever this pass finds, it need not be found again while the listing stays as it
        // leaves it.
        let finish = |trashed_snapshots: &HashSet<Handle>| {
            let left = listed.snapshots_fingerprint(trashed_snapshots);
            self.db.meta_set("cleanup_done", &cleanup_key(&mine, &left))
        };
        let intact = |m: &ObjMeta| {
            !m.trashed
                && m.size == size
                && m.md5
                    .is_none_or(|have| md5.as_deref().is_none_or(|want| want == have))
        };
        if !self
            .backend
            .stat(&Handle(id))
            .await?
            .is_some_and(|m| intact(&m))
        {
            finish(&HashSet::new())?;
            return Ok(0);
        }

        // K: every accepted snapshot in the listing, newest (inner lamport) first.
        let mut accepted = Vec::new();
        for (name, metas) in listed.snaps.iter().rev() {
            if let Some(snap) = self.fetch_snapshot(name, metas).await?
                && snap.on_remote
            {
                accepted.push((name, metas, snap.body));
            }
        }
        accepted.sort_by(|a, b| (b.2.lamport, b.0).cmp(&(a.2.lamport, a.0)));
        let Some(own) = accepted.iter().find(|(name, ..)| **name == mine) else {
            finish(&HashSet::new())?;
            return Ok(0);
        };
        let own_covered = own.2.covered.clone();

        let mut victims: Vec<Handle> = Vec::new();
        let mut trashed_snapshots: HashSet<Handle> = HashSet::new();
        let mut retained = Vec::new();
        for (rank, (name, metas, snap)) in accepted.iter().enumerate() {
            let dominated = **name != mine && is_superset(&own_covered, &snap.covered);
            if dominated && rank >= SNAPSHOT_KEEP {
                victims.extend(metas.iter().map(|m| m.handle.clone()));
                trashed_snapshots.extend(metas.iter().map(|m| m.handle.clone()));
            } else {
                retained.push(snap);
            }
        }
        for (name, metas) in &listed.segs {
            let Some(IndexName::Segment { device, seq, h8 }) = parse_index_name(name) else {
                continue;
            };
            let identity = CoveredSeg {
                device,
                seq,
                h4: h8,
            };
            if !retained
                .iter()
                .all(|s| s.covered.binary_search(&identity).is_ok())
            {
                continue;
            }
            for meta in metas {
                if self.is_genuine(name, meta).await? {
                    victims.push(meta.handle.clone());
                }
            }
        }

        let backend = &self.backend;
        let trashed = futures_util::stream::iter(victims)
            .map(|h| async move {
                match backend.trash(&h).await {
                    Ok(()) | Err(BackendError::NotFound) => Ok(1u64),
                    Err(e) => Err(IndexError::from(e)),
                }
            })
            .buffer_unordered(8)
            .try_fold(0u64, |n, one| async move { Ok(n + one) })
            .await?;
        finish(&trashed_snapshots)?;
        Ok(trashed)
    }

    /// A listed object that fails acceptance is never trashed (§5.6): the listed object must be
    /// the cached, accepted bytes — or be downloaded and accepted now.
    async fn is_genuine(&self, name: &str, meta: &ObjMeta) -> Result<bool, IndexError> {
        let cached = self.cache_read(name).filter(|bytes| {
            matches!(parse_index_name(name), Some(IndexName::Segment { h8, .. })
                if blake3::hash(bytes).as_bytes()[..4] == h8)
        });
        match cached {
            Some(bytes) => {
                Ok(meta.size == bytes.len() as u64 && meta.md5.is_none_or(|m| m == md5_of(&bytes)))
            }
            None => Ok(self
                .fetch_segment(name, std::slice::from_ref(meta))
                .await?
                .is_some()),
        }
    }

    /// The index cache keeps every object until the base covers it and it is 30 days old.
    fn prune_cache(&self) {
        let keep = self.db.read(|c| {
            let covered: HashSet<CoveredSeg> = tables::base_covered_all(c)?.into_iter().collect();
            let snapshots = [
                tables::meta_str(c, "base_snapshot_name")?,
                tables::meta_str(c, "last_snapshot_name")?,
            ];
            Ok::<_, StateError>((covered, snapshots))
        });
        let (Ok((covered, snapshots)), Ok(dir)) = (keep, std::fs::read_dir(&self.cache_dir)) else {
            return;
        };
        let now = SystemTime::now();
        for entry in dir.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let age_ms = entry
                .metadata()
                .and_then(|md| md.modified())
                .ok()
                .and_then(|at| now.duration_since(at).ok())
                .map_or(0, |d| d.as_millis() as u64);
            let stale = age_ms >= INDEX_CACHE_KEEP_MS
                && match parse_index_name(&name) {
                    Some(IndexName::Segment { device, seq, h8 }) => covered.contains(&CoveredSeg {
                        device,
                        seq,
                        h4: h8,
                    }),
                    Some(IndexName::Snapshot { .. }) => {
                        !snapshots.iter().flatten().any(|keep| *keep == name)
                    }
                    // leftovers of interrupted atomic writes
                    None => true,
                };
            if stale {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// §5.6: commit → resolve_conflicts → maybe_compact → cleanup_index. Called exactly once per
    /// mutating command, by the CLI layer.
    pub async fn finish_mutation(&self) -> Result<(), IndexError> {
        let _journal = self.journal.lock().await;
        // Nothing can be published while the outbox is stuck; the command's own commit said so.
        if self.db.read(tables::outbox_exists)? {
            return Ok(());
        }
        self.commit_locked().await?;
        self.resolve_locked().await?;
        let compacted = self.maybe_compact_locked().await.map(drop);
        let cleaned = match compacted {
            Ok(()) => self.cleanup_locked(true).await.map(drop),
            failed => failed,
        };
        match cleaned {
            Err(IndexError::Backend(e)) if e.is_temporary() => {
                tracing::warn!("index compaction and cleanup are postponed: {e}");
                Ok(())
            }
            other => other,
        }
    }
}

/// Records which snapshot the replica is based on (§5.3).
pub(super) fn set_base_meta(
    c: &Connection,
    name: &str,
    lamport: u64,
    size: u64,
    md5: &[u8; 16],
    file_id: &str,
) -> Result<(), StateError> {
    tables::meta_set_str(c, "base_snapshot_name", name)?;
    tables::meta_set_u64(c, "base_snapshot_lamport", lamport)?;
    tables::meta_set_u64(c, "base_snapshot_size", size)?;
    tables::meta_set(c, "base_snapshot_md5", md5)?;
    tables::meta_set_str(c, "base_snapshot_id", file_id)
}

/// What a complete cleanup pass leaves in `meta.cleanup_done`: the snapshot it cleaned up for
/// and the snapshots the listing showed when it was done (§5.6).
fn cleanup_key(mine: &str, listed_snapshots: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"gclone/v1/cleanup");
    h.update(&(mine.len() as u64).to_be_bytes());
    h.update(mine.as_bytes());
    h.update(listed_snapshots);
    *h.finalize().as_bytes()
}

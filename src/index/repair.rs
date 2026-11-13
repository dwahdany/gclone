//! `gclone repair`: republish from the index cache, publish a snapshot, `--accept-loss`
//! (SPEC §5.10) — owned by WP4. Private to `index`.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;

use super::commit::{apply_and_record, tips};
use super::refresh::{Pulled, is_superset};
use super::{RepairReport, Vault, blocking, fresh_ids, put_retrying};
use crate::backend::{Backend, Handle, ObjMeta, md5_of};
use crate::error::{BackendError, IndexError, StateError};
use crate::format::{
    IndexName, SnapshotV1, open_segment, open_snapshot, parse_index_name, segment_name,
};
use crate::state::tables::{self, AppliedRow};
use crate::types::CoveredSeg;
use crate::util;

impl<B: Backend> Vault<B> {
    /// §5.10 (refreshes by itself). A gap or an unsatisfied mark that remains without
    /// `accept_loss` is reported in `RepairReport::still_missing`.
    pub async fn repair(&self, accept_loss: bool) -> Result<RepairReport, IndexError> {
        let _journal = self.journal.lock().await;
        let mut report = RepairReport::default();

        // 1.–2. Refresh with the verdicts collected, then give back what only this cache holds.
        let first = self.pull().await?;
        self.republish(&first, &mut report).await?;

        // 3. Clean, or only the remote lost objects: publish what this replica knows.
        let second = self.pull().await?;
        if second.verdict.mark.is_none() && second.verdict.gap.is_empty() {
            self.resolve_locked().await?;
            report.snapshot = Some(self.write_snapshot_locked().await?);
            return Ok(report);
        }

        // 4. A gap or an unsatisfied mark remains.
        let now = self.now();
        let mut lost: Vec<String> = second
            .missing
            .iter()
            .map(|(r, since)| {
                format!(
                    "{} (device {}, seq {}, missing for {})",
                    segment_name(r.device, r.seq, &r.hash),
                    r.device,
                    r.seq,
                    util::human_age(now.saturating_sub(*since))
                )
            })
            .collect();
        if let Some(mark) = &second.verdict.mark {
            lost.push(format!(
                "{} (device {}, seq {}, rollback mark without its segment)",
                segment_name(mark.device, mark.seq, &mark.hash),
                mark.device,
                mark.seq
            ));
        }
        if !accept_loss {
            report.still_missing = lost;
            return Ok(report);
        }

        // Apply every blocked segment ignoring its unsatisfied references, in stamp order, and
        // reset the marks to what this replica now holds.
        let mut blocked = second.blocked;
        blocked.sort_by_key(|((seg, hash), _)| (seg.lamport, seg.device, seg.seq, *hash));
        let db = self.db.clone();
        blocking(move || {
            db.txn(|c| {
                for ((seg, hash), info) in &blocked {
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
                let held = tables::base_covers_all(c)?
                    .into_iter()
                    .chain(tables::applied_all(c)?.into_iter().map(|a| a.seg_ref()));
                let marks: Vec<_> = tips(held).into_values().collect();
                tables::hw_replace(c, &marks)?;
                tables::blocked_replace(c, &Default::default())?;
                Ok::<_, IndexError>(())
            })
        })
        .await?;
        report.accepted_loss = lost;
        self.resolve_locked().await?;
        // Its `covered` set lists only what was applied: a skipped segment is never claimed.
        report.snapshot = Some(self.write_snapshot_locked().await?);
        Ok(report)
    }

    /// Step 2: every object in the local index cache that is neither listed nor covered by an
    /// accepted listed snapshot is un-trashed, or put again under a new id.
    ///
    /// "Listed" means the cached bytes, not the name (§5.3 presence, §17.26): an object that
    /// stands under the name of a cached one with another size or md5 was overwritten or
    /// planted. It can pass acceptance for nobody — the name carries the hash of the content
    /// it belongs to — so it is moved to the trash and the cached object is put in its place.
    async fn republish(
        &self,
        pulled: &Pulled,
        report: &mut RepairReport,
    ) -> Result<(), IndexError> {
        let mut listed_snapshots: Vec<Arc<SnapshotV1>> = Vec::new();
        for (name, metas) in &pulled.listed.snaps {
            if let Some(snap) = self.fetch_snapshot(name, metas).await?
                && snap.on_remote
            {
                listed_snapshots.push(snap.body);
            }
        }
        // Where this replica last knew each object, by name.
        let mut places: HashMap<String, String> = self.db.read(|c| {
            let mut places = HashMap::new();
            for mark in tables::hw_all(c)?
                .into_iter()
                .chain(tables::base_covers_all(c)?)
            {
                places.insert(
                    segment_name(mark.device, mark.seq, &mark.hash),
                    mark.file_id,
                );
            }
            for row in tables::applied_all(c)? {
                places.insert(row.name, row.file_id);
            }
            for kind in ["base", "last"] {
                if let (Some(name), Some(id)) = (
                    tables::meta_str(c, &format!("{kind}_snapshot_name"))?,
                    tables::meta_str(c, &format!("{kind}_snapshot_id"))?,
                ) {
                    places.insert(name, id);
                }
            }
            Ok::<_, StateError>(places)
        })?;
        for (_, info) in &pulled.blocked {
            places
                .entry(info.name.clone())
                .or_insert_with(|| info.file_id.clone());
        }

        let mut cached: Vec<String> = match std::fs::read_dir(&self.cache_dir) {
            Ok(dir) => dir
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect(),
            Err(_) => Vec::new(),
        };
        cached.sort();
        for name in cached {
            let Some(kind) = parse_index_name(&name) else {
                continue;
            };
            let Some(bytes) = self.cache_read(&name) else {
                continue;
            };
            let (size, md5) = (bytes.len() as u64, md5_of(&bytes));
            let listed: &[ObjMeta] = match kind {
                IndexName::Segment { .. } => pulled.listed.segs.get(&name),
                IndexName::Snapshot { .. } => pulled.listed.snaps.get(&name),
            }
            .map_or(&[], Vec::as_slice);
            // The store holds this very object: by size and md5, and where it reports no md5,
            // by its content — never by the size alone (a plant of the right size under the
            // name would otherwise keep the lost object from being published again).
            let held = self.find_object(&name, listed, size, &md5).await?.is_some();
            // Nothing is published that would not be accepted.
            let keys = self.keys.clone();
            let object = name.clone();
            let (bytes, hash, wanted) = match kind {
                IndexName::Segment { device, seq, h8 } => {
                    let identity = CoveredSeg {
                        device,
                        seq,
                        h4: h8,
                    };
                    if held
                        || listed_snapshots
                            .iter()
                            .any(|s| s.covered.binary_search(&identity).is_ok())
                    {
                        continue;
                    }
                    blocking(move || {
                        let hash = open_segment(&keys, &object, &bytes).ok().map(|(_, h)| h);
                        Ok((bytes, hash, true))
                    })
                    .await?
                }
                IndexName::Snapshot { .. } => {
                    if held {
                        continue;
                    }
                    let others = listed_snapshots.clone();
                    blocking(move || {
                        let opened = open_snapshot(&keys, &object, &bytes).ok();
                        // A snapshot that a listed one dominates is history, not a loss.
                        let wanted = opened.as_ref().is_some_and(|(snap, _)| {
                            !others
                                .iter()
                                .any(|o| is_superset(&o.covered, &snap.covered))
                        });
                        Ok((bytes, opened.map(|(_, h)| h), wanted))
                    })
                    .await?
                }
            };
            let Some(hash) = hash.filter(|_| wanted) else {
                continue;
            };

            let place = places.remove(&name).filter(|id| !id.is_empty());
            // The object this replica knew, if it still holds the cached bytes under its name.
            let known = match &place {
                Some(id) => match self.backend.stat(&Handle(id.clone())).await? {
                    Some(m)
                        if !m.is_folder
                            && m.name == name
                            && self.is_object(&name, &m, size, &md5).await? =>
                    {
                        Some(m)
                    }
                    _ => None,
                },
                None => None,
            };
            // Present under its name: only the listing lags.
            if known.as_ref().is_some_and(|m| !m.trashed) {
                continue;
            }
            // What stands under the name with other bytes makes room first: a directory
            // vault holds one object per name, and no device can use this one.
            for impostor in listed {
                tracing::warn!(
                    "index object {name} in the store is not the object this device holds \
                     ({} bytes there, {size} here): moved to the trash and put again",
                    impostor.size
                );
                match self.backend.trash(&impostor.handle).await {
                    Ok(()) | Err(BackendError::NotFound) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if let Some(m) = known {
                self.backend.untrash(&m.handle).await?;
                report.untrashed.push(name);
                continue;
            }
            let [id] = fresh_ids(&*self.backend).await?;
            let index = &self.handles.index;
            let bytes = Bytes::from(bytes);
            let (id, _) =
                put_retrying(&*self.backend, id, index, &name, &bytes, |_| Ok(())).await?;
            self.db.txn(|c| {
                match kind {
                    IndexName::Segment { device, seq, .. } => {
                        tables::applied_set_file_id(c, device, seq, &hash, &id.0)?;
                        tables::own_set_file_id(c, seq, &hash, &id.0)?;
                    }
                    IndexName::Snapshot { .. } => {
                        for kind in ["base", "last"] {
                            let key = format!("{kind}_snapshot_name");
                            if tables::meta_str(c, &key)?.as_deref() == Some(name.as_str()) {
                                tables::meta_set_str(c, &format!("{kind}_snapshot_id"), &id.0)?;
                            }
                        }
                    }
                }
                Ok::<_, StateError>(())
            })?;
            report.republished.push(name);
        }
        Ok(())
    }
}

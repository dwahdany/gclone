//! SQL reads behind the `Vault` query methods (SPEC §9.7) — owned by WP4. Private to `index`.
//! Everything here looks at the local replica only.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, params};

use super::{DeviceInfo, ListRow, MemIndex, Vault, VaultStats};
use crate::backend::Backend;
use crate::consts::{GC_GRACE_MS, RESTORE_WINDOW_MS};
use crate::error::{IndexError, StateError};
use crate::format::{DeviceRec, HeadRec, Op, RemovedRec, SnapshotV1, blob_name, open_segment};
use crate::state::tables::{self, VERSION_COLS, arr, blob_at, heads_query, to_i, to_u, version_at};
use crate::types::{BlobId, BlobRec, DeviceId, EntryKind, Head, OpDraft, RemovedVersion, Stamp};
use crate::util;

const BLOB_COLS: &str = "id, file_id, clen, md5, created_ms";

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

/// `(first path under prefix/, first path after the subtree)`: `'/' + 1 == '0'`.
fn subtree(prefix: &str) -> (String, String) {
    (format!("{prefix}/"), format!("{prefix}0"))
}

pub(super) fn removed_all(
    c: &Connection,
    cond: &str,
    args: &[Value],
) -> Result<Vec<RemovedVersion>, StateError> {
    let mut stmt = c.prepare_cached(&format!(
        "SELECT {VERSION_COLS}, removed_ms, by_l, by_d, by_i FROM removed {cond}"
    ))?;
    let mut rows = stmt.query(rusqlite::params_from_iter(args.iter()))?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let v = version_at(r)?;
        out.push(RemovedVersion {
            path: v.path,
            stamp: v.stamp,
            entry: v.entry,
            removed_ms: to_u(r.get(20)?)?,
            by: Stamp {
                lamport: to_u(r.get(21)?)?,
                device: DeviceId(arr(r.get(22)?)?),
                idx: u32::try_from(r.get::<_, i64>(23)?)
                    .map_err(|_| StateError::Corrupt("op index out of range".into()))?,
            },
        });
    }
    Ok(out)
}

fn blobs_where(c: &Connection, cond: &str, args: &[Value]) -> Result<Vec<BlobRec>, StateError> {
    let mut stmt = c.prepare_cached(&format!("SELECT {BLOB_COLS} FROM blobs b {cond}"))?;
    let mut rows = stmt.query(rusqlite::params_from_iter(args.iter()))?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(blob_at(r, 0)?);
    }
    Ok(out)
}

pub(super) fn devices_all(c: &Connection) -> Result<Vec<DeviceInfo>, StateError> {
    let mut stmt =
        c.prepare_cached("SELECT id, name, first_ms, last_ms FROM devices ORDER BY first_ms, id")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(DeviceInfo {
            id: DeviceId(arr(r.get(0)?)?),
            name: r.get(1)?,
            first_ms: to_u(r.get(2)?)?,
            last_ms: to_u(r.get(3)?)?,
        });
    }
    Ok(out)
}

/// Served by the partial index `heads_losers` (§8.4): O(losers), not a scan of every head.
pub(super) const CONFLICT_COUNT: &str = "SELECT count(*) FROM heads WHERE winner = 0";

pub(super) fn conflict_count(c: &Connection) -> Result<u64, StateError> {
    to_u(c.query_row(CONFLICT_COUNT, [], |r| r.get(0))?)
}

/// The whole replica as a `MemIndex`: every head, removed version, blob row and device.
pub(super) fn mem_index(c: &Connection) -> Result<MemIndex, StateError> {
    let heads = heads_query(c, "1 ORDER BY path, st_l, st_d, st_i, hash", &[])?;
    let removed = removed_all(c, "ORDER BY path, st_l, st_d, st_i, hash", &[])?;
    let all = SnapshotV1 {
        vault_id: [0; 16],
        device: DeviceId([0; 8]),
        lamport: 0,
        created_ms: 0,
        vault_format: u16::try_from(tables::meta_u64(c, "vault_format")?.unwrap_or(0))
            .map_err(|_| StateError::Corrupt("vault format out of range".into()))?,
        vault_name: tables::meta_str(c, "vault_name")?.unwrap_or_default(),
        covers: Vec::new(),
        covered: Vec::new(),
        devices: devices_all(c)?
            .into_iter()
            .map(|d| DeviceRec {
                id: d.id,
                name: d.name,
                first_ms: d.first_ms,
            })
            .collect(),
        blobs: blobs_where(c, "ORDER BY id", &[])?,
        heads: heads
            .into_iter()
            .map(|h| HeadRec {
                path: h.path,
                stamp: h.stamp,
                entry: h.entry,
                origin: h.origin,
            })
            .collect(),
        removed: removed
            .into_iter()
            .map(|r| RemovedRec {
                path: r.path,
                stamp: r.stamp,
                entry: r.entry,
                removed_ms: r.removed_ms,
                by: r.by,
            })
            .collect(),
    };
    Ok(MemIndex::load_snapshot(&all))
}

/// Blobs no head references, with the time they died: the newest `removed` reference, or the
/// blob's creation if nothing ever referenced it. Rows already trashed by this device are out.
fn dead_since(c: &Connection) -> Result<Vec<(BlobRec, u64)>, StateError> {
    let mut stmt = c.prepare_cached(
        "SELECT b.id, b.file_id, b.clen, b.md5, b.created_ms, \
                coalesce((SELECT max(r.removed_ms) FROM removed r WHERE r.blob = b.id), b.created_ms) \
         FROM blobs b \
         WHERE b.trashed_ms IS NULL AND NOT EXISTS (SELECT 1 FROM heads h WHERE h.blob = b.id) \
         ORDER BY b.id",
    )?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push((blob_at(r, 0)?, to_u(r.get(5)?)?));
    }
    Ok(out)
}

/// `staged`: blobs that unpublished ops of this device name (`pending`, `outbox`). No head
/// references them yet, but one will as soon as the ops are published — they are not dead.
fn dead_blobs(
    c: &Connection,
    now_ms: u64,
    staged: &BTreeSet<BlobId>,
) -> Result<Vec<(BlobRec, u64)>, StateError> {
    let mut dead = dead_since(c)?;
    dead.retain(|(rec, since)| {
        now_ms.saturating_sub(*since) >= GC_GRACE_MS && !staged.contains(&rec.id)
    });
    Ok(dead)
}

impl<B: Backend> Vault<B> {
    // --- queries (local replica only)

    /// Winner.
    pub fn head(&self, path: &str) -> Result<Option<Head>, IndexError> {
        let mut found = self
            .db
            .read(|c| heads_query(c, "path = ? AND winner = 1", &[text(path)]))?;
        Ok(found.pop())
    }

    /// Winner + losers (the winner first, then by falling stamp).
    pub fn heads(&self, path: &str) -> Result<Vec<Head>, IndexError> {
        Ok(self.db.read(|c| {
            heads_query(
                c,
                "path = ? ORDER BY st_l DESC, st_d DESC, st_i DESC, hash DESC",
                &[text(path)],
            )
        })?)
    }

    /// Winners at/under prefix, sorted by path (`""` = everything).
    pub fn walk(&self, prefix: &str) -> Result<Vec<Head>, IndexError> {
        Ok(self.db.read(|c| {
            if prefix.is_empty() {
                return heads_query(c, "winner = 1 ORDER BY path", &[]);
            }
            let (lo, hi) = subtree(prefix);
            heads_query(
                c,
                "winner = 1 AND (path = ?1 OR (path > ?2 AND path < ?3)) ORDER BY path",
                &[text(prefix), text(lo), text(hi)],
            )
        })?)
    }

    /// Direct children incl. implied dirs, sorted by name.
    pub fn list(&self, prefix: &str) -> Result<Vec<ListRow>, IndexError> {
        let (lo, hi) = if prefix.is_empty() {
            (String::new(), Value::Null)
        } else {
            let (lo, hi) = subtree(prefix);
            (lo, text(hi))
        };
        let mut rows: BTreeMap<String, ListRow> = BTreeMap::new();
        self.db.read(|c| {
            // One index seek per child: a directory's subtree is skipped, not scanned.
            let (mut cursor, mut inclusive) = (lo.clone(), false);
            loop {
                let cond = if inclusive {
                    "winner = 1 AND path >= ?1 AND (?2 IS NULL OR path < ?2) ORDER BY path LIMIT 1"
                } else {
                    "winner = 1 AND path > ?1 AND (?2 IS NULL OR path < ?2) ORDER BY path LIMIT 1"
                };
                let Some(head) = heads_query(c, cond, &[text(cursor.as_str()), hi.clone()])?.pop()
                else {
                    return Ok::<_, StateError>(());
                };
                let rel = &head.path[lo.len()..];
                let (name, direct) = match rel.split_once('/') {
                    Some((dir, _)) => (dir.to_owned(), false),
                    None => (rel.to_owned(), true),
                };
                let row = rows.entry(name.clone()).or_insert_with(|| ListRow {
                    name: name.clone(),
                    is_dir: false,
                    head: None,
                });
                if direct {
                    (cursor, inclusive) = (head.path.clone(), false);
                    row.is_dir |= head.entry.kind == EntryKind::Dir;
                    row.head = Some(head);
                } else {
                    (cursor, inclusive) = (format!("{lo}{name}0"), true);
                    row.is_dir = true;
                }
            }
        })?;
        Ok(rows.into_values().collect())
    }

    /// Dir head or any winner under `path/`. The vault root always exists.
    pub fn exists_dir(&self, path: &str) -> Result<bool, IndexError> {
        if path.is_empty() {
            return Ok(true);
        }
        let (lo, hi) = subtree(path);
        Ok(self.db.read(|c| {
            c.query_row(
                "SELECT EXISTS (SELECT 1 FROM heads WHERE winner = 1 \
                   AND ((path = ?1 AND kind = 1) OR (path > ?2 AND path < ?3)))",
                params![path, lo, hi],
                |r| r.get(0),
            )
            .map_err(StateError::from)
        })?)
    }

    pub fn blob(&self, id: &BlobId) -> Result<Option<BlobRec>, IndexError> {
        let mut found = self
            .db
            .read(|c| blobs_where(c, "WHERE id = ?", &[Value::Blob(id.0.to_vec())]))?;
        Ok(found.pop())
    }

    /// Every blob row, including the ones this device trashed and has not purged yet.
    pub fn blobs(&self) -> Result<Vec<BlobRec>, IndexError> {
        Ok(self.db.read(|c| blobs_where(c, "ORDER BY id", &[]))?)
    }

    /// `(record, dead since ms)` for every blob that no head references and that has been dead
    /// for at least `GC_GRACE` at `now_ms` (§5.9 step 1). Blobs already trashed are not listed,
    /// and neither are blobs that this device's unpublished ops (`pending`, `outbox`) name: a
    /// `restore` or `mv` whose segment is stuck is about to give them a head again.
    pub fn dead_blobs(&self, now_ms: u64) -> Result<Vec<(BlobRec, u64)>, IndexError> {
        let staged = self.staged_blob_ids()?;
        Ok(self.db.read(|c| dead_blobs(c, now_ms, &staged))?)
    }

    /// gc sets, restore/check clear.
    pub fn set_blob_trashed(&self, id: &BlobId, trashed_ms: Option<u64>) -> Result<(), IndexError> {
        let ms = trashed_ms.map(to_i).transpose()?;
        self.db.read(|c| {
            c.execute(
                "UPDATE blobs SET trashed_ms = ? WHERE id = ?",
                params![ms, &id.0[..]],
            )
            .map_err(StateError::from)
        })?;
        Ok(())
    }

    /// §5.9 step 3: `trashed_ms` set, unreferenced within `RESTORE_WINDOW` — and not named by
    /// an unpublished op of this device (`pending`, `outbox`).
    pub fn purge_candidates(&self, now_ms: u64) -> Result<Vec<BlobRec>, IndexError> {
        let cutoff = to_i(now_ms.saturating_sub(RESTORE_WINDOW_MS))?;
        let staged = self.staged_blob_ids()?;
        let mut found = self.db.read(|c| {
            blobs_where(
                c,
                "WHERE b.trashed_ms IS NOT NULL \
                   AND NOT EXISTS (SELECT 1 FROM heads h WHERE h.blob = b.id) \
                   AND NOT EXISTS (SELECT 1 FROM removed r WHERE r.blob = b.id AND r.removed_ms > ?) \
                 ORDER BY b.id",
                &[Value::Integer(cutoff)],
            )
        })?;
        found.retain(|rec| !staged.contains(&rec.id));
        Ok(found)
    }

    /// After a successful purge.
    pub fn forget_blob(&self, id: &BlobId) -> Result<(), IndexError> {
        self.db.read(|c| {
            c.execute("DELETE FROM blobs WHERE id = ?", params![&id.0[..]])
                .map_err(StateError::from)
        })?;
        Ok(())
    }

    /// Newest first.
    pub fn removed_versions(&self, path: &str) -> Result<Vec<RemovedVersion>, IndexError> {
        Ok(self.db.read(|c| {
            removed_all(
                c,
                "WHERE path = ? ORDER BY removed_ms DESC, st_l DESC, st_d DESC, st_i DESC, hash DESC",
                &[text(path)],
            )
        })?)
    }

    /// Removed versions strictly under `prefix/` (`""` = everywhere) that were removed at or
    /// after `since_ms`: by path, newest first within a path. For `restore` of a directory (§5.5.4).
    pub fn removed_under(
        &self,
        prefix: &str,
        since_ms: u64,
    ) -> Result<Vec<RemovedVersion>, IndexError> {
        const ORDER: &str =
            "ORDER BY path, removed_ms DESC, st_l DESC, st_d DESC, st_i DESC, hash DESC";
        let since = Value::Integer(to_i(since_ms)?);
        Ok(self.db.read(|c| {
            if prefix.is_empty() {
                return removed_all(c, &format!("WHERE removed_ms >= ?1 {ORDER}"), &[since]);
            }
            let (lo, hi) = subtree(prefix);
            removed_all(
                c,
                &format!("WHERE path > ?1 AND path < ?2 AND removed_ms >= ?3 {ORDER}"),
                &[text(lo), text(hi), since],
            )
        })?)
    }

    /// Non-winner heads.
    pub fn conflicts(&self) -> Result<Vec<Head>, IndexError> {
        Ok(self
            .db
            .read(|c| heads_query(c, super::resolve::LOSERS, &[]))?)
    }

    pub fn devices(&self) -> Result<Vec<DeviceInfo>, IndexError> {
        Ok(self.db.read(devices_all)?)
    }

    /// §2.6 head fingerprint: `"XXXX-XXXX"` = Crockford32(BLAKE3("gclone/v1/head" ‖ every `hw`
    /// row in device order: device ‖ seq u64 BE ‖ hash)[0..5]). Equal on replicas that applied
    /// the same journal; printed by `status` and at the end of `login`.
    pub fn head_fingerprint(&self) -> Result<String, IndexError> {
        let marks = self.db.read(tables::hw_all)?;
        let mut h = blake3::Hasher::new();
        h.update(b"gclone/v1/head");
        for mark in &marks {
            h.update(&mark.device.0);
            h.update(&mark.seq.to_be_bytes());
            h.update(&mark.hash);
        }
        let code = util::crockford_encode(&h.finalize().as_bytes()[..5]);
        Ok(format!("{}-{}", &code[..4], &code[4..]))
    }

    /// `dead_blob_bytes` counts what `gclone gc` would trash at `now_ms`.
    pub fn stats(&self, now_ms: u64) -> Result<VaultStats, IndexError> {
        let staged = self.staged_blob_ids()?;
        Ok(self.db.read(|c| {
            let mut s = VaultStats::default();
            {
                let mut stmt = c.prepare_cached(
                    "SELECT kind, count(*), coalesce(sum(size), 0) FROM heads \
                     WHERE winner = 1 GROUP BY kind",
                )?;
                let mut rows = stmt.query([])?;
                while let Some(r) = rows.next()? {
                    let n = to_u(r.get(1)?)?;
                    if r.get::<_, i64>(0)? == 0 {
                        (s.files, s.bytes) = (n, to_u(r.get(2)?)?);
                    } else {
                        s.dirs = n;
                    }
                }
            }
            let sums = |sql: &str| -> Result<(u64, u64), StateError> {
                let (n, bytes): (i64, i64) =
                    c.query_row(sql, [], |r| Ok((r.get(0)?, r.get(1)?)))?;
                Ok((to_u(n)?, to_u(bytes.max(0))?))
            };
            (s.blobs, s.blob_bytes) = sums(
                "SELECT count(*), coalesce(sum(clen), 0) FROM blobs WHERE trashed_ms IS NULL",
            )?;
            (_, s.trashed_blob_bytes) = sums(
                "SELECT count(*), coalesce(sum(clen), 0) FROM blobs WHERE trashed_ms IS NOT NULL",
            )?;
            // Bytes of live blobs that no head points into any more (dead pack members).
            (_, s.pack_dead_bytes) = sums(
                "SELECT count(*), coalesce(sum(b.clen - m.used), 0) FROM blobs b JOIN \
                   (SELECT blob, sum(clen) AS used FROM \
                      (SELECT DISTINCT blob, off, clen FROM heads WHERE blob IS NOT NULL) \
                    GROUP BY blob) m ON m.blob = b.id \
                 WHERE b.trashed_ms IS NULL",
            )?;
            s.dead_blob_bytes = dead_blobs(c, now_ms, &staged)?
                .iter()
                .map(|(b, _)| b.clen)
                .sum();
            s.segments = tables::applied_totals(c)?.0;
            s.snapshots = u64::from(tables::meta_get(c, "base_snapshot_name")?.is_some());
            s.conflicts = conflict_count(c)?;
            let last: Option<(String, i64)> = c
                .query_row(
                    "SELECT name, last_ms FROM devices ORDER BY last_ms DESC, id LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((name, ms)) = last {
                s.last_change_ms = Some(to_u(ms)?);
                s.last_change_by = Some(name);
            }
            Ok::<_, StateError>(s)
        })?)
    }

    /// Blob names referenced by pending/outbox (for `gc --orphans`).
    pub fn pending_blob_names(&self) -> Result<Vec<String>, IndexError> {
        Ok(self.staged_blob_ids()?.iter().map(blob_name).collect())
    }

    /// The blobs that this device's unpublished ops name: `Blob` records and the data location
    /// of `Put`s, in `pending` and in the sealed segment of the outbox. Garbage collection must
    /// treat them as referenced (§5.9).
    pub(super) fn staged_blob_ids(&self) -> Result<BTreeSet<BlobId>, IndexError> {
        let (pending, outbox) = self
            .db
            .read(|c| Ok::<_, StateError>((tables::pending_all(c)?, tables::outbox_get(c)?)))?;
        let mut ids: BTreeSet<BlobId> = BTreeSet::new();
        for (_, draft) in &pending {
            match draft {
                OpDraft::Blob(rec) => ids.extend([rec.id]),
                OpDraft::Put { entry, .. } => ids.extend(entry.loc.as_ref().map(|l| l.blob)),
                _ => {}
            }
        }
        if let Some(row) = outbox {
            let (seg, _) = open_segment(&self.keys, &row.name, &row.bytes)?;
            for op in &seg.ops {
                match op {
                    Op::Blob(rec) => ids.extend([rec.id]),
                    Op::Put { entry, .. } => ids.extend(entry.loc.as_ref().map(|l| l.blob)),
                    _ => {}
                }
            }
        }
        Ok(ids)
    }
}

//! `impl HeadStore for` a SQLite transaction wrapper + CRUD for `meta`, `applied`, `hw`, `own`,
//! `base_covers`, `base_covered`, `blocked`, `pending`, `outbox` and `base` (SPEC §8.4, §9.7) —
//! owned by WP4. `pub(crate)`: used by `index` only.
//!
//! Every function takes the connection (or the open transaction, which derefs to one), so
//! callers compose them inside [`super::Db::txn`].

use std::collections::BTreeMap;

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, Row, params, params_from_iter};

use crate::error::StateError;
use crate::index::apply::{HeadStore, rank};
use crate::types::{
    BaseEffect, BaseRow, BlobId, BlobRec, CoveredSeg, DeviceId, Entry, EntryKind, Head, Loc,
    OpDraft, SegRef, Stamp, StatSig,
};

// ---------------------------------------------------------------------------------------------
// value conversions (§8.4 "Integer binding")
// ---------------------------------------------------------------------------------------------

/// Sequence numbers, lamports, sizes and timestamps are below 2^63 by construction.
pub(crate) fn to_i(v: u64) -> Result<i64, StateError> {
    i64::try_from(v)
        .map_err(|_| StateError::Corrupt(format!("the value {v} does not fit the state database")))
}

pub(crate) fn to_u(v: i64) -> Result<u64, StateError> {
    u64::try_from(v).map_err(|_| {
        StateError::Corrupt(format!(
            "the state database holds {v} where a count belongs"
        ))
    })
}

pub(crate) fn arr<const N: usize>(v: Vec<u8>) -> Result<[u8; N], StateError> {
    let len = v.len();
    v.try_into().map_err(|_| {
        StateError::Corrupt(format!(
            "the state database holds {len} bytes where {N} belong"
        ))
    })
}

fn narrow<T: TryFrom<i64>>(v: i64) -> Result<T, StateError> {
    T::try_from(v)
        .map_err(|_| StateError::Corrupt(format!("the state database holds {v} out of range")))
}

fn stamp_at(r: &Row<'_>, i: usize) -> Result<Stamp, StateError> {
    Ok(Stamp {
        lamport: to_u(r.get(i)?)?,
        device: DeviceId(arr(r.get(i + 1)?)?),
        idx: narrow(r.get(i + 2)?)?,
    })
}

fn stamp_values(s: &Stamp) -> Result<[Value; 3], StateError> {
    Ok([
        Value::Integer(to_i(s.lamport)?),
        Value::Blob(s.device.0.to_vec()),
        Value::Integer(i64::from(s.idx)),
    ])
}

// ---------------------------------------------------------------------------------------------
// versions: the columns shared by `heads` and `removed`
// ---------------------------------------------------------------------------------------------

/// The 20 version columns, in the order [`version_at`] and [`version_values`] use.
pub(crate) const VERSION_COLS: &str = "path, st_l, st_d, st_i, kind, size, mtime_ns, exec, hash, \
     blob, off, clen, salt, chunk_log2, epoch, suite, flags, o_l, o_d, o_i";
const VERSION_MARKS: &str = "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?";

pub(crate) struct Version {
    pub path: String,
    pub stamp: Stamp,
    pub entry: Entry,
    pub origin: Option<Stamp>,
}

/// Decodes the columns of [`VERSION_COLS`] starting at column 0.
pub(crate) fn version_at(r: &Row<'_>) -> Result<Version, StateError> {
    let kind = match r.get::<_, i64>(4)? {
        0 => EntryKind::File,
        1 => EntryKind::Dir,
        n => {
            return Err(StateError::Corrupt(format!(
                "unknown entry kind {n} in the state database"
            )));
        }
    };
    let loc = match r.get::<_, Option<Vec<u8>>>(9)? {
        None => None,
        Some(blob) => Some(Loc {
            blob: BlobId(arr(blob)?),
            off: to_u(r.get(10)?)?,
            clen: to_u(r.get(11)?)?,
            salt: arr(r.get(12)?)?,
            chunk_log2: narrow(r.get(13)?)?,
            epoch: narrow(r.get(14)?)?,
            suite: narrow(r.get(15)?)?,
            flags: narrow(r.get(16)?)?,
        }),
    };
    let origin = match r.get::<_, Option<i64>>(17)? {
        None => None,
        Some(_) => Some(stamp_at(r, 17)?),
    };
    Ok(Version {
        path: r.get(0)?,
        stamp: stamp_at(r, 1)?,
        entry: Entry {
            kind,
            size: to_u(r.get(5)?)?,
            mtime_ns: r.get(6)?,
            exec: r.get::<_, i64>(7)? != 0,
            hash: arr(r.get(8)?)?,
            loc,
        },
        origin,
    })
}

fn version_values(
    path: &str,
    stamp: &Stamp,
    entry: &Entry,
    origin: Option<&Stamp>,
) -> Result<Vec<Value>, StateError> {
    let mut v = Vec::with_capacity(24);
    v.push(Value::Text(path.to_owned()));
    v.extend(stamp_values(stamp)?);
    v.push(Value::Integer(match entry.kind {
        EntryKind::File => 0,
        EntryKind::Dir => 1,
    }));
    v.push(Value::Integer(to_i(entry.size)?));
    v.push(Value::Integer(entry.mtime_ns));
    v.push(Value::Integer(i64::from(entry.exec)));
    v.push(Value::Blob(entry.hash.to_vec()));
    match &entry.loc {
        Some(loc) => v.extend([
            Value::Blob(loc.blob.0.to_vec()),
            Value::Integer(to_i(loc.off)?),
            Value::Integer(to_i(loc.clen)?),
            Value::Blob(loc.salt.to_vec()),
            Value::Integer(i64::from(loc.chunk_log2)),
            Value::Integer(i64::from(loc.epoch)),
            Value::Integer(i64::from(loc.suite)),
            Value::Integer(i64::from(loc.flags)),
        ]),
        None => v.extend(std::iter::repeat_n(Value::Null, 8)),
    }
    match origin {
        Some(o) => v.extend(stamp_values(o)?),
        None => v.extend(std::iter::repeat_n(Value::Null, 3)),
    }
    Ok(v)
}

pub(crate) fn head_insert(
    c: &Connection,
    path: &str,
    stamp: &Stamp,
    entry: &Entry,
    origin: Option<&Stamp>,
    winner: bool,
) -> Result<(), StateError> {
    let mut values = version_values(path, stamp, entry, origin)?;
    values.push(Value::Integer(i64::from(winner)));
    c.prepare_cached(&format!(
        "INSERT OR REPLACE INTO heads ({VERSION_COLS}, winner) VALUES ({VERSION_MARKS},?)"
    ))?
    .execute(params_from_iter(values))?;
    Ok(())
}

pub(crate) fn removed_insert(
    c: &Connection,
    v: &Version,
    removed_ms: u64,
    by: &Stamp,
) -> Result<(), StateError> {
    let mut values = version_values(&v.path, &v.stamp, &v.entry, v.origin.as_ref())?;
    values.push(Value::Integer(to_i(removed_ms)?));
    values.extend(stamp_values(by)?);
    c.prepare_cached(&format!(
        "INSERT OR REPLACE INTO removed ({VERSION_COLS}, removed_ms, by_l, by_d, by_i) \
         VALUES ({VERSION_MARKS},?,?,?,?)"
    ))?
    .execute(params_from_iter(values))?;
    Ok(())
}

/// `(version, removed_ms, by)` of the `removed` row with this exact key.
fn removed_get(
    c: &Connection,
    path: &str,
    stamp: &Stamp,
    hash: &[u8; 32],
) -> Result<Option<(Version, u64, Stamp)>, StateError> {
    let mut stmt = c.prepare_cached(&format!(
        "SELECT {VERSION_COLS}, removed_ms, by_l, by_d, by_i FROM removed \
         WHERE path = ? AND st_l = ? AND st_d = ? AND st_i = ? AND hash = ?"
    ))?;
    let [l, d, i] = stamp_values(stamp)?;
    let mut rows = stmt.query(params![path, l, d, i, &hash[..]])?;
    match rows.next()? {
        None => Ok(None),
        Some(r) => Ok(Some((version_at(r)?, to_u(r.get(20)?)?, stamp_at(r, 21)?))),
    }
}

fn heads_where(c: &Connection, cond: &str, args: &[Value]) -> Result<Vec<Head>, StateError> {
    let mut stmt = c.prepare_cached(&format!(
        "SELECT {VERSION_COLS}, winner FROM heads WHERE {cond}"
    ))?;
    let mut rows = stmt.query(params_from_iter(args.iter()))?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let v = version_at(r)?;
        out.push(Head {
            path: v.path,
            stamp: v.stamp,
            entry: v.entry,
            origin: v.origin,
            winner: r.get::<_, i64>(20)? != 0,
        });
    }
    Ok(out)
}

/// Heads matching `cond` (a WHERE clause over `heads`, with its ORDER BY).
pub(crate) fn heads_query(
    c: &Connection,
    cond: &str,
    args: &[Value],
) -> Result<Vec<Head>, StateError> {
    heads_where(c, cond, args)
}

/// The max-stamp head of `path` (ties: greatest `entry.hash`) gets `winner = 1`.
fn recompute_winner(c: &Connection, path: &str) -> Result<(), StateError> {
    c.prepare_cached("UPDATE heads SET winner = 0 WHERE path = ?1 AND winner = 1")?
        .execute(params![path])?;
    c.prepare_cached(
        "UPDATE heads SET winner = 1 WHERE path = ?1 AND (st_l, st_d, st_i, hash) = \
         (SELECT st_l, st_d, st_i, hash FROM heads WHERE path = ?1 \
          ORDER BY st_l DESC, st_d DESC, st_i DESC, hash DESC LIMIT 1)",
    )?
    .execute(params![path])?;
    Ok(())
}

/// The production [`HeadStore`]: the tables `heads`, `removed`, `blobs`, `devices` and the
/// vault keys of `meta`, written through an open transaction.
pub(crate) struct SqlStore<'c>(pub &'c Connection);

impl HeadStore for SqlStore<'_> {
    fn heads(&self, path: &str) -> Result<Vec<Head>, StateError> {
        heads_where(
            self.0,
            "path = ? ORDER BY st_l, st_d, st_i, hash",
            &[Value::Text(path.to_owned())],
        )
    }

    fn supersede(
        &mut self,
        path: &str,
        stamp: &Stamp,
        removed_ms: u64,
        by: Stamp,
    ) -> Result<usize, StateError> {
        let c = self.0;
        let [l, d, i] = stamp_values(stamp)?;
        let [bl, bd, bi] = stamp_values(&by)?;
        let ms = to_i(removed_ms)?;
        // The smallest superseding (by, removed_ms) is recorded, whatever the application order.
        c.prepare_cached(
            "UPDATE removed SET removed_ms = ?5, by_l = ?6, by_d = ?7, by_i = ?8 \
             WHERE path = ?1 AND st_l = ?2 AND st_d = ?3 AND st_i = ?4 \
               AND (by_l, by_d, by_i, removed_ms) > (?6, ?7, ?8, ?5)",
        )?
        .execute(params![path, l, d, i, ms, bl, bd, bi])?;

        let moved = {
            let mut stmt = c.prepare_cached(&format!(
                "SELECT {VERSION_COLS} FROM heads \
                 WHERE path = ? AND st_l = ? AND st_d = ? AND st_i = ?"
            ))?;
            let mut rows = stmt.query(params![path, l, d, i])?;
            let mut moved = Vec::new();
            while let Some(r) = rows.next()? {
                moved.push(version_at(r)?);
            }
            moved
        };
        let count = moved.len();
        for mut v in moved {
            let (mut at, mut who) = (removed_ms, by);
            if let Some((old, old_ms, old_by)) = removed_get(c, path, stamp, &v.entry.hash)? {
                if (old_by, old_ms) < (who, at) {
                    (at, who) = (old_ms, old_by);
                }
                if rank(&old.entry, None) < rank(&v.entry, None) {
                    v.entry = old.entry;
                    v.origin = old.origin;
                }
            }
            removed_insert(c, &v, at, &who)?;
        }
        if count > 0 {
            c.prepare_cached(
                "DELETE FROM heads WHERE path = ? AND st_l = ? AND st_d = ? AND st_i = ?",
            )?
            .execute(params![path, l, d, i])?;
            recompute_winner(c, path)?;
            // Another head of the path may have become its winner.
            touched_add(c, path)?;
        }
        Ok(count)
    }

    fn insert_head(
        &mut self,
        path: &str,
        stamp: Stamp,
        entry: &Entry,
        origin: Option<Stamp>,
    ) -> Result<(), StateError> {
        let c = self.0;
        let [l, d, i] = stamp_values(&stamp)?;
        let twin = heads_where(
            c,
            "path = ? AND st_l = ? AND st_d = ? AND st_i = ? AND hash = ?",
            &[
                Value::Text(path.to_owned()),
                l,
                d,
                i,
                Value::Blob(entry.hash.to_vec()),
            ],
        )?;
        if let Some(old) = twin.first()
            && rank(&old.entry, old.origin.as_ref()) <= rank(entry, origin.as_ref())
        {
            return Ok(());
        }
        head_insert(c, path, &stamp, entry, origin.as_ref(), false)?;
        recompute_winner(c, path)?;
        touched_add(c, path)
    }

    fn upsert_blob(&mut self, rec: &BlobRec) -> Result<(), StateError> {
        blob_upsert(self.0, rec)
    }

    fn upsert_device(&mut self, id: DeviceId, name: &str, seen_ms: u64) -> Result<(), StateError> {
        device_upsert(self.0, id, name, seen_ms, seen_ms)
    }

    fn set_vault(&mut self, format: u16, name: &str) -> Result<(), StateError> {
        meta_set_u64(self.0, "vault_format", u64::from(format))?;
        meta_set(self.0, "vault_name", name.as_bytes())
    }
}

/// Keeps `trashed_ms` (a local mark, §5.9).
pub(crate) fn blob_upsert(c: &Connection, rec: &BlobRec) -> Result<(), StateError> {
    c.prepare_cached(
        "INSERT INTO blobs (id, file_id, clen, md5, created_ms) VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(id) DO UPDATE SET file_id = ?2, clen = ?3, md5 = ?4, created_ms = ?5",
    )?
    .execute(params![
        &rec.id.0[..],
        rec.file_id,
        to_i(rec.clen)?,
        &rec.md5[..],
        to_i(rec.created_ms)?
    ])?;
    Ok(())
}

pub(crate) fn blob_at(r: &Row<'_>, i: usize) -> Result<BlobRec, StateError> {
    Ok(BlobRec {
        id: BlobId(arr(r.get(i)?)?),
        file_id: r.get(i + 1)?,
        clen: to_u(r.get(i + 2)?)?,
        md5: arr(r.get(i + 3)?)?,
        created_ms: to_u(r.get(i + 4)?)?,
    })
}

/// The name of the latest op wins; `first_ms` only ever falls, `last_ms` only ever rises.
pub(crate) fn device_upsert(
    c: &Connection,
    id: DeviceId,
    name: &str,
    first_ms: u64,
    last_ms: u64,
) -> Result<(), StateError> {
    c.prepare_cached(
        "INSERT INTO devices (id, name, first_ms, last_ms) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(id) DO UPDATE SET name = ?2, first_ms = min(first_ms, ?3), \
                                       last_ms = max(last_ms, ?4)",
    )?
    .execute(params![&id.0[..], name, to_i(first_ms)?, to_i(last_ms)?])?;
    Ok(())
}

/// A segment written by `id` was applied: the device was alive at `ms`.
pub(crate) fn device_seen(c: &Connection, id: DeviceId, ms: u64) -> Result<(), StateError> {
    c.prepare_cached("UPDATE devices SET last_ms = max(last_ms, ?2) WHERE id = ?1")?
        .execute(params![&id.0[..], to_i(ms)?])?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// touched: what resolution rule 2 has to look at (§5.2.3)
// ---------------------------------------------------------------------------------------------

/// More touched paths than this are not tracked one by one: the next resolution scans every
/// head once instead (`meta.resolve_all`).
pub(crate) const TOUCHED_MAX: u64 = 16_384;

/// Remembers that the heads of `path` changed. Nothing is recorded while `resolve_all` is set:
/// the full scan it stands for covers every path.
fn touched_add(c: &Connection, path: &str) -> Result<(), StateError> {
    c.prepare_cached(
        "INSERT OR IGNORE INTO touched (path) \
         SELECT ?1 WHERE NOT EXISTS (SELECT 1 FROM meta WHERE k = 'resolve_all')",
    )?
    .execute(params![path])?;
    Ok(())
}

/// The next resolution must look at every head: the replica's content was replaced.
pub(crate) fn resolve_all_set(c: &Connection) -> Result<(), StateError> {
    meta_set(c, "resolve_all", &[1])?;
    c.execute("DELETE FROM touched", [])?;
    Ok(())
}

/// Bounds the `touched` table (a first sync of a large tree touches every path).
pub(crate) fn touched_bound(c: &Connection) -> Result<(), StateError> {
    let over: bool = c
        .prepare_cached("SELECT EXISTS (SELECT 1 FROM touched LIMIT 1 OFFSET ?)")?
        .query_row(params![to_i(TOUCHED_MAX)?], |r| r.get(0))?;
    if over {
        resolve_all_set(c)?;
    }
    Ok(())
}

/// `None`: every head has to be looked at. Otherwise the touched paths, sorted.
pub(crate) fn touched_paths(c: &Connection) -> Result<Option<Vec<String>>, StateError> {
    if meta_get(c, "resolve_all")?.is_some() {
        return Ok(None);
    }
    let mut stmt = c.prepare_cached("SELECT path FROM touched ORDER BY path")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(r.get(0)?);
    }
    Ok(Some(out))
}

/// Whether a resolution has anything to look at for rule 2.
pub(crate) fn touched_any(c: &Connection) -> Result<bool, StateError> {
    Ok(c.prepare_cached(
        "SELECT EXISTS (SELECT 1 FROM touched) \
             OR EXISTS (SELECT 1 FROM meta WHERE k = 'resolve_all')",
    )?
    .query_row([], |r| r.get(0))?)
}

/// A resolution looked at everything recorded so far and found nothing left to do.
pub(crate) fn touched_clear(c: &Connection) -> Result<(), StateError> {
    c.execute("DELETE FROM touched", [])?;
    meta_del(c, "resolve_all")
}

// ---------------------------------------------------------------------------------------------
// meta
// ---------------------------------------------------------------------------------------------

pub(crate) fn meta_get(c: &Connection, k: &str) -> Result<Option<Vec<u8>>, StateError> {
    Ok(c.prepare_cached("SELECT v FROM meta WHERE k = ?")?
        .query_row(params![k], |r| r.get(0))
        .optional()?)
}

pub(crate) fn meta_set(c: &Connection, k: &str, v: &[u8]) -> Result<(), StateError> {
    c.prepare_cached(
        "INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = ?2",
    )?
    .execute(params![k, v])?;
    Ok(())
}

pub(crate) fn meta_del(c: &Connection, k: &str) -> Result<(), StateError> {
    c.prepare_cached("DELETE FROM meta WHERE k = ?")?
        .execute(params![k])?;
    Ok(())
}

pub(crate) fn meta_u64(c: &Connection, k: &str) -> Result<Option<u64>, StateError> {
    match meta_get(c, k)? {
        None => Ok(None),
        Some(v) => Ok(Some(u64::from_be_bytes(arr(v)?))),
    }
}

pub(crate) fn meta_set_u64(c: &Connection, k: &str, v: u64) -> Result<(), StateError> {
    meta_set(c, k, &v.to_be_bytes())
}

pub(crate) fn meta_str(c: &Connection, k: &str) -> Result<Option<String>, StateError> {
    match meta_get(c, k)? {
        None => Ok(None),
        Some(v) => String::from_utf8(v)
            .map(Some)
            .map_err(|_| StateError::Corrupt(format!("meta value {k} is not text"))),
    }
}

pub(crate) fn meta_set_str(c: &Connection, k: &str, v: &str) -> Result<(), StateError> {
    meta_set(c, k, v.as_bytes())
}

// ---------------------------------------------------------------------------------------------
// applied, base_covered, base_covers, hw, own
// ---------------------------------------------------------------------------------------------

/// One segment applied since the base snapshot (§5.3).
#[derive(Clone, Debug)]
pub(crate) struct AppliedRow {
    pub dev: DeviceId,
    pub seq: u64,
    pub hash: [u8; 32],
    pub file_id: String,
    pub name: String,
    pub lamport: u64,
    pub created_ms: u64,
    pub size: u64,
}

impl AppliedRow {
    pub(crate) fn seg_ref(&self) -> SegRef {
        SegRef {
            device: self.dev,
            seq: self.seq,
            hash: self.hash,
            file_id: self.file_id.clone(),
        }
    }
}

pub(crate) fn applied_all(c: &Connection) -> Result<Vec<AppliedRow>, StateError> {
    let mut stmt = c.prepare_cached(
        "SELECT dev, seq, hash, file_id, name, lamport, created_ms, size FROM applied \
         ORDER BY dev, seq, hash",
    )?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(AppliedRow {
            dev: DeviceId(arr(r.get(0)?)?),
            seq: to_u(r.get(1)?)?,
            hash: arr(r.get(2)?)?,
            file_id: r.get(3)?,
            name: r.get(4)?,
            lamport: to_u(r.get(5)?)?,
            created_ms: to_u(r.get(6)?)?,
            size: to_u(r.get(7)?)?,
        });
    }
    Ok(out)
}

pub(crate) fn applied_insert(c: &Connection, a: &AppliedRow) -> Result<(), StateError> {
    c.prepare_cached(
        "INSERT OR REPLACE INTO applied (dev, seq, hash, file_id, name, lamport, created_ms, size) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )?
    .execute(params![
        &a.dev.0[..],
        to_i(a.seq)?,
        &a.hash[..],
        a.file_id,
        a.name,
        to_i(a.lamport)?,
        to_i(a.created_ms)?,
        to_i(a.size)?
    ])?;
    Ok(())
}

pub(crate) fn applied_delete(
    c: &Connection,
    dev: DeviceId,
    seq: u64,
    hash: &[u8; 32],
) -> Result<(), StateError> {
    c.prepare_cached("DELETE FROM applied WHERE dev = ? AND seq = ? AND hash = ?")?
        .execute(params![&dev.0[..], to_i(seq)?, &hash[..]])?;
    Ok(())
}

pub(crate) fn applied_set_file_id(
    c: &Connection,
    dev: DeviceId,
    seq: u64,
    hash: &[u8; 32],
    file_id: &str,
) -> Result<(), StateError> {
    for table in ["applied", "hw", "base_covers"] {
        c.execute(
            &format!("UPDATE {table} SET file_id = ?4 WHERE dev = ?1 AND seq = ?2 AND hash = ?3"),
            params![&dev.0[..], to_i(seq)?, &hash[..], file_id],
        )?;
    }
    Ok(())
}

/// §5.3: an identity is known iff it is in `applied` or its `(dev, seq, h4)` is in `base_covered`.
pub(crate) fn is_known(
    c: &Connection,
    dev: DeviceId,
    seq: u64,
    hash: &[u8; 32],
) -> Result<bool, StateError> {
    Ok(c.prepare_cached(
        "SELECT EXISTS (SELECT 1 FROM applied WHERE dev = ?1 AND seq = ?2 AND hash = ?3) \
             OR EXISTS (SELECT 1 FROM base_covered WHERE dev = ?1 AND seq = ?2 AND h4 = ?4)",
    )?
    .query_row(
        params![&dev.0[..], to_i(seq)?, &hash[..], &hash[..4]],
        |r| r.get(0),
    )?)
}

/// Whether `(dev, seq)` is already known under ANOTHER hash: a fork (§5.2.2).
pub(crate) fn is_fork(
    c: &Connection,
    dev: DeviceId,
    seq: u64,
    hash: &[u8; 32],
) -> Result<bool, StateError> {
    Ok(c.prepare_cached(
        "SELECT EXISTS (SELECT 1 FROM applied WHERE dev = ?1 AND seq = ?2 AND hash <> ?3) \
             OR EXISTS (SELECT 1 FROM base_covered WHERE dev = ?1 AND seq = ?2 AND h4 <> ?4)",
    )?
    .query_row(
        params![&dev.0[..], to_i(seq)?, &hash[..], &hash[..4]],
        |r| r.get(0),
    )?)
}

/// `(number of applied segments, their total size)`.
pub(crate) fn applied_totals(c: &Connection) -> Result<(u64, u64), StateError> {
    let (n, bytes): (i64, i64) = c.query_row(
        "SELECT count(*), coalesce(sum(size), 0) FROM applied",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok((to_u(n)?, to_u(bytes)?))
}

pub(crate) fn base_covered_all(c: &Connection) -> Result<Vec<CoveredSeg>, StateError> {
    let mut stmt =
        c.prepare_cached("SELECT dev, seq, h4 FROM base_covered ORDER BY dev, seq, h4")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(CoveredSeg {
            device: DeviceId(arr(r.get(0)?)?),
            seq: to_u(r.get(1)?)?,
            h4: arr(r.get(2)?)?,
        });
    }
    Ok(out)
}

pub(crate) fn base_covered_replace(c: &Connection, set: &[CoveredSeg]) -> Result<(), StateError> {
    c.execute("DELETE FROM base_covered", [])?;
    let mut stmt =
        c.prepare_cached("INSERT OR IGNORE INTO base_covered (dev, seq, h4) VALUES (?, ?, ?)")?;
    for s in set {
        stmt.execute(params![&s.device.0[..], to_i(s.seq)?, &s.h4[..]])?;
    }
    Ok(())
}

fn seg_refs(c: &Connection, table: &str) -> Result<Vec<SegRef>, StateError> {
    let mut stmt = c.prepare_cached(&format!(
        "SELECT dev, seq, hash, file_id FROM {table} ORDER BY dev"
    ))?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(SegRef {
            device: DeviceId(arr(r.get(0)?)?),
            seq: to_u(r.get(1)?)?,
            hash: arr(r.get(2)?)?,
            file_id: r.get(3)?,
        });
    }
    Ok(out)
}

fn seg_refs_replace(c: &Connection, table: &str, refs: &[SegRef]) -> Result<(), StateError> {
    c.execute(&format!("DELETE FROM {table}"), [])?;
    let mut stmt = c.prepare_cached(&format!(
        "INSERT OR REPLACE INTO {table} (dev, seq, hash, file_id) VALUES (?, ?, ?, ?)"
    ))?;
    for r in refs {
        stmt.execute(params![
            &r.device.0[..],
            to_i(r.seq)?,
            &r.hash[..],
            r.file_id
        ])?;
    }
    Ok(())
}

/// The tips of the base snapshot, sorted by device.
pub(crate) fn base_covers_all(c: &Connection) -> Result<Vec<SegRef>, StateError> {
    seg_refs(c, "base_covers")
}

pub(crate) fn base_covers_replace(c: &Connection, tips: &[SegRef]) -> Result<(), StateError> {
    seg_refs_replace(c, "base_covers", tips)
}

/// The rollback marks, sorted by device.
pub(crate) fn hw_all(c: &Connection) -> Result<Vec<SegRef>, StateError> {
    seg_refs(c, "hw")
}

pub(crate) fn hw_replace(c: &Connection, marks: &[SegRef]) -> Result<(), StateError> {
    seg_refs_replace(c, "hw", marks)
}

/// Raises the mark of `r.device` to `r` if `(seq, hash)` is greater than the recorded one.
pub(crate) fn hw_raise(c: &Connection, r: &SegRef) -> Result<(), StateError> {
    c.prepare_cached(
        "INSERT INTO hw (dev, seq, hash, file_id) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(dev) DO UPDATE SET seq = ?2, hash = ?3, file_id = ?4 \
         WHERE (seq, hash) < (?2, ?3)",
    )?
    .execute(params![
        &r.device.0[..],
        to_i(r.seq)?,
        &r.hash[..],
        r.file_id
    ])?;
    Ok(())
}

/// `(seq, hash, file_id)` of every segment sealed under the current device id, ascending.
pub(crate) fn own_all(c: &Connection) -> Result<Vec<(u64, [u8; 32], String)>, StateError> {
    let mut stmt = c.prepare_cached("SELECT seq, hash, file_id FROM own ORDER BY seq")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push((to_u(r.get(0)?)?, arr(r.get(1)?)?, r.get(2)?));
    }
    Ok(out)
}

pub(crate) fn own_last(c: &Connection) -> Result<Option<(u64, [u8; 32], String)>, StateError> {
    let mut stmt =
        c.prepare_cached("SELECT seq, hash, file_id FROM own ORDER BY seq DESC LIMIT 1")?;
    let mut rows = stmt.query([])?;
    match rows.next()? {
        None => Ok(None),
        Some(r) => Ok(Some((to_u(r.get(0)?)?, arr(r.get(1)?)?, r.get(2)?))),
    }
}

pub(crate) fn own_insert(
    c: &Connection,
    seq: u64,
    hash: &[u8; 32],
    file_id: &str,
) -> Result<(), StateError> {
    c.prepare_cached("INSERT OR REPLACE INTO own (seq, hash, file_id) VALUES (?, ?, ?)")?
        .execute(params![to_i(seq)?, &hash[..], file_id])?;
    Ok(())
}

pub(crate) fn own_set_file_id(
    c: &Connection,
    seq: u64,
    hash: &[u8; 32],
    file_id: &str,
) -> Result<(), StateError> {
    c.execute(
        "UPDATE own SET file_id = ?3 WHERE seq = ?1 AND hash = ?2",
        params![to_i(seq)?, &hash[..], file_id],
    )?;
    Ok(())
}

/// A sealed segment that was withdrawn before it was published (§5.8).
pub(crate) fn own_delete(c: &Connection, seq: u64, hash: &[u8; 32]) -> Result<(), StateError> {
    c.execute(
        "DELETE FROM own WHERE seq = ?1 AND hash = ?2",
        params![to_i(seq)?, &hash[..]],
    )?;
    Ok(())
}

pub(crate) fn own_clear(c: &Connection) -> Result<(), StateError> {
    c.execute("DELETE FROM own", [])?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// blocked, pending, outbox
// ---------------------------------------------------------------------------------------------

pub(crate) fn blocked_all(c: &Connection) -> Result<BTreeMap<String, u64>, StateError> {
    let mut stmt = c.prepare_cached("SELECT name, first_seen_ms FROM blocked")?;
    let mut rows = stmt.query([])?;
    let mut out = BTreeMap::new();
    while let Some(r) = rows.next()? {
        out.insert(r.get(0)?, to_u(r.get(1)?)?);
    }
    Ok(out)
}

pub(crate) fn blocked_replace(
    c: &Connection,
    rows: &BTreeMap<String, u64>,
) -> Result<(), StateError> {
    c.execute("DELETE FROM blocked", [])?;
    let mut stmt = c.prepare_cached("INSERT INTO blocked (name, first_seen_ms) VALUES (?, ?)")?;
    for (name, first_seen_ms) in rows {
        stmt.execute(params![name, to_i(*first_seen_ms)?])?;
    }
    Ok(())
}

pub(crate) fn pending_insert(
    c: &Connection,
    draft: &OpDraft,
    created_ms: u64,
) -> Result<(), StateError> {
    let bytes = postcard::to_stdvec(draft)
        .map_err(|e| StateError::Corrupt(format!("cannot encode a staged op: {e}")))?;
    c.prepare_cached("INSERT INTO pending (draft, created_ms, pid) VALUES (?, ?, ?)")?
        .execute(params![
            bytes,
            to_i(created_ms)?,
            i64::from(std::process::id())
        ])?;
    Ok(())
}

/// `(id, draft)` in id order.
pub(crate) fn pending_all(c: &Connection) -> Result<Vec<(i64, OpDraft)>, StateError> {
    let mut stmt = c.prepare_cached("SELECT id, draft FROM pending ORDER BY id")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let bytes: Vec<u8> = r.get(1)?;
        let draft = postcard::from_bytes(&bytes)
            .map_err(|e| StateError::Corrupt(format!("cannot decode a staged op: {e}")))?;
        out.push((r.get(0)?, draft));
    }
    Ok(out)
}

pub(crate) fn pending_delete(c: &Connection, ids: &[i64]) -> Result<(), StateError> {
    let mut stmt = c.prepare_cached("DELETE FROM pending WHERE id = ?")?;
    for id in ids {
        stmt.execute(params![id])?;
    }
    Ok(())
}

/// The greatest id ever handed out (0 if none): rows at or below it were staged earlier.
pub(crate) fn pending_max_id(c: &Connection) -> Result<i64, StateError> {
    Ok(c.query_row("SELECT coalesce(max(id), 0) FROM pending", [], |r| r.get(0))?)
}

pub(crate) fn pending_count(c: &Connection) -> Result<u64, StateError> {
    to_u(c.query_row(
        "SELECT (SELECT count(*) FROM pending) + (SELECT count(*) FROM outbox)",
        [],
        |r| r.get(0),
    )?)
}

/// The sealed segment that waits for its publication, with the base effects of its ops
/// (index = op index).
pub(crate) struct OutboxRow {
    pub seq: u64,
    pub name: String,
    pub file_id: String,
    pub bytes: Vec<u8>,
    pub effects: Vec<Option<BaseEffect>>,
}

pub(crate) fn outbox_get(c: &Connection) -> Result<Option<OutboxRow>, StateError> {
    let mut stmt = c.prepare_cached(
        "SELECT seq, name, file_id, bytes, effects FROM outbox ORDER BY seq LIMIT 1",
    )?;
    let mut rows = stmt.query([])?;
    let Some(r) = rows.next()? else {
        return Ok(None);
    };
    let effects: Vec<u8> = r.get(4)?;
    Ok(Some(OutboxRow {
        seq: to_u(r.get(0)?)?,
        name: r.get(1)?,
        file_id: r.get(2)?,
        bytes: r.get(3)?,
        effects: postcard::from_bytes(&effects)
            .map_err(|e| StateError::Corrupt(format!("cannot decode the outbox effects: {e}")))?,
    }))
}

pub(crate) fn outbox_exists(c: &Connection) -> Result<bool, StateError> {
    Ok(c.query_row("SELECT EXISTS (SELECT 1 FROM outbox)", [], |r| r.get(0))?)
}

pub(crate) fn outbox_put(c: &Connection, row: &OutboxRow) -> Result<(), StateError> {
    let effects = postcard::to_stdvec(&row.effects)
        .map_err(|e| StateError::Corrupt(format!("cannot encode the outbox effects: {e}")))?;
    c.execute(
        "INSERT INTO outbox (seq, name, file_id, bytes, effects) VALUES (?, ?, ?, ?, ?)",
        params![to_i(row.seq)?, row.name, row.file_id, row.bytes, effects],
    )?;
    Ok(())
}

pub(crate) fn outbox_set_file_id(c: &Connection, file_id: &str) -> Result<(), StateError> {
    c.execute("UPDATE outbox SET file_id = ?", params![file_id])?;
    Ok(())
}

pub(crate) fn outbox_clear(c: &Connection) -> Result<(), StateError> {
    c.execute("DELETE FROM outbox", [])?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// base (per-pair rows of the three-way planner, §5.5)
// ---------------------------------------------------------------------------------------------

pub(crate) fn base_upsert(c: &Connection, pair: i64, row: &BaseRow) -> Result<(), StateError> {
    let [l, d, i] = stamp_values(&row.remote_stamp)?;
    c.prepare_cached(
        "INSERT OR REPLACE INTO base (pair, key, rel, kind, size, mtime_ns, ctime_ns, ino, mode, \
                                      hash, st_l, st_d, st_i, observed_ns) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )?
    .execute(params![
        pair,
        row.key,
        row.rel,
        match row.kind {
            EntryKind::File => 0i64,
            EntryKind::Dir => 1,
        },
        to_i(row.sig.size)?,
        row.sig.mtime_ns,
        row.sig.ctime_ns,
        // inode numbers may exceed 2^63: stored bit-cast, never converted (§8.4)
        row.sig.ino as i64,
        i64::from(row.sig.mode),
        &row.hash[..],
        l,
        d,
        i,
        row.observed_ns
    ])?;
    Ok(())
}

pub(crate) fn base_delete(c: &Connection, pair: i64, key: &str) -> Result<(), StateError> {
    c.prepare_cached("DELETE FROM base WHERE pair = ? AND key = ?")?
        .execute(params![pair, key])?;
    Ok(())
}

pub(crate) fn base_all(c: &Connection, pair: i64) -> Result<Vec<BaseRow>, StateError> {
    let mut stmt = c.prepare_cached(
        "SELECT key, rel, kind, size, mtime_ns, ctime_ns, ino, mode, hash, st_l, st_d, st_i, \
                observed_ns FROM base WHERE pair = ? ORDER BY key",
    )?;
    let mut rows = stmt.query(params![pair])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(BaseRow {
            key: r.get(0)?,
            rel: r.get(1)?,
            kind: match r.get::<_, i64>(2)? {
                0 => EntryKind::File,
                _ => EntryKind::Dir,
            },
            sig: StatSig {
                size: to_u(r.get(3)?)?,
                mtime_ns: r.get(4)?,
                ctime_ns: r.get(5)?,
                ino: r.get::<_, i64>(6)? as u64,
                mode: narrow(r.get(7)?)?,
            },
            hash: arr(r.get(8)?)?,
            remote_stamp: stamp_at(r, 9)?,
            observed_ns: r.get(12)?,
        });
    }
    Ok(out)
}

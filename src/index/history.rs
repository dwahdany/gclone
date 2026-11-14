//! The replica as a source of history (SPEC §7.4, "Time machine"): the rows that
//! `web::past` asks for, read from `heads` and `removed` by primary-key ranges, and the few
//! statements the clock of the segments is built from. Private to `index`; everything here is
//! a SELECT inside a deferred read transaction, so a process without the state lock may run it.

use std::cell::OnceCell;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, Row, params};

use super::Vault;
use crate::backend::Backend;
use crate::error::{IndexError, StateError};
use crate::state::Db;
use crate::state::tables::{self, arr, heads_query, to_i, to_u};
use crate::types::{BlobRec, DeviceId, EntryKind, Head, Stamp};
use crate::web::past::{self, Group, History, PathVers, Resolved, Source, Ver};

/// Rows asked for after a seek, and the most that are read at once while the reader goes on
/// from where the last batch ended.
const BATCH_FIRST: usize = 2;
const BATCH_MAX: usize = 1024;

/// The bytes of a column that holds exactly `N` of them, read in place.
fn bytes_at<const N: usize>(r: &Row<'_>, at: usize) -> Result<[u8; N], StateError> {
    let corrupt = |what: String| StateError::Corrupt(what);
    let bytes = r
        .get_ref(at)?
        .as_blob()
        .map_err(|e| corrupt(e.to_string()))?;
    bytes.try_into().map_err(|_| {
        corrupt(format!(
            "the state database holds {} bytes where {N} belong",
            bytes.len()
        ))
    })
}

/// The version of a row of `heads` or `removed`, read with the columns of [`Side::columns`].
fn ver_at(r: &Row<'_>, removed: bool) -> Result<Ver, StateError> {
    let stamp = |at: usize| -> Result<Stamp, StateError> {
        Ok(Stamp {
            lamport: to_u(r.get(at)?)?,
            device: DeviceId(bytes_at(r, at + 1)?),
            idx: u32::try_from(r.get::<_, i64>(at + 2)?)
                .map_err(|_| StateError::Corrupt("op index out of range".into()))?,
        })
    };
    Ok(Ver {
        stamp: stamp(1)?,
        hash: bytes_at(r, 4)?,
        kind: match r.get::<_, i64>(5)? {
            0 => EntryKind::File,
            1 => EntryKind::Dir,
            n => {
                return Err(StateError::Corrupt(format!(
                    "unknown entry kind {n} in the state database"
                )));
            }
        },
        size: to_u(r.get(6)?)?,
        mtime_ns: r.get(7)?,
        end: match removed {
            true => Some((stamp(9)?, to_u(r.get(8)?)?)),
            false => None,
        },
    })
}

/// One of the two tables, read in path order in batches.
struct Side {
    removed: bool,
    rows: VecDeque<(String, Ver)>,
    /// `rows` holds every row of the paths from `.0` up to (not including) `.1`; `None`: to the
    /// end of the table.
    covered: Option<(String, Option<String>)>,
    size: usize,
}

impl Side {
    fn new(removed: bool) -> Side {
        Side {
            removed,
            rows: VecDeque::new(),
            covered: None,
            size: BATCH_FIRST,
        }
    }

    fn columns(&self) -> (&'static str, &'static str) {
        match self.removed {
            true => (
                "removed",
                "path, st_l, st_d, st_i, hash, kind, size, mtime_ns, removed_ms, by_l, by_d, by_i",
            ),
            false => (
                "heads",
                "path, st_l, st_d, st_i, hash, kind, size, mtime_ns",
            ),
        }
    }

    fn decode(&self, r: &Row<'_>) -> Result<(String, Ver), StateError> {
        Ok((r.get(0)?, ver_at(r, self.removed)?))
    }

    /// Reads the next batch: the rows of the paths from `start` on, below `hi`. `known`: the
    /// path from which on nothing lies before `start` — where what `rows` covers begins.
    fn fetch(
        &mut self,
        c: &Connection,
        known: &str,
        start: &str,
        hi: Option<&str>,
    ) -> Result<(), StateError> {
        const ORDER: &str = "ORDER BY path, st_l, st_d, st_i, hash";
        let (table, columns) = self.columns();
        let mut rows = Vec::with_capacity(self.size);
        {
            // Two statements, not one with an optional bound: only a plain `path < ?` ends
            // the walk of the primary key where the range ends.
            let limit = self.size as i64;
            let mut stmt = c.prepare_cached(&match hi {
                Some(_) => format!(
                    "SELECT {columns} FROM {table} WHERE path >= ?1 AND path < ?2 {ORDER} LIMIT ?3"
                ),
                None => format!("SELECT {columns} FROM {table} WHERE path >= ?1 {ORDER} LIMIT ?2"),
            })?;
            let mut found = match hi {
                Some(hi) => stmt.query(params![start, hi, limit])?,
                None => stmt.query(params![start, limit])?,
            };
            while let Some(r) = found.next()? {
                rows.push(self.decode(r)?);
            }
        }
        let end = if rows.len() < self.size {
            hi.map(str::to_owned)
        } else {
            // The batch may end inside a path: that path is left for the next batch — or, if
            // the batch holds nothing else, read whole.
            let last = rows[rows.len() - 1].0.clone();
            if rows[0].0 == last {
                let mut stmt = c.prepare_cached(&format!(
                    "SELECT {columns} FROM {table} WHERE path = ?1 {ORDER}"
                ))?;
                let mut found = stmt.query(params![last])?;
                rows.clear();
                while let Some(r) = found.next()? {
                    rows.push(self.decode(r)?);
                }
                Some(past::successor(&last))
            } else {
                rows.retain(|(path, _)| *path != last);
                Some(last)
            }
        };
        self.rows = rows.into();
        self.covered = Some((known.to_owned(), end));
        Ok(())
    }

    /// `rows` lost what lies before `start`: it covers what follows.
    fn covers_from(&mut self, start: String) {
        if let Some((from, _)) = &mut self.covered {
            *from = start;
        }
    }

    /// The first path in `[from, hi)` with a row in this table, and its rows.
    fn first(
        &mut self,
        c: &Connection,
        from: &str,
        hi: Option<&str>,
    ) -> Result<Option<PathVers>, StateError> {
        if hi.is_some_and(|hi| hi <= from) {
            return Ok(None);
        }
        loop {
            let inside = match &self.covered {
                Some((start, end)) => {
                    start.as_str() <= from && end.as_deref().is_none_or(|end| from < end)
                }
                None => false,
            };
            if inside {
                let mut passed = false;
                while self
                    .rows
                    .front()
                    .is_some_and(|(path, _)| path.as_str() < from)
                {
                    self.rows.pop_front();
                    passed = true;
                }
                if passed {
                    self.covers_from(from.to_owned());
                }
                match self.rows.front().map(|(path, _)| path.clone()) {
                    Some(path) if hi.is_some_and(|hi| path.as_str() >= hi) => return Ok(None),
                    Some(path) => {
                        let mut vers = Vec::new();
                        while self.rows.front().is_some_and(|(p, _)| *p == path) {
                            vers.extend(self.rows.pop_front().map(|(_, ver)| ver));
                        }
                        self.covers_from(past::successor(&path));
                        return Ok(Some((path, vers)));
                    }
                    None => {}
                }
            }
            // Nothing in what was read. Where it ended, the reader goes on through the table
            // with larger batches; anywhere else is a seek.
            let on = match &self.covered {
                Some((_, None)) if inside => return Ok(None),
                Some((_, Some(end))) if inside && hi.is_some_and(|hi| hi <= end.as_str()) => {
                    return Ok(None);
                }
                Some((_, Some(end))) if inside || end == from => Some(end.clone()),
                _ => None,
            };
            match on {
                Some(next) => {
                    self.size = (self.size * 4).min(BATCH_MAX);
                    self.fetch(c, from, &next, hi)?;
                }
                None => {
                    self.size = BATCH_FIRST;
                    self.fetch(c, from, from, hi)?;
                }
            }
        }
    }
}

/// The SQL replica as a [`Source`], over one connection inside a read snapshot.
pub struct SqlSource<'c> {
    conn: &'c Connection,
    heads: Side,
    removed: Side,
    devices: OnceCell<HashMap<DeviceId, String>>,
}

impl<'c> SqlSource<'c> {
    pub(crate) fn new(conn: &'c Connection) -> Self {
        SqlSource {
            conn,
            heads: Side::new(false),
            removed: Side::new(true),
            devices: OnceCell::new(),
        }
    }
}

impl Source for SqlSource<'_> {
    type Err = StateError;

    fn heads_from(&mut self, from: &str, hi: Option<&str>) -> Result<Option<PathVers>, StateError> {
        self.heads.first(self.conn, from, hi)
    }

    fn removed_from(
        &mut self,
        from: &str,
        hi: Option<&str>,
    ) -> Result<Option<PathVers>, StateError> {
        self.removed.first(self.conn, from, hi)
    }

    fn device_name(&self, id: &DeviceId) -> Option<String> {
        let names = self.devices.get_or_init(|| {
            super::query::devices_all(self.conn)
                .map(|all| all.into_iter().map(|d| (d.id, d.name)).collect())
                .unwrap_or_default()
        });
        names.get(id).cloned()
    }

    /// One statement per table, read to its end side by side: no batches, no seek per path,
    /// and no allocation per row but for the versions of the path at hand.
    fn walk(
        &mut self,
        from: &str,
        hi: Option<&str>,
        visit: &mut dyn FnMut(&Group) -> bool,
    ) -> Result<(), StateError> {
        const ORDER: &str = "ORDER BY path, st_l, st_d, st_i, hash";
        let sql = |side: &Side| {
            let (table, columns) = side.columns();
            match hi {
                Some(_) => {
                    format!("SELECT {columns} FROM {table} WHERE path >= ?1 AND path < ?2 {ORDER}")
                }
                None => format!("SELECT {columns} FROM {table} WHERE path >= ?1 {ORDER}"),
            }
        };
        let mut heads = self.conn.prepare_cached(&sql(&self.heads))?;
        let mut removed = self.conn.prepare_cached(&sql(&self.removed))?;
        let (mut heads, mut removed) = match hi {
            Some(hi) => (
                heads.query(params![from, hi])?,
                removed.query(params![from, hi])?,
            ),
            None => (heads.query(params![from])?, removed.query(params![from])?),
        };
        /// The next row of one side: its path into `path`, its version; `None` at the end.
        fn pull(
            rows: &mut rusqlite::Rows<'_>,
            removed: bool,
            path: &mut String,
        ) -> Result<Option<Ver>, StateError> {
            let Some(row) = rows.next()? else {
                return Ok(None);
            };
            let text = row.get_ref(0)?.as_str();
            path.clear();
            path.push_str(text.map_err(|e| StateError::Corrupt(e.to_string()))?);
            Ok(Some(ver_at(row, removed)?))
        }
        let (mut head_path, mut removed_path) = (String::new(), String::new());
        let mut head = pull(&mut heads, false, &mut head_path)?;
        let mut gone = pull(&mut removed, true, &mut removed_path)?;
        let mut group = Group::default();
        loop {
            let path = match (&head, &gone) {
                (None, None) => return Ok(()),
                (Some(_), None) => &head_path,
                (None, Some(_)) => &removed_path,
                (Some(_), Some(_)) => (&head_path).min(&removed_path),
            };
            group.path.clone_from(path);
            group.heads.clear();
            group.removed.clear();
            while head.is_some() && head_path == group.path {
                group.heads.extend(head.take());
                head = pull(&mut heads, false, &mut head_path)?;
            }
            while gone.is_some() && removed_path == group.path {
                group.removed.extend(gone.take());
                gone = pull(&mut removed, true, &mut removed_path)?;
            }
            if group.removed.len() > 1 {
                past::by_removal(&mut group.removed);
            }
            if !visit(&group) {
                return Ok(());
            }
        }
    }
}

/// What other connections committed since this one last looked: changes when they did. Inside
/// a read transaction it is the version of the snapshot being read.
fn data_version(c: &Connection) -> Result<i64, StateError> {
    Ok(c.pragma_query_value(None, "data_version", |r| r.get(0))?)
}

/// Segments that superseded something: the time recorded for that and the files it took.
pub(super) const ANCHORS: &str =
    "SELECT by_l, by_d, min(removed_ms), sum(kind = 0) FROM removed GROUP BY by_l, by_d";
/// The versions that point into blobs created after `?1`, each with its blob and its segment,
/// over the heads …
pub(super) const FRESH_HEADS: &str = "SELECT b.id, b.created_ms, h.st_l, h.st_d \
     FROM blobs b CROSS JOIN heads h ON h.blob = b.id WHERE b.created_ms > ?1";
/// … and over the removed versions. Both start from `blobs` and reach the versions through
/// the index on their `blob` column, which holds the stamp as well: no scan of `heads`.
pub(super) const FRESH_REMOVED: &str = "SELECT b.id, b.created_ms, r.st_l, r.st_d \
     FROM blobs b CROSS JOIN removed r ON r.blob = b.id WHERE b.created_ms > ?1";
/// When each device was first seen.
const FIRSTS: &str = "SELECT id, first_ms FROM devices";

fn anchors(c: &Connection) -> Result<Vec<(u64, DeviceId, u64, u64)>, StateError> {
    let mut stmt = c.prepare_cached(ANCHORS)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push((
            to_u(r.get(0)?)?,
            DeviceId(arr(r.get(1)?)?),
            to_u(r.get(2)?)?,
            to_u(r.get::<_, Option<i64>>(3)?.unwrap_or(0))?,
        ));
    }
    Ok(out)
}

fn build(c: &Connection, now_ms: u64) -> Result<History, StateError> {
    let floor = History::floor_for(now_ms);
    let mut uploads = past::Uploads::new(floor);
    for sql in [FRESH_HEADS, FRESH_REMOVED] {
        let mut stmt = c.prepare_cached(sql)?;
        let mut rows = stmt.query(params![to_i(floor)?])?;
        while let Some(r) = rows.next()? {
            let (created_ms, lamport) = (to_u(r.get(1)?)?, to_u(r.get(2)?)?);
            uploads.see(
                bytes_at(r, 0)?,
                created_ms,
                lamport,
                DeviceId(bytes_at(r, 3)?),
                1,
            );
        }
    }
    let mut firsts = Vec::new();
    let mut stmt = c.prepare_cached(FIRSTS)?;
    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        firsts.push((DeviceId(bytes_at(r, 0)?), to_u(r.get(1)?)?));
    }
    Ok(History::build(floor, anchors(c)?, uploads.fresh(), firsts))
}

/// What changes whenever the tables behind a `History` do. `heads`, `removed`, `blobs` and
/// `devices` change in three ways only: a segment is applied (a row of `applied`, the lamport
/// clock, the next own sequence number), a snapshot becomes the replica's base, or the
/// replica writes one (which drops old removed versions). Everything else that is committed
/// to the database — the transfer ledger the viewer itself writes for every file it serves,
/// the base rows of a `gclone sync` next to it — leaves them, and this, as they are.
const MARK: &str = "SELECT (SELECT count(*) FROM applied), \
     (SELECT total(seq) FROM applied), (SELECT total(lamport) FROM applied), \
     (SELECT count(*) FROM devices), (SELECT v FROM meta WHERE k = 'lamport'), \
     (SELECT v FROM meta WHERE k = 'next_seq'), (SELECT v FROM meta WHERE k = 'base_snapshot_name'), \
     (SELECT v FROM meta WHERE k = 'last_snapshot_name'), (SELECT v FROM meta WHERE k = 'snap_checked')";

type Mark = Vec<rusqlite::types::Value>;

fn mark(c: &Connection) -> Result<Mark, StateError> {
    let mut stmt = c.prepare_cached(MARK)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    if let Some(r) = rows.next()? {
        for at in 0..r.as_ref().column_count() {
            out.push(r.get(at)?);
        }
    }
    Ok(out)
}

/// The head or the removed version `(path, stamp, hash)` with everything the reader of a file
/// needs — as a `Head` — and its blob record.
fn version_row(
    c: &Connection,
    path: &str,
    ver: &Ver,
) -> Result<Option<(Head, Option<BlobRec>)>, StateError> {
    let head = match ver.end {
        None => {
            let key = [
                rusqlite::types::Value::Text(path.to_owned()),
                rusqlite::types::Value::Integer(to_i(ver.stamp.lamport)?),
                rusqlite::types::Value::Blob(ver.stamp.device.0.to_vec()),
                rusqlite::types::Value::Integer(i64::from(ver.stamp.idx)),
                rusqlite::types::Value::Blob(ver.hash.to_vec()),
            ];
            let cond = "path = ? AND st_l = ? AND st_d = ? AND st_i = ? AND hash = ?";
            heads_query(c, cond, &key)?.pop()
        }
        Some(_) => tables::removed_get(c, path, &ver.stamp, &ver.hash)?.map(|(v, _, _)| Head {
            path: v.path,
            stamp: v.stamp,
            entry: v.entry,
            origin: v.origin,
            winner: false,
        }),
    };
    let Some(head) = head else {
        return Ok(None);
    };
    let blob = match &head.entry.loc {
        Some(loc) => c
            .prepare_cached("SELECT id, file_id, clen, md5, created_ms FROM blobs WHERE id = ?")?
            .query_map(params![&loc.blob.0[..]], |r| Ok(tables::blob_at(r, 0)))?
            .next()
            .transpose()?
            .transpose()?,
        None => None,
    };
    Ok(Some((head, blob)))
}

/// A connection of its own for questions about the past, and what is derived once per state
/// of the replica (`History`). A long walk here holds up no listing of the present.
pub struct HistoryDb {
    db: Db,
    /// The history and the state it was built from: `PRAGMA data_version` as last seen, and
    /// the mark of the index tables ([`MARK`]). Built again when the mark has changed —
    /// looked at only when another connection committed something.
    cached: Mutex<Option<(i64, Mark, Arc<History>)>>,
}

impl HistoryDb {
    /// `db`: from `Db::open_shared` — never the connection the present view reads through.
    pub fn new(db: Db) -> HistoryDb {
        HistoryDb {
            db,
            cached: Mutex::new(None),
        }
    }

    /// Runs `f` over the replica as it is at one moment, with the history of that state.
    pub fn read<T>(
        &self,
        now_ms: u64,
        f: impl FnOnce(&mut SqlSource<'_>, &History) -> Result<T, StateError>,
    ) -> Result<T, IndexError> {
        Ok(self.db.read_snapshot(|c| {
            let version = data_version(c)?;
            let history = {
                let mut cached = self.cached.lock().unwrap_or_else(|e| e.into_inner());
                let kept = match &mut *cached {
                    Some((seen, _, history)) if *seen == version && history.serves(now_ms) => {
                        Some(history.clone())
                    }
                    // Something was committed: to the index, or beside it?
                    Some((seen, built, history)) if history.serves(now_ms) => (mark(c)? == *built)
                        .then(|| {
                            *seen = version;
                            history.clone()
                        }),
                    _ => None,
                };
                match kept {
                    Some(history) => history,
                    None => {
                        let history = Arc::new(build(c, now_ms)?);
                        *cached = Some((version, mark(c)?, history.clone()));
                        history
                    }
                }
            };
            f(&mut SqlSource::new(c), &history)
        })?)
    }

    /// The same without a history: for the questions that need none (`deleted`).
    pub fn rows<T>(
        &self,
        f: impl FnOnce(&mut SqlSource<'_>) -> Result<T, StateError>,
    ) -> Result<T, IndexError> {
        Ok(self.db.read_snapshot(|c| f(&mut SqlSource::new(c)))?)
    }
}

impl<B: Backend> Vault<B> {
    /// The version of `path` that the id `v` names (`past::resolve`: a file head, or a removed
    /// file version inside the restore window at `now_ms`) as a `Head` a reader can be given,
    /// with its blob record. `None`: no such version, or two of them. One read snapshot.
    pub fn version(
        &self,
        path: &str,
        v: &str,
        now_ms: u64,
    ) -> Result<Option<(Head, Option<BlobRec>)>, IndexError> {
        Ok(self.db.read_snapshot(|c| {
            match past::resolve(&mut SqlSource::new(c), path, v, now_ms)? {
                Resolved::One(ver) => version_row(c, path, &ver),
                Resolved::None | Resolved::Ambiguous => Ok::<_, StateError>(None),
            }
        })?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::consts::RESTORE_WINDOW_MS;
    use crate::format::{Op, SegmentV1};
    use crate::index::{HeadStore, MemIndex, apply_segment};
    use crate::state::tables::SqlStore;
    use crate::test_prng::{Prng, for_each_seed};
    use crate::types::{BlobId, Entry, Loc};
    use crate::web::past::MemSource;
    use crate::web::rules::{self, SortOrder};

    const DAY: u64 = 86_400_000;
    const NOW_MS: u64 = 1_000 * DAY;
    const FROM_MS: u64 = NOW_MS - RESTORE_WINDOW_MS;

    const NAMES: [&str; 16] = [
        "a",
        "a.txt",
        "a/b",
        "a/b/c",
        "a/d",
        "a0",
        "b",
        "b/x",
        "b/y/z",
        "c",
        "dir/1",
        "dir/2",
        "dir/sub/3",
        "dir.d",
        "e e",
        "z",
    ];

    /// Random segments of three devices — uploads, overwrites (also of versions another
    /// device has replaced meanwhile: conflicts), deletes, folders — applied to a SQL replica
    /// and to an in-memory index alike.
    fn random_index(rng: &mut Prng) -> (Db, MemIndex, Vec<u64>) {
        let db = Db::open_in_memory().unwrap();
        let mut mem = MemIndex::default();
        let mut time = FROM_MS - 2 * DAY;
        let mut times = Vec::new();
        let mut blobs = 0u64;
        for lamport in 1..=rng.range(4, 40) {
            time += rng.range(1, 400_000_000);
            let device = DeviceId([rng.range(1, 4) as u8; 8]);
            let mut ops = vec![Op::Device {
                id: device,
                name: format!("device-{}", device.0[0]),
            }];
            for _ in 0..rng.range(1, 6) {
                let path = *rng.pick(&NAMES);
                let heads = mem.heads(path).unwrap();
                // Mostly the winner; sometimes a version that lost, or none at all.
                let base = match heads.len() {
                    0 => None,
                    n if rng.chance(1, 6) => Some(heads[rng.index(n)].stamp),
                    _ if rng.chance(1, 10) => None,
                    n => Some(heads[n - 1].stamp),
                };
                match (base, rng.below(4)) {
                    (Some(base), 0) => ops.push(Op::Del {
                        path: path.to_owned(),
                        base,
                    }),
                    (base, kind) => {
                        let content = rng.range(1, 4) as u8;
                        let loc = (kind != 1).then(|| {
                            blobs += 1;
                            let mut id = [0u8; 16];
                            id[..8].copy_from_slice(&blobs.to_be_bytes());
                            ops.push(Op::Blob(BlobRec {
                                id: BlobId(id),
                                file_id: String::new(),
                                clen: 100,
                                md5: [0; 16],
                                created_ms: time - rng.range(1, 5_000),
                            }));
                            Loc {
                                blob: BlobId(id),
                                off: 0,
                                clen: 100,
                                salt: [0; 16],
                                chunk_log2: 16,
                                epoch: 1,
                                suite: 1,
                                flags: 0,
                            }
                        });
                        let dir = kind == 1 && rng.bool();
                        ops.push(Op::Put {
                            path: path.to_owned(),
                            entry: Entry {
                                kind: if dir { EntryKind::Dir } else { EntryKind::File },
                                size: if dir { 0 } else { u64::from(content) },
                                mtime_ns: 0,
                                exec: false,
                                hash: if dir { [0; 32] } else { [content; 32] },
                                loc,
                            },
                            base,
                            origin: None,
                        });
                    }
                }
            }
            let seg = SegmentV1 {
                vault_id: [0; 16],
                device,
                seq: lamport,
                lamport,
                prev: None,
                seen: Vec::new(),
                created_ms: time,
                host: String::new(),
                ops,
            };
            // A recorded time that may lie after the truth.
            let recorded = time + rng.below(3) * rng.below(DAY);
            apply_segment(&mut mem, &seg, recorded).unwrap();
            db.txn(|c| apply_segment(&mut SqlStore(c), &seg, recorded))
                .unwrap();
            times.push(time);
        }
        (db, mem, times)
    }

    #[test]
    fn the_sql_source_gives_what_the_memory_index_gives() {
        for_each_seed("history_source", 60, |rng| {
            let (db, mem, _) = random_index(rng);
            let mut bounds: Vec<String> = vec![String::new(), "\u{10ffff}".into()];
            for name in NAMES {
                bounds.extend([
                    name.to_owned(),
                    past::successor(name),
                    format!("{name}/"),
                    format!("{name}0"),
                ]);
            }
            db.read_snapshot(|c| {
                let mut sql = SqlSource::new(c);
                let mut memory = MemSource(&mem);
                let mut from = String::new();
                for _ in 0..600 {
                    // A walk in order for a while, then a jump — forward or back.
                    if rng.chance(1, 5) {
                        from = rng.pick(&bounds).clone();
                    }
                    let hi = rng.chance(1, 2).then(|| rng.pick(&bounds).clone());
                    let removed = rng.bool();
                    let (got, expected) = match removed {
                        true => (
                            sql.removed_from(&from, hi.as_deref())?,
                            memory.removed_from(&from, hi.as_deref()).unwrap(),
                        ),
                        false => (
                            sql.heads_from(&from, hi.as_deref())?,
                            memory.heads_from(&from, hi.as_deref()).unwrap(),
                        ),
                    };
                    assert_eq!(
                        got, expected,
                        "removed={removed} from {from:?} below {hi:?}"
                    );
                    if let Some((path, _)) = got
                        && rng.chance(4, 5)
                    {
                        from = past::successor(&path);
                    }
                }
                for id in 0..5u8 {
                    let id = DeviceId([id; 8]);
                    assert_eq!(sql.device_name(&id), memory.device_name(&id));
                }
                Ok::<_, StateError>(())
            })
            .unwrap();
        });
    }

    /// Every answer about the past, as JSON, from the replica and from the in-memory index.
    #[test]
    fn the_replica_and_the_memory_index_tell_the_same_past() {
        for_each_seed("history_parity", 30, |rng| {
            let (db, mem, times) = random_index(rng);
            let history = HistoryDb::new(db);
            let in_memory = History::of_mem(&mem, NOW_MS);
            let json = |value: &dyn erased::Json| value.text();
            let by = SortOrder::parse(None, None).unwrap();
            let mut moments = vec![FROM_MS, NOW_MS - 1, past::NOW];
            for time in &times {
                moments.extend([time - 1, *time, time + rng.range(1, DAY)]);
            }
            let dirs = [
                "",
                "a",
                "a/b",
                "b",
                "b/y",
                "dir",
                "dir/sub",
                "c",
                "nope/at/all",
            ];
            history
                .read(NOW_MS, |sql, from_sql| {
                    let mut memory = MemSource(&mem);
                    assert_eq!(
                        json(&past::timeline(sql, from_sql, NOW_MS)),
                        json(&past::timeline(&memory, &in_memory, NOW_MS))
                    );
                    for t in &moments {
                        for dir in dirs {
                            let listing = |found| match found {
                                past::Listing::Rows(rows) => {
                                    json(&rules::list_json(dir.to_owned(), rows, by, 0, 1_000))
                                }
                                past::Listing::Absent { nearest } => format!("absent: {nearest}"),
                            };
                            assert_eq!(
                                listing(past::list_at(sql, from_sql, dir, *t)?),
                                listing(past::list_at(&mut memory, &in_memory, dir, *t).unwrap()),
                                "list {dir:?} at {t}"
                            );
                        }
                        for needle in ["a", "b", "1", "d"] {
                            let search = |(hits, more)| {
                                json(&rules::search_json(needle.to_owned(), hits, more, by))
                            };
                            assert_eq!(
                                search(past::search_at(sql, from_sql, needle, 5, *t)?),
                                search(
                                    past::search_at(&mut memory, &in_memory, needle, 5, *t)
                                        .unwrap()
                                ),
                                "search {needle:?} at {t}"
                            );
                        }
                        for path in NAMES {
                            let stat = |row: Option<past::Row>| row.map(|row| json(&row.json()));
                            assert_eq!(
                                stat(past::stat_at(sql, from_sql, path, *t)?),
                                stat(past::stat_at(&mut memory, &in_memory, path, *t).unwrap()),
                                "stat {path:?} at {t}"
                            );
                        }
                    }
                    for path in NAMES {
                        let listed = past::versions(sql, from_sql, path, None, NOW_MS)?;
                        let expected =
                            past::versions(&mut memory, &in_memory, path, None, NOW_MS).unwrap();
                        assert_eq!(json(&listed), json(&expected), "versions of {path:?}");
                        for row in &listed.versions {
                            assert_eq!(
                                past::resolve(sql, path, &row.v, NOW_MS)?,
                                past::resolve(&mut memory, path, &row.v, NOW_MS).unwrap()
                            );
                        }
                    }
                    for dir in dirs {
                        let deleted = |found: Option<past::Deleted>| {
                            found.map(|found| {
                                json(&past::deleted_json(dir.to_owned(), found, by, 0, 1_000))
                            })
                        };
                        assert_eq!(
                            deleted(past::deleted(sql, dir, NOW_MS)?),
                            deleted(past::deleted(&mut memory, dir, NOW_MS).unwrap()),
                            "deleted from {dir:?}"
                        );
                    }
                    Ok(())
                })
                .unwrap();
        });
    }

    /// `serde::Serialize` is not object-safe; this is, for the one use above.
    mod erased {
        pub trait Json {
            fn text(&self) -> String;
        }
        impl<T: serde::Serialize> Json for T {
            fn text(&self) -> String {
                serde_json::to_string(self).unwrap()
            }
        }
    }

    /// What the bounds of §7.4 rest on: the clock is built from `removed` and `blobs`, and the
    /// rows of a path range are read off the primary key.
    #[test]
    fn the_statements_scan_neither_heads_nor_a_whole_range() {
        let db = Db::open_in_memory().unwrap();
        db.read(|c| {
            let plan = |sql: &str| -> Vec<String> {
                let mut stmt = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
                let rows = stmt.query_map([], |r| r.get::<_, String>(3)).unwrap();
                rows.map(|r| r.unwrap()).collect()
            };
            let fresh = plan(&FRESH_HEADS.replace("?1", "0"));
            assert!(fresh.iter().any(|l| l.starts_with("SCAN b")), "{fresh:?}");
            assert!(
                fresh
                    .iter()
                    .any(|l| l.starts_with("SEARCH h USING COVERING INDEX heads_blob (blob=?)")),
                "{fresh:?}"
            );
            assert!(!fresh.iter().any(|l| l.starts_with("SCAN h")), "{fresh:?}");
            let fresh = plan(&FRESH_REMOVED.replace("?1", "0"));
            assert!(
                fresh
                    .iter()
                    .any(|l| l.starts_with("SEARCH r USING COVERING INDEX removed_blob (blob=?)")),
                "{fresh:?}"
            );
            let anchors = plan(ANCHORS);
            assert!(anchors.iter().all(|l| !l.contains("heads")), "{anchors:?}");
            for table in ["heads", "removed"] {
                let range = plan(&format!(
                    "SELECT path FROM {table} WHERE path >= 'a' AND path < 'b' \
                     ORDER BY path, st_l, st_d, st_i, hash LIMIT 2"
                ));
                assert_eq!(
                    range,
                    [format!(
                        "SEARCH {table} USING PRIMARY KEY (path>? AND path<?)"
                    )],
                    "{table}"
                );
            }
            Ok::<_, StateError>(())
        })
        .unwrap();
    }

    /// The history is built once per state of the index: again when another connection
    /// applied a segment, and when the clock went back past its floor — and not when
    /// something else was committed to the database (the transfer ledger: the viewer writes
    /// it for every file it serves).
    #[test]
    fn the_history_follows_what_other_connections_commit() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("state.db");
        let writer = Db::open(&file).unwrap();
        let reader = HistoryDb::new(Db::open_shared(&file).unwrap());
        let t = FROM_MS + DAY;
        let put = |lamport: u64, content: u8, base: Option<Stamp>| SegmentV1 {
            vault_id: [0; 16],
            device: DeviceId([1; 8]),
            seq: lamport,
            lamport,
            prev: None,
            seen: Vec::new(),
            created_ms: t + lamport,
            host: String::new(),
            ops: vec![Op::Put {
                path: "f".into(),
                entry: Entry {
                    kind: EntryKind::File,
                    size: 1,
                    mtime_ns: 0,
                    exec: false,
                    hash: [content; 32],
                    loc: None,
                },
                base,
                origin: None,
            }],
        };
        // As a refresh or a commit applies a segment: with its row in `applied`.
        let apply = |seg: &SegmentV1| {
            let row = crate::state::tables::AppliedRow {
                dev: seg.device,
                seq: seg.seq,
                hash: [seg.seq as u8; 32],
                file_id: String::new(),
                name: String::new(),
                lamport: seg.lamport,
                created_ms: seg.created_ms,
                size: 0,
            };
            writer
                .txn(|c| crate::index::commit::apply_and_record(c, seg, &row))
                .unwrap();
        };
        let look = |now: u64| {
            reader
                .read(now, |src, history| {
                    let listed = past::versions(src, history, "f", None, now)?;
                    let moments = past::timeline(src, history, now).moments.len();
                    let built = history as *const History as usize;
                    Ok((listed.versions.len(), moments, built))
                })
                .unwrap()
        };
        apply(&put(1, 1, None));
        let first = look(NOW_MS);
        assert_eq!((first.0, first.1), (1, 0));
        assert_eq!(look(NOW_MS), first, "nothing changed: the same history");
        assert_eq!(look(NOW_MS + DAY), first, "a later now needs no new one");
        // Another connection commits: the next question sees it.
        let v1 = Stamp {
            lamport: 1,
            device: DeviceId([1; 8]),
            idx: 0,
        };
        apply(&put(2, 2, Some(v1)));
        let second = look(NOW_MS);
        assert_eq!((second.0, second.1), (2, 1));
        assert_ne!(second.2, first.2, "built again");
        assert_eq!(look(NOW_MS), second);
        // A commit beside the index — the ledger of transfers, which the viewer itself writes
        // after every file it serves: the same history, with what its walks have learned.
        for i in 0..3 {
            writer
                .ledger_add(NOW_MS + i, crate::state::LedgerDir::Down, 1_000)
                .unwrap();
            assert_eq!(
                look(NOW_MS),
                second,
                "a ledger row is no change of the index"
            );
        }
        apply(&put(3, 3, Some(Stamp { lamport: 2, ..v1 })));
        let third = look(NOW_MS);
        assert_eq!((third.0, third.1), (3, 2));
        assert_ne!(third.2, second.2, "built again after the ledger rows");
        let second = third;
        // The clock went back behind the floor the history was built with: built again.
        let earlier = look(NOW_MS - DAY);
        assert_ne!(earlier.2, second.2);
        assert_eq!((earlier.0, earlier.1), (3, 2));
        // A read without a history sees the same rows.
        let ids: BTreeSet<String> = reader
            .rows(|src| {
                Ok(past::Cursor::new(src)
                    .at("f")?
                    .removed
                    .iter()
                    .map(|v| past::version_id("f", &v.stamp, &v.hash))
                    .collect())
            })
            .unwrap();
        assert_eq!(ids.len(), 2);
    }
}

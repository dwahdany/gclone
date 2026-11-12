//! SQLite schema v1 and pragmas (SPEC §8.4) — owned by WP4. Private to `state`.

use std::time::Duration;

use rusqlite::Connection;

use crate::error::StateError;

const USER_VERSION: i64 = 1;

/// Columns shared by `heads` and `removed`: one version of a path (`Loc` and origin are NULL
/// when absent).
const VERSION_COLUMNS: &str = "
  path TEXT NOT NULL, st_l INTEGER NOT NULL, st_d BLOB NOT NULL, st_i INTEGER NOT NULL,
  kind INTEGER NOT NULL, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL, exec INTEGER NOT NULL, hash BLOB NOT NULL,
  blob BLOB, off INTEGER, clen INTEGER, salt BLOB, chunk_log2 INTEGER, epoch INTEGER, suite INTEGER, flags INTEGER,
  o_l INTEGER, o_d BLOB, o_i INTEGER";

/// Added after the first builds (§8.4, §17.11) — also created in a `state.db` those builds
/// left behind ([`upgrade`]):
/// - `heads_losers`: the conflict losers, so that "are there conflicts?" and resolution rule 1
///   cost O(losers) instead of a scan of every head;
/// - `touched`: the paths whose heads changed since the last complete resolution — rule 2
///   (file vs directory) looks only at them and their ancestors.
const ADDITIONS: &str = "\
CREATE INDEX IF NOT EXISTS heads_losers ON heads(path) WHERE winner = 0;
CREATE TABLE IF NOT EXISTS touched(path TEXT PRIMARY KEY) WITHOUT ROWID;";

fn schema() -> String {
    format!(
        "
CREATE TABLE meta(k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE heads({VERSION_COLUMNS},
  winner INTEGER NOT NULL,
  PRIMARY KEY(path, st_l, st_d, st_i, hash)) WITHOUT ROWID;
CREATE INDEX heads_size ON heads(size) WHERE winner = 1;
CREATE INDEX heads_blob ON heads(blob);
{ADDITIONS}
CREATE TABLE removed({VERSION_COLUMNS},
  removed_ms INTEGER NOT NULL,
  by_l INTEGER NOT NULL, by_d BLOB NOT NULL, by_i INTEGER NOT NULL,
  PRIMARY KEY(path, st_l, st_d, st_i, hash)) WITHOUT ROWID;
CREATE INDEX removed_blob ON removed(blob);
CREATE TABLE blobs(id BLOB PRIMARY KEY, file_id TEXT NOT NULL, clen INTEGER NOT NULL, md5 BLOB NOT NULL,
  created_ms INTEGER NOT NULL, trashed_ms INTEGER) WITHOUT ROWID;
CREATE TABLE devices(id BLOB PRIMARY KEY, name TEXT NOT NULL, first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE applied(dev BLOB NOT NULL, seq INTEGER NOT NULL, hash BLOB NOT NULL, file_id TEXT NOT NULL, name TEXT NOT NULL,
  lamport INTEGER NOT NULL, created_ms INTEGER NOT NULL, size INTEGER NOT NULL, PRIMARY KEY(dev, seq, hash)) WITHOUT ROWID;
CREATE TABLE base_covers(dev BLOB PRIMARY KEY, seq INTEGER NOT NULL, hash BLOB NOT NULL, file_id TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE base_covered(dev BLOB NOT NULL, seq INTEGER NOT NULL, h4 BLOB NOT NULL, PRIMARY KEY(dev, seq, h4)) WITHOUT ROWID;
CREATE TABLE hw(dev BLOB PRIMARY KEY, seq INTEGER NOT NULL, hash BLOB NOT NULL, file_id TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE own(seq INTEGER PRIMARY KEY, hash BLOB NOT NULL, file_id TEXT NOT NULL);
CREATE TABLE blocked(name TEXT PRIMARY KEY, first_seen_ms INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE pending(id INTEGER PRIMARY KEY AUTOINCREMENT, draft BLOB NOT NULL, created_ms INTEGER NOT NULL, pid INTEGER NOT NULL);
CREATE TABLE outbox(seq INTEGER PRIMARY KEY, name TEXT NOT NULL, file_id TEXT NOT NULL, bytes BLOB NOT NULL, effects BLOB NOT NULL);
CREATE TABLE pairs(id INTEGER PRIMARY KEY, local_root TEXT NOT NULL, remote_prefix TEXT NOT NULL,
  root_ino INTEGER NOT NULL, root_birth_ns INTEGER NOT NULL, fold_case INTEGER NOT NULL, UNIQUE(local_root, remote_prefix));
CREATE TABLE base(pair INTEGER NOT NULL, key TEXT NOT NULL, rel TEXT NOT NULL, kind INTEGER NOT NULL,
  size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL, ctime_ns INTEGER NOT NULL, ino INTEGER NOT NULL, mode INTEGER NOT NULL,
  hash BLOB NOT NULL, st_l INTEGER NOT NULL, st_d BLOB NOT NULL, st_i INTEGER NOT NULL, observed_ns INTEGER NOT NULL,
  PRIMARY KEY(pair, key)) WITHOUT ROWID;
CREATE TABLE ledger(ts_ms INTEGER NOT NULL, dir INTEGER NOT NULL, bytes INTEGER NOT NULL);
PRAGMA user_version = {USER_VERSION};
"
    )
}

/// For a connection of a process that does not hold the state lock (§8.3): the pragmas that
/// touch nothing, and no schema work. `Ok(false)` if the database has no schema yet — only
/// the lock holder creates it (two processes that both saw an empty database would both try).
pub(super) fn init_shared(conn: &Connection) -> Result<bool, StateError> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    match version {
        0 => Ok(false),
        USER_VERSION => Ok(true),
        other => Err(StateError::Corrupt(format!(
            "state.db has schema version {other}; this gclone reads version {USER_VERSION}"
        ))),
    }
}

/// Pragmas for every connection, and the schema for a new database.
pub(super) fn init(conn: &Connection) -> Result<(), StateError> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    match version {
        0 => {
            let tables: i64 =
                conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))?;
            if tables != 0 {
                return Err(StateError::Corrupt(
                    "state.db is not a gclone state database".into(),
                ));
            }
            conn.execute_batch(&format!("BEGIN IMMEDIATE;{}COMMIT;", schema()))?;
            Ok(())
        }
        USER_VERSION => upgrade(conn),
        other => Err(StateError::Corrupt(format!(
            "state.db has schema version {other}; this gclone reads version {USER_VERSION}"
        ))),
    }
}

/// A version-1 database written before [`ADDITIONS`] existed gets them now. Nothing tracked the
/// paths touched so far, so the next resolution looks at every head once (`resolve_all`).
/// Only the lock holder comes here (`Db::open`); a process without the lock never upgrades
/// (`init_shared`).
fn upgrade(conn: &Connection) -> Result<(), StateError> {
    let present: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE name IN ('heads_losers', 'touched')",
        [],
        |r| r.get(0),
    )?;
    if present == 2 {
        return Ok(());
    }
    let added = conn.execute_batch(&format!(
        "BEGIN IMMEDIATE;{ADDITIONS}\
         INSERT OR REPLACE INTO meta (k, v) VALUES ('resolve_all', x'01');COMMIT;"
    ));
    if added.is_err() {
        let _ = conn.execute_batch("ROLLBACK");
    }
    Ok(added?)
}

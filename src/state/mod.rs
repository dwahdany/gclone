//! Local state: SQLite replica, base tables, ledger, process lock (SPEC §8.3, §8.4, §9.7) —
//! owned by WP4.
//!
//! No module other than `state`/`index` executes SQL. Index tables are `pub(crate)` in
//! `state::tables`.

use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, params};

use crate::consts::LEDGER_WINDOW_MS;
use crate::error::StateError;
use crate::types::BaseRow;
use crate::util;

mod schema;
pub(crate) mod tables;

/// Page cache of [`Db::txn_bulk`], in KiB.
const BULK_CACHE_KIB: i64 = 64 * 1024;

/// `Arc<Mutex<rusqlite::Connection>>` — cheap to clone, `Send + Sync`.
#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

/// Root `(st_ino, birth time)` vs the recorded one, §5.5.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PairIdentity {
    New,
    Same,
    Changed,
}

pub struct PairInfo {
    pub id: i64,
    pub identity: PairIdentity,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LedgerDir {
    Up,
    Down,
}

impl LedgerDir {
    fn code(self) -> i64 {
        match self {
            LedgerDir::Up => 0,
            LedgerDir::Down => 1,
        }
    }
}

impl Db {
    /// Creates schema v1, sets pragmas, file mode 0600.
    pub fn open(path: &Path) -> Result<Db, StateError> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            util::create_dir_private(dir)?;
        }
        // SQLite would create the file with the umask's mode; the WAL and SHM files inherit
        // the mode of the main file.
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        Self::init(Connection::open(path)?)
    }

    /// For a process that does **not** hold the state lock — a read-only command that found
    /// it busy (§8.3). Creates nothing and writes nothing: no file, no schema, no upgrade; a
    /// reader of a WAL database is never blocked by the lock holder's write transaction.
    /// `StateError::Locked` if the database is not there yet or has no schema: the process
    /// that holds the lock is still creating it.
    pub fn open_shared(path: &Path) -> Result<Db, StateError> {
        use rusqlite::OpenFlags;
        if !path.exists() {
            return Err(StateError::Locked);
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI;
        let conn = Connection::open_with_flags(path, flags)?;
        if !schema::init_shared(&conn)? {
            return Err(StateError::Locked);
        }
        Self::tune(&conn)?;
        Ok(Db {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn open_in_memory() -> Result<Db, StateError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Db, StateError> {
        schema::init(&conn)?;
        Self::tune(&conn)?;
        Ok(Db {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// What every connection gets besides the pragmas: the statement cache, and the query
    /// planner's stability guarantee. Without the latter SQLite looks at the value bound to a
    /// parameter where a partial index might apply (`heads_size`, `heads_losers`) and then
    /// compiles the statement again on every later bind: two statements of every applied
    /// `Put` were compiled once per op, more than half the time of a large replay (§17.34).
    /// No statement here depends on that look: the conditions that select a partial index
    /// are written as literals.
    fn tune(conn: &Connection) -> Result<(), StateError> {
        conn.set_prepared_statement_cache_capacity(128);
        conn.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG,
            true,
        )?;
        Ok(())
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        // A panic while the guard was held rolled its transaction back; the connection is usable.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs `f` on the connection outside a transaction (reads, single statements).
    pub(crate) fn read<T, E>(&self, f: impl FnOnce(&Connection) -> Result<T, E>) -> Result<T, E> {
        f(&self.conn())
    }

    /// Runs `f` inside one deferred read transaction: every statement of `f` sees the same
    /// state of the database, whatever other processes commit meanwhile. For SELECTs only — it
    /// takes no write lock, so it is what a process without the state lock may use.
    pub(crate) fn read_snapshot<T, E: From<StateError>>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, E>,
    ) -> Result<T, E> {
        let conn = self.conn();
        // Deferred; rolled back when dropped (there is nothing to roll back).
        let tx = conn.unchecked_transaction().map_err(StateError::from)?;
        let out = f(&tx)?;
        tx.commit().map_err(StateError::from)?;
        Ok(out)
    }

    /// Runs `f` in one transaction: committed when `f` returns `Ok`, rolled back otherwise.
    pub(crate) fn txn<T, E: From<StateError>>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(StateError::from)?;
        let out = f(&tx)?;
        tx.commit().map_err(StateError::from)?;
        Ok(out)
    }

    /// [`Db::txn`] for a transaction that writes a large part of the replica — a snapshot's
    /// content, a long batch of segments: SQLite gets [`BULK_CACHE_KIB`] of page cache while
    /// it runs. With the 2 MiB a connection has otherwise, the pages of such a transaction
    /// are written to the WAL as soon as they leave the cache and read back when the next
    /// row needs them — the indexes of `heads` are not written in order. What is committed,
    /// and when, is the same.
    pub(crate) fn txn_bulk<T, E: From<StateError>>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, E>,
    ) -> Result<T, E> {
        self.txn_sized(true, f)
    }

    /// [`Db::txn`], or [`Db::txn_bulk`] when `bulk`.
    pub(crate) fn txn_sized<T, E: From<StateError>>(
        &self,
        bulk: bool,
        f: impl FnOnce(&Connection) -> Result<T, E>,
    ) -> Result<T, E> {
        if !bulk {
            return self.txn(f);
        }
        let usual: i64 = self
            .read(|c| c.pragma_query_value(None, "cache_size", |r| r.get(0)))
            .map_err(StateError::from)?;
        self.read(|c| c.pragma_update(None, "cache_size", -BULK_CACHE_KIB))
            .map_err(StateError::from)?;
        let out = self.txn(f);
        // Back to the usual size, and the memory back to the system — whatever `f` returned.
        let _ = self.read(|c| {
            c.pragma_update(None, "cache_size", usual)?;
            c.execute_batch("PRAGMA shrink_memory")
        });
        out
    }

    pub fn meta_get(&self, k: &str) -> Result<Option<Vec<u8>>, StateError> {
        self.read(|c| tables::meta_get(c, k))
    }

    pub fn meta_set(&self, k: &str, v: &[u8]) -> Result<(), StateError> {
        self.read(|c| tables::meta_set(c, k, v))
    }

    pub fn meta_get_u64(&self, k: &str) -> Result<Option<u64>, StateError> {
        self.read(|c| tables::meta_u64(c, k))
    }

    pub fn meta_set_u64(&self, k: &str, v: u64) -> Result<(), StateError> {
        self.read(|c| tables::meta_set_u64(c, k, v))
    }

    /// Finds or creates the pair and reports how the root identity compares. NEVER discards rows.
    pub fn pair_open(
        &self,
        local_root: &str,
        remote_prefix: &str,
        root_ino: u64,
        root_birth_ns: i64,
        fold_case: bool,
    ) -> Result<PairInfo, StateError> {
        self.txn(|c| {
            let found: Option<(i64, i64, i64)> = c
                .query_row(
                    "SELECT id, root_ino, root_birth_ns FROM pairs \
                     WHERE local_root = ? AND remote_prefix = ?",
                    params![local_root, remote_prefix],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((id, ino, birth_ns)) = found else {
                c.execute(
                    "INSERT INTO pairs (local_root, remote_prefix, root_ino, root_birth_ns, fold_case) \
                     VALUES (?, ?, ?, ?, ?)",
                    params![local_root, remote_prefix, root_ino as i64, root_birth_ns, fold_case],
                )?;
                return Ok(PairInfo {
                    id: c.last_insert_rowid(),
                    identity: PairIdentity::New,
                });
            };
            c.execute(
                "UPDATE pairs SET fold_case = ? WHERE id = ?",
                params![fold_case, id],
            )?;
            // A birth time of 0 means "unavailable": then the inode number alone decides (§5.5).
            let same = ino as u64 == root_ino
                && (birth_ns == root_birth_ns || birth_ns == 0 || root_birth_ns == 0);
            Ok(PairInfo {
                id,
                identity: if same {
                    PairIdentity::Same
                } else {
                    PairIdentity::Changed
                },
            })
        })
    }

    /// `--reset-pair`: drop the pair's base rows, record the identity.
    pub fn pair_reset(
        &self,
        pair: i64,
        root_ino: u64,
        root_birth_ns: i64,
    ) -> Result<(), StateError> {
        self.txn(|c| {
            c.execute("DELETE FROM base WHERE pair = ?", params![pair])?;
            set_pair_identity(c, pair, root_ino, root_birth_ns)
        })
    }

    /// `--keep-pair`: keep the rows, record the identity.
    pub fn pair_rebind(
        &self,
        pair: i64,
        root_ino: u64,
        root_birth_ns: i64,
    ) -> Result<(), StateError> {
        self.read(|c| set_pair_identity(c, pair, root_ino, root_birth_ns))
    }

    /// Sorted by key.
    pub fn base_all(&self, pair: i64) -> Result<Vec<BaseRow>, StateError> {
        self.read(|c| tables::base_all(c, pair))
    }

    pub fn base_put(&self, pair: i64, rows: &[BaseRow]) -> Result<(), StateError> {
        self.txn(|c| {
            rows.iter()
                .try_for_each(|row| tables::base_upsert(c, pair, row))
        })
    }

    pub fn base_forget(&self, pair: i64, keys: &[String]) -> Result<(), StateError> {
        self.txn(|c| {
            keys.iter()
                .try_for_each(|key| tables::base_delete(c, pair, key))
        })
    }

    pub fn ledger_add(&self, ts_ms: u64, dir: LedgerDir, bytes: u64) -> Result<(), StateError> {
        self.read(|c| {
            c.execute(
                "INSERT INTO ledger (ts_ms, dir, bytes) VALUES (?, ?, ?)",
                params![tables::to_i(ts_ms)?, dir.code(), tables::to_i(bytes)?],
            )?;
            Ok(())
        })
    }

    /// Also prunes older rows.
    pub fn ledger_sum_24h(&self, now_ms: u64, dir: LedgerDir) -> Result<u64, StateError> {
        let since = tables::to_i(now_ms.saturating_sub(LEDGER_WINDOW_MS))?;
        self.txn(|c| {
            c.execute("DELETE FROM ledger WHERE ts_ms < ?", params![since])?;
            let sum: i64 = c.query_row(
                "SELECT coalesce(sum(bytes), 0) FROM ledger WHERE dir = ?",
                params![dir.code()],
                |r| r.get(0),
            )?;
            tables::to_u(sum)
        })
    }

    /// Staged ops, plus 1 if a sealed segment waits in `outbox`.
    pub fn pending_count(&self) -> Result<u64, StateError> {
        self.read(tables::pending_count)
    }
}

fn set_pair_identity(
    c: &Connection,
    pair: i64,
    root_ino: u64,
    root_birth_ns: i64,
) -> Result<(), StateError> {
    c.execute(
        "UPDATE pairs SET root_ino = ?, root_birth_ns = ? WHERE id = ?",
        params![root_ino as i64, root_birth_ns, pair],
    )?;
    Ok(())
}

/// Open `File` holding the kernel lock (`<state>/lock`, §8.3); released on drop / process death.
pub struct StateLock {
    file: std::fs::File,
}

impl Drop for StateLock {
    fn drop(&mut self) {
        // Closing the descriptor releases the lock as well; this only makes it prompt.
        let _ = self.file.unlock();
    }
}

fn lock_file(state_dir: &Path) -> Result<std::fs::File, StateError> {
    util::create_dir_private(state_dir)?;
    Ok(std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(state_dir.join("lock"))?)
}

fn try_acquire(file: &std::fs::File) -> Result<bool, StateError> {
    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// `StateError::Locked` on timeout.
pub fn lock_exclusive(state_dir: &Path, wait: Duration) -> Result<StateLock, StateError> {
    let file = lock_file(state_dir)?;
    let deadline = Instant::now() + wait;
    loop {
        if try_acquire(&file)? {
            return Ok(StateLock { file });
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(StateError::Locked);
        }
        std::thread::sleep(left.min(Duration::from_millis(50)));
    }
}

pub fn try_lock(state_dir: &Path) -> Result<Option<StateLock>, StateError> {
    let file = lock_file(state_dir)?;
    Ok(try_acquire(&file)?.then_some(StateLock { file }))
}

/// What `try_lock_existing` found.
pub enum Existing {
    Held(StateLock),
    /// Another gclone holds the lock.
    Busy,
    /// There is no lock file: this vault has no state on this device (any more).
    Gone,
}

/// `try_lock` for a process that must never create state — a running `gclone web`, which a
/// `gclone logout --forget` may have taken the state directory from (§7.4): neither the
/// directory nor the lock file is created.
pub fn try_lock_existing(state_dir: &Path) -> Result<Existing, StateError> {
    let file = match std::fs::OpenOptions::new()
        .write(true)
        .open(state_dir.join("lock"))
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Existing::Gone),
        Err(e) => return Err(e.into()),
    };
    Ok(match try_acquire(&file)? {
        true => Existing::Held(StateLock { file }),
        false => Existing::Busy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DeviceId, EntryKind, Stamp, StatSig};
    use std::os::unix::fs::PermissionsExt;

    fn row(key: &str, ino: u64) -> BaseRow {
        BaseRow {
            key: key.into(),
            rel: key.to_uppercase(),
            kind: EntryKind::File,
            sig: StatSig {
                size: 7,
                mtime_ns: -5,
                ctime_ns: 9,
                ino,
                mode: 0o100644,
            },
            hash: [3; 32],
            remote_stamp: Stamp {
                lamport: 4,
                device: DeviceId([1; 8]),
                idx: 2,
            },
            observed_ns: 11,
        }
    }

    #[test]
    fn open_creates_a_private_file_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("state.db");
        let db = Db::open(&path).unwrap();
        db.meta_set("k", b"v").unwrap();
        db.meta_set_u64("n", u64::MAX).unwrap();
        drop(db);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let db = Db::open(&path).unwrap();
        assert_eq!(db.meta_get("k").unwrap().as_deref(), Some(&b"v"[..]));
        assert_eq!(db.meta_get_u64("n").unwrap(), Some(u64::MAX));
        assert_eq!(db.meta_get("absent").unwrap(), None);
        let (mode, sync, version): (String, i64, i64) = db
            .read(|c| {
                Ok::<_, StateError>((
                    c.pragma_query_value(None, "journal_mode", |r| r.get(0))?,
                    c.pragma_query_value(None, "synchronous", |r| r.get(0))?,
                    c.pragma_query_value(None, "user_version", |r| r.get(0))?,
                ))
            })
            .unwrap();
        assert_eq!((mode.as_str(), sync, version), ("wal", 2, 1));
    }

    /// The lock for a process that must not create state (`gclone web` after `logout
    /// --forget`).
    #[test]
    fn try_lock_existing_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        assert!(matches!(try_lock_existing(&state).unwrap(), Existing::Gone));
        assert!(!state.exists(), "no directory was made");
        std::fs::create_dir(&state).unwrap();
        assert!(matches!(try_lock_existing(&state).unwrap(), Existing::Gone));
        assert!(!state.join("lock").exists(), "no lock file was made");

        let held = try_lock(&state).unwrap().expect("the lock");
        assert!(matches!(try_lock_existing(&state).unwrap(), Existing::Busy));
        drop(held);
        let Existing::Held(lock) = try_lock_existing(&state).unwrap() else {
            panic!("the lock is free");
        };
        assert!(try_lock(&state).unwrap().is_none(), "it is the same lock");
        drop(lock);
        assert!(try_lock(&state).unwrap().is_some());
    }

    #[test]
    fn a_foreign_or_newer_database_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA user_version = 2;").unwrap();
        drop(conn);
        assert!(matches!(Db::open(&path), Err(StateError::Corrupt(_))));
    }

    /// A `state.db` written before the `heads_losers` index and the `touched` table existed
    /// gets both at its next open, and its next resolution looks at every head once.
    #[test]
    fn an_older_database_gets_the_later_additions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        drop(Db::open(&path).unwrap());
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("DROP INDEX heads_losers; DROP TABLE touched;")
            .unwrap();
        drop(conn);

        // A process without the lock changes nothing …
        let shared = Db::open_shared(&path).unwrap();
        let count = |db: &Db| -> i64 {
            db.read(|c| {
                c.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name IN ('heads_losers', 'touched')",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap()
        };
        assert_eq!(count(&shared), 0);
        drop(shared);
        // … the next ordinary open adds them.
        let db = Db::open(&path).unwrap();
        assert_eq!(count(&db), 2);
        assert_eq!(db.read(tables::touched_paths).unwrap(), None);
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(count(&db), 2);
    }

    #[test]
    fn pairs_and_base_rows() {
        let db = Db::open_in_memory().unwrap();
        let p = db.pair_open("/a", "docs", u64::MAX - 1, 77, false).unwrap();
        assert_eq!(p.identity, PairIdentity::New);
        let same = db.pair_open("/a", "docs", u64::MAX - 1, 77, true).unwrap();
        assert_eq!((same.id, same.identity), (p.id, PairIdentity::Same));
        // an unavailable birth time leaves the decision to the inode number
        assert_eq!(
            db.pair_open("/a", "docs", u64::MAX - 1, 0, true)
                .unwrap()
                .identity,
            PairIdentity::Same
        );
        assert_eq!(
            db.pair_open("/a", "docs", u64::MAX - 1, 78, true)
                .unwrap()
                .identity,
            PairIdentity::Changed
        );
        assert_eq!(
            db.pair_open("/a", "docs", 5, 77, true).unwrap().identity,
            PairIdentity::Changed
        );
        let other = db.pair_open("/a", "pics", 5, 77, true).unwrap();
        assert_ne!(other.id, p.id);

        db.base_put(p.id, &[row("b", u64::MAX), row("a", 1)])
            .unwrap();
        db.base_put(other.id, &[row("z", 2)]).unwrap();
        let rows = db.base_all(p.id).unwrap();
        assert_eq!(rows, vec![row("a", 1), row("b", u64::MAX)]);

        // a changed identity never discards rows by itself
        db.pair_open("/a", "docs", 5, 78, true).unwrap();
        assert_eq!(db.base_all(p.id).unwrap().len(), 2);
        db.pair_rebind(p.id, 5, 78).unwrap();
        assert_eq!(
            db.pair_open("/a", "docs", 5, 78, true).unwrap().identity,
            PairIdentity::Same
        );
        assert_eq!(db.base_all(p.id).unwrap().len(), 2);

        db.base_forget(p.id, &["a".into(), "nope".into()]).unwrap();
        assert_eq!(db.base_all(p.id).unwrap(), vec![row("b", u64::MAX)]);
        db.pair_reset(p.id, 6, 79).unwrap();
        assert!(db.base_all(p.id).unwrap().is_empty());
        assert_eq!(db.base_all(other.id).unwrap().len(), 1);
        assert_eq!(
            db.pair_open("/a", "docs", 6, 79, true).unwrap().identity,
            PairIdentity::Same
        );
    }

    #[test]
    fn ledger_sums_the_last_24_hours_and_prunes() {
        let db = Db::open_in_memory().unwrap();
        let day = LEDGER_WINDOW_MS;
        db.ledger_add(1_000, LedgerDir::Up, 10).unwrap();
        db.ledger_add(day, LedgerDir::Up, 20).unwrap();
        db.ledger_add(day + 500, LedgerDir::Down, 7).unwrap();
        assert_eq!(db.ledger_sum_24h(day + 999, LedgerDir::Up).unwrap(), 30);
        assert_eq!(db.ledger_sum_24h(day + 1_001, LedgerDir::Up).unwrap(), 20);
        assert_eq!(db.ledger_sum_24h(day + 1_001, LedgerDir::Down).unwrap(), 7);
        let left: i64 = db
            .read(|c| c.query_row("SELECT count(*) FROM ledger", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(left, 2);
        assert_eq!(db.ledger_sum_24h(3 * day, LedgerDir::Up).unwrap(), 0);
        assert_eq!(db.pending_count().unwrap(), 0);
    }

    #[test]
    fn the_lock_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("vault");
        let held = lock_exclusive(&state, Duration::from_millis(10)).unwrap();
        assert!(try_lock(&state).unwrap().is_none());
        let started = Instant::now();
        assert!(matches!(
            lock_exclusive(&state, Duration::from_millis(120)),
            Err(StateError::Locked)
        ));
        assert!(started.elapsed() >= Duration::from_millis(120));
        drop(held);
        let again = try_lock(&state).unwrap();
        assert!(again.is_some());
        drop(again);
        lock_exclusive(&state, Duration::ZERO).unwrap();
    }

    /// `(sql, times SQLite compiled it again)` for every statement the connection holds.
    fn reprepared(c: &Connection) -> Vec<(String, i32)> {
        use rusqlite::ffi;
        let mut out = Vec::new();
        // SAFETY: the connection is borrowed for the whole walk; the statements it lists are
        // the ones in rusqlite's cache, which nothing finalizes meanwhile.
        unsafe {
            let db = c.handle();
            let mut stmt = ffi::sqlite3_next_stmt(db, std::ptr::null_mut());
            while !stmt.is_null() {
                let sql = std::ffi::CStr::from_ptr(ffi::sqlite3_sql(stmt))
                    .to_string_lossy()
                    .into_owned();
                let n = ffi::sqlite3_stmt_status(stmt, ffi::SQLITE_STMTSTATUS_REPREPARE, 0);
                out.push((sql, n));
                stmt = ffi::sqlite3_next_stmt(db, stmt);
            }
        }
        out
    }

    /// Applying an op binds new values to the same few statements again and again. SQLite
    /// compiles a statement anew when a bound value might change its plan (it looks at the
    /// value where a partial index could apply); with the planner's stability guarantee
    /// switched on it never does. Without it two statements of every `Put` were compiled
    /// hundreds of thousands of times in the first refresh of a large vault.
    #[test]
    fn binding_values_never_recompiles_a_statement() {
        use crate::index::apply::HeadStore;
        use crate::types::Entry;
        let db = Db::open_in_memory().unwrap();
        db.txn(|c| {
            let mut store = tables::SqlStore(c);
            for i in 0..200u32 {
                let entry = Entry {
                    kind: EntryKind::File,
                    size: u64::from(i),
                    mtime_ns: 1,
                    exec: false,
                    hash: [i as u8; 32],
                    loc: None,
                };
                let path = format!("dir/file-{}", i % 150);
                let stamp = Stamp {
                    lamport: u64::from(i) + 1,
                    device: DeviceId([1; 8]),
                    idx: 0,
                };
                if i % 3 == 0 {
                    let base = Stamp {
                        lamport: u64::from(i),
                        ..stamp
                    };
                    store.supersede(&path, &base, 5, stamp)?;
                }
                store.insert_head(&path, stamp, &entry, None)?;
                assert!(!store.heads(&path)?.is_empty());
            }
            Ok::<_, StateError>(())
        })
        .unwrap();
        let again: Vec<(String, i32)> = db
            .read(|c| Ok::<_, StateError>(reprepared(c)))
            .unwrap()
            .into_iter()
            .filter(|(_, n)| *n > 0)
            .collect();
        assert!(again.is_empty(), "compiled again: {again:#?}");
    }
}

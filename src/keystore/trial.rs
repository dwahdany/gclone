//! The Secure Enclave trial (SPEC §8.2): before a device depends on the enclave, gclone keeps
//! an enclave key that seals a random test value — never the secrets — and opens it in every
//! run, in whatever session that run is. `keystore-trial.json` records what was seen: on how
//! many days it worked, whether it worked after a restart, in which sessions, and every
//! failure. The record decides nothing: it is what `gclone status` shows, and what `gclone
//! keystore use enclave` tells the owner before the plain file is removed.

use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::seal::{SealError, Sealer, probe};
use crate::config::Paths;
use crate::util;

const VERSION: u32 = 1;
/// Larger than any record this code writes; anything bigger is not ours.
const FILE_MAX: u64 = 256 * 1024;
/// `ok` holds one entry per (day, boot, session), the newest this many.
pub(crate) const OK_MAX: usize = 64;
/// `failures` holds the newest this many; `failure_count` counts all.
pub(crate) const FAILURES_KEPT: usize = 5;
/// Days with a success that make the trial complete (together with a restart and no failure).
pub(crate) const DAYS_NEEDED: usize = 3;
const DAY_MS: u64 = 86_400_000;
/// A machine that could not make a key is asked again after this long (or after a restart or
/// a system update).
const UNAVAILABLE_RETRY_MS: u64 = 7 * DAY_MS;
/// How long a command waits for the trial's step of its run. The step calls into the Secure
/// Enclave from whatever session the command runs in — sessions nobody measured among them —
/// and nothing a device that never chose the sealed store does may wait for that without a
/// bound.
pub(crate) const STEP_WAIT: Duration = Duration::from_secs(2);
/// After a step that did not come back in time, the same boot and session are left alone for
/// this long: one slow command, not every command.
const TIMEOUT_REST_MS: u64 = DAY_MS;
/// How long a writer of the record waits for another one (each holds the lock for a
/// read-change-write of a small file).
const RECORD_LOCK_WAIT: Duration = Duration::from_millis(1500);
/// `SessionGetInfo`: the session has graphic access (a logged-in desktop).
const SESSION_HAS_GRAPHIC_ACCESS: u32 = 0x10;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct OkEntry {
    /// The UTC day number (days since 1970-01-01).
    pub day: u64,
    pub boot: String,
    pub session: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Failure {
    pub ms: u64,
    pub boot: String,
    pub session: String,
    /// Whether a key made at that moment worked: yes = the stored key is the problem, no =
    /// the session could not use the enclave at all.
    pub fresh_key_ok: bool,
    pub error: String,
    /// The step did not come back within `STEP_WAIT`: nothing is known beyond that (no key
    /// was tried afterwards).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub timed_out: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Unavailable {
    pub ms: u64,
    pub boot: String,
    #[serde(default)]
    pub os: String,
    /// The session that could not make a key: the failure says something about that session,
    /// and about the machine only if the session had graphic access.
    #[serde(default)]
    pub session: String,
    pub error: String,
}

impl Unavailable {
    /// The failure happened in a logged-in desktop session: then it is the machine that has
    /// no usable Secure Enclave, not the session that has no access to it.
    pub(crate) fn says_no_hardware(&self) -> bool {
        session_kind(&self.session) == "with graphic access"
    }
}

/// Notes that are shown once.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Notes {
    /// "The trial is complete" was shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_ms: Option<u64>,
}

/// `keystore-trial.json`. Every member but `version` is optional. Nothing in it is vault key
/// material or a token: `key` is the blob of the trial's own enclave key, `canary` 32 random
/// bytes sealed to it.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Record {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_boot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ok: Vec<OkEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<Failure>,
    #[serde(default)]
    pub failure_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<Unavailable>,
    /// When `gclone keystore use enclave` moved the secrets and ended this trial. Whether it
    /// was the trial's key that took them is not recorded here but read off the files: the
    /// record keeps `public`, and `secrets.sealed` names the key it is sealed to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moved_ms: Option<u64>,
    #[serde(default)]
    pub notes: Notes,
}

/// The decoded members of a record that holds a key.
struct KeyParts {
    blob: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
    /// The sealed test value.
    canary: Vec<u8>,
    canary_hash: String,
}

/// The moment and place of one run.
#[derive(Clone, Debug)]
pub(crate) struct Moment {
    pub ms: u64,
    /// Names the boot (`kern.bootsessionuuid`); does not depend on the clock.
    pub boot: String,
    /// The attribute word of the caller's security session, as `0x2030`; `"none"` without one.
    pub session: String,
    pub os: String,
}

impl Moment {
    /// Now and here. Debug builds honour `GCLONE_TEST_NOW_MS`, `GCLONE_TEST_BOOT` and
    /// `GCLONE_TEST_SESSION` (§7.1), so that a test can age a trial and move it between
    /// sessions.
    pub(crate) fn now() -> Moment {
        let test = crate::cli::test_env;
        #[cfg(target_os = "macos")]
        let (boot, session, os) = (
            super::macos::boot_session(),
            super::macos::session_attributes().map(|word| format!("{word:#x}")),
            super::macos::os_version(),
        );
        #[cfg(not(target_os = "macos"))]
        let (boot, session, os): (Option<String>, Option<String>, Option<String>) =
            (None, None, None);
        Moment {
            ms: test("GCLONE_TEST_NOW_MS")
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(util::now_ms),
            boot: test("GCLONE_TEST_BOOT")
                .or(boot)
                .unwrap_or_else(|| "unknown".into()),
            session: test("GCLONE_TEST_SESSION")
                .or(session)
                .unwrap_or_else(|| "none".into()),
            os: os.unwrap_or_default(),
        }
    }

    fn day(&self) -> u64 {
        self.ms / DAY_MS
    }
}

/// "with graphic access" / "without graphic access", from a session word.
pub(crate) fn session_kind(word: &str) -> &'static str {
    let bits = word
        .strip_prefix("0x")
        .and_then(|hex| u32::from_str_radix(hex, 16).ok());
    match bits {
        Some(bits) if bits & SESSION_HAS_GRAPHIC_ACCESS != 0 => "with graphic access",
        Some(_) => "without graphic access",
        None => "no login session",
    }
}

/// What the record amounts to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Summary {
    /// A key exists and is being tested.
    pub running: bool,
    /// Distinct days with a success.
    pub days: usize,
    /// A success in another boot than the one the key was made in.
    pub restart: bool,
    /// The distinct sessions with a success, as recorded.
    pub sessions: Vec<String>,
    pub failures: u64,
    pub last_failures: Vec<Failure>,
    /// At least `DAYS_NEEDED` days, a restart survived, and no failure.
    pub complete: bool,
    /// No key could be made: when, in which session, and the error.
    pub unavailable: Option<Unavailable>,
    /// `gclone keystore use enclave` ended the trial (whose key took the secrets, or not:
    /// `public` against the sealed file's).
    pub moved: bool,
    /// The public half of the trial's key, as recorded.
    pub public: Option<String>,
}

impl Record {
    pub(crate) fn summary(&self) -> Summary {
        let mut days: Vec<u64> = self.ok.iter().map(|e| e.day).collect();
        days.sort_unstable();
        days.dedup();
        let mut sessions: Vec<String> = self.ok.iter().map(|e| e.session.clone()).collect();
        sessions.sort();
        sessions.dedup();
        let restart = match &self.created_boot {
            Some(created) => self.ok.iter().any(|e| &e.boot != created),
            None => false,
        };
        let running = self.key.is_some() && self.canary.is_some();
        Summary {
            running,
            days: days.len(),
            restart,
            sessions,
            failures: self.failure_count,
            last_failures: self.failures.clone(),
            complete: running && days.len() >= DAYS_NEEDED && restart && self.failure_count == 0,
            unavailable: self.unavailable.clone(),
            moved: self.moved_ms.is_some(),
            public: self.public.clone(),
        }
    }

    /// A success now. `true` = the record changed (this day, boot and session were not seen
    /// together before).
    pub(crate) fn note_ok(&mut self, at: &Moment) -> bool {
        let entry = OkEntry {
            day: at.day(),
            boot: at.boot.clone(),
            session: at.session.clone(),
        };
        if self.ok.contains(&entry) {
            return false;
        }
        self.ok.push(entry);
        if self.ok.len() > OK_MAX {
            let extra = self.ok.len() - OK_MAX;
            self.ok.drain(..extra);
        }
        true
    }

    pub(crate) fn note_failure(&mut self, at: &Moment, fresh_key_ok: bool, error: &SealError) {
        self.failure_count = self.failure_count.saturating_add(1);
        self.failures.push(Failure {
            ms: at.ms,
            boot: at.boot.clone(),
            session: at.session.clone(),
            fresh_key_ok,
            error: error.0.clone(),
            timed_out: false,
        });
        self.trim_failures();
    }

    /// The step of `at` did not come back within `STEP_WAIT`.
    fn note_timeout(&mut self, at: &Moment) {
        self.failure_count = self.failure_count.saturating_add(1);
        self.failures.push(Failure {
            ms: at.ms,
            boot: at.boot.clone(),
            session: at.session.clone(),
            fresh_key_ok: false,
            error: format!(
                "the call into the Secure Enclave did not return within {} s",
                STEP_WAIT.as_secs()
            ),
            timed_out: true,
        });
        self.trim_failures();
    }

    /// A step timed out in this boot and session not long ago: they are left alone.
    fn resting(&self, at: &Moment) -> bool {
        self.failures.iter().any(|f| {
            f.timed_out
                && f.boot == at.boot
                && f.session == at.session
                && at.ms.saturating_sub(f.ms) < TIMEOUT_REST_MS
        })
    }

    fn trim_failures(&mut self) {
        if self.failures.len() > FAILURES_KEPT {
            let extra = self.failures.len() - FAILURES_KEPT;
            self.failures.drain(..extra);
        }
    }

    /// The trial's key, if it has one.
    fn key_parts(&self) -> Option<KeyParts> {
        Some(KeyParts {
            blob: Zeroizing::new(util::unb64url(self.key.as_deref()?)?),
            public: util::unb64url(self.public.as_deref()?)?,
            canary: util::unb64url(self.canary.as_deref()?)?,
            canary_hash: self.canary_hash.clone()?,
        })
    }

    /// Opens the test value with the stored key and compares it with its hash.
    pub(crate) fn open_canary(&self, sealer: &dyn Sealer) -> Result<(), SealError> {
        let key = self
            .key_parts()
            .ok_or_else(|| SealError("the trial record holds no usable key".into()))?;
        let value = sealer.open(&key.blob, &key.public, &key.canary)?;
        if blake3::hash(&value).to_hex().as_str() == key.canary_hash {
            Ok(())
        } else {
            Err(SealError(
                "the test value opened to something else than was sealed".into(),
            ))
        }
    }

    /// The trial's key for the secrets (`gclone keystore use enclave`): `(blob, public)`.
    pub(crate) fn key_for_secrets(&self) -> Option<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        self.key_parts().map(|key| (key.blob, key.public))
    }

    /// A new key and test value in place of whatever the record held; the notes stay.
    #[cfg(test)]
    fn start(&mut self, sealer: &dyn Sealer, at: &Moment) -> Result<(), SealError> {
        let key = NewKey::make(sealer)?;
        self.begin(key, at);
        Ok(())
    }

    /// The record of a trial that starts now with `key`. The notes stay. What a record that
    /// never held a key says about this device stays too, as failures of the new trial: the
    /// session that could not make a key (`unavailable`) and the steps that did not come
    /// back. A trial that began with "no key can be made in session 0x2" is not complete
    /// before somebody looked at that (`gclone keystore check --new-trial` clears it).
    fn begin(&mut self, key: NewKey, at: &Moment) {
        let never_had_a_key = self.public.is_none();
        let mut failures = Vec::new();
        let mut failure_count = 0;
        if never_had_a_key {
            failures.clone_from(&self.failures);
            failure_count = self.failure_count;
            if let Some(u) = &self.unavailable {
                failure_count += 1;
                failures.push(Failure {
                    ms: u.ms,
                    boot: u.boot.clone(),
                    session: u.session.clone(),
                    fresh_key_ok: false,
                    error: format!("no key could be made: {}", u.error),
                    timed_out: false,
                });
            }
        }
        *self = Record {
            version: VERSION,
            public: Some(util::b64url(&key.public)),
            key: Some(util::b64url(&key.blob)),
            canary: Some(util::b64url(&key.canary)),
            canary_hash: Some(key.canary_hash),
            created_ms: Some(at.ms),
            created_boot: Some(at.boot.clone()),
            os: Some(at.os.clone()),
            failures,
            failure_count,
            notes: self.notes.clone(),
            ..Record::default()
        };
        self.trim_failures();
        self.note_ok(at);
    }

    /// The record after `gclone keystore use enclave`: the trial is over, its evidence stays
    /// (with `public`, which says whose evidence it is), its key goes.
    pub(crate) fn moved(mut self, at_ms: u64) -> Record {
        self.key = None;
        self.canary = None;
        self.canary_hash = None;
        self.moved_ms = Some(at_ms);
        self
    }

    /// Whether a session that could not make a key is asked again now: in another boot, on
    /// another system version, after a week — and at once in any OTHER session, about which
    /// the failure says nothing.
    fn retry_unavailable(&self, at: &Moment) -> bool {
        match &self.unavailable {
            None => true,
            Some(u) => {
                u.boot != at.boot
                    || u.os != at.os
                    || u.session != at.session
                    || at.ms.saturating_sub(u.ms) >= UNAVAILABLE_RETRY_MS
            }
        }
    }
}

/// A key made for a trial, with its sealed test value: everything of a new record that comes
/// from the Secure Enclave.
struct NewKey {
    blob: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
    canary: Vec<u8>,
    canary_hash: String,
}

impl NewKey {
    fn make(sealer: &dyn Sealer) -> Result<NewKey, SealError> {
        let (blob, public) = sealer.create()?;
        let value: Zeroizing<[u8; 32]> = Zeroizing::new(util::random());
        let canary = sealer.seal(&public, value.as_slice())?;
        if sealer.open(&blob, &public, &canary)?.as_slice() != value.as_slice() {
            return Err(SealError(
                "a test value sealed to a new key did not open to itself".into(),
            ));
        }
        Ok(NewKey {
            blob,
            public,
            canary,
            canary_hash: blake3::hash(value.as_slice()).to_hex().to_string(),
        })
    }
}

/// What is on disk.
pub(crate) enum Stored {
    Absent,
    Record(Box<Record>),
    /// There is a file and it is not a record this version reads: replaced by a new trial.
    Unreadable,
}

pub(crate) fn load(paths: &Paths) -> Stored {
    let file = match std::fs::File::open(paths.trial_file()) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Stored::Absent,
        Err(_) => return Stored::Unreadable,
    };
    let mut bytes = Vec::new();
    if file.take(FILE_MAX + 1).read_to_end(&mut bytes).is_err() || bytes.len() as u64 > FILE_MAX {
        return Stored::Unreadable;
    }
    match serde_json::from_slice::<Record>(&bytes) {
        Ok(record) if record.version == VERSION => Stored::Record(Box::new(record)),
        _ => Stored::Unreadable,
    }
}

/// The record, or an empty one.
pub(crate) fn load_or_new(paths: &Paths) -> Record {
    match load(paths) {
        Stored::Record(record) => *record,
        _ => Record {
            version: VERSION,
            ..Record::default()
        },
    }
}

/// Writes the record. Callers hold the record's lock ([`update`]); tests write it directly.
pub(crate) fn save(paths: &Paths, record: &Record) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(record).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    util::write_atomic(&paths.trial_file(), &bytes, 0o600)
}

/// The kernel lock of `keystore-trial.lock`; released on drop and when the process dies.
struct RecordLock(std::fs::File);

impl Drop for RecordLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

fn lock_record(paths: &Paths) -> Option<RecordLock> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(paths.trial_lock())
        .ok()?;
    let deadline = Instant::now() + RECORD_LOCK_WAIT;
    loop {
        match file.try_lock() {
            Ok(()) => return Some(RecordLock(file)),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(_)) => return None,
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        std::thread::sleep(left.min(Duration::from_millis(10)));
    }
}

/// One change of the record: under its lock, on the record as it is on disk NOW, written back
/// if `change` says it changed. Every process of a device runs a step, several at once when a
/// scheduler starts them together, and each used to write back the copy it had loaded before
/// its call into the enclave — the later writer undid the earlier one's entry (a failure, a
/// note). `change` must not call into the Secure Enclave: the lock is held for a
/// read-change-write and nothing else. `false`: the lock could not be had in time (or the
/// record could not be written) and nothing was changed — the step is skipped, never waited
/// for.
pub(crate) fn update(paths: &Paths, change: impl FnOnce(&mut Record) -> bool) -> bool {
    let Some(_lock) = lock_record(paths) else {
        tracing::debug!("Secure Enclave trial: the record is busy; this step is skipped");
        return false;
    };
    let mut record = load_or_new(paths);
    if !change(&mut record) {
        return true;
    }
    match save(paths, &record) {
        Ok(()) => true,
        Err(e) => {
            tracing::debug!("Secure Enclave trial: cannot write the record: {e}");
            false
        }
    }
}

/// `GCLONE_KEYSTORE_TRIAL=0`: no trial and no trial file in this process.
pub(crate) fn disabled_by_env() -> bool {
    std::env::var("GCLONE_KEYSTORE_TRIAL").is_ok_and(|v| v.trim() == "0")
}

fn ready_note(days: usize) -> String {
    format!(
        "note: this Mac's Secure Enclave has opened gclone's test value on {days} days, across a \
         restart, in every session gclone ran in. `gclone keystore use enclave` moves this \
         device's key and login out of the plain file; it checks your passphrase first. `gclone \
         keystore use file` keeps the plain file and silences this note."
    )
}

/// What one step found, about the key whose public half is `about` (`None`: there was none).
enum Outcome {
    Started(NewKey),
    Unavailable(SealError),
    Opened,
    Failed {
        fresh_key_ok: bool,
        error: SealError,
    },
}

/// One step of the trial, for a device whose secrets are in the plain file. Never fails and
/// never touches the secrets: whatever goes wrong is written into the record, or dropped.
///
/// Two halves. The first calls into the Secure Enclave and holds no lock: it works on the
/// record as it was read. The second writes what was found into the record as it is by then
/// ([`update`]) — if another process changed the trial's key in between, what this step found
/// is about a key that is gone, and it is dropped.
pub(crate) fn step(paths: &Paths, sealer: &dyn Sealer) {
    let at = Moment::now();
    let seen = load_or_new(paths);
    if seen.resting(&at) {
        return;
    }
    let about = seen.key_parts().map(|_| seen.public.clone());
    let outcome = match &about {
        // No key yet — or a record whose trial ended with a move, on a device that is back
        // on the plain file: a new key and a new record.
        None => {
            if !seen.retry_unavailable(&at) {
                return;
            }
            match NewKey::make(sealer) {
                Ok(key) => Outcome::Started(key),
                Err(e) => {
                    tracing::debug!("Secure Enclave trial: no key can be made here: {e}");
                    Outcome::Unavailable(e)
                }
            }
        }
        Some(_) => match seen.open_canary(sealer) {
            Ok(()) => Outcome::Opened,
            Err(e) => {
                tracing::debug!("Secure Enclave trial: the test value did not open: {e}");
                Outcome::Failed {
                    fresh_key_ok: probe(sealer).is_ok(),
                    error: e,
                }
            }
        },
    };
    update(paths, |record| {
        let same_key = record.key_parts().map(|_| record.public.clone()) == about;
        let mut changed = match outcome {
            // Another process started a trial in the meantime: its key stays, this one is
            // dropped (and with it the handle of an enclave key nothing refers to).
            Outcome::Started(_) | Outcome::Unavailable(_) if !same_key => false,
            Outcome::Started(key) => {
                record.begin(key, &at);
                true
            }
            Outcome::Unavailable(e) => {
                record.unavailable = Some(Unavailable {
                    ms: at.ms,
                    boot: at.boot.clone(),
                    os: at.os.clone(),
                    session: at.session.clone(),
                    error: e.0,
                });
                true
            }
            Outcome::Opened | Outcome::Failed { .. } if !same_key => false,
            Outcome::Opened => record.note_ok(&at),
            Outcome::Failed {
                fresh_key_ok,
                error,
            } => {
                record.note_failure(&at, fresh_key_ok, &error);
                true
            }
        };
        let summary = record.summary();
        if summary.complete && record.notes.ready_ms.is_none() && super::can_show_notes() {
            eprintln!("{}", ready_note(summary.days));
            record.notes.ready_ms = Some(at.ms);
            changed = true;
        }
        changed
    });
}

/// [`step`] for a command that has other work to do: on a thread of its own, awaited for at
/// most [`STEP_WAIT`]. The step calls into Security.framework in whatever session the command
/// runs in — a scheduler's, an ssh login's, before the first unlock — and a call that does
/// not return must not hold up a device that never asked for the sealed store. When the wait
/// runs out the command goes on, the record gets a failure ("did not return"), and this boot
/// and session are left alone for a day; the thread ends with the process.
pub(crate) fn step_bounded(paths: &Paths, sealer: Arc<dyn Sealer>) {
    step_within(paths, sealer, STEP_WAIT);
}

fn step_within(paths: &Paths, sealer: Arc<dyn Sealer>, wait: Duration) {
    let at = Moment::now();
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let for_thread = paths.clone();
    let spawned = std::thread::Builder::new()
        .name("keystore-trial".into())
        .spawn(move || {
            step(&for_thread, sealer.as_ref());
            let _ = done.send(());
        });
    if spawned.is_err() {
        return;
    }
    if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = finished.recv_timeout(wait) {
        tracing::debug!("Secure Enclave trial: the step did not return in time; going on");
        update(paths, |record| {
            record.note_timeout(&at);
            true
        });
    }
}

/// `gclone keystore check --new-trial`: forget the record (the notes stay) and start a new
/// key.
pub(crate) fn restart(paths: &Paths, sealer: &dyn Sealer) -> Result<(), SealError> {
    let at = Moment::now();
    let made = NewKey::make(sealer);
    let mut started = Ok(());
    let written = update(paths, |record| {
        let mut fresh = Record {
            version: VERSION,
            notes: record.notes.clone(),
            ..Record::default()
        };
        match made {
            Ok(key) => fresh.begin(key, &at),
            Err(e) => {
                fresh.unavailable = Some(Unavailable {
                    ms: at.ms,
                    boot: at.boot.clone(),
                    os: at.os.clone(),
                    session: at.session.clone(),
                    error: e.0.clone(),
                });
                started = Err(e);
            }
        }
        *record = fresh;
        true
    });
    if !written {
        return Err(SealError("cannot write the trial record".into()));
    }
    started
}

/// `gclone keystore use enclave` moved the secrets: the trial is over.
pub(crate) fn end_at_move(paths: &Paths, at_ms: u64) {
    update(paths, |record| {
        *record = std::mem::take(record).moved(at_ms);
        true
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::seal::{FakeFail, FakeSealer};
    use std::path::Path;

    fn paths(root: &Path) -> Paths {
        let p = Paths {
            config_dir: root.join("config"),
            state_root: root.join("state"),
        };
        util::create_dir_private(&p.state_root).unwrap();
        p
    }

    fn at(day: u64, boot: &str, session: &str) -> Moment {
        Moment {
            ms: day * DAY_MS + 5,
            boot: boot.into(),
            session: session.into(),
            os: "27.2".into(),
        }
    }

    fn started(sealer: &FakeSealer, moment: &Moment) -> Record {
        let mut record = Record::default();
        record.start(sealer, moment).unwrap();
        record
    }

    #[test]
    fn the_summary_counts_days_boots_and_sessions() {
        let sealer = FakeSealer::new("mac", None);
        let mut r = started(&sealer, &at(100, "boot-a", "0x2030"));
        let s = r.summary();
        assert!(s.running && !s.complete && !s.restart);
        assert_eq!((s.days, s.failures), (1, 0));
        assert_eq!(s.sessions, ["0x2030"]);

        assert!(!r.note_ok(&at(100, "boot-a", "0x2030")), "seen already");
        assert!(r.note_ok(&at(100, "boot-a", "0x2")), "another session");
        assert!(r.note_ok(&at(101, "boot-a", "0x2030")));
        assert!(r.note_ok(&at(102, "boot-a", "0x2030")));
        let s = r.summary();
        assert_eq!(s.days, 3);
        assert_eq!(s.sessions, ["0x2", "0x2030"]);
        assert!(!s.restart && !s.complete, "three days without a restart");

        assert!(r.note_ok(&at(102, "boot-b", "0x2030")));
        let s = r.summary();
        assert!(s.restart && s.complete);
    }

    /// The clock is not evidence of a restart: only another boot identifier is.
    #[test]
    fn a_clock_jump_alone_is_no_restart() {
        let sealer = FakeSealer::new("mac", None);
        let mut r = started(&sealer, &at(100, "boot-a", "0x2030"));
        for day in [200, 300, 4000] {
            r.note_ok(&at(day, "boot-a", "0x2030"));
        }
        let s = r.summary();
        assert_eq!(s.days, 4);
        assert!(!s.restart && !s.complete);
    }

    #[test]
    fn complete_needs_three_days_a_second_boot_and_no_failure() {
        let sealer = FakeSealer::new("mac", None);
        // a restart, but only two days
        let mut r = started(&sealer, &at(100, "boot-a", "0x2030"));
        r.note_ok(&at(101, "boot-b", "0x2030"));
        assert!(r.summary().restart && !r.summary().complete);
        r.note_ok(&at(102, "boot-b", "0x2030"));
        assert!(r.summary().complete);
        // one failure, and it never clears by itself
        r.note_failure(
            &at(103, "boot-b", "0x2"),
            true,
            &SealError("token error -3".into()),
        );
        r.note_ok(&at(104, "boot-b", "0x2030"));
        r.note_ok(&at(105, "boot-c", "0x2030"));
        let s = r.summary();
        assert!(!s.complete);
        assert_eq!(s.failures, 1);
        assert_eq!(s.last_failures[0].session, "0x2");
        assert!(s.last_failures[0].fresh_key_ok);
    }

    #[test]
    fn the_lists_are_bounded() {
        let sealer = FakeSealer::new("mac", None);
        let mut r = started(&sealer, &at(1, "boot-a", "0x2030"));
        for day in 2..200 {
            r.note_ok(&at(day, "boot-a", "0x2030"));
        }
        assert_eq!(r.ok.len(), OK_MAX);
        assert_eq!(r.ok.last().unwrap().day, 199);
        for n in 0..9 {
            r.note_failure(
                &at(300 + n, "boot-a", "0x2"),
                false,
                &SealError(format!("e{n}")),
            );
        }
        assert_eq!(r.failures.len(), FAILURES_KEPT);
        assert_eq!(r.failure_count, 9);
        assert_eq!(r.failures.last().unwrap().error, "e8");
    }

    #[test]
    fn the_record_holds_a_test_value_and_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        assert!(matches!(load(&p), Stored::Absent));
        let sealer = FakeSealer::new("mac", None);
        let r = started(&sealer, &at(100, "boot-a", "0x2030"));
        r.open_canary(&sealer).unwrap();
        save(&p, &r).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(p.trial_file())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let Stored::Record(back) = load(&p) else {
            panic!("the record just written");
        };
        assert_eq!(*back, r);
        back.open_canary(&sealer).unwrap();
        assert!(back.key_for_secrets().is_some());

        // on another machine the test value does not open
        assert!(back.open_canary(&FakeSealer::new("other", None)).is_err());

        // after the move: the evidence without the key
        let moved = back.clone().moved(7);
        assert!(moved.key.is_none() && moved.canary.is_none() && moved.canary_hash.is_none());
        assert_eq!(moved.ok, r.ok);
        assert!(moved.summary().moved && !moved.summary().running);
        assert!(moved.key_for_secrets().is_none());
    }

    #[test]
    fn an_unparsable_or_foreign_record_is_replaced_by_a_new_trial() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        let sealer = FakeSealer::new("mac", None);
        for junk in [
            &b"not json"[..],
            br#"{"version":2}"#,
            b"",
            br#"{"version":1,"ok":7}"#,
        ] {
            std::fs::write(p.trial_file(), junk).unwrap();
            assert!(matches!(load(&p), Stored::Unreadable));
            step(&p, &sealer);
            let Stored::Record(r) = load(&p) else {
                panic!("a new record");
            };
            assert!(r.summary().running);
            assert_eq!(r.ok.len(), 1);
        }
    }

    #[test]
    fn step_creates_then_opens_and_mostly_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        let sealer = FakeSealer::new("mac", None);
        step(&p, &sealer);
        let first = std::fs::read(p.trial_file()).unwrap();
        let text = String::from_utf8(first.clone()).unwrap();
        for member in [
            "public",
            "key",
            "canary",
            "canary_hash",
            "created_boot",
            "ok",
        ] {
            assert!(
                text.contains(&format!("\"{member}\"")),
                "{member} in {text}"
            );
        }
        step(&p, &sealer);
        step(&p, &sealer);
        assert_eq!(
            std::fs::read(p.trial_file()).unwrap(),
            first,
            "same day, boot, session"
        );
    }

    #[test]
    fn a_failure_is_recorded_with_what_a_fresh_key_did() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        step(&p, &FakeSealer::new("mac", None));

        // the stored key is dead, a fresh key works
        step(&p, &FakeSealer::new("mac", Some(FakeFail::OpenStored)));
        // the session cannot use the store at all
        step(&p, &FakeSealer::new("mac", Some(FakeFail::Open)));
        let r = load_or_new(&p);
        assert_eq!(r.failure_count, 2);
        assert!(r.failures[0].fresh_key_ok);
        assert!(!r.failures[1].fresh_key_ok);
        assert!(!r.summary().complete);
        // the key is kept: a failure does not start a new trial by itself
        assert!(r.summary().running);
        step(&p, &FakeSealer::new("mac", None));
        assert_eq!(load_or_new(&p).failure_count, 2);

        // --new-trial does
        restart(&p, &FakeSealer::new("mac", None)).unwrap();
        let r = load_or_new(&p);
        assert_eq!((r.failure_count, r.ok.len()), (0, 1));
    }

    #[test]
    fn a_machine_without_the_hardware_is_recorded_and_not_asked_every_run() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        let none = FakeSealer::new("mac", Some(FakeFail::Create));
        step(&p, &none);
        let r = load_or_new(&p);
        assert!(r.key.is_none());
        let unavailable = r.unavailable.clone().expect("recorded");
        assert!(unavailable.error.contains("no key can be made"));
        assert_eq!(r.summary().unavailable, Some(unavailable.clone()));
        assert_eq!(unavailable.session, Moment::now().session);
        let written = std::fs::read(p.trial_file()).unwrap();
        // the same boot and system, a moment later: not tried again, nothing written
        step(&p, &FakeSealer::new("mac", None));
        assert_eq!(std::fs::read(p.trial_file()).unwrap(), written);

        // after a week, or a restart, or a system update, it is
        let mut later = at(0, &unavailable.boot, &unavailable.session);
        later.os = unavailable.os.clone();
        later.ms = unavailable.ms + UNAVAILABLE_RETRY_MS - 1;
        assert!(!r.retry_unavailable(&later));
        later.ms += 1;
        assert!(r.retry_unavailable(&later));
        later.ms = unavailable.ms;
        later.boot = "another boot".into();
        assert!(r.retry_unavailable(&later));
        later.boot = unavailable.boot.clone();
        later.os = "99.0".into();
        assert!(r.retry_unavailable(&later));
    }

    /// A session that could not make a key says nothing about another session: the trial
    /// starts in the first one that can — at once, not after a week — and keeps what the
    /// other one said as a failure. It used to wait for another boot, another system or seven
    /// days whatever the session, and `gclone status` in a terminal meanwhile read "no Secure
    /// Enclave on this machine" on a Mac whose enclave worked.
    #[test]
    fn a_session_that_cannot_make_a_key_speaks_for_itself_alone() {
        let scheduler = at(100, "boot-a", "0x2");
        let mut r = Record {
            version: VERSION,
            unavailable: Some(Unavailable {
                ms: scheduler.ms,
                boot: scheduler.boot.clone(),
                os: scheduler.os.clone(),
                session: scheduler.session.clone(),
                error: "no key can be made here".into(),
            }),
            ..Record::default()
        };
        let u = r.unavailable.clone().unwrap();
        assert!(!u.says_no_hardware(), "a session without graphic access");
        // the same session, an hour later: left alone
        let mut same = at(100, "boot-a", "0x2");
        same.ms += 3_600_000;
        assert!(!r.retry_unavailable(&same));
        // a terminal in the same boot, an hour later: asked
        let mut desktop = at(100, "boot-a", "0x2030");
        desktop.ms += 3_600_000;
        assert!(r.retry_unavailable(&desktop));

        // … and the trial that starts there remembers the session that failed.
        let sealer = FakeSealer::new("mac", None);
        r.start(&sealer, &desktop).unwrap();
        let s = r.summary();
        assert!(s.running && s.unavailable.is_none());
        assert_eq!(s.failures, 1);
        assert_eq!(s.last_failures[0].session, "0x2");
        assert!(s.last_failures[0].error.contains("no key could be made"));
        for day in 101..104 {
            r.note_ok(&at(day, "boot-b", "0x2030"));
        }
        assert!(!r.summary().complete, "not before somebody looked at it");

        // A desktop session that cannot make a key is the machine.
        let on_desktop = Unavailable {
            session: "0x2030".into(),
            ..u
        };
        assert!(on_desktop.says_no_hardware());
        // A record without the session (none was recorded) claims nothing about the machine.
        let old: Unavailable =
            serde_json::from_str(r#"{"ms":1,"boot":"b","os":"27.2","error":"e"}"#).unwrap();
        assert!(!old.says_no_hardware());

        // A trial whose key took the secrets starts clean when the device is back on the
        // plain file: the failures of the old key are not the new one's.
        let mut moved = started(&sealer, &at(1, "boot-a", "0x2030"));
        moved.note_failure(&at(2, "boot-a", "0x2"), true, &SealError("e".into()));
        let mut moved = moved.moved(9);
        moved.start(&sealer, &at(3, "boot-a", "0x2030")).unwrap();
        assert_eq!(moved.summary().failures, 0);
    }

    /// A call into the Secure Enclave that does not return holds a command up for the
    /// bounded wait, once: the record gets a failure, and the same boot and session are not
    /// tried again for a day. (The step used to run inline in `load`, with no bound at all.)
    #[test]
    fn a_step_that_does_not_return_is_given_up_and_not_repeated() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        let hangs =
            || -> Arc<dyn Sealer> { Arc::new(FakeSealer::new("mac", Some(FakeFail::Hang))) };

        // No key yet: making one hangs.
        let before = Instant::now();
        step_within(&p, hangs(), Duration::from_millis(150));
        let waited = before.elapsed();
        assert!(
            waited >= Duration::from_millis(150) && waited < Duration::from_secs(5),
            "{waited:?}"
        );
        let r = load_or_new(&p);
        assert_eq!(r.failure_count, 1);
        assert!(r.failures[0].timed_out);
        assert!(r.failures[0].error.contains("did not return"));
        assert!(r.key.is_none());
        // The next command in this boot and session does not call into the enclave at all:
        // run on this very thread, a call would never come back.
        assert!(r.resting(&Moment::now()));
        step(&p, hangs().as_ref());
        assert_eq!(load_or_new(&p).failure_count, 1);
        // Another session, or a day later, is asked again.
        let now = Moment::now();
        let mut elsewhere = now.clone();
        elsewhere.session = "0x9999".into();
        assert!(!r.resting(&elsewhere));
        let mut later = now.clone();
        later.ms += TIMEOUT_REST_MS;
        assert!(!r.resting(&later));

        // With a key: opening the test value hangs; the key and its record stay.
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        step(&p, &FakeSealer::new("mac", None));
        let key = load_or_new(&p).key.clone();
        step_within(&p, hangs(), Duration::from_millis(150));
        let r = load_or_new(&p);
        assert_eq!((r.failure_count, r.key.clone()), (1, key));
        assert!(!r.summary().complete);
        // A trial that starts after a timeout keeps it (the record never held a key).
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        step_within(&p, hangs(), Duration::from_millis(50));
        let mut r = load_or_new(&p);
        r.start(&FakeSealer::new("mac", None), &at(5, "boot-z", "0x2030"))
            .unwrap();
        assert_eq!(r.failure_count, 1);
        assert!(r.failures[0].timed_out);
    }

    /// Every change of the record is made on the record as it is on disk at that moment:
    /// what one process wrote while another was inside the enclave is not undone.
    #[test]
    fn a_step_writes_into_the_record_as_it_is_now() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        let sealer = FakeSealer::new("mac", None);
        step(&p, &sealer);
        // Another process notes a failure and a shown note …
        assert!(update(&p, |record| {
            record.note_failure(&at(7, "boot-q", "0x2"), true, &SealError("e".into()));
            record.notes.ready_ms = Some(77);
            true
        }));
        // … and many steps at once then add their own entries without losing it.
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| step(&p, &sealer));
            }
        });
        let r = load_or_new(&p);
        assert_eq!(r.failure_count, 1);
        assert_eq!(r.notes.ready_ms, Some(77));
        assert_eq!(r.ok.len(), 1);

        // Eight first steps at once: one trial key, one record — the others drop theirs.
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| step(&p, &sealer));
            }
        });
        let r = load_or_new(&p);
        r.open_canary(&sealer)
            .expect("the key of the record opens its own test value");
        assert_eq!((r.ok.len(), r.failure_count), (1, 0));

        // What a step found about a key that is no longer the record's is dropped.
        let before = load_or_new(&p);
        let stale = before.clone();
        restart(&p, &sealer).unwrap();
        let fresh = load_or_new(&p);
        assert_ne!(fresh.public, stale.public);
        // the change is a no-op when the closure says so, and the file stays byte for byte
        let bytes = std::fs::read(p.trial_file()).unwrap();
        assert!(update(&p, |_| false));
        assert_eq!(std::fs::read(p.trial_file()).unwrap(), bytes);

        // The end of a trial at the move keeps the evidence and whose it is.
        end_at_move(&p, 99);
        let moved = load_or_new(&p);
        assert_eq!(moved.moved_ms, Some(99));
        assert_eq!(moved.public, fresh.public);
        assert!(moved.key.is_none() && moved.summary().moved);
    }

    #[test]
    fn a_record_that_cannot_be_written_changes_nothing_and_raises_nothing() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        std::fs::set_permissions(&p.state_root, std::fs::Permissions::from_mode(0o500)).unwrap();
        step(&p, &FakeSealer::new("mac", None));
        assert!(!p.trial_file().exists());
        std::fs::set_permissions(&p.state_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn session_words_are_named() {
        assert_eq!(session_kind("0x2030"), "with graphic access");
        assert_eq!(session_kind("0x2"), "without graphic access");
        assert_eq!(session_kind("0x1020"), "without graphic access");
        assert_eq!(session_kind("none"), "no login session");
    }
}

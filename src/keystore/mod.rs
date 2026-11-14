//! Where a device keeps its secrets (SPEC §8.2, §8.3, §17.28).
//!
//! Two stores hold the same thing — a `secrets.json` document: the Google login and the
//! vault's keys.
//!
//! - `file`: `secrets.json`, plain JSON, mode 0600. The version-1 format, unchanged.
//! - `enclave`: `secrets.sealed`, the same document encrypted to a Secure Enclave key of this
//!   Mac. A copy of the file is useless on any other machine.
//!
//! Since 0.5.1 (§17.30) the sealed store is what a Mac uses unless its owner said otherwise:
//! a login seals its secrets from the start, and a device that is on the plain file is moved
//! by itself once the trial has passed ([`automatic_move`]). `gclone keystore use file` and
//! `GCLONE_KEYSTORE_TRIAL=0` switch that off — the variable for the whole device, through a
//! marker that a run with it leaves ([`mark_trial_off`]); Linux has no sealed store.
//!
//! Rules that hold everywhere in this module:
//!
//! 1. Reading finds the secrets wherever they are ([`LayeredStore::resolve`]).
//! 2. Only four things create, replace or remove either file, each under the exclusive
//!    secrets lock: `login` (`save`, and the move at its end), `logout` (`delete`), `gclone
//!    keystore use` (the two moves) and the automatic move towards `secrets.sealed`. Nothing
//!    ever moves secrets to the plain file but `gclone keystore use file` and a save that
//!    could not seal.
//! 3. `secrets.sealed` is never written unless it was opened in the same process, or is made
//!    from the exact bytes of a `secrets.json` that holds keys and is read back, through the
//!    enclave, to those bytes before that file is removed; and it is never removed unless
//!    `secrets.json` holds the keys — or the device is being signed out. Sealed keys are
//!    never replaced by a document without keys: a login that has no key (yet) goes to
//!    `secrets.json`, beside the sealed file.
//! 4. Nothing here can show a dialog: there is no Keychain call (see `macos.rs`).
//! 5. The trial (`trial.rs`) never influences what `load` returns, and neither does the
//!    automatic move; a command waits for the trial's step for at most `trial::STEP_WAIT`
//!    and for a move it started for at most [`AUTO_MOVE_WAIT`]. No call into the Secure
//!    Enclave is waited for without a bound, whoever makes it (`seal::Bounded`).
//! 6. The automatic move never happens from a process that did not open the trial's test
//!    value itself, with the very key it then seals to.

use std::collections::HashSet;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{
    Config, FileSecretStore, Paths, SecretStore, Secrets, check_private_dir, parse_json,
    read_private, remove_if_present, to_json,
};
use crate::error::ConfigError;
use crate::util;

#[cfg(target_os = "macos")]
pub(crate) mod macos;
pub(crate) mod seal;
pub(crate) mod trial;

use seal::{SealError, Sealer};

const ENVELOPE_VERSION: u32 = 1;
const STORE_ENCLAVE: &str = "enclave";
const STORE_FILE: &str = "file";
/// Apple's ECIES: `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM` with a
/// P-256 key.
pub(crate) const SEALED_ALG: &str = "ecies-p256-x963-sha256-aesgcm";

/// How long `login`, `logout` and `keystore use` wait for the secrets lock.
pub(crate) const WRITER_WAIT: Duration = Duration::from_secs(5);
/// How long a reader that found neither file waits for a move in progress to end.
const READER_WAIT: Duration = Duration::from_secs(2);
/// The pause before the one second try of a stored key that failed while a new key works.
const STORED_KEY_RETRY_PAUSE: Duration = Duration::from_millis(300);
/// How long a command waits for an automatic move that it started ([`automatic_move`]): the
/// move makes two calls into the Secure Enclave and a handful of small writes, some tens of
/// milliseconds together. A move that takes longer goes on on its own thread while the
/// command does its work — every point of it is a safe place to be cut off — and the trial's
/// record gets a failure, so that it is not tried again run after run.
pub(crate) const AUTO_MOVE_WAIT: Duration = Duration::from_secs(10);

/// The standard first line of a cache directory tag (https://bford.info/cachedir/).
const CACHEDIR_TAG: &str = "Signature: 8a477f597d28d172789f06886806bc55\n\
    # This file is a cache directory tag created by gclone.\n\
    # Backup tools that are asked to (restic, borg and tar: --exclude-caches) leave this\n\
    # directory out: it holds this device's login, vault key and local state, none of which\n\
    # belongs in a backup. For information about cache directory tags see\n\
    # https://bford.info/cachedir/\n";

// ---------------------------------------------------------------------------------------------
// Which sealer
// ---------------------------------------------------------------------------------------------

/// Why this process has no sealer. (Which of the two a build can produce depends on the
/// platform and the profile: a release build on macOS produces neither.)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum NoSealer {
    /// Not a Mac: there is no sealed store here (§8.2).
    NotMac,
    /// A debug build without a test switch: it touches no hardware.
    DebugBuild,
}

impl NoSealer {
    pub(crate) fn text(self) -> &'static str {
        match self {
            NoSealer::NotMac => {
                "the sealed key store needs the Secure Enclave of a Mac; on this system the \
                 secrets stay in the plain file secrets.json (mode 0600)"
            }
            NoSealer::DebugBuild => {
                "this is a debug build of gclone, which does not use the Secure Enclave (the \
                 test switch GCLONE_TEST_KEYSTORE_SEALER selects a sealer)"
            }
        }
    }
}

pub(crate) type SealerChoice = Result<Arc<dyn Sealer>, NoSealer>;

/// Unit tests: one stand-in machine for the whole test process, so that `secret_store` opens
/// what a test sealed. Nothing reads the environment.
#[cfg(test)]
fn pick_sealer() -> SealerChoice {
    Ok(Arc::new(seal::FakeSealer::new("unit-test-machine", None)))
}

#[cfg(all(debug_assertions, not(test)))]
fn pick_sealer() -> SealerChoice {
    let test = crate::cli::test_env;
    match test("GCLONE_TEST_KEYSTORE_SEALER").as_deref() {
        Some("fake") => {
            let machine =
                test("GCLONE_TEST_KEYSTORE_MACHINE").unwrap_or_else(|| "test-machine".into());
            let fail = test("GCLONE_TEST_KEYSTORE_FAIL")
                .as_deref()
                .and_then(seal::FakeFail::parse);
            Ok(Arc::new(seal::FakeSealer::new(&machine, fail)))
        }
        #[cfg(target_os = "macos")]
        Some("soft") => Ok(Arc::new(macos::SoftKeySealer)),
        #[cfg(target_os = "macos")]
        Some("real") => Ok(Arc::new(macos::EnclaveSealer)),
        Some(_) if !cfg!(target_os = "macos") => Err(NoSealer::NotMac),
        _ => Err(NoSealer::DebugBuild),
    }
}

#[cfg(all(not(debug_assertions), not(test), target_os = "macos"))]
fn pick_sealer() -> SealerChoice {
    Ok(Arc::new(macos::EnclaveSealer))
}

#[cfg(all(not(debug_assertions), not(test), not(target_os = "macos")))]
fn pick_sealer() -> SealerChoice {
    Err(NoSealer::NotMac)
}

/// The sealer of this process: the Secure Enclave in a release build on macOS; in a debug
/// build only what `GCLONE_TEST_KEYSTORE_SEALER` names (§7.1).
///
/// Whatever it is, its calls into the hardware are bounded (`seal::Bounded`, rule 5): ten
/// seconds each, and after one that did not come back every later one fails at once.
pub(crate) fn sealer() -> SealerChoice {
    static SEALER: OnceLock<SealerChoice> = OnceLock::new();
    SEALER
        .get_or_init(|| {
            pick_sealer()
                .map(|inner| Arc::new(seal::Bounded::new(inner, call_wait())) as Arc<dyn Sealer>)
        })
        .clone()
}

/// `seal::CALL_WAIT`; debug builds honour `GCLONE_TEST_KEYSTORE_WAIT_MS` (§7.1), so that a
/// test of a call that does not return need not wait ten seconds for every command.
fn call_wait() -> Duration {
    crate::cli::test_env("GCLONE_TEST_KEYSTORE_WAIT_MS")
        .and_then(|v| v.parse().ok())
        .map(Duration::from_millis)
        .unwrap_or(seal::CALL_WAIT)
}

// ---------------------------------------------------------------------------------------------
// Notes and test hooks
// ---------------------------------------------------------------------------------------------

static NOTES: AtomicBool = AtomicBool::new(true);

/// `-q` and `--json` switch the once-only notes off (`cli::run`).
pub(crate) fn set_notes_enabled(enabled: bool) {
    NOTES.store(enabled, Ordering::SeqCst);
}

pub(crate) fn notes_enabled() -> bool {
    NOTES.load(Ordering::SeqCst)
}

/// A note for a person may be printed now: stderr is a terminal and nothing silenced it. Unit
/// tests never print one; `GCLONE_TEST_NOTES=1` (debug builds) stands in for the terminal.
fn can_show_notes() -> bool {
    if cfg!(test) {
        return false;
    }
    if crate::cli::test_env("GCLONE_TEST_NOTES").as_deref() == Some("1") {
        return notes_enabled();
    }
    notes_enabled() && std::io::IsTerminal::is_terminal(&std::io::stderr())
}

/// `GCLONE_TEST_KEYSTORE_STOP=<point>` (debug builds): the process ends at that point as if
/// it had been killed.
fn stop_is(point: &str) -> bool {
    crate::cli::test_env("GCLONE_TEST_KEYSTORE_STOP").as_deref() == Some(point)
}

fn stop(point: &str) {
    if stop_is(point) {
        std::process::exit(137);
    }
}

/// `util::write_atomic(path, bytes, 0600)` with two stop points: `<point>-temp` (killed after
/// the temp file was written, before the rename) and `<point>-done` (killed right after the
/// rename).
fn write_file(path: &Path, bytes: &[u8], point: &str) -> std::io::Result<()> {
    if stop_is(&format!("{point}-temp")) {
        // What a kill between the write and the rename leaves: a full copy under the temp
        // name that `util::remove_atomic_leftovers` knows.
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let temp = path.with_file_name(format!(".{name}.tmp-{}", util::hex(&util::random::<8>())));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .and_then(|mut f| std::io::Write::write_all(&mut f, bytes))?;
        std::process::exit(137);
    }
    util::write_atomic(path, bytes, 0o600)?;
    stop(&format!("{point}-done"));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The secrets lock
// ---------------------------------------------------------------------------------------------

/// The kernel lock of `<state root>/secrets.lock` (§8.3); released on drop and when the
/// process dies.
pub(crate) struct SecretsLock(std::fs::File);

impl Drop for SecretsLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// The exclusive lock of whoever writes or moves secrets. Waits up to `wait`, then
/// `ConfigError::KeyStoreBusy`. Creates the lock file (0600); the state root has to exist.
pub(crate) fn lock_exclusive(paths: &Paths, wait: Duration) -> Result<SecretsLock, ConfigError> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(paths.secrets_lock())?;
    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(SecretsLock(file)),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ConfigError::KeyStoreBusy);
        }
        std::thread::sleep(left.min(Duration::from_millis(20)));
    }
}

/// The shared lock of a reader that found neither file: no move is in progress while it is
/// held. `None`: there is no lock file (nobody ever moved anything here), or the wait ran out.
/// A reader never creates the lock file.
fn lock_shared(paths: &Paths, wait: Duration) -> Option<SecretsLock> {
    let file = std::fs::File::open(paths.secrets_lock()).ok()?;
    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock_shared() {
            Ok(()) => return Some(SecretsLock(file)),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(_)) => return None,
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        std::thread::sleep(left.min(Duration::from_millis(20)));
    }
}

// ---------------------------------------------------------------------------------------------
// keystore.json: the choice
// ---------------------------------------------------------------------------------------------

/// What `gclone keystore use` recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Choice {
    /// No file: no choice was made. The trial runs.
    Unset,
    /// The owner keeps the plain file: no trial, no hint.
    File,
    /// The owner chose the sealed store.
    Enclave,
    /// The file is there and cannot be used (unreadable, open permissions, an unknown value).
    /// Counts as "no choice made" with the trial suspended; never blocks a read.
    Unreadable(String),
}

#[derive(Serialize, Deserialize)]
struct ChoiceFile {
    version: u32,
    store: String,
}

pub(crate) fn read_choice(paths: &Paths) -> Choice {
    let bytes = match read_private(&paths.keystore_file(), "keystore.json") {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Choice::Unset,
        Err(e) => return Choice::Unreadable(e.to_string()),
    };
    match parse_json::<ChoiceFile>("keystore.json", &bytes) {
        Ok(file) if file.store == STORE_FILE => Choice::File,
        Ok(file) if file.store == STORE_ENCLAVE => Choice::Enclave,
        Ok(_) => Choice::Unreadable(
            "keystore.json names a store this gclone does not know (written by a newer gclone?)"
                .into(),
        ),
        Err(e) => Choice::Unreadable(e.to_string()),
    }
}

/// Written only by `gclone keystore use`, under the exclusive lock.
fn write_choice(paths: &Paths, store: &str, point: &str) -> Result<(), ConfigError> {
    let file = ChoiceFile {
        version: ENVELOPE_VERSION,
        store: store.to_string(),
    };
    let bytes = to_json("keystore.json", &file)?;
    Ok(write_file(&paths.keystore_file(), &bytes, point)?)
}

// ---------------------------------------------------------------------------------------------
// keystore-trial.off: GCLONE_KEYSTORE_TRIAL=0, for the whole device
// ---------------------------------------------------------------------------------------------

/// A run with `GCLONE_KEYSTORE_TRIAL=0` used this device's plain `secrets.json` and left its
/// marker ([`mark_trial_off`]).
pub(crate) fn trial_off_marked(paths: &Paths) -> bool {
    std::fs::symlink_metadata(paths.trial_off_file()).is_ok()
}

/// `GCLONE_KEYSTORE_TRIAL=0` in a run's environment says "this run must not come to depend
/// on the Secure Enclave" — a scheduler's job in a session nobody tried, say. The variable
/// alone could not keep that promise: it made the run take no step of the trial, so the one
/// session the owner was unsure about was the one the test never saw, any other run passed
/// the bar, removed `secrets.json`, and the job needed the enclave after all (§17.30). So a
/// run with the variable that is answered from a `secrets.json` with keys leaves this empty
/// marker (created once, `O_EXCL`), and while it is there nothing is tested, sealed or moved
/// on this device by itself — in any run. `gclone keystore use enclave` and `gclone keystore
/// check --new-trial` take it away; a run with the variable puts it back.
///
/// `GCLONE_TEST_KEYSTORE_NO_MARKER=1` (debug builds, §7.1) keeps a run from leaving it: the
/// tests' way to look at a device, or to prepare one, without changing what happens to it.
fn mark_trial_off(paths: &Paths) {
    if trial_off_marked(paths)
        || crate::cli::test_env("GCLONE_TEST_KEYSTORE_NO_MARKER").as_deref() == Some("1")
    {
        return;
    }
    let made = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(paths.trial_off_file());
    match made {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => tracing::debug!("cannot record that GCLONE_KEYSTORE_TRIAL=0 is used here: {e}"),
    }
}

/// The owner asked for the sealed store, or for a new trial: the marker goes.
pub(crate) fn clear_trial_off(paths: &Paths) {
    let _ = std::fs::remove_file(paths.trial_off_file());
}

// ---------------------------------------------------------------------------------------------
// secrets.sealed: the envelope
// ---------------------------------------------------------------------------------------------

/// `secrets.sealed`. What is sealed is a complete `secrets.json` document: there is no second
/// secrets format.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Envelope {
    pub version: u32,
    pub store: String,
    pub alg: String,
    /// The key's public half (X9.63), base64url: sealing needs nothing else, and a reloaded
    /// key that is not this one is refused.
    pub public: String,
    /// The Secure Enclave key blob, base64url. Usable only by the enclave that made it.
    pub key: String,
    /// `ECIES(public, the exact bytes of a secrets.json document)`, base64url.
    pub sealed: String,
    /// The vault the sealed keys belong to (not secret); absent while the document holds no
    /// keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    pub sealed_ms: u64,
}

/// Why a `secrets.sealed` that exists could not be opened.
#[derive(Clone, Debug)]
pub(crate) enum Unopenable {
    /// Not an envelope this version reads: damaged, or of a newer gclone.
    Damaged(String),
    /// This process has no sealer.
    NoSealer(NoSealer),
    /// The sealer refused: a dead key, or a session without access.
    Key(SealError),
}

impl Unopenable {
    /// One line for `status`, `-v` and `keystore`.
    pub(crate) fn brief(&self) -> String {
        match self {
            Unopenable::Damaged(detail) => format!("secrets.sealed cannot be read ({detail})"),
            Unopenable::NoSealer(why) => why.text().to_string(),
            Unopenable::Key(e) => format!("the stored key cannot be used here ({e})"),
        }
    }
}

/// An opened `secrets.sealed`.
pub(crate) struct Opened {
    pub envelope: Envelope,
    /// The exact bytes that were sealed.
    pub document: Zeroizing<Vec<u8>>,
    pub secrets: Secrets,
}

fn parse_envelope(bytes: &[u8]) -> Result<Envelope, Unopenable> {
    let envelope: Envelope = parse_json("secrets.sealed", bytes).map_err(|e| {
        Unopenable::Damaged(match e {
            ConfigError::Version(v) => format!("version {v}, this gclone reads version 1"),
            other => other.to_string(),
        })
    })?;
    if envelope.store != STORE_ENCLAVE {
        return Err(Unopenable::Damaged(
            "it names a store this gclone does not know".into(),
        ));
    }
    if envelope.alg != SEALED_ALG {
        return Err(Unopenable::Damaged(
            "it names an algorithm this gclone does not know".into(),
        ));
    }
    Ok(envelope)
}

/// The keyrings of two secrets documents are the same keys.
pub(crate) fn same_keys(a: &Secrets, b: &Secrets) -> bool {
    a.min_epoch == b.min_epoch
        && a.keys.len() == b.keys.len()
        && a.keys
            .iter()
            .zip(&b.keys)
            .all(|(x, y)| x.epoch == y.epoch && util::ct_eq(x.key.as_bytes(), y.key.as_bytes()))
}

// ---------------------------------------------------------------------------------------------
// The layered store
// ---------------------------------------------------------------------------------------------

/// Where `load` found the secrets.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    /// `secrets.json`.
    Plain,
    /// `secrets.sealed`, alone.
    Sealed,
    /// The login of a keyless `secrets.json`, the keys of `secrets.sealed` (in memory only).
    Merged,
}

pub(crate) struct Loaded {
    pub secrets: Secrets,
    pub source: Source,
    /// A `secrets.sealed` beside the `secrets.json` that answered did not open: why.
    pub sealed_problem: Option<String>,
}

/// The store behind `config::secret_store`.
pub struct LayeredStore {
    paths: Paths,
    plain: FileSecretStore,
    sealer: SealerChoice,
    /// The trial and the once-only notes run from `load` (never in unit tests unless asked).
    side_effects: bool,
    /// The sealed store is the default (§17.30): a login with no choice on file seals, and a
    /// passed trial is followed by the move. Off in unit tests unless asked
    /// ([`LayeredStore::sealed_by_default`]), so that a test of another module that saves
    /// secrets finds them in `secrets.json`.
    automatic: bool,
}

/// State roots whose once-per-process work after a load is done.
fn settled() -> &'static Mutex<HashSet<PathBuf>> {
    static DONE: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    DONE.get_or_init(Default::default)
}

impl LayeredStore {
    pub fn new(paths: &Paths) -> LayeredStore {
        LayeredStore::with_sealer(paths, sealer(), !cfg!(test))
    }

    pub(crate) fn with_sealer(paths: &Paths, sealer: SealerChoice, side_effects: bool) -> Self {
        LayeredStore {
            paths: paths.clone(),
            plain: FileSecretStore {
                path: paths.secrets_file(),
            },
            sealer,
            side_effects,
            automatic: !cfg!(test),
        }
    }

    /// This store with the default of §17.30 switched on or off (unit tests).
    #[cfg(test)]
    pub(crate) fn sealed_by_default(mut self, on: bool) -> Self {
        self.automatic = on;
        self
    }

    /// This store for a load that takes the trial's step and does not move the secrets
    /// afterwards: `gclone keystore use enclave`, whose own move — after the key was proven
    /// against the vault and the passphrase against a keyfile — is the one that must happen.
    pub(crate) fn without_unasked_move(mut self) -> Self {
        self.automatic = false;
        self
    }

    /// A `secrets.sealed` lies beside the `secrets.json` this device is working from, and it
    /// is not the unfinished work of a move to the running trial's key (which the next run
    /// finishes): it is sealed to another key, cannot be read, or there is no running trial.
    /// That is what an older gclone leaves that signed in on a sealed device — its
    /// `secrets.json` beside the store it cannot read — and what an interrupted `keystore
    /// use` leaves. While it lies there nothing is tested and nothing is moved by itself:
    /// moving again removed the file the older gclone needs, every time its owner had just
    /// repaired it (§17.30). Read off the two files; no call into the enclave.
    pub(crate) fn sealed_beside_is_foreign(&self) -> bool {
        let sealed_to = match self.read_sealed() {
            Ok(None) => return false,
            Ok(Some(bytes)) => parse_envelope(&bytes).ok().map(|envelope| envelope.public),
            Err(_) => None,
        };
        match (sealed_to, trial::load(&self.paths)) {
            (Some(sealed_to), trial::Stored::Record(record)) => {
                !(record.key.is_some() && record.public.as_deref() == Some(sealed_to.as_str()))
            }
            _ => true,
        }
    }

    /// The sealer for secrets that nobody asked to seal (§17.30), or `None`: the owner chose
    /// the plain file, `keystore.json` cannot be read, `GCLONE_KEYSTORE_TRIAL=0` is set — here,
    /// or in a run that left its marker —, or this process has no sealer. The explicit choice
    /// `enclave` counts whatever the environment says — it is the owner's command.
    fn sealer_by_default(&self) -> Option<Arc<dyn Sealer>> {
        let sealer = self.sealer.as_ref().ok()?;
        match read_choice(&self.paths) {
            Choice::Enclave => Some(sealer.clone()),
            Choice::Unset
                if self.automatic
                    && !trial::disabled_by_env()
                    && !trial_off_marked(&self.paths) =>
            {
                Some(sealer.clone())
            }
            _ => None,
        }
    }

    /// The sealer for what happens without any command of the owner's — the trial's step
    /// and the move after it — or `None`: the owner chose the plain file, `keystore.json`
    /// cannot be read, `GCLONE_KEYSTORE_TRIAL=0` is set here or left its marker (which also
    /// stops a device that chose `enclave` from being moved by itself), or this process has
    /// no sealer.
    fn sealer_for_unasked_steps(&self) -> Option<Arc<dyn Sealer>> {
        if trial::disabled_by_env() || trial_off_marked(&self.paths) {
            return None;
        }
        let sealer = self.sealer.as_ref().ok()?;
        matches!(read_choice(&self.paths), Choice::Unset | Choice::Enclave).then(|| sealer.clone())
    }

    pub(crate) fn sealer(&self) -> &SealerChoice {
        &self.sealer
    }

    /// `secrets.json`, strictly; `None` = no such file.
    pub(crate) fn read_plain_bytes(&self) -> Result<Option<Zeroizing<Vec<u8>>>, ConfigError> {
        read_private(&self.paths.secrets_file(), "secrets.json")
    }

    fn read_plain(&self) -> Result<Option<Secrets>, ConfigError> {
        self.plain.load()
    }

    /// `secrets.sealed`, strictly (owner, mode, `O_NOFOLLOW`, private directory, size limit —
    /// as for `secrets.json`); `None` = no such file.
    pub(crate) fn read_sealed(&self) -> Result<Option<Zeroizing<Vec<u8>>>, ConfigError> {
        read_private(&self.paths.sealed_file(), "secrets.sealed")
    }

    /// Parses and opens the bytes of a `secrets.sealed`.
    pub(crate) fn open_sealed(&self, bytes: &[u8]) -> Result<Opened, Unopenable> {
        let envelope = parse_envelope(bytes)?;
        let field = |name: &str, text: &str| {
            util::unb64url(text)
                .ok_or_else(|| Unopenable::Damaged(format!("`{name}` is not base64url")))
        };
        let blob = Zeroizing::new(field("key", &envelope.key)?);
        let public = field("public", &envelope.public)?;
        let sealed = field("sealed", &envelope.sealed)?;
        let sealer = self.sealer.clone().map_err(Unopenable::NoSealer)?;
        let document = sealer
            .open(&blob, &public, &sealed)
            .map_err(Unopenable::Key)?;
        // Not `e.to_string()` of serde's own error: `parse_json` never quotes the document.
        let secrets: Secrets = parse_json("the document in secrets.sealed", &document)
            .map_err(|e| Unopenable::Damaged(e.to_string()))?;
        Ok(Opened {
            envelope,
            document,
            secrets,
        })
    }

    /// [`LayeredStore::open_sealed`] for a reader that is about to answer "the stored key
    /// cannot be used any more": when the sealer refuses the stored key while a key made at
    /// this moment works, the stored key is tried once more after a short pause. One failed
    /// call is not a dead key, and the answer for a dead key sends the owner to `gclone
    /// login` — away from a key that may be intact.
    fn open_sealed_patiently(&self, bytes: &[u8]) -> Result<Opened, Unopenable> {
        let why = match self.open_sealed(bytes) {
            Err(why @ Unopenable::Key(_)) => why,
            other => return other,
        };
        let fresh_key_works = self
            .sealer
            .as_ref()
            .is_ok_and(|sealer| seal::probe(sealer.as_ref()).is_ok());
        if !fresh_key_works {
            // A session without access: nothing a second try would change.
            return Err(why);
        }
        std::thread::sleep(STORED_KEY_RETRY_PAUSE);
        match self.open_sealed(bytes) {
            Ok(opened) => {
                tracing::warn!(
                    "the Secure Enclave refused this device's key once ({}) and opened it at \
                     the second try",
                    why.brief()
                );
                Ok(opened)
            }
            Err(again) => Err(again),
        }
    }

    /// The text of `ConfigError::KeyStoreUnavailable`: what failed and what to do. For a key
    /// that the sealer refused, a fresh key decides between "this key is dead" (`gclone
    /// login` is the way) and "this session cannot use the enclave" (signing in again would
    /// throw away a key that is probably intact).
    pub(crate) fn unavailable_text(&self, why: &Unopenable) -> String {
        match why {
            Unopenable::Damaged(detail) => format!(
                "secrets.sealed, which holds this device's login and key, is damaged or was \
                 written by a newer gclone ({detail}). Use that gclone, or run `gclone login`."
            ),
            Unopenable::NoSealer(NoSealer::NotMac) => {
                "This device's login and key are in secrets.sealed, sealed by the Secure \
                 Enclave of a Mac; this machine cannot open that file. Run `gclone login`; it \
                 asks for the passphrase and connects this device again."
                    .into()
            }
            Unopenable::NoSealer(NoSealer::DebugBuild) => format!(
                "This device's login and key are in secrets.sealed, and {}. Use a release \
                 build. Nothing was changed.",
                NoSealer::DebugBuild.text()
            ),
            Unopenable::Key(e) => {
                let fresh = match &self.sealer {
                    Ok(sealer) => seal::probe(sealer.as_ref()),
                    Err(_) => Err(SealError(String::new())),
                };
                match fresh {
                    Ok(()) => format!(
                        "This Mac's Secure Enclave cannot open this device's sealed key \
                         (secrets.sealed): it was sealed for another Mac — the files came here \
                         by a migration or from a backup — or this Mac's Secure Enclave was \
                         reset, and the stored key cannot be used any more ({e}; tried twice, \
                         and a new key works). Run `gclone login`; it asks for the passphrase \
                         (for a vault on Google Drive it signs in to Google first) and \
                         connects this device again. The sealed file is kept until that login \
                         has the key again."
                    ),
                    Err(_) => format!(
                        "The Secure Enclave cannot be used in this session ({e}). Run gclone \
                         from a terminal or a LaunchAgent of the logged-in user; `gclone \
                         keystore check` shows what this session can do. Do not sign in again: \
                         the stored key is probably intact. If gclone has to run in this \
                         session, `gclone keystore use file` — from a session where it works — \
                         moves the secrets back to the plain file, which every session reads."
                    ),
                }
            }
        }
    }

    /// The vault id in `config.json`, if the device is attached to a vault.
    fn configured_vault(&self) -> Option<String> {
        Config::load(&self.paths).ok().map(|c| c.vault_id)
    }

    /// The answer for one look at both files (the load table of §8.2). `Ok(None)`: neither is
    /// there.
    fn decide(
        &self,
        plain: Option<Secrets>,
        sealed: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<Option<Loaded>, ConfigError> {
        let from_plain = |secrets: Secrets, sealed_problem: Option<String>| Loaded {
            secrets,
            source: Source::Plain,
            sealed_problem,
        };
        Ok(match (plain, sealed) {
            (None, None) => None,
            (Some(s), None) => Some(from_plain(s, None)),
            // secrets.json holds keys: it is the answer, and secrets.sealed is not opened.
            (Some(s), Some(_)) if !s.keys.is_empty() => Some(from_plain(s, None)),
            (None, Some(bytes)) => match self.open_sealed_patiently(&bytes) {
                Ok(opened) => Some(Loaded {
                    secrets: opened.secrets,
                    source: Source::Sealed,
                    sealed_problem: None,
                }),
                Err(why) => {
                    return Err(ConfigError::KeyStoreUnavailable(
                        self.unavailable_text(&why),
                    ));
                }
            },
            // A keyless secrets.json beside the sealed file: an older gclone signed in on a
            // sealed device and did not get to the passphrase. The key stays where it is and
            // works with the login just made — for the vault the sealed keys belong to only.
            (Some(s), Some(bytes)) => match self.open_sealed_patiently(&bytes) {
                Ok(opened)
                    if s.has_login()
                        && !opened.secrets.keys.is_empty()
                        && opened.envelope.vault_id.is_some()
                        && opened.envelope.vault_id == self.configured_vault() =>
                {
                    let mut merged = s;
                    merged.keys = opened.secrets.keys.clone();
                    merged.min_epoch = opened.secrets.min_epoch;
                    Some(Loaded {
                        secrets: merged,
                        source: Source::Merged,
                        sealed_problem: None,
                    })
                }
                Ok(_) => Some(from_plain(s, None)),
                Err(why) => Some(from_plain(s, Some(why.brief()))),
            },
        })
    }

    /// Where the secrets are, and the secrets (§8.2). Takes no lock on the normal path: each
    /// file is replaced by rename, so a reader sees one whole version of it, and a move
    /// creates the new file before it removes the old one. A reader that looked for
    /// `secrets.json` too early and for `secrets.sealed` too late looks at `secrets.json` a
    /// third time; one that still found nothing looks once more under the shared lock, where
    /// no move is in progress.
    pub(crate) fn resolve(&self) -> Result<Option<Loaded>, ConfigError> {
        let keyed = |s: &Option<Secrets>| s.as_ref().is_some_and(|s| !s.keys.is_empty());
        let plain = self.read_plain()?;
        if keyed(&plain) {
            return self.decide(plain, None);
        }
        let sealed = self.read_sealed()?;
        if sealed.is_some() {
            return self.decide(plain, sealed);
        }
        // Neither a keyed secrets.json nor a sealed file: look at secrets.json again.
        let again = self.read_plain()?;
        if again.is_some() {
            let sealed = if keyed(&again) {
                None
            } else {
                self.read_sealed()?
            };
            return self.decide(again, sealed);
        }
        let lock = lock_shared(&self.paths, READER_WAIT);
        let plain = self.read_plain()?;
        let sealed = if keyed(&plain) {
            None
        } else {
            self.read_sealed()?
        };
        drop(lock);
        self.decide(plain, sealed)
    }

    /// What `load` does besides answering, once per process and state root: the backup
    /// exclusion; for a device on the plain file one step of the trial and, when the trial
    /// has passed, the move into the sealed store (§17.30); and the note about that move, if
    /// one is owed. Nothing here can fail the load or change what it returns.
    fn after_load(&self, loaded: &Loaded) {
        if !self.side_effects {
            return;
        }
        if !settled()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(self.paths.state_root.clone())
        {
            return;
        }
        protect_state_root(&self.paths, true);
        let keyed_plain = loaded.source == Source::Plain && !loaded.secrets.keys.is_empty();
        // This run must not come to depend on the enclave, its environment says: then no
        // other run makes it so either.
        if keyed_plain
            && trial::disabled_by_env()
            && self.sealer.is_ok()
            && matches!(read_choice(&self.paths), Choice::Unset | Choice::Enclave)
        {
            mark_trial_off(&self.paths);
        }
        if loaded.source == Source::Plain
            && let Some(sealer) = self.sealer_for_unasked_steps()
            && !self.sealed_beside_is_foreign()
        {
            // On a thread of its own, awaited for a bounded time: rule 5. A step that did not
            // come back is not followed by a move.
            let stepped = trial::step_bounded(&self.paths, sealer.clone());
            if stepped && self.automatic && keyed_plain {
                let store = LayeredStore {
                    paths: self.paths.clone(),
                    plain: FileSecretStore {
                        path: self.paths.secrets_file(),
                    },
                    sealer: Ok(sealer),
                    side_effects: false,
                    automatic: true,
                };
                let outcome =
                    trial::within(&self.paths, AUTO_MOVE_WAIT, move || automatic_move(&store));
                match outcome {
                    Some(AutoMove::Moved | AutoMove::NotDue | AutoMove::Busy) | None => {}
                    Some(AutoMove::Kept(why)) => {
                        tracing::debug!("the secrets were not moved into the sealed store: {why}");
                    }
                }
            }
        }
        if loaded.source == Source::Sealed && !trial::disabled_by_env() {
            self.end_trial_of_sealing_key();
        }
        move_note(&self.paths);
    }

    /// A move that was cut off between the removal of the plain file and the end of the
    /// trial's record left a record that still looks like a running trial — of the very key
    /// the secrets are sealed to. The first load afterwards ends it. (Read off the two
    /// files; no call into the enclave.)
    fn end_trial_of_sealing_key(&self) {
        if std::fs::symlink_metadata(self.paths.trial_file()).is_err() {
            return;
        }
        let trial::Stored::Record(record) = trial::load(&self.paths) else {
            return;
        };
        if record.key.is_none() || record.public.is_none() {
            return;
        }
        let sealed_to = self
            .read_sealed()
            .ok()
            .flatten()
            .and_then(|bytes| parse_envelope(&bytes).ok())
            .map(|envelope| envelope.public);
        if sealed_to == record.public {
            let public = record.public;
            trial::update(&self.paths, |now| {
                // Only the record that was looked at: another process may have started a
                // new trial in between.
                if now.public != public || now.key.is_none() {
                    return false;
                }
                *now = std::mem::take(now).moved(trial::clock_ms());
                true
            });
        }
    }

    /// The secrets document for the file, and the vault it belongs to if it holds keys.
    fn envelope_for(
        &self,
        sealer: &dyn Sealer,
        blob: &[u8],
        public: &[u8],
        document: &[u8],
        has_keys: bool,
    ) -> Result<Zeroizing<Vec<u8>>, ConfigError> {
        let failed = |e: SealError| ConfigError::Json(format!("cannot seal the secrets: {e}"));
        let sealed = sealer.seal(public, document).map_err(failed)?;
        // Opened again before anything is written: what goes to disk is known to open.
        let back = sealer.open(blob, public, &sealed).map_err(failed)?;
        if back.as_slice() != document {
            return Err(ConfigError::Json(
                "the sealed secrets do not open to what was sealed".into(),
            ));
        }
        let envelope = Envelope {
            version: ENVELOPE_VERSION,
            store: STORE_ENCLAVE.into(),
            alg: SEALED_ALG.into(),
            public: util::b64url(public),
            key: util::b64url(blob),
            sealed: util::b64url(&sealed),
            vault_id: has_keys.then(|| self.configured_vault()).flatten(),
            sealed_ms: util::now_ms(),
        };
        to_json("secrets.sealed", &envelope)
    }

    /// Writes `secrets.sealed` and reads the file back: the bytes on disk are the ones made.
    fn write_sealed(&self, envelope: &[u8], point: &str) -> Result<(), ConfigError> {
        write_file(&self.paths.sealed_file(), envelope, point)?;
        match self.read_sealed()? {
            Some(back) if back.as_slice() == envelope => Ok(()),
            _ => Err(ConfigError::Json(
                "secrets.sealed does not read back as it was written".into(),
            )),
        }
    }

    fn remove_sealed(&self) -> Result<(), ConfigError> {
        remove_if_present(&self.paths.sealed_file())?;
        util::remove_atomic_leftovers(&self.paths.sealed_file())?;
        Ok(())
    }

    fn remove_plain(&self) -> Result<(), ConfigError> {
        remove_if_present(&self.paths.secrets_file())?;
        util::remove_atomic_leftovers(&self.paths.secrets_file())?;
        // The removal itself is made durable: after a crash the plain copy must not be back.
        if let Ok(dir) = std::fs::File::open(&self.paths.state_root) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    /// One save (the save table of §8.2), under the exclusive lock, looking at the files as
    /// they are now.
    fn save_with(&self, s: &Secrets, how: Save<'_>) -> Result<(), ConfigError> {
        util::create_dir_private(&self.paths.state_root)?;
        // An existing directory that others can read would make every later load fail.
        check_private_dir(&self.paths.state_root)?;
        let held_login = self.paths.secrets_present();
        let lock = lock_exclusive(&self.paths, WRITER_WAIT)?;
        let document = to_json("secrets.json", s)?;
        let has_keys = !s.keys.is_empty();
        let proven = matches!(how, Save::Proven);
        stop("save-locked");
        // Plain copies that a killed write left under a temp name: every writer of these
        // files holds the lock, so whatever lies there now belongs to nobody. Without this a
        // copy of the login and key stayed beside a sealed store for as long as nobody ran
        // `logout` or a move.
        clean_leftovers(&self.paths)?;

        let plain_exists = std::fs::symlink_metadata(self.paths.secrets_file()).is_ok();
        let chosen = read_choice(&self.paths) == Choice::Enclave;
        let mut to_sealed = None;
        let mut new_store = false;
        if !plain_exists {
            match self.read_sealed()? {
                // The sealed file is this device's store and opens here: the save stays in it.
                Some(bytes) => {
                    if let (Ok(opened), Ok(sealer)) = (self.open_sealed(&bytes), &self.sealer)
                        // Sealed keys are never replaced by a document without keys. `login`
                        // saves the grant without a key before it asks for the passphrase,
                        // and it gets here also when its own look at the sealed file failed a
                        // moment ago (a transient error of the enclave): re-sealing that
                        // keyless document over the file threw away the only copy of the
                        // key before the passphrase was even asked. The keyless login goes
                        // to secrets.json instead — beside the keyed sealed file that is the
                        // merged view of the load table — and the sealed file stays as it
                        // is. The one exception names the keys it gives up.
                        && (has_keys
                            || opened.secrets.keys.is_empty()
                            || matches!(how, Save::Dropping(old) if same_keys(&opened.secrets, old)))
                        && let (Some(blob), Some(public)) = (
                            util::unb64url(&opened.envelope.key),
                            util::unb64url(&opened.envelope.public),
                        )
                    {
                        to_sealed = Some((sealer.clone(), Zeroizing::new(blob), public));
                    }
                    // A sealed file that does not open is never written to, and neither is
                    // one whose keys this save would drop: the save goes to secrets.json
                    // and the file stays as it is.
                }
                // A signed-out device: the sealed store from the start (§17.30), unless the
                // owner chose the plain file, the trial's record speaks against it or has not
                // passed yet, or no key can be made and used here ([`Self::key_for_login`]).
                None => {
                    // Nothing of an earlier login is left here, so no note about one is owed
                    // either: an older gclone's `logout` leaves the marker of a move behind,
                    // and the note then said "gclone tested it over several days" about a
                    // store that this login is only now beginning.
                    let _ = std::fs::remove_file(self.paths.move_note_file());
                    if let Some(sealer) = self.sealer_by_default() {
                        let undecided = trial_undecided(&self.paths);
                        match self.key_for_login(&sealer, chosen, undecided) {
                            LoginKey::Key(key) => {
                                to_sealed = Some((sealer, key.blob, key.public));
                                new_store = true;
                            }
                            LoginKey::Held(why) => {
                                tracing::debug!("this login goes to secrets.json: {why}");
                            }
                            LoginKey::Failed(e) => self.could_not_seal(chosen, &e),
                        }
                    }
                }
            }
        }
        if let Some((sealer, blob, public)) = to_sealed {
            let written = self
                .envelope_for(sealer.as_ref(), &blob, &public, &document, has_keys)
                .and_then(|envelope| self.write_sealed(&envelope, "save-sealed"));
            match written {
                Ok(()) => {
                    // A sealed store that begins here ends a trial that was running — its
                    // record says whose key took the secrets (`Report`) — and takes the
                    // record of a trial that ended earlier, for another key, away.
                    if new_store {
                        trial::note_sealed(&self.paths, &util::b64url(&public));
                    }
                    drop(lock);
                    protect_state_root(&self.paths, held_login);
                    return Ok(());
                }
                // Nothing was renamed into place, or what was does not read back: the
                // secrets go to the plain file, which readers prefer when it holds keys.
                Err(e) if new_store => {
                    self.could_not_seal(chosen, &seal::SealError(e.to_string()));
                }
                Err(e) => tracing::warn!(
                    "the secrets could not be sealed ({e}); they were saved to secrets.json \
                     instead"
                ),
            }
        }

        write_file(&self.paths.secrets_file(), &document, "save-plain")?;
        // secrets.json holds the keys now. A sealed file beside it goes when the keys were
        // just opened from a keyfile (the passphrase is proven), or when it opens and holds
        // the same keys; otherwise it may be the only copy of another state and stays.
        if has_keys && let Some(bytes) = self.read_sealed()? {
            let obsolete = proven
                || self
                    .open_sealed(&bytes)
                    .is_ok_and(|opened| same_keys(&opened.secrets, s));
            if obsolete {
                self.remove_sealed()?;
                // The device is on the plain file again: a note that says "your secrets are
                // in secrets.sealed now" is owed to nobody (a later move owes it anew).
                let _ = std::fs::remove_file(self.paths.move_note_file());
            }
        }
        drop(lock);
        protect_state_root(&self.paths, held_login);
        Ok(())
    }
}

/// The key a login seals its secrets to, or why it does not seal.
enum LoginKey {
    Key(PickedKey),
    /// The login goes to `secrets.json` and nothing is wrong: the trial has the word.
    Held(&'static str),
    /// No key could be made and used here.
    Failed(SealError),
}

/// A trial is running on this device and has not passed. Looked at by `gclone login` before
/// it does anything else: a trial that this login's own loads start does not count. Nor does
/// a record beside a device whose secrets are in the sealed store alone — there is no trial
/// there, whatever a record says that an older gclone or an interrupted move left.
pub(crate) fn trial_undecided(paths: &Paths) -> bool {
    let sealed_alone = std::fs::symlink_metadata(paths.secrets_file()).is_err()
        && std::fs::symlink_metadata(paths.sealed_file()).is_ok();
    if sealed_alone {
        return false;
    }
    match trial::load(paths) {
        trial::Stored::Record(record) => {
            let summary = record.summary();
            summary.running && !summary.complete
        }
        _ => false,
    }
}

impl LayeredStore {
    /// The trial's record speaks against sealing secrets that nobody asked to seal: a
    /// failure is on it, in some session of this Mac.
    fn trial_speaks_against(&self) -> bool {
        matches!(trial::load(&self.paths), trial::Stored::Record(record) if record.speaks_against())
    }

    /// The key for a login's secrets, where the sealed store is this device's default — the
    /// bar of §8.2 as a login meets it:
    ///
    /// - the owner chose `enclave`: a key, whatever the trial's record says;
    /// - the record speaks against it (a failure, a session that could not make a key): no;
    /// - **a trial was running when the login began and had not passed** (`undecided`): no.
    ///   The device was working from `secrets.json` a `gclone logout` ago, with whatever
    ///   runs unattended on it, and the trial had not yet seen a restart or all of that:
    ///   signing out and in again does not jump the bar, any more than signing in again
    ///   without the `logout` does. The login goes to `secrets.json` and the trial goes on;
    /// - the trial has passed and its move has not happened yet: the trial's key, if its
    ///   test value opens in this process — otherwise no, as for the automatic move;
    /// - otherwise — no record, or one that ended with a move: this is a new device, or one
    ///   that depended on the enclave already — a key made now, which sealed a value and
    ///   opened it in this process.
    fn key_for_login(&self, sealer: &Arc<dyn Sealer>, chosen: bool, undecided: bool) -> LoginKey {
        let pick = || pick_key_bounded(&self.paths, sealer);
        if chosen {
            return pick().map_or_else(LoginKey::Failed, LoginKey::Key);
        }
        if self.trial_speaks_against() {
            return LoginKey::Held("the Secure Enclave trial's record holds a failure");
        }
        if undecided {
            return LoginKey::Held(
                "the Secure Enclave trial of this device has not passed yet, and it decides",
            );
        }
        let passed = matches!(
            trial::load(&self.paths),
            trial::Stored::Record(record) if record.summary().complete
        );
        match pick() {
            Ok(key) if passed && !key.from_trial => LoginKey::Held(
                "the Secure Enclave trial has passed, and its test value did not open in this \
                 process",
            ),
            Ok(key) => LoginKey::Key(key),
            Err(e) => LoginKey::Failed(e),
        }
    }

    /// A login that should have been sealed goes to the plain file. Where the owner chose the
    /// sealed store that is a warning; where it is only the default it is silent, and the
    /// reason is written down for `gclone status` and `gclone keystore` (§17.30).
    fn could_not_seal(&self, chosen: bool, error: &seal::SealError) {
        if chosen {
            tracing::warn!(
                "the sealed key store cannot be used here ({error}); this login goes to \
                 secrets.json"
            );
        } else {
            tracing::debug!(
                "the sealed key store cannot be used here ({error}); this login goes to \
                 secrets.json"
            );
        }
        if !trial::disabled_by_env() {
            trial::note_cannot_seal(&self.paths, error);
        }
    }
}

/// A key for this device's secrets: the trial's own key if its test value opens right now —
/// then the trial's record belongs to the very key the device will depend on — else a new
/// key, which sealed a value and opened it again in this process.
pub(crate) struct PickedKey {
    pub blob: Zeroizing<Vec<u8>>,
    pub public: Vec<u8>,
    /// It is the trial's key.
    pub from_trial: bool,
}

pub(crate) fn pick_key(paths: &Paths, sealer: &dyn Sealer) -> Result<PickedKey, SealError> {
    if let trial::Stored::Record(record) = trial::load(paths)
        && record.open_canary(sealer).is_ok()
        && let Some((blob, public)) = record.key_for_secrets()
    {
        return Ok(PickedKey {
            blob,
            public,
            from_trial: true,
        });
    }
    let (blob, public) = sealer.create()?;
    let value: [u8; 16] = util::random();
    let sealed = sealer.seal(&public, &value)?;
    let back = sealer.open(&blob, &public, &sealed)?;
    if back.as_slice() != value {
        return Err(SealError(
            "a value sealed to the new key did not open to itself".into(),
        ));
    }
    Ok(PickedKey {
        blob,
        public,
        from_trial: false,
    })
}

/// [`pick_key`] for a login, which is the first thing many a session asks of the Secure
/// Enclave: on a thread of its own, awaited for at most `trial::STEP_WAIT`. A call that does
/// not come back is "no key can be made here": the login goes to the plain file and says
/// nothing (§17.30), instead of standing still with the secrets lock held.
fn pick_key_bounded(paths: &Paths, sealer: &Arc<dyn Sealer>) -> Result<PickedKey, SealError> {
    let (for_thread, sealer) = (paths.clone(), sealer.clone());
    trial::within(paths, trial::STEP_WAIT, move || {
        pick_key(&for_thread, sealer.as_ref())
    })
    .unwrap_or_else(|| {
        Err(SealError(format!(
            "the call into the Secure Enclave did not return within {} s",
            trial::STEP_WAIT.as_secs()
        )))
    })
}

/// What a save knows about the secrets it replaces.
#[derive(Copy, Clone)]
enum Save<'a> {
    /// Nothing.
    Plain,
    /// The keys were just opened from a keyfile: the passphrase is proven.
    Proven,
    /// These secrets, saved by this run a moment ago, hold keys that are of no use any more:
    /// a sealed file with exactly these keys may be replaced by a document without keys.
    Dropping(&'a Secrets),
}

impl SecretStore for LayeredStore {
    fn load(&self) -> Result<Option<Secrets>, ConfigError> {
        let Some(loaded) = self.resolve()? else {
            return Ok(None);
        };
        if let Some(problem) = &loaded.sealed_problem {
            tracing::info!("secrets.sealed exists beside secrets.json and was not used: {problem}");
        }
        self.after_load(&loaded);
        Ok(Some(loaded.secrets))
    }

    fn save(&self, s: &Secrets) -> Result<(), ConfigError> {
        self.save_with(s, Save::Plain)
    }

    fn save_proven(&self, s: &Secrets) -> Result<(), ConfigError> {
        self.save_with(s, Save::Proven)
    }

    fn save_dropping_keys(&self, s: &Secrets, dropped: &Secrets) -> Result<(), ConfigError> {
        self.save_with(s, Save::Dropping(dropped))
    }

    /// `logout`: the cached access token, what interrupted writes left of any of the files,
    /// then `secrets.json`, then `secrets.sealed` — in this order, so that a `logout` that
    /// stops half-way still finds the device signed in and finishes. `keystore.json` and
    /// `keystore-trial.json` stay: a choice and a record, no secret.
    fn delete(&self) -> Result<(), ConfigError> {
        let lock = match std::fs::symlink_metadata(&self.paths.state_root) {
            Ok(_) => Some(lock_exclusive(&self.paths, WRITER_WAIT)?),
            Err(_) => None,
        };
        remove_if_present(&self.paths.token_file())?;
        for file in [
            self.paths.token_file(),
            self.paths.secrets_file(),
            self.paths.sealed_file(),
            self.paths.trial_file(),
            self.paths.keystore_file(),
        ] {
            util::remove_atomic_leftovers(&file)?;
        }
        stop("delete-leftovers-done");
        remove_if_present(&self.paths.secrets_file())?;
        stop("delete-plain-done");
        remove_if_present(&self.paths.sealed_file())?;
        // A note about a move that is still owed has nothing left to be about.
        let _ = std::fs::remove_file(self.paths.move_note_file());
        drop(lock);
        Ok(())
    }
}

/// What a login can leave in the state root besides the two secrets files: the cached access
/// token and temp copies from writes that were killed before their rename. `true` = something
/// was there. For a `logout` on a device that is not signed in.
pub(crate) fn remove_leftovers(paths: &Paths) -> std::io::Result<bool> {
    let token = match std::fs::remove_file(paths.token_file()) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e),
    };
    let mut temps = 0;
    for file in [
        paths.token_file(),
        paths.secrets_file(),
        paths.sealed_file(),
        paths.trial_file(),
        paths.keystore_file(),
    ] {
        temps += util::remove_atomic_leftovers(&file)?;
    }
    Ok(token || temps > 0)
}

// ---------------------------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------------------------

#[cfg(target_os = "macos")]
const BACKUP_NOTE: &str = "note: gclone's state folder is now left out of Time Machine backups. \
    Backups made before today still contain secrets.json with the vault key in plain; delete \
    it from them if they leave your hands. A restored Mac signs in again with `gclone login` \
    and the passphrase.";

/// Keeps the state root out of backups (§8.1): a `CACHEDIR.TAG` on both platforms and, on
/// macOS, the Time Machine exclusion attribute on the directory. Best effort: a failure is
/// logged at debug level and shown by `gclone keystore`. `held_login`: the state root held a
/// login before this call — then older backups hold the plain file, and the owner is told
/// once (on a terminal).
pub(crate) fn protect_state_root(paths: &Paths, held_login: bool) {
    let root = &paths.state_root;
    if !root.is_dir() {
        return;
    }
    let tag = root.join("CACHEDIR.TAG");
    if std::fs::symlink_metadata(&tag).is_err() {
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tag)
            .and_then(|mut f| std::io::Write::write_all(&mut f, CACHEDIR_TAG.as_bytes()));
        if let Err(e) = written {
            tracing::debug!("cannot write {}: {e}", tag.display());
        }
    }
    #[cfg(target_os = "macos")]
    {
        let newly = match macos::exclude_from_backups(root) {
            Ok(newly) => newly,
            Err(e) => {
                tracing::debug!("cannot exclude {} from backups: {e}", root.display());
                return;
            }
        };
        backup_note(paths, newly && held_login);
    }
    #[cfg(not(target_os = "macos"))]
    let _ = held_login;
}

/// The once-only note about older backups: shown when it becomes due on a terminal; when it
/// becomes due anywhere else, kept as owed by an empty marker file (`backup-note.due`) until
/// a run on a terminal takes the marker away and shows the note.
///
/// The marker is created with `O_EXCL` and consumed by its removal, so that no two processes
/// can undo each other: it once was a member of the trial's record, which every process of a
/// first run rewrote from the copy it had loaded — several unattended commands starting
/// together lost the "owed" for good (the exclusion attribute was set by then, so the note
/// never became due again).
///
/// It does not depend on the trial: `GCLONE_KEYSTORE_TRIAL=0` used to switch it off as well,
/// and a device whose scheduler sets that never learned that its older backups hold the key
/// (§17.30).
#[cfg(target_os = "macos")]
fn backup_note(paths: &Paths, due_now: bool) {
    let marker = paths.backup_note_file();
    if can_show_notes() {
        // Whoever removes the marker shows what was owed: once, whatever runs beside this.
        let owed = std::fs::remove_file(&marker).is_ok();
        if due_now || owed {
            eprintln!("{BACKUP_NOTE}");
        }
    } else if due_now {
        let made = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&marker);
        match made {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => tracing::debug!("cannot record that the backup note is owed: {e}"),
        }
    }
}

/// Whether the state root is left out of Time Machine backups; `None` where there is no such
/// thing (Linux), `Some(Err)` if it cannot be told.
pub(crate) fn backup_excluded(paths: &Paths) -> Option<Result<bool, String>> {
    #[cfg(target_os = "macos")]
    {
        Some(macos::excluded_from_backups(&paths.state_root).map_err(|e| e.to_string()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = paths;
        None
    }
}

// ---------------------------------------------------------------------------------------------
// The moves: `gclone keystore use`, the end of a login, and the one that nobody asked for
// ---------------------------------------------------------------------------------------------

/// Why a move did not happen. Nothing was changed unless the text says otherwise.
#[derive(Debug)]
pub(crate) enum MoveError {
    /// `secrets.json` is not what the caller looked at before it began.
    Changed,
    /// `secrets.json` is gone and `secrets.sealed` opens here: another move into the sealed
    /// store finished while this one ran. Nothing was changed by this one.
    AlreadySealed,
    /// Refused, with the text for the user.
    Refused(String),
    Config(ConfigError),
}

impl From<ConfigError> for MoveError {
    fn from(e: ConfigError) -> Self {
        MoveError::Config(e)
    }
}

impl From<std::io::Error> for MoveError {
    fn from(e: std::io::Error) -> Self {
        MoveError::Config(e.into())
    }
}

/// Who moves the secrets into the sealed store (§8.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum MoveBy {
    /// `gclone keystore use enclave`: the owner's command, after the key was proven against
    /// the vault and the passphrase against a keyfile. Waits for the lock, records the choice,
    /// and replaces whatever `secrets.sealed` lies beside the plain file.
    Command,
    /// The end of a `gclone login` whose secrets ended in the plain file although the sealed
    /// store is this device's default (§17.30). Waits for the lock; records no choice.
    Login,
    /// By itself, after a passed trial (§17.30): one try for the lock, no choice recorded,
    /// and the note about the move is owed before the plain file goes.
    Trial,
}

/// What an interrupted `login` or `keystore use` left beside the files they write: temp
/// copies from before a rename. The caller holds the exclusive lock, so nobody is writing
/// these files now. (The trial's record is written without the lock and is left alone.)
fn clean_leftovers(paths: &Paths) -> std::io::Result<()> {
    for file in [
        paths.secrets_file(),
        paths.sealed_file(),
        paths.keystore_file(),
    ] {
        util::remove_atomic_leftovers(&file)?;
    }
    Ok(())
}

/// The move into the sealed store, one sequence for every caller (`by`): seals the exact
/// bytes of `secrets.json` to the key (`blob`, `public`), verifies what was written through
/// the normal load path, and only then removes the plain file. `expected`: the bytes of
/// `secrets.json` the caller looked at before it began (`gclone keystore use enclave` proved
/// them against the vault). A failure before the removal leaves `secrets.json` in place and
/// takes the sealed file of this run away again.
///
/// A move that nobody asked for ([`MoveBy::Login`], [`MoveBy::Trial`]) looks at the
/// opt-outs again under the lock, and never writes over a `secrets.sealed` that it cannot
/// open or that holds other keys than `secrets.json`: such a file may be the only copy of
/// another state, and only the owner's command gives it up.
pub(crate) fn move_to_enclave(
    store: &LayeredStore,
    expected: &[u8],
    blob: &[u8],
    public: &[u8],
    by: MoveBy,
) -> Result<(), MoveError> {
    let paths = &store.paths;
    let sealer = store
        .sealer
        .clone()
        .map_err(|why| MoveError::Refused(why.text().to_string()))?;
    let wait = match by {
        MoveBy::Command | MoveBy::Login => WRITER_WAIT,
        MoveBy::Trial => Duration::ZERO,
    };
    let _lock = lock_exclusive(paths, wait)?;
    clean_leftovers(paths)?;
    // 5.1
    let Some(document) = store.read_plain_bytes()? else {
        // No plain file any more. If the sealed file opens here, another move got there
        // first: that is not "the login changed".
        return Err(match store.read_sealed()? {
            Some(bytes) if store.open_sealed(&bytes).is_ok() => MoveError::AlreadySealed,
            _ => MoveError::Changed,
        });
    };
    if document.as_slice() != expected {
        return Err(MoveError::Changed);
    }
    let secrets: Secrets = parse_json("secrets.json", &document)?;
    if secrets.keys.is_empty() {
        return Err(MoveError::Changed);
    }
    if by != MoveBy::Command {
        // The owner may have said no since the caller looked (`gclone keystore use file`
        // writes its choice under this lock).
        let wanted = match by {
            MoveBy::Trial => store.sealer_for_unasked_steps().is_some(),
            _ => store.sealer_by_default().is_some(),
        };
        if !wanted {
            return Err(MoveError::Refused(
                "the sealed store is not wanted on this device (`gclone keystore use file`, or \
                 GCLONE_KEYSTORE_TRIAL=0)"
                    .into(),
            ));
        }
        if let Some(beside) = store.read_sealed()? {
            match store.open_sealed(&beside) {
                // The automatic move finishes only what it began itself: a sealed copy of
                // the same keys under the very key it seals to. One under another key is the
                // store of an earlier sealing with an older gclone's `secrets.json` beside
                // it (or an interrupted command): removing that plain file again broke the
                // older gclone every time its owner had signed in with it.
                Ok(opened)
                    if same_keys(&opened.secrets, &secrets)
                        && by == MoveBy::Trial
                        && opened.envelope.public != util::b64url(public) =>
                {
                    return Err(MoveError::Refused(
                        "a secrets.sealed that is sealed to another key lies beside \
                         secrets.json (an older gclone signed in here after the secrets were \
                         sealed, or a `gclone keystore use` was interrupted); `gclone keystore \
                         use enclave` or `gclone keystore use file` settles it"
                            .into(),
                    ));
                }
                Ok(opened) if same_keys(&opened.secrets, &secrets) => {}
                Ok(_) => {
                    return Err(MoveError::Refused(
                        "a secrets.sealed with other keys lies beside secrets.json; `gclone \
                         keystore use file` or `gclone keystore use enclave` settles it"
                            .into(),
                    ));
                }
                Err(why) => {
                    return Err(MoveError::Refused(format!(
                        "a secrets.sealed that does not open lies beside secrets.json ({}); \
                         `gclone keystore use file --discard-sealed` or `gclone keystore use \
                         enclave` settles it",
                        why.brief()
                    )));
                }
            }
        }
    }
    // 5.2 – 5.4
    let sealed = (|| {
        let envelope = store.envelope_for(sealer.as_ref(), blob, public, &document, true)?;
        store.write_sealed(&envelope, "enclave-sealed")?;
        // Read back the way every later command will read it: strict file read, enclave open.
        let back = store
            .read_sealed()?
            .ok_or_else(|| ConfigError::Json("secrets.sealed is gone".into()))?;
        match store.open_sealed(&back) {
            Ok(opened) if opened.document.as_slice() == document.as_slice() => Ok(()),
            Ok(_) => Err(ConfigError::Json(
                "secrets.sealed opens to something else than secrets.json".into(),
            )),
            Err(why) => Err(ConfigError::Json(why.brief())),
        }
    })();
    if let Err(e) = sealed {
        let _ = store.remove_sealed();
        return Err(MoveError::Refused(format!(
            "the secrets could not be sealed and read back ({e}). Nothing was changed: \
             secrets.json is still this device's key store."
        )));
    }
    // 5.5: the choice is the owner's — only the command records one. The move that nobody
    // asked for leaves its note owed instead, before the plain file goes: a run that is
    // killed after this point is finished by the next one, and the note is still there. A
    // note that cannot be recorded stops that move: without it nobody would ever be told
    // that this device depends on this Mac's enclave and on the passphrase from now on.
    match by {
        MoveBy::Command => {
            write_choice(paths, STORE_ENCLAVE, "enclave-choice")?;
            // The owner's command is the answer to a run that asked for no trial …
            clear_trial_off(paths);
        }
        MoveBy::Trial => {
            if !owe_move_note(paths) {
                let _ = store.remove_sealed();
                return Err(MoveError::Refused(
                    "the note about the move cannot be recorded (keystore-note.due in the \
                     state folder). Nothing was changed: secrets.json is still this device's \
                     key store."
                        .into(),
                ));
            }
            stop("enclave-note-owed");
        }
        MoveBy::Login => {}
    }
    if by != MoveBy::Trial {
        // … and the command and the login say themselves what they did: a note that an
        // earlier move by itself still owes is about a store that is being replaced.
        let _ = std::fs::remove_file(paths.move_note_file());
    }
    // 5.6
    store.remove_plain()?;
    stop("enclave-plain-removed");
    // 5.7: a running trial is over; its record stays as the evidence — of the trial's key,
    // which is the key that holds the secrets now only if `pick_key` could use it. The record
    // keeps the public half of its key, and whoever reports compares it with the sealed
    // file's (`Report::trial_key_holds_secrets`): nothing here claims it. The record of a
    // trial that ended at an earlier sealing, for another key, is forgotten.
    // (A device that never had a trial gets no record from this: there is nothing to end.)
    trial::note_sealed(paths, &util::b64url(public));
    protect_state_root(paths, true);
    Ok(())
}

/// What the move that nobody asked for came to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AutoMove {
    /// The secrets are in `secrets.sealed` now, and the plain file is gone.
    Moved,
    /// Nothing to do: the trial has not passed (or there is none), or the secrets are not —
    /// or no longer — in a plain file with keys.
    NotDue,
    /// Another gclone holds the secrets lock; a later run looks again.
    Busy,
    /// The trial has passed and the secrets stay where they are all the same: why.
    Kept(String),
}

/// The move that nobody asked for (§8.2, §17.30): a device on the plain file whose trial is
/// complete — the test value opened on enough days, across a restart, without one failure —
/// gets its secrets sealed to the trial's own key, by the same sequence as `gclone keystore
/// use enclave` and under the same lock, without the passphrase and without a question.
///
/// It runs in the process that just took a step of the trial, and opens the test value once
/// more here, with the key it is about to seal to: a process that cannot use that key moves
/// nothing (rule 6). The opt-outs — the choice `file`, `GCLONE_KEYSTORE_TRIAL=0` — are looked
/// at here and again under the lock.
pub(crate) fn automatic_move(store: &LayeredStore) -> AutoMove {
    let paths = &store.paths;
    if !store.automatic {
        return AutoMove::NotDue;
    }
    let Some(sealer) = store.sealer_for_unasked_steps() else {
        return AutoMove::NotDue;
    };
    let trial::Stored::Record(record) = trial::load(paths) else {
        return AutoMove::NotDue;
    };
    if !record.summary().complete {
        return AutoMove::NotDue;
    }
    if let Err(e) = record.open_canary(sealer.as_ref()) {
        return AutoMove::Kept(format!(
            "the trial's test value did not open in this process ({e})"
        ));
    }
    let Some((blob, public)) = record.key_for_secrets() else {
        return AutoMove::NotDue;
    };
    let expected = match store.read_plain_bytes() {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return AutoMove::NotDue,
        Err(e) => return AutoMove::Kept(e.to_string()),
    };
    match move_to_enclave(store, &expected, &blob, &public, MoveBy::Trial) {
        Ok(()) => AutoMove::Moved,
        Err(MoveError::AlreadySealed) => AutoMove::NotDue,
        Err(MoveError::Config(ConfigError::KeyStoreBusy)) => AutoMove::Busy,
        Err(MoveError::Changed) => {
            AutoMove::Kept("secrets.json changed while it was looked at".into())
        }
        Err(MoveError::Refused(why)) => AutoMove::Kept(why),
        Err(MoveError::Config(e)) => AutoMove::Kept(e.to_string()),
    }
}

/// What the end of a `gclone login` did about the key store.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AfterLogin {
    /// The secrets are in `secrets.sealed` (the saves put them there).
    Sealed,
    /// They were in the plain file and were moved into `secrets.sealed` now.
    Moved,
    /// They are in the plain file and stay there: the sealed store is not this device's
    /// default (Linux, a choice, the environment), or it could not be used — the text, if
    /// there is something to say.
    Plain(Option<String>),
}

/// The end of a `gclone login` (§17.30): where the sealed store is this device's default and
/// the login's secrets ended in the plain file all the same — it found a sealed file that
/// did not open, or an older gclone's keyless login beside the sealed keys — they are moved
/// now, to a key that opened a value in this process. The caller does not ask for this on a
/// device that was on a plain file with keys when the login began: there the trial decides.
/// `undecided_before`: a trial was running and had not passed when the login began
/// ([`trial_undecided`]) — then it decides here as well ([`LayeredStore::key_for_login`]).
pub(crate) fn seal_after_login(store: &LayeredStore, undecided_before: bool) -> AfterLogin {
    let paths = &store.paths;
    let loaded = match store.resolve() {
        Ok(Some(loaded)) => loaded,
        _ => return AfterLogin::Plain(None),
    };
    match loaded.source {
        Source::Sealed => return AfterLogin::Sealed,
        Source::Merged => return AfterLogin::Plain(None),
        Source::Plain if loaded.secrets.keys.is_empty() => return AfterLogin::Plain(None),
        Source::Plain => {}
    }
    let Some(sealer) = store.sealer_by_default() else {
        return AfterLogin::Plain(None);
    };
    let chosen = read_choice(paths) == Choice::Enclave;
    let key = match store.key_for_login(&sealer, chosen, undecided_before) {
        LoginKey::Key(key) => key,
        LoginKey::Held(why) => return AfterLogin::Plain(Some(why.to_string())),
        LoginKey::Failed(e) => {
            store.could_not_seal(false, &e);
            return AfterLogin::Plain(Some(e.to_string()));
        }
    };
    let expected = match store.read_plain_bytes() {
        Ok(Some(bytes)) => bytes,
        _ => return AfterLogin::Plain(None),
    };
    match move_to_enclave(store, &expected, &key.blob, &key.public, MoveBy::Login) {
        Ok(()) => AfterLogin::Moved,
        Err(MoveError::AlreadySealed) => AfterLogin::Sealed,
        Err(MoveError::Changed) => AfterLogin::Plain(None),
        Err(MoveError::Refused(why)) => AfterLogin::Plain(Some(why)),
        Err(MoveError::Config(e)) => AfterLogin::Plain(Some(e.to_string())),
    }
}

/// The note about a move that nobody asked for. Shown once, to a person: when the move
/// happens in a run on a terminal, by that run; otherwise it is owed — the empty marker
/// `keystore-note.due`, made with `O_EXCL` before the plain file is removed and consumed by
/// its removal, like the backup note's — and shown by the next run on a terminal that finds
/// the device sealed. `gclone keystore use file`, `gclone keystore use enclave`, `logout` and
/// a login that begins a new store take the marker away. A marker that cannot be made stops
/// the move.
const MOVE_NOTE: &str = "note: this device's login and vault key are now kept in secrets.sealed, \
    which only this Mac's Secure Enclave can open (gclone tested it over several days and a \
    restart first); the plain secrets.json is gone. A copy of the sealed file is useless \
    anywhere else. If this Mac is erased, repaired or replaced, `gclone login` and your \
    passphrase connect it again. `gclone keystore use file` moves back to the plain file \
    (gclone 0.4.0 and older read only that one); `gclone keystore` shows the details.";

/// `true`: the note is owed — the marker is there, as a file that a later run can take
/// away. `false`: it could not be made (a full disk, say), and the move does not happen.
fn owe_move_note(paths: &Paths) -> bool {
    let marker = paths.move_note_file();
    let made = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&marker);
    match made {
        Ok(_) => true,
        // Owed already: an earlier try of this move got this far.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::symlink_metadata(&marker).is_ok_and(|md| md.file_type().is_file())
        }
        Err(e) => {
            tracing::debug!("cannot record that the note about the move is owed: {e}");
            false
        }
    }
}

/// Shows the note about the move if it is owed, this run may show notes and the device is on
/// the sealed store now. Whoever removes the marker shows the note: once, whatever runs
/// beside this.
fn move_note(paths: &Paths) {
    let marker = paths.move_note_file();
    if std::fs::symlink_metadata(&marker).is_err() || !can_show_notes() {
        return;
    }
    let sealed_alone = std::fs::symlink_metadata(paths.secrets_file()).is_err()
        && std::fs::symlink_metadata(paths.sealed_file()).is_ok();
    if sealed_alone && std::fs::remove_file(&marker).is_ok() {
        eprintln!("{MOVE_NOTE}");
    }
}

/// `gclone keystore use enclave` on a device whose secrets are sealed already: nothing moves,
/// but what an interrupted command left is settled under the lock — plain temp copies of the
/// secrets are removed, and a `keystore.json` that still says `file` (an interrupted `use
/// file`) says `enclave` again, so that the next login after a logout is not saved to the
/// plain file. `Ok(false)`: the sealed file is not (or no longer) this device's store.
pub(crate) fn settle_sealed(store: &LayeredStore) -> Result<bool, MoveError> {
    let paths = &store.paths;
    let _lock = lock_exclusive(paths, WRITER_WAIT)?;
    let sealed_alone = std::fs::symlink_metadata(paths.secrets_file()).is_err()
        && store
            .read_sealed()?
            .is_some_and(|bytes| store.open_sealed(&bytes).is_ok());
    if !sealed_alone {
        return Ok(false);
    }
    clean_leftovers(paths)?;
    if read_choice(paths) != Choice::Enclave {
        write_choice(paths, STORE_ENCLAVE, "enclave-choice")?;
    }
    clear_trial_off(paths);
    Ok(true)
}

/// The plain temp copies of the secrets that a killed write left in the state root
/// (`.secrets.json.tmp-…`): each is a full `secrets.json`. Counted, not touched.
pub(crate) fn plain_leftovers(paths: &Paths) -> usize {
    let Ok(entries) = std::fs::read_dir(&paths.state_root) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix(".secrets.json.tmp-"))
                .is_some_and(|rest| rest.len() == 16 && rest.bytes().all(|b| b.is_ascii_hexdigit()))
        })
        .count()
}

/// What `gclone keystore use file` did.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ToFile {
    /// The secrets were in `secrets.sealed` and are in `secrets.json` now.
    Moved,
    /// A keyless `secrets.json` and the sealed keys were written as one `secrets.json`.
    Merged,
    /// `secrets.json` was the store already; nothing moved.
    AlreadyPlain,
    /// `secrets.json` was the store; a sealed copy of the same keys was removed.
    SealedCopyRemoved,
    /// `secrets.json` was the store; `--discard-sealed` removed a sealed file that differs
    /// or does not open.
    SealedDiscarded,
    /// The device is not signed in: only the choice was recorded.
    NotSignedIn,
}

/// `gclone keystore use file` (the table of §8.2). The choice is written first, so that an
/// interrupted run is never undone by a later command — not by the automatic move either,
/// which looks at the choice under this lock; `secrets.json` is written and read back before
/// `secrets.sealed` is removed.
pub(crate) fn move_to_file(
    store: &LayeredStore,
    discard_sealed: bool,
) -> Result<ToFile, MoveError> {
    let paths = &store.paths;
    util::create_dir_private(&paths.state_root)?;
    check_private_dir(&paths.state_root)?;
    let _lock = lock_exclusive(paths, WRITER_WAIT)?;
    clean_leftovers(paths)?;
    // Whatever happens next, a note that says "your secrets are sealed now" is not owed to
    // somebody who is moving them back.
    let _ = std::fs::remove_file(paths.move_note_file());
    let plain = store.read_plain()?;
    let sealed = store.read_sealed()?;
    let has_keys = |s: &Secrets| !s.keys.is_empty();

    // Writes `secrets` as secrets.json, reads it back strictly, then removes the sealed file.
    let replace_sealed = |secrets_json: &[u8]| -> Result<(), MoveError> {
        write_file(&paths.secrets_file(), secrets_json, "file-plain")?;
        match store.read_plain_bytes()? {
            Some(back) if back.as_slice() == secrets_json => {}
            _ => {
                return Err(MoveError::Refused(
                    "secrets.json does not read back as it was written; secrets.sealed was \
                     kept and stays this device's key store"
                        .into(),
                ));
            }
        }
        store.remove_sealed()?;
        Ok(())
    };

    let outcome = match (plain, sealed) {
        (None, None) => {
            write_choice(paths, STORE_FILE, "file-choice")?;
            ToFile::NotSignedIn
        }
        (Some(_), None) => {
            write_choice(paths, STORE_FILE, "file-choice")?;
            ToFile::AlreadyPlain
        }
        (None, Some(bytes)) => {
            let opened = store.open_sealed(&bytes).map_err(|why| {
                MoveError::Refused(format!(
                    "Nothing can be moved: {}",
                    store.unavailable_text(&why)
                ))
            })?;
            write_choice(paths, STORE_FILE, "file-choice")?;
            replace_sealed(&opened.document)?;
            ToFile::Moved
        }
        (Some(s), Some(bytes)) if has_keys(&s) => match store.open_sealed(&bytes) {
            Ok(opened) if same_keys(&opened.secrets, &s) => {
                write_choice(paths, STORE_FILE, "file-choice")?;
                store.remove_sealed()?;
                ToFile::SealedCopyRemoved
            }
            other => {
                let what = match other {
                    Ok(_) => "it opens and holds OTHER keys than secrets.json".to_string(),
                    Err(why) => format!("it does not open: {}", why.brief()),
                };
                if !discard_sealed {
                    return Err(MoveError::Refused(format!(
                        "secrets.json is this device's key store, and secrets.sealed exists \
                         beside it: {what}. Nothing was changed. `gclone keystore use file \
                         --discard-sealed` removes secrets.sealed (secrets.json is what this \
                         device has been using)."
                    )));
                }
                write_choice(paths, STORE_FILE, "file-choice")?;
                store.remove_sealed()?;
                ToFile::SealedDiscarded
            }
        },
        // A keyless secrets.json beside the sealed file (an older gclone signed in here).
        (Some(s), Some(bytes)) => {
            let opened = store.open_sealed(&bytes).map_err(|why| {
                MoveError::Refused(format!(
                    "Nothing can be moved: secrets.json holds no key, and secrets.sealed does \
                     not open ({}). Nothing was changed. Run `gclone login`; it asks for the \
                     passphrase.",
                    why.brief()
                ))
            })?;
            let mergeable = s.has_login()
                && has_keys(&opened.secrets)
                && opened.envelope.vault_id.is_some()
                && opened.envelope.vault_id == store.configured_vault();
            if !mergeable {
                return Err(MoveError::Refused(
                    "Nothing can be moved: secrets.json holds a login without a key, and the \
                     keys in secrets.sealed belong to another vault or to no login. Nothing \
                     was changed. Run `gclone login`; it asks for the passphrase."
                        .into(),
                ));
            }
            let mut merged = s;
            merged.keys = opened.secrets.keys.clone();
            merged.min_epoch = opened.secrets.min_epoch;
            let document = to_json("secrets.json", &merged)?;
            write_choice(paths, STORE_FILE, "file-choice")?;
            replace_sealed(&document)?;
            ToFile::Merged
        }
    };
    protect_state_root(paths, true);
    Ok(outcome)
}

// ---------------------------------------------------------------------------------------------
// What `gclone status` and `gclone keystore` show
// ---------------------------------------------------------------------------------------------

/// Where this device's secrets are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Where {
    NotSignedIn,
    Plain,
    Sealed,
    /// The login of a keyless `secrets.json`, the keys of `secrets.sealed`.
    Merged,
    /// `secrets.sealed` alone, and it does not open: the text.
    SealedUnusable(String),
    /// The files cannot be read (open permissions, damaged JSON): the text.
    Unreadable(String),
}

pub(crate) struct Report {
    pub store: Where,
    /// `secrets.json` and `secrets.sealed` both exist.
    pub both_present: bool,
    /// Both exist and the sealed one is not a copy of the plain one's keys: why.
    pub sealed_differs: Option<String>,
    pub choice: Choice,
    /// The trial's record, if there is one.
    pub trial: Option<trial::Summary>,
    /// Whether the key `secrets.sealed` is sealed to is the trial's key — the one the
    /// trial's evidence is about. `None`: there is no sealed file or no trial key to compare.
    pub trial_key_holds_secrets: Option<bool>,
    /// Plain temp copies of the secrets left by interrupted writes ([`plain_leftovers`]).
    pub plain_leftovers: usize,
    /// `Err`: why this process cannot use a sealed store at all.
    pub sealer: Result<&'static str, NoSealer>,
    /// `GCLONE_KEYSTORE_TRIAL=0` is set for this process: no trial, and nothing is moved.
    pub trial_off: bool,
    /// A run with `GCLONE_KEYSTORE_TRIAL=0` left its marker: no trial and no move on this
    /// device, in any run ([`mark_trial_off`]).
    pub trial_off_marked: bool,
    /// `secrets.json` is the store, a `secrets.sealed` lies beside it, and it is not the
    /// unfinished work of a move to the trial's key: nothing is tested or moved by itself
    /// ([`LayeredStore::sealed_beside_is_foreign`]).
    pub blocked_by_sealed: bool,
    /// The Time Machine exclusion; `None` on Linux.
    pub backup_excluded: Option<Result<bool, String>>,
    pub cachedir_tag: bool,
}

pub(crate) fn report(paths: &Paths) -> Report {
    report_with(paths, &LayeredStore::with_sealer(paths, sealer(), false))
}

/// [`report`] as `store` sees the files.
pub(crate) fn report_with(paths: &Paths, store: &LayeredStore) -> Report {
    let exists = |p: PathBuf| std::fs::symlink_metadata(p).is_ok();
    let both_present = exists(paths.secrets_file()) && exists(paths.sealed_file());
    let mut sealed_differs = None;
    let place = match store.resolve() {
        Ok(None) => Where::NotSignedIn,
        Ok(Some(loaded)) => {
            if both_present && loaded.source == Source::Plain {
                sealed_differs = match store.read_sealed().ok().flatten() {
                    Some(bytes) => match store.open_sealed(&bytes) {
                        Ok(opened) if same_keys(&opened.secrets, &loaded.secrets) => None,
                        Ok(_) => Some("it opens and holds other keys than secrets.json".into()),
                        Err(why) => Some(why.brief()),
                    },
                    None => None,
                };
            }
            match loaded.source {
                Source::Plain => Where::Plain,
                Source::Sealed => Where::Sealed,
                Source::Merged => Where::Merged,
            }
        }
        Err(ConfigError::KeyStoreUnavailable(text)) => Where::SealedUnusable(text),
        Err(e) => Where::Unreadable(e.to_string()),
    };
    // A record that was forgotten (`trial::note_sealed`, `trial::forget`) is no trial.
    let trial = match trial::load(paths) {
        trial::Stored::Record(record) if !record.is_blank() => Some(record.summary()),
        _ => None,
    };
    let blocked_by_sealed =
        both_present && place == Where::Plain && store.sealed_beside_is_foreign();
    // Read off the two files: the public half the trial recorded, and the one the sealed
    // file names (not secret; the file is not opened for it).
    let sealed_to = store
        .read_sealed()
        .ok()
        .flatten()
        .and_then(|bytes| parse_envelope(&bytes).ok())
        .map(|envelope| envelope.public);
    let trial_key_holds_secrets = match (&trial, sealed_to) {
        (Some(t), Some(sealed_to)) => t.public.as_ref().map(|public| *public == sealed_to),
        _ => None,
    };
    Report {
        store: place,
        both_present,
        sealed_differs,
        choice: read_choice(paths),
        trial,
        trial_key_holds_secrets,
        plain_leftovers: plain_leftovers(paths),
        sealer: store.sealer.as_ref().map(|s| s.name()).map_err(|e| *e),
        trial_off: trial::disabled_by_env(),
        trial_off_marked: trial_off_marked(paths),
        blocked_by_sealed,
        backup_excluded: backup_excluded(paths),
        cachedir_tag: exists(paths.state_root.join("CACHEDIR.TAG")),
    }
}

impl Report {
    /// "2 of 3 days, no restart seen yet".
    fn trial_progress(t: &trial::Summary) -> String {
        let days = if t.days < trial::DAYS_NEEDED {
            format!("{} of {} days", t.days, trial::DAYS_NEEDED)
        } else if t.running && !t.aged {
            // Three calendar days can be little more than 24 hours.
            format!("{} days, not yet 48 hours apart", t.days)
        } else {
            format!("{} days", t.days)
        };
        let restart = if t.restart {
            "a restart survived"
        } else {
            "no restart seen yet"
        };
        match t.failures {
            0 => format!("{days}, {restart}"),
            1 => format!("{days}, {restart}, 1 failure"),
            n => format!("{days}, {restart}, {n} failures"),
        }
    }

    /// The text of the `Key store` line of `gclone status`.
    pub(crate) fn line(&self) -> String {
        let plain = "plain file secrets.json (0600)";
        let about_plain = || -> String {
            match (&self.choice, &self.sealer, &self.trial) {
                (Choice::File, _, _) => format!("{plain} — kept by choice"),
                // Linux, or a debug build: there is nothing to try.
                (_, Err(_), _) => plain.to_string(),
                (Choice::Unreadable(_), _, _) => {
                    format!(
                        "{plain} — Secure Enclave trial suspended (keystore.json is unreadable)"
                    )
                }
                // A run with the variable used this device: its marker holds for every run.
                _ if self.trial_off_marked => format!(
                    "{plain} — kept: a run with GCLONE_KEYSTORE_TRIAL=0 uses this device (no \
                     Secure Enclave trial, nothing is moved; `gclone keystore use enclave` \
                     moves the secrets)"
                ),
                // The environment of this run switches the trial and the move off; a run
                // that loads the secrets with it leaves the marker of the arm above.
                _ if self.trial_off => format!(
                    "{plain} — GCLONE_KEYSTORE_TRIAL=0: no Secure Enclave trial here, nothing \
                     is moved"
                ),
                // The warning says what lies there and what settles it.
                _ if self.blocked_by_sealed => format!(
                    "{plain} — kept: nothing is tested or moved while secrets.sealed lies \
                     beside it"
                ),
                // Still here although the trial has passed: the run that looks has not taken
                // its own step yet (`gclone keystore`), or its session cannot open the key.
                (_, Ok(_), Some(t)) if t.complete => {
                    format!(
                        "{plain} — Secure Enclave trial complete: the next run that can open \
                         the test value moves the secrets into the sealed store"
                    )
                }
                (_, Ok(_), Some(t)) if t.running => {
                    format!(
                        "{plain} — Secure Enclave trial: {}",
                        Self::trial_progress(t)
                    )
                }
                // Said about the machine only when a desktop session could not make a key;
                // any other session speaks for itself alone.
                (_, Ok(_), Some(t)) if t.unavailable.is_some() => match &t.unavailable {
                    Some(u) if u.says_no_hardware() => {
                        format!("{plain} — no Secure Enclave on this machine")
                    }
                    Some(u) => format!(
                        "{plain} — no Secure Enclave key could be made in session {} ({}) on \
                         {}; `gclone keystore check` tries this session",
                        u.session,
                        trial::session_kind(&u.session),
                        &util::format_local_minute(u.ms)[..10]
                    ),
                    None => plain.to_string(),
                },
                (Choice::Enclave, Ok(_), _) => format!(
                    "{plain} — the sealed store was chosen: `gclone keystore use enclave` moves \
                     the secrets"
                ),
                (_, Ok(_), _) => format!("{plain} — Secure Enclave trial not started yet"),
            }
        };
        match &self.store {
            Where::NotSignedIn => "none — this device is not signed in".to_string(),
            Where::Plain => about_plain(),
            Where::Sealed => "Secure Enclave of this Mac (secrets.sealed)".to_string(),
            Where::Merged => "Secure Enclave of this Mac (secrets.sealed) for the key, \
                              secrets.json for the login"
                .to_string(),
            Where::SealedUnusable(_) => "secrets.sealed — cannot be opened here".to_string(),
            Where::Unreadable(_) => "cannot be read".to_string(),
        }
    }

    /// What `gclone status` and `gclone keystore` warn about.
    pub(crate) fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(t) = &self.trial
            && t.failures > 0
            && self.store == Where::Plain
            && self.choice != Choice::File
        {
            let last = t.last_failures.last();
            let whereabouts = last
                .map(|f| {
                    format!(
                        " in a session {} (last: {})",
                        trial::session_kind(&f.session),
                        &util::format_local_minute(f.ms)[..10]
                    )
                })
                .unwrap_or_default();
            out.push(format!(
                "the Secure Enclave trial failed {} time(s){whereabouts}. Nothing is moved into \
                 the sealed store while a failure is on its record: `gclone keystore` shows the \
                 details, `gclone keystore check --new-trial` starts a new trial.",
                t.failures
            ));
        }
        if self.plain_leftovers > 0 {
            let sealed = matches!(
                self.store,
                Where::Sealed | Where::Merged | Where::SealedUnusable(_)
            );
            out.push(format!(
                "{} plain copy(ies) of this device's login and key from an interrupted write \
                 lie in the state folder (.secrets.json.tmp-…){}. `gclone keystore use {}` \
                 removes them (so does `gclone logout`, and a `gclone login` that signs in).",
                self.plain_leftovers,
                if sealed {
                    ", outside the sealed store: a copy of the state folder is NOT worthless \
                     elsewhere while they are there"
                } else {
                    ""
                },
                if sealed { "enclave" } else { "file" }
            ));
        }
        if self.trial_evidence_is_for_another_key() {
            out.push(
                "the secrets are sealed to a key that was made at the move, not to the Secure \
                 Enclave trial's key: the trial's record (days, restart, sessions) is evidence \
                 for another key. `gclone keystore check` from every session gclone runs in \
                 (cron, ssh, a LaunchAgent) shows whether this one opens there; `gclone \
                 keystore check --new-trial` forgets the old record."
                    .into(),
            );
        }
        if self.both_present && self.store == Where::Plain {
            let detail = match &self.sealed_differs {
                None => String::new(),
                Some(why) => format!(" secrets.sealed is not a copy of it: {why}."),
            };
            // What settles it: `use file` refuses a sealed file that differs or does not
            // open unless it is told to give it up.
            let remedy = if self.sealed_differs.is_some() {
                "`gclone keystore use file --discard-sealed` removes secrets.sealed, `gclone \
                 keystore use enclave` replaces it"
            } else {
                "`gclone keystore use file` or `gclone keystore use enclave` settles it"
            };
            let by_itself = if self.choice == Choice::File {
                ""
            } else if self.blocked_by_sealed {
                ". Until then gclone tests and moves nothing by itself here; if an older gclone \
                 uses this device (0.4.0 and before read only secrets.json), update it first, \
                 or keep the plain file with `gclone keystore use file`"
            } else {
                "; a move that gclone began by itself is finished by the next run"
            };
            out.push(format!(
                "secrets.json and secrets.sealed both exist (an interrupted move, or an older \
                 gclone signed in here). gclone uses secrets.json.{detail} {remedy}{by_itself}."
            ));
        }
        if self.store == Where::Merged {
            out.push(
                "secrets.json holds a login without a key (an older gclone signed in here); the \
                 key comes from secrets.sealed. `gclone login` or `gclone keystore use file` \
                 settles it."
                    .into(),
            );
        }
        match (&self.choice, &self.store) {
            (Choice::Unreadable(why), _) => out.push(format!(
                "keystore.json cannot be used ({why}); no choice counts as made and the Secure \
                 Enclave trial is suspended. `gclone keystore use file` or `gclone keystore use \
                 enclave` writes it anew."
            )),
            (Choice::Enclave, Where::Plain) if !self.both_present => out.push(format!(
                "the sealed store was chosen with `gclone keystore use enclave`, but this \
                 device's secrets are in the plain file secrets.json (a login that could not use \
                 the Secure Enclave, or an older gclone, put them there). `gclone keystore use \
                 enclave` moves them now{}; `gclone keystore use file` keeps the plain file.",
                if self.trial_off_marked {
                    ""
                } else {
                    " — gclone does it by itself once its trial has passed"
                }
            )),
            (Choice::File, Where::Sealed) => out.push(
                "the plain file was chosen with `gclone keystore use file`, but the secrets are \
                 still in secrets.sealed (an interrupted move). Run `gclone keystore use file` \
                 again."
                    .into(),
            ),
            _ => {}
        }
        out
    }

    /// The trial ended when the secrets were sealed, to another key than its own — and it
    /// had seen something: more than its first day, or a restart. Then its record looks like
    /// evidence and is none, and `status` and `keystore` say so. A record of one day without
    /// a restart is what `gclone keystore use enclave` as the first command after a login
    /// left with gclone 0.5.0 (§17.30): no evidence to mistake, nothing to warn about.
    pub(crate) fn trial_evidence_is_for_another_key(&self) -> bool {
        self.trial_key_holds_secrets == Some(false)
            && self
                .trial
                .as_ref()
                .is_some_and(|t| t.moved && (t.days > 1 || t.restart))
            && matches!(self.store, Where::Sealed | Where::Merged)
    }

    /// `key_store` of `gclone keystore --json`.
    pub(crate) fn json(&self, paths: &Paths) -> serde_json::Value {
        let (store, path) = match &self.store {
            Where::NotSignedIn => ("none", None),
            Where::Plain => ("file", Some(paths.secrets_file())),
            Where::Sealed | Where::Merged | Where::SealedUnusable(_) => {
                ("enclave", Some(paths.sealed_file()))
            }
            Where::Unreadable(_) => ("unreadable", None),
        };
        let choice = match &self.choice {
            Choice::Unset => serde_json::Value::Null,
            Choice::File => "file".into(),
            Choice::Enclave => "enclave".into(),
            Choice::Unreadable(_) => "unreadable".into(),
        };
        let trial = match &self.trial {
            None => serde_json::Value::Null,
            Some(t) => serde_json::json!({
                "running": t.running,
                "days": t.days,
                "restart": t.restart,
                "sessions": t.sessions,
                "failures": t.failures,
                "aged": t.aged,
                "complete": t.complete,
                "unavailable": t.unavailable.as_ref().map(|u| u.error.clone()),
                "unavailable_session": t.unavailable.as_ref().map(|u| u.session.clone()),
                "moved": t.moved,
                "key_holds_secrets": self.trial_key_holds_secrets,
            }),
        };
        let backup = match &self.backup_excluded {
            None => serde_json::Value::Null,
            Some(Ok(excluded)) => (*excluded).into(),
            Some(Err(_)) => serde_json::Value::Null,
        };
        serde_json::json!({
            "key_store": {
                "store": store,
                "path": path.map(|p| p.display().to_string()),
                "usable": !matches!(self.store, Where::SealedUnusable(_) | Where::Unreadable(_)),
                "choice": choice,
                "trial": trial,
                "trial_disabled": self.trial_off,
                "trial_off_marker": self.trial_off_marked,
                "both_present": self.both_present,
                "blocked_by_sealed": self.blocked_by_sealed,
                "plain_leftovers": self.plain_leftovers,
                "backup_excluded": backup,
                "cachedir_tag": self.cachedir_tag,
            }
        })
    }
}

#[cfg(test)]
mod tests;

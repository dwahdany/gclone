//! Where a device keeps its secrets (SPEC §8.2, §8.3, §17.28).
//!
//! Two stores hold the same thing — a `secrets.json` document: the Google login and the
//! vault's keys.
//!
//! - `file`: `secrets.json`, plain JSON, mode 0600. The version-1 format, unchanged.
//! - `enclave`: `secrets.sealed`, the same document encrypted to a Secure Enclave key of this
//!   Mac. A copy of the file is useless on any other machine.
//!
//! Rules that hold everywhere in this module:
//!
//! 1. Reading finds the secrets wherever they are ([`LayeredStore::resolve`]).
//! 2. No automatic step creates, replaces or removes either file. Only `login` (`save`),
//!    `logout` (`delete`) and `gclone keystore use` (the two moves) do, each under the
//!    exclusive secrets lock.
//! 3. `secrets.sealed` is never written unless it was opened in the same process (or is made
//!    from a `secrets.json` whose keys were just proven), and never removed unless
//!    `secrets.json` holds the keys — or the device is being signed out. Sealed keys are
//!    never replaced by a document without keys: a login that has no key (yet) goes to
//!    `secrets.json`, beside the sealed file.
//! 4. Nothing here can show a dialog: there is no Keychain call (see `macos.rs`).
//! 5. The trial (`trial.rs`) never influences what `load` returns, and never holds a command
//!    up for longer than `trial::STEP_WAIT`.

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
pub(crate) fn sealer() -> SealerChoice {
    static SEALER: OnceLock<SealerChoice> = OnceLock::new();
    SEALER.get_or_init(pick_sealer).clone()
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
        }
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
                 asks for the passphrase."
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
                        "This device's key was sealed for another Mac, or this Mac's Secure \
                         Enclave was reset: the stored key cannot be used any more ({e}; tried \
                         twice, and a new key works). Run `gclone login`; it asks for the \
                         passphrase. The sealed file is kept until that login has the key \
                         again."
                    ),
                    Err(_) => format!(
                        "The Secure Enclave cannot be used in this session ({e}). Run gclone \
                         from a terminal or a LaunchAgent of the logged-in user; `gclone \
                         keystore check` shows what this session can do. Do not sign in again: \
                         the stored key is probably intact."
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
    /// exclusion and, for a device on the plain file, one step of the trial. Nothing here can
    /// fail the load.
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
        let on_plain = loaded.source == Source::Plain
            && std::fs::symlink_metadata(self.paths.sealed_file()).is_err();
        if on_plain
            && !trial::disabled_by_env()
            && matches!(read_choice(&self.paths), Choice::Unset | Choice::Enclave)
            && let Ok(sealer) = &self.sealer
        {
            // On a thread of its own, awaited for a bounded time: rule 5.
            trial::step_bounded(&self.paths, sealer.clone());
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
        let mut to_sealed = None;
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
                // A signed-out device whose owner chose the sealed store: a new key, if one
                // can be made and used here.
                None => {
                    if read_choice(&self.paths) == Choice::Enclave
                        && let Ok(sealer) = &self.sealer
                    {
                        match sealer.create() {
                            Ok((blob, public)) => {
                                to_sealed = Some((sealer.clone(), blob, public));
                            }
                            Err(e) => tracing::warn!(
                                "the sealed key store cannot be used here ({e}); this login \
                                 goes to secrets.json"
                            ),
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
                    drop(lock);
                    protect_state_root(&self.paths, held_login);
                    return Ok(());
                }
                // Nothing was renamed into place, or what was does not read back: the
                // secrets go to the plain file, which readers prefer when it holds keys.
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
            }
        }
        drop(lock);
        protect_state_root(&self.paths, held_login);
        Ok(())
    }
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
#[cfg(target_os = "macos")]
fn backup_note(paths: &Paths, due_now: bool) {
    if trial::disabled_by_env() {
        return;
    }
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
// The moves of `gclone keystore use`
// ---------------------------------------------------------------------------------------------

/// Why a move did not happen. Nothing was changed unless the text says otherwise.
#[derive(Debug)]
pub(crate) enum MoveError {
    /// `secrets.json` is not what the command looked at before it asked its questions.
    Changed,
    /// `secrets.json` is gone and `secrets.sealed` opens here: another `gclone keystore use
    /// enclave` finished the move while this one ran. Nothing was changed by this one.
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

/// `gclone keystore use enclave`, step 5: seals the exact bytes of `secrets.json` to the key
/// (`blob`, `public`), verifies what was written through the normal load path, and only then
/// removes the plain file. `expected`: the bytes of `secrets.json` the command proved against
/// the vault. A failure before the removal leaves `secrets.json` in place and takes the
/// sealed file of this run away again.
pub(crate) fn move_to_enclave(
    store: &LayeredStore,
    expected: &[u8],
    blob: &[u8],
    public: &[u8],
) -> Result<(), MoveError> {
    let paths = &store.paths;
    let sealer = store
        .sealer
        .clone()
        .map_err(|why| MoveError::Refused(why.text().to_string()))?;
    let _lock = lock_exclusive(paths, WRITER_WAIT)?;
    clean_leftovers(paths)?;
    // 5.1
    let Some(document) = store.read_plain_bytes()? else {
        // No plain file any more. If the sealed file opens here, another run of this very
        // command got there first: that is not "the login changed".
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
    // 5.5
    write_choice(paths, STORE_ENCLAVE, "enclave-choice")?;
    // 5.6
    store.remove_plain()?;
    stop("enclave-plain-removed");
    // 5.7: the trial is over; its record stays as the evidence — of the trial's key, which
    // is the key that holds the secrets now only if `choose_key` could use it. The record
    // keeps the public half of its key, and whoever reports compares it with the sealed
    // file's (`Report::trial_key_holds_secrets`): nothing here claims it.
    if !trial::disabled_by_env() || matches!(trial::load(paths), trial::Stored::Record(_)) {
        trial::end_at_move(paths, util::now_ms());
    }
    protect_state_root(paths, true);
    Ok(())
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
/// interrupted run is never undone by a later command; `secrets.json` is written and read
/// back before `secrets.sealed` is removed.
pub(crate) fn move_to_file(
    store: &LayeredStore,
    discard_sealed: bool,
) -> Result<ToFile, MoveError> {
    let paths = &store.paths;
    util::create_dir_private(&paths.state_root)?;
    check_private_dir(&paths.state_root)?;
    let _lock = lock_exclusive(paths, WRITER_WAIT)?;
    clean_leftovers(paths)?;
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
    let trial = match trial::load(paths) {
        trial::Stored::Record(record) => Some(record.summary()),
        _ => None,
    };
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
        backup_excluded: backup_excluded(paths),
        cachedir_tag: exists(paths.state_root.join("CACHEDIR.TAG")),
    }
}

impl Report {
    /// "2 of 3 days, no restart seen yet".
    fn trial_progress(t: &trial::Summary) -> String {
        let days = if t.days >= trial::DAYS_NEEDED {
            format!("{} days", t.days)
        } else {
            format!("{} of {} days", t.days, trial::DAYS_NEEDED)
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
                (_, Ok(_), Some(t)) if t.complete => {
                    format!(
                        "{plain} — Secure Enclave trial complete: `gclone keystore use enclave`"
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
                "the Secure Enclave trial failed {} time(s){whereabouts}. `gclone keystore` \
                 shows the details.",
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
        if self.trial_key_holds_secrets == Some(false)
            && self.trial.as_ref().is_some_and(|t| t.moved)
            && matches!(self.store, Where::Sealed | Where::Merged)
        {
            out.push(
                "the secrets are sealed to a key that was made at the move, not to the Secure \
                 Enclave trial's key: the trial's record (days, restart, sessions) is evidence \
                 for another key. `gclone keystore check` from every session gclone runs in \
                 (cron, ssh, a LaunchAgent) shows whether this one opens there."
                    .into(),
            );
        }
        if self.both_present && self.store == Where::Plain {
            let detail = match &self.sealed_differs {
                None => String::new(),
                Some(why) => format!(" secrets.sealed is not a copy of it: {why}."),
            };
            out.push(format!(
                "secrets.json and secrets.sealed both exist (an interrupted move, or an older \
                 gclone signed in here). gclone uses secrets.json.{detail} `gclone keystore use \
                 file` or `gclone keystore use enclave` settles it."
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
            (Choice::Enclave, Where::Plain) if !self.both_present => out.push(
                "the sealed store was chosen with `gclone keystore use enclave`, but this \
                 device's secrets are in the plain file secrets.json (a login that could not use \
                 the Secure Enclave, or an older gclone, put them there). `gclone keystore use \
                 enclave` moves them; `gclone keystore use file` keeps the plain file."
                    .into(),
            ),
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
                "both_present": self.both_present,
                "plain_leftovers": self.plain_leftovers,
                "backup_excluded": backup,
                "cachedir_tag": self.cachedir_tag,
            }
        })
    }
}

#[cfg(test)]
mod tests;

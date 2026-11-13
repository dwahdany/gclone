//! Opening a command's context: config, secrets, backend, lock, vault, refresh policy
//! (SPEC §9.10, §10) — owned by WP7.

use std::io::Read as _;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::Context as _;
use zeroize::Zeroizing;

use super::GlobalOpts;
use crate::auth::{AuthClient, AuthEndpoints, TokenProvider};
use crate::backend::drive::{DriveBackend, DriveConfig};
use crate::backend::{AnyBackend, DirBackend};
use crate::config::{BackendCfg, Config, Paths, Secrets, secret_store};
use crate::consts::{LOCK_WAIT, PASSPHRASE_WARN_CHARS};
use crate::crypto::{KdfParams, Keyring, Passphrase};
use crate::error::{
    AuthError, BackendError, ConfigError, FormatError, IndexError, StateError, SyncError,
};
use crate::index::{OpenParams, RefreshReport, Vault};
use crate::state::{self, Db, StateLock};
use crate::ui::{Ui, UiOpts};
use crate::util;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LockMode {
    Exclusive,
    TryShared,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RefreshPolicy {
    /// Refresh errors (Gap, Rollback, …) fail `open_ctx` — mutating commands.
    Required,
    /// The Result is stored in `Ctx.refresh` and the command continues — read-only commands, gc.
    Tolerant,
    /// No refresh — repair (`Vault::repair` refreshes by itself).
    Skip,
}

#[derive(Copy, Clone, Debug)]
pub struct OpenOpts {
    pub lock: LockMode,
    pub refresh: RefreshPolicy,
    /// After a successful refresh under the exclusive lock: `vault.commit()` →
    /// `vault.resolve_conflicts()` (§5.8).
    pub settle: bool,
    /// Reaches `DriveConfig.transfers`; `TRANSFERS_DEFAULT` for commands without `--transfers`.
    pub transfers: usize,
}

impl OpenOpts {
    /// Read-only commands (`ls`, `tree`, `cat`, `about`, `status`, `check`).
    pub fn read_only() -> Self {
        OpenOpts {
            lock: LockMode::TryShared,
            refresh: RefreshPolicy::Tolerant,
            settle: false,
            transfers: crate::consts::TRANSFERS_DEFAULT,
        }
    }

    /// Commands that publish index changes (`copy`, `sync`, `mkdir`, `rm`, `mv`, `restore`).
    pub fn mutating() -> Self {
        OpenOpts {
            lock: LockMode::Exclusive,
            refresh: RefreshPolicy::Required,
            settle: true,
            transfers: crate::consts::TRANSFERS_DEFAULT,
        }
    }
}

pub struct Ctx {
    pub paths: Paths,
    pub config: Config,
    pub vault: Vault<AnyBackend>,
    pub ui: Ui,
    pub lock: Option<StateLock>,
    /// `None`: skipped, or the TryShared lock was busy.
    pub refresh: Option<Result<RefreshReport, IndexError>>,
    /// Settle hit `IndexError::OutboxStuck` (not fatal by itself).
    pub commit_blocked: Option<String>,
    pub cancel: tokio_util::sync::CancellationToken,
    pub tokens: Option<Arc<TokenProvider>>,
}

impl Ctx {
    /// For commands that must publish index changes (copy/sync up, mkdir, rm, mv, restore):
    /// `Err(IndexError::OutboxStuck)` if blocked.
    pub fn require_commit(&self) -> Result<(), IndexError> {
        match self
            .commit_blocked
            .clone()
            .or_else(|| self.vault.outbox_stuck())
        {
            Some(cause) => Err(IndexError::OutboxStuck(cause)),
            None => Ok(()),
        }
    }

    /// What a read-only command says about the state of its replica (§7.1, §10): the lock was
    /// busy, or the refresh came back with a verdict. The command continues either way.
    pub fn report_refresh(&self) {
        match &self.refresh {
            None if self.lock.is_none() => self.ui.info(&format!("note: {NOT_REFRESHED}")),
            Some(Err(e)) => self.ui.warn(&stale_text(e)),
            Some(Ok(report)) => warn_corrupt(&self.ui, report),
            None => {}
        }
    }
}

/// What a read-only command says when the lock was busy (§7.1).
pub(crate) const NOT_REFRESHED: &str = "index not refreshed (another gclone is running)";

/// What a read-only command says about a refresh that failed and left it with the replica.
pub(crate) fn stale_text(e: &IndexError) -> String {
    format!(
        "{e}. Showing the last state this device has seen{}",
        if needs_repair(e) {
            "; run `gclone repair`."
        } else {
            "."
        }
    )
}

/// The failures whose fix is `gclone login` (or the Worker's configuration), not waiting: this
/// login no longer works, or no longer sees the vault. An auth Worker that cannot be reached
/// (`AuthError::Network`: offline, Worker down, rate limit, quota page) or a local I/O error on
/// the way to a token says nothing about the login — it is a network condition like an
/// unreachable Drive, and `RefreshPolicy::Tolerant` treats it as one (§9.10, §17.9).
pub(crate) fn login_failure(e: &IndexError) -> bool {
    match e {
        IndexError::VaultNotVisible | IndexError::Backend(BackendError::AppNotAuthorized) => true,
        IndexError::Backend(BackendError::Auth(auth)) => {
            !matches!(auth, AuthError::Network(_) | AuthError::Io(_))
        }
        _ => false,
    }
}

fn needs_repair(e: &IndexError) -> bool {
    matches!(e, IndexError::Gap { .. } | IndexError::Rollback { .. })
}

/// Index objects that the refresh could not verify and left out, if any.
pub(crate) fn corrupt_text(report: &RefreshReport) -> Option<String> {
    (!report.corrupt_objects.is_empty()).then(|| {
        format!(
            "{} index object(s) failed verification (damaged, oversized, or not written with \
             this vault's key) and were ignored: {}",
            report.corrupt_objects.len(),
            report.corrupt_objects.join(", ")
        )
    })
}

fn warn_corrupt(ui: &Ui, report: &RefreshReport) {
    if let Some(text) = corrupt_text(report) {
        ui.warn(&text);
    }
}

// ---------------------------------------------------------------------------------------------
// Process-wide pieces: the Ctrl-C token and what the error texts of §2.8 need to name
// ---------------------------------------------------------------------------------------------

/// Cancelled by the first Ctrl-C (`cli::run` installs the handler); every `Ctx` carries a clone.
pub(crate) fn cancel_token() -> tokio_util::sync::CancellationToken {
    static TOKEN: OnceLock<tokio_util::sync::CancellationToken> = OnceLock::new();
    TOKEN.get_or_init(Default::default).clone()
}

/// Facts a command learnt before it failed, for the user-facing texts of §2.8.
#[derive(Clone, Default)]
pub(crate) struct Hints {
    pub auth_url: Option<String>,
    /// `config.backend.path` of a directory vault.
    pub vault_dir: Option<std::path::PathBuf>,
    pub refresh_expires_at_ms: Option<u64>,
    pub secrets_file: Option<std::path::PathBuf>,
    /// The login on file was made through the Worker's legacy client (gclone before 0.2.0).
    pub legacy_login: bool,
}

fn hints_cell() -> &'static Mutex<Hints> {
    static HINTS: OnceLock<Mutex<Hints>> = OnceLock::new();
    HINTS.get_or_init(Default::default)
}

pub(crate) fn hints() -> Hints {
    hints_cell()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

pub(crate) fn note(update: impl FnOnce(&mut Hints)) {
    update(&mut hints_cell().lock().unwrap_or_else(|e| e.into_inner()));
}

pub(crate) fn note_config(paths: &Paths, config: &Config) {
    note(|h| {
        h.secrets_file = Some(paths.secrets_file());
        if let BackendCfg::Dir { path } = &config.backend {
            h.vault_dir = Some(path.clone());
        }
        if h.auth_url.is_none() {
            h.auth_url = config.auth_url.clone();
        }
    });
}

pub(crate) fn note_secrets(secrets: &Secrets) {
    note(|h| {
        if secrets.auth_url.is_some() {
            h.auth_url = secrets.auth_url.clone();
        }
        h.refresh_expires_at_ms = secrets.refresh_expires_at_ms;
        h.legacy_login = secrets.has_login() && secrets.client.is_legacy();
    });
}

/// The value of a test-only switch of §7.1 — honoured only by builds with debug assertions.
pub(crate) fn test_env(name: &str) -> Option<String> {
    if cfg!(debug_assertions) {
        std::env::var(name).ok().filter(|v| !v.is_empty())
    } else {
        None
    }
}

pub(crate) fn ui_for(g: &GlobalOpts) -> Ui {
    Ui::new(UiOpts {
        json: g.json,
        quiet: g.quiet,
        verbose: g.verbose,
    })
}

/// Blocking work (terminal prompts, key derivation, SQLite) with owned inputs, off the async
/// threads.
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> anyhow::Result<T> {
    match tokio::task::spawn_blocking(f).await {
        Ok(out) => out,
        Err(e) => match e.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            Err(_) => Err(SyncError::Interrupted.into()),
        },
    }
}

/// The exclusive process lock of §8.3, waiting up to `LOCK_WAIT`.
pub(crate) async fn lock_state(state_dir: &Path) -> anyhow::Result<StateLock> {
    let dir = state_dir.to_path_buf();
    blocking(move || Ok(state::lock_exclusive(&dir, LOCK_WAIT)?)).await
}

/// The name this device was given at `login` (kept in `state.db`), else the host name.
pub(crate) fn stored_device_name(db: &Db) -> Result<String, StateError> {
    Ok(db
        .meta_get("device_name")?
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(util::hostname))
}

/// Loads config + secrets, builds the backend, takes the lock, opens the vault, then applies
/// `o.refresh` and `o.settle`. In TryShared mode a busy lock means: no refresh, no settle,
/// replica used as is.
/// Errors before anything is opened (all exit 4, §2.8), checked in this order — the same for
/// BOTH backends unless stated:
///   no config.json                                      → ConfigError::NotConfigured
///   secrets file with unsafe permissions                → InsecurePermissions
///   no secrets file (e.g. after `logout`)               → NotLoggedIn   (directory vault: the message names `login --vault-dir <path>`)
///   Drive vault whose secrets hold no refresh token     → NotLoggedIn
///   secrets with keys == []                             → Locked
pub async fn open_ctx(g: &GlobalOpts, o: OpenOpts) -> anyhow::Result<Ctx> {
    let ui = ui_for(g);
    let paths = Paths::resolve()?;
    note(|h| h.secrets_file = Some(paths.secrets_file()));
    let config = Config::load(&paths)?;
    note_config(&paths, &config);
    let secrets = secret_store(&paths)
        .load()?
        .ok_or(ConfigError::NotLoggedIn)?;
    note_secrets(&secrets);
    if matches!(config.backend, BackendCfg::Drive) && !secrets.has_login() {
        return Err(ConfigError::NotLoggedIn.into());
    }
    let vault_id = config.vault_id_bytes()?;
    let keys = secrets.keyring(vault_id)?;
    let (backend, tokens) = build_backend(&config, &secrets, &paths, o.transfers)?;
    drop(secrets);

    let (vault, lock) = open_vault(&paths, &config, Arc::new(backend), keys, Some(o.lock)).await?;

    let mut refresh = None;
    let mut commit_blocked = None;
    if lock.is_some() && o.refresh != RefreshPolicy::Skip {
        let result = vault.refresh().await;
        refresh = Some(match (result, o.refresh) {
            (Ok(report), _) => Ok(report),
            // Read-only commands continue on the replica after an integrity verdict or while
            // the store — or the auth Worker in front of it — is unreachable; a login that no
            // longer works (exit 4) is never papered over — its fix is `gclone login`, not
            // waiting.
            (Err(e), RefreshPolicy::Tolerant) if !login_failure(&e) => Err(e),
            (Err(e), _) => return Err(e.into()),
        });
        if o.settle && o.lock == LockMode::Exclusive && matches!(refresh, Some(Ok(_))) {
            match settle(&vault).await {
                Ok(()) => {}
                Err(IndexError::OutboxStuck(cause)) => commit_blocked = Some(cause),
                Err(e) => return Err(e.into()),
            }
        }
    }
    if let Some(Ok(report)) = &refresh
        && o.refresh == RefreshPolicy::Required
    {
        warn_corrupt(&ui, report);
    }
    Ok(Ctx {
        paths,
        config,
        vault,
        ui,
        lock,
        refresh,
        commit_blocked,
        cancel: cancel_token(),
        tokens,
    })
}

/// The vault over this device's replica (§8.3): with the state lock when `lock` asks for one
/// and gets it, otherwise — `None`, or a busy `TryShared` — read as it is, for queries and
/// downloads only. `open_ctx` uses it once per command; `gclone web` (§7.4) keeps a lock-less
/// vault for its whole life (`lock: None`).
pub(crate) async fn open_vault(
    paths: &Paths,
    config: &Config,
    backend: Arc<AnyBackend>,
    keys: Keyring,
    lock: Option<LockMode>,
) -> anyhow::Result<(Vault<AnyBackend>, Option<StateLock>)> {
    let state_dir = paths.state_dir(&config.vault_id);
    let lock = match lock {
        Some(LockMode::Exclusive) => Some(lock_state(&state_dir).await?),
        Some(LockMode::TryShared) => {
            let dir = state_dir.clone();
            blocking(move || Ok(state::try_lock(&dir)?)).await?
        }
        None => None,
    };
    let vault = open_replica(paths, config, backend, keys, lock.is_some()).await?;
    Ok((vault, lock))
}

/// The second half of `open_vault`. `locked`: the caller holds the state lock — `gclone web`
/// takes it for the length of each refresh, and only where state exists already
/// (`state::try_lock_existing`).
pub(crate) async fn open_replica(
    paths: &Paths,
    config: &Config,
    backend: Arc<AnyBackend>,
    keys: Keyring,
    locked: bool,
) -> anyhow::Result<Vault<AnyBackend>> {
    let db_file = paths.db_file(&config.vault_id);
    // Without the lock (TryShared, busy) nothing may be written to the state: the replica is
    // read as it is (§8.3). The lock holder may be inside a write transaction of many seconds
    // — a rebuild from a snapshot — and an open that wrote would wait for it and then fail.
    let (db, device_name) = blocking(move || {
        let db = if locked {
            Db::open(&db_file)?
        } else {
            Db::open_shared(&db_file)?
        };
        let name = stored_device_name(&db)?;
        Ok((db, name))
    })
    .await?;
    let params = OpenParams {
        vault_id: config.vault_id_bytes()?,
        handles: config.handles(),
        device_name,
        cache_dir: paths.index_cache_dir(&config.vault_id),
        machine_fp: None,
    };
    Ok(if locked {
        Vault::open(backend, db, keys, params).await?
    } else {
        Vault::open_unlocked(backend, db, keys, params).await?
    })
}

/// §5.8: leftover staged ops are published, and conflicts resolved, before anything is planned.
async fn settle(vault: &Vault<AnyBackend>) -> Result<(), IndexError> {
    vault.commit().await?;
    vault.resolve_conflicts().await?;
    Ok(())
}

/// Drive vaults: `drive_backend(secrets.endpoints()?, .., secrets.client, .., cache = true)`.
pub fn build_backend(
    cfg: &Config,
    secrets: &Secrets,
    paths: &Paths,
    transfers: usize,
) -> anyhow::Result<(AnyBackend, Option<Arc<TokenProvider>>)> {
    match &cfg.backend {
        BackendCfg::Dir { path } => {
            let backend = DirBackend::open(path)
                .with_context(|| format!("cannot open the vault directory {}", path.display()))?;
            Ok((AnyBackend::Dir(backend), None))
        }
        BackendCfg::Drive => {
            let token = secrets
                .refresh_token
                .as_deref()
                .filter(|t| !t.is_empty())
                .ok_or(ConfigError::NotLoggedIn)?;
            let (backend, tokens) = drive_backend(
                secrets.endpoints()?,
                token,
                secrets.client,
                paths,
                transfers,
                true,
            )?;
            Ok((AnyBackend::Drive(backend), Some(tokens)))
        }
    }
}

/// The Drive backend for a login alone — `login` needs it before a config exists (discovery,
/// vault creation). `cache`: true = the TokenProvider uses `paths.token_file()`; false = no
/// cache file at all. `login` ALWAYS passes false (§2.6: an access token obtained while signing
/// in must never reach token.json); every other command passes true. Honours the debug-only
/// `GCLONE_TEST_DRIVE_*` switches of §7.1 (as `build_backend` does). `client`: the OAuth client
/// `refresh_token` belongs to (`Secrets::client`). `GCLONE_TEST_FAST_PACER=1` (debug builds
/// only, like the other switches) takes the pacing away.
pub fn drive_backend(
    ep: AuthEndpoints,
    refresh_token: &str,
    client: AuthClient,
    paths: &Paths,
    transfers: usize,
    cache: bool,
) -> anyhow::Result<(DriveBackend, Arc<TokenProvider>)> {
    let http = crate::auth::http_client()?;
    let tokens = Arc::new(TokenProvider::new(
        http,
        ep,
        refresh_token.to_string(),
        client,
        cache.then(|| paths.token_file()),
    ));
    let mut cfg = DriveConfig {
        transfers: transfers.max(1),
        ..DriveConfig::default()
    };
    if let Some(api) = test_env("GCLONE_TEST_DRIVE_API") {
        cfg.endpoints.api = api;
    }
    if let Some(upload) = test_env("GCLONE_TEST_DRIVE_UPLOAD") {
        cfg.endpoints.upload = upload;
    }
    tracing::debug!(
        "drive backend: transfers={} api={}",
        cfg.transfers,
        cfg.endpoints.api
    );
    // Tests that drive the binary against the fake Drive: no pacing, millisecond backoff (the
    // settings of the library tests' `fast_pacer`).
    let fast = test_env("GCLONE_TEST_FAST_PACER").as_deref() == Some("1");
    if fast {
        let (rate, floor) = (1_000_000.0, 10_000.0);
        cfg.pacer = crate::backend::drive::PacerConfig {
            write_start: rate,
            write_min: floor,
            write_max: rate,
            read_start: rate,
            read_min: floor,
            read_max: rate,
            units_per_min: u32::MAX,
            ..Default::default()
        };
    }
    let backend = DriveBackend::new(tokens.clone(), cfg)?;
    if fast {
        backend
            .pacer()
            .set_backoff_unit(std::time::Duration::from_millis(2));
    }
    Ok((backend, tokens))
}

/// Keyfile KDF parameters for `login` and `passwd`: `KdfParams::default()` (256 MiB, t = 3,
/// p = 1) — or, only in builds with debug assertions and only when `GCLONE_TEST_FAST_KDF=1`,
/// `{ m_kib: 8192, t: 1, p: 1 }` (§7.1).
pub fn kdf_params() -> KdfParams {
    if test_env("GCLONE_TEST_FAST_KDF").as_deref() == Some("1") {
        KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
        }
    } else {
        KdfParams::default()
    }
}

/// The first line of `--passphrase-file` (e.g. `/dev/fd/3`), without its line break.
fn passphrase_line(file: &Path) -> anyhow::Result<Zeroizing<String>> {
    const MAX: u64 = 64 * 1024;
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(file)
        .and_then(|f| f.take(MAX).read_to_end(&mut bytes))
        .with_context(|| format!("cannot read the passphrase file {}", file.display()))?;
    let line = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    match std::str::from_utf8(line) {
        Ok(text) => Ok(Zeroizing::new(text.to_owned())),
        Err(_) => anyhow::bail!("the passphrase file {} is not UTF-8 text", file.display()),
    }
}

fn no_terminal() -> anyhow::Error {
    SyncError::Usage(
        "a passphrase is needed and there is no terminal to ask on: pass --passphrase-file PATH \
         (the first line of the file; for example /dev/fd/3)"
            .into(),
    )
    .into()
}

fn prompt_secret(ui: &Ui, question: &str) -> anyhow::Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        ui.prompt_secret(question)
            .context("cannot read from the terminal")?,
    ))
}

/// A passphrase for setting (prompt twice / generate on empty input / `--passphrase-file`), per §2.6.
pub fn read_new_passphrase(ui: &Ui, file: Option<&Path>) -> anyhow::Result<Passphrase> {
    if let Some(file) = file {
        // Same minimum as at the prompt, so an empty line is refused: a passphrase is generated
        // only where it can be shown to a person.
        let pass = Passphrase::set_checked(&passphrase_line(file)?).with_context(|| {
            format!(
                "the passphrase in {} cannot be used (an empty line does not generate one)",
                file.display()
            )
        })?;
        note_exact_spelling(ui, &pass);
        return Ok(pass);
    }
    if !ui.is_tty() {
        return Err(no_terminal());
    }
    loop {
        let typed = prompt_secret(
            ui,
            "New passphrase (leave empty to let gclone generate a strong one):",
        )?;
        if typed.is_empty() {
            let pass = Passphrase::generate();
            // Shown exactly once, on the terminal the prompt ran on — also with -q and --json.
            eprintln!("Generated passphrase:  {}", pass.display().as_str());
            eprintln!(
                "Store it in your password manager. It is needed once on every new device and \
                 cannot be recovered."
            );
            return Ok(pass);
        }
        let pass = match Passphrase::set_checked(&typed) {
            Ok(pass) => pass,
            Err(e @ FormatError::WeakPassphrase) => {
                ui.error(&format!("{e}"));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        if pass.char_count() < PASSPHRASE_WARN_CHARS {
            ui.warn(
                "This passphrase is short. Anyone who can read the vault folder, Google \
                 included, can try guesses against it offline, for as long as they like — and \
                 changing the passphrase later does not take a weak one back (the old keyfile \
                 stays good for whoever copied it). Prefer five or more random words, or the \
                 generated passphrase (26 characters, 130 bits).",
            );
            if !ui.confirm("Use this passphrase anyway?") {
                continue;
            }
        }
        // Compared as it is set: a typed passphrase is exact in case and spacing (§2.6).
        let again = Passphrase::for_setting(&prompt_secret(ui, "Repeat:")?);
        if again.display() == pass.display() {
            note_exact_spelling(ui, &pass);
            return Ok(pass);
        }
        ui.error("the two entries differ");
    }
}

/// §2.6: a passphrase that is set in the shape of a generated one, but not in the form gclone
/// displays, is a typed passphrase — kept exactly as typed, so that gclone 0.4.0 and a hosted
/// viewer of that version open the keyfile with it too. Said once, where it is set: the shape
/// invites the assumption that case and grouping do not matter.
fn note_exact_spelling(ui: &Ui, pass: &Passphrase) {
    if pass.looks_generated() {
        ui.warn(
            "This passphrase has the shape of a generated one (26 letters and digits) but is \
             not written the way gclone displays one: it is kept exactly as entered. Enter it \
             with the same capitals, spaces and hyphens every time.",
        );
    }
}

/// A passphrase for entering (prompt / file), per §2.6.
pub fn read_passphrase(ui: &Ui, file: Option<&Path>) -> anyhow::Result<Passphrase> {
    if let Some(file) = file {
        return Ok(Passphrase::from_input(&passphrase_line(file)?));
    }
    if !ui.is_tty() {
        return Err(no_terminal());
    }
    Ok(Passphrase::from_input(&prompt_secret(ui, "Passphrase:")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `RefreshPolicy::Tolerant` refuses to continue on (exit 4) and what it treats like an
    /// unreachable store.
    #[test]
    fn login_failure_is_a_dead_login_not_an_unreachable_worker() {
        let auth = |e: AuthError| IndexError::Backend(BackendError::Auth(e));
        for dead in [
            IndexError::VaultNotVisible,
            IndexError::Backend(BackendError::AppNotAuthorized),
            auth(AuthError::Expired),
            auth(AuthError::NotAllowed("a@example.com".into())),
            auth(AuthError::Denied("access_denied".into())),
            auth(AuthError::ScopeMissing),
            auth(AuthError::WorkerMisconfigured("client_invalid".into())),
        ] {
            assert!(login_failure(&dead), "{dead}");
        }
        for tolerated in [
            auth(AuthError::Network("connection refused".into())),
            auth(AuthError::Io(std::io::Error::other("disk"))),
            IndexError::Backend(BackendError::Transient("backendError".into())),
            IndexError::Gap {
                names: vec!["x".into()],
            },
        ] {
            assert!(!login_failure(&tolerated), "{tolerated}");
        }
    }

    #[test]
    fn passphrase_file_gives_its_first_line() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("pass");
        let ui = Ui::silent();

        std::fs::write(&file, "correct horse battery\r\nsecond line\n").unwrap();
        let entered = read_passphrase(&ui, Some(&file)).unwrap();
        assert_eq!(entered.display().as_str(), "correct horse battery");
        let set = read_new_passphrase(&ui, Some(&file)).unwrap();
        assert_eq!(set.display().as_str(), "correct horse battery");

        std::fs::write(&file, "elevenchars\n").unwrap();
        let err = read_new_passphrase(&ui, Some(&file)).err().unwrap();
        assert!(matches!(
            crate::error::find::<FormatError>(&err),
            Some(FormatError::WeakPassphrase)
        ));

        for empty in ["", "\n", "\nnot the first line\n"] {
            std::fs::write(&file, empty).unwrap();
            assert!(
                read_new_passphrase(&ui, Some(&file)).is_err(),
                "an empty first line must not generate a passphrase"
            );
        }
        assert!(read_passphrase(&ui, Some(&tmp.path().join("absent"))).is_err());
    }

    #[test]
    fn without_a_terminal_and_without_a_file_it_is_a_usage_error() {
        let ui = Ui::silent();
        for err in [
            read_passphrase(&ui, None).err().unwrap(),
            read_new_passphrase(&ui, None).err().unwrap(),
        ] {
            assert_eq!(crate::error::exit_code(&err), 2);
            assert!(err.to_string().contains("--passphrase-file"));
        }
    }

    #[test]
    fn kdf_parameters_are_the_production_ones_unless_the_test_switch_is_set() {
        // The switch is read from the environment of this process; tests do not set it.
        if std::env::var_os("GCLONE_TEST_FAST_KDF").is_none() {
            assert_eq!(kdf_params(), KdfParams::default());
        }
    }
}

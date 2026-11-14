//! `gclone login` (SPEC §2.4, §2.6, §9.10, §10) — owned by WP7.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use bytes::Bytes;
use zeroize::Zeroizing;

use super::{
    GlobalOpts, VAULT_NOT_VISIBLE, blocking, drive_backend, explained, kdf_params, lock_state,
    note, note_config, read_new_passphrase, read_passphrase, stored_device_name, ui_for, usage,
};
use crate::auth::{self, AuthClient, AuthEndpoints, InteractiveOpts, LoginGrant, TokenProvider};
use crate::backend::{AnyBackend, Backend as _, DirBackend, ObjMeta, get_all};
use crate::config::{BackendCfg, Config, Paths, SecretStore, Secrets, secret_store};
use crate::consts::{
    KEYFILE_LOOK_ALL_MAX, KEYFILE_LOOK_MAX, KEYFILE_MAX, KEYFILE_TRY_MAX, PROMPT_ATTEMPTS,
    TRANSFERS_DEFAULT,
};
use crate::crypto::{Keyring, MasterKey, Passphrase};
use crate::error::{AuthError, BackendError, ConfigError, CryptoError, FormatError, IndexError};
use crate::format::{KeyfilePayload, check_keyfile, open_keyfile, seal_keyfile};
use crate::index::{CreateParams, FoundVault, OpenParams, Vault, creation_winner};
use crate::keystore;
use crate::state::Db;
use crate::types::OpDraft;
use crate::ui::Ui;
use crate::util;

#[derive(clap::Args, Clone, Debug, Default)]
pub struct LoginArgs {
    /// The auth Worker's URL (needed the first time only; env GCLONE_AUTH_URL also works).
    pub auth_url: Option<String>,
    /// Do not open a browser: only print the sign-in address and code (enter the code on any device).
    #[arg(long)]
    pub no_browser: bool,
    /// Name of this device in the vault (default: the host name).
    #[arg(long, value_name = "NAME")]
    pub device_name: Option<String>,
    /// Name of the vault folder when a vault is created.
    #[arg(long, value_name = "NAME")]
    pub vault_name: Option<String>,
    /// Create a new vault although others exist.
    #[arg(long, conflicts_with = "vault_id")]
    pub new_vault: bool,
    /// Pick one of several vaults.
    #[arg(long, value_name = "HEX")]
    pub vault_id: Option<String>,
    /// Use a directory as the vault store (no Google account, no auth Worker).
    #[arg(long, value_name = "DIR", conflicts_with = "auth_url")]
    pub vault_dir: Option<PathBuf>,
    /// Read the passphrase from the first line of this file (e.g. /dev/fd/3).
    #[arg(long, value_name = "PATH")]
    pub passphrase_file: Option<PathBuf>,
    /// Accept a time-limited Google login (OAuth app still in Testing).
    #[arg(long)]
    pub allow_expiring_login: bool,
    /// Try the passphrase on every keyfile of the vault, not only on the four newest (slower:
    /// one key derivation each). For a vault whose folder holds keyfiles that are not yours.
    #[arg(long)]
    pub all_keyfiles: bool,
}

const DEFAULT_VAULT_NAME: &str = "gclone";

/// This device's Google login, as it goes into `secrets.json`.
#[derive(Clone)]
struct Login {
    auth_url: String,
    refresh_token: String,
    email: Option<String>,
    consent_ms: Option<u64>,
    refresh_expires_at_ms: Option<u64>,
    /// The Worker's OAuth client the refresh token belongs to.
    client: AuthClient,
    /// An interactive sign-in happened in this run (step A.3).
    fresh: bool,
    /// That sign-in replaces a login of the legacy client (gclone before 0.2.0) that is on file.
    replaces_legacy: bool,
}

/// Everything the vault part of the command needs.
struct Session {
    ui: Arc<Ui>,
    paths: Paths,
    store: Box<dyn SecretStore>,
    args: LoginArgs,
    backend_cfg: BackendCfg,
    backend: Arc<AnyBackend>,
    /// `None` for a directory vault.
    login: Option<Login>,
    config: Option<Config>,
}

impl Session {
    /// "this Drive" / the directory, for messages.
    fn place(&self) -> String {
        match &self.backend_cfg {
            BackendCfg::Drive => "this Drive".into(),
            BackendCfg::Dir { path } => path.display().to_string(),
        }
    }

    fn secrets(&self, keys: Option<&Keyring>) -> Secrets {
        let mut s = Secrets::empty();
        if let Some(login) = &self.login {
            s.auth_url = Some(login.auth_url.clone());
            s.refresh_token = Some(login.refresh_token.clone());
            s.email = login.email.clone();
            s.consent_ms = login.consent_ms;
            s.refresh_expires_at_ms = login.refresh_expires_at_ms;
            s.client = login.client;
        }
        if let Some(keys) = keys {
            s.set_keys(keys);
        }
        s
    }

    /// The device is connected from here on: `config.json` first, so that cached keys never
    /// exist without the vault they belong to.
    fn save_connected(
        &self,
        found: &FoundVault,
        vault_name: &str,
        keys: &Keyring,
    ) -> anyhow::Result<()> {
        let config = Config {
            version: 1,
            vault_id: util::hex(&found.vault_id),
            vault_name: vault_name.to_string(),
            backend: self.backend_cfg.clone(),
            auth_url: self.login.as_ref().map(|l| l.auth_url.clone()),
            root_id: found.handles.root.0.clone(),
            index_id: found.handles.index.0.clone(),
            data_id: found.handles.data.0.clone(),
        };
        config.save(&self.paths)?;
        // The keys were just opened from a keyfile, or made here: a sealed copy that this
        // run could not open is no longer the only place they are in (§8.2).
        self.store.save_proven(&self.secrets(Some(keys)))?;
        Ok(())
    }

    async fn passphrase(&self, new: bool) -> anyhow::Result<Passphrase> {
        let (ui, file) = (self.ui.clone(), self.args.passphrase_file.clone());
        blocking(move || {
            if new {
                read_new_passphrase(&ui, file.as_deref())
            } else {
                read_passphrase(&ui, file.as_deref())
            }
        })
        .await
    }
}

pub async fn run(g: &GlobalOpts, args: LoginArgs) -> anyhow::Result<i32> {
    let ui = Arc::new(ui_for(g));
    let paths = Paths::resolve()?;
    note(|h| h.secrets_file = Some(paths.secrets_file()));
    let store = secret_store(&paths);
    let config = match Config::load(&paths) {
        Ok(config) => Some(config),
        Err(ConfigError::NotConfigured) => None,
        Err(e) => return Err(e.into()),
    };
    if let Some(config) = &config {
        note_config(&paths, config);
    }
    // Before anything is loaded (a load takes the trial's step): a trial that is running on
    // this device and has not passed decides where the secrets go — signing out and in
    // again does not jump its bar (§8.2).
    let trial_undecided = keystore::trial_undecided(&paths);
    // A sealed key store that cannot be opened is "no usable secrets" for `login`, the one
    // command that can put the key back: it says why and goes on. The sealed file is not
    // touched until this login holds the key again (§8.2).
    let secrets = match store.load() {
        Err(ConfigError::KeyStoreUnavailable(why)) => {
            ui.warn(&why);
            None
        }
        loaded => loaded?,
    };
    // Found now rather than after the sign-in: the secrets could not be saved there (§8.1).
    if let Ok(md) = std::fs::symlink_metadata(&paths.state_root)
        && !(md.is_dir() && util::is_private(&md))
    {
        let dir = paths.state_root.display().to_string();
        return Err(ConfigError::InsecurePermissions(dir).into());
    }
    if let Some(name) = &args.vault_name {
        check_vault_name(name)?;
    }
    if let Some(config) = &config {
        let attached = format!(
            "this device is attached to vault {}; run `gclone logout --forget` first",
            config.vault_id
        );
        if args.new_vault {
            return Err(usage(format!("--new-vault: {attached}")));
        }
        if let Some(wanted) = &args.vault_id
            && parse_vault_id(wanted)? != config.vault_id_bytes()?
        {
            return Err(usage(format!("--vault-id: {attached}")));
        }
    }

    // --- step 0: which backend
    let given_dir = match &args.vault_dir {
        // Compared in canonical form; a directory that does not exist yet is created below,
        // once it is clear that it will be used.
        Some(dir) => Some(std::fs::canonicalize(dir).or_else(|_| std::path::absolute(dir))?),
        None => None,
    };
    let backend_cfg = login_backend(
        config.as_ref().map(|c| &c.backend),
        given_dir.as_deref(),
        args.auth_url.is_some(),
    )?;

    let (backend, login) = match &backend_cfg {
        // Only a directory named on the command line is created; the one a device is attached
        // to has to be there.
        BackendCfg::Dir { path } => (open_dir(path, config.is_none())?, None),
        BackendCfg::Drive => {
            let (backend, login) =
                sign_in(&ui, &paths, &args, config.as_ref(), secrets.as_ref()).await?;
            (backend, Some(login))
        }
    };
    let backend_cfg = match backend_cfg {
        BackendCfg::Dir { path } => BackendCfg::Dir {
            path: std::fs::canonicalize(&path)?,
        },
        drive => drive,
    };
    let cached_keys = secrets.as_ref().is_some_and(|s| !s.keys.is_empty());
    // Where the keys this login found came from (§8.2), looked at after the load above — which
    // may itself have moved a device whose trial had passed into the sealed store.
    let keys_from = match keystore::LayeredStore::new(&paths).resolve() {
        Ok(Some(loaded)) if cached_keys => Some(loaded.source),
        _ => None,
    };
    // The login of a keyless secrets.json with the keys of secrets.sealed (an older gclone
    // signed in on a sealed device, §8.2): this run writes the two as one file.
    let merged = keys_from == Some(keystore::Source::Merged);
    let before = KeyStoreBefore {
        // A device that was working from a plain file with keys: its secrets stay there
        // until the trial has passed (§17.30) — this login does not jump that queue.
        on_plain: keys_from == Some(keystore::Source::Plain),
        sealed: keys_from == Some(keystore::Source::Sealed),
        trial_undecided,
    };
    let session = Session {
        ui,
        paths,
        store,
        args,
        backend_cfg,
        backend: Arc::new(backend),
        login,
        config,
    };

    // --- step B.1: a connected device that only signed in again
    if let (Some(config), true) = (&session.config, cached_keys) {
        let code = relogin(&session, config, secrets, merged).await?;
        settle_key_store(&session.ui, &session.paths, before).await?;
        return Ok(code);
    }

    // --- step A.4: not connected yet — keep the grant, so that it survives a later failure.
    // Not yet on a device that is attached to a vault (config.json without a cached key: after
    // `logout`, or a first login that was interrupted): there the grant is kept only once that
    // vault was found with it (below). A sign-in with the wrong Google account must not become
    // the login on file — every later `gclone login` would find a login that works, never ask
    // again, and fail on the vault again.
    // Not yet either where the sign-in replaces a login of the legacy client on a device that
    // is not attached (signed in with gclone before 0.2.0, the vault part never finished): a
    // vault made through that client may exist and be invisible to the new login (§17.18), so
    // the old login — which cannot be issued again — is given up only once a vault was seen.
    let fresh = session.login.as_ref().filter(|l| l.fresh);
    let unattached_legacy = fresh.is_some_and(|l| l.replaces_legacy) && session.config.is_none();
    if let Some(login) = fresh {
        if session.config.is_none() && !unattached_legacy {
            session.store.save(&session.secrets(None))?;
        }
        match &login.email {
            Some(email) => session.ui.out(&format!("Signed in as {email}.")),
            None => session.ui.out("Signed in."),
        }
    }
    drop(secrets);

    // --- step B.2
    let found = Vault::discover(&*session.backend).await?;
    let configured = match &session.config {
        Some(config) => Some(config.vault_id_bytes()?),
        None => None,
    };
    let wanted = match &session.args.vault_id {
        Some(hex) => Some(parse_vault_id(hex)?),
        None => None,
    };
    let choice = choose_vault(
        &found,
        configured,
        session.args.new_vault,
        wanted,
        session.ui.is_tty(),
    )
    .map_err(|e| match (&session.backend_cfg, configured) {
        // A directory has no "other Google account" to blame.
        (BackendCfg::Dir { path }, Some(id)) => explained(
            e,
            format!(
                "The vault this device is attached to ({}) is not in {}. Put the vault folder \
                 back, or run `gclone logout --forget` and `gclone login --vault-dir DIR`.",
                util::hex(&id),
                path.display()
            ),
        ),
        (BackendCfg::Drive, Some(_)) => not_visible_hint(e, session.login.as_ref()),
        _ => e,
    })?;
    // "No vault here" is what a login that cannot see the old client's files looks like: not
    // the moment to create a second vault without being asked to (`--new-vault`).
    if unattached_legacy && found.is_empty() && !session.args.new_vault {
        return Err(no_vault_for_legacy_login(session.login.as_ref()));
    }
    // The attached vault is visible to the login made in this run: now it is worth keeping.
    if fresh.is_some() && (session.config.is_some() || unattached_legacy) {
        session.store.save(&session.secrets(None))?;
    }
    match choice {
        VaultChoice::Create => create(&session).await?,
        VaultChoice::Attach(i) => attach(&session, &found[i]).await?,
        VaultChoice::Ask => {
            let options: Vec<String> = found.iter().map(vault_line).collect();
            let ui = session.ui.clone();
            let picked = blocking(move || {
                let options: Vec<&str> = options.iter().map(String::as_str).collect();
                Ok(ui.choose("Several gclone vaults exist. Which one?", &options))
            })
            .await?
            .ok_or_else(|| usage("no vault was chosen (pass --vault-id HEX to pick one)"))?;
            attach(&session, &found[picked]).await?
        }
    }
    settle_key_store(&session.ui, &session.paths, before).await?;
    Ok(0)
}

/// Where this device's keys were when the login began.
#[derive(Copy, Clone)]
struct KeyStoreBefore {
    /// In `secrets.json`.
    on_plain: bool,
    /// In `secrets.sealed`.
    sealed: bool,
    /// A trial was running and had not passed (`keystore::trial_undecided`).
    trial_undecided: bool,
}

/// The end of every login (§8.2, §17.30). On a Mac the sealed store is the default: the
/// saves above put a new login there from the start, and what ended in the plain file all
/// the same — this login found a sealed file that did not open, or an older gclone's login
/// beside the sealed key — is moved now (`keystore::seal_after_login`), unless the device was
/// working from the plain file before, or a trial was running there that had not passed (a
/// `logout` and a `login` in the middle of it): there the trial decides. Says where the secrets are
/// when that changed, and warns when a login ended in the plain file although the owner
/// chose the sealed store.
async fn settle_key_store(ui: &Ui, paths: &Paths, before: KeyStoreBefore) -> anyhow::Result<()> {
    let after = if before.on_plain {
        None
    } else {
        let store = keystore::LayeredStore::new(paths);
        let undecided = before.trial_undecided;
        Some(blocking(move || Ok(keystore::seal_after_login(&store, undecided))).await?)
    };
    match after {
        Some(keystore::AfterLogin::Sealed | keystore::AfterLogin::Moved) if !before.sealed => {
            ui.info(
                "This device's login and key are sealed by this Mac's Secure Enclave \
                 (secrets.sealed): a copy of that file is useless anywhere else. If this Mac is \
                 erased or repaired, `gclone login` and the passphrase connect it again. \
                 `gclone keystore use file` keeps a plain file instead.",
            );
        }
        Some(keystore::AfterLogin::Plain(Some(why))) => {
            tracing::debug!("this login stays in secrets.json: {why}");
        }
        _ => {}
    }
    if keystore::read_choice(paths) == keystore::Choice::Enclave
        && std::fs::symlink_metadata(paths.secrets_file()).is_ok()
    {
        ui.warn(
            "this login was saved to the plain file secrets.json although the sealed key store \
             was chosen: the sealed file could not be opened, or the Secure Enclave could not \
             be used in this session. `gclone keystore use enclave` moves it there.",
        );
    }
    Ok(())
}

fn check_vault_name(name: &str) -> anyhow::Result<()> {
    let bad = name.is_empty()
        || name.starts_with('.')
        || name.len() > 255
        || name.chars().any(|c| c == '/' || c.is_control());
    if bad {
        return Err(usage(format!(
            "--vault-name {name:?}: a vault name is 1 to 255 bytes without '/' or control \
             characters and does not start with '.'"
        )));
    }
    Ok(())
}

fn parse_vault_id(text: &str) -> anyhow::Result<[u8; 16]> {
    util::unhex(&text.to_ascii_lowercase())
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .ok_or_else(|| usage(format!("--vault-id {text}: a vault id is 32 hex digits")))
}

fn open_dir(path: &Path, create: bool) -> anyhow::Result<AnyBackend> {
    if create {
        std::fs::create_dir_all(path)
            .with_context(|| format!("cannot create the vault directory {}", path.display()))?;
    }
    let backend = DirBackend::open(path)
        .with_context(|| format!("cannot open the vault directory {}", path.display()))?;
    Ok(AnyBackend::Dir(backend))
}

/// `"gclone"  created 2026-11-11  id 9f2c11aa…` — one found vault, for menus and error lists.
fn vault_line(v: &FoundVault) -> String {
    let name = if v.root_name.is_empty() {
        "(top level)".to_string()
    } else {
        format!("{:?}", v.root_name)
    };
    format!(
        "{name}  created {}  id {}",
        created_date(v),
        util::hex(&v.vault_id)
    )
}

fn created_date(v: &FoundVault) -> String {
    util::format_local_minute(v.descriptor_created_ms)[..10].to_string()
}

// ---------------------------------------------------------------------------------------------
// A. Sign in (Drive backend)
// ---------------------------------------------------------------------------------------------

async fn sign_in(
    ui: &Ui,
    paths: &Paths,
    args: &LoginArgs,
    config: Option<&Config>,
    secrets: Option<&Secrets>,
) -> anyhow::Result<(AnyBackend, Login)> {
    // A.1
    let stored = secrets
        .and_then(|s| s.auth_url.clone())
        .or_else(|| config.and_then(|c| c.auth_url.clone()));
    let env = std::env::var("GCLONE_AUTH_URL").ok();
    let auth_url =
        auth::resolve_auth_url(args.auth_url.as_deref(), env.as_deref(), stored.as_deref())?;
    note(|h| h.auth_url = Some(auth_url.clone()));
    let ep = AuthEndpoints::new(&auth_url)?;

    // A.2: the login on file still works. Not for a login of the legacy client: `gclone login`
    // is how a device moves to the device client, so that one is always replaced.
    let on_file = secrets.filter(|s| s.has_login());
    let replaces_legacy = on_file.is_some_and(|s| s.client.is_legacy());
    if let Some(s) = on_file.filter(|_| !replaces_legacy)
        && let Some(token) = &s.refresh_token
        && s.endpoints().is_ok_and(|stored| stored.base == ep.base)
    {
        let (backend, tokens) =
            drive_backend(ep.clone(), token, s.client, paths, TRANSFERS_DEFAULT, false)?;
        match tokens.force_refresh().await {
            Ok(_) => {
                match &s.email {
                    Some(email) => ui.out(&format!("Already signed in as {email}.")),
                    None => ui.out("Already signed in."),
                }
                let login = Login {
                    auth_url,
                    refresh_token: token.clone(),
                    email: s.email.clone(),
                    consent_ms: s.consent_ms,
                    refresh_expires_at_ms: s.refresh_expires_at_ms,
                    client: s.client,
                    fresh: false,
                    replaces_legacy: false,
                };
                return Ok((AnyBackend::Drive(backend), login));
            }
            Err(e) => tracing::debug!("the stored login does not work any more: {e}"),
        }
    }

    // A.3
    if replaces_legacy {
        ui.info(
            "This device's Google login was made with the browser sign-in of gclone before \
             0.2.0. Signing in again replaces it; until that has worked, nothing on this \
             device changes.",
        );
    }
    let opts = InteractiveOpts {
        no_browser: want_headless(
            args.no_browser,
            &|name| std::env::var(name).ok(),
            cfg!(target_os = "linux"),
        ),
        // Needed to get through the sign-in at all: shown with -q and --json as well.
        print: Box::new(|line| eprintln!("{line}")),
        // Detached: some launchers stay alive as long as the browser does.
        open: Box::new(|url| drop(open::that_detached(url))),
    };
    let http = auth::http_client()?;
    let outcome = auth::login_interactive(&http, &ep, opts).await;
    // Whatever comes next: an access token of an earlier login must not serve later commands
    // (the new login may belong to another account), and `login` itself never writes one.
    remove_token_cache(paths);
    let grant = outcome?;
    let now = util::now_ms();
    let refresh_expires_at_ms = expiring_login_decision(&grant, args.allow_expiring_login, now)?;

    let (backend, tokens) = drive_backend(
        ep,
        &grant.refresh_token,
        AuthClient::Device,
        paths,
        TRANSFERS_DEFAULT,
        false,
    )?;
    prime(&tokens, &grant);
    let login = Login {
        auth_url,
        refresh_token: grant.refresh_token.clone(),
        email: Some(grant.email.clone()),
        consent_ms: Some(now),
        refresh_expires_at_ms,
        client: AuthClient::Device,
        fresh: true,
        replaces_legacy,
    };
    Ok((AnyBackend::Drive(backend), login))
}

fn prime(tokens: &TokenProvider, grant: &LoginGrant) {
    tokens.prime(&grant.access_token, grant.expires_at_ms);
}

fn remove_token_cache(paths: &Paths) {
    if let Err(e) = std::fs::remove_file(paths.token_file())
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!("cannot remove {}: {e}", paths.token_file().display());
    }
}

// ---------------------------------------------------------------------------------------------
// B. Vault
// ---------------------------------------------------------------------------------------------

/// B.1: the device is connected; check that this login (or directory) still shows its vault.
async fn relogin(
    s: &Session,
    config: &Config,
    secrets: Option<Secrets>,
    merged: bool,
) -> anyhow::Result<i32> {
    // On failure nothing was written: the token on file stays in use (§2.6).
    Vault::verify_visible(&*s.backend, &config.handles())
        .await
        .map_err(|e| match (&s.backend_cfg, &e) {
            (BackendCfg::Dir { path }, IndexError::VaultNotVisible) => {
                let text = format!(
                    "The vault this device is attached to is no longer in {}. Put the vault \
                     folder back, or run `gclone logout --forget` and `gclone login --vault-dir \
                     DIR`.",
                    path.display()
                );
                explained(e, text)
            }
            (BackendCfg::Drive, _) => not_visible_hint(e.into(), s.login.as_ref()),
            _ => e.into(),
        })?;
    let Some(login) = &s.login else {
        s.ui.out(&format!(
            "This device is already connected to vault {:?}. Nothing changed.",
            config.vault_name
        ));
        return Ok(0);
    };
    if !login.fresh {
        // The login still works and nothing is renewed — but where it lies in secrets.json
        // without a key, with the key in secrets.sealed, the two become one file now: the
        // save goes to secrets.json, and the sealed copy of the same keys is removed. (On a
        // Mac whose default is the sealed store the end of this login then moves that file
        // back into it, §17.30, and says so.)
        if merged && let Some(both) = &secrets {
            s.store.save(both)?;
            s.ui.info("The login in secrets.json and the key in secrets.sealed are one again.");
        }
        s.ui.out("Vault unchanged.");
        return Ok(0);
    }
    let mut updated = s.secrets(None);
    if let Some(old) = secrets {
        updated.keys = old.keys;
        updated.min_epoch = old.min_epoch;
    }
    if config.auth_url.as_deref() != Some(login.auth_url.as_str()) {
        let mut config = config.clone();
        config.auth_url = Some(login.auth_url.clone());
        config.save(&s.paths)?;
    }
    s.store.save(&updated)?;
    match &login.email {
        Some(email) => {
            s.ui.out(&format!("Signed in again as {email}. Vault unchanged."))
        }
        None => s.ui.out("Signed in again. Vault unchanged."),
    }
    Ok(0)
}

/// `VaultNotVisible` from `login` on a device that is attached to a vault, said so that the
/// next step is clear (§2.8). Nothing was written before it, whichever case it is.
///
/// - The login on file was kept (step A.2: it still works, so nobody was asked to sign in):
///   "sign in with the account that owns the vault" needs a `logout` first — `gclone login`
///   alone would keep this login for ever.
/// - A sign-in was just made and does not see the vault: another Google account — or the
///   vault was created through the Worker's legacy OAuth client (gclone before 0.2.0) and
///   Google does not show it to the device client. Whether Google does is unverified, so the
///   message names both and what keeps the device working meanwhile.
fn not_visible_hint(e: anyhow::Error, login: Option<&Login>) -> anyhow::Error {
    let not_visible = matches!(
        crate::error::find::<IndexError>(&e),
        Some(IndexError::VaultNotVisible)
    );
    let Some(login) = login.filter(|_| not_visible) else {
        return e;
    };
    let who = match &login.email {
        Some(email) => format!("signed in as {email}"),
        None => "signed in".to_string(),
    };
    let text = if !login.fresh {
        format!(
            "{VAULT_NOT_VISIBLE} This device is {who}, and `gclone login` keeps a login that \
             still works: to sign in with another account run `gclone logout` first, then \
             `gclone login`."
        )
    } else {
        let kept = if login.replaces_legacy {
            "Nothing was changed: this device keeps its previous login, which goes on working \
             only while the deployed auth Worker is older than gclone 0.4.0 and has its \
             GOOGLE_LEGACY_CLIENT_ID and GOOGLE_LEGACY_CLIENT_SECRET secrets."
        } else {
            "Nothing was changed on this device, and the new sign-in was not kept."
        };
        format!(
            "The Google login just made ({who}) cannot see the vault this device is attached \
             to. {kept} If that was not the Google account that owns the vault: run `gclone \
             login` again and choose the right one. If it was: Google does not show the \
             vault's files to this login — they were created through another OAuth client \
             (the browser sign-in of gclone before 0.2.0, or another Cloud project), or the \
             app was removed and approved again. See \"Moving from the browser sign-in\" in \
             worker/README.md for the ways out (move the vault while an auth Worker older than \
             0.4.0 is still deployed); the last resort is to download the vault folder from \
             drive.google.com, unzip it, and run `gclone logout --forget`, then `gclone login \
             --vault-dir DIR`."
        )
    };
    explained(e, text)
}

/// A device that holds a login of the legacy client (gclone before 0.2.0) and is attached to
/// no vault signed in again, and the new login finds no vault at all. That is the ordinary
/// first-device situation — and also exactly what it looks like when Google does not show a
/// vault made through the old OAuth client to the new one (unverified, §17.18). Creating a
/// vault here would make a second one beside the real one, so it takes `--new-vault`.
/// Nothing was written: the previous login stays on file.
fn no_vault_for_legacy_login(login: Option<&Login>) -> anyhow::Error {
    let who = match login.and_then(|l| l.email.as_deref()) {
        Some(email) => format!("signed in as {email}"),
        None => "signed in".to_string(),
    };
    explained(
        IndexError::VaultNotVisible,
        format!(
            "The Google login just made ({who}) sees no gclone vault. This device's previous \
             login was made with the browser sign-in of gclone before 0.2.0, so a vault \
             created back then may exist without being visible to the new login. Nothing was \
             changed: the previous login stays on file. First run `gclone login` on a device \
             that is attached to the vault and wait for \"Vault unchanged.\"; then run it here \
             again (see \"Moving from the browser sign-in\" in worker/README.md). If there \
             really is no vault yet, create one with `gclone login --new-vault`."
        ),
    )
}

fn device_name(args: &LoginArgs, stored: Option<String>) -> String {
    args.device_name
        .clone()
        .filter(|n| !n.trim().is_empty())
        .or(stored)
        .unwrap_or_else(util::hostname)
}

/// CREATE (first device).
async fn create(s: &Session) -> anyhow::Result<()> {
    s.ui.info(&format!("No gclone vault found in {}.", s.place()));
    let pass = s.passphrase(true).await?;
    let vault_id: [u8; 16] = util::random();
    let keys = Keyring::new(vault_id, vec![(1, MasterKey::generate())], 1)?;
    let device = device_name(&s.args, None);
    let vault_name = s
        .args
        .vault_name
        .clone()
        .unwrap_or_else(|| DEFAULT_VAULT_NAME.to_string());

    let payload = KeyfilePayload::from_keyring(&keys, 1, &device, util::now_ms());
    let params = kdf_params();
    let keyfile = blocking(move || {
        let sealed = seal_keyfile(&payload, &pass, params)?;
        // Self-test: what was just written must open with the passphrase just given.
        if open_keyfile(&sealed.name, &sealed.bytes, &pass)? != payload {
            anyhow::bail!("the new keyfile does not open to what was sealed");
        }
        Ok(sealed)
    })
    .await?;

    let vault_hex = util::hex(&vault_id);
    let state_dir = s.paths.state_dir(&vault_hex);
    let lock = lock_state(&state_dir).await?;
    s.ui.info(&format!("Creating vault {vault_name:?}..."));
    let created = async {
        let db_file = s.paths.db_file(&vault_hex);
        let db = blocking(move || Ok(Db::open(&db_file)?)).await?;
        let params = CreateParams {
            vault_id,
            vault_name: vault_name.clone(),
            device_name: device.clone(),
            cache_dir: s.paths.index_cache_dir(&vault_hex),
            machine_fp: None,
            keyfile,
        };
        Vault::create(s.backend.clone(), db, keys.clone(), params)
            .await
            .map_err(|e| name_conflict(e, s, &vault_name))
    }
    .await;
    let (vault, own) = match created {
        Ok(created) => created,
        Err(e) => {
            // The state of a vault that will never exist.
            drop(lock);
            let _ = std::fs::remove_dir_all(&state_dir);
            return Err(e);
        }
    };
    s.save_connected(&own, &vault_name, &keys)?;

    if !s.args.new_vault {
        match lost_race(s, &vault, &own).await {
            Ok(Some(winner)) => {
                drop(vault);
                drop(lock);
                Config::delete(&s.paths)?;
                // Back to "signed in, not connected": the login stays, the key goes.
                match &s.login {
                    // The keys just saved are those of the vault that lost: the one keyless
                    // save that may take the place of sealed keys (§8.2).
                    Some(_) => s
                        .store
                        .save_dropping_keys(&s.secrets(None), &s.secrets(Some(&keys)))?,
                    None => s.store.delete()?,
                }
                let _ = std::fs::remove_dir_all(&state_dir);
                s.ui.warn(
                    "Another device created the vault a moment earlier; using that one. The \
                     passphrase you just set here is NOT in use — enter the passphrase chosen \
                     on the other device.",
                );
                return attach(s, &winner).await;
            }
            Ok(None) => {}
            Err(e) => s.ui.warn(&format!(
                "could not check whether another device created a vault at the same time ({e}); \
                 `gclone status` will tell"
            )),
        }
    }
    s.ui.out(&format!("Vault created. This device: {device:?}."));
    s.ui.info("");
    s.ui.info("Try:  gclone copy ~/Documents :Documents");
    Ok(())
}

/// A directory cannot hold a second folder of the vault's name (§2.6 "two first devices").
fn name_conflict(e: IndexError, s: &Session, vault_name: &str) -> anyhow::Error {
    let conflict = matches!(
        &e,
        IndexError::Backend(BackendError::Fatal { status: 409, reason, .. }) if reason == "nameConflict"
    );
    match (&s.backend_cfg, conflict) {
        (BackendCfg::Dir { path }, true) => explained(
            e,
            format!(
                "`{}` exists but holds no complete vault (an interrupted `gclone login`?). \
                 Delete that folder, or choose another name with `--vault-name`.",
                path.join(vault_name).display()
            ),
        ),
        _ => e.into(),
    }
}

/// §2.6 "two first devices", step 2. `Some(winner)`: this device's vault lost and its root
/// folder is in the trash.
async fn lost_race(
    s: &Session,
    vault: &Vault<AnyBackend>,
    own: &FoundVault,
) -> Result<Option<FoundVault>, IndexError> {
    let mut found = Vault::discover(&*s.backend).await?;
    // This device's own vault always counts, listed or not.
    if !found.iter().any(|v| v.vault_id == own.vault_id) {
        found.push(own.clone());
    }
    match creation_race(&found, own.vault_id) {
        RaceOutcome::Alone => Ok(None),
        RaceOutcome::Won { other } => {
            s.ui.warn(&format!(
                "Another gclone vault ({}) was created at the same time on another device. \
                 This device's vault is the older one and stays; the other device switches to \
                 it at its next `gclone login`.",
                util::hex(&other)
            ));
            Ok(None)
        }
        RaceOutcome::Lost { winner } => {
            // The vault holds nothing but this run's first segment.
            vault.backend().trash(&own.handles.root).await?;
            Ok(Some(found.swap_remove(winner)))
        }
    }
}

/// One keyfile candidate of ATTACH: a well-formed keyfile (`format::check_keyfile`).
struct Candidate {
    name: String,
    bytes: Bytes,
    /// The passphrases that answered "wrong key" here: no pair is derived twice (§2.6).
    tried: Vec<Zeroizing<String>>,
}

/// What ATTACH found under the keyfile names of the vault's root.
#[derive(Default)]
struct Keyfiles {
    /// The well-formed keyfiles, highest generation first.
    candidates: Vec<Candidate>,
    /// Objects with a keyfile's name that are no keyfile: refused before any derivation.
    refused: usize,
    /// One of them was refused for a version this build does not read.
    newer: Option<FormatError>,
    /// Objects with a keyfile's name beyond the ones this login looks at.
    unseen: usize,
}

enum Unlock {
    Opened(Box<KeyfilePayload>),
    /// Every candidate that is left has answered "wrong key" to this passphrase.
    WrongPassphrase,
    /// As many candidates as one attempt may ask answered "wrong key"; this many were not
    /// asked. The passphrase may be right: "wrong passphrase" would be a guess.
    Untried(usize),
    /// No candidate is left to try.
    Unusable(FormatError),
}

/// Tries `pass` on the candidates, highest generation first, until one opens or `limit` of
/// them have answered "wrong key" — each of those is one key derivation, and the number of
/// well-formed keyfiles in a vault folder is up to whoever can write to it. A candidate that
/// already refused this passphrase — every reading of it (`Passphrase::readings`) — is not
/// asked again and does not count; one that fails with anything other than a wrong key is
/// dropped for the rest of the command (§2.6: each (keyfile, passphrase) pair runs at most
/// once, a passphrase being one reading of what was entered).
fn unlock(
    candidates: &mut Vec<Candidate>,
    pass: &Passphrase,
    vault_id: [u8; 16],
    limit: usize,
) -> Unlock {
    // Both readings of the input (§2.6): the canonical one, and the text as typed where that
    // is another passphrase. The memo is per reading — two spellings with one canonical form
    // are two passphrases to a keyfile that was sealed under the text as typed.
    let readings: Vec<(Zeroizing<String>, Passphrase)> = pass
        .readings()
        .into_iter()
        .map(|reading| (reading.display(), reading))
        .collect();
    let mut dropped = FormatError::KeyfileDamaged;
    let mut kept = Vec::new();
    let mut opened = None;
    let (mut wrong, mut untried) = (0, 0);
    for mut c in candidates.drain(..) {
        let fresh: Vec<&(Zeroizing<String>, Passphrase)> = readings
            .iter()
            .filter(|(text, _)| !c.tried.contains(text))
            .collect();
        if opened.is_some() || fresh.is_empty() {
            kept.push(c);
            continue;
        }
        if wrong >= limit {
            untried += 1;
            kept.push(c);
            continue;
        }
        // Only the readings this keyfile has not refused yet are derived, in their order.
        let mut answer = Err(FormatError::Crypto(CryptoError::WrongKey));
        let mut refused = Vec::new();
        for (text, reading) in fresh {
            answer = open_keyfile(&c.name, &c.bytes, reading);
            if !matches!(answer, Err(FormatError::Crypto(CryptoError::WrongKey))) {
                break;
            }
            refused.push(text.clone());
        }
        c.tried.append(&mut refused);
        match answer {
            Ok(payload) if payload.vault_id_bytes().is_ok_and(|id| id == vault_id) => {
                opened = Some(payload);
                kept.push(c);
            }
            Ok(_) => tracing::warn!("keyfile {} belongs to another vault; ignored", c.name),
            Err(FormatError::Crypto(CryptoError::WrongKey)) => {
                wrong += 1;
                kept.push(c);
            }
            Err(e) => {
                tracing::warn!("keyfile {} is not usable ({e}); ignored", c.name);
                if matches!(e, FormatError::KeyfileVersion(_)) {
                    dropped = e;
                }
            }
        }
    }
    *candidates = kept;
    match opened {
        Some(payload) => Unlock::Opened(Box::new(payload)),
        None if candidates.is_empty() => Unlock::Unusable(dropped),
        None if untried > 0 => Unlock::Untried(untried),
        None => Unlock::WrongPassphrase,
    }
}

/// The keyfiles ATTACH can try (§2.6). Every object under a keyfile's name is unauthenticated
/// — anyone who can write to the vault folder can put objects there, under any generation —
/// so the names only give the order, and what is fetched is bounded: at most `look_max`
/// objects of at most `KEYFILE_MAX` bytes. An object that is no keyfile (junk, another name's
/// content, parameters out of bounds, too large) is refused here, before any derivation, and
/// takes no place among the candidates: planted names of higher generations do not push the
/// real keyfile out.
async fn keyfile_candidates(
    backend: &AnyBackend,
    listed: &[ObjMeta],
    all: bool,
) -> anyhow::Result<Keyfiles> {
    let look_max = if all {
        KEYFILE_LOOK_ALL_MAX
    } else {
        KEYFILE_LOOK_MAX
    };
    let mut keyfiles = Keyfiles::default();
    let mut fetched = 0;
    for meta in listed {
        let ObjMeta {
            name, handle, size, ..
        } = meta;
        if *size > KEYFILE_MAX {
            tracing::warn!("keyfile {name} is too large; ignored");
            keyfiles.refused += 1;
            continue;
        }
        if fetched >= look_max {
            keyfiles.unseen += 1;
            continue;
        }
        fetched += 1;
        tracing::debug!("reading keyfile candidate {name}");
        // One byte more than allowed is asked for, so that an object that grew is noticed.
        let bytes = match get_all(backend, handle, Some(0..KEYFILE_MAX + 1)).await {
            Ok(bytes) => bytes,
            Err(BackendError::NotFound) => {
                tracing::warn!("keyfile {name} disappeared; ignored");
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        match check_keyfile(name, &bytes) {
            Ok(_) => keyfiles.candidates.push(Candidate {
                name: name.clone(),
                bytes,
                tried: Vec::new(),
            }),
            Err(e) => {
                tracing::warn!("keyfile {name} is not usable ({e}); ignored");
                keyfiles.refused += 1;
                if matches!(e, FormatError::KeyfileVersion(_)) {
                    keyfiles.newer = Some(e);
                }
            }
        }
    }
    Ok(keyfiles)
}

fn keyfiles_text(n: usize) -> String {
    match n {
        1 => "one keyfile".into(),
        n => format!("{n} keyfiles"),
    }
}

/// "one older keyfile was" / "3 older keyfiles were" (… not tried).
fn older_text(n: usize) -> String {
    match n {
        1 => "one older keyfile was".into(),
        n => format!("{n} older keyfiles were"),
    }
}

/// What to do about keyfiles that hide the real one, for the messages below.
const PLANTED_KEYFILES: &str = "Anyone who can write to the vault folder can put keyfiles of \
    their own in front of the real one; they cost a try each and open with nothing.";

/// " N more objects with keyfile names were not looked at …", or nothing.
fn unseen_text(unseen: usize, all: bool) -> String {
    if unseen == 0 {
        return String::new();
    }
    let more = if all {
        "remove the planted objects from the vault folder in drive.google.com".to_string()
    } else {
        format!("`gclone login --all-keyfiles` looks at up to {KEYFILE_LOOK_ALL_MAX}")
    };
    format!(
        " {unseen} more object(s) with keyfile names were not looked at ({more}; `gclone \
         passwd` on a connected device writes a keyfile ahead of them all)."
    )
}

/// Asks for the passphrase and opens one of the vault's keyfiles with it (§2.6): what ATTACH
/// does on a new device, and what `gclone keystore use enclave` does to prove that the
/// passphrase is still the way back. `listed`: the objects under keyfile names in the vault's
/// root. `retry_all`: the command that tries every keyfile, for the messages.
pub(super) async fn unlock_with_passphrase(
    ui: &Arc<Ui>,
    backend: &AnyBackend,
    listed: &[ObjMeta],
    vault_id: [u8; 16],
    passphrase_file: Option<&Path>,
    all: bool,
    retry_all: &str,
) -> anyhow::Result<Box<KeyfilePayload>> {
    let Keyfiles {
        mut candidates,
        refused,
        newer,
        unseen,
    } = keyfile_candidates(backend, listed, all).await?;
    if candidates.is_empty() {
        let e = newer.unwrap_or(FormatError::KeyfileDamaged);
        if unseen == 0 {
            return Err(e.into());
        }
        // Not "the keyfile is missing": this login has not looked at all of them.
        return Err(explained(
            e,
            format!(
                "None of the {refused} object(s) with keyfile names that this login looked at \
                 is a keyfile.{} {PLANTED_KEYFILES}",
                unseen_text(unseen, all)
            ),
        ));
    }
    // Asking is for a person at a terminal; `--passphrase-file` gets one attempt and no question.
    let interactive = passphrase_file.is_none();
    let attempts = if interactive { PROMPT_ATTEMPTS } else { 1 };
    let mut payload = None;
    let mut last = Unlock::WrongPassphrase;
    for attempt in 1..=attempts {
        let mut pass = {
            let (ui, file) = (ui.clone(), passphrase_file.map(Path::to_path_buf));
            blocking(move || read_passphrase(&ui, file.as_deref())).await?
        };
        // What one attempt may cost without being asked for more: `KEYFILE_TRY_MAX` derivations.
        let mut limit = if all { usize::MAX } else { KEYFILE_TRY_MAX };
        let outcome = loop {
            let (outcome, rest, pass_back) = blocking(move || {
                let outcome = unlock(&mut candidates, &pass, vault_id, limit);
                Ok((outcome, candidates, pass))
            })
            .await?;
            (candidates, pass) = (rest, pass_back);
            match outcome {
                Unlock::Untried(n)
                    if interactive
                        && ui.confirm(&format!(
                            "That passphrase does not open the {} newest keyfiles of this \
                             vault. Try it on the {} older one(s) too (a key derivation each)?",
                            candidates.len() - n,
                            n
                        )) =>
                {
                    limit = usize::MAX;
                }
                outcome => break outcome,
            }
        };
        match outcome {
            Unlock::Opened(p) => {
                payload = Some(p);
                break;
            }
            Unlock::Unusable(e) => return Err(e.into()),
            Unlock::WrongPassphrase if attempt < attempts => ui.error("Wrong passphrase."),
            Unlock::Untried(n) if attempt < attempts => ui.error(&format!(
                "That passphrase does not open the newest keyfiles of this vault; {} not tried.",
                older_text(n)
            )),
            Unlock::WrongPassphrase | Unlock::Untried(_) => {}
        }
        last = outcome;
    }
    let Some(payload) = payload else {
        // "Wrong passphrase" is said only when it is known: every keyfile of the vault was
        // asked. While some were not, the passphrase may be right (§2.6, §17.26).
        return Err(match last {
            Unlock::Untried(n) => explained(
                ConfigError::WrongPassphrase,
                format!(
                    "The passphrase does not open the {} newest keyfiles of this vault, and {} \
                     not tried.{} {PLANTED_KEYFILES} If the passphrase is right, run \
                     `{retry_all}`: it tries every keyfile, one key derivation each.",
                    candidates.len() - n,
                    older_text(n),
                    unseen_text(unseen, all)
                ),
            ),
            _ if unseen > 0 => explained(
                ConfigError::WrongPassphrase,
                format!(
                    "The passphrase opens none of the {} this login looked at.{} \
                     {PLANTED_KEYFILES}",
                    keyfiles_text(candidates.len()),
                    unseen_text(unseen, all)
                ),
            ),
            _ => ConfigError::WrongPassphrase.into(),
        });
    };
    Ok(payload)
}

/// ATTACH (every later device, and a device that comes back after `logout`).
async fn attach(s: &Session, found: &FoundVault) -> anyhow::Result<()> {
    let shown_name = if found.root_name.is_empty() {
        s.place()
    } else {
        format!("{:?}", found.root_name)
    };
    s.ui.info(&format!(
        "Found vault {shown_name} (created {}).",
        created_date(found)
    ));

    let payload = unlock_with_passphrase(
        &s.ui,
        &s.backend,
        &found.keyfiles,
        found.vault_id,
        s.args.passphrase_file.as_deref(),
        s.args.all_keyfiles,
        "gclone login --all-keyfiles",
    )
    .await?;
    let keys = payload.keyring()?;
    drop(payload);

    // The key stays in memory until the other devices can see this one.
    let vault_hex = util::hex(&found.vault_id);
    let state_dir = s.paths.state_dir(&vault_hex);
    let _lock = lock_state(&state_dir).await?;
    let db_file = s.paths.db_file(&vault_hex);
    // A device that comes back after `logout` keeps the name it had.
    let (db, stored_name) = blocking(move || {
        let db = Db::open(&db_file)?;
        let name = stored_device_name(&db)?;
        Ok((db, name))
    })
    .await?;
    let device = device_name(&s.args, Some(stored_name));
    let vault = Vault::open(
        s.backend.clone(),
        db,
        keys.clone(),
        OpenParams {
            vault_id: found.vault_id,
            handles: found.handles.clone(),
            device_name: device.clone(),
            cache_dir: s.paths.index_cache_dir(&vault_hex),
            machine_fp: None,
        },
    )
    .await?;
    let verdict = register(&vault, &device).await.context(
        "this device could not be registered in the vault; nothing was saved — run `gclone \
         login` again",
    )?;

    let vault_name = match vault.vault_name() {
        name if !name.is_empty() => name,
        _ if !found.root_name.is_empty() => found.root_name.clone(),
        _ => DEFAULT_VAULT_NAME.to_string(),
    };
    s.save_connected(found, &vault_name, &keys)?;

    let files = util::group_thousands(vault.stats(vault.backend().now_ms())?.files);
    s.ui.out(&format!(
        "Connected to vault {vault_name:?} ({files} files). This device: {device:?}."
    ));
    if let Some(verdict) = verdict {
        // Connected all the same: `gclone repair` needs the key this login just saved, and
        // this device's index cache may hold exactly the objects the vault is missing.
        s.ui.warn(&format!(
            "{verdict}. This device is connected, but nothing can be changed in the vault until \
             the index is repaired: run `gclone repair` — on this device, or on one that has \
             seen the missing objects."
        ));
        return Ok(());
    }
    s.ui.out(&format!(
        "Compare with `gclone status` on a device you trust (run it there now): head {}, {files} files.",
        vault.head_fingerprint()?
    ));
    s.ui.out(
        "A new device trusts the vault as Google serves it; equal head values mean both devices \
         have applied the same history. Take the device that wrote last: the value shows \
         agreement, not that either device is up to date.",
    );
    Ok(())
}

/// Makes the other devices see this one — before any key is saved (§2.6).
///
/// `Ok(Some(verdict))`: the refresh ended with an integrity verdict (`Gap` / `Rollback`). The
/// vault is the right one — every object the refresh accepted names it, and nothing else
/// passes — but its index is incomplete, so nothing is published from here (as for every
/// mutating command, §5.3) and the device is announced by its first commit after the repair.
/// The login must still complete: `gclone repair` is the cure for exactly these verdicts, it
/// needs the cached key, and a device that could not log in would be left with
/// `logout --forget`, which deletes the index cache that `repair` republishes from.
async fn register(
    vault: &Vault<AnyBackend>,
    device: &str,
) -> Result<Option<IndexError>, IndexError> {
    // The authoritative identity check: every index object names the vault it belongs to.
    match vault.refresh().await {
        Ok(_) => {}
        Err(e @ (IndexError::Gap { .. } | IndexError::Rollback { .. })) => return Ok(Some(e)),
        Err(e) => return Err(e),
    }
    let id = vault.device_id();
    // A device that comes back, or a run that was interrupted after publishing, is listed.
    let listed = vault
        .devices()?
        .iter()
        .any(|d| d.id == id && d.name == device);
    if !listed {
        vault
            .commit_ops(vec![OpDraft::Device {
                id,
                name: device.to_string(),
            }])
            .await?;
    }
    vault.finish_mutation().await?;
    Ok(None)
}

// ---- the pure decisions of §2.4 / §2.6, unit-tested without I/O ----

/// §2.6 step 0 — which backend this `login` uses. `configured` = config.json's backend, if the
/// device is attached.
///   vault_dir = Some(d): configured None or Dir{path == d} → Dir{d};  configured Dir{other} or Drive → usage error
///   vault_dir = None:    configured Dir{p} and !auth_url_given → Dir{p};  configured Dir and auth_url_given → usage error;
///                        configured Drive or None → Drive
/// The usage error (`SyncError::Usage`) names what the device is attached to and
/// `gclone logout --forget`. Paths are compared after canonicalisation by the caller.
pub fn login_backend(
    configured: Option<&BackendCfg>,
    vault_dir: Option<&std::path::Path>,
    auth_url_given: bool,
) -> anyhow::Result<BackendCfg> {
    let attached_to = |what: String| {
        usage(format!(
            "this device is attached to {what}; run `gclone logout --forget` first"
        ))
    };
    let dir_vault = |p: &Path| format!("the vault directory {}", p.display());
    match (vault_dir, configured) {
        (Some(d), None) => Ok(BackendCfg::Dir { path: d.into() }),
        (Some(d), Some(BackendCfg::Dir { path })) if path == d => {
            Ok(BackendCfg::Dir { path: d.into() })
        }
        (Some(_), Some(BackendCfg::Dir { path })) => Err(attached_to(dir_vault(path))),
        (Some(_), Some(BackendCfg::Drive)) => Err(attached_to("a Google Drive vault".to_string())),
        (None, Some(BackendCfg::Dir { path })) if !auth_url_given => {
            Ok(BackendCfg::Dir { path: path.clone() })
        }
        (None, Some(BackendCfg::Dir { path })) => Err(attached_to(dir_vault(path))),
        (None, Some(BackendCfg::Drive) | None) => Ok(BackendCfg::Drive),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultChoice {
    Create,
    /// Index into `found`.
    Attach(usize),
    Ask,
}

/// §2.6 step B.2. `configured` = config.json's vault id when the device is attached but has no
/// cached key. Errors: the configured or requested vault is not among `found`; several vaults
/// without `--vault-id` when not on a TTY.
pub fn choose_vault(
    found: &[FoundVault],
    configured: Option<[u8; 16]>,
    new_vault: bool,
    vault_id: Option<[u8; 16]>,
    tty: bool,
) -> anyhow::Result<VaultChoice> {
    let position = |id: [u8; 16]| found.iter().position(|v| v.vault_id == id);
    let listing = || {
        if found.is_empty() {
            "  (none)".to_string()
        } else {
            found
                .iter()
                .map(|v| format!("  {}", vault_line(v)))
                .collect::<Vec<_>>()
                .join("\n")
        }
    };
    if let Some(id) = configured {
        return match position(id) {
            Some(i) => Ok(VaultChoice::Attach(i)),
            None => Err(IndexError::VaultNotVisible.into()),
        };
    }
    if new_vault {
        return Ok(VaultChoice::Create);
    }
    if let Some(id) = vault_id {
        // Also when nothing at all was found: a vault asked for by id is never created.
        return match position(id) {
            Some(i) => Ok(VaultChoice::Attach(i)),
            None => Err(usage(format!(
                "no vault with id {} is visible. Found:\n{}",
                util::hex(&id),
                listing()
            ))),
        };
    }
    match found.len() {
        0 => Ok(VaultChoice::Create),
        1 => Ok(VaultChoice::Attach(0)),
        _ if tty => Ok(VaultChoice::Ask),
        _ => Err(usage(format!(
            "several gclone vaults exist; pick one with --vault-id HEX:\n{}",
            listing()
        ))),
    }
}

/// §2.4 expiring-grant check: `Ok(None)` = normal login; `Ok(Some(expires_at_ms))` =
/// time-limited and allowed; `Err` = refused (exit 4).
pub fn expiring_login_decision(
    grant: &LoginGrant,
    allow_expiring: bool,
    now_ms: u64,
) -> anyhow::Result<Option<u64>> {
    let Some(secs) = grant.refresh_expires_in else {
        return Ok(None);
    };
    if allow_expiring {
        return Ok(Some(now_ms.saturating_add(secs.saturating_mul(1000))));
    }
    // `secs` is whatever the Worker's answer said: no arithmetic on it may overflow.
    let days = secs.saturating_add(43_200) / 86_400;
    Err(explained(
        AuthError::LoginFailed("Google time-limited this login".into()),
        format!(
            "Google will expire this login in {days} day{} — the OAuth app is still in Testing \
             (Google Auth Platform → Audience → Publish app), or time-limited access was chosen. \
             Publish the app, then run `gclone login` again. (Nothing was stored; \
             --allow-expiring-login accepts such a login.)",
            if days == 1 { "" } else { "s" }
        ),
    ))
}

/// §2.4: no browser is opened — the address and the code are only printed — with
/// `--no-browser`, when `SSH_CONNECTION` / `SSH_TTY` is set, or on Linux without `DISPLAY` and
/// `WAYLAND_DISPLAY`.
pub fn want_headless(
    no_browser: bool,
    env: &dyn Fn(&str) -> Option<String>,
    is_linux: bool,
) -> bool {
    let set = |name: &str| env(name).is_some_and(|v| !v.is_empty());
    no_browser
        || set("SSH_CONNECTION")
        || set("SSH_TTY")
        || (is_linux && !set("DISPLAY") && !set("WAYLAND_DISPLAY"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RaceOutcome {
    Alone,
    Won {
        other: [u8; 16],
    },
    /// Index into `found`.
    Lost {
        winner: usize,
    },
}

/// §2.6 "two first devices": `found` is a fresh discovery plus one's own vault; uses
/// `index::creation_winner`.
pub fn creation_race(found: &[FoundVault], mine: [u8; 16]) -> RaceOutcome {
    let Some(other) = found
        .iter()
        .filter(|v| v.vault_id != mine)
        .min_by_key(|v| (v.descriptor_created_ms, v.vault_id))
    else {
        return RaceOutcome::Alone;
    };
    let other = other.vault_id;
    match creation_winner(found) {
        Some(winner) if winner.vault_id != mine && found.iter().any(|v| v.vault_id == mine) => {
            match found.iter().position(|v| v.vault_id == winner.vault_id) {
                Some(winner) => RaceOutcome::Lost { winner },
                None => RaceOutcome::Won { other },
            }
        }
        // This device's vault is the oldest — or it is missing from `found`, and then nothing
        // is known that would justify discarding it.
        _ => RaceOutcome::Won { other },
    }
}

#[cfg(test)]
mod tests {
    use super::super::Explained;
    use super::*;
    use crate::backend::Handle;
    use crate::error::{SyncError, exit_code, find};
    use crate::index::VaultHandles;

    fn vault(id: u8, created_ms: u64) -> FoundVault {
        FoundVault {
            vault_id: [id; 16],
            root_name: format!("vault-{id}"),
            descriptor_created_ms: created_ms,
            handles: VaultHandles {
                root: Handle(format!("root-{id}")),
                index: Handle(format!("index-{id}")),
                data: Handle(format!("data-{id}")),
            },
            keyfiles: Vec::new(),
        }
    }

    fn grant(refresh_expires_in: Option<u64>) -> LoginGrant {
        LoginGrant {
            refresh_token: "rt".into(),
            access_token: "at".into(),
            expires_at_ms: 0,
            scope: auth::SCOPE_DRIVE_FILE.into(),
            email: "me@example.com".into(),
            refresh_expires_in,
        }
    }

    fn usage_text(e: &anyhow::Error) -> String {
        assert_eq!(exit_code(e), 2, "{e:#}");
        match find::<SyncError>(e) {
            Some(SyncError::Usage(text)) => text.clone(),
            _ => panic!("not a usage error: {e:#}"),
        }
    }

    #[test]
    fn expiring_login_decision_table() {
        let now = 1_794_400_000_000;
        assert_eq!(
            expiring_login_decision(&grant(None), false, now).unwrap(),
            None
        );
        assert_eq!(
            expiring_login_decision(&grant(None), true, now).unwrap(),
            None
        );

        let refused = expiring_login_decision(&grant(Some(604_799)), false, now).unwrap_err();
        assert_eq!(exit_code(&refused), 4);
        let text = super::super::describe(&refused);
        assert!(
            text.starts_with("Google will expire this login in 7 days"),
            "{text}"
        );
        assert!(text.contains("still in Testing"));
        assert!(text.contains("Publish app"));
        assert!(text.contains("run `gclone login` again"));

        assert_eq!(
            expiring_login_decision(&grant(Some(604_799)), true, now).unwrap(),
            Some(now + 604_799_000)
        );
        let one_day = expiring_login_decision(&grant(Some(86_400)), false, now).unwrap_err();
        assert!(super::super::describe(&one_day).contains("in 1 day —"));
        // A nonsensical lifetime in the Worker's answer is refused like any other, not a panic.
        assert!(expiring_login_decision(&grant(Some(u64::MAX)), false, now).is_err());
        assert_eq!(
            expiring_login_decision(&grant(Some(u64::MAX)), true, now).unwrap(),
            Some(u64::MAX)
        );
    }

    #[test]
    fn choose_vault_table() {
        let (a, b) = (vault(1, 10), vault(2, 20));
        let one = [a.clone()];
        let two = [a.clone(), b.clone()];
        let choose = |found: &[FoundVault], configured, new_vault, vault_id, tty| {
            choose_vault(found, configured, new_vault, vault_id, tty)
        };

        assert_eq!(
            choose(&[], None, false, None, false).unwrap(),
            VaultChoice::Create
        );
        assert_eq!(
            choose(&one, None, false, None, false).unwrap(),
            VaultChoice::Attach(0)
        );
        assert_eq!(
            choose(&two, None, false, None, true).unwrap(),
            VaultChoice::Ask
        );

        let several = choose(&two, None, false, None, false).unwrap_err();
        let text = usage_text(&several);
        assert!(text.contains("--vault-id"));
        assert!(text.contains(&util::hex(&[1; 16])) && text.contains(&util::hex(&[2; 16])));
        assert!(text.contains("\"vault-1\"") && text.contains("\"vault-2\""));

        // --vault-id: hit, miss, and a miss when nothing was found at all
        assert_eq!(
            choose(&two, None, false, Some([2; 16]), false).unwrap(),
            VaultChoice::Attach(1)
        );
        let miss = choose(&two, None, false, Some([9; 16]), true).unwrap_err();
        let text = usage_text(&miss);
        assert!(text.contains(&util::hex(&[9; 16])) && text.contains(&util::hex(&[1; 16])));
        assert!(choose(&[], None, false, Some([9; 16]), true).is_err());

        // --new-vault creates although others exist
        assert_eq!(
            choose(&two, None, true, None, false).unwrap(),
            VaultChoice::Create
        );
        assert_eq!(
            choose(&[], None, true, None, false).unwrap(),
            VaultChoice::Create
        );

        // an attached device goes back to its own vault, whatever else is visible
        assert_eq!(
            choose(&two, Some([2; 16]), false, None, false).unwrap(),
            VaultChoice::Attach(1)
        );
        assert_eq!(
            choose(&two, Some([1; 16]), true, Some([2; 16]), false).unwrap(),
            VaultChoice::Attach(0)
        );
        for found in [&two[..], &[]] {
            let gone = choose(found, Some([9; 16]), false, None, true).unwrap_err();
            assert!(matches!(
                find::<IndexError>(&gone),
                Some(IndexError::VaultNotVisible)
            ));
            assert_eq!(exit_code(&gone), 4);
        }
    }

    #[test]
    fn login_backend_table() {
        let dir = |p: &str| BackendCfg::Dir { path: p.into() };
        let is_dir = |r: anyhow::Result<BackendCfg>, p: &str| match r.unwrap() {
            BackendCfg::Dir { path } => assert_eq!(path, Path::new(p)),
            BackendCfg::Drive => panic!("expected the directory backend"),
        };
        let is_drive = |r: anyhow::Result<BackendCfg>| {
            assert!(matches!(r.unwrap(), BackendCfg::Drive));
        };
        let refused = |r: anyhow::Result<BackendCfg>, names: &str| {
            let text = usage_text(&r.unwrap_err());
            assert!(text.contains(names), "{text}");
            assert!(text.contains("gclone logout --forget"), "{text}");
        };
        let (a, b) = (Path::new("/v/a"), Path::new("/v/b"));

        // --vault-dir on an unattached / same-directory / other-directory / Drive-attached device
        is_dir(login_backend(None, Some(a), false), "/v/a");
        is_dir(login_backend(Some(&dir("/v/a")), Some(a), false), "/v/a");
        refused(login_backend(Some(&dir("/v/a")), Some(b), false), "/v/a");
        refused(
            login_backend(Some(&BackendCfg::Drive), Some(a), false),
            "Google Drive",
        );
        // no flag on a directory-attached device, without and with an AUTH_URL
        is_dir(login_backend(Some(&dir("/v/a")), None, false), "/v/a");
        refused(login_backend(Some(&dir("/v/a")), None, true), "/v/a");
        // no flag on a Drive-attached or unattached device
        is_drive(login_backend(Some(&BackendCfg::Drive), None, false));
        is_drive(login_backend(Some(&BackendCfg::Drive), None, true));
        is_drive(login_backend(None, None, false));
        is_drive(login_backend(None, None, true));
    }

    #[test]
    fn creation_race_table() {
        let mine = [5; 16];
        let me = |ms| vault(5, ms);

        assert_eq!(creation_race(&[me(10)], mine), RaceOutcome::Alone);
        assert_eq!(creation_race(&[], mine), RaceOutcome::Alone);

        assert_eq!(
            creation_race(&[me(10), vault(7, 20)], mine),
            RaceOutcome::Won { other: [7; 16] }
        );
        // lost by an earlier descriptor
        assert_eq!(
            creation_race(&[me(20), vault(7, 10)], mine),
            RaceOutcome::Lost { winner: 1 }
        );
        assert_eq!(
            creation_race(&[vault(7, 10), vault(8, 5), me(20)], mine),
            RaceOutcome::Lost { winner: 1 }
        );
        // equal times: the smaller vault id wins, on both devices alike
        assert_eq!(
            creation_race(&[me(10), vault(7, 10)], mine),
            RaceOutcome::Won { other: [7; 16] }
        );
        assert_eq!(
            creation_race(&[me(10), vault(3, 10)], mine),
            RaceOutcome::Lost { winner: 1 }
        );
        // the own vault missing from the listing still counts: it is never "alone", and it is
        // not discarded on the strength of a listing that does not show it
        assert_eq!(
            creation_race(&[vault(7, 1)], mine),
            RaceOutcome::Won { other: [7; 16] }
        );
    }

    #[test]
    fn want_headless_table() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| v.to_string())
            }
        };
        let none = env(&[]);
        // --no-browser
        assert!(want_headless(true, &none, false));
        assert!(want_headless(true, &env(&[("DISPLAY", ":0")]), true));
        // an SSH session
        assert!(want_headless(
            false,
            &env(&[("SSH_CONNECTION", "1.2.3.4 5 6.7.8.9 22")]),
            false
        ));
        assert!(want_headless(
            false,
            &env(&[("SSH_TTY", "/dev/pts/0")]),
            false
        ));
        assert!(want_headless(
            false,
            &env(&[("SSH_TTY", "/dev/pts/0"), ("DISPLAY", ":0")]),
            true
        ));
        // Linux without a display
        assert!(want_headless(false, &none, true));
        assert!(want_headless(false, &env(&[("DISPLAY", "")]), true));
        assert!(!want_headless(false, &env(&[("DISPLAY", ":0")]), true));
        assert!(!want_headless(
            false,
            &env(&[("WAYLAND_DISPLAY", "wayland-0")]),
            true
        ));
        // macOS default: the browser
        assert!(!want_headless(false, &none, false));
        assert!(!want_headless(
            false,
            &env(&[("SSH_CONNECTION", "")]),
            false
        ));
    }

    #[test]
    fn vault_names_and_ids_are_checked() {
        assert!(check_vault_name("gclone").is_ok());
        assert!(check_vault_name("My Vault 2").is_ok());
        for bad in ["", ".hidden", "a/b", "a\nb"] {
            assert_eq!(exit_code(&check_vault_name(bad).unwrap_err()), 2, "{bad:?}");
        }
        assert_eq!(
            parse_vault_id("00112233445566778899AABBCCDDEEFF").unwrap(),
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
        for bad in ["", "0011", "zz112233445566778899aabbccddeeff"] {
            assert_eq!(exit_code(&parse_vault_id(bad).unwrap_err()), 2, "{bad:?}");
        }
    }

    #[test]
    fn unlock_bounds_the_work_per_candidate() {
        use crate::crypto::kdf::tests::argon2_runs;
        let params = crate::crypto::KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
        };
        let vault_id = [4; 16];
        let keys = Keyring::new(vault_id, vec![(1, MasterKey::from_bytes([1; 32]))], 1).unwrap();
        let right = Passphrase::from_input("correct horse battery staple");
        let wrong = Passphrase::from_input("not the passphrase at all");
        let real = seal_keyfile(
            &KeyfilePayload::from_keyring(&keys, 1, "dev", 0),
            &right,
            params,
        )
        .unwrap();
        let foreign_keys =
            Keyring::new([9; 16], vec![(1, MasterKey::from_bytes([2; 32]))], 1).unwrap();
        let foreign = seal_keyfile(
            &KeyfilePayload::from_keyring(&foreign_keys, 3, "dev", 0),
            &right,
            params,
        )
        .unwrap();
        let candidate = |name: &str, bytes: &[u8]| Candidate {
            name: name.to_string(),
            bytes: Bytes::copy_from_slice(bytes),
            tried: Vec::new(),
        };
        let all = || {
            vec![
                candidate("gclone-key-00000009-00000000", b"junk"),
                candidate(&foreign.name, &foreign.bytes),
                candidate(&real.name, &real.bytes),
            ]
        };

        // A wrong passphrase: junk is dropped for good, the two real keyfiles stay.
        let mut candidates = all();
        assert!(matches!(
            unlock(&mut candidates, &wrong, vault_id, KEYFILE_TRY_MAX),
            Unlock::WrongPassphrase
        ));
        let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, [foreign.name.as_str(), real.name.as_str()]);
        // The same passphrase again: every candidate has answered — no derivation.
        let before = argon2_runs();
        assert!(matches!(
            unlock(&mut candidates, &wrong, vault_id, KEYFILE_TRY_MAX),
            Unlock::WrongPassphrase
        ));
        assert_eq!(argon2_runs(), before);

        // The right one: the keyfile of another vault opens and is ignored; the real one wins.
        match unlock(&mut candidates, &right, vault_id, KEYFILE_TRY_MAX) {
            Unlock::Opened(payload) => assert_eq!(payload.generation, 1),
            _ => panic!("the real keyfile must open"),
        }

        // Only junk: nothing is left to try.
        let mut junk = vec![candidate("gclone-key-00000009-00000000", b"junk")];
        assert!(matches!(
            unlock(&mut junk, &right, vault_id, KEYFILE_TRY_MAX),
            Unlock::Unusable(FormatError::KeyfileDamaged)
        ));
        assert!(junk.is_empty());
    }

    /// Audit L10: well-formed keyfiles can be planted without any secret — a keyfile of any
    /// other vault, under a higher generation. Four of them used to fill the four places, the
    /// real keyfile was never asked, and the answer to the right passphrase was "Wrong
    /// passphrase". Now the answer says that keyfiles were not tried, and they can be.
    #[test]
    fn planted_keyfiles_never_turn_the_right_passphrase_into_a_wrong_one() {
        use crate::crypto::kdf::tests::argon2_runs;
        let params = crate::crypto::KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
        };
        let vault_id = [4; 16];
        let keys = Keyring::new(vault_id, vec![(1, MasterKey::from_bytes([1; 32]))], 1).unwrap();
        let right = Passphrase::from_input("correct horse battery staple");
        let real = seal_keyfile(
            &KeyfilePayload::from_keyring(&keys, 1, "dev", 0),
            &right,
            params,
        )
        .unwrap();
        // Six keyfiles of an attacker's own vault, under his own passphrase.
        let his_keys = Keyring::new([9; 16], vec![(1, MasterKey::from_bytes([2; 32]))], 1).unwrap();
        let his_pass = Passphrase::from_input("the attacker's own passphrase");
        let planted: Vec<_> = (0..6u32)
            .map(|i| {
                let payload = KeyfilePayload::from_keyring(&his_keys, 0xffff_fff0 + i, "x", 0);
                seal_keyfile(&payload, &his_pass, params).unwrap()
            })
            .collect();
        let fresh = || {
            let mut candidates: Vec<Candidate> = planted
                .iter()
                .rev()
                .map(|k| Candidate {
                    name: k.name.clone(),
                    bytes: Bytes::copy_from_slice(&k.bytes),
                    tried: Vec::new(),
                })
                .collect();
            candidates.push(Candidate {
                name: real.name.clone(),
                bytes: Bytes::copy_from_slice(&real.bytes),
                tried: Vec::new(),
            });
            candidates
        };

        // One attempt asks four keyfiles — four derivations — and says how many it left out.
        let mut candidates = fresh();
        let before = argon2_runs();
        assert!(matches!(
            unlock(&mut candidates, &right, vault_id, KEYFILE_TRY_MAX),
            Unlock::Untried(3)
        ));
        assert_eq!(argon2_runs(), before + 4);
        assert_eq!(candidates.len(), 7, "a wrong key drops nothing");
        // The same passphrase once more goes on where it stopped: two planted ones, then the
        // real keyfile — three derivations, none of them a repetition.
        let before = argon2_runs();
        match unlock(&mut candidates, &right, vault_id, KEYFILE_TRY_MAX) {
            Unlock::Opened(payload) => assert_eq!(payload.generation, 1),
            _ => panic!("the real keyfile is among the untried ones"),
        }
        assert_eq!(argon2_runs(), before + 3);

        // On request (`--all-keyfiles`, or a yes at the terminal) one call tries them all.
        let mut candidates = fresh();
        assert!(matches!(
            unlock(&mut candidates, &right, vault_id, usize::MAX),
            Unlock::Opened(_)
        ));

        // A passphrase that really is wrong is called wrong only once every keyfile said so.
        let wrong = Passphrase::from_input("not the passphrase at all");
        let mut candidates = fresh();
        assert!(matches!(
            unlock(&mut candidates, &wrong, vault_id, KEYFILE_TRY_MAX),
            Unlock::Untried(3)
        ));
        assert!(matches!(
            unlock(&mut candidates, &wrong, vault_id, usize::MAX),
            Unlock::WrongPassphrase
        ));
    }

    /// A keyfile sealed under a typed passphrase of the 26-symbol shape (what gclone 0.4.0
    /// sealed, and what is sealed now) opens with exactly that spelling. Another spelling
    /// with the same canonical form — wrong capitals — is another passphrase to it, and the
    /// memo of refused passphrases must not take the right one for the refused one: it used
    /// to be keyed by the canonical form alone, and the exactly right passphrase was then
    /// answered "Wrong passphrase" without a derivation.
    #[test]
    fn the_right_spelling_opens_after_a_miscased_attempt() {
        use crate::crypto::kdf::tests::argon2_runs;
        let params = crate::crypto::KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
        };
        let vault_id = [4; 16];
        let keys = Keyring::new(vault_id, vec![(1, MasterKey::from_bytes([1; 32]))], 1).unwrap();
        let typed = "Maple Tiger Candle Stone Wharf";
        let set = Passphrase::set_checked(typed).unwrap();
        assert_eq!(set.display().as_str(), typed, "set as typed");
        let real = seal_keyfile(
            &KeyfilePayload::from_keyring(&keys, 1, "dev", 0),
            &set,
            params,
        )
        .unwrap();
        let mut candidates = vec![Candidate {
            name: real.name.clone(),
            bytes: Bytes::copy_from_slice(&real.bytes),
            tried: Vec::new(),
        }];

        // Attempt 1, wrong capitals: both readings are derived and refused.
        let miscased = Passphrase::from_input("maple tiger candle stone wharf");
        let before = argon2_runs();
        assert!(matches!(
            unlock(&mut candidates, &miscased, vault_id, KEYFILE_TRY_MAX),
            Unlock::WrongPassphrase
        ));
        assert_eq!(argon2_runs(), before + 2);
        // The same wrong spelling again costs nothing.
        assert!(matches!(
            unlock(&mut candidates, &miscased, vault_id, KEYFILE_TRY_MAX),
            Unlock::WrongPassphrase
        ));
        assert_eq!(argon2_runs(), before + 2);

        // Attempt 2, exactly as set: the canonical form was refused already and is not
        // derived again; the text as typed is new — one derivation, and it opens.
        let exact = Passphrase::from_input(typed);
        let before = argon2_runs();
        match unlock(&mut candidates, &exact, vault_id, KEYFILE_TRY_MAX) {
            Unlock::Opened(payload) => assert_eq!(payload.generation, 1),
            _ => panic!("the passphrase exactly as set must open the keyfile"),
        }
        assert_eq!(argon2_runs(), before + 1);
    }

    #[test]
    fn explained_errors_keep_their_exit_code() {
        let e = explained(FormatError::KeyfileDamaged, "custom text");
        assert_eq!(exit_code(&e), 3);
        assert_eq!(super::super::describe(&e), "custom text");
        assert!(e.downcast_ref::<Explained>().is_some());
    }
}

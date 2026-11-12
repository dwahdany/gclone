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
use crate::consts::{KEYFILE_MAX, KEYFILE_TRY_MAX, PROMPT_ATTEMPTS, TRANSFERS_DEFAULT};
use crate::crypto::{Keyring, MasterKey, Passphrase};
use crate::error::{AuthError, BackendError, ConfigError, CryptoError, FormatError, IndexError};
use crate::format::{KeyfilePayload, open_keyfile, seal_keyfile};
use crate::index::{CreateParams, FoundVault, OpenParams, Vault, creation_winner};
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
        self.store.save(&self.secrets(Some(keys)))?;
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
    let secrets = store.load()?;
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
        return relogin(&session, config, secrets).await;
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
    Ok(0)
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
async fn relogin(s: &Session, config: &Config, secrets: Option<Secrets>) -> anyhow::Result<i32> {
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
             as long as the auth Worker has its GOOGLE_LEGACY_CLIENT_ID and \
             GOOGLE_LEGACY_CLIENT_SECRET secrets."
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
             worker/README.md for the ways out (keep the legacy secrets on the Worker, or move \
             the vault); the last resort is to download the vault folder from \
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
                    Some(_) => s.store.save(&s.secrets(None))?,
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

/// One keyfile candidate of ATTACH.
struct Candidate {
    name: String,
    bytes: Bytes,
}

enum Unlock {
    Opened(Box<KeyfilePayload>),
    /// At least one candidate answered "wrong key".
    WrongPassphrase,
    /// No candidate is left to try.
    Unusable(FormatError),
}

/// Tries `pass` on every candidate, highest generation first. A candidate that fails with
/// anything other than a wrong key is dropped for the rest of the command (§2.6: each
/// (keyfile, passphrase) pair runs at most once).
fn unlock(candidates: &mut Vec<Candidate>, pass: &Passphrase, vault_id: [u8; 16]) -> Unlock {
    let mut dropped = FormatError::KeyfileDamaged;
    let mut kept = Vec::new();
    let mut opened = None;
    for c in candidates.drain(..) {
        if opened.is_some() {
            kept.push(c);
            continue;
        }
        match open_keyfile(&c.name, &c.bytes, pass) {
            Ok(payload) if payload.vault_id_bytes().is_ok_and(|id| id == vault_id) => {
                opened = Some(payload);
                kept.push(c);
            }
            Ok(_) => tracing::warn!("keyfile {} belongs to another vault; ignored", c.name),
            Err(FormatError::Crypto(CryptoError::WrongKey)) => kept.push(c),
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
        None => Unlock::WrongPassphrase,
    }
}

/// The keyfiles ATTACH looks at: the `KEYFILE_TRY_MAX` highest generations, no more.
async fn keyfile_candidates(s: &Session, found: &FoundVault) -> anyhow::Result<Vec<Candidate>> {
    let mut candidates = Vec::new();
    for meta in found.keyfiles.iter().take(KEYFILE_TRY_MAX) {
        let ObjMeta {
            name, handle, size, ..
        } = meta;
        if *size > KEYFILE_MAX {
            tracing::warn!("keyfile {name} is too large; ignored");
            continue;
        }
        tracing::debug!("reading keyfile candidate {name}");
        // One byte more than allowed is asked for, so that an object that grew is noticed.
        match get_all(&*s.backend, handle, Some(0..KEYFILE_MAX + 1)).await {
            Ok(bytes) if bytes.len() as u64 <= KEYFILE_MAX => candidates.push(Candidate {
                name: name.clone(),
                bytes,
            }),
            Ok(_) => tracing::warn!("keyfile {name} is too large; ignored"),
            Err(BackendError::NotFound) => tracing::warn!("keyfile {name} disappeared; ignored"),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(candidates)
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

    let mut candidates = keyfile_candidates(s, found).await?;
    if candidates.is_empty() {
        return Err(FormatError::KeyfileDamaged.into());
    }
    let attempts = if s.args.passphrase_file.is_some() {
        1
    } else {
        PROMPT_ATTEMPTS
    };
    let mut tried: Vec<Zeroizing<String>> = Vec::new();
    let mut payload = None;
    for attempt in 1..=attempts {
        let pass = s.passphrase(false).await?;
        let text = pass.display();
        // A passphrase that already failed is not run through Argon2 again.
        let outcome = if tried.contains(&text) {
            Unlock::WrongPassphrase
        } else {
            tried.push(text);
            let vault_id = found.vault_id;
            let (outcome, rest) = blocking(move || {
                let outcome = unlock(&mut candidates, &pass, vault_id);
                Ok((outcome, candidates))
            })
            .await?;
            candidates = rest;
            outcome
        };
        match outcome {
            Unlock::Opened(p) => {
                payload = Some(p);
                break;
            }
            Unlock::Unusable(e) => return Err(e.into()),
            Unlock::WrongPassphrase if attempt < attempts => s.ui.error("Wrong passphrase."),
            Unlock::WrongPassphrase => {}
        }
    }
    let Some(payload) = payload else {
        return Err(ConfigError::WrongPassphrase.into());
    };
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
         see the same history.",
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
            unlock(&mut candidates, &wrong, vault_id),
            Unlock::WrongPassphrase
        ));
        let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, [foreign.name.as_str(), real.name.as_str()]);

        // The right one: the keyfile of another vault opens and is ignored; the real one wins.
        match unlock(&mut candidates, &right, vault_id) {
            Unlock::Opened(payload) => assert_eq!(payload.generation, 1),
            _ => panic!("the real keyfile must open"),
        }

        // Only junk: nothing is left to try.
        let mut junk = vec![candidate("gclone-key-00000009-00000000", b"junk")];
        assert!(matches!(
            unlock(&mut junk, &right, vault_id),
            Unlock::Unusable(FormatError::KeyfileDamaged)
        ));
        assert!(junk.is_empty());
    }

    #[test]
    fn explained_errors_keep_their_exit_code() {
        let e = explained(FormatError::KeyfileDamaged, "custom text");
        assert_eq!(exit_code(&e), 3);
        assert_eq!(super::super::describe(&e), "custom text");
        assert!(e.downcast_ref::<Explained>().is_some());
    }
}

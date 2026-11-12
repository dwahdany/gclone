//! `gclone logout` (SPEC §2.7, §10) — owned by WP7.

use super::{GlobalOpts, blocking, lock_state, note_config, note_secrets, test_env, ui_for, usage};
use crate::auth;
use crate::config::{BackendCfg, Config, Paths, secret_store};
use crate::error::ConfigError;
use crate::state::Db;
use crate::util;

#[derive(clap::Args, Clone, Debug)]
#[command(after_help = "\
A lost or stolen device: run `gclone logout --revoke` on any other device (or remove the app at
https://myaccount.google.com/permissions). This ends the Google login of ALL your devices; run
`gclone login` again on each one you keep. It is unverified whether the vault stays visible after
a new sign-in, so keep a web download of the vault folder first. The lost device still holds the
vault key: data it could already download stays exposed.")]
pub struct LogoutArgs {
    /// Sign out everywhere: ends the Google login of ALL your gclone devices.
    #[arg(long)]
    pub revoke: bool,
    /// Also remove this device's vault configuration and local state.
    #[arg(long)]
    pub forget: bool,
    /// Do not ask for confirmation.
    #[arg(long)]
    pub yes: bool,
}

const REVOKE_WARNING: &str = "This ends the Google login of ALL your gclone devices; each needs \
    `gclone login` again. It is unverified whether the vault stays visible after a new sign-in — \
    keep a web download of the vault folder first.";

/// `true` = the file was there.
fn remove_file(path: &std::path::Path) -> std::io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// What a login can leave in the state root besides `secrets.json`: the cached access token,
/// and temp copies of either file from a write that was killed before its rename (a temp copy
/// of `secrets.json` holds the refresh token and the cached key). Removed by every `logout`,
/// signed in or not, and BEFORE `secrets.json`: if the command stops half-way, the next
/// `logout` still finds the device signed in and finishes. `true` = something was there.
fn remove_login_leftovers(paths: &Paths) -> std::io::Result<bool> {
    let token = remove_file(&paths.token_file())?;
    let temps = util::remove_atomic_leftovers(&paths.token_file())?
        + util::remove_atomic_leftovers(&paths.secrets_file())?;
    Ok(token || temps > 0)
}

async fn confirm(g: &GlobalOpts, question: &'static str) -> anyhow::Result<bool> {
    let ui = ui_for(g);
    blocking(move || Ok(ui.confirm(question))).await
}

pub async fn run(g: &GlobalOpts, args: LogoutArgs) -> anyhow::Result<i32> {
    let ui = ui_for(g);
    let paths = Paths::resolve()?;
    let store = secret_store(&paths);
    let config = match Config::load(&paths) {
        Ok(config) => Some(config),
        Err(ConfigError::NotConfigured) => None,
        Err(e) => return Err(e.into()),
    };
    if let Some(config) = &config {
        note_config(&paths, config);
    }
    let directory_vault = matches!(
        config.as_ref().map(|c| &c.backend),
        Some(BackendCfg::Dir { .. })
    );
    if args.revoke && directory_vault {
        return Err(usage(
            "--revoke: this device is attached to a directory vault; there is no Google login \
             to revoke",
        ));
    }
    // Only a revoke needs what is inside the file: a plain logout must also get rid of a
    // secrets file that strict loading refuses.
    let signed_in = std::fs::symlink_metadata(paths.secrets_file()).is_ok();
    if !signed_in && !args.forget {
        // No login on file — but nothing of an earlier one may stay behind either.
        let leftovers = remove_login_leftovers(&paths)?;
        if args.revoke {
            return Err(ConfigError::NotLoggedIn.into());
        }
        ui.out(if leftovers {
            "Not signed in on this device; leftover files of an earlier login (cached access \
             token, unfinished writes) were removed."
        } else {
            "Not signed in on this device; nothing to do."
        });
        return Ok(0);
    }

    let state_dir = config.as_ref().map(|c| paths.state_dir(&c.vault_id));
    let lock = match &state_dir {
        Some(dir) if dir.exists() => Some(lock_state(dir).await?),
        _ => None,
    };

    // Everything that can still stop the command — a missing login, both confirmations — comes
    // BEFORE the revoke: that request cannot be taken back and signs out every device.
    let mut revoke = None;
    if args.revoke {
        let secrets = store.load()?.ok_or(ConfigError::NotLoggedIn)?;
        note_secrets(&secrets);
        let token = secrets
            .refresh_token
            .clone()
            .filter(|t| !t.is_empty())
            .ok_or(ConfigError::NotLoggedIn)?;
        let mut ep = secrets.endpoints()?;
        if let Some(url) = test_env("GCLONE_TEST_REVOKE_URL") {
            ep.revoke_url = url;
        }
        ui.warn(REVOKE_WARNING);
        if !args.yes {
            if !ui.is_tty() {
                return Err(usage(
                    "--revoke needs a confirmation: run it on a terminal, or pass --yes",
                ));
            }
            if !confirm(g, "Continue?").await? {
                ui.out("Nothing was revoked and nothing was removed.");
                return Ok(1);
            }
        }
        revoke = Some((ep, token));
    }

    if args.forget
        && let Some(config) = &config
    {
        let db_file = paths.db_file(&config.vault_id);
        let unpublished = if db_file.exists() {
            blocking(move || Ok(Db::open(&db_file)?.pending_count()?)).await?
        } else {
            0
        };
        if unpublished > 0 && !args.yes {
            ui.warn(&format!(
                "{unpublished} change(s) made on this device are not published yet (run any \
                 gclone command to publish them). --forget would lose them."
            ));
            if !confirm(g, "Forget this device's vault state anyway?").await? {
                ui.error(if revoke.is_some() {
                    "nothing was revoked and nothing was removed (pass --yes to forget anyway)"
                } else {
                    "nothing was removed (pass --yes to forget anyway)"
                });
                return Ok(5);
            }
        }
    }

    let mut revoked = None;
    if let Some((ep, token)) = revoke {
        // A failure stops here: the local secrets stay, so the command can be repeated.
        revoked = Some(auth::revoke(&auth::http_client()?, &ep, &token).await?);
    }

    remove_login_leftovers(&paths)?;
    store.delete()?;
    if args.forget {
        Config::delete(&paths)?;
        drop(lock);
        if let Some(dir) = &state_dir
            && let Err(e) = std::fs::remove_dir_all(dir)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(e.into());
        }
    }

    if signed_in {
        ui.out("Signed out on this device.");
        match (revoked, directory_vault) {
            (Some(true), _) => ui.out(
                "Google revoked the login of all your gclone devices. Run `gclone login` on each \
                 device you keep.",
            ),
            (Some(false), _) => ui.out(
                "Google had already ended this login (revoked or expired); nothing was left to \
                 revoke.",
            ),
            (None, true) => ui.out("The cached vault key was removed from this device."),
            (None, false) => ui.out(
                "The Google token was discarded, not revoked — Google can only revoke the login \
                 of all devices at once (gclone logout --revoke).",
            ),
        }
    }
    if args.forget {
        ui.out("This device's vault configuration and local state were removed.");
    }
    Ok(0)
}

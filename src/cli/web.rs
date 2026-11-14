//! `gclone web` (SPEC §7.4, §10): the glue between the command line and `crate::web`.

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::Context as _;

use super::{
    Ctx, GlobalOpts, NOT_REFRESHED, OpenOpts, blocking, cancel_token, corrupt_text, describe,
    explained, login_failure, open_ctx, open_replica, open_vault, stale_text, stored_device_name,
    test_env,
};
use crate::backend::AnyBackend;
use crate::config::{BackendCfg, Config, FileStamp, Paths, Secrets, SecretsPresence, secret_store};
use crate::crypto::Keyring;
use crate::error::{ConfigError, IndexError};
use crate::index::RefreshReport;
use crate::state::{self, Db, Existing};
use crate::util;
use crate::web::{self, RefreshState};

#[derive(clap::Args, Clone, Debug)]
pub struct WebArgs {
    /// Port on 127.0.0.1 [default: a free one].
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..))]
    pub port: Option<u16>,
    /// Only print the link; do not open a browser.
    #[arg(long)]
    pub no_browser: bool,
}

/// How often the running viewer looks whether this device is still signed in (`DeviceGuard`);
/// every request looks as well.
const GUARD_INTERVAL: Duration = Duration::from_secs(1);
/// A launch page that a viewer left behind (killed before its link was used) is removed by
/// the next viewer once it is this old.
const LAUNCH_PAGE_STALE: Duration = Duration::from_secs(600);

const SIGNED_OUT: &str = "The viewer has stopped: this device was signed out, or signed in \
    anew, while it ran (`gclone logout`, `gclone login`). Start `gclone web` again.";
const STATE_GONE: &str = "The viewer has stopped: this device's local state of the vault was \
    removed or replaced while it ran (`gclone logout --forget`). Start `gclone web` again.";

type Stamp = FileStamp;
/// `secrets.json` and `secrets.sealed`.
type SecretsStamps = (Option<Stamp>, Option<Stamp>);

fn stamp(path: &Path) -> Option<Stamp> {
    FileStamp::of(path)
}

/// The login a secrets file holds, as far as the viewer depends on it: the Google login and
/// the vault's keys. A digest under a key of this process, not the secrets themselves.
fn login_digest(key: &[u8; 32], secrets: &Secrets) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_keyed(key);
    let mut field = |bytes: &[u8]| {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    field(secrets.refresh_token.as_deref().unwrap_or("").as_bytes());
    field(&secrets.min_epoch.to_le_bytes());
    for entry in &secrets.keys {
        field(&entry.epoch.to_le_bytes());
        field(entry.key.as_bytes());
    }
    hasher.finalize()
}

/// Whether this device is still what it was when the viewer started (§7.4): `config.json`
/// names the same vault, the key store (`secrets.json` or `secrets.sealed`) holds the same
/// login and keys, and `state.db` is the
/// file the viewer has open. `gclone logout` takes the first two away, `--forget` all three;
/// the viewer keeps keys, backend and an open database in memory and would otherwise go on
/// serving — and, with the next refresh, write the state back. Once it has failed it stays
/// failed.
pub(crate) struct DeviceGuard {
    paths: Paths,
    vault_id: String,
    digest_key: [u8; 32],
    login: blake3::Hash,
    /// Device and inode of `state.db`.
    db: (u64, u64),
    /// `config.json` and the secrets files (`secrets.json`, `secrets.sealed`) as last read
    /// and found unchanged.
    seen: Mutex<Option<(Stamp, SecretsStamps)>>,
    gone: OnceLock<&'static str>,
}

impl DeviceGuard {
    /// For a device that is signed in right now (`open_ctx` has just succeeded).
    pub(crate) fn new(paths: &Paths, config: &Config) -> anyhow::Result<DeviceGuard> {
        let secrets = secret_store(paths)
            .load()?
            .ok_or(ConfigError::NotLoggedIn)?;
        let digest_key = util::random();
        let db = stamp(&paths.db_file(&config.vault_id))
            .ok_or_else(|| anyhow::anyhow!("this device has no local state of the vault"))?;
        Ok(DeviceGuard {
            paths: paths.clone(),
            vault_id: config.vault_id.clone(),
            login: login_digest(&digest_key, &secrets),
            digest_key,
            db: db.file_id(),
            seen: Mutex::new(None),
            gone: OnceLock::new(),
        })
    }

    fn look(&self) -> Result<(), &'static str> {
        match stamp(&self.paths.db_file(&self.vault_id)) {
            Some(db) if db.file_id() == self.db => {}
            _ => return Err(STATE_GONE),
        }
        let Some(config) = stamp(&self.paths.config_file()) else {
            return Err(SIGNED_OUT);
        };
        // The secrets are in `secrets.json` or in `secrets.sealed`, and `gclone keystore use`
        // moves them between the two while this viewer runs (§8.3): neither file found while
        // another gclone holds the secrets lock is a move in progress, not a sign-out.
        let secrets = match self.paths.secrets_presence() {
            SecretsPresence::Present(plain, sealed) => (plain, sealed),
            SecretsPresence::Busy => return Ok(()),
            SecretsPresence::Absent => return Err(SIGNED_OUT),
        };
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if *seen == Some((config, secrets)) {
            return Ok(());
        }
        // One of the files was written since: the same vault, the same login?
        if !Config::load(&self.paths).is_ok_and(|c| c.vault_id == self.vault_id) {
            return Err(SIGNED_OUT);
        }
        match secret_store(&self.paths).load() {
            Ok(Some(s)) if login_digest(&self.digest_key, &s) == self.login => {}
            // Signed out, or another login or other keys.
            Ok(_) => return Err(SIGNED_OUT),
            // The files could not be read at this moment — a sealed store in the middle of
            // being replaced, a session hiccup: not a sign-out. Look again at the next tick.
            Err(e) => {
                tracing::debug!("the viewer could not re-read this device's secrets: {e}");
                return Ok(());
            }
        }
        *seen = Some((config, secrets));
        Ok(())
    }

    /// `Err(text)`: the viewer has to stop.
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        if let Some(text) = self.gone.get() {
            return Err(text);
        }
        self.look().map_err(|text| *self.gone.get_or_init(|| text))
    }
}

/// What the page says about a refresh: `None` = the state lock was busy.
fn refresh_state(
    outcome: anyhow::Result<Option<Result<RefreshReport, IndexError>>>,
) -> RefreshState {
    let (ok, applied, note) = match outcome {
        Ok(Some(Ok(report))) => (true, report.applied, corrupt_text(&report)),
        // A login that ended is not something to wait out: say what the command line says.
        Ok(Some(Err(e))) if login_failure(&e) => (false, 0, Some(describe(&e.into()))),
        Ok(Some(Err(e))) => (false, 0, Some(stale_text(&e))),
        Ok(None) => (
            false,
            0,
            Some(format!(
                "The {NOT_REFRESHED}. Showing the last state this device has seen."
            )),
        ),
        Err(e) => (false, 0, Some(describe(&e))),
    };
    RefreshState {
        at_ms: util::now_ms(),
        ok,
        applied,
        note,
    }
}

/// One refresh, the way a read-only command makes it (§8.3): try the state lock; with it, open
/// the vault, pull, and let go of both. A `gclone sync` in another terminal waits for this at
/// most as long as for a `gclone ls`.
///
/// Unlike a command, the viewer may have outlived its device's login: nothing is opened — and
/// so nothing created — unless `guard` still holds, and the lock is taken only where the lock
/// file exists. `gclone logout` holds that lock while it removes things, so the second look,
/// under the lock, cannot be overtaken by one.
async fn refresh_once(
    paths: &Paths,
    config: &Config,
    backend: Arc<AnyBackend>,
    keys: Keyring,
    guard: &DeviceGuard,
) -> RefreshState {
    let stopped = |text: &'static str| explained(anyhow::anyhow!("the viewer has stopped"), text);
    let pulled = async {
        guard.check().map_err(stopped)?;
        let dir = paths.state_dir(&config.vault_id);
        let lock = match blocking(move || Ok(state::try_lock_existing(&dir)?)).await? {
            Existing::Held(lock) => lock,
            Existing::Busy => return Ok(None),
            Existing::Gone => return Err(stopped(STATE_GONE)),
        };
        guard.check().map_err(stopped)?;
        let vault = open_replica(paths, config, backend, keys, true).await?;
        let report = vault.refresh().await;
        // The replica is closed before the lock is let go.
        drop(vault);
        drop(lock);
        Ok::<_, anyhow::Error>(Some(report))
    };
    refresh_state(pulled.await)
}

/// `<state root>/web-open-<port>.html`: the page that takes the browser to the link. The
/// launcher gets this file's path, so the link's key is in no argument list — those are
/// readable by every account of the machine — and the file is as private as `secrets.json`
/// beside it (0600 in the 0700 state directory).
fn write_launch_page(paths: &Paths, port: u16, link: &str) -> std::io::Result<PathBuf> {
    // What viewers that were killed left behind: links that died with them.
    for entry in std::fs::read_dir(&paths.state_root)?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let stale = entry
            .metadata()
            .and_then(|md| md.modified())
            .is_ok_and(|at| at.elapsed().is_ok_and(|age| age > LAUNCH_PAGE_STALE));
        if name.starts_with("web-open-") && name.ends_with(".html") && stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    let file = paths.state_root.join(format!("web-open-{port}.html"));
    util::write_atomic(&file, web::launch_page(link).as_bytes(), 0o600)?;
    Ok(file)
}

/// Hands `file` to the default browser. Detached: some launchers stay alive as long as the
/// browser does. No test may open a browser: in debug builds `GCLONE_TEST_BROWSER` (§7.1)
/// names a file that gets what the launcher would have been given, and nothing is launched.
fn open_in_browser(file: &Path) {
    match test_env("GCLONE_TEST_BROWSER") {
        Some(record) => drop(std::fs::write(record, file.as_os_str().as_encoded_bytes())),
        None => drop(open::that_detached(file)),
    }
}

/// Stdin is a terminal and this process is in its foreground group: a line typed there
/// reaches it.
fn in_foreground() -> bool {
    // SAFETY: both calls only read process state; `tcgetpgrp` fails (-1) off a terminal.
    std::io::stdin().is_terminal()
        && unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) == libc::getpgrp() }
}

/// Every line typed in the terminal makes a new link — and with it a new session.
///
/// The viewer may be a background job (`gclone web &`, Ctrl-Z and `bg`): a read from the
/// terminal then raises SIGTTIN, whose default action stops the whole process — the server
/// with it. The signal is ignored, the read fails with EIO instead, and the thread waits for
/// the job to be brought to the foreground.
fn new_link_on_enter(app: Arc<web::App>) {
    // SAFETY: changes the disposition of one signal for which this process has no handler.
    unsafe { libc::signal(libc::SIGTTIN, libc::SIG_IGN) };
    std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            match std::io::stdin().read_line(&mut line) {
                Ok(0) => return,
                Ok(_) => {}
                // Bytes that are not text are a line all the same.
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {}
                // SAFETY: as in `in_foreground`. -1: the terminal is gone.
                Err(e)
                    if e.raw_os_error() == Some(libc::EIO)
                        && unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) } >= 0 =>
                {
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                }
                Err(_) => return,
            }
            println!(
                "\nA new link. Every link and every browser session from before has stopped \
                 working:\n\n  {}\n",
                app.login_url()
            );
        }
    });
}

pub async fn run(g: &GlobalOpts, args: WebArgs) -> anyhow::Result<i32> {
    // Exactly what `ls` does, with its errors and exit codes: not connected, signed out,
    // locked, a login that no longer works.
    let ctx = open_ctx(g, OpenOpts::read_only()).await?;
    ctx.report_refresh();
    let Ctx {
        paths,
        config,
        vault,
        ui,
        lock,
        refresh,
        ..
    } = ctx;
    // `None`: the lock was busy (`report_refresh` has said so).
    let refreshed = refresh_state(Ok(refresh));
    let backend = vault.backend().clone();
    let keys = vault.keys().clone();
    let device = stored_device_name(vault.db())?;
    // From here on the state lock is free: the server reads the replica as any lock-less
    // reader does, and takes the lock only for the length of a refresh.
    drop(vault);
    drop(lock);
    let (vault, _) = open_vault(&paths, &config, backend.clone(), keys.clone(), None).await?;
    let ledger = Db::open_shared(&paths.db_file(&config.vault_id)).ok();
    // And one for the time machine: a walk through the history must not hold up a listing.
    let history = Db::open_shared(&paths.db_file(&config.vault_id)).ok();
    let guard = Arc::new(DeviceGuard::new(&paths, &config)?);

    let wanted = args.port.unwrap_or(0);
    let (listeners, port) = web::bind(wanted)
        .await
        .with_context(|| format!("cannot listen on 127.0.0.1:{wanted}"))?;
    let refresher: web::Refresher = {
        let (paths, config, guard) = (paths.clone(), config.clone(), guard.clone());
        Box::new(move || {
            let (paths, config, guard) = (paths.clone(), config.clone(), guard.clone());
            let (backend, keys) = (backend.clone(), keys.clone());
            Box::pin(async move { refresh_once(&paths, &config, backend, keys, &guard).await })
        })
    };
    let name = match vault.vault_name() {
        name if !name.is_empty() => name,
        _ => config.vault_name.clone(),
    };
    let interactive = in_foreground();
    let app = web::App::new(web::Options {
        vault,
        ledger,
        history,
        refresher,
        refreshed,
        vault_name: name.clone(),
        backend: match config.backend {
            BackendCfg::Drive => "drive",
            BackendCfg::Dir { .. } => "dir",
        },
        device,
        port,
        alive: Box::new(move || guard.check().map_err(str::to_owned)),
        interactive,
    });

    // The link is the way in: it is shown with -q as well. Its key never reaches a log, and
    // never an argument list.
    let headless = super::login::want_headless(
        args.no_browser,
        &|name| std::env::var(name).ok(),
        cfg!(target_os = "linux"),
    );
    let link = app.login_url();
    let launch = match headless {
        true => None,
        false => match write_launch_page(&paths, port, &link) {
            Ok(file) => Some(file),
            Err(e) => {
                ui.warn(&format!("cannot hand the link to the browser: {e}"));
                None
            }
        },
    };
    match launch {
        Some(file) => {
            let otherwise = if interactive {
                "Press Enter for a link to open yourself — if no browser opened, or to end every \
                 session so far"
            } else {
                "If no browser opens, run `gclone web --no-browser` for a link"
            };
            ui.out(&format!(
                "Vault {name:?}, read-only, on 127.0.0.1:{port} — opening it in your \
                 browser.\n{otherwise}; Ctrl-C stops the viewer."
            ));
            app.delete_when_used(file.clone());
            open_in_browser(&file);
        }
        None => {
            let again = if interactive {
                "Press Enter for a new link (it ends every session before it)"
            } else {
                "Run `gclone web` again for a new link"
            };
            ui.out(&format!(
                "Vault {name:?}, read-only. Open this link in a browser on this machine:\n\n  \
                 {link}\n\nThe link works once. {again}; Ctrl-C stops the viewer."
            ));
        }
    }
    if std::io::stdin().is_terminal() {
        new_link_on_enter(app.clone());
    }

    // Ctrl-C is how the viewer is ended: exit 0. A device that was signed out ends it too.
    super::SERVING.store(true, Ordering::SeqCst);
    let serving = cancel_token().child_token();
    tokio::spawn({
        let (app, serving) = (app.clone(), serving.clone());
        async move {
            while app.check_alive().is_ok() {
                tokio::select! {
                    () = serving.cancelled() => return,
                    () = tokio::time::sleep(GUARD_INTERVAL) => {}
                }
            }
            serving.cancel();
        }
    });
    let handler = {
        let app = app.clone();
        move |req| app.clone().handle(req)
    };
    web::serve(listeners, handler, web::CONNECTIONS_MAX, serving).await;
    app.close();
    match app.check_alive() {
        Ok(()) => Ok(0),
        Err(stopped) => {
            ui.error(&stopped);
            Ok(4)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{AuthError, BackendError};

    #[test]
    fn refresh_outcomes_as_the_page_shows_them() {
        let fresh = refresh_state(Ok(Some(Ok(RefreshReport {
            applied: 3,
            ..RefreshReport::default()
        }))));
        assert!(fresh.ok && fresh.applied == 3 && fresh.note.is_none());

        let ignored = refresh_state(Ok(Some(Ok(RefreshReport {
            corrupt_objects: vec!["s-1".into()],
            ..RefreshReport::default()
        }))));
        assert!(ignored.ok);
        assert!(ignored.note.unwrap().contains("failed verification"));

        let busy = refresh_state(Ok(None));
        assert!(!busy.ok);
        assert!(busy.note.unwrap().contains("another gclone is running"));

        let gap = refresh_state(Ok(Some(Err(IndexError::Gap {
            names: vec!["s-1".into()],
        }))));
        assert!(!gap.ok);
        assert!(gap.note.unwrap().ends_with("run `gclone repair`."));

        let offline = refresh_state(Ok(Some(Err(IndexError::Backend(BackendError::Transient(
            "connection refused".into(),
        ))))));
        let note = offline.note.unwrap();
        assert!(note.contains("connection refused"), "{note}");
        assert!(note.ends_with("Showing the last state this device has seen."));

        let expired = refresh_state(Ok(Some(Err(IndexError::Backend(BackendError::Auth(
            AuthError::Expired,
        ))))));
        assert!(expired.note.unwrap().contains("Run `gclone login`"));

        // The device was signed out under the viewer: the text of the guard, as it is.
        let stopped = refresh_state(Err(explained(anyhow::anyhow!("stopped"), SIGNED_OUT)));
        assert!(!stopped.ok);
        assert_eq!(stopped.note.as_deref(), Some(SIGNED_OUT));
    }

    /// A device with a config, secrets and a state database, as after `login`.
    fn device(root: &Path) -> (Paths, Config, Secrets) {
        let paths = Paths {
            config_dir: root.join("config"),
            state_root: root.join("state"),
        };
        let config = Config {
            version: 1,
            vault_id: "00112233445566778899aabbccddeeff".into(),
            vault_name: "v".into(),
            backend: BackendCfg::Dir {
                path: root.join("vault"),
            },
            auth_url: None,
            root_id: "r".into(),
            index_id: "i".into(),
            data_id: "d".into(),
        };
        config.save(&paths).unwrap();
        let mut secrets = Secrets::empty();
        secrets.keys = vec![crate::config::KeyEntry {
            epoch: 1,
            key: util::b64url(&[7; 32]),
        }];
        secret_store(&paths).save(&secrets).unwrap();
        drop(Db::open(&paths.db_file(&config.vault_id)).unwrap());
        (paths, config, secrets)
    }

    #[test]
    fn the_guard_notices_a_logout_and_stays_tripped() {
        let tmp = tempfile::tempdir().unwrap();
        let (paths, config, secrets) = device(tmp.path());
        let store = secret_store(&paths);

        // Unchanged files, and files that were written again with the same login.
        let guard = DeviceGuard::new(&paths, &config).unwrap();
        assert_eq!(guard.check(), Ok(()));
        assert_eq!(guard.check(), Ok(()));
        store.save(&secrets).unwrap();
        config.save(&paths).unwrap();
        assert_eq!(guard.check(), Ok(()));
        // `gclone logout`: the secrets are gone — and stay "gone" for this viewer when a
        // new login puts the very same ones back.
        store.delete().unwrap();
        assert_eq!(guard.check(), Err(SIGNED_OUT));
        store.save(&secrets).unwrap();
        assert_eq!(guard.check(), Err(SIGNED_OUT));

        // Another login: other keys, or another Google login.
        for change in [
            (|s: &mut Secrets| s.keys[0].key = util::b64url(&[8; 32])) as fn(&mut Secrets),
            |s| s.keys[0].epoch = 2,
            |s| s.min_epoch = 1,
            |s| s.refresh_token = Some("another".into()),
            |s| s.keys.clear(),
        ] {
            store.save(&secrets).unwrap();
            let guard = DeviceGuard::new(&paths, &config).unwrap();
            assert_eq!(guard.check(), Ok(()));
            let mut other = secrets.clone();
            change(&mut other);
            store.save(&other).unwrap();
            assert_eq!(guard.check(), Err(SIGNED_OUT));
        }
        store.save(&secrets).unwrap();

        // The config names another vault, or is gone (`logout --forget`).
        let guard = DeviceGuard::new(&paths, &config).unwrap();
        let mut elsewhere = config.clone();
        elsewhere.vault_id = "ffeeddccbbaa99887766554433221100".into();
        elsewhere.save(&paths).unwrap();
        assert_eq!(guard.check(), Err(SIGNED_OUT));
        config.save(&paths).unwrap();
        let guard = DeviceGuard::new(&paths, &config).unwrap();
        Config::delete(&paths).unwrap();
        assert_eq!(guard.check(), Err(SIGNED_OUT));
        config.save(&paths).unwrap();

        // The state database is gone, or another file took its place: what the viewer has
        // open is not what the device has.
        let db_file = paths.db_file(&config.vault_id);
        let guard = DeviceGuard::new(&paths, &config).unwrap();
        assert_eq!(guard.check(), Ok(()));
        std::fs::rename(&db_file, db_file.with_extension("old")).unwrap();
        assert_eq!(guard.check(), Err(STATE_GONE));
        drop(Db::open(&db_file).unwrap());
        let guard2 = DeviceGuard::new(&paths, &config).unwrap();
        assert_eq!(guard2.check(), Ok(()));
        assert_eq!(
            guard.check(),
            Err(STATE_GONE),
            "tripped once, tripped for good"
        );
        std::fs::remove_dir_all(paths.state_dir(&config.vault_id)).unwrap();
        assert_eq!(guard2.check(), Err(STATE_GONE));
        // A device without state has no viewer to guard.
        assert!(DeviceGuard::new(&paths, &config).is_err());
    }

    /// `gclone keystore use` moves the secrets between `secrets.json` and `secrets.sealed`
    /// while a viewer runs (§8.3): the same login in another file is not a sign-out, a
    /// moment in which another gclone holds the secrets lock is not one, and neither is a
    /// sealed file that cannot be read at the moment of the look. A logout is, from either.
    #[test]
    fn the_guard_survives_the_key_store_moves() {
        use crate::keystore::{self, LayeredStore};
        let tmp = tempfile::tempdir().unwrap();
        let (paths, config, secrets) = device(tmp.path());
        let store = LayeredStore::new(&paths);
        let sealer = store.sealer().clone().unwrap();
        let guard = DeviceGuard::new(&paths, &config).unwrap();
        assert_eq!(guard.check(), Ok(()));

        for _ in 0..3 {
            let document = std::fs::read(paths.secrets_file()).unwrap();
            let (blob, public) = sealer.create().unwrap();
            keystore::move_to_enclave(&store, &document, &blob, &public, keystore::MoveBy::Command)
                .unwrap();
            assert!(!paths.secrets_file().exists() && paths.sealed_file().exists());
            assert_eq!(guard.check(), Ok(()), "moved into the sealed store");
            assert_eq!(guard.check(), Ok(()));
            keystore::move_to_file(&store, false).unwrap();
            assert!(paths.secrets_file().exists() && !paths.sealed_file().exists());
            assert_eq!(guard.check(), Ok(()), "moved back");
        }

        // Sealed, and the file cannot be read right now: look again, do not stop.
        let document = std::fs::read(paths.secrets_file()).unwrap();
        let (blob, public) = sealer.create().unwrap();
        keystore::move_to_enclave(&store, &document, &blob, &public, keystore::MoveBy::Command)
            .unwrap();
        assert_eq!(guard.check(), Ok(()));
        let good = std::fs::read(paths.sealed_file()).unwrap();
        std::fs::write(paths.sealed_file(), b"{ damaged").unwrap();
        assert_eq!(guard.check(), Ok(()), "a load error is not a sign-out");
        assert_eq!(guard.check(), Ok(()));
        std::fs::write(paths.sealed_file(), &good).unwrap();
        assert_eq!(guard.check(), Ok(()));

        // Neither file while a writer holds the lock: a move in progress.
        let aside = tmp.path().join("aside");
        std::fs::rename(paths.sealed_file(), &aside).unwrap();
        let lock = std::fs::File::open(paths.secrets_lock()).unwrap();
        lock.lock().unwrap();
        assert_eq!(guard.check(), Ok(()), "busy: look again next tick");
        std::fs::rename(&aside, paths.sealed_file()).unwrap();
        lock.unlock().unwrap();
        assert_eq!(guard.check(), Ok(()));

        // Another login in the sealed store: signed in anew.
        let mut other = secrets.clone();
        other.keys[0].key = util::b64url(&[8; 32]);
        secret_store(&paths).save(&other).unwrap();
        assert!(
            !paths.secrets_file().exists(),
            "the save stayed in the sealed store"
        );
        assert_eq!(guard.check(), Err(SIGNED_OUT));

        // A logout of a sealed device.
        secret_store(&paths).save(&secrets).unwrap();
        let guard = DeviceGuard::new(&paths, &config).unwrap();
        assert_eq!(guard.check(), Ok(()));
        secret_store(&paths).delete().unwrap();
        assert!(!paths.sealed_file().exists());
        assert_eq!(guard.check(), Err(SIGNED_OUT));
        assert_eq!(guard.check(), Err(SIGNED_OUT), "tripped for good");
    }

    #[test]
    fn the_launch_page_is_private_and_stale_ones_are_removed() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths {
            config_dir: tmp.path().join("config"),
            state_root: tmp.path().join("state"),
        };
        util::create_dir_private(&paths.state_root).unwrap();
        // Left behind by a viewer that was killed long ago, by one a moment ago, and a file
        // that is none of this function's business.
        let old = paths.state_root.join("web-open-1.html");
        let recent = paths.state_root.join("web-open-2.html");
        let other = paths.state_root.join("secrets.json");
        for file in [&old, &recent, &other] {
            std::fs::write(file, "x").unwrap();
        }
        let long_ago = std::time::SystemTime::now() - 2 * LAUNCH_PAGE_STALE;
        for file in [&old, &other] {
            let handle = std::fs::File::options().write(true).open(file).unwrap();
            handle.set_modified(long_ago).unwrap();
        }

        let link = "http://127.0.0.1:8377/?k=abc_DEF-123";
        let file = write_launch_page(&paths, 8377, link).unwrap();
        assert_eq!(file, paths.state_root.join("web-open-8377.html"));
        assert!(!file.to_string_lossy().contains("abc_DEF-123"));
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let page = std::fs::read_to_string(&file).unwrap();
        assert!(
            page.contains(&format!(r#"content="0;url={link}""#)),
            "{page}"
        );
        assert!(page.contains(r#"<meta name="referrer" content="no-referrer">"#));
        assert!(!page.contains("<script"));
        assert!(!old.exists() && recent.exists() && other.exists());
    }
}

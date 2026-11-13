//! `gclone keystore` (SPEC §7.1, §8.2): where this device keeps its secrets, the Secure
//! Enclave trial, and the two moves between the plain file and the sealed store.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use super::{
    GlobalOpts, LockMode, OpenOpts, RefreshPolicy, blocking, explained, login, note, note_config,
    open_ctx, ui_for, usage,
};
use crate::config::{Config, Paths};
use crate::consts::TRANSFERS_DEFAULT;
use crate::crypto::Keyring;
use crate::error::ConfigError;
use crate::keystore::seal::{self, Sealer};
use crate::keystore::trial::{self, Moment};
use crate::keystore::{
    self, Choice, LayeredStore, MoveError, Report, Source, ToFile, Where, move_to_enclave,
    move_to_file,
};
use crate::ui::Ui;
use crate::util;

#[derive(clap::Args, Clone, Debug)]
pub struct KeystoreArgs {
    #[command(subcommand)]
    pub command: Option<KeystoreCommand>,
}

#[derive(clap::Subcommand, Clone, Debug)]
pub enum KeystoreCommand {
    /// Can THIS session use the Secure Enclave? Made to be run from cron, ssh or a LaunchAgent
    ///
    /// Prints the identifiers of this boot and of this login session, creates a Secure
    /// Enclave key and discards it, opens the trial's test value and — if this device's
    /// secrets are sealed — the sealed store (nothing from it is printed). Stores nothing.
    /// Exit 0 = the Secure Enclave is usable here.
    Check(CheckArgs),
    /// Move this device's login and key: into this Mac's Secure Enclave, or back to the file
    ///
    /// `enclave`: the secrets leave the plain file secrets.json and are kept in
    /// secrets.sealed, encrypted to a key that only this Mac's Secure Enclave can use: a copy
    /// of the file — from a backup, a synced folder, a disk image — is worth nothing anywhere
    /// else. It does not stop a program that runs as you on this Mac. The command first
    /// proves this device's key against the vault and checks that your passphrase opens a
    /// keyfile: if this Mac is erased or repaired, the passphrase is the only way back.
    ///
    /// `file`: back to the plain file (mode 0600), which is what gclone 0.4.0 and older read.
    Use(UseArgs),
}

#[derive(clap::Args, Clone, Debug)]
pub struct CheckArgs {
    /// Discard the trial's record and start a new key.
    #[arg(long)]
    pub new_trial: bool,
}

#[derive(clap::ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum StoreArg {
    /// secrets.sealed: sealed by this Mac's Secure Enclave
    Enclave,
    /// secrets.json: the plain file, mode 0600
    File,
}

#[derive(clap::Args, Clone, Debug)]
pub struct UseArgs {
    #[arg(value_enum)]
    pub store: StoreArg,
    /// enclave: read the passphrase from the first line of this file (e.g. /dev/fd/3).
    #[arg(long, value_name = "PATH")]
    pub passphrase_file: Option<PathBuf>,
    /// enclave: do not check that the passphrase opens a keyfile (NOT recommended: after the
    /// move, the passphrase is the only way back if this Mac is erased or repaired).
    #[arg(long, conflicts_with = "passphrase_file")]
    pub skip_passphrase_check: bool,
    /// enclave: try the passphrase on every keyfile of the vault, not only on the newest.
    #[arg(long)]
    pub all_keyfiles: bool,
    /// enclave: do not ask for confirmation.
    #[arg(long)]
    pub yes: bool,
    /// file: remove a secrets.sealed that lies beside a working secrets.json and differs from
    /// it or does not open.
    #[arg(long)]
    pub discard_sealed: bool,
}

pub async fn run(g: &GlobalOpts, args: KeystoreArgs) -> anyhow::Result<i32> {
    match args.command {
        None => show(g),
        Some(KeystoreCommand::Check(args)) => check(g, args),
        Some(KeystoreCommand::Use(args)) => match args.store {
            StoreArg::Enclave => use_enclave(g, args).await,
            StoreArg::File => use_file(g, args).await,
        },
    }
}

/// An error whose text is the whole message (exit 1).
fn refused(text: impl Into<String>) -> anyhow::Error {
    let text = text.into();
    explained(std::io::Error::other("refused"), text)
}

fn session_text(at: &Moment) -> String {
    format!("{} ({})", at.session, trial::session_kind(&at.session))
}

// ---------------------------------------------------------------------------------------------
// gclone keystore
// ---------------------------------------------------------------------------------------------

fn show(g: &GlobalOpts) -> anyhow::Result<i32> {
    let ui = ui_for(g);
    let paths = Paths::resolve()?;
    let report = keystore::report(&paths);
    if g.json {
        // The one line of this command's JSON output; `Ui::out` is silent with --json.
        println!("{}", report.json(&paths));
        return Ok(0);
    }
    let line = |label: &str, text: String| ui.out(&format!("{label:<12} {text}"));
    line("Key store", report.line());
    match &report.store {
        Where::Plain | Where::Merged => line("File", paths.secrets_file().display().to_string()),
        Where::Sealed | Where::SealedUnusable(_) => {
            line("File", paths.sealed_file().display().to_string())
        }
        _ => {}
    }
    line(
        "Choice",
        match &report.choice {
            Choice::Unset => "none made (`gclone keystore use enclave` or `gclone keystore use \
                              file`)"
                .to_string(),
            Choice::File => "the plain file (`gclone keystore use file`)".to_string(),
            Choice::Enclave => "the Secure Enclave (`gclone keystore use enclave`)".to_string(),
            Choice::Unreadable(why) => format!("keystore.json cannot be used: {why}"),
        },
    );
    match (&report.sealer, &report.trial) {
        (Err(why), _) => line("Sealed store", format!("not available: {}", why.text())),
        (Ok(_), None) => line(
            "Trial",
            match report.choice {
                Choice::File => "not running (the plain file was chosen)".to_string(),
                _ => "not started yet".to_string(),
            },
        ),
        (Ok(_), Some(t)) => {
            if let Some(u) = &t.unavailable
                && !t.running
            {
                line(
                    "Trial",
                    format!(
                        "no Secure Enclave key could be made in session {} ({}) on {}: {}{}",
                        u.session,
                        trial::session_kind(&u.session),
                        &util::format_local_minute(u.ms)[..10],
                        u.error,
                        if u.says_no_hardware() {
                            ""
                        } else {
                            " — that session only; the trial starts in the first session \
                             that can make one"
                        }
                    ),
                );
            } else if t.moved && !t.running {
                let evidence = format!(
                    "{} days, {}",
                    t.days,
                    if t.restart {
                        "a restart survived"
                    } else {
                        "no restart seen"
                    }
                );
                line(
                    "Trial",
                    match report.trial_key_holds_secrets {
                        Some(true) => format!("ended: its key holds the secrets ({evidence})"),
                        // `choose_key` could not use the trial's key at the move.
                        Some(false) => format!(
                            "ended at the move — the secrets were sealed to a NEW key made \
                             then; the trial's evidence ({evidence}) belongs to another key"
                        ),
                        None => format!("ended at a move into the sealed store ({evidence})"),
                    },
                );
            } else {
                line(
                    "Trial",
                    format!(
                        "the test value opened on {} day(s) (complete with {}); {}; {} failure(s)",
                        t.days,
                        trial::DAYS_NEEDED,
                        if t.restart {
                            "a restart survived"
                        } else {
                            "no restart seen yet"
                        },
                        t.failures
                    ),
                );
            }
            if !t.sessions.is_empty() {
                let sessions: Vec<String> = t
                    .sessions
                    .iter()
                    .map(|s| format!("{s} ({})", trial::session_kind(s)))
                    .collect();
                line("Sessions", sessions.join(", "));
            }
            for f in &t.last_failures {
                line(
                    "Failure",
                    format!(
                        "{} in session {} ({}): {}{}",
                        util::format_local_minute(f.ms),
                        f.session,
                        trial::session_kind(&f.session),
                        f.error,
                        if f.timed_out {
                            " — the command went on without it; this session is left alone \
                             for a day"
                        } else if f.fresh_key_ok {
                            " — a new key worked at that moment"
                        } else {
                            " — a new key failed too at that moment"
                        }
                    ),
                );
            }
            if t.complete {
                line(
                    "",
                    "complete: `gclone keystore use enclave` moves this device's key and login \
                     out of the plain file"
                        .to_string(),
                );
            } else if t.failures > 0 {
                line(
                    "",
                    "a failure never clears by itself: `gclone keystore check --new-trial` \
                     starts a new key and record"
                        .to_string(),
                );
            }
        }
    }
    let tag = if report.cachedir_tag {
        "CACHEDIR.TAG present"
    } else {
        "no CACHEDIR.TAG yet"
    };
    line(
        "Backups",
        match &report.backup_excluded {
            Some(Ok(true)) => {
                format!("the state folder is left out of Time Machine backups; {tag}")
            }
            Some(Ok(false)) => format!(
                "the state folder is NOT left out of Time Machine backups yet (set at the next \
                 command that uses the login); {tag}"
            ),
            Some(Err(e)) => format!("the Time Machine exclusion cannot be read ({e}); {tag}"),
            None => format!(
                "{tag} (backup tools skip the state folder only when asked: restic, borg and tar \
                 with --exclude-caches)"
            ),
        },
    );
    match &report.store {
        Where::SealedUnusable(text) | Where::Unreadable(text) => ui.warn(text),
        _ => {}
    }
    for warning in report.warnings() {
        ui.warn(&warning);
    }
    Ok(0)
}

// ---------------------------------------------------------------------------------------------
// gclone keystore check
// ---------------------------------------------------------------------------------------------

fn check(g: &GlobalOpts, args: CheckArgs) -> anyhow::Result<i32> {
    let ui = ui_for(g);
    let paths = Paths::resolve()?;
    let store = LayeredStore::new(&paths);
    let line = |label: &str, text: String| ui.out(&format!("{label:<12} {text}"));
    let at = Moment::now();
    line("Boot", at.boot.clone());
    line("Session", session_text(&at));
    let sealer = match store.sealer() {
        Ok(sealer) => sealer.clone(),
        Err(why) => {
            ui.error(why.text());
            return Ok(1);
        }
    };
    let mut usable = true;
    let started = Instant::now();
    match seal::probe(sealer.as_ref()) {
        Ok(()) => line(
            "New key",
            format!(
                "a {} key can be made and used in this session ({} ms); it was discarded",
                sealer.name(),
                started.elapsed().as_millis()
            ),
        ),
        Err(e) => {
            usable = false;
            line("New key", format!("FAILED: {e}"));
        }
    }
    if args.new_trial {
        match trial::restart(&paths, sealer.as_ref()) {
            Ok(()) => line(
                "Trial",
                "a new key and a new record were started".to_string(),
            ),
            Err(e) => {
                usable = false;
                line("Trial", format!("a new trial could not be started: {e}"));
            }
        }
    } else {
        match trial::load(&paths) {
            trial::Stored::Record(record) if record.summary().running => {
                match record.open_canary(sealer.as_ref()) {
                    Ok(()) => line("Trial", "the test value opens in this session".to_string()),
                    Err(e) => {
                        usable = false;
                        line("Trial", format!("the test value does NOT open: {e}"));
                    }
                }
            }
            _ => line("Trial", "no trial key on this device".to_string()),
        }
    }
    match store.read_sealed() {
        Ok(None) => line("Sealed store", "not in use (no secrets.sealed)".to_string()),
        Ok(Some(bytes)) => match store.open_sealed(&bytes) {
            Ok(_) => line(
                "Sealed store",
                "secrets.sealed opens in this session".to_string(),
            ),
            Err(why) => {
                usable = false;
                line(
                    "Sealed store",
                    format!("secrets.sealed does NOT open: {}", why.brief()),
                );
            }
        },
        Err(e) => {
            usable = false;
            line(
                "Sealed store",
                format!("secrets.sealed cannot be read: {e}"),
            );
        }
    }
    if usable {
        ui.out("The Secure Enclave is usable in this session.");
        Ok(0)
    } else {
        ui.error("the Secure Enclave is NOT fully usable in this session");
        Ok(1)
    }
}

// ---------------------------------------------------------------------------------------------
// gclone keystore use enclave
// ---------------------------------------------------------------------------------------------

/// Other files named `gclone` that a shell or a scheduler may start instead of this binary:
/// on `PATH` and in the usual install directories. Listed, never started.
fn other_binaries() -> Vec<PathBuf> {
    let own = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok());
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        dirs.push(home.join(".local/bin"));
        dirs.push(home.join(".nix-profile/bin"));
    }
    dirs.push("/usr/local/bin".into());
    dirs.push("/opt/homebrew/bin".into());
    let mut seen = BTreeSet::new();
    let mut found = Vec::new();
    for dir in dirs {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join("gclone");
        let Ok(real) = std::fs::canonicalize(&candidate) else {
            continue;
        };
        if !real.is_file() || Some(&real) == own.as_ref() || !seen.insert(real) {
            continue;
        }
        found.push(candidate);
    }
    found
}

/// The key the secrets will be sealed to: the trial's own key if its test value opens right
/// now — then the trial's record belongs to the very key the device will depend on — else a
/// new key, made and tried here.
fn choose_key(
    paths: &Paths,
    sealer: &dyn Sealer,
) -> anyhow::Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>, bool)> {
    if let trial::Stored::Record(record) = trial::load(paths)
        && record.open_canary(sealer).is_ok()
        && let Some((blob, public)) = record.key_for_secrets()
    {
        return Ok((blob, public, true));
    }
    let unusable = |e: seal::SealError| {
        refused(format!(
            "No {} key can be made and used in this session ({e}). Nothing was changed. \
             `gclone keystore check` shows what this session can do.",
            sealer.name()
        ))
    };
    let (blob, public) = sealer.create().map_err(unusable)?;
    let value: [u8; 16] = util::random();
    let sealed = sealer.seal(&public, &value).map_err(unusable)?;
    let back = sealer.open(&blob, &public, &sealed).map_err(unusable)?;
    if back.as_slice() != value {
        return Err(unusable(seal::SealError(
            "a value sealed to the new key did not open to itself".into(),
        )));
    }
    Ok((blob, public, false))
}

fn same_keyring(a: &Keyring, b: &Keyring) -> bool {
    let (a_keys, b_keys) = (a.export(), b.export());
    a.min_epoch() == b.min_epoch()
        && a_keys.len() == b_keys.len()
        && a_keys
            .iter()
            .zip(&b_keys)
            .all(|(x, y)| x.0 == y.0 && util::ct_eq(x.1.as_slice(), y.1.as_slice()))
}

/// What the owner is told before the plain file is removed.
fn announce(ui: &Ui, paths: &Paths, from_trial: bool, passphrase_checked: bool) {
    let summary = match trial::load(paths) {
        trial::Stored::Record(record) => Some(record.summary()),
        _ => None,
    };
    ui.info("");
    match &summary {
        Some(t) if t.running && from_trial => {
            ui.info(&format!(
                "The Secure Enclave trial on this Mac: the test value opened on {} day(s){}, in \
                 {} session(s){}. The secrets are sealed to the same key.",
                t.days,
                if t.restart { ", across a restart" } else { "" },
                t.sessions.len(),
                match t.failures {
                    0 => String::new(),
                    n => format!(", and FAILED {n} time(s)"),
                }
            ));
            let mut missing = Vec::new();
            if t.days < trial::DAYS_NEEDED {
                missing.push(format!("fewer than {} days", trial::DAYS_NEEDED));
            }
            if !t.restart {
                missing.push("no restart yet".to_string());
            }
            if !t
                .sessions
                .iter()
                .any(|s| trial::session_kind(s) != "with graphic access")
            {
                missing.push("no session without graphic access (cron, ssh, a daemon)".to_string());
            }
            if t.failures > 0 {
                missing.push(format!("{} failure(s): see `gclone keystore`", t.failures));
            }
            if !missing.is_empty() {
                ui.warn(&format!("not seen by the trial: {}.", missing.join("; ")));
            }
        }
        _ => ui.warn(
            "the Secure Enclave trial has no evidence for the key that will be used (a new key, \
             made now): not seen on several days, across a restart, or in another session.",
        ),
    }
    ui.info(&format!(
        "After the move this device's login and vault key are in {}, usable only on this Mac. \
         secrets.json is removed.",
        paths.sealed_file().display()
    ));
    ui.info(if passphrase_checked {
        "If this Mac is erased or repaired, the passphrase you just entered is the only way back \
         for this device."
    } else {
        "If this Mac is erased or repaired, the vault passphrase is the only way back for this \
         device — and it was NOT checked now."
    });
    ui.info(
        "Older gclone binaries on this Mac (0.4.0 and before) will say 'not signed in', their \
         `gclone logout` will not sign this device out, and a running `gclone web` or `serve \
         restic` of an older version stops. restic starts `gclone` from its PATH.",
    );
    let others = other_binaries();
    if !others.is_empty() {
        ui.info("Other files named gclone on this Mac (not started, only listed):");
        for other in &others {
            ui.info(&format!("  {}", other.display()));
        }
    }
    ui.info("Run `gclone keystore check` from your scheduler if gclone runs there.");
    ui.info("`gclone keystore use file` moves everything back.");
}

/// `gclone keystore use enclave` on a device whose secrets are sealed already and open here:
/// nothing moves. What an interrupted command left beside the store is settled — plain temp
/// copies of the secrets, a choice that still says `file`.
async fn already_sealed(
    ui: &Ui,
    paths: &Paths,
    store: LayeredStore,
    sealer: &dyn Sealer,
) -> anyhow::Result<i32> {
    let leftovers = keystore::plain_leftovers(paths);
    let choice = keystore::read_choice(paths);
    let settled = blocking(move || Ok(keystore::settle_sealed(&store))).await?;
    match settled {
        Ok(true) => {}
        Ok(false) => {
            return Err(refused(
                "This device's key store changed while the command ran. Nothing was changed \
                 by it. Run the command again.",
            ));
        }
        Err(MoveError::Config(e)) => return Err(e.into()),
        Err(MoveError::Refused(text)) => return Err(refused(text)),
        Err(MoveError::Changed | MoveError::AlreadySealed) => {
            return Err(refused("Nothing was changed."));
        }
    }
    ui.out(&format!(
        "This device's login and key are already sealed by the {} ({}), and the file opens in \
         this session. Nothing was moved.",
        sealer.name(),
        paths.sealed_file().display()
    ));
    if leftovers > 0 {
        ui.out(&format!(
            "Removed {leftovers} plain copy(ies) of the secrets that an interrupted write had \
             left in the state folder."
        ));
    }
    if choice != Choice::Enclave {
        ui.out(
            "keystore.json now records the sealed store as this device's choice (it did not: \
             an interrupted `gclone keystore use file`).",
        );
    }
    Ok(0)
}

async fn use_enclave(g: &GlobalOpts, args: UseArgs) -> anyhow::Result<i32> {
    if args.discard_sealed {
        return Err(usage(
            "--discard-sealed belongs to `gclone keystore use file`",
        ));
    }
    let ui = Arc::new(ui_for(g));
    let paths = Paths::resolve()?;
    note(|h| h.secrets_file = Some(paths.secrets_file()));
    let store = LayeredStore::new(&paths);
    let sealer = match store.sealer() {
        Ok(sealer) => sealer.clone(),
        Err(why) => return Err(refused(format!("Not possible here: {}.", why.text()))),
    };
    // A device that is not connected has nothing to move.
    let config = Config::load(&paths)?;
    note_config(&paths, &config);
    // Where the secrets are — looked at again if the plain file is gone by the time it is
    // read (another `gclone keystore use enclave` finished in between).
    let mut before = None;
    for _ in 0..2 {
        let loaded = store.resolve()?.ok_or(ConfigError::NotLoggedIn)?;
        match loaded.source {
            Source::Sealed => return already_sealed(&ui, &paths, store, sealer.as_ref()).await,
            Source::Merged => {
                return Err(refused(
                    "secrets.json holds a login without a key (an older gclone signed in \
                     here); the key is in secrets.sealed. Run `gclone login` first: it asks \
                     for the passphrase and settles the two files.",
                ));
            }
            Source::Plain if loaded.secrets.keys.is_empty() => {
                return Err(ConfigError::Locked.into());
            }
            Source::Plain => {}
        }
        drop(loaded);
        before = store.read_plain_bytes()?;
        if before.is_some() {
            break;
        }
    }
    let before = before.ok_or(ConfigError::NotLoggedIn)?;
    if !args.yes && !ui.is_tty() {
        return Err(usage(
            "`gclone keystore use enclave` asks for a confirmation: run it on a terminal, or \
             pass --yes (with --passphrase-file PATH)",
        ));
    }

    // Step 3 of §8.2, before anything is asked of the network: the key.
    let (blob, public, from_trial) = {
        let (paths, sealer) = (paths.clone(), sealer.clone());
        blocking(move || choose_key(&paths, sealer.as_ref())).await?
    };

    // Step 1: the login and the cached key are proven against the store.
    let ctx = open_ctx(
        g,
        OpenOpts {
            lock: LockMode::Exclusive,
            refresh: RefreshPolicy::Required,
            settle: false,
            transfers: TRANSFERS_DEFAULT,
        },
    )
    .await?;

    // Step 2: the way back. A keyfile must be on the store, and the passphrase must open it
    // to the very keys this device holds.
    let keyfiles = ctx.vault.keyfiles().await?;
    if keyfiles.is_empty() {
        return Err(refused(
            "There is no keyfile on the store: the passphrase could not bring this device back. \
             Nothing was changed. Run `gclone passwd` first; it writes one.",
        ));
    }
    if args.skip_passphrase_check {
        ui.warn(
            "--skip-passphrase-check: whether your passphrase opens the vault was NOT checked. \
             If it does not, and this Mac is erased or repaired, this device's access is gone; \
             `gclone passwd` on a connected device sets a new passphrase without the old one.",
        );
    } else {
        ui.info(
            "Enter the vault passphrase: after the move it is the only way back if this Mac is \
             erased or repaired.",
        );
        let unlocked = login::unlock_with_passphrase(
            &ui,
            ctx.vault.backend(),
            &keyfiles,
            config.vault_id_bytes()?,
            args.passphrase_file.as_deref(),
            args.all_keyfiles,
            "gclone keystore use enclave --all-keyfiles",
        )
        .await;
        let payload = match unlocked {
            Ok(payload) => payload,
            Err(e)
                if matches!(
                    crate::error::find::<ConfigError>(&e),
                    Some(ConfigError::WrongPassphrase)
                ) =>
            {
                let text = format!(
                    "{} Nothing was changed. Not sure of the passphrase? `gclone passwd` on this \
                     device sets a new one now, without the old one.",
                    super::describe(&e)
                );
                return Err(explained(e, text));
            }
            Err(e) => return Err(e),
        };
        if !same_keyring(&payload.keyring()?, ctx.vault.keys()) {
            return Err(refused(
                "The passphrase opens a keyfile, but with other keys than this device holds. \
                 Nothing was changed. Run `gclone login` on this device first.",
            ));
        }
        ui.info("The passphrase opens the vault's keyfile.");
    }
    // The vault is not needed any more; its lock is not held across the question.
    drop(ctx);

    // Step 4
    announce(&ui, &paths, from_trial, !args.skip_passphrase_check);
    if !args.yes {
        let asked = ui.clone();
        let yes = blocking(move || {
            Ok(asked.confirm("Move this device's login and key into the Secure Enclave store?"))
        })
        .await?;
        if !yes {
            ui.out("Nothing was changed.");
            return Ok(1);
        }
    }

    // Step 5
    let moved = blocking(move || Ok(move_to_enclave(&store, &before, &blob, &public))).await?;
    match moved {
        Ok(()) => {}
        Err(MoveError::Changed) => {
            return Err(refused(
                "This device's login changed while the command ran (another `gclone login`?). \
                 Nothing was changed. Run the command again.",
            ));
        }
        Err(MoveError::AlreadySealed) => {
            ui.out(&format!(
                "Another `gclone keystore use enclave` finished while this one ran: this \
                 device's login and key are sealed by the {} ({}), and the file opens in this \
                 session. This run changed nothing.",
                sealer.name(),
                paths.sealed_file().display()
            ));
            return Ok(0);
        }
        Err(MoveError::Refused(text)) => return Err(refused(text)),
        Err(MoveError::Config(e)) => return Err(e.into()),
    }
    ui.out(&format!(
        "This device's login and key are now sealed by the {} of this Mac: {}",
        sealer.name(),
        paths.sealed_file().display()
    ));
    ui.out("secrets.json was removed. `gclone keystore use file` moves everything back.");
    Ok(0)
}

// ---------------------------------------------------------------------------------------------
// gclone keystore use file
// ---------------------------------------------------------------------------------------------

async fn use_file(g: &GlobalOpts, args: UseArgs) -> anyhow::Result<i32> {
    if args.passphrase_file.is_some() || args.skip_passphrase_check || args.all_keyfiles {
        return Err(usage(
            "--passphrase-file, --skip-passphrase-check and --all-keyfiles belong to `gclone \
             keystore use enclave`",
        ));
    }
    let ui = ui_for(g);
    let paths = Paths::resolve()?;
    note(|h| h.secrets_file = Some(paths.secrets_file()));
    let store = LayeredStore::new(&paths);
    let discard = args.discard_sealed;
    let moved = blocking(move || Ok(move_to_file(&store, discard))).await?;
    let outcome = match moved {
        Ok(outcome) => outcome,
        Err(MoveError::Changed | MoveError::AlreadySealed) => {
            return Err(refused("Nothing was changed."));
        }
        Err(MoveError::Refused(text)) => return Err(refused(text)),
        Err(MoveError::Config(e)) => return Err(e.into()),
    };
    let file = paths.secrets_file();
    let file: &Path = &file;
    ui.out(&match outcome {
        ToFile::Moved => format!(
            "This device's login and key are back in the plain file {} (mode 0600); \
             secrets.sealed was removed.",
            file.display()
        ),
        ToFile::Merged => format!(
            "The login in secrets.json and the key in secrets.sealed are now one plain file, {} \
             (mode 0600); secrets.sealed was removed.",
            file.display()
        ),
        ToFile::AlreadyPlain => format!(
            "This device's login and key are in the plain file {} already; nothing was moved.",
            file.display()
        ),
        ToFile::SealedCopyRemoved => format!(
            "This device's login and key are in the plain file {}; a sealed copy of the same \
             key (secrets.sealed, left by an interrupted move) was removed.",
            file.display()
        ),
        ToFile::SealedDiscarded => format!(
            "This device's login and key are in the plain file {}; secrets.sealed was removed \
             as asked (--discard-sealed).",
            file.display()
        ),
        ToFile::NotSignedIn => {
            "This device is not signed in; nothing was moved. The next `gclone login` saves to \
             the plain file secrets.json."
                .to_string()
        }
    });
    ui.out("The plain file is kept from now on: no Secure Enclave trial, no hint.");
    Ok(0)
}

/// The `Key store` line and the warnings of `gclone status`.
pub(crate) fn status_lines(paths: &Paths) -> (String, Vec<String>) {
    let report: Report = keystore::report(paths);
    let mut warnings = report.warnings();
    if let Where::SealedUnusable(text) | Where::Unreadable(text) = &report.store {
        warnings.insert(0, text.clone());
    }
    (report.line(), warnings)
}

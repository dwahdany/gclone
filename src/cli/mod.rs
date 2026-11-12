//! Command line (SPEC §7, §9.10, §10) — owned by WP7.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::error::{
    self, AuthError, BackendError, ConfigError, FormatError, IndexError, StateError,
};

pub mod about;
pub mod cat;
pub mod check;
pub mod context;
pub mod copy;
pub mod gc;
pub mod login;
pub mod logout;
pub mod ls;
pub mod mkdir;
pub mod mv;
pub mod passwd;
pub mod probe;
pub mod repair;
pub mod restore;
pub mod rm;
pub mod status;

pub use context::*;

/// Options accepted by every command.
#[derive(clap::Args, Clone, Debug)]
pub struct GlobalOpts {
    /// More output (repeatable).
    #[arg(short = 'v', long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,
    /// Less output.
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,
    /// copy and sync only: NDJSON events on stdout, one final {"event":"summary",…}.
    #[arg(long, global = true)]
    pub json: bool,
}

/// What `gclone --version` prints after the name: the version, the target the binary was built
/// for, and the auth Worker URL compiled in (`GCLONE_DEFAULT_AUTH_URL`), if any — that is what
/// tells a binary that needs `gclone login <AUTH_URL>` from one that needs `gclone login`.
fn version_text(built_in_auth_url: Option<&str>) -> String {
    let auth = match built_in_auth_url.map(str::trim).filter(|u| !u.is_empty()) {
        Some(url) => format!("auth URL {url}"),
        None => "no auth URL built in".to_string(),
    };
    format!(
        "{} ({}, {auth})",
        env!("CARGO_PKG_VERSION"),
        env!("GCLONE_TARGET")
    )
}

static VERSION: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| version_text(crate::auth::DEFAULT_AUTH_URL));

#[derive(clap::Parser, Clone, Debug)]
#[command(
    name = "gclone",
    version = VERSION.as_str(),
    about = "Client-side encrypted, rsync-style sync to Google Drive",
    max_term_width = 100
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOpts,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Clone, Debug)]
pub enum Command {
    /// Connect this device: sign in, then create the vault or attach to the existing one
    Login(login::LoginArgs),
    /// Remove this device's login and cached key
    Logout(logout::LogoutArgs),
    /// Set a new passphrase (writes a new keyfile)
    Passwd(passwd::PasswdArgs),
    /// Show login, vault, head fingerprint and devices
    Status(status::StatusArgs),
    /// Show storage and vault statistics
    About(about::AboutArgs),
    /// Copy the contents of a directory to or from the vault; never deletes
    ///
    /// SRC and DST are directories, one local and one in the vault (`:PATH`). The contents of
    /// SRC go into DST, as with `rsync SRC/ DST/`: `gclone copy ~/Photos :Photos` puts
    /// ~/Photos/a.jpg at :Photos/a.jpg. A trailing slash changes nothing. A single file
    /// cannot be named as SRC; `gclone cat :PATH > FILE` fetches one file.
    ///
    /// Files that exist only at the destination are left alone. A file that the other side
    /// changed since the last sync is not overwritten but skipped and reported, and the run
    /// then exits 6 (--force overwrites).
    Copy(copy::CopyArgs),
    /// Like copy, and deletes at the destination what was deleted at the source
    ///
    /// SRC and DST are directories, one local and one in the vault (`:PATH`); the contents of
    /// SRC go into DST, as with `copy`.
    ///
    /// Only what this directory pair has synced before is ever deleted: an entry that was
    /// transferred earlier and has since been removed from SRC is removed from DST (in the
    /// vault it stays restorable for 25 days: gclone restore). Entries that exist only at DST
    /// and were never synced — another device's uploads, files that were always only there —
    /// are kept and reported as skipped, and the run exits 6 until they are copied to the
    /// SRC side (`gclone copy DST SRC`) or removed. --force does not delete them. A first
    /// sync therefore never deletes anything.
    ///
    /// Large deletions need a confirmation (--yes off a terminal); --max-delete N is a hard
    /// limit.
    Sync(copy::SyncArgs),
    /// List a remote directory
    Ls(ls::LsArgs),
    /// Show a remote directory as a tree
    Tree(ls::TreeArgs),
    /// Write a remote file to stdout (a failure after output started is signalled only by the exit code)
    Cat(cat::CatArgs),
    /// Create a remote directory
    Mkdir(mkdir::MkdirArgs),
    /// Remove remote files or directories
    Rm(rm::RmArgs),
    /// Move or rename inside the vault; replaces nothing without --force
    Mv(mv::MvArgs),
    /// Bring back deleted or overwritten files (25 days); -r for a directory
    Restore(restore::RestoreArgs),
    /// Verify blobs, or compare a local tree with the vault
    Check(check::CheckArgs),
    /// Trash data no longer referenced; --purge deletes it permanently
    Gc(gc::GcArgs),
    /// Republish missing index objects and write a fresh snapshot
    Repair(repair::RepairArgs),
    /// The automatable day-0 probes of SPEC §2.9
    #[command(hide = true)]
    Probe(probe::ProbeArgs),
}

/// Text a command chose for its failure, shown instead of the typed error's own message. The
/// typed error stays in the chain and still decides the exit code.
#[derive(Debug)]
pub(crate) struct Explained(pub String);

impl std::fmt::Display for Explained {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// §2.8, `IndexError::VaultNotVisible` on a Drive vault.
pub(crate) const VAULT_NOT_VISIBLE: &str = "This Google login cannot see the vault this device \
    is attached to (another Google account, a new Cloud project, or the app was removed and \
    approved again). Sign in with the account that owns the vault. If the files are really out \
    of the app's reach: download the vault folder from drive.google.com, unzip it, and run \
    `gclone logout --forget`, then `gclone login --vault-dir DIR`.";

/// `err` (which keeps deciding the exit code) presented to the user as `text`.
pub(crate) fn explained(err: impl Into<anyhow::Error>, text: impl Into<String>) -> anyhow::Error {
    err.into().context(Explained(text.into()))
}

/// A usage error found after argument parsing (exit 2, §7.2).
pub(crate) fn usage(text: impl Into<String>) -> anyhow::Error {
    error::SyncError::Usage(text.into()).into()
}

/// A `:PATH` argument → the vault path (`""` = the root).
pub(crate) fn remote_arg(arg: &str) -> anyhow::Result<String> {
    match crate::path::parse_arg(arg) {
        Ok(crate::path::Arg::Remote(path)) => Ok(path),
        Ok(crate::path::Arg::Local(_)) => Err(usage(format!(
            "{arg}: remote paths start with ':' (for example :Photos/2026)"
        ))),
        Err(e) => Err(usage(format!("{arg}: {e}"))),
    }
}

/// `:` or `:path`, as the user would type it.
pub(crate) fn shown(path: &str) -> String {
    format!(":{path}")
}

/// Set while `copy` / `sync` run: the first Ctrl-C then only cancels (the run commits what
/// completed and ends with exit 130); otherwise — and on a second Ctrl-C — the process exits at
/// once, which every command tolerates (§5.8).
pub(crate) static GRACEFUL: AtomicBool = AtomicBool::new(false);

/// The terminal's settings as found: a Ctrl-C during a no-echo prompt must not leave echo off.
fn saved_terminal() -> &'static Mutex<Option<libc::termios>> {
    static SAVED: OnceLock<Mutex<Option<libc::termios>>> = OnceLock::new();
    SAVED.get_or_init(|| {
        // SAFETY: `termios` is plain data; tcgetattr fills it or fails (not a terminal).
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        let ok = unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut t) } == 0;
        Mutex::new(ok.then_some(t))
    })
}

fn exit_interrupted() -> ! {
    if let Some(t) = *saved_terminal().lock().unwrap_or_else(|e| e.into_inner()) {
        // SAFETY: `t` came from tcgetattr on the same descriptor.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t) };
        eprintln!();
    }
    std::process::exit(130);
}

fn install_interrupt_handler() {
    saved_terminal();
    let token = cancel_token();
    tokio::spawn(async move {
        loop {
            if tokio::signal::ctrl_c().await.is_err() {
                return;
            }
            if GRACEFUL.load(Ordering::SeqCst) && !token.is_cancelled() {
                token.cancel();
                eprintln!(
                    "\ninterrupted: committing what is finished (Ctrl-C again stops at once)"
                );
            } else {
                exit_interrupted();
            }
        }
    });
}

/// `gclone login` finds the auth Worker's URL without an argument: this build has a default
/// (`GCLONE_DEFAULT_AUTH_URL`) or the environment names one (`GCLONE_AUTH_URL`, §2.2).
fn auth_url_is_known() -> bool {
    let set = |v: Option<String>| v.is_some_and(|v| !v.trim().is_empty());
    crate::auth::DEFAULT_AUTH_URL.is_some_and(|v| !v.trim().is_empty())
        || set(std::env::var("GCLONE_AUTH_URL").ok())
}

/// §2.8 "not connected": the command to run, without an argument the user does not need.
fn not_configured(auth_url_known: bool) -> String {
    let login = if auth_url_known {
        "gclone login"
    } else {
        "gclone login <AUTH_URL>"
    };
    format!(
        "This device is not connected. Run `{login}` (or `gclone login --vault-dir DIR` for a \
         directory vault)."
    )
}

/// `--json` is implemented by `copy` and `sync`. Every other command would print nothing on
/// stdout and exit 0 — a script could not tell that from "no entries" (§7.1).
fn json_supported(command: &Command) -> bool {
    matches!(command, Command::Copy(_) | Command::Sync(_))
}

/// The user-facing text of a failure (§2.8). Typed errors are found anywhere in the chain.
pub(crate) fn describe(e: &anyhow::Error) -> String {
    if let Some(Explained(text)) = e.downcast_ref::<Explained>() {
        return text.clone();
    }
    let hints = hints();
    if let Some(c) = error::find::<ConfigError>(e) {
        match c {
            ConfigError::NotConfigured => return not_configured(auth_url_is_known()),
            ConfigError::NotLoggedIn => {
                return match &hints.vault_dir {
                    Some(dir) => format!(
                        "This device is not connected (signed out). Run `gclone login \
                         --vault-dir {}`.",
                        dir.display()
                    ),
                    None => "This device is not connected (signed out). Run `gclone login`.".into(),
                };
            }
            ConfigError::Locked => {
                return "Run `gclone login` to finish connecting this device (it will ask for \
                        the passphrase)."
                    .into();
            }
            ConfigError::InsecurePermissions(path) => {
                let file = hints
                    .secrets_file
                    .clone()
                    .unwrap_or_else(|| std::path::PathBuf::from(path));
                let dir = file.parent().unwrap_or(&file).display().to_string();
                return format!(
                    "Refusing to use {path}: it is readable by others. Fix with `chmod 700 \
                     {dir}; chmod 600 {}` — and if it was copied or restored from somewhere, \
                     treat the login and the key as exposed.",
                    file.display()
                );
            }
            ConfigError::WrongPassphrase => return "Wrong passphrase.".into(),
            _ => {}
        }
    }
    if let Some(a) = error::find::<AuthError>(e) {
        let incomplete = |reason: &str| {
            format!("Sign-in was not completed ({reason}). Run `gclone login` again.")
        };
        match a {
            AuthError::Expired => {
                let day_ms = 86_400_000;
                return match hints.refresh_expires_at_ms {
                    Some(end) if crate::util::now_ms() >= end.saturating_sub(day_ms) => format!(
                        "This login was time-limited by Google and ended on {}: the OAuth app \
                         is still in Testing. Open Google Auth Platform → Audience → Publish \
                         app, then run `gclone login`.",
                        &crate::util::format_local_minute(end)[..10]
                    ),
                    _ => "Google no longer accepts this device's login (revoked, signed out \
                          everywhere, or unused for 6 months). Run `gclone login`."
                        .into(),
                };
            }
            AuthError::NotAllowed(message) => {
                return format!(
                    "The auth Worker does not allow this Google account ({message}). Sign in \
                     with the right Google account, or add the address to ALLOWED_EMAILS \
                     (worker/README.md)."
                );
            }
            AuthError::WorkerMisconfigured(message) => {
                return format!(
                    "The auth Worker cannot authenticate to Google ({message}): its secrets are \
                     missing or wrong, or the OAuth client was deleted (Google removes clients \
                     idle for 6 months; restorable for 30 days). Fix it per worker/README.md — \
                     restore the client, or create a new Web application client in the same \
                     Cloud project and `wrangler secret put` its ID and secret — then retry."
                );
            }
            AuthError::Denied(reason) => return incomplete(&format!("access denied: {reason}")),
            AuthError::ScopeMissing => {
                return incomplete("Google Drive file access was not granted");
            }
            AuthError::LoginFailed(reason) => return incomplete(reason),
            AuthError::Timeout => {
                return format!(
                    "{} Without a browser on this machine: `gclone login --no-browser`.",
                    incomplete("no answer from the browser in time")
                );
            }
            AuthError::StateMismatch => {
                return incomplete("the answer does not belong to this sign-in");
            }
            AuthError::BadAuthUrl(detail) if detail.contains("(given: ") => {
                return format!("The auth Worker URL must be https://… — {detail}.");
            }
            AuthError::BadAuthUrl(detail) => {
                let mut text = detail.clone();
                if let Some(first) = text.get(..1) {
                    let upper = first.to_uppercase();
                    text.replace_range(..1, &upper);
                }
                return format!("{text}.");
            }
            AuthError::Network(detail) => {
                return match &hints.auth_url {
                    Some(url) => format!("Could not reach the auth Worker at {url} ({detail})."),
                    None => format!("Could not reach the auth Worker ({detail})."),
                };
            }
            AuthError::Io(_) => {}
        }
    }
    let not_visible = matches!(
        error::find::<IndexError>(e),
        Some(IndexError::VaultNotVisible)
    ) || matches!(
        error::find::<BackendError>(e),
        Some(BackendError::AppNotAuthorized)
    );
    if not_visible {
        return VAULT_NOT_VISIBLE.into();
    }
    match error::find::<IndexError>(e) {
        Some(IndexError::VaultTrashed) => {
            return "The vault folder is in the Drive trash. Restore it in drive.google.com (it \
                    is deleted for good after 30 days)."
                .into();
        }
        Some(gap @ (IndexError::Gap { .. } | IndexError::Rollback { .. })) => {
            return format!(
                "{gap}. Nothing was changed. Run `gclone repair` — on this device, or on one \
                 that has seen the missing objects."
            );
        }
        Some(stuck @ IndexError::OutboxStuck(_)) => {
            return format!("{stuck}. Run the command again once the cause is gone.");
        }
        Some(unreadable @ IndexError::UnsupportedObject { .. }) => {
            return format!(
                "{unreadable}. Update gclone on this device. If no newer gclone has ever \
                 written to this vault, the object was not written by gclone: remove it from \
                 the vault's `index` folder in drive.google.com."
            );
        }
        _ => {}
    }
    match error::find::<FormatError>(e) {
        Some(FormatError::KeyfileDamaged) => {
            return "The vault's keyfile is missing or damaged. Run `gclone passwd` on a \
                    connected device to write a new one."
                .into();
        }
        Some(FormatError::WeakPassphrase) => {
            return format!("{e:#}. Nothing was changed.");
        }
        _ => {}
    }
    if matches!(error::find::<StateError>(e), Some(StateError::Locked)) {
        return format!(
            "another gclone is running on this vault. Nothing was changed: run the command \
             again when the other one is done (a command that changes the vault waits {} \
             seconds for it; `pgrep -l gclone` shows it, and its lock ends with the process).",
            crate::consts::LOCK_WAIT.as_secs()
        );
    }
    format!("{e:#}")
}

async fn dispatch(g: &GlobalOpts, command: Command) -> anyhow::Result<i32> {
    if g.json && !json_supported(&command) {
        return Err(usage(
            "--json is supported by copy and sync only; this command has no JSON output",
        ));
    }
    match command {
        Command::Login(a) => login::run(g, a).await,
        Command::Logout(a) => logout::run(g, a).await,
        Command::Passwd(a) => passwd::run(g, a).await,
        Command::Status(a) => status::run(g, a).await,
        Command::About(a) => about::run(g, a).await,
        Command::Copy(a) => copy::run(g, a).await,
        Command::Sync(a) => copy::run_sync(g, a).await,
        Command::Ls(a) => ls::run(g, a).await,
        Command::Tree(a) => ls::run_tree(g, a).await,
        Command::Cat(a) => cat::run(g, a).await,
        Command::Mkdir(a) => mkdir::run(g, a).await,
        Command::Rm(a) => rm::run(g, a).await,
        Command::Mv(a) => mv::run(g, a).await,
        Command::Restore(a) => restore::run(g, a).await,
        Command::Check(a) => check::run(g, a).await,
        Command::Gc(a) => gc::run(g, a).await,
        Command::Repair(a) => repair::run(g, a).await,
        Command::Probe(a) => probe::run(g, a).await,
    }
}

fn report(result: anyhow::Result<i32>) -> (i32, Option<anyhow::Error>) {
    match result {
        Ok(code) => (code, None),
        Err(e) => {
            eprintln!("error: {}", describe(&e));
            (error::exit_code(&e), Some(e))
        }
    }
}

/// §2.8: after "Google no longer accepts this device's login", a terminal user is offered the
/// fix right away.
async fn offer_login(g: &GlobalOpts, e: &anyhow::Error) -> bool {
    if !matches!(error::find::<AuthError>(e), Some(AuthError::Expired)) {
        return false;
    }
    let ui = ui_for(g);
    if !ui.is_tty() {
        return false;
    }
    blocking(move || Ok(ui.confirm("Run `gclone login` now?")))
        .await
        .unwrap_or(false)
}

/// Parse (clap derive), dispatch, map errors → exit code (`error::exit_code`), install the
/// Ctrl-C handler.
pub async fn run() -> i32 {
    use clap::Parser as _;
    // Usage errors and --help/--version exit here (code 2 / 0).
    let cli = Cli::parse();
    crate::ui::init_logging(cli.global.verbose);
    install_interrupt_handler();
    let g = cli.global;
    let is_login = matches!(cli.command, Command::Login(_));
    let (code, failure) = report(dispatch(&g, cli.command).await);
    if let Some(e) = failure
        && !is_login
        && offer_login(&g, &e).await
    {
        let (login_code, _) = report(login::run(&g, login::LoginArgs::default()).await);
        if login_code == 0 {
            eprintln!("Signed in. Run the command again.");
        }
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn clap_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn version_names_the_target_and_the_built_in_auth_url() {
        let target = env!("GCLONE_TARGET");
        assert!(target.split('-').count() >= 3, "a target triple: {target}");
        let v = env!("CARGO_PKG_VERSION");
        assert_eq!(
            version_text(Some("https://auth.example.org")),
            format!("{v} ({target}, auth URL https://auth.example.org)")
        );
        for none in [None, Some(""), Some("  ")] {
            assert_eq!(
                version_text(none),
                format!("{v} ({target}, no auth URL built in)")
            );
        }
        // What clap prints for -V and --version alike.
        assert_eq!(
            Cli::command().render_version(),
            format!("gclone {}\n", version_text(crate::auth::DEFAULT_AUTH_URL))
        );
        assert_eq!(
            Cli::command().render_long_version(),
            Cli::command().render_version()
        );
    }

    #[test]
    fn documented_invocations_parse() {
        for argv in [
            "gclone login https://gclone-auth.example.workers.dev",
            "gclone login --no-browser --device-name nas --vault-name v --new-vault --passphrase-file /dev/fd/3 --allow-expiring-login",
            "gclone login --vault-dir /tmp/v --vault-id 00112233445566778899aabbccddeeff",
            "gclone logout --revoke --forget --yes",
            "gclone passwd --passphrase-file f",
            "gclone status -q",
            "gclone about",
            "gclone copy ./a :b -n --checksum --force --exclude *.tmp --exclude node_modules/ --transfers 2 --reset-pair",
            "gclone sync :b ./a --dry-run --keep-pair --max-delete 5 --yes",
            "gclone ls -l -R :Photos",
            "gclone ls",
            "gclone tree :",
            "gclone cat :a/b --offset 10 --count 20",
            "gclone mkdir :d",
            "gclone rm -r :a :b",
            "gclone mv :a :b",
            "gclone restore :p --list",
            "gclone restore :p --version 2",
            "gclone restore -r :dir :file --list",
            "gclone mv --force :a :b",
            "gclone mv :a :",
            "gclone check",
            "gclone check ./local :remote",
            "gclone check --download :p",
            "gclone gc -n --orphans --purge",
            "gclone repair --accept-loss",
            "gclone probe",
            "gclone -vv --json sync ./a :b",
            "gclone sync ./a :b -v -q --json",
        ] {
            let args: Vec<&str> = argv.split(' ').collect();
            Cli::try_parse_from(&args).unwrap_or_else(|e| panic!("{argv}: {e}"));
        }
        let cli = Cli::try_parse_from(["gclone", "-vv", "status", "-q"]).unwrap();
        assert_eq!(cli.global.verbose, 2);
        assert!(cli.global.quiet);
        assert!(!cli.global.json);
    }

    #[test]
    fn not_connected_names_a_command_that_works() {
        assert!(not_configured(false).contains("Run `gclone login <AUTH_URL>` (or"));
        let known = not_configured(true);
        assert!(known.contains("Run `gclone login` (or"), "{known}");
        assert!(!known.contains("AUTH_URL"), "{known}");
    }

    #[test]
    fn json_is_offered_where_it_is_implemented() {
        for (argv, supported) in [
            ("gclone --json copy a :b", true),
            ("gclone sync a :b --json", true),
            ("gclone --json ls", false),
            ("gclone status --json", false),
            ("gclone restore --list :p --json", false),
            ("gclone login --json", false),
        ] {
            let args: Vec<&str> = argv.split(' ').collect();
            let cli = Cli::try_parse_from(&args).unwrap();
            assert!(cli.global.json);
            assert_eq!(json_supported(&cli.command), supported, "{argv}");
        }
        // The help says so where the flag is listed.
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("copy and sync only"), "{help}");
    }

    #[test]
    fn usage_errors_are_rejected() {
        for argv in [
            "gclone",
            "gclone frobnicate",
            "gclone copy onlyone",
            "gclone sync a b --reset-pair --keep-pair",
            "gclone rm",
            "gclone mv :a",
            "gclone cat",
            "gclone copy a b --max-delete 3",
            "gclone check a b c",
        ] {
            let args: Vec<&str> = argv.split(' ').collect();
            assert!(
                Cli::try_parse_from(&args).is_err(),
                "{argv} should be a usage error"
            );
        }
    }
}

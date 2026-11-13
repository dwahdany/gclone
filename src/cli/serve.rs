//! `gclone serve restic` (SPEC §7.6, §10): the command line, the start-up and the two front
//! ends of `crate::restic`.
//!
//! Only the sign-in is used: `secrets.json` for the login and the shared `token.json`. No
//! vault, no passphrase, no `config.json`, no state lock, no `state.db` — a running server
//! holds up no other gclone command, and none holds it up.

use std::io::IsTerminal as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context as _;

use super::{
    GlobalOpts, cancel_token, drive_backend, explained, note, note_secrets, ui_for, usage,
};
use crate::backend::drive::DriveBackend;
use crate::config::{Paths, secret_store};
use crate::consts::TRANSFERS_DEFAULT;
use crate::error::ConfigError;
use crate::restic::{self, App, EXIT_GRACE, LISTENER_CONNECTIONS, Options, RepoName};
use crate::util;
use crate::web::{self, V6};

#[derive(clap::Args, Clone, Debug)]
pub struct ServeArgs {
    #[command(subcommand)]
    pub what: ServeWhat,
}

#[derive(clap::Subcommand, Clone, Debug)]
pub enum ServeWhat {
    /// Keep a restic repository on Google Drive (restic's REST backend protocol)
    ///
    /// restic starts this command by itself, through its rclone backend — there is no daemon
    /// and no port:
    ///
    ///   restic -o rclone.program=gclone -r rclone:NAME init
    ///   restic -o rclone.program=gclone -r rclone:NAME backup ~/Documents
    ///
    /// NAME is the repository's name on Drive: its files are in the folder gclone-restic/NAME,
    /// beside the vault and not part of it. restic encrypts, deduplicates and packs; gclone
    /// adds no second encryption and only contributes the Google sign-in and the Drive client.
    /// A signed-in device is all it needs (`gclone login`): no vault passphrase is asked for.
    /// `restic init` takes about a minute (it creates 262 folders).
    ///
    /// Use a larger pack size than restic's default, because every file costs Drive API calls:
    /// --pack-size 64, or RESTIC_PACK_SIZE=64.
    ///
    /// A delete moves the file to the Drive trash, as everywhere in gclone: it can be brought
    /// back for about 30 days, and its space is freed when the trash is emptied.
    /// --append-only refuses every delete except locks — a guard against mistakes, not a
    /// security boundary: this device's Google login can still trash the same files.
    ///
    ///   restic -o rclone.program=gclone -o rclone.args="serve restic --stdio --append-only" …
    ///
    /// --port N instead listens on 127.0.0.1:N for restic's rest: backend and prints the token
    /// restic has to send:
    ///
    ///   restic -r rest:http://127.0.0.1:N/NAME/ snapshots
    #[command(verbatim_doc_comment)]
    Restic(ResticArgs),
}

#[derive(clap::Args, Clone, Debug)]
#[command(group(clap::ArgGroup::new("transport").required(true).args(["stdio", "port"])))]
pub struct ResticArgs {
    /// HTTP/2 over stdin and stdout: the mode restic starts by itself (-o rclone.program=gclone).
    #[arg(long)]
    pub stdio: bool,
    /// Listen on 127.0.0.1:N (and [::1]:N) for restic's rest: backend, behind a token.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..))]
    pub port: Option<u16>,
    /// Refuse every delete except locks.
    #[arg(long)]
    pub append_only: bool,
    /// Accepted and ignored — restic passes it to every rclone-style backend. Deletes always go
    /// to the Drive trash.
    #[arg(long, hide = true)]
    pub b2_hard_delete: bool,
    /// With --stdio: the repository's name on Drive (restic passes what follows `rclone:`).
    #[arg(
        value_name = "REPO",
        required_unless_present = "port",
        conflicts_with = "port"
    )]
    pub repo: Option<RepoName>,
}

const NOT_SIGNED_IN: &str = "This device is not signed in to Google. Run `gclone login` first \
    (gclone serve restic needs the sign-in, not the vault passphrase).";

/// How often the listener looks whether this device is still signed in.
const GUARD_INTERVAL: Duration = Duration::from_secs(1);

pub async fn run(g: &GlobalOpts, args: ServeArgs) -> anyhow::Result<i32> {
    let ServeWhat::Restic(args) = args.what;
    let opts = Options {
        append_only: args.append_only,
        ..Options::default()
    };
    if args.stdio && (std::io::stdin().is_terminal() || std::io::stdout().is_terminal()) {
        return Err(usage(
            "--stdio is the mode restic starts by itself: restic -o rclone.program=gclone -r \
             rclone:NAME …",
        ));
    }
    let (backend, paths) = signed_in()?;
    match (args.repo, args.port) {
        (Some(repo), _) => stdio(backend, repo, opts).await,
        (None, Some(port)) => listen(g, backend, &paths, port, opts).await,
        (None, None) => Err(usage("serve restic needs --stdio REPO or --port N")),
    }
}

/// The Drive client of this device's login. Nothing is asked of the network yet.
fn signed_in() -> anyhow::Result<(Arc<DriveBackend>, Paths)> {
    let paths = Paths::resolve()?;
    note(|h| h.secrets_file = Some(paths.secrets_file()));
    let not_signed_in = || explained(ConfigError::NotLoggedIn, NOT_SIGNED_IN);
    let secrets = secret_store(&paths).load()?.ok_or_else(not_signed_in)?;
    note_secrets(&secrets);
    // A device of a directory vault has secrets without a login.
    let token = secrets.refresh_token.as_deref().filter(|t| !t.is_empty());
    let token = token.ok_or_else(not_signed_in)?;
    let (backend, _) = drive_backend(
        secrets.endpoints()?,
        token,
        secrets.client,
        &paths,
        TRANSFERS_DEFAULT,
        true,
    )?;
    Ok((Arc::new(backend), paths))
}

/// The peer went away: how every stdio run ends.
fn peer_closed(e: &hyper::Error) -> bool {
    use std::error::Error as _;
    use std::io::ErrorKind as K;
    let mut cause = e.source();
    while let Some(inner) = cause {
        if let Some(io) = inner.downcast_ref::<std::io::Error>() {
            return matches!(
                io.kind(),
                K::BrokenPipe | K::UnexpectedEof | K::ConnectionReset | K::ConnectionAborted
            );
        }
        cause = inner.source();
    }
    e.is_closed() || e.is_canceled() || e.is_incomplete_message()
}

/// `--stdio`: one HTTP/2 connection over the two pipes. It ends when restic closes them, and
/// only then: restic removes its lock through this process after a SIGINT or SIGTERM, and a
/// service manager that stops a unit signals both processes at once.
async fn stdio(backend: Arc<DriveBackend>, repo: RepoName, opts: Options) -> anyhow::Result<i32> {
    let (input, output) =
        restic::stdio::claim().context("cannot take stdin and stdout for the protocol")?;
    super::DETACHED.store(true, Ordering::SeqCst);
    // SAFETY: changes the disposition of two signals for which this process has no handler.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
    let app = App::single(backend, repo, opts);
    let io = restic::stdio::connection(input, output);
    let served = restic::http::serve_h2(app.clone(), io).await;
    // restic is gone — it does not wait for this process. An upload it was not answered for,
    // the lock of a restic that was interrupted while it created it, is taken back before
    // the process ends.
    let _ = tokio::time::timeout(EXIT_GRACE, app.close()).await;
    match served {
        Ok(()) => Ok(0),
        Err(e) if peer_closed(&e) => Ok(0),
        Err(e) => {
            restic::note(&format!("the connection to restic failed: {e}"));
            Ok(1)
        }
    }
}

/// SIGTERM and SIGHUP stop the listener the way the first Ctrl-C does: the default action
/// would end the process at once, without taking back the uploads nobody was answered for
/// and with the status of a killed process. A signal the process was started to ignore
/// (`nohup`) stays ignored.
fn stop_on_signals(serving: &tokio_util::sync::CancellationToken) -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let signals = [
        (libc::SIGTERM, SignalKind::terminate()),
        (libc::SIGHUP, SignalKind::hangup()),
    ];
    for (number, kind) in signals {
        if ignored(number) {
            continue;
        }
        let mut signalled = signal(kind).context("cannot install a signal handler")?;
        let serving = serving.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = signalled.recv() => serving.cancel(),
                () = serving.cancelled() => {}
            }
        });
    }
    Ok(())
}

/// Whether the process ignores `signal` now.
fn ignored(signal: libc::c_int) -> bool {
    // SAFETY: `sigaction` is plain data, and with no new action the call only fills it in.
    let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
    let read = unsafe { libc::sigaction(signal, std::ptr::null(), &mut current) };
    read == 0 && current.sa_sigaction == libc::SIG_IGN
}

/// `--port N`: HTTP/1.1 on loopback for restic's `rest:` backend, behind a token that is new
/// for every start. Both loopback addresses are bound or nothing is: restic sends the token
/// unasked, and `localhost` may mean `::1`.
async fn listen(
    g: &GlobalOpts,
    backend: Arc<DriveBackend>,
    paths: &Paths,
    port: u16,
    opts: Options,
) -> anyhow::Result<i32> {
    let ui = ui_for(g);
    let (listeners, port) = web::bind_v6(port, V6::Required)
        .await
        .map_err(|e| anyhow::anyhow!("cannot listen on 127.0.0.1:{port}: {e}"))?;
    let mut hosts = vec![format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    if listeners.len() > 1 {
        hosts.push(format!("[::1]:{port}"));
    }
    let token = util::hex(&util::random::<16>());
    let app = App::listener(backend, token.clone(), hosts, opts);
    ui.out(&format!(
        "Serving restic repositories on http://127.0.0.1:{port}/NAME/ — Ctrl-C stops.\n\
         export RESTIC_REST_USERNAME=gclone\n\
         export RESTIC_REST_PASSWORD={token}\n\
         restic -r rest:http://127.0.0.1:{port}/NAME/ snapshots"
    ));

    // Ctrl-C ends it (exit 0), and so do SIGTERM and SIGHUP — what a service manager, `kill`
    // and a closing terminal send; so does `gclone logout` on this device (exit 4).
    super::SERVING.store(true, Ordering::SeqCst);
    let serving = cancel_token().child_token();
    stop_on_signals(&serving)?;
    let signed_out = Arc::new(AtomicBool::new(false));
    tokio::spawn({
        let (serving, signed_out) = (serving.clone(), signed_out.clone());
        let secrets = paths.secrets_file();
        async move {
            while secrets.exists() {
                tokio::select! {
                    () = serving.cancelled() => return,
                    () = tokio::time::sleep(GUARD_INTERVAL) => {}
                }
            }
            signed_out.store(true, Ordering::SeqCst);
            serving.cancel();
        }
    });
    let handler = {
        let app = app.clone();
        move |req| app.clone().handle(req)
    };
    web::serve(listeners, handler, LISTENER_CONNECTIONS, serving).await;
    let _ = tokio::time::timeout(EXIT_GRACE, app.close()).await;
    if signed_out.load(Ordering::SeqCst) {
        ui.error("this device was signed out: stopped");
        return Ok(4);
    }
    Ok(0)
}

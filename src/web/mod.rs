//! `gclone web`: the decrypted vault as a file browser, served on loopback (SPEC §7.4).
//!
//! Read-only: no route changes the vault or the index. What the server protects is the user's
//! plaintext, so every request has to pass, in this order: the `Host` check (the exact
//! loopback authorities this server listens on — a DNS-rebinding defence), the same-origin
//! check (`Origin`, `Sec-Fetch-Site`), and the session cookie, which only the one-time link
//! printed in the terminal hands out. Everything but the link itself lives under a random
//! path prefix that the cookie is scoped to, so that the browser shows the cookie to this
//! server and to no other port of the loopback host. Files of the vault are untrusted content
//! and are served so that they can never act with the viewer's origin (`mime`).

use std::collections::VecDeque;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::{CancellationToken, PollSender};

use crate::backend::{AnyBackend, Backend as _};
use crate::error::{IndexError, TransferError};
use crate::index::{ListRow, SearchHit, Vault};
use crate::state::{Db, LedgerDir};
use crate::types::{BlobRec, EntryKind, Head};
use crate::util;

pub mod http;
pub mod mime;
pub mod rules;

use http::{BadRequest, Body, ByteRange, Failure};
use rules::{EntryJson, InfoJson, RowView, SortOrder};
pub use rules::{LIST_PAGE, LIST_PAGE_MAX, RefreshState, SEARCH_HITS, SEARCH_HITS_MAX};

pub const INDEX_HTML: &str = include_str!("assets/index.html");
pub const APP_CSS: &str = include_str!("assets/app.css");
pub const APP_JS: &str = include_str!("assets/app.js");
pub const ICON_SVG: &str = include_str!("assets/icon.svg");

/// The policy of the viewer's own page: nothing but its own script, style, images, media and
/// frames (the PDF preview), no inline script or style, no plugins, no forms, no framing.
pub const PAGE_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
     img-src 'self' blob:; media-src 'self'; frame-src 'self'; connect-src 'self'; \
     base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
/// Everything that is neither the page nor a file: nothing to load, nothing to run.
const BARE_CSP: &str = "default-src 'none'; frame-ancestors 'none'";

/// File streams at a time — each one holds a download from the store — and how long a
/// request waits for a free one before it is told to come back (`503`).
pub const STREAMS_MAX: usize = 16;
const STREAM_WAIT: Duration = Duration::from_secs(5);
/// Connections at a time.
pub const CONNECTIONS_MAX: usize = 128;
/// Time for a client to send its request head, and the size that head may have: request
/// line and header lines as they were sent. `handle` enforces the number; hyper's read buffer
/// (`max_buf_size`, which grows past it before it gives up) only bounds what is read at all.
const HEADER_TIMEOUT: Duration = Duration::from_secs(15);
pub const HEADER_BYTES_MAX: usize = 64 * 1024;
/// Keys of used links that are remembered, to tell "used already" from "never valid".
const USED_KEYS_KEPT: usize = 16;
/// Plaintext handed to hyper per frame, and frames waiting between download and client.
const FRAME_BYTES: usize = 64 * 1024;
const FRAMES_QUEUED: usize = 16;

/// Refreshes the replica the way a read-only command does — try the state lock, open the vault
/// with it, `refresh()`, release — and says how it went. Never holds the lock longer.
pub type Refresher =
    Box<dyn Fn() -> Pin<Box<dyn Future<Output = RefreshState> + Send>> + Send + Sync>;

/// Whether this device may still serve the vault: `Err(text)` once it was signed out or its
/// local state was removed (`gclone logout [--forget]`). Asked for every request — it must be
/// cheap — and by the command's timer.
pub type Alive = Box<dyn Fn() -> Result<(), String> + Send + Sync>;

pub struct Options {
    /// Opened without the state lock (`Vault::open_unlocked`): queries and downloads only.
    pub vault: Vault<AnyBackend>,
    /// A connection of its own for the download ledger, so that a ledger write that waits for
    /// another gclone's transaction holds up no listing.
    pub ledger: Option<Db>,
    pub refresher: Refresher,
    pub refreshed: RefreshState,
    /// Shown until the replica knows the vault's name.
    pub vault_name: String,
    /// `"drive"` or `"dir"`.
    pub backend: &'static str,
    pub device: String,
    pub port: u16,
    pub alive: Alive,
    /// Enter in the terminal makes a new link (else the viewer has to be started again): only
    /// for the texts that say how to get one.
    pub interactive: bool,
}

/// One browser session. A new link starts a new one and ends the one before.
struct Session {
    /// `/s-<128 random bits>/`: where the page, its assets, the API and the files live, and
    /// the cookie's `Path`. Not a credential — it is in the address bar; it keeps the browser
    /// from attaching the cookie to requests for other loopback ports, whose servers do not
    /// know it.
    prefix: String,
    /// The cookie's value: 256 bits from the OS.
    secret: String,
    /// Fires when the session is replaced or the viewer stops: its file streams end.
    ended: CancellationToken,
}

impl Session {
    fn new() -> Arc<Session> {
        Arc::new(Session {
            prefix: format!("/s-{}/", util::b64url(&util::random::<16>())),
            secret: util::b64url(&util::random::<32>()),
            ended: CancellationToken::new(),
        })
    }
}

/// The way in: the session, and the link that opens it.
struct Access {
    session: Arc<Session>,
    /// The key of the link that has not been used yet. Each link works once.
    key: Option<String>,
    used: VecDeque<String>,
    /// The page that took the browser to the link (`launch_page`): removed with the key.
    launch: Option<PathBuf>,
}

enum Redeemed {
    Granted(Arc<Session>),
    Used,
    Unknown,
}

/// Opaque names for files in URLs the browser may keep (a tab's address, the download list):
/// the path, encrypted under a key that lives as long as this process. Deterministic — the
/// nonce is a keyed hash of the path — so one file has one address.
struct FileIds {
    cipher: XChaCha20Poly1305,
    nonce_key: [u8; 32],
}

impl FileIds {
    fn new() -> FileIds {
        FileIds {
            cipher: XChaCha20Poly1305::new(&util::random::<32>().into()),
            nonce_key: util::random(),
        }
    }

    fn seal(&self, path: &str) -> Option<String> {
        let hash = blake3::keyed_hash(&self.nonce_key, path.as_bytes());
        let nonce: [u8; 24] = hash.as_bytes()[..24].try_into().ok()?;
        let sealed = self.cipher.encrypt(&nonce.into(), path.as_bytes()).ok()?;
        Some(util::b64url(&[&nonce[..], &sealed].concat()))
    }

    fn open(&self, id: &str) -> Option<String> {
        let raw = util::unb64url(id)?;
        let (nonce, sealed) = raw.split_at_checked(24)?;
        let nonce: [u8; 24] = nonce.try_into().ok()?;
        let plain = self.cipher.decrypt(&nonce.into(), sealed).ok()?;
        String::from_utf8(plain).ok()
    }
}

pub struct App {
    vault: Arc<Vault<AnyBackend>>,
    ledger: Option<Db>,
    refresher: Refresher,
    refreshed: Mutex<RefreshState>,
    /// One refresh at a time.
    refreshing: tokio::sync::Mutex<()>,
    vault_name: String,
    backend: &'static str,
    device: String,
    port: u16,
    /// The `Host` values this server answers to, and the origins that are its own.
    hosts: Vec<String>,
    origins: Vec<String>,
    cookie_name: String,
    access: Mutex<Access>,
    ids: FileIds,
    alive: Alive,
    /// Why this viewer serves nothing any more (`Alive` said so once: that is final).
    stopped: Mutex<Option<String>>,
    interactive: bool,
    streams: Arc<Semaphore>,
}

/// An answer that is not the one the client asked for: status and a line of plain text.
struct Refusal {
    status: StatusCode,
    message: String,
}

fn refuse(status: StatusCode, message: impl Into<String>) -> Refusal {
    Refusal {
        status,
        message: message.into(),
    }
}

impl From<BadRequest> for Refusal {
    fn from(e: BadRequest) -> Self {
        refuse(StatusCode::BAD_REQUEST, e.0)
    }
}

impl From<IndexError> for Refusal {
    fn from(e: IndexError) -> Self {
        refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cannot read the local index: {e}"),
        )
    }
}

type Outcome<T> = Result<T, Refusal>;

// ---------------------------------------------------------------------------------------------
// Listing rows (the JSON shapes and the order of a listing are in `rules`)
// ---------------------------------------------------------------------------------------------

impl RowView for ListRow {
    fn name(&self) -> &str {
        &self.name
    }
    fn tie(&self) -> &str {
        &self.name
    }
    fn is_dir(&self) -> bool {
        self.is_dir
    }
    fn head(&self) -> Option<&Head> {
        self.head.as_ref()
    }
}

impl RowView for SearchHit {
    fn name(&self) -> &str {
        crate::path::file_name(&self.path)
    }
    fn tie(&self) -> &str {
        &self.path
    }
    fn is_dir(&self) -> bool {
        self.is_dir
    }
    fn head(&self) -> Option<&Head> {
        self.head.as_ref()
    }
}

/// `sort` and `order` of a listing or a search.
fn sort_params(query: &[(String, String)]) -> Outcome<SortOrder> {
    SortOrder::parse(http::param(query, "sort"), http::param(query, "order"))
        .map_err(|what| refuse(StatusCode::BAD_REQUEST, what))
}

// ---------------------------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------------------------

fn respond(
    status: StatusCode,
    content_type: &'static str,
    body: impl Into<Bytes>,
) -> Response<Body> {
    let body: Bytes = body.into();
    let mut res = Response::new(Body::full(body.clone()));
    *res.status_mut() = status;
    let headers = res.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    res
}

fn text(status: StatusCode, message: &str) -> Response<Body> {
    respond(status, "text/plain; charset=utf-8", format!("{message}\n"))
}

fn json(value: &impl Serialize) -> Response<Body> {
    match serde_json::to_vec(value) {
        Ok(bytes) => respond(StatusCode::OK, "application/json", bytes),
        Err(_) => text(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot encode the answer",
        ),
    }
}

fn set(res: &mut Response<Body>, name: header::HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        res.headers_mut().insert(name, value);
    }
}

/// A header of the file routes whose absence changes nothing for the worse (`Range`,
/// `If-Range`, `If-None-Match`): one that cannot be read counts as absent.
fn header_str(req: &Request<Incoming>, name: header::HeaderName) -> Option<&str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

/// A header the checks rest on (`Origin`, `Sec-Fetch-*`): absent, or there exactly once and
/// readable. Anything else — sent twice, bytes outside ASCII — is refused, as for `Host`: a
/// value this server cannot read must not count as "no such header".
fn one_header<'a>(req: &'a Request<Incoming>, name: &'static str) -> Outcome<Option<&'a str>> {
    let mut values = req.headers().get_all(name).iter();
    match (values.next().map(|v| v.to_str()), values.next()) {
        (None, _) => Ok(None),
        (Some(Ok(value)), None) => Ok(Some(value)),
        _ => Err(cross_site()),
    }
}

fn cross_site() -> Refusal {
    refuse(StatusCode::FORBIDDEN, "Cross-site requests are refused.")
}

/// The bytes of a request head as it was sent, near enough: the request line and every header
/// line with their separators.
fn head_bytes(req: &Request<Incoming>) -> usize {
    let uri = req.uri();
    let target = uri.path().len()
        + uri.query().map_or(0, |q| q.len() + 1)
        + uri
            .authority()
            .map_or(0, |a| a.as_str().len() + "http://".len());
    let headers: usize = req
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + 4)
        .sum();
    req.method().as_str().len() + target + " HTTP/1.1\r\n".len() + 1 + headers + 2
}

/// The page that takes a browser to `link` — what gclone hands to the browser launcher in
/// place of the link, so that the link's key is in no argument list (a 0600 file in gclone's
/// 0700 state directory). `link` is made by `App::login_url`: nothing in it needs escaping.
pub fn launch_page(link: &str) -> String {
    format!(
        "<!doctype html><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\">\
         <meta http-equiv=\"refresh\" content=\"0;url={link}\"><title>gclone</title>\
         <a href=\"{link}\">Open the vault</a>\n"
    )
}

// ---------------------------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------------------------

/// What `bind` does when `[::1]:port` is already taken by someone else.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum V6 {
    /// Serve on `127.0.0.1` alone (`gclone web`: a browser volunteers no secret).
    IfFree,
    /// Fail with `AddrInUse` (`gclone serve restic`: its client sends a token unasked, and
    /// `localhost` may resolve to `::1` first). A machine without an IPv6 loopback — any other
    /// bind error — still serves on `127.0.0.1` alone.
    Required,
}

/// Listens on `127.0.0.1:port` (`0`: a free port) and, when that address is free as well, on
/// `[::1]` with the same port. Never on anything but loopback.
pub async fn bind(port: u16) -> std::io::Result<(Vec<TcpListener>, u16)> {
    bind_v6(port, V6::IfFree).await
}

/// [`bind`], with the choice of what a taken `[::1]:port` means.
pub async fn bind_v6(port: u16, v6: V6) -> std::io::Result<(Vec<TcpListener>, u16)> {
    let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    let port = v4.local_addr()?.port();
    let mut listeners = vec![v4];
    match TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
        Ok(v6) => listeners.push(v6),
        Err(e) if v6 == V6::Required && e.kind() == std::io::ErrorKind::AddrInUse => {
            let text = format!("port {port} is in use on [::1]");
            return Err(std::io::Error::new(e.kind(), text));
        }
        Err(e) => tracing::debug!("web: not listening on [::1]:{port}: {e}"),
    }
    Ok((listeners, port))
}

/// Whether a request names this server: exactly one `Host` header, readable, one of `hosts`
/// (ASCII case-insensitive) — and the same for the authority of an absolute-form request
/// target. A page of another site that points its own host name at 127.0.0.1 (DNS rebinding)
/// still sends that name.
pub fn host_allowed(headers: &header::HeaderMap, uri: &hyper::Uri, hosts: &[String]) -> bool {
    let host_ok = |host: &str| hosts.iter().any(|h| h.eq_ignore_ascii_case(host));
    let mut named = headers.get_all(header::HOST).iter();
    let named = match (named.next().map(|h| h.to_str()), named.next()) {
        (Some(Ok(host)), None) => host_ok(host),
        _ => false,
    };
    named && uri.authority().is_none_or(|a| host_ok(a.as_str()))
}

/// Serves `handler` on `listeners` — at most `connections` connections at a time, HTTP/1.1,
/// loopback peers only — until `cancel` fires. Connections still open then are dropped.
/// Shared by `gclone web` and the listener of `gclone serve restic`.
pub async fn serve<H, F>(
    listeners: Vec<TcpListener>,
    handler: H,
    connections: usize,
    cancel: CancellationToken,
) where
    H: Fn(Request<Incoming>) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Response<Body>> + Send + 'static,
{
    let connections = Arc::new(Semaphore::new(connections));
    for listener in listeners {
        tokio::spawn(accept(
            listener,
            handler.clone(),
            connections.clone(),
            cancel.clone(),
        ));
    }
    cancel.cancelled().await;
}

async fn accept<H, F>(
    listener: TcpListener,
    handler: H,
    connections: Arc<Semaphore>,
    cancel: CancellationToken,
) where
    H: Fn(Request<Incoming>) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Response<Body>> + Send + 'static,
{
    loop {
        let accepted = async {
            let permit = connections.clone().acquire_owned().await.ok()?;
            Some((listener.accept().await, permit))
        };
        let (accepted, permit) = tokio::select! {
            () = cancel.cancelled() => return,
            next = accepted => match next {
                Some(next) => next,
                None => return,
            },
        };
        let stream = match accepted {
            // The listener is bound to loopback; a peer from elsewhere cannot exist.
            Ok((stream, peer)) if peer.ip().is_loopback() => stream,
            Ok(_) => continue,
            Err(e) => {
                tracing::debug!("web: accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let (handler, cancel) = (handler.clone(), cancel.clone());
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                let answer = handler(req);
                async move { Ok::<_, std::convert::Infallible>(answer.await) }
            });
            let mut http = hyper::server::conn::http1::Builder::new();
            http.timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .max_buf_size(HEADER_BYTES_MAX);
            let connection = http.serve_connection(hyper_util::rt::TokioIo::new(stream), service);
            tokio::select! {
                () = cancel.cancelled() => {}
                // A client that went away mid-answer ends here; that is not worth a line.
                ended = connection => if let Err(e) = ended {
                    tracing::trace!("web: connection ended: {e}");
                },
            }
            drop(permit);
        });
    }
}

impl App {
    pub fn new(o: Options) -> Arc<App> {
        let port = o.port;
        let hosts: Vec<String> = ["127.0.0.1", "localhost", "[::1]"]
            .iter()
            .map(|host| format!("{host}:{port}"))
            .collect();
        Arc::new(App {
            vault: Arc::new(o.vault),
            ledger: o.ledger,
            refresher: o.refresher,
            refreshed: Mutex::new(o.refreshed),
            refreshing: tokio::sync::Mutex::new(()),
            vault_name: o.vault_name,
            backend: o.backend,
            device: o.device,
            port,
            origins: hosts.iter().map(|h| format!("http://{h}")).collect(),
            hosts,
            // Cookies are not separated by port: the name keeps two viewers apart, the
            // cookie's path (`Session::prefix`) keeps it from other servers.
            cookie_name: format!("gclone_web_{port}"),
            access: Mutex::new(Access {
                session: Session::new(),
                key: None,
                used: VecDeque::new(),
                launch: None,
            }),
            ids: FileIds::new(),
            alive: o.alive,
            stopped: Mutex::new(None),
            interactive: o.interactive,
            streams: Arc::new(Semaphore::new(STREAMS_MAX)),
        })
    }

    fn access(&self) -> std::sync::MutexGuard<'_, Access> {
        self.access.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A new one-time link (192 random bits) **and a new session**: every link and every
    /// cookie handed out before stop working, and the file streams of the old session end.
    /// So a new link is also the way to shut out whoever used the last one. The link is shown
    /// to the user and to nothing else: it is not logged.
    pub fn login_url(&self) -> String {
        let key = util::b64url(&util::random::<24>());
        let url = format!("http://127.0.0.1:{}/?k={key}", self.port);
        let (old, launch) = {
            let mut access = self.access();
            access.key = Some(key);
            let old = std::mem::replace(&mut access.session, Session::new());
            (old, access.launch.take())
        };
        old.ended.cancel();
        remove_launch(launch);
        url
    }

    /// `file` holds the current link (`launch_page`): it is removed as soon as the link is
    /// used or replaced, and by `close`.
    pub fn delete_when_used(&self, file: PathBuf) {
        let stale = {
            let mut access = self.access();
            match access.key {
                Some(_) => access.launch.replace(file),
                // Used before this call: nothing to wait for.
                None => Some(file),
            }
        };
        remove_launch(stale);
    }

    /// The end of the viewer: no link, no session, no stream, no launch page.
    pub fn close(&self) {
        let (session, launch) = {
            let mut access = self.access();
            access.key = None;
            (access.session.clone(), access.launch.take())
        };
        session.ended.cancel();
        remove_launch(launch);
    }

    /// Uses up the link's key if `candidate` is it.
    fn redeem(&self, candidate: &str) -> Redeemed {
        let same = |key: &String| util::ct_eq(key.as_bytes(), candidate.as_bytes());
        let (session, launch) = {
            let mut access = self.access();
            if !access.key.as_ref().is_some_and(same) {
                return match access.used.iter().any(same) {
                    true => Redeemed::Used,
                    false => Redeemed::Unknown,
                };
            }
            if let Some(key) = access.key.take() {
                if access.used.len() == USED_KEYS_KEPT {
                    access.used.pop_front();
                }
                access.used.push_back(key);
            }
            (access.session.clone(), access.launch.take())
        };
        remove_launch(launch);
        Redeemed::Granted(session)
    }

    /// The session, if the request carries its cookie. Cookies are compared as bytes: a
    /// browser sends the cookies of every port of the loopback host in one header, and any of
    /// them may hold bytes that are not ASCII.
    fn session_of(&self, req: &Request<Incoming>) -> Option<Arc<Session>> {
        let session = self.access().session.clone();
        let (name, secret) = (self.cookie_name.as_bytes(), session.secret.as_bytes());
        let found = req
            .headers()
            .get_all(header::COOKIE)
            .iter()
            .flat_map(|v| v.as_bytes().split(|b| *b == b';'))
            .filter_map(|pair| {
                let at = pair.iter().position(|b| *b == b'=')?;
                Some((pair[..at].trim_ascii(), pair[at + 1..].trim_ascii()))
            })
            .any(|(n, v)| n == name && util::ct_eq(v, secret));
        found.then_some(session)
    }

    fn refreshed(&self) -> RefreshState {
        self.refreshed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// `Err(text)` once this device was signed out or lost its state (`Alive`): from then on
    /// nothing is served, and what was being sent stops. The command ends the process.
    pub fn check_alive(&self) -> Result<(), String> {
        let text = {
            let mut stopped = self.stopped.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(text) = &*stopped {
                return Err(text.clone());
            }
            match (self.alive)() {
                Ok(()) => return Ok(()),
                Err(text) => stopped.insert(text).clone(),
            }
        };
        self.close();
        Err(text)
    }

    /// How the user gets a new link.
    fn new_link(&self) -> &'static str {
        match self.interactive {
            true => "press Enter in the terminal where `gclone web` runs",
            false => "stop `gclone web` (Ctrl-C) and start it again",
        }
    }

    fn use_the_link(&self) -> Refusal {
        refuse(
            StatusCode::FORBIDDEN,
            format!(
                "gclone web: open the link that `gclone web` printed in the terminal (for a new \
                 one, {}).",
                self.new_link()
            ),
        )
    }

    /// One request → one response, with the headers every response carries.
    pub async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Response<Body> {
        // Never the query: it carries paths, and the key of the link.
        tracing::debug!("web: {} {}", req.method(), logged_path(req.uri().path()));
        let answer = match head_bytes(&req) > HEADER_BYTES_MAX {
            true => Err(refuse(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "The request's header is too large.",
            )),
            false => self.answer(&req).await,
        };
        let mut res = match answer {
            Ok(res) => res,
            Err(refusal) => text(refusal.status, &refusal.message),
        };
        if req.method() == Method::HEAD {
            *res.body_mut() = Body::empty();
        }
        let headers = res.headers_mut();
        for (name, value) in [
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
            (
                header::HeaderName::from_static("cross-origin-resource-policy"),
                "same-origin",
            ),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        if !headers.contains_key(header::CONTENT_SECURITY_POLICY) {
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(BARE_CSP),
            );
        }
        res
    }

    async fn answer(self: &Arc<Self>, req: &Request<Incoming>) -> Outcome<Response<Body>> {
        // 1. Host: only the names this server listens under (`host_allowed`).
        if !host_allowed(req.headers(), req.uri(), &self.hosts) {
            return Err(refuse(
                StatusCode::FORBIDDEN,
                format!(
                    "gclone web answers only as http://127.0.0.1:{}/ (through an ssh tunnel: use \
                     the same port on both ends).",
                    self.port
                ),
            ));
        }

        // 2. Same origin. `Origin`, when a browser sends it, must be this server; so must the
        //    initiator according to `Sec-Fetch-Site` (`none`: typed, bookmarked, opened by
        //    another program).
        let origin = one_header(req, "origin")?;
        let site = one_header(req, "sec-fetch-site")?;
        let foreign_origin = origin.is_some_and(|o| !self.origins.iter().any(|own| own == o));
        let foreign_site = site.is_some_and(|site| !matches!(site, "same-origin" | "none"));

        // 3. A device that was signed out serves nothing, to anyone.
        if let Err(stopped) = self.check_alive() {
            return Err(refuse(StatusCode::FORBIDDEN, stopped));
        }

        // 4. The session: the cookie, or — on `/` only — the one-time key that is exchanged
        //    for it.
        let path = req.uri().path();
        let query = http::parse_query(req.uri().query());
        let key = match (req.method(), path, &query) {
            (&Method::GET, "/", Ok(query)) => http::param(query, "k"),
            _ => None,
        };
        if let Some(key) = key {
            // A link is followed by a navigation — from the terminal, the address bar, the
            // page gclone hands to the browser launcher, a terminal in a browser tab — never
            // fetched by a page.
            let navigation = origin.is_none()
                && one_header(req, "sec-fetch-mode")? == Some("navigate")
                && one_header(req, "sec-fetch-dest")? == Some("document");
            if foreign_origin || (foreign_site && !navigation) {
                return Err(cross_site());
            }
            return match self.redeem(key) {
                // A redirect only where the browser says that no other site began this
                // navigation: `SameSite=Strict` keeps the new cookie out of a navigation
                // another site began, its redirects included.
                Redeemed::Granted(session) => {
                    Ok(self.enter(&session, matches!(site, Some("same-origin" | "none"))))
                }
                Redeemed::Used => Err(refuse(
                    StatusCode::FORBIDDEN,
                    format!(
                        "This link has been used already: each link from `gclone web` works \
                         once. If it was not you who opened it, another program on this \
                         machine did — {}: that ends every session and gives you a new link.",
                        self.new_link()
                    ),
                )),
                Redeemed::Unknown => Err(refuse(
                    StatusCode::FORBIDDEN,
                    format!(
                        "This is not a valid link of the running `gclone web` (a newer link \
                         replaces the ones before it). For a new one, {}.",
                        self.new_link()
                    ),
                )),
            };
        }
        if foreign_origin || foreign_site {
            return Err(cross_site());
        }
        // Everything else lives under the session's prefix, and needs its cookie.
        let Some(session) = self.session_of(req) else {
            return Err(self.use_the_link());
        };
        let Some(route) = path.strip_prefix(session.prefix.as_str()) else {
            return Err(self.use_the_link());
        };
        let query = query?;

        // 5. The route.
        let read = matches!(*req.method(), Method::GET | Method::HEAD);
        let allow = |methods: &'static str| {
            let mut res = text(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed.");
            set(&mut res, header::ALLOW, methods);
            res
        };
        let asset = |content_type: &'static str, body: &'static str| {
            let mut res = respond(StatusCode::OK, content_type, body);
            set(&mut res, header::CONTENT_SECURITY_POLICY, PAGE_CSP);
            res
        };
        Ok(match route {
            "api/refresh" if *req.method() == Method::POST => self.refresh().await?,
            "api/refresh" => allow("POST"),
            "" | "assets/app.css" | "assets/app.js" | "assets/icon.svg" | "api/info"
            | "api/list" | "api/stat" | "api/search" | "file"
                if !read =>
            {
                allow("GET, HEAD")
            }
            "" => asset("text/html; charset=utf-8", INDEX_HTML),
            "assets/app.css" => asset("text/css; charset=utf-8", APP_CSS),
            "assets/app.js" => asset("text/javascript; charset=utf-8", APP_JS),
            "assets/icon.svg" => asset("image/svg+xml", ICON_SVG),
            "api/info" => self.info().await?,
            "api/list" => self.list(&query).await?,
            "api/stat" => self.stat(&query).await?,
            "api/search" => self.search(&query).await?,
            "file" => self.file(req, &query, &session).await?,
            _ => return Err(refuse(StatusCode::NOT_FOUND, "Not found.")),
        })
    }

    /// The answer to a link: the cookie, scoped to the session's prefix, and the way to the
    /// page there — a redirect, or a page that goes there by itself.
    fn enter(&self, session: &Session, redirect: bool) -> Response<Body> {
        let to = session.prefix.as_str();
        let mut res = if redirect {
            let mut res = text(StatusCode::SEE_OTHER, "See the page.");
            set(&mut res, header::LOCATION, to);
            res
        } else {
            respond(
                StatusCode::OK,
                "text/html; charset=utf-8",
                format!(
                    "<!doctype html><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" \
                     content=\"0;url={to}\"><title>gclone</title><a href=\"{to}\">Open the \
                     vault</a>\n"
                ),
            )
        };
        let cookie = format!(
            "{}={}; Path={to}; HttpOnly; SameSite=Strict",
            self.cookie_name, session.secret
        );
        set(&mut res, header::SET_COOKIE, &cookie);
        res
    }

    /// A query against the replica, off the async threads.
    async fn query<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Vault<AnyBackend>) -> Result<T, IndexError> + Send + 'static,
    ) -> Outcome<T> {
        let vault = self.vault.clone();
        match tokio::task::spawn_blocking(move || f(&vault)).await {
            Ok(out) => Ok(out?),
            Err(_) => Err(refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the query was interrupted",
            )),
        }
    }

    async fn info(&self) -> Outcome<Response<Body>> {
        let now = self.vault.backend().now_ms();
        let (stats, name) = self
            .query(move |v| Ok((v.stats(now)?, v.vault_name())))
            .await?;
        Ok(json(&InfoJson {
            vault: match name.is_empty() {
                true => self.vault_name.clone(),
                false => name,
            },
            backend: self.backend,
            device: self.device.clone(),
            version: env!("CARGO_PKG_VERSION"),
            read_only: true,
            files: stats.files,
            bytes: stats.bytes,
            last_change_ms: stats.last_change_ms,
            last_change_by: stats.last_change_by,
            refresh: self.refreshed(),
            head: None,
        }))
    }

    async fn refresh(&self) -> Outcome<Response<Body>> {
        {
            let _one = self.refreshing.lock().await;
            let state = (self.refresher)().await;
            *self.refreshed.lock().unwrap_or_else(|e| e.into_inner()) = state;
        }
        self.info().await
    }

    async fn list(&self, query: &[(String, String)]) -> Outcome<Response<Body>> {
        let path = dir_param(query)?;
        let by = sort_params(query)?;
        let offset = number(query, "offset", 0, usize::MAX)?;
        let limit = number(query, "limit", LIST_PAGE, LIST_PAGE_MAX)?;
        if limit == 0 {
            return Err(refuse(StatusCode::BAD_REQUEST, rules::LIMIT_IS_ZERO));
        }
        let dir = path.clone();
        let rows = self
            .query(move |v| {
                Ok(match v.exists_dir(&dir)? {
                    true => Some(v.list(&dir)?),
                    false => None,
                })
            })
            .await?;
        let Some(rows) = rows else {
            return Err(refuse(StatusCode::NOT_FOUND, rules::no_folder(&path)));
        };
        Ok(json(&rules::list_json(path, rows, by, offset, limit)))
    }

    async fn stat(&self, query: &[(String, String)]) -> Outcome<Response<Body>> {
        let path = file_param(query)?;
        let target = path.clone();
        let found = self
            .query(move |v| Ok((v.head(&target)?, v.exists_dir(&target)?)))
            .await?;
        let name = crate::path::file_name(&path);
        let entry = match found {
            (_, true) => EntryJson::new(name, Some(path.clone()), true, None),
            (Some(head), false) => EntryJson {
                id: self.ids.seal(&path),
                ..EntryJson::new(name, Some(path.clone()), false, Some(&head))
            },
            (None, false) => return Err(not_in_vault(&path)),
        };
        Ok(json(&entry))
    }

    async fn search(&self, query: &[(String, String)]) -> Outcome<Response<Body>> {
        let q = http::param(query, "q")
            .ok_or_else(|| refuse(StatusCode::BAD_REQUEST, "q is missing"))?
            .trim()
            .to_owned();
        let limit = number(query, "limit", SEARCH_HITS, SEARCH_HITS_MAX)?;
        let by = sort_params(query)?;
        let needle = q.clone();
        let (hits, more) = self.query(move |v| v.search(&needle, limit)).await?;
        Ok(json(&rules::search_json(q, hits, more, by)))
    }

    /// `GET|HEAD file?path=…|id=…[&dl=1]`: the bytes of one file, decrypted as they are sent.
    /// `id` is the path as `/api/stat` sealed it (`FileIds`): what the page uses, so that no
    /// file name is in an address the browser keeps.
    async fn file(
        self: &Arc<Self>,
        req: &Request<Incoming>,
        query: &[(String, String)],
        session: &Arc<Session>,
    ) -> Outcome<Response<Body>> {
        let bad = |what: &'static str| refuse(StatusCode::BAD_REQUEST, what);
        let path = match http::param(query, "id") {
            None => file_param(query)?,
            Some(_) if http::param(query, "path").is_some() => {
                return Err(bad("path or id, not both"));
            }
            Some(id) => match self.ids.open(id) {
                Some(path) if crate::path::validate(&path).is_ok() => path,
                _ => return Err(bad("id is not one this viewer gave out")),
            },
        };
        let download = match http::param(query, "dl") {
            None => false,
            Some("1") => true,
            Some(_) => return Err(refuse(StatusCode::BAD_REQUEST, "dl is 1 or absent")),
        };
        let target = path.clone();
        let (head, blob) = self
            .query(move |v| {
                let head = v.head(&target)?;
                let loc = head.as_ref().and_then(|h| h.entry.loc.as_ref());
                let blob = match loc {
                    Some(loc) => v.blob(&loc.blob)?,
                    None => None,
                };
                Ok((head, blob))
            })
            .await?;
        let head = match head {
            Some(head) if head.entry.kind == EntryKind::File => head,
            _ => return Err(not_in_vault(&path)),
        };

        let name = crate::path::file_name(&path);
        let served = mime::of_name(name);
        let size = head.entry.size;
        let tag = http::etag(&head.entry.hash);
        let describe = |res: &mut Response<Body>| {
            set(res, header::ETAG, &tag);
            set(res, header::ACCEPT_RANGES, "bytes");
            set(res, header::CONTENT_TYPE, served.mime);
            set(res, header::CONTENT_SECURITY_POLICY, served.csp());
            let inline = served.inline() && !download;
            let disposition = http::content_disposition(inline, name);
            set(res, header::CONTENT_DISPOSITION, &disposition);
        };

        if header_str(req, header::IF_NONE_MATCH).is_some_and(|h| http::none_match(h, &tag)) {
            let mut res = Response::new(Body::empty());
            *res.status_mut() = StatusCode::NOT_MODIFIED;
            set(&mut res, header::ETAG, &tag);
            return Ok(res);
        }
        // `Range` belongs to GET alone (RFC 9110 §14.2: ignored with any other method), so
        // HEAD describes the whole file. `If-Range` with another version's tag: the range was
        // meant for that version.
        let range = match header_str(req, header::IF_RANGE) {
            _ if req.method() != Method::GET => None,
            Some(version) if version != tag => None,
            _ => header_str(req, header::RANGE),
        };
        let (status, range) = match http::parse_range(range, size) {
            ByteRange::Whole => (StatusCode::OK, 0..size),
            ByteRange::Part(range) => (StatusCode::PARTIAL_CONTENT, range),
            ByteRange::Unsatisfiable => {
                let mut res = text(
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    "The range is outside the file.",
                );
                set(&mut res, header::CONTENT_RANGE, &format!("bytes */{size}"));
                set(&mut res, header::ACCEPT_RANGES, "bytes");
                return Ok(res);
            }
        };
        let length = range.end - range.start;
        let mut res = Response::new(Body::empty());
        *res.status_mut() = status;
        describe(&mut res);
        res.headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
        if status == StatusCode::PARTIAL_CONTENT {
            let content_range = format!("bytes {}-{}/{size}", range.start, range.end - 1);
            set(&mut res, header::CONTENT_RANGE, &content_range);
        }
        if req.method() == Method::HEAD || length == 0 {
            return Ok(res);
        }

        let Some(blob) = blob else {
            return Err(unreadable(&TransferError::BlobMissing(
                head.entry
                    .loc
                    .as_ref()
                    .map_or_else(String::new, |l| l.blob.hex()),
            )));
        };
        let permit = tokio::time::timeout(STREAM_WAIT, self.streams.clone().acquire_owned()).await;
        let Ok(Ok(permit)) = permit else {
            let mut res = text(
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many files are being read at once. Try again in a moment.",
            );
            set(&mut res, header::RETRY_AFTER, "2");
            return Ok(res);
        };
        let (tx, mut rx) = mpsc::channel(FRAMES_QUEUED);
        let (app, session) = (self.clone(), session.clone());
        tokio::spawn(async move {
            app.pump(head, blob, range, tx, &session).await;
            drop(permit);
        });
        // Nothing is promised before the first bytes are verified: a blob that is missing or
        // damaged from the start is an error answer, not a broken one.
        match rx.recv().await {
            Some(Ok(first)) => {
                *res.body_mut() = Body::Stream {
                    first: Some(first),
                    rx,
                    left: length,
                };
                Ok(res)
            }
            Some(Err(failure)) => Err(refuse(failure.status, failure.message)),
            None => Err(refuse(
                StatusCode::BAD_GATEWAY,
                "The file could not be read from the vault.",
            )),
        }
    }

    /// Downloads and decrypts `range` of one file into `tx` (`transfer::read_range`, the
    /// reader of `gclone cat`: every chunk is authenticated before a byte of it is passed on).
    /// Ends when the range is done, on the first failure, when the receiver is gone or when
    /// the session ended — dropping the store's stream with it.
    async fn pump(
        &self,
        head: Head,
        blob: BlobRec,
        range: std::ops::Range<u64>,
        tx: mpsc::Sender<Result<Bytes, Failure>>,
        session: &Session,
    ) {
        let mut out = FrameWriter {
            tx: PollSender::new(tx.clone()),
            written: 0,
        };
        let backend = &**self.vault.backend();
        let read =
            crate::transfer::read_range(backend, self.vault.keys(), &blob, &head, range, &mut out);
        let result = tokio::select! {
            result = read => result,
            () = tx.closed() => Err(TransferError::Cancelled),
            () = session.ended.cancelled() => Err(TransferError::Cancelled),
        };
        let written = out.written;
        match result {
            Ok(_) | Err(TransferError::Cancelled) => {}
            Err(TransferError::Io(e)) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => {
                tracing::debug!("web: reading a file failed: {e}");
                let _ = tx.send(Err(unreadable_failure(&e))).await;
            }
        }
        // As `cat` does: what was downloaded counts against the day's allowance (`about`).
        if let Some(ledger) = self.ledger.clone().filter(|_| written > 0) {
            let added = tokio::task::spawn_blocking(move || {
                ledger.ledger_add(util::now_ms(), LedgerDir::Down, written)
            });
            if let Ok(Err(e)) = added.await {
                tracing::debug!("web: download ledger not updated: {e}");
            }
        }
    }
}

/// The store did not deliver a file that the index has: missing or damaged data, an
/// unreachable store, a login that ended. The text is the one the command line would print.
fn unreadable_failure(e: &TransferError) -> Failure {
    let reason = crate::cli::describe(&anyhow::Error::new(crate::transfer::replicate(e)));
    Failure {
        status: StatusCode::BAD_GATEWAY,
        message: format!("The file could not be read from the vault: {reason}"),
    }
}

fn unreadable(e: &TransferError) -> Refusal {
    let failure = unreadable_failure(e);
    refuse(failure.status, failure.message)
}

/// The path of a request for the log: without the session's prefix.
fn logged_path(path: &str) -> &str {
    match path.strip_prefix("/s-").and_then(|rest| rest.find('/')) {
        Some(at) => &path["/s-".len() + at..],
        None => path,
    }
}

fn remove_launch(file: Option<PathBuf>) {
    if let Some(file) = file
        && let Err(e) = std::fs::remove_file(&file)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::debug!("web: the launch page was not removed: {e}");
    }
}

fn not_in_vault(path: &str) -> Refusal {
    refuse(StatusCode::NOT_FOUND, rules::no_file(path))
}

/// `path` of a listing: absent or empty for the vault root, else a valid remote path (§5.1).
/// The path is only ever looked up in the index; it never reaches the file system.
fn dir_param(query: &[(String, String)]) -> Outcome<String> {
    rules::dir_path(http::param(query, "path"))
        .map_err(|what| refuse(StatusCode::BAD_REQUEST, what))
}

/// `path` of one entry: required, a valid remote path.
fn file_param(query: &[(String, String)]) -> Outcome<String> {
    rules::entry_path(http::param(query, "path"))
        .map_err(|what| refuse(StatusCode::BAD_REQUEST, what))
}

fn number(
    query: &[(String, String)],
    name: &'static str,
    default: usize,
    max: usize,
) -> Outcome<usize> {
    match http::param(query, name) {
        None => Ok(default),
        Some(digits) => match digits.parse::<usize>() {
            Ok(n) if n <= max && digits.bytes().all(|b| b.is_ascii_digit()) => Ok(n),
            _ => Err(refuse(
                StatusCode::BAD_REQUEST,
                rules::not_a_number(name, max),
            )),
        },
    }
}

/// `AsyncWrite` into the response body's channel, in frames of at most `FRAME_BYTES`. A full
/// channel is back-pressure on the download; a closed one is a broken pipe.
struct FrameWriter {
    tx: PollSender<Result<Bytes, Failure>>,
    written: u64,
}

impl tokio::io::AsyncWrite for FrameWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let gone = || std::io::Error::from(std::io::ErrorKind::BrokenPipe);
        if std::task::ready!(self.tx.poll_reserve(cx)).is_err() {
            return Poll::Ready(Err(gone()));
        }
        let n = buf.len().min(FRAME_BYTES);
        if self
            .tx
            .send_item(Ok(Bytes::copy_from_slice(&buf[..n])))
            .is_err()
        {
            return Poll::Ready(Err(gone()));
        }
        self.written += n as u64;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_ids_seal_the_path() {
        let ids = FileIds::new();
        for path in [
            "a",
            "docs/a.txt",
            "gr\u{f6}\u{df}e \u{1f389}/line\nbreak.txt",
            &"x".repeat(4096),
        ] {
            let id = ids.seal(path).unwrap();
            assert!(
                id.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "{id}"
            );
            assert_eq!(ids.open(&id).as_deref(), Some(path));
            // One file, one address.
            assert_eq!(ids.seal(path).unwrap(), id);
            // Authenticated: any change is refused, as is another viewer's id.
            let mut bytes = util::unb64url(&id).unwrap();
            for at in [0, 23, 24, bytes.len() - 1] {
                bytes[at] ^= 1;
                assert_eq!(ids.open(&util::b64url(&bytes)), None, "byte {at}");
                bytes[at] ^= 1;
            }
            assert_eq!(ids.open(&id[..id.len() - 2]), None);
            assert_eq!(FileIds::new().open(&id), None);
        }
        // Nothing of the path is readable in the id.
        let id = ids.seal("Geheim/Steuer.txt").unwrap();
        let raw = util::unb64url(&id).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"Geheim" || w == b"Steuer"));
        assert_ne!(ids.seal("a/b").unwrap(), ids.seal("a/c").unwrap());
        for junk in ["", "AAAA", "not base64!", "docs/a.txt"] {
            assert_eq!(ids.open(junk), None, "{junk:?}");
        }
    }

    #[test]
    fn the_log_shows_routes_without_the_session_path() {
        assert_eq!(logged_path("/"), "/");
        assert_eq!(logged_path("/s-abcDEF_-123/"), "/");
        assert_eq!(logged_path("/s-abcDEF_-123/api/list"), "/api/list");
        assert_eq!(logged_path("/s-abc"), "/s-abc");
        assert_eq!(logged_path("/api/info"), "/api/info");
        assert_eq!(logged_path("/favicon.ico"), "/favicon.ico");
    }

    #[test]
    fn the_launch_page_leads_to_the_link_and_says_nothing_else() {
        let link = "http://127.0.0.1:8377/?k=abc_DEF-0123456789";
        let page = launch_page(link);
        assert!(page.contains(&format!(
            r#"<meta http-equiv="refresh" content="0;url={link}">"#
        )));
        assert!(page.contains(r#"<meta name="referrer" content="no-referrer">"#));
        assert!(page.contains(&format!(r#"<a href="{link}">"#)));
        assert!(!page.to_ascii_lowercase().contains("<script"));
        // Sessions differ, and a session's path is 128 random bits.
        let (a, b) = (Session::new(), Session::new());
        assert_ne!(a.prefix, b.prefix);
        assert_ne!(a.secret, b.secret);
        assert_eq!(a.prefix.len(), "/s-".len() + 22 + 1);
        assert_eq!(a.secret.len(), 43);
    }

    /// The page is one document with its own script and style and nothing from elsewhere: it
    /// has to work under `PAGE_CSP`, and no request may leave the machine.
    #[test]
    fn the_page_references_only_its_own_assets() {
        let html = INDEX_HTML;
        let lower = html.to_ascii_lowercase();
        // No inline script, style or event handler.
        assert_eq!(lower.matches("<script").count(), 1);
        assert!(lower.contains(r#"<script src="assets/app.js" defer></script>"#));
        assert!(!lower.contains("<style"));
        assert!(!lower.contains(" style="));
        assert!(!lower.contains("javascript:"));
        for handler in [
            " onclick",
            " onload",
            " onerror",
            " oninput",
            " onsubmit",
            " onkey",
        ] {
            assert!(!lower.contains(handler), "{handler}");
        }
        // Every src / href is a relative path into assets/, the page itself, or a fragment
        // of it.
        let mut references = 0;
        for attribute in ["src=\"", "href=\""] {
            for (at, _) in lower.match_indices(attribute) {
                let rest = &lower[at + attribute.len()..];
                let value = &rest[..rest.find('"').unwrap()];
                assert!(
                    value.starts_with("assets/") || value == "./" || value.starts_with('#'),
                    "{attribute}{value}"
                );
                references += 1;
            }
        }
        assert!(references >= 3, "script, stylesheet and icon");
        for (name, asset) in [
            ("html", html),
            ("css", APP_CSS),
            ("js", APP_JS),
            ("icon", ICON_SVG),
        ] {
            // Nothing is fetched from another host: no absolute or protocol-relative URL. (The
            // SVG namespace is a name, not an address.)
            let stripped = asset.replace("http://www.w3.org/2000/svg", "");
            for foreign in ["http://", "https://", "url(//", "\"//", "'//", "@import"] {
                assert!(!stripped.contains(foreign), "{name} contains {foreign}");
            }
        }
        // The script builds the page from nodes and text: vault names never become markup.
        for sink in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
            "srcdoc",
        ] {
            assert!(!APP_JS.contains(sink), "app.js uses {sink}");
        }
        assert!(!ICON_SVG.to_ascii_lowercase().contains("<script"));
        // No name from the vault reaches the browser's history: the title is fixed, the
        // address is never rewritten (the place is in history.state, pushed without a URL),
        // and files are fetched by id, never by path.
        assert!(lower.contains("<title>gclone</title>"));
        for keeps in [
            "document.title",
            "location.hash",
            "location.href",
            "file?path",
        ] {
            assert!(!APP_JS.contains(keeps), "app.js uses {keeps}");
        }
        let mut states = 0;
        for call in ["history.pushState(", "history.replaceState("] {
            for (at, _) in APP_JS.match_indices(call) {
                let statement = &APP_JS[at..at + APP_JS[at..].find(";\n").unwrap()];
                assert!(statement.ends_with(", '')"), "{statement}");
                states += 1;
            }
        }
        assert_eq!(states, 2, "one push, one replace");
        // The preview is a modal dialog: what is behind it is inert while it is open.
        assert!(lower.contains(r#"role="dialog" aria-modal="true""#));
        assert!(APP_JS.contains("node.inert = inert"));
        // The policy the page is served with.
        for directive in [
            "default-src 'none'",
            "script-src 'self'",
            "style-src 'self'",
            "connect-src 'self'",
            "base-uri 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
        ] {
            assert!(PAGE_CSP.contains(directive), "{directive}");
        }
        assert!(!PAGE_CSP.contains("unsafe"));
    }

    /// The `Host` check that `gclone web` and `gclone serve restic` share.
    #[test]
    fn host_allow_list() {
        let hosts: Vec<String> = ["127.0.0.1:8377", "localhost:8377", "[::1]:8377"]
            .iter()
            .map(|h| h.to_string())
            .collect();
        let check = |named: &[&str], uri: &str| {
            let mut headers = header::HeaderMap::new();
            for host in named {
                headers.append(header::HOST, HeaderValue::from_str(host).unwrap());
            }
            host_allowed(&headers, &uri.parse().unwrap(), &hosts)
        };
        for ok in [
            "127.0.0.1:8377",
            "localhost:8377",
            "LOCALHOST:8377",
            "[::1]:8377",
        ] {
            assert!(check(&[ok], "/"), "{ok}");
        }
        for bad in [
            "127.0.0.1",
            "127.0.0.1:8378",
            "localhost",
            "evil.example:8377",
            "127.0.0.1:8377.evil.example",
            "[::1]",
            "",
        ] {
            assert!(!check(&[bad], "/"), "{bad:?}");
        }
        assert!(!check(&[], "/"), "no Host at all");
        assert!(!check(&["127.0.0.1:8377", "127.0.0.1:8377"], "/"), "twice");
        let mut unreadable = header::HeaderMap::new();
        unreadable.insert(header::HOST, HeaderValue::from_bytes(b"\xff").unwrap());
        assert!(!host_allowed(&unreadable, &"/".parse().unwrap(), &hosts));
        // An absolute-form request target has to name this server as well.
        assert!(check(&["127.0.0.1:8377"], "http://localhost:8377/x"));
        assert!(!check(&["127.0.0.1:8377"], "http://evil.example:8377/x"));
        assert!(!check(&["127.0.0.1:8377"], "http://127.0.0.1/x"));
    }

    /// `[::1]:N` in someone else's hands: `gclone web` serves on 127.0.0.1 alone, a server
    /// whose client volunteers a secret does not start.
    #[tokio::test]
    async fn a_taken_ipv6_loopback_port() {
        // Find a port that is free on 127.0.0.1 while this test holds it on [::1].
        let mut held = None;
        for _ in 0..50 {
            let Ok(v6) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await else {
                // No IPv6 loopback on this machine: nothing to tell apart.
                return;
            };
            let port = v6.local_addr().unwrap().port();
            if let Ok(probe) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
                drop(probe);
                held = Some((v6, port));
                break;
            }
        }
        let (_v6, port) = held.expect("a port that is free on 127.0.0.1");
        let failed = bind_v6(port, V6::Required).await.unwrap_err();
        assert_eq!(failed.kind(), std::io::ErrorKind::AddrInUse);
        assert_eq!(
            failed.to_string(),
            format!("port {port} is in use on [::1]")
        );
        let (listeners, bound) = bind_v6(port, V6::IfFree).await.unwrap();
        assert_eq!((listeners.len(), bound), (1, port));
        drop(listeners);
        let (listeners, _) = bind(port).await.unwrap();
        assert_eq!(listeners.len(), 1);
        // Both free: both are bound, in either mode.
        drop((listeners, _v6));
        let (listeners, _) = bind_v6(0, V6::Required).await.unwrap();
        assert!(!listeners.is_empty());
    }
}

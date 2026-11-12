//! The device side of the login (SPEC §2.4, §9.6) — owned by WP3.
//! `LoginGrant` and `AccessGrant` hold secrets: NO `Debug` derive.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::{AuthEndpoints, PASTE_PREFIX, SCOPE_DRIVE_FILE};
use crate::consts::{AUTH_REFRESH_ATTEMPTS, AUTH_RETRY_AFTER_MAX, PROMPT_ATTEMPTS};
use crate::error::AuthError;
use crate::util;

/// Domain separation of the check code (§2.4); the Worker's confirmation page computes the same.
const CHECK_CODE_LABEL: &[u8] = b"gclone-auth/v1/check";
/// First pause between `/refresh` attempts; doubled each time (0.25 s, 0.5 s, 1 s, 2 s).
const REFRESH_BACKOFF: Duration = Duration::from_millis(250);
/// Wait after a `429` that carries no usable `Retry-After`.
const RETRY_AFTER_DEFAULT: Duration = Duration::from_secs(5);
/// Largest answer body read from the Worker or the revoke endpoint.
const ANSWER_MAX: usize = 64 * 1024;
/// A loopback connection that has not sent its request line by then is dropped.
const LOOPBACK_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest request line of a loopback request. The redirect that carries the grant is about
/// 1 KiB; a longer line is answered `414`.
const LOOPBACK_LINE_MAX: usize = 8 * 1024;
/// Header bytes read and thrown away after the request line. Only the request line matters, but
/// a browser sends every cookie it holds for host 127.0.0.1 — whatever the port — with the
/// redirect, which can be hundreds of KiB (local dev servers, notebooks). The size of the
/// headers must never decide whether a sign-in is accepted.
const LOOPBACK_DRAIN_MAX: usize = 4 * 1024 * 1024;
/// How long the rest of the head is waited for once the request line is there.
const LOOPBACK_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

const UNEXPECTED: &str = "unexpected answer from the auth Worker";
const NOT_A_CODE: &str = "that is not a gclone sign-in code";

pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
    pub state: String,
}

impl Pkce {
    pub fn generate() -> Self {
        Pkce::from_verifier(
            &util::b64url(&util::random::<32>()),
            &util::b64url(&util::random::<16>()),
        )
    }

    /// Tests / vectors.
    pub fn from_verifier(verifier: &str, state: &str) -> Self {
        Pkce {
            verifier: verifier.to_string(),
            challenge: util::b64url(&Sha256::digest(verifier.as_bytes())),
            state: state.to_string(),
        }
    }

    /// `"XXXX-XXXX"`, §2.4 (vector: `D2KC-JCJY`).
    pub fn check_code(&self) -> String {
        let digest = Sha256::new()
            .chain_update(CHECK_CODE_LABEL)
            .chain_update(self.challenge.as_bytes())
            .finalize();
        let code = util::crockford_encode(&digest[..5]);
        format!("{}-{}", &code[..4], &code[4..])
    }
}

/// `Some` = browser flow (port + state), `None` = headless. Both flows print
/// `pkce.check_code()` next to the URL: the Worker's `/login` answers a confirmation page in
/// both modes (§2.3).
pub fn login_url(ep: &AuthEndpoints, pkce: &Pkce, loopback_port: Option<u16>) -> String {
    // Challenge and state are base64url text: nothing needs escaping.
    let mut url = format!("{}/login?challenge={}", ep.base, pkce.challenge);
    if let Some(port) = loopback_port {
        url.push_str(&format!("&port={port}&state={}", pkce.state));
    }
    url
}

/// Query string of the loopback request → the grant. `StateMismatch` if `state` differs
/// (constant time); `Denied(e)` for `error=e`.
pub fn parse_loopback(query: &str, expected_state: &str) -> Result<String, AuthError> {
    let (mut state, mut code, mut error) = (None, None, None);
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let slot = match &*name {
            "state" => &mut state,
            "code" => &mut code,
            "error" => &mut error,
            _ => continue,
        };
        slot.get_or_insert(value.into_owned());
    }
    let state = state.unwrap_or_default();
    if !util::ct_eq(state.as_bytes(), expected_state.as_bytes()) {
        return Err(AuthError::StateMismatch);
    }
    if let Some(e) = error {
        // The Worker sends `[a-z_]{1,64}`; anything else is not worth printing.
        let known =
            (1..=64).contains(&e.len()) && e.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
        return Err(AuthError::Denied(if known { e } else { "error".into() }));
    }
    match code {
        Some(grant) if !grant.is_empty() => Ok(grant),
        _ => Err(AuthError::LoginFailed(
            "the sign-in answer carries neither a code nor an error".into(),
        )),
    }
}

/// Strips whitespace, requires `PASTE_PREFIX` → the grant; `LoginFailed` otherwise.
pub fn parse_pasted(input: &str) -> Result<String, AuthError> {
    let text: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    match text.strip_prefix(PASTE_PREFIX) {
        Some(grant) if !grant.is_empty() => Ok(grant.to_string()),
        _ => Err(AuthError::LoginFailed(NOT_A_CODE.into())),
    }
}

#[derive(Clone)]
pub struct LoginGrant {
    pub refresh_token: String,
    pub access_token: String,
    pub expires_at_ms: u64,
    pub scope: String,
    pub email: String,
    /// Seconds; `Some` = time-limited grant, §2.4.
    pub refresh_expires_in: Option<u64>,
}

#[derive(Clone)]
pub struct AccessGrant {
    pub access_token: String,
    pub expires_at_ms: u64,
}

pub struct InteractiveOpts {
    pub no_browser: bool,
    pub timeout: std::time::Duration,
    /// How to show instructions / the URL.
    pub print: Box<dyn Fn(&str) + Send + Sync>,
    /// Open a URL in the browser; false = could not (→ headless flow).
    pub open: Box<dyn Fn(&str) -> bool + Send + Sync>,
    /// Lines typed or piped by the user (headless flow).
    pub paste: Option<tokio::sync::mpsc::Receiver<String>>,
}

/// §2.4, both flows, including the redeem. Returns the grant as received; the CALLER applies
/// the expiring-grant rule (`refresh_expires_in.is_some()`).
pub async fn login_interactive(
    http: &reqwest::Client,
    ep: &AuthEndpoints,
    mut opts: InteractiveOpts,
) -> Result<LoginGrant, AuthError> {
    if !opts.no_browser
        && let Some(grant) = browser_flow(http, ep, &opts).await?
    {
        return Ok(grant);
    }
    headless_flow(http, ep, &mut opts).await
}

// ---------------------------------------------------------------------------------------------
// Browser flow: a loopback listener receives the grant
// ---------------------------------------------------------------------------------------------

/// `Ok(None)` = the browser could not be opened; the caller falls back to the headless flow,
/// which starts over with a fresh verifier.
async fn browser_flow(
    http: &reqwest::Client,
    ep: &AuthEndpoints,
    opts: &InteractiveOpts,
) -> Result<Option<LoginGrant>, AuthError> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let pkce = Pkce::generate();
    let url = login_url(ep, &pkce, Some(port));
    if !(opts.open)(&url) {
        return Ok(None);
    }
    (opts.print)("Your browser should open now. If it does not, open this URL on this computer:");
    (opts.print)(&url);
    (opts.print)(&format!(
        "The page must show the check code {}. Click Continue there only if it does.",
        pkce.check_code()
    ));
    match tokio::time::timeout(opts.timeout, serve_loopback(&listener, http, ep, &pkce)).await {
        Ok(result) => result.map(Some),
        Err(_) => Err(AuthError::Timeout),
    }
}

/// Serves the listener until one request ends the login. Connections are handled side by side:
/// browsers open spare connections that never send a request.
async fn serve_loopback(
    listener: &TcpListener,
    http: &reqwest::Client,
    ep: &AuthEndpoints,
    pkce: &Pkce,
) -> Result<LoginGrant, AuthError> {
    let claimed = AtomicBool::new(false);
    let mut connections = FuturesUnordered::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => connections.push(serve_connection(stream, http, ep, pkce, &claimed)),
                // Out of descriptors and the like: give the system a moment, keep listening.
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            },
            Some(outcome) = connections.next(), if !connections.is_empty() => {
                if let Some(result) = outcome {
                    return result;
                }
            }
        }
    }
}

/// `None` = this request did not end the login (keep listening).
async fn serve_connection(
    mut stream: TcpStream,
    http: &reqwest::Client,
    ep: &AuthEndpoints,
    pkce: &Pkce,
    claimed: &AtomicBool,
) -> Option<Result<LoginGrant, AuthError>> {
    let (line, seen) = tokio::time::timeout(LOOPBACK_READ_TIMEOUT, read_request_line(&mut stream))
        .await
        .ok()??;
    // The headers are not needed, only taken off the socket: closing a connection with unread
    // input makes the system reset it, and the browser would then show an error instead of the
    // page. Whether the whole head arrives in time or not, the request line is acted upon.
    let _ = tokio::time::timeout(LOOPBACK_DRAIN_TIMEOUT, drain_head(&mut stream, seen)).await;
    let Some(line) = line else {
        respond(
            &mut stream,
            "414 URI Too Long",
            "This request is too long to be a gclone sign-in answer.",
        )
        .await;
        return None;
    };
    let mut request_line = line.split(' ');
    let (method, target) = (request_line.next()?, request_line.next()?);
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let carries_answer = url::form_urlencoded::parse(query.as_bytes())
        .any(|(name, _)| name == "code" || name == "error");
    if method != "GET" || path != "/" || !carries_answer {
        // favicon.ico and the like
        respond(&mut stream, "404 Not Found", "Nothing here.").await;
        return None;
    }
    match parse_loopback(query, &pkce.state) {
        Err(AuthError::Denied(reason)) => {
            respond(&mut stream, "200 OK", PAGE_FAILED).await;
            Some(Err(AuthError::Denied(reason)))
        }
        // A stray or forged request must not end the login.
        Err(_) => {
            respond(
                &mut stream,
                "400 Bad Request",
                "This request does not belong to the sign-in that is waiting.",
            )
            .await;
            None
        }
        Ok(grant) => {
            if claimed.swap(true, Ordering::SeqCst) {
                respond(
                    &mut stream,
                    "409 Conflict",
                    "This sign-in was already answered.",
                )
                .await;
                return None;
            }
            // Redeem first: the page must not say "connected" before it is true.
            let result = redeem(http, ep, &grant, &pkce.verifier).await;
            let page = if result.is_ok() {
                PAGE_CONNECTED
            } else {
                PAGE_FAILED
            };
            respond(&mut stream, "200 OK", page).await;
            Some(result)
        }
    }
}

const PAGE_CONNECTED: &str = "gclone is connected. You can close this tab.";
const PAGE_FAILED: &str = "gclone could not sign in — see the terminal.";

/// The request line of a loopback request (without its line end) and the bytes read after it,
/// which begin with that line end. `None`: the peer closed before a whole line arrived, or the
/// line is not text. A line longer than `LOOPBACK_LINE_MAX` comes back as `Some((None, _))`.
/// The headers that follow are deliberately NOT waited for here: nothing in them is used.
async fn read_request_line(stream: &mut TcpStream) -> Option<(Option<String>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(newline) = buf.iter().position(|&b| b == b'\n') {
            let end = if buf[..newline].ends_with(b"\r") {
                newline - 1
            } else {
                newline
            };
            let rest = buf.split_off(end);
            if end > LOOPBACK_LINE_MAX {
                return Some((None, rest));
            }
            return Some((Some(String::from_utf8(buf).ok()?), rest));
        }
        if buf.len() > LOOPBACK_LINE_MAX {
            return Some((None, buf));
        }
    }
}

/// Reads and discards the rest of the request head: up to the empty line, the end of the
/// stream, or `LOOPBACK_DRAIN_MAX` bytes. `seen` is what was already read after the request
/// line.
async fn drain_head(stream: &mut TcpStream, seen: Vec<u8>) {
    const END: &[u8] = b"\r\n\r\n";
    // "\n\n": a client that ends its lines without a carriage return.
    let ended = |bytes: &[u8]| {
        bytes.windows(END.len()).any(|w| w == END) || bytes.windows(2).any(|w| w == b"\n\n")
    };
    // Only the last bytes are kept between reads: enough to find an end split across two.
    let keep = |bytes: &[u8]| bytes[bytes.len().saturating_sub(END.len() - 1)..].to_vec();
    if ended(&seen) {
        return;
    }
    let mut total = seen.len();
    let mut tail = keep(&seen);
    let mut chunk = [0u8; 8192];
    while total < LOOPBACK_DRAIN_MAX {
        let n = match stream.read(&mut chunk).await {
            Ok(n) if n > 0 => n,
            _ => return,
        };
        total += n;
        tail.extend_from_slice(&chunk[..n]);
        if ended(&tail) {
            return;
        }
        tail = keep(&tail);
    }
}

/// A small static page; `text` is a constant (nothing from the request is echoed).
async fn respond(stream: &mut TcpStream, status: &str, text: &str) {
    let body = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>gclone</title>\
         <body style=\"font: 16px system-ui, sans-serif; margin: 3rem\"><p>{text}</p></body></html>\n"
    );
    let answer = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    // The browser may already be gone; the login does not depend on the page arriving.
    let _ = stream.write_all(answer.as_bytes()).await;
    let _ = stream.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Headless flow: the user carries a code from any browser to this terminal
// ---------------------------------------------------------------------------------------------

async fn headless_flow(
    http: &reqwest::Client,
    ep: &AuthEndpoints,
    opts: &mut InteractiveOpts,
) -> Result<LoginGrant, AuthError> {
    let no_terminal = || AuthError::LoginFailed("no terminal to paste the code into".into());
    let Some(paste) = opts.paste.as_mut() else {
        return Err(no_terminal());
    };
    let pkce = Pkce::generate();
    (opts.print)("Open this URL in a browser on any device:");
    (opts.print)(&login_url(ep, &pkce, None));
    (opts.print)(&format!(
        "The page must show the check code {}. Approve access, then paste the code from the \
         final page here:",
        pkce.check_code()
    ));
    let mut attempts = 0;
    loop {
        let Some(line) = paste.recv().await else {
            return Err(if attempts == 0 {
                no_terminal()
            } else {
                AuthError::LoginFailed(NOT_A_CODE.into())
            });
        };
        if line.trim().is_empty() {
            continue;
        }
        match parse_pasted(&line) {
            Ok(grant) => return redeem(http, ep, &grant, &pkce.verifier).await,
            Err(e) => {
                attempts += 1;
                if attempts >= PROMPT_ATTEMPTS {
                    return Err(e);
                }
                (opts.print)(
                    "That is not a gclone sign-in code. Paste the code from the final page:",
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The Worker's JSON routes and the mapping table of §2.4
// ---------------------------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq)]
enum Route {
    Token,
    Refresh,
}

impl Route {
    fn path(self) -> &'static str {
        match self {
            Route::Token => "/token",
            Route::Refresh => "/refresh",
        }
    }
}

struct Answer {
    status: u16,
    retry_after: Option<Duration>,
    /// `None`: the body is not JSON.
    json: Option<serde_json::Value>,
}

enum Outcome {
    Success(serde_json::Value),
    /// `429`: answered before the Worker contacted Google, so one more try is safe.
    RateLimited(Duration),
    /// `502 upstream_error`, other 5xx.
    Transient(String),
    Final(AuthError),
}

/// reqwest's own message stops at "error sending request"; the cause is in the source chain.
pub(crate) fn describe(e: &reqwest::Error) -> String {
    let mut text = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// Text from the Worker ends up in a terminal: one line, no control characters, bounded.
fn clean(message: &str) -> String {
    message
        .chars()
        .filter(|c| !c.is_control())
        .take(300)
        .collect()
}

async fn read_capped(mut response: reqwest::Response) -> Result<Vec<u8>, reqwest::Error> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let room = ANSWER_MAX.saturating_sub(body.len());
        body.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if room <= chunk.len() {
            break;
        }
    }
    Ok(body)
}

async fn post(
    http: &reqwest::Client,
    ep: &AuthEndpoints,
    route: Route,
    body: &serde_json::Value,
) -> Result<Answer, String> {
    let url = format!("{}{}", ep.base, route.path());
    let response = http
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|e| describe(&e.without_url()))?;
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    let bytes = read_capped(response)
        .await
        .map_err(|e| describe(&e.without_url()))?;
    Ok(Answer {
        status,
        retry_after,
        json: serde_json::from_slice(&bytes).ok(),
    })
}

/// The mapping table of §2.4, rows top to bottom.
fn interpret(route: Route, answer: Answer) -> Outcome {
    let unexpected = || Outcome::Final(AuthError::Network(UNEXPECTED.into()));
    let Answer {
        status,
        retry_after,
        json,
    } = answer;
    if status == 200 {
        return match json {
            Some(v) if v.is_object() => Outcome::Success(v),
            _ => unexpected(),
        };
    }
    if status == 429 {
        let wait = retry_after.unwrap_or(RETRY_AFTER_DEFAULT);
        return Outcome::RateLimited(wait.min(AUTH_RETRY_AFTER_MAX));
    }
    let field = |name: &str| {
        json.as_ref()
            .and_then(|v| v.get(name))
            .and_then(|v| v.as_str())
            .unwrap_or("")
    };
    let (code, message) = (field("error"), clean(field("message")));
    let mapped = match (status, code) {
        (400, "invalid_grant") => match route {
            Route::Token => {
                AuthError::LoginFailed("the sign-in code expired or was already used".into())
            }
            Route::Refresh => AuthError::Expired,
        },
        (403, "email_not_allowed") => AuthError::NotAllowed(message),
        (403, "scope_missing") => AuthError::ScopeMissing,
        (403, "scope_not_allowed" | "access_denied") => AuthError::Denied(message),
        (500, "client_invalid" | "server_misconfigured") => AuthError::WorkerMisconfigured(message),
        (500..=599, _) => {
            let code = if code.is_empty() {
                "without detail"
            } else {
                code
            };
            return Outcome::Transient(format!("the auth Worker answered {status} ({code})"));
        }
        _ => return unexpected(),
    };
    Outcome::Final(mapped)
}

fn string_field(v: &serde_json::Value, name: &str) -> Result<String, AuthError> {
    match v.get(name).and_then(|x| x.as_str()) {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        _ => Err(AuthError::Network(UNEXPECTED.into())),
    }
}

fn seconds_field(v: &serde_json::Value, name: &str) -> Option<u64> {
    let x = v.get(name)?;
    x.as_u64()
        .or_else(|| x.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64))
}

fn expires_at_ms(v: &serde_json::Value) -> Result<u64, AuthError> {
    let secs =
        seconds_field(v, "expires_in").ok_or_else(|| AuthError::Network(UNEXPECTED.into()))?;
    Ok(util::now_ms().saturating_add(secs.saturating_mul(1000)))
}

const RATE_LIMITED: &str = "the auth Worker is rate-limiting this address";

/// `POST /token`; no retry, except once after `429 rate_limited` (`Retry-After` ≤ 60 s), §2.4.
pub async fn redeem(
    http: &reqwest::Client,
    ep: &AuthEndpoints,
    grant: &str,
    verifier: &str,
) -> Result<LoginGrant, AuthError> {
    let body = serde_json::json!({ "code": grant, "verifier": verifier });
    let mut waited = false;
    loop {
        // Any failure after the request left may have consumed Google's code: never resend.
        let answer = post(http, ep, Route::Token, &body)
            .await
            .map_err(AuthError::Network)?;
        let v = match interpret(Route::Token, answer) {
            Outcome::Success(v) => v,
            Outcome::RateLimited(wait) if !waited => {
                waited = true;
                tokio::time::sleep(wait).await;
                continue;
            }
            Outcome::RateLimited(_) => return Err(AuthError::Network(RATE_LIMITED.into())),
            Outcome::Transient(detail) => return Err(AuthError::Network(detail)),
            Outcome::Final(e) => return Err(e),
        };
        let grant = LoginGrant {
            refresh_token: string_field(&v, "refresh_token")?,
            access_token: string_field(&v, "access_token")?,
            expires_at_ms: expires_at_ms(&v)?,
            scope: string_field(&v, "scope")?,
            email: string_field(&v, "email")?,
            refresh_expires_in: seconds_field(&v, "refresh_token_expires_in"),
        };
        if !grant.scope.split(' ').any(|s| s == SCOPE_DRIVE_FILE) {
            return Err(AuthError::ScopeMissing);
        }
        return Ok(grant);
    }
}

/// `POST /refresh`, 5 tries on 5xx/network; 429: once more after `Retry-After`.
pub async fn refresh(
    http: &reqwest::Client,
    ep: &AuthEndpoints,
    refresh_token: &str,
) -> Result<AccessGrant, AuthError> {
    let body = serde_json::json!({ "refresh_token": refresh_token });
    let mut waited = false;
    let mut failures = 0u32;
    loop {
        let outcome = match post(http, ep, Route::Refresh, &body).await {
            Ok(answer) => interpret(Route::Refresh, answer),
            Err(detail) => Outcome::Transient(detail),
        };
        match outcome {
            Outcome::Success(v) => {
                return Ok(AccessGrant {
                    access_token: string_field(&v, "access_token")?,
                    expires_at_ms: expires_at_ms(&v)?,
                });
            }
            Outcome::RateLimited(wait) if !waited => {
                waited = true;
                tokio::time::sleep(wait).await;
            }
            Outcome::RateLimited(_) => return Err(AuthError::Network(RATE_LIMITED.into())),
            Outcome::Transient(detail) => {
                failures += 1;
                if failures >= AUTH_REFRESH_ATTEMPTS {
                    return Err(AuthError::Network(detail));
                }
                tokio::time::sleep(REFRESH_BACKOFF * 2u32.pow(failures - 1)).await;
            }
            Outcome::Final(e) => return Err(e),
        }
    }
}

/// `POST ep.revoke_url`, form `token=…`. 200 → `Ok(true)`; 400 → `Ok(false)` (already
/// invalid); anything else → `Network`. Grant-wide at Google (§2.7).
pub async fn revoke(
    http: &reqwest::Client,
    ep: &AuthEndpoints,
    token: &str,
) -> Result<bool, AuthError> {
    let response = http
        .post(&ep.revoke_url)
        .form(&[("token", token)])
        .send()
        .await
        .map_err(|e| AuthError::Network(describe(&e.without_url())))?;
    match response.status().as_u16() {
        200 => Ok(true),
        400 => Ok(false),
        status => Err(AuthError::Network(format!(
            "Google's revoke endpoint answered {status}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, body: &str) -> Answer {
        Answer {
            status,
            retry_after: None,
            json: serde_json::from_str(body).ok(),
        }
    }

    fn final_error(route: Route, status: u16, body: &str) -> AuthError {
        match interpret(route, answer(status, body)) {
            Outcome::Final(e) => e,
            _ => panic!("{status} {body}: expected a final error"),
        }
    }

    #[test]
    fn mapping_table() {
        let err = |code: &str| format!(r#"{{"error":"{code}","message":"m\u0007 text"}}"#);
        for route in [Route::Token, Route::Refresh] {
            let e = final_error(route, 400, &err("invalid_grant"));
            match route {
                Route::Token => assert!(matches!(e, AuthError::LoginFailed(_))),
                Route::Refresh => assert!(matches!(e, AuthError::Expired)),
            }
            let e = final_error(route, 403, &err("email_not_allowed"));
            assert!(matches!(e, AuthError::NotAllowed(m) if m == "m text"));
            let e = final_error(route, 403, &err("scope_missing"));
            assert!(matches!(e, AuthError::ScopeMissing));
            for code in ["access_denied", "scope_not_allowed"] {
                let e = final_error(route, 403, &err(code));
                assert!(matches!(e, AuthError::Denied(m) if m == "m text"), "{code}");
            }
            for code in ["client_invalid", "server_misconfigured"] {
                let e = final_error(route, 500, &err(code));
                assert!(matches!(e, AuthError::WorkerMisconfigured(_)));
            }
            for (status, body) in [
                (502, err("upstream_error")),
                (500, err("internal_error")),
                (503, "<html>down</html>".to_string()),
            ] {
                let outcome = interpret(route, answer(status, &body));
                assert!(matches!(outcome, Outcome::Transient(_)), "{status}");
            }
            for (status, body) in [
                (302, String::new()),
                (200, "<html>".to_string()),
                (200, "[1]".to_string()),
                (400, err("invalid_request")),
                (404, err("not_found")),
                (403, "<html>forbidden</html>".to_string()),
                // a code under another status is not the mapped answer
                (400, err("scope_missing")),
            ] {
                let e = final_error(route, status, &body);
                assert!(
                    matches!(e, AuthError::Network(m) if m == UNEXPECTED),
                    "{status}"
                );
            }
        }
    }

    #[test]
    fn rate_limit_wait_is_capped() {
        let wait = |retry_after| {
            let a = Answer {
                status: 429,
                retry_after,
                json: None,
            };
            match interpret(Route::Token, a) {
                Outcome::RateLimited(d) => d,
                _ => panic!("expected RateLimited"),
            }
        };
        assert_eq!(wait(Some(Duration::from_secs(7))), Duration::from_secs(7));
        assert_eq!(wait(Some(Duration::from_secs(3600))), AUTH_RETRY_AFTER_MAX);
        assert_eq!(wait(None), RETRY_AFTER_DEFAULT);
    }

    #[test]
    fn loopback_query() {
        let ok = parse_loopback("code=g-1&state=abc", "abc").unwrap();
        assert_eq!(ok, "g-1");
        let e = parse_loopback("code=g-1&state=abd", "abc").unwrap_err();
        assert!(matches!(e, AuthError::StateMismatch));
        let e = parse_loopback("code=g-1", "abc").unwrap_err();
        assert!(matches!(e, AuthError::StateMismatch));
        let e = parse_loopback("error=access_denied&state=abc", "abc").unwrap_err();
        assert!(matches!(e, AuthError::Denied(r) if r == "access_denied"));
        let e = parse_loopback("error=%1b%5b2J&state=abc", "abc").unwrap_err();
        assert!(matches!(e, AuthError::Denied(r) if r == "error"));
        // the state is checked before anything else is believed
        let e = parse_loopback("error=access_denied&state=x", "abc").unwrap_err();
        assert!(matches!(e, AuthError::StateMismatch));
        let e = parse_loopback("state=abc&code=", "abc").unwrap_err();
        assert!(matches!(e, AuthError::LoginFailed(_)));
    }

    #[test]
    fn pasted_code() {
        assert_eq!(parse_pasted("gclone-code1_abc").unwrap(), "abc");
        assert_eq!(parse_pasted("  gclone-\n code1_a b\tc\r\n").unwrap(), "abc");
        for bad in [
            "",
            "abc",
            "gclone-code1_",
            "gclone-code2_abc",
            "x gclone-code1_abc",
        ] {
            assert!(
                matches!(parse_pasted(bad), Err(AuthError::LoginFailed(_))),
                "{bad:?}"
            );
        }
    }
}

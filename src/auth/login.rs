//! The device side of the login (SPEC §2.4, §9.6) — owned by WP3: Google's device
//! authorization grant (RFC 8628) through the auth Worker. The device asks the Worker for a
//! code, shows it, and polls until the user has entered it at Google.
//! `DeviceCode`, `LoginGrant` and `AccessGrant` hold secrets: NO `Debug` derive.

use std::time::Duration;

use super::{AuthClient, AuthEndpoints, SCOPE_DRIVE_FILE};
use crate::consts::{
    AUTH_POLL_INTERVAL_DEFAULT, AUTH_POLL_SLOW_DOWN, AUTH_REFRESH_ATTEMPTS, AUTH_RETRY_AFTER_MAX,
    AUTH_TIMEOUT,
};
use crate::error::AuthError;
use crate::util;

/// First pause between attempts at a repeatable route; doubled each time (0.25 s … 2 s).
const RETRY_BACKOFF: Duration = Duration::from_millis(250);
/// Wait after a `429` that carries no usable `Retry-After`.
const RETRY_AFTER_DEFAULT: Duration = Duration::from_secs(5);
/// Largest answer body read from the Worker or the revoke endpoint.
const ANSWER_MAX: usize = 64 * 1024;
/// Longest user code / verification URL that is shown in a terminal.
const USER_CODE_MAX: usize = 64;
const VERIFICATION_URL_MAX: usize = 256;
/// Longest account address that is shown and stored (the length limit of an e-mail address).
const EMAIL_MAX: usize = 254;

const UNEXPECTED: &str = "unexpected answer from the auth Worker";
const RATE_LIMITED: &str = "the auth Worker is rate-limiting this address";

/// The Worker's answer to `/device/start`: what the user is shown and what the device polls with.
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub verification_url: String,
    /// Lifetime of both codes, at most `AUTH_TIMEOUT`.
    pub expires_in: Duration,
    /// Pause between two polls.
    pub interval: Duration,
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
    /// Do not try to open a browser. The URL and the code are printed either way.
    pub no_browser: bool,
    /// How to show the URL, the code and notes.
    pub print: Box<dyn Fn(&str) + Send + Sync>,
    /// Open a URL in the local browser — a convenience whose failure changes nothing.
    pub open: Box<dyn Fn(&str) + Send + Sync>,
}

/// §2.4, the whole sign-in: start, show the code, poll. Returns the grant as received; the
/// CALLER applies the expiring-grant rule (`refresh_expires_in.is_some()`).
pub async fn login_interactive(
    http: &reqwest::Client,
    ep: &AuthEndpoints,
    opts: InteractiveOpts,
) -> Result<LoginGrant, AuthError> {
    let code = device_start(http, ep).await?;
    // The address is the Worker's word. Google's page is the only one the user code belongs
    // on, so anything else is shown with a warning and never opened: whoever controls the
    // Worker or its host name must not get a page of their choice in front of the user.
    let at_google = is_google_page(&code.verification_url);
    (opts.print)(&format!("To sign in, open  {}", code.verification_url));
    (opts.print)(&format!("and enter the code  {}", code.user_code));
    if !at_google {
        (opts.print)(NOT_GOOGLE_NOTE);
    }
    // A code from anywhere else belongs to someone else's sign-in (device-code phishing, §2.3.2).
    (opts.print)("(enter only a code shown in this terminal; waiting…)");
    if !opts.no_browser && at_google {
        (opts.open)(&code.verification_url);
    }
    device_wait(http, ep, &code, &*opts.print).await
}

/// Printed after the two sign-in lines when the address is not one of Google's.
pub const NOT_GOOGLE_NOTE: &str = "(warning: that is not a google.com address, and it was not opened. Google's page for \
     this is https://www.google.com/device; open another one only if you trust this auth Worker)";

/// The address is an `https` page of `google.com` or of a host below it — the only kind that
/// is opened in a browser without being asked.
pub fn is_google_page(verification_url: &str) -> bool {
    url::Url::parse(verification_url).is_ok_and(|url| {
        url.scheme() == "https"
            && url
                .host_str()
                .is_some_and(|host| host == "google.com" || host.ends_with(".google.com"))
    })
}

/// `POST /device/start`: 5 tries on 5xx/network, one more after a `429` — starting twice only
/// leaves an unused code behind.
pub async fn device_start(
    http: &reqwest::Client,
    ep: &AuthEndpoints,
) -> Result<DeviceCode, AuthError> {
    let v = post_retrying(http, ep, Route::DeviceStart, &serde_json::json!({})).await?;
    device_code(&v).ok_or_else(|| AuthError::Network(UNEXPECTED.into()))
}

/// The answer of `/device/start`, or `None` when it is not one. The user code and the URL end
/// up in a terminal (and the URL in a browser): printable ASCII of bounded length; the URL an
/// `https` address with a host and without a user name or password (`https://google.com@host/`
/// reads like another host than it is). `interval` may be absent: then it is 5 s.
fn device_code(v: &serde_json::Value) -> Option<DeviceCode> {
    let text = |name: &str| v.get(name).and_then(|x| x.as_str()).unwrap_or("");
    let (device_code, user_code, url) = (
        text("device_code"),
        text("user_code"),
        text("verification_url"),
    );
    let printable = |s: &str, max: usize| {
        !s.is_empty() && s.len() <= max && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
    };
    let shown = printable(user_code, USER_CODE_MAX)
        && user_code.trim() == user_code
        && printable(url, VERIFICATION_URL_MAX)
        && !url.contains(' ')
        && url.starts_with("https://")
        && url::Url::parse(url).is_ok_and(|parsed| {
            parsed.scheme() == "https"
                && parsed.host_str().is_some_and(|host| !host.is_empty())
                && parsed.username().is_empty()
                && parsed.password().is_none()
        });
    if device_code.is_empty() || !shown {
        return None;
    }
    let interval = match v.get("interval") {
        None => AUTH_POLL_INTERVAL_DEFAULT,
        Some(_) => positive_seconds(v, "interval")?,
    };
    Some(DeviceCode {
        device_code: device_code.to_string(),
        user_code: user_code.to_string(),
        verification_url: url.to_string(),
        expires_in: positive_seconds(v, "expires_in")?.min(AUTH_TIMEOUT),
        interval: interval.min(AUTH_RETRY_AFTER_MAX),
    })
}

/// Polls `/device/poll` every `code.interval` until the user approved (the grant), refused
/// (`Denied`), or the code ran out (`Timeout`). `slow_down` adds 5 s to the interval for the
/// rest of the login. A poll that brings no answer about the login — it does not reach the
/// Worker, or the Worker could not ask Google — is followed by the next one after a pause
/// that doubles with every such poll in a row (`poll_pause`; RFC 8628 §3.5: "clients MUST
/// unilaterally reduce their polling frequency"); `note` hears about the first of a streak.
pub async fn device_wait(
    http: &reqwest::Client,
    ep: &AuthEndpoints,
    code: &DeviceCode,
    note: &(dyn Fn(&str) + Send + Sync),
) -> Result<LoginGrant, AuthError> {
    let body = serde_json::json!({ "device_code": code.device_code });
    let deadline = tokio::time::Instant::now() + code.expires_in;
    let mut interval = code.interval;
    // Polls in a row that failed without an answer about the login.
    let mut failures = 0u32;
    // `Some`: the polls since the last answer all failed, the newest for this reason.
    let mut unreachable: Option<String> = None;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if interval >= left {
            return Err(match unreachable {
                Some(detail) => AuthError::Network(detail),
                None => AuthError::Timeout,
            });
        }
        tokio::time::sleep(poll_pause(interval, failures, left)).await;
        let outcome = match post(http, ep, Route::DevicePoll, &body).await {
            Ok(answer) => interpret(Route::DevicePoll, answer),
            Err(detail) => Outcome::Transient(detail),
        };
        let failed = match outcome {
            Outcome::Success(v) => return login_grant(&v),
            Outcome::Final(e) => return Err(e),
            Outcome::Pending => None,
            Outcome::SlowDown => {
                interval += AUTH_POLL_SLOW_DOWN;
                None
            }
            // The Worker said how long to stay away: that wait is the whole back-off.
            Outcome::RateLimited(wait) => {
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                tokio::time::sleep(wait.min(left)).await;
                Some(RATE_LIMITED.to_string())
            }
            Outcome::Transient(detail) => {
                failures = failures.saturating_add(1);
                Some(detail)
            }
        };
        if failed.is_none() {
            failures = 0;
        }
        if let (Some(detail), None) = (&failed, &unreachable) {
            note(&format!(
                "(cannot reach the sign-in service right now: {detail} — still trying)"
            ));
        }
        unreachable = failed;
    }
}

/// How long to wait before the next poll: `interval`, doubled for every poll in a row that
/// failed (`failures`) up to `AUTH_RETRY_AFTER_MAX` — never less than `interval`, so a
/// `slow_down` increment is kept in full. `left` is what remains of the code's lifetime: the
/// back-off does not skip the last poll that the plain interval would still have made.
fn poll_pause(interval: Duration, failures: u32, left: Duration) -> Duration {
    let factor = 1u32.checked_shl(failures).unwrap_or(u32::MAX);
    interval
        .saturating_mul(factor)
        .min(AUTH_RETRY_AFTER_MAX)
        .min(left.saturating_sub(interval))
        .max(interval)
}

fn login_grant(v: &serde_json::Value) -> Result<LoginGrant, AuthError> {
    let grant = LoginGrant {
        refresh_token: string_field(v, "refresh_token")?,
        access_token: string_field(v, "access_token")?,
        expires_at_ms: expires_at_ms(v)?,
        scope: string_field(v, "scope")?,
        email: account_email(v)?,
        refresh_expires_in: seconds_field(v, "refresh_token_expires_in"),
    };
    if !grant.scope.split(' ').any(|s| s == SCOPE_DRIVE_FILE) {
        return Err(AuthError::ScopeMissing);
    }
    Ok(grant)
}

// ---------------------------------------------------------------------------------------------
// The Worker's JSON routes and the mapping table of §2.4
// ---------------------------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Route {
    DeviceStart,
    DevicePoll,
    Refresh,
}

impl Route {
    fn path(self) -> &'static str {
        match self {
            Route::DeviceStart => "/device/start",
            Route::DevicePoll => "/device/poll",
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
    /// `/device/poll`: nobody has entered the code yet.
    Pending,
    /// `/device/poll`: as `Pending`, and the interval grows.
    SlowDown,
    /// `429`: answered before the Worker contacted Google.
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
    let mapped = match (status, code, route) {
        (400, "authorization_pending", Route::DevicePoll) => return Outcome::Pending,
        (400, "slow_down", Route::DevicePoll) => return Outcome::SlowDown,
        (400, "expired_token", Route::DevicePoll) => AuthError::Timeout,
        (400, "invalid_grant", Route::DevicePoll) => AuthError::LoginFailed(
            "the code is no longer valid: it expired, or this sign-in was already completed".into(),
        ),
        (400, "invalid_grant", Route::Refresh) => AuthError::Expired,
        // Google issued the grant — the code is used up — and the Worker could not hand it
        // out. Final, with the Worker's own reason: polling again could only get the
        // `invalid_grant` above and hide it.
        (403, "grant_unusable", Route::DevicePoll) => {
            AuthError::LoginFailed(if message.is_empty() {
                "Google approved the sign-in, but the auth Worker could not use Google's answer"
                    .into()
            } else {
                message
            })
        }
        // A Worker deployed before gclone 0.2.0 has no such route.
        (404, "not_found", Route::DeviceStart) => AuthError::LoginFailed(
            "the auth Worker at this URL is an older version without the code sign-in; deploy \
             the current worker/ first (worker/README.md)"
                .into(),
        ),
        (403, "email_not_allowed", _) => AuthError::NotAllowed(message),
        (403, "scope_missing", _) => AuthError::ScopeMissing,
        (403, "scope_not_allowed" | "access_denied", _) => AuthError::Denied(message),
        (500, "client_invalid" | "server_misconfigured", _) => {
            AuthError::WorkerMisconfigured(message)
        }
        (500..=599, _, _) => {
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

/// The `email` of a `/device/poll` answer. It is printed ("Signed in as …") and stored, so it
/// is held to what `/device/start`'s texts are: printable ASCII without a space, bounded — and
/// it has an `@`. Anything else is not the promised answer.
fn account_email(v: &serde_json::Value) -> Result<String, AuthError> {
    let email = string_field(v, "email")?;
    let plain = email.len() <= EMAIL_MAX
        && email.bytes().all(|b| (0x21..=0x7e).contains(&b))
        && email.contains('@');
    if !plain {
        return Err(AuthError::Network(UNEXPECTED.into()));
    }
    Ok(email)
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

/// A number of seconds greater than zero; fractions count (the Worker passes Google's number on).
fn positive_seconds(v: &serde_json::Value, name: &str) -> Option<Duration> {
    let secs = v.get(name)?.as_f64()?;
    (secs.is_finite() && secs > 0.0).then(|| Duration::from_secs_f64(secs.min(1e9)))
}

fn expires_at_ms(v: &serde_json::Value) -> Result<u64, AuthError> {
    let secs =
        seconds_field(v, "expires_in").ok_or_else(|| AuthError::Network(UNEXPECTED.into()))?;
    Ok(util::now_ms().saturating_add(secs.saturating_mul(1000)))
}

/// A route that is safe to repeat: 5 tries on 5xx/network; 429: once more after `Retry-After`.
async fn post_retrying(
    http: &reqwest::Client,
    ep: &AuthEndpoints,
    route: Route,
    body: &serde_json::Value,
) -> Result<serde_json::Value, AuthError> {
    let mut waited = false;
    let mut failures = 0u32;
    loop {
        let outcome = match post(http, ep, route, body).await {
            Ok(answer) => interpret(route, answer),
            Err(detail) => Outcome::Transient(detail),
        };
        match outcome {
            Outcome::Success(v) => return Ok(v),
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
                tokio::time::sleep(RETRY_BACKOFF * 2u32.pow(failures - 1)).await;
            }
            Outcome::Final(e) => return Err(e),
            // `interpret` gives these for `/device/poll` only, which is not repeated here.
            Outcome::Pending | Outcome::SlowDown => {
                return Err(AuthError::Network(UNEXPECTED.into()));
            }
        }
    }
}

/// `POST /refresh`, 5 tries on 5xx/network; 429: once more after `Retry-After`. `client` says
/// which of the Worker's OAuth clients issued the token: `Device` is sent as `"client":
/// "device"`, `Legacy` (a login from before 0.2.0) as no field at all.
pub async fn refresh(
    http: &reqwest::Client,
    ep: &AuthEndpoints,
    refresh_token: &str,
    client: AuthClient,
) -> Result<AccessGrant, AuthError> {
    let mut body = serde_json::json!({ "refresh_token": refresh_token });
    if client == AuthClient::Device {
        body["client"] = "device".into();
    }
    let v = post_retrying(http, ep, Route::Refresh, &body).await?;
    Ok(AccessGrant {
        access_token: string_field(&v, "access_token")?,
        expires_at_ms: expires_at_ms(&v)?,
    })
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

    const ROUTES: [Route; 3] = [Route::DeviceStart, Route::DevicePoll, Route::Refresh];

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
            _ => panic!("{route:?} {status} {body}: expected a final error"),
        }
    }

    fn err(code: &str) -> String {
        format!(r#"{{"error":"{code}","message":"m\u0007 text"}}"#)
    }

    #[test]
    fn mapping_table() {
        for route in ROUTES {
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
                (404, "<html>not found</html>".to_string()),
                (403, "<html>forbidden</html>".to_string()),
                // a code under another status is not the mapped answer
                (400, err("scope_missing")),
                (403, err("authorization_pending")),
                (428, err("authorization_pending")),
            ] {
                let e = final_error(route, status, &body);
                assert!(
                    matches!(e, AuthError::Network(m) if m == UNEXPECTED),
                    "{route:?} {status}"
                );
            }
        }
    }

    #[test]
    fn rows_of_one_route() {
        use Route::{DevicePoll, DeviceStart, Refresh};
        // the states of a device code
        let pending = interpret(DevicePoll, answer(400, &err("authorization_pending")));
        assert!(matches!(pending, Outcome::Pending));
        let slow = interpret(DevicePoll, answer(400, &err("slow_down")));
        assert!(matches!(slow, Outcome::SlowDown));
        let e = final_error(DevicePoll, 400, &err("expired_token"));
        assert!(matches!(e, AuthError::Timeout));
        for code in ["authorization_pending", "slow_down", "expired_token"] {
            for route in [DeviceStart, Refresh] {
                let e = final_error(route, 400, &err(code));
                assert!(matches!(e, AuthError::Network(_)), "{route:?} {code}");
            }
        }
        // invalid_grant: a dead device code, or a dead refresh token
        let e = final_error(DevicePoll, 400, &err("invalid_grant"));
        assert!(matches!(e, AuthError::LoginFailed(_)));
        // a grant Google issued and the Worker could not hand out: final, with the Worker's reason
        let e = final_error(DevicePoll, 403, &err("grant_unusable"));
        assert!(matches!(e, AuthError::LoginFailed(m) if m == "m text"));
        let e = final_error(DevicePoll, 403, r#"{"error":"grant_unusable"}"#);
        assert!(
            matches!(e, AuthError::LoginFailed(m) if m.contains("could not use Google's answer"))
        );
        for route in [DeviceStart, Refresh] {
            let e = final_error(route, 403, &err("grant_unusable"));
            assert!(matches!(e, AuthError::Network(_)), "{route:?}");
        }
        // … and never under a 5xx, which a poll is repeated on
        let outcome = interpret(DevicePoll, answer(502, &err("grant_unusable")));
        assert!(matches!(outcome, Outcome::Transient(_)));
        let e = final_error(Refresh, 400, &err("invalid_grant"));
        assert!(matches!(e, AuthError::Expired));
        let e = final_error(DeviceStart, 400, &err("invalid_grant"));
        assert!(matches!(e, AuthError::Network(_)));
        // a Worker from before the device flow
        let e = final_error(DeviceStart, 404, &err("not_found"));
        assert!(matches!(e, AuthError::LoginFailed(m) if m.contains("older version")));
        for route in [DevicePoll, Refresh] {
            let e = final_error(route, 404, &err("not_found"));
            assert!(matches!(e, AuthError::Network(_)));
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
            match interpret(Route::DevicePoll, a) {
                Outcome::RateLimited(d) => d,
                _ => panic!("expected RateLimited"),
            }
        };
        assert_eq!(wait(Some(Duration::from_secs(7))), Duration::from_secs(7));
        assert_eq!(wait(Some(Duration::from_secs(3600))), AUTH_RETRY_AFTER_MAX);
        assert_eq!(wait(None), RETRY_AFTER_DEFAULT);
    }

    #[test]
    fn device_code_answers() {
        let good = serde_json::json!({
            "device_code": "AH-1Ng/device_code", "user_code": "GQVQ-JKEC",
            "verification_url": "https://www.google.com/device", "expires_in": 1800, "interval": 5
        });
        let code = device_code(&good).unwrap();
        assert_eq!(code.device_code, "AH-1Ng/device_code");
        assert_eq!(code.user_code, "GQVQ-JKEC");
        assert_eq!(code.verification_url, "https://www.google.com/device");
        assert_eq!(code.expires_in, Duration::from_secs(1800));
        assert_eq!(code.interval, Duration::from_secs(5));

        let with = |name: &str, value: serde_json::Value| {
            let mut v = good.clone();
            v[name] = value;
            device_code(&v)
        };
        // fractions count; absurd values are capped
        let code = with("interval", 0.25.into()).unwrap();
        assert_eq!(code.interval, Duration::from_millis(250));
        let code = with("expires_in", 1e12.into()).unwrap();
        assert_eq!(code.expires_in, AUTH_TIMEOUT);
        let code = with("interval", 86_400.into()).unwrap();
        assert_eq!(code.interval, AUTH_RETRY_AFTER_MAX);
        assert_eq!(
            with("user_code", "AB CD".into()).unwrap().user_code,
            "AB CD"
        );

        // nothing that is not plain text reaches the terminal or the browser
        for (name, bad) in [
            ("device_code", serde_json::json!("")),
            ("device_code", serde_json::json!(5)),
            ("user_code", serde_json::json!("")),
            ("user_code", serde_json::json!(" GQVQ")),
            ("user_code", serde_json::json!("GQVQ\u{1b}[2J")),
            ("user_code", serde_json::json!("GQVQ\nJKEC")),
            ("user_code", serde_json::json!("ü")),
            ("user_code", serde_json::json!("x".repeat(65))),
            (
                "verification_url",
                serde_json::json!("http://www.google.com/device"),
            ),
            ("verification_url", serde_json::json!("https://")),
            ("verification_url", serde_json::json!("file:///etc/passwd")),
            ("verification_url", serde_json::json!("https://a b")),
            ("verification_url", serde_json::json!("https://a\u{7}")),
            ("verification_url", serde_json::json!("https://?x")),
            (
                "verification_url",
                serde_json::json!("https://www.google.com@evil.example/device"),
            ),
            (
                "verification_url",
                serde_json::json!("https://user:pw@www.google.com/device"),
            ),
            (
                "verification_url",
                serde_json::json!(format!("https://{}", "g".repeat(250))),
            ),
            ("expires_in", serde_json::json!(0)),
            ("expires_in", serde_json::json!("1800")),
            ("expires_in", serde_json::json!(-1)),
            ("interval", serde_json::json!(0)),
            ("interval", serde_json::json!(-5)),
            ("interval", serde_json::json!("5")),
            ("interval", serde_json::Value::Null),
        ] {
            assert!(with(name, bad.clone()).is_none(), "{name} = {bad}");
        }
        assert!(device_code(&serde_json::json!({})).is_none());

        // RFC 8628 §3.2 / §3.5: `interval` is optional, and its default is 5 seconds
        let mut without = good.clone();
        without.as_object_mut().unwrap().remove("interval");
        let code = device_code(&without).unwrap();
        assert_eq!(code.interval, Duration::from_secs(5));
        assert_eq!(code.interval, AUTH_POLL_INTERVAL_DEFAULT);
        // … the other four are not
        for name in ["device_code", "user_code", "verification_url", "expires_in"] {
            let mut v = good.clone();
            v.as_object_mut().unwrap().remove(name);
            assert!(device_code(&v).is_none(), "without {name}");
        }
    }

    #[test]
    fn only_a_google_page_is_opened() {
        for url in [
            "https://www.google.com/device",
            "https://google.com/device",
            "https://accounts.google.com/o/oauth2/device/usercode?hl=en",
            "https://WWW.Google.COM/device",
            "https://www.google.com:443/device",
        ] {
            assert!(is_google_page(url), "{url}");
            // … and every one of them is an address the device accepts
            let v = serde_json::json!({ "device_code": "d", "user_code": "U", "verification_url": url,
                                        "expires_in": 1, "interval": 1 });
            assert!(device_code(&v).is_some(), "{url}");
        }
        for url in [
            "https://evil.example/device",
            "https://www.google.com.evil.example/device",
            "https://evilgoogle.com/device",
            "https://google.com.evil.example/",
            "https://evil.example/www.google.com/device",
            "https://evil.example/?next=https://www.google.com/device",
            "https://www.google.com@evil.example/device",
            "https://www.google.co/device",
            "https://www.google.com./device",
            "https://g.co/device",
            "http://www.google.com/device",
            "www.google.com/device",
            "",
        ] {
            assert!(!is_google_page(url), "{url}");
        }
    }

    #[test]
    fn failed_polls_back_off_and_never_poll_faster_than_the_interval() {
        let s = Duration::from_secs;
        let long = s(1800);
        // interval, 2×, 4×, … capped at AUTH_RETRY_AFTER_MAX
        let pauses: Vec<u64> = (0..7)
            .map(|n| poll_pause(s(5), n, long).as_secs())
            .collect();
        assert_eq!(pauses, [5, 10, 20, 40, 60, 60, 60]);
        assert_eq!(poll_pause(s(5), u32::MAX, long), AUTH_RETRY_AFTER_MAX);
        assert_eq!(poll_pause(s(5), 40, long), AUTH_RETRY_AFTER_MAX);
        // a slow_down increment is never shortened, also beyond the cap
        assert_eq!(poll_pause(s(10), 0, long), s(10));
        assert_eq!(poll_pause(s(65), 0, long), s(65));
        assert_eq!(poll_pause(s(65), 3, long), s(65));
        // near the end of the code the back-off still leaves room for the last poll …
        assert_eq!(poll_pause(s(5), 4, s(30)), s(25));
        assert_eq!(poll_pause(s(5), 2, s(12)), s(7));
        // … and is never less than the interval
        assert_eq!(poll_pause(s(5), 4, s(8)), s(5));
        assert_eq!(poll_pause(s(5), 0, s(6)), s(5));
        let ms = Duration::from_millis;
        assert_eq!(poll_pause(ms(20), 3, long), ms(160));
    }

    #[test]
    fn the_account_address_is_plain_text() {
        let grant = |email: serde_json::Value| {
            login_grant(&serde_json::json!({
                "refresh_token": "1//r", "access_token": "ya29.a", "expires_in": 3599,
                "scope": SCOPE_DRIVE_FILE, "email": email
            }))
        };
        for good in ["me@example.com", "Me+tag@Sub.Example.org", "a@b"] {
            assert_eq!(grant(good.into()).ok().unwrap().email, good);
        }
        let longest = format!("{}@example.com", "l".repeat(EMAIL_MAX - 12));
        assert_eq!(longest.len(), EMAIL_MAX);
        assert!(grant(longest.clone().into()).is_ok());
        for bad in [
            serde_json::json!(
                "me@example.com\u{1b}[31mRED\u{1b}]0;title\u{7}\nerror: fake second line"
            ),
            serde_json::json!("me@example.com\n"),
            serde_json::json!("me@example.com\r"),
            serde_json::json!("me @example.com"),
            serde_json::json!("me@example.com\u{7f}"),
            serde_json::json!("m\u{e9}@example.com"),
            serde_json::json!("me@example.com\u{202e}"),
            serde_json::json!("no-at-sign"),
            serde_json::json!(format!("l{longest}")),
            serde_json::json!(""),
            serde_json::json!(5),
            serde_json::Value::Null,
        ] {
            let e = match grant(bad.clone()) {
                Ok(_) => panic!("accepted {bad}"),
                Err(e) => e,
            };
            assert!(
                matches!(e, AuthError::Network(m) if m == UNEXPECTED),
                "{bad}"
            );
        }
    }
}

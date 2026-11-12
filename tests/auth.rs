//! WP3 acceptance (SPEC §12.1), auth side: the device's part of the login (§2.4 — Google's
//! device authorization grant through the auth Worker), token handling, and the contract
//! fixture `worker/test/contract.json` (§16.5) — all against the fake auth Worker of
//! `FakeDrive`. No network beyond 127.0.0.1.

#[path = "support/fake_drive.rs"]
mod fake_drive;

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fake_drive::{FakeDrive, Route, VERIFICATION_URL};
use gclone::auth::{
    self, AccessGrant, AuthClient, AuthEndpoints, DeviceCode, InteractiveOpts, LoginGrant,
    NOT_GOOGLE_NOTE, SCOPE_DRIVE_FILE, TokenProvider,
};
use gclone::error::AuthError;
use serde::Deserialize;
use serde_json::{Value, json};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A grant that covers the whole Drive (an older, wider grant of the same account).
const WIDE_SCOPE: &str = "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/drive";
const ENTER_THE_CODE: &str = "and enter the code  ";

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

fn http() -> reqwest::Client {
    auth::http_client().unwrap()
}

/// `LoginGrant`, `AccessGrant` and `DeviceCode` have no `Debug` (they hold secrets), so no
/// `unwrap_err`.
fn err<T>(r: Result<T, AuthError>) -> AuthError {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

/// What a login printed.
#[derive(Clone, Default)]
struct Printed(Arc<Mutex<Vec<String>>>);

impl Printed {
    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }

    fn text(&self) -> String {
        self.lines().join("\n")
    }

    /// The user code, once the terminal shows it — what the user reads off the screen.
    async fn user_code(&self) -> String {
        for _ in 0..2000 {
            let shown = self
                .lines()
                .into_iter()
                .find_map(|l| l.strip_prefix(ENTER_THE_CODE).map(str::to_owned));
            if let Some(code) = shown {
                return code;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the login printed no code: {}", self.text());
    }

    /// Lines that say a poll did not get through.
    fn retry_notes(&self) -> usize {
        self.lines()
            .iter()
            .filter(|l| l.contains("still trying"))
            .count()
    }

    fn printer(&self) -> Box<dyn Fn(&str) + Send + Sync> {
        let lines = self.0.clone();
        Box::new(move |s| lines.lock().unwrap().push(s.to_string()))
    }
}

/// URLs the login asked to have opened in a browser.
type Opened = Arc<Mutex<Vec<String>>>;

fn opts(printed: &Printed, no_browser: bool) -> (InteractiveOpts, Opened) {
    let opened = Opened::default();
    let record = opened.clone();
    let opts = InteractiveOpts {
        no_browser,
        print: printed.printer(),
        open: Box::new(move |url| record.lock().unwrap().push(url.to_string())),
    };
    (opts, opened)
}

type Login = tokio::task::JoinHandle<Result<LoginGrant, AuthError>>;

/// `login_interactive` against the fake, running beside the test (which plays the user).
fn spawn_login(fake: &FakeDrive, printed: &Printed) -> Login {
    let ep = fake.auth();
    let (opts, _) = opts(printed, true);
    tokio::spawn(async move { auth::login_interactive(&http(), &ep, opts).await })
}

/// A whole login: the device starts, the user enters the code at "Google", the device's poll
/// brings the tokens.
async fn try_login(fake: &FakeDrive) -> Result<LoginGrant, AuthError> {
    let printed = Printed::default();
    let login = spawn_login(fake, &printed);
    fake.approve(&printed.user_code().await);
    login.await.unwrap()
}

async fn login_tokens(fake: &FakeDrive) -> LoginGrant {
    match try_login(fake).await {
        Ok(grant) => grant,
        Err(e) => panic!("the login failed: {e:?}"),
    }
}

/// A device code to poll with by hand: short-lived, polled every 10 ms.
fn code(device_code: &str, lifetime_ms: u64) -> DeviceCode {
    DeviceCode {
        device_code: device_code.to_string(),
        user_code: "TEST-CODE".into(),
        verification_url: VERIFICATION_URL.into(),
        expires_in: Duration::from_millis(lifetime_ms),
        interval: Duration::from_millis(10),
    }
}

async fn wait(ep: &AuthEndpoints, code: &DeviceCode) -> Result<LoginGrant, AuthError> {
    auth::device_wait(&http(), ep, code, &|_| {}).await
}

/// A server that answers every request the same way.
async fn stub(
    status: u16,
    content_type: &str,
    body: &[u8],
    headers: &[(&str, &str)],
) -> (MockServer, AuthEndpoints) {
    let server = MockServer::start().await;
    let mut answer = ResponseTemplate::new(status).set_body_raw(body.to_vec(), content_type);
    for (name, value) in headers {
        answer = answer.insert_header(*name, *value);
    }
    Mock::given(wiremock::matchers::any())
        .respond_with(answer)
        .mount(&server)
        .await;
    let ep = AuthEndpoints {
        base: server.uri(),
        revoke_url: format!("{}/revoke", server.uri()),
    };
    (server, ep)
}

async fn stub_hits(server: &MockServer) -> usize {
    server.received_requests().await.unwrap().len()
}

/// An address nothing listens on.
fn dead_endpoints() -> AuthEndpoints {
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    AuthEndpoints {
        base: format!("http://127.0.0.1:{closed}/auth"),
        revoke_url: String::new(),
    }
}

fn private_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("state");
    gclone::util::create_dir_private(&dir).unwrap();
    (tmp, dir)
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// ---------------------------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------------------------

#[test]
fn auth_url_rules() {
    let ok = |given: &str, want: &str| {
        assert_eq!(auth::validate_auth_url(given).unwrap(), want, "{given}")
    };
    ok("https://h", "https://h");
    ok("https://h/", "https://h");
    ok("https://h/base/", "https://h/base");
    ok(
        "https://gclone-auth.me.workers.dev",
        "https://gclone-auth.me.workers.dev",
    );
    ok("http://127.0.0.1:8787", "http://127.0.0.1:8787");
    ok("http://localhost:1/x", "http://localhost:1/x");
    ok("http://[::1]:9", "http://[::1]:9");
    ok("https://[::1]:9/auth/", "https://[::1]:9/auth");
    for bad in [
        "http://example.com",
        "http://127.0.0.2:80",
        "http://localhost.example.com",
        "ftp://h",
        "h",
        "",
        "https://user@h",
        "https://user:pw@h",
        "https://:pw@h",
        "https://h?x=1",
        "https://h/?",
        "https://h#frag",
        "https://h/#",
        "https://",
        "https://:443",
        "file:///etc/passwd",
    ] {
        let e = auth::validate_auth_url(bad).unwrap_err();
        assert!(matches!(e, AuthError::BadAuthUrl(_)), "{bad}: {e:?}");
    }

    // precedence: argument > environment > stored > built-in
    let r = |a, e, s| auth::resolve_auth_url(a, e, s).unwrap();
    assert_eq!(
        r(
            Some("https://arg/"),
            Some("https://env"),
            Some("https://stored")
        ),
        "https://arg"
    );
    assert_eq!(
        r(None, Some("https://env"), Some("https://stored")),
        "https://env"
    );
    assert_eq!(r(None, None, Some("https://stored/x/")), "https://stored/x");
    match (
        auth::resolve_auth_url(None, None, None),
        auth::DEFAULT_AUTH_URL,
    ) {
        (Ok(url), Some(built_in)) => assert_eq!(url, auth::validate_auth_url(built_in).unwrap()),
        (Err(AuthError::BadAuthUrl(msg)), None) => {
            assert!(
                msg.contains("gclone login")
                    && msg.contains("GCLONE_AUTH_URL")
                    && msg.contains("GCLONE_DEFAULT_AUTH_URL")
            );
        }
        (other, built_in) => panic!("built-in {built_in:?}: {:?}", other.map(|_| ())),
    }
    // the value that wins is validated, not skipped
    assert!(auth::resolve_auth_url(Some("http://example.com"), Some("https://env"), None).is_err());
    assert_eq!(
        auth::AuthEndpoints::new("https://h/").unwrap().revoke_url,
        auth::GOOGLE_REVOKE_URL
    );
}

// ---------------------------------------------------------------------------------------------
// the sign-in: start, show the code, poll
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn device_flow_signs_in() {
    let fake = FakeDrive::start().await;
    let printed = Printed::default();
    let (o, opened) = opts(&printed, false);
    let ep = fake.auth();
    let login = tokio::spawn(async move { auth::login_interactive(&http(), &ep, o).await });

    // The terminal: where to go, the code, and whose code to trust — nothing else.
    let user_code = printed.user_code().await;
    assert_eq!(Some(user_code.clone()), fake.last_user_code());
    assert_eq!(
        printed.lines(),
        [
            format!("To sign in, open  {VERIFICATION_URL}"),
            format!("{ENTER_THE_CODE}{user_code}"),
            "(enter only a code shown in this terminal; waiting…)".to_string(),
        ]
    );
    // Nobody has entered the code yet: the device polls, and nothing is handed out.
    while fake.hits(Route::AuthPoll) < 3 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(fake.issued_refresh_tokens().is_empty());
    assert!(!login.is_finished());

    fake.approve(&user_code);
    let grant = login.await.unwrap().unwrap();
    assert_eq!(grant.refresh_token, "rt-1");
    assert_eq!(grant.email, "me@example.com");
    assert!(grant.scope.split(' ').any(|s| s == SCOPE_DRIVE_FILE));
    assert!(grant.access_token.starts_with("at-"));
    assert!(grant.refresh_expires_in.is_none());
    let in_an_hour = gclone::util::now_ms() + 3_599_000;
    assert!(grant.expires_at_ms.abs_diff(in_an_hour) < 10_000);
    assert_eq!(fake.issued_refresh_tokens(), ["rt-1"]);
    assert_eq!(printed.lines().len(), 3, "nothing more was printed");
    // The browser was pointed at Google's page — the address as the Worker gave it.
    assert_eq!(*opened.lock().unwrap(), [VERIFICATION_URL]);

    // What went over the wire: one start with an empty object, polls that carry the device code.
    let starts = fake.requests(Route::AuthStart);
    assert_eq!(starts.len(), 1);
    assert_eq!(
        (starts[0].method.as_str(), starts[0].path.as_str()),
        ("POST", "/auth/device/start")
    );
    assert_eq!(starts[0].json, Some(json!({})));
    assert!(starts[0].headers["content-type"].starts_with("application/json"));
    assert!(starts[0].headers["user-agent"].starts_with("gclone/"));
    let polls = fake.requests(Route::AuthPoll);
    assert!(polls.len() >= 4);
    let device_code = polls[0].json.as_ref().unwrap()["device_code"]
        .as_str()
        .unwrap()
        .to_string();
    for poll in &polls {
        assert_eq!(
            (poll.method.as_str(), poll.path.as_str()),
            ("POST", "/auth/device/poll")
        );
        assert_eq!(poll.json, Some(json!({ "device_code": device_code })));
    }
    // The device code never reaches the terminal; the user code never goes back to the Worker.
    assert!(!printed.text().contains(&device_code));
    assert_ne!(device_code, user_code);

    // The new login works on Drive.
    let tokens = fake.token_provider_for(&grant.refresh_token);
    tokens.prime(&grant.access_token, grant.expires_at_ms);
    assert_eq!(tokens.access_token().await.unwrap(), grant.access_token);
    assert_eq!(fake.hits(Route::AuthRefresh), 0);
}

#[tokio::test]
async fn no_browser_prints_the_same_and_opens_nothing() {
    let fake = FakeDrive::start().await;
    let printed = Printed::default();
    let (o, opened) = opts(&printed, true);
    let ep = fake.auth();
    let login = tokio::spawn(async move { auth::login_interactive(&http(), &ep, o).await });
    let user_code = printed.user_code().await;
    fake.approve(&user_code);
    assert_eq!(login.await.unwrap().unwrap().refresh_token, "rt-1");
    assert!(opened.lock().unwrap().is_empty());
    assert_eq!(printed.lines().len(), 3);
    assert!(printed.text().contains(VERIFICATION_URL));
}

#[tokio::test]
async fn a_refused_consent_ends_the_login() {
    let fake = FakeDrive::start().await;
    let printed = Printed::default();
    let login = spawn_login(&fake, &printed);
    fake.deny(&printed.user_code().await);
    let e = err(login.await.unwrap());
    assert!(
        matches!(&e, AuthError::Denied(msg) if msg.contains("access_denied")),
        "{e:?}"
    );
    assert!(fake.issued_refresh_tokens().is_empty());
}

#[tokio::test]
async fn a_code_that_runs_out_ends_the_login() {
    // Google says so …
    let fake = FakeDrive::start().await;
    let printed = Printed::default();
    let login = spawn_login(&fake, &printed);
    printed.user_code().await;
    fake.expire_codes();
    let e = err(login.await.unwrap());
    assert!(matches!(e, AuthError::Timeout), "{e:?}");

    // … or the device's own clock does: it stops polling when the lifetime it was told is over.
    fake.set_code_lifetime(0.4);
    let printed = Printed::default();
    let started = Instant::now();
    let login = spawn_login(&fake, &printed);
    let e = err(login.await.unwrap());
    assert!(matches!(e, AuthError::Timeout), "{e:?}");
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(300) && took < Duration::from_secs(5),
        "{took:?}"
    );
    assert!(fake.hits(Route::AuthPoll) > 3, "it polled until then");
    assert!(fake.issued_refresh_tokens().is_empty());
}

#[tokio::test]
async fn slow_down_adds_five_seconds_to_the_interval() {
    let fake = FakeDrive::start().await;
    let printed = Printed::default();
    fake.slow_down(1);
    let login = spawn_login(&fake, &printed);
    let user_code = printed.user_code().await;
    // The first poll is answered slow_down; the second comes 5 s + the interval later.
    while fake.hits(Route::AuthPoll) < 1 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let slowed = Instant::now();
    fake.approve(&user_code);
    assert_eq!(login.await.unwrap().unwrap().refresh_token, "rt-1");
    assert!(
        slowed.elapsed() >= Duration::from_millis(4900),
        "{:?}",
        slowed.elapsed()
    );
    assert_eq!(fake.hits(Route::AuthPoll), 2);
    assert_eq!(printed.retry_notes(), 0, "slow_down is not a failure");
}

#[tokio::test]
async fn polls_that_fail_are_followed_by_the_next_one() {
    let fake = FakeDrive::start().await;
    // What a network blip, a Worker that cannot reach Google, and a rate limit look like.
    fake.fail_next(Route::AuthPoll, 2, 502, "upstream_error");
    fake.fail_next_raw(Route::AuthPoll, 1, 503, "<html>Service Unavailable</html>");
    fake.fail_next(Route::AuthPoll, 1, 500, "internal_error");
    fake.fail_next(Route::AuthPoll, 1, 429, "rate_limited");
    let printed = Printed::default();
    let login = spawn_login(&fake, &printed);
    fake.approve(&printed.user_code().await);
    let started = Instant::now();
    assert_eq!(login.await.unwrap().unwrap().refresh_token, "rt-1");
    assert_eq!(fake.hits(Route::AuthPoll), 6);
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "Retry-After: 1 was honoured"
    );
    // One note for the whole streak, not one per failed poll.
    assert_eq!(printed.retry_notes(), 1, "{}", printed.text());
    assert!(printed.text().contains("502"), "{}", printed.text());

    // A Worker that disappears for good: the login ends when the code does, as a network error.
    let fake = FakeDrive::start().await;
    fake.set_code_lifetime(0.5);
    let started = auth::device_start(&http(), &fake.auth()).await.unwrap();
    let e = err(wait(&dead_endpoints(), &started).await);
    assert!(matches!(e, AuthError::Network(_)), "{e:?}");
}

#[tokio::test]
async fn a_device_code_is_good_for_one_login() {
    let fake = FakeDrive::start().await;
    let (http, ep) = (http(), fake.auth());
    let started = auth::device_start(&http, &ep).await.unwrap();
    assert_eq!(started.verification_url, VERIFICATION_URL);
    assert_eq!(started.expires_in, Duration::from_secs(1800));
    assert_eq!(started.interval, Duration::from_millis(20));
    fake.approve(&started.user_code);
    let grant = wait(&ep, &started).await.unwrap();
    assert_eq!(grant.refresh_token, "rt-1");

    // used: Google's device code is single-use
    let e = err(wait(&ep, &started).await);
    assert!(
        matches!(&e, AuthError::LoginFailed(msg) if msg.contains("no longer valid")),
        "{e:?}"
    );
    // never issued
    let unknown = code("dc-never-issued-xxxxxxxxxxxx", 2000);
    assert!(matches!(
        err(wait(&ep, &unknown).await),
        AuthError::LoginFailed(_)
    ));
    // a string the Worker's pre-filter refuses
    let e = err(wait(&ep, &code("not a device code", 2000)).await);
    assert!(
        matches!(&e, AuthError::Network(msg) if msg.contains("unexpected answer")),
        "{e:?}"
    );
    assert_eq!(fake.issued_refresh_tokens(), ["rt-1"]);

    // Two logins side by side: approving one does not end the other.
    let (a, b) = (
        auth::device_start(&http, &ep).await.unwrap(),
        auth::device_start(&http, &ep).await.unwrap(),
    );
    assert_ne!(a.device_code, b.device_code);
    assert_ne!(a.user_code, b.user_code);
    fake.approve(&b.user_code);
    assert_eq!(wait(&ep, &b).await.unwrap().refresh_token, "rt-2");
    let short = code(&a.device_code, 150);
    assert!(matches!(err(wait(&ep, &short).await), AuthError::Timeout));
    fake.approve(&a.user_code);
    assert_eq!(wait(&ep, &a).await.unwrap().refresh_token, "rt-3");
}

#[tokio::test]
async fn poll_maps_the_workers_refusals() {
    let fake = FakeDrive::start().await;
    let (http, ep) = (http(), fake.auth());

    // The answer names the account masked: the route is open to anyone who has a device code.
    fake.set_login_email("other@example.com");
    let e = err(try_login(&fake).await);
    assert!(
        matches!(&e, AuthError::NotAllowed(msg) if msg.contains("o***@example.com") && !msg.contains("other")),
        "{e:?}"
    );
    // an allowlist entry in another case matches
    fake.set_login_email("Me@Example.com");
    fake.set_allowed_emails(&["someone@example.com", " ME@example.COM "]);
    assert_eq!(login_tokens(&fake).await.email, "Me@Example.com");
    fake.set_login_email("me@example.com");
    fake.set_allowed_emails(&["me@example.com"]);

    fake.set_granted_scope("openid");
    assert!(matches!(
        err(try_login(&fake).await),
        AuthError::ScopeMissing
    ));
    // More than gclone's scopes: the Worker hands out nothing, on /device/poll …
    fake.set_granted_scope(WIDE_SCOPE);
    let issued_before = fake.issued_refresh_tokens().len();
    let e = err(try_login(&fake).await);
    assert!(
        matches!(&e, AuthError::Denied(msg) if msg.contains("myaccount.google.com/permissions")),
        "{e:?}"
    );
    assert_eq!(
        fake.issued_refresh_tokens().len(),
        issued_before,
        "no token was issued"
    );
    // … and on /refresh for a token whose grant is that wide.
    fake.set_granted_scope(&format!("openid {SCOPE_DRIVE_FILE}"));
    let tokens = login_tokens(&fake).await;
    let refresh = |token: String| {
        let (http, ep) = (http.clone(), ep.clone());
        async move { auth::refresh(&http, &ep, &token, AuthClient::Device).await }
    };
    assert!(refresh(tokens.refresh_token.clone()).await.is_ok());
    fake.set_granted_scope(WIDE_SCOPE);
    let e = err(refresh(tokens.refresh_token.clone()).await);
    assert!(matches!(e, AuthError::Denied(_)), "{e:?}");
    fake.set_granted_scope(&format!("openid {SCOPE_DRIVE_FILE}"));

    // A client Google no longer accepts: at the poll, and already at the start.
    let started = auth::device_start(&http, &ep).await.unwrap();
    fake.approve(&started.user_code);
    fake.break_client();
    let e = err(wait(&ep, &started).await);
    assert!(matches!(e, AuthError::WorkerMisconfigured(_)), "{e:?}");
    let starts = fake.hits(Route::AuthStart);
    let e = err(auth::device_start(&http, &ep).await);
    assert!(matches!(e, AuthError::WorkerMisconfigured(_)), "{e:?}");
    assert_eq!(
        fake.hits(Route::AuthStart),
        starts + 1,
        "a broken client is not retried"
    );

    // The device checks the scope of a 200 answer itself.
    let body = json!({ "refresh_token": "1//r", "access_token": "ya29.a", "expires_in": 3599,
                       "scope": "openid https://www.googleapis.com/auth/drive.file.other", "email": "me@example.com" });
    let (_server, ep) = stub(
        200,
        "application/json; charset=utf-8",
        body.to_string().as_bytes(),
        &[],
    )
    .await;
    let any = code("dc-any-xxxxxxxxxxxxxxxx", 2000);
    assert!(matches!(
        err(wait(&ep, &any).await),
        AuthError::ScopeMissing
    ));
    // … and refuses a 200 answer that is not the promised shape — also one whose account
    // address is not plain text: it is printed ("Signed in as …") and stored.
    let with_email = |email: &str| {
        json!({ "refresh_token": "1//r", "access_token": "a", "expires_in": 1,
                "scope": SCOPE_DRIVE_FILE, "email": email })
    };
    let (_server, ok_ep) = stub(
        200,
        "application/json",
        with_email("me@example.com").to_string().as_bytes(),
        &[],
    )
    .await;
    assert_eq!(wait(&ok_ep, &any).await.unwrap().email, "me@example.com");
    for body in [
        json!({ "access_token": "a", "expires_in": 1, "scope": SCOPE_DRIVE_FILE, "email": "e@x" }),
        with_email("me@example.com\u{1b}[31mRED\u{1b}]0;title\u{7}\nerror: fake second line"),
        with_email("me@example.com\nSigned in as someone@else.example"),
        with_email("me @example.com"),
        with_email("m\u{e9}@example.com"),
        with_email("not-an-address"),
        with_email(&format!("{}@example.com", "l".repeat(250))),
        json!([1]),
        json!("ok"),
    ] {
        let (_server, ep) = stub(200, "application/json", body.to_string().as_bytes(), &[]).await;
        let e = err(wait(&ep, &any).await);
        assert!(
            matches!(&e, AuthError::Network(msg) if msg.contains("unexpected answer")),
            "{e:?}"
        );
    }
    let (_server, ep) = stub(
        403,
        "application/json",
        br#"{"error":"access_denied","message":"org_internal"}"#,
        &[],
    )
    .await;
    let e = err(wait(&ep, &any).await);
    assert!(
        matches!(&e, AuthError::Denied(msg) if msg == "org_internal"),
        "{e:?}"
    );
}

#[tokio::test]
async fn poll_passes_refresh_token_expires_in_through() {
    let fake = FakeDrive::start().await;
    assert!(login_tokens(&fake).await.refresh_expires_in.is_none());
    fake.set_refresh_expires_in(Some(604_799));
    assert_eq!(login_tokens(&fake).await.refresh_expires_in, Some(604_799));
    fake.set_refresh_expires_in(None);
    assert!(login_tokens(&fake).await.refresh_expires_in.is_none());
}

#[tokio::test]
async fn device_start_is_retried_and_its_answer_is_checked() {
    let http = http();

    // a 502 is retried and then succeeds; so is a 500 without a mapped code and an HTML 503
    let fake = FakeDrive::start().await;
    fake.fail_next(Route::AuthStart, 1, 502, "upstream_error");
    fake.fail_next(Route::AuthStart, 1, 500, "internal_error");
    fake.fail_next_raw(Route::AuthStart, 1, 503, "<html>down</html>");
    assert!(auth::device_start(&http, &fake.auth()).await.is_ok());
    assert_eq!(fake.hits(Route::AuthStart), 4);

    // five failures are the end
    let fake = FakeDrive::start().await;
    fake.fail_next(Route::AuthStart, u32::MAX, 502, "upstream_error");
    let e = err(auth::device_start(&http, &fake.auth()).await);
    assert!(
        matches!(&e, AuthError::Network(msg) if msg.contains("502")),
        "{e:?}"
    );
    assert_eq!(fake.hits(Route::AuthStart), 5);

    // one 429 is waited out, two are not
    let fake = FakeDrive::start().await;
    fake.fail_next(Route::AuthStart, 1, 429, "rate_limited");
    let started = Instant::now();
    assert!(auth::device_start(&http, &fake.auth()).await.is_ok());
    assert_eq!(fake.hits(Route::AuthStart), 2);
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "Retry-After: 1 was honoured"
    );
    fake.fail_next(Route::AuthStart, 2, 429, "rate_limited");
    let e = err(auth::device_start(&http, &fake.auth()).await);
    assert!(
        matches!(&e, AuthError::Network(msg) if msg.contains("rate-limiting")),
        "{e:?}"
    );
    assert_eq!(fake.hits(Route::AuthStart), 4);

    // nothing listening → Network
    assert!(matches!(
        err(auth::device_start(&http, &dead_endpoints()).await),
        AuthError::Network(_)
    ));

    // a Worker from before 0.2.0 has no such route: the message says what to do
    let (_server, ep) = stub(
        404,
        "application/json; charset=utf-8",
        br#"{"error":"not_found","message":"There is nothing at this address."}"#,
        &[],
    )
    .await;
    let e = err(auth::device_start(&http, &ep).await);
    assert!(
        matches!(&e, AuthError::LoginFailed(msg) if msg.contains("older version")),
        "{e:?}"
    );

    // An answer whose code or address is not plain text never reaches the terminal or a browser.
    let good = json!({ "device_code": "dc-1-xxxxxxxxxxxxxxxx", "user_code": "ABCD-EFGH",
                       "verification_url": VERIFICATION_URL, "expires_in": 1800, "interval": 5 });
    for (field, bad) in [
        ("user_code", json!("ABCD\u{1b}[2J")),
        ("user_code", json!("")),
        ("verification_url", json!("http://www.google.com/device")),
        ("verification_url", json!("javascript:alert(1)")),
        ("device_code", json!("")),
        ("expires_in", json!("soon")),
        ("interval", json!(0)),
    ] {
        let mut body = good.clone();
        body[field] = bad.clone();
        let (server, ep) = stub(200, "application/json", body.to_string().as_bytes(), &[]).await;
        let printed = Printed::default();
        let (o, opened) = opts(&printed, false);
        let e = err(auth::login_interactive(&http, &ep, o).await);
        assert!(
            matches!(&e, AuthError::Network(msg) if msg.contains("unexpected answer")),
            "{field} = {bad}: {e:?}"
        );
        assert!(printed.lines().is_empty(), "{field}: {}", printed.text());
        assert!(opened.lock().unwrap().is_empty(), "{field}");
        assert_eq!(stub_hits(&server).await, 1, "{field}: no poll");
    }
}

/// One raw `POST /device/poll`: the status and the error code of the answer.
async fn raw_poll(ep: &AuthEndpoints, device_code: &str) -> (u16, String) {
    let response = reqwest::Client::new()
        .post(format!("{}/device/poll", ep.base))
        .json(&json!({ "device_code": device_code }))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body: Value = response.json().await.unwrap();
    (status, body["error"].as_str().unwrap_or("").to_string())
}

/// The fake holds a login to the two timing rules of the grant as Google does: a poll that
/// comes sooner than `interval` after the previous one is `slow_down`, and a code runs out.
#[tokio::test]
async fn the_fake_enforces_the_poll_interval_and_the_lifetime_of_a_code() {
    let fake = FakeDrive::start().await;
    let (http, ep) = (http(), fake.auth());
    // Wide margins: "too early" has 300 ms to spare, "late enough" 30 ms.
    let interval = Duration::from_millis(400);
    let pending = (400, "authorization_pending".to_string());
    let slow_down = (400, "slow_down".to_string());

    fake.set_poll_interval(0.4);
    let started = auth::device_start(&http, &ep).await.unwrap();
    assert_eq!(started.interval, interval);
    // The first poll has no previous one; the second comes at once: too early.
    assert_eq!(raw_poll(&ep, &started.device_code).await, pending);
    assert_eq!(raw_poll(&ep, &started.device_code).await, slow_down);
    assert_eq!(fake.early_polls(), 1);
    // … and that poll counts as the previous one of the next.
    tokio::time::sleep(interval / 4).await;
    assert_eq!(raw_poll(&ep, &started.device_code).await, slow_down);
    tokio::time::sleep(interval + Duration::from_millis(30)).await;
    assert_eq!(raw_poll(&ep, &started.device_code).await, pending);
    // A poll that comes too early does not redeem an approved code either.
    fake.approve(&started.user_code);
    assert_eq!(raw_poll(&ep, &started.device_code).await, slow_down);
    assert!(fake.issued_refresh_tokens().is_empty());
    assert_eq!(fake.early_polls(), 3);
    tokio::time::sleep(interval + Duration::from_millis(30)).await;
    assert_eq!(raw_poll(&ep, &started.device_code).await.0, 200);
    assert_eq!(fake.issued_refresh_tokens(), ["rt-1"]);
    // Used: the state of the code, whatever the timing.
    assert_eq!(
        raw_poll(&ep, &started.device_code).await,
        (400, "invalid_grant".to_string())
    );

    // A code runs out by itself, entered or not; another login has its own clock.
    fake.set_poll_interval(0.02);
    fake.set_code_lifetime(0.6);
    let (short, approved) = (
        auth::device_start(&http, &ep).await.unwrap(),
        auth::device_start(&http, &ep).await.unwrap(),
    );
    fake.set_code_lifetime(1800.0);
    let lasting = auth::device_start(&http, &ep).await.unwrap();
    assert_eq!(raw_poll(&ep, &short.device_code).await, pending);
    fake.approve(&approved.user_code);
    tokio::time::sleep(Duration::from_millis(630)).await;
    let expired = (400, "expired_token".to_string());
    assert_eq!(raw_poll(&ep, &short.device_code).await, expired);
    assert_eq!(raw_poll(&ep, &approved.device_code).await, expired);
    assert_eq!(raw_poll(&ep, &lasting.device_code).await, pending);
    assert_eq!(fake.issued_refresh_tokens(), ["rt-1"]);
}

/// The device never polls sooner than the interval it was told — against a server that
/// would answer `slow_down` if it did, as Google does.
#[tokio::test]
async fn the_device_keeps_to_the_poll_interval() {
    let fake = FakeDrive::start().await;
    let interval = Duration::from_millis(300);
    fake.set_poll_interval(0.3);
    let printed = Printed::default();
    let login = spawn_login(&fake, &printed);
    let user_code = printed.user_code().await;
    while fake.hits(Route::AuthPoll) < 4 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    fake.approve(&user_code);
    assert_eq!(login.await.unwrap().unwrap().refresh_token, "rt-1");

    let start = fake.requests(Route::AuthStart)[0].at;
    let polls: Vec<Instant> = fake
        .requests(Route::AuthPoll)
        .iter()
        .map(|poll| poll.at)
        .collect();
    let n = polls.len();
    assert_eq!(
        n, 5,
        "four polls while nobody had entered the code, one after"
    );
    // The first poll comes no earlier than one interval after /device/start …
    assert!(
        polls[0].duration_since(start) >= interval,
        "{:?}",
        polls[0].duration_since(start)
    );
    // … and each one no earlier than one interval after the one before.
    for pair in polls.windows(2) {
        let gap = pair[1].duration_since(pair[0]);
        assert!(gap >= interval, "{gap:?}");
    }
    assert!(polls[n - 1].duration_since(polls[0]) >= interval * (n as u32 - 1));
    assert_eq!(fake.early_polls(), 0, "the fake never had to say slow_down");
    assert_eq!(printed.retry_notes(), 0);
}

/// RFC 8628 §3.5: polls that fail are spaced further and further apart, and the first poll
/// that gets an answer about the login ends the back-off.
#[tokio::test]
async fn failed_polls_back_off() {
    let fake = FakeDrive::start().await;
    let (http, ep) = (http(), fake.auth());
    let interval = Duration::from_millis(40);
    fake.set_poll_interval(0.04);
    // A Worker that cannot reach Google (or that Google is rate-limiting), four times.
    fake.fail_next(Route::AuthPoll, 4, 502, "upstream_error");
    let started = auth::device_start(&http, &ep).await.unwrap();
    let printed = Printed::default();
    let note = printed.printer();
    let wait_ep = ep.clone();
    let login =
        tokio::spawn(async move { auth::device_wait(&http, &wait_ep, &started, &*note).await });
    // Four failures, then two polls that are answered "not yet".
    while fake.hits(Route::AuthPoll) < 6 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    fake.approve(&fake.last_user_code().unwrap());
    assert_eq!(login.await.unwrap().unwrap().refresh_token, "rt-1");

    let start = fake.requests(Route::AuthStart)[0].at;
    let polls: Vec<Instant> = fake
        .requests(Route::AuthPoll)
        .iter()
        .map(|poll| poll.at)
        .collect();
    assert!(polls.len() >= 7, "{}", polls.len());
    let gaps: Vec<Duration> = polls
        .windows(2)
        .map(|pair| pair[1].duration_since(pair[0]))
        .collect();
    assert!(polls[0].duration_since(start) >= interval);
    // After the n-th failure in a row the device stays away 2^n intervals.
    for (n, gap) in gaps[..4].iter().enumerate() {
        let least = interval * 2u32.pow(n as u32 + 1);
        assert!(
            *gap >= least,
            "gap {n}: {gap:?}, expected at least {least:?}"
        );
    }
    // The poll after the fourth failure was answered: back to the plain interval (not 32 of
    // them, which is what the next pause would have been).
    assert!(
        gaps[4] >= interval && gaps[4] < interval * 12,
        "{:?}",
        gaps[4]
    );
    assert_eq!(fake.early_polls(), 0);
    assert_eq!(printed.retry_notes(), 1, "{}", printed.text());
}

/// Google has issued the grant — the device code is used up — and the Worker cannot hand it
/// out (here: no ID token in Google's answer). The login ends at once with that reason; the
/// device does not poll the dead code again, which would only get "no longer valid".
#[tokio::test]
async fn a_grant_the_worker_cannot_use_ends_the_login_with_its_reason() {
    let fake = FakeDrive::start().await;
    let (http, ep) = (http(), fake.auth());
    fake.omit_id_token();
    let started = auth::device_start(&http, &ep).await.unwrap();
    fake.approve(&started.user_code);
    let printed = Printed::default();
    let e = err(auth::device_wait(&http, &ep, &started, &*printed.printer()).await);
    assert!(
        matches!(&e, AuthError::LoginFailed(msg) if msg.contains("no ID token") && msg.contains("Google approved the sign-in")),
        "{e:?}"
    );
    assert_eq!(fake.hits(Route::AuthPoll), 1, "one poll, not a second one");
    assert_eq!(printed.retry_notes(), 0, "{}", printed.text());
    assert!(fake.issued_refresh_tokens().is_empty());
    // The code was consumed by that answer, as at Google: this is what polling on would get.
    let e = err(wait(&ep, &started).await);
    assert!(
        matches!(&e, AuthError::LoginFailed(msg) if msg.contains("no longer valid")),
        "{e:?}"
    );

    // The same answer under a 502 would be polled again: the code must be 403.
    let (server, stub_ep) = stub(
        403,
        "application/json; charset=utf-8",
        br#"{"error":"grant_unusable","message":"Google approved the sign-in, but its answer carried no refresh token, so nothing was handed out and the code is used up."}"#,
        &[],
    )
    .await;
    let e = err(wait(&stub_ep, &code("dc-any-xxxxxxxxxxxxxxxx", 2000)).await);
    assert!(
        matches!(&e, AuthError::LoginFailed(msg) if msg.contains("no refresh token")),
        "{e:?}"
    );
    assert_eq!(stub_hits(&server).await, 1);
}

/// The address to open is the Worker's word. One that is not Google's is shown with a
/// warning and is not opened: a Worker (or whoever answers under its name) cannot put a page
/// of its choice in front of the user.
#[tokio::test]
async fn an_address_that_is_not_googles_is_not_opened() {
    for url in [
        "https://sign-in.example.net/device",
        "https://www.google.com.example.net/device",
    ] {
        let fake = FakeDrive::start().await;
        fake.set_verification_url(url);
        let printed = Printed::default();
        let (o, opened) = opts(&printed, false);
        let ep = fake.auth();
        let login = tokio::spawn(async move { auth::login_interactive(&http(), &ep, o).await });
        let user_code = printed.user_code().await;
        fake.approve(&user_code);
        // The login itself still works: Google may move its page one day.
        assert_eq!(login.await.unwrap().unwrap().refresh_token, "rt-1");
        assert_eq!(
            printed.lines(),
            [
                format!("To sign in, open  {url}"),
                format!("{ENTER_THE_CODE}{user_code}"),
                NOT_GOOGLE_NOTE.to_string(),
                "(enter only a code shown in this terminal; waiting…)".to_string(),
            ]
        );
        assert!(NOT_GOOGLE_NOTE.contains("not a google.com address"));
        assert!(opened.lock().unwrap().is_empty(), "{url} was opened");
    }
    // An address that reads like Google's and is another host is not shown at all.
    let body = json!({ "device_code": "dc-1-xxxxxxxxxxxxxxxx", "user_code": "ABCD-EFGH",
                       "verification_url": "https://www.google.com@example.net/device",
                       "expires_in": 1800, "interval": 5 });
    let (_server, ep) = stub(200, "application/json", body.to_string().as_bytes(), &[]).await;
    let printed = Printed::default();
    let (o, opened) = opts(&printed, false);
    let e = err(auth::login_interactive(&http(), &ep, o).await);
    assert!(matches!(e, AuthError::Network(_)), "{e:?}");
    assert!(printed.lines().is_empty() && opened.lock().unwrap().is_empty());
}

// ---------------------------------------------------------------------------------------------
// refresh, revoke
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn refresh_maps_the_workers_answers() {
    let fake = FakeDrive::start().await;
    let (http, ep) = (http(), fake.auth());
    let device = AuthClient::Device;
    let ok: AccessGrant = auth::refresh(&http, &ep, "rt-ok", device).await.unwrap();
    assert!(ok.access_token.starts_with("at-"));
    assert!(
        ok.expires_at_ms
            .abs_diff(gclone::util::now_ms() + 3_599_000)
            < 10_000
    );
    let seen = &fake.requests(Route::AuthRefresh)[0];
    assert_eq!(
        (seen.method.as_str(), seen.path.as_str()),
        ("POST", "/auth/refresh")
    );
    assert_eq!(
        seen.json,
        Some(json!({ "refresh_token": "rt-ok", "client": "device" }))
    );

    // a token Google never issued; a string the Worker's pre-filter refuses
    assert!(matches!(
        err(auth::refresh(&http, &ep, "1//0unknown-but-well-formed-token", device).await),
        AuthError::Expired
    ));
    let e = err(auth::refresh(&http, &ep, "not a refresh token", device).await);
    assert!(
        matches!(&e, AuthError::Network(msg) if msg.contains("unexpected answer")),
        "{e:?}"
    );

    fake.revoke_refresh_token();
    assert!(matches!(
        err(auth::refresh(&http, &ep, "rt-ok", device).await),
        AuthError::Expired
    ));

    let fake = FakeDrive::start().await;
    fake.break_client();
    let e = err(auth::refresh(&http, &fake.auth(), "rt-ok", device).await);
    assert!(matches!(e, AuthError::WorkerMisconfigured(_)), "{e:?}");
    assert_eq!(
        fake.hits(Route::AuthRefresh),
        1,
        "a broken client is not retried"
    );
    fake.fail_next(Route::AuthRefresh, 1, 500, "server_misconfigured");
    assert!(matches!(
        err(auth::refresh(&http, &fake.auth(), "rt-ok", device).await),
        AuthError::WorkerMisconfigured(_)
    ));
}

/// The transition of 0.2.0: a login made before it belongs to the Worker's legacy client, and
/// the device says so by sending no `client` field.
#[tokio::test]
async fn a_legacy_login_refreshes_only_while_the_worker_keeps_the_legacy_client() {
    let fake = FakeDrive::start().await;
    let (http, ep) = (http(), fake.auth());
    let legacy_token = fake.add_legacy_token();

    // The Worker has the legacy secrets: the old token goes on working.
    fake.set_legacy_client(true);
    assert!(
        auth::refresh(&http, &ep, &legacy_token, AuthClient::Legacy)
            .await
            .is_ok()
    );
    let seen = fake.requests(Route::AuthRefresh);
    assert_eq!(
        seen[0].json,
        Some(json!({ "refresh_token": legacy_token })),
        "no client field at all"
    );
    // through the provider, as every command uses it
    let provider = TokenProvider::new(
        http.clone(),
        ep.clone(),
        legacy_token.clone(),
        AuthClient::Legacy,
        None,
    );
    assert!(provider.access_token().await.unwrap().starts_with("at-"));
    assert!(
        fake.requests(Route::AuthRefresh)[1]
            .json
            .as_ref()
            .unwrap()
            .get("client")
            .is_none()
    );
    // Each token under its own client only.
    assert!(matches!(
        err(auth::refresh(&http, &ep, &legacy_token, AuthClient::Device).await),
        AuthError::Expired
    ));
    assert!(matches!(
        err(auth::refresh(&http, &ep, "rt-ok", AuthClient::Legacy).await),
        AuthError::Expired
    ));
    assert!(
        auth::refresh(&http, &ep, "rt-ok", AuthClient::Device)
            .await
            .is_ok()
    );

    // Only one of the two legacy secrets is there (the Worker's owner is in the middle of
    // putting or deleting the pair): a legacy login is told so — it is not asked to log in
    // again — and everything of the device client goes on working.
    fake.set_legacy_client_half_set();
    let hits = fake.hits(Route::AuthRefresh);
    let e = err(auth::refresh(&http, &ep, &legacy_token, AuthClient::Legacy).await);
    assert!(
        matches!(&e, AuthError::WorkerMisconfigured(msg) if msg.contains("GOOGLE_LEGACY_CLIENT_SECRET")),
        "{e:?}"
    );
    assert_eq!(fake.hits(Route::AuthRefresh), hits + 1);
    assert!(
        auth::refresh(&http, &ep, "rt-ok", AuthClient::Device)
            .await
            .is_ok()
    );
    assert!(login_tokens(&fake).await.refresh_token.starts_with("rt-"));

    // The legacy secrets are gone: "run `gclone login`", at once and without a retry.
    fake.set_legacy_client(false);
    let hits = fake.hits(Route::AuthRefresh);
    let e = err(auth::refresh(&http, &ep, &legacy_token, AuthClient::Legacy).await);
    assert!(matches!(e, AuthError::Expired), "{e:?}");
    assert!(e.to_string().contains("run `gclone login`"));
    assert_eq!(fake.hits(Route::AuthRefresh), hits + 1);
    // A login of the device client is not affected.
    assert!(
        auth::refresh(&http, &ep, "rt-ok", AuthClient::Device)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn refresh_retries_server_errors_and_one_429() {
    let http = http();
    let refresh = |fake: &FakeDrive| {
        let (http, ep) = (http.clone(), fake.auth());
        async move { auth::refresh(&http, &ep, "rt-ok", AuthClient::Device).await }
    };
    // a 502 is retried and then succeeds; so is a 500 without a mapped code and an HTML 503
    let fake = FakeDrive::start().await;
    fake.fail_next(Route::AuthRefresh, 1, 502, "upstream_error");
    fake.fail_next(Route::AuthRefresh, 1, 500, "internal_error");
    fake.fail_next_raw(Route::AuthRefresh, 1, 503, "<html>down</html>");
    assert!(refresh(&fake).await.is_ok());
    assert_eq!(fake.hits(Route::AuthRefresh), 4);

    // five failures are the end
    let fake = FakeDrive::start().await;
    fake.fail_next(Route::AuthRefresh, u32::MAX, 502, "upstream_error");
    let e = err(refresh(&fake).await);
    assert!(
        matches!(&e, AuthError::Network(msg) if msg.contains("502")),
        "{e:?}"
    );
    assert_eq!(fake.hits(Route::AuthRefresh), 5);

    // one 429 is waited out, two are not
    let fake = FakeDrive::start().await;
    fake.fail_next(Route::AuthRefresh, 1, 429, "rate_limited");
    let started = Instant::now();
    assert!(refresh(&fake).await.is_ok());
    assert_eq!(fake.hits(Route::AuthRefresh), 2);
    assert!(started.elapsed() >= Duration::from_millis(900));
    fake.fail_next(Route::AuthRefresh, 2, 429, "rate_limited");
    let e = err(refresh(&fake).await);
    assert!(
        matches!(&e, AuthError::Network(msg) if msg.contains("rate-limiting")),
        "{e:?}"
    );
    assert_eq!(fake.hits(Route::AuthRefresh), 4);
}

#[tokio::test]
async fn a_redirect_from_the_worker_is_an_error_and_is_not_followed() {
    let fake = FakeDrive::start().await;
    let http = http();
    // The injected 3xx points back at the route itself: following it would succeed.
    for status in [301, 302, 303, 307, 308] {
        let hits = fake.hits(Route::AuthRefresh);
        fake.fail_next_raw(Route::AuthRefresh, 1, status, "");
        let e = err(auth::refresh(&http, &fake.auth(), "rt-ok", AuthClient::Device).await);
        assert!(
            matches!(&e, AuthError::Network(msg) if msg.contains("unexpected answer")),
            "{status}: {e:?}"
        );
        assert_eq!(
            fake.hits(Route::AuthRefresh),
            hits + 1,
            "{status}: neither followed nor retried"
        );
    }
    fake.fail_next_raw(Route::AuthStart, 1, 302, "");
    let e = err(auth::device_start(&http, &fake.auth()).await);
    assert!(
        matches!(&e, AuthError::Network(msg) if msg.contains("unexpected answer")),
        "{e:?}"
    );
    assert_eq!(fake.hits(Route::AuthStart), 1);
    // … and a redirected poll ends the login: the device code is not sent anywhere else.
    let started = auth::device_start(&http, &fake.auth()).await.unwrap();
    fake.approve(&started.user_code);
    fake.fail_next_raw(Route::AuthPoll, 1, 307, "");
    let e = err(wait(&fake.auth(), &started).await);
    assert!(
        matches!(&e, AuthError::Network(msg) if msg.contains("unexpected answer")),
        "{e:?}"
    );
    assert_eq!(fake.hits(Route::AuthPoll), 1);
    assert!(fake.issued_refresh_tokens().is_empty());
}

#[tokio::test]
async fn two_logins_give_two_refresh_tokens_that_both_work() {
    let fake = FakeDrive::start().await;
    let (http, ep) = (http(), fake.auth());
    let (a, b) = (login_tokens(&fake).await, login_tokens(&fake).await);
    assert_ne!(a.refresh_token, b.refresh_token);
    assert_ne!(a.access_token, b.access_token);
    assert_eq!(
        fake.issued_refresh_tokens(),
        [a.refresh_token.clone(), b.refresh_token.clone()]
    );
    for _ in 0..2 {
        for token in [&a.refresh_token, &b.refresh_token] {
            assert!(
                auth::refresh(&http, &ep, token, AuthClient::Device)
                    .await
                    .is_ok()
            );
        }
    }
    // both devices reach Drive side by side
    for grant in [&a, &b] {
        let backend = fake.backend_with(
            fake.token_provider_for(&grant.refresh_token),
            fake_drive::fast_pacer(),
        );
        use gclone::backend::Backend;
        backend.about().await.unwrap();
    }
}

#[tokio::test]
async fn revoke_is_grant_wide() {
    let fake = FakeDrive::start().await;
    let (http, ep) = (http(), fake.auth());
    let (a, b) = (login_tokens(&fake).await, login_tokens(&fake).await);

    assert!(auth::revoke(&http, &ep, &a.refresh_token).await.unwrap());
    let seen = &fake.requests(Route::Revoke)[0];
    assert_eq!(
        (seen.method.as_str(), seen.path.as_str()),
        ("POST", "/revoke")
    );
    assert_eq!(
        seen.headers["content-type"],
        "application/x-www-form-urlencoded"
    );
    assert_eq!(
        seen.text.as_deref(),
        Some(format!("token={}", a.refresh_token).as_str())
    );
    assert!(
        !seen.headers.contains_key("authorization"),
        "no client credentials, no bearer"
    );
    assert_eq!(fake.revoked(), std::slice::from_ref(&a.refresh_token));

    // every device is signed out, not only the one whose token was posted
    for token in [&a.refresh_token, &b.refresh_token, &"rt-ok".to_string()] {
        assert!(
            matches!(
                err(auth::refresh(&http, &ep, token, AuthClient::Device).await),
                AuthError::Expired
            ),
            "{token}"
        );
    }
    // already revoked, or never known: Ok(false)
    assert!(!auth::revoke(&http, &ep, &a.refresh_token).await.unwrap());
    assert!(!auth::revoke(&http, &ep, "1//never-issued").await.unwrap());
    assert_eq!(fake.revoked().len(), 1);
    // a new login works again
    let c = login_tokens(&fake).await;
    assert!(
        auth::refresh(&http, &ep, &c.refresh_token, AuthClient::Device)
            .await
            .is_ok()
    );

    // anything else is a network error and the caller keeps its secrets
    fake.fail_next(Route::Revoke, 1, 503, "backend_error");
    assert!(matches!(
        auth::revoke(&http, &ep, &c.refresh_token).await,
        Err(AuthError::Network(_))
    ));
    let dead = AuthEndpoints {
        base: ep.base.clone(),
        revoke_url: "http://127.0.0.1:1/revoke".into(),
    };
    assert!(matches!(
        auth::revoke(&http, &dead, "t").await,
        Err(AuthError::Network(_))
    ));
    // a token with characters that need form encoding arrives intact
    assert!(!auth::revoke(&http, &ep, "1//a+b/c=d&e").await.unwrap());
    assert_eq!(
        fake.requests(Route::Revoke).last().unwrap().text.as_deref(),
        Some("token=1%2F%2Fa%2Bb%2Fc%3Dd%26e")
    );
}

// ---------------------------------------------------------------------------------------------
// TokenProvider
// ---------------------------------------------------------------------------------------------

fn provider(fake: &FakeDrive, cache: Option<&Path>) -> TokenProvider {
    TokenProvider::new(
        http(),
        fake.auth(),
        "rt-ok".into(),
        AuthClient::Device,
        cache.map(Path::to_path_buf),
    )
}

#[tokio::test]
async fn token_cache_file_is_reused_across_instances() {
    let fake = FakeDrive::start().await;
    let (_tmp, dir) = private_dir();
    let cache = dir.join("token.json");

    let first = provider(&fake, Some(&cache));
    assert!(first.last_refresh_ms().is_none());
    let token = first.access_token().await.unwrap();
    assert_eq!(
        first.access_token().await.unwrap(),
        token,
        "cached in memory"
    );
    assert_eq!(fake.hits(Route::AuthRefresh), 1);
    let refreshed = first.last_refresh_ms().unwrap();
    assert!(refreshed.abs_diff(gclone::util::now_ms()) < 10_000);

    // token.json: 0600, the three keys of §8.2
    assert_eq!(mode(&cache), 0o600);
    let on_disk: Value = serde_json::from_slice(&std::fs::read(&cache).unwrap()).unwrap();
    let keys: Vec<&String> = on_disk.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["access_token", "expires_at_ms", "refreshed_at_ms"]);
    assert_eq!(on_disk["access_token"], json!(token));
    assert_eq!(on_disk["refreshed_at_ms"], json!(refreshed));
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        1,
        "no temp file left behind"
    );

    // a second process: no request to the Worker at all
    let second = provider(&fake, Some(&cache));
    assert_eq!(second.access_token().await.unwrap(), token);
    assert_eq!(second.last_refresh_ms(), Some(refreshed));
    assert_eq!(fake.hits(Route::AuthRefresh), 1);

    // a forced refresh rewrites the file
    let newer = second.force_refresh().await.unwrap();
    assert_ne!(newer, token);
    assert_eq!(fake.hits(Route::AuthRefresh), 2);
    let on_disk: Value = serde_json::from_slice(&std::fs::read(&cache).unwrap()).unwrap();
    assert_eq!(on_disk["access_token"], json!(newer));
    assert_eq!(
        provider(&fake, Some(&cache)).access_token().await.unwrap(),
        newer
    );

    // a cached token inside the 60 s skew, or past its expiry, is not used
    for left_ms in [30_000i64, -5_000] {
        let expires = (gclone::util::now_ms() as i64 + left_ms) as u64;
        let stale = json!({ "access_token": "at-stale", "expires_at_ms": expires, "refreshed_at_ms": 1_700_000_000_000u64 });
        gclone::util::write_atomic(&cache, stale.to_string().as_bytes(), 0o600).unwrap();
        let p = provider(&fake, Some(&cache));
        assert_eq!(
            p.last_refresh_ms(),
            Some(1_700_000_000_000),
            "the time of the last refresh is still known"
        );
        let hits = fake.hits(Route::AuthRefresh);
        assert_ne!(p.access_token().await.unwrap(), "at-stale");
        assert_eq!(fake.hits(Route::AuthRefresh), hits + 1);
    }
}

#[tokio::test]
async fn prime_avoids_a_refresh_and_writes_no_file() {
    let fake = FakeDrive::start().await;
    let (_tmp, dir) = private_dir();
    let cache = dir.join("token.json");
    let grant = login_tokens(&fake).await;

    let p = TokenProvider::new(
        http(),
        fake.auth(),
        grant.refresh_token.clone(),
        AuthClient::Device,
        Some(cache.clone()),
    );
    p.prime(&grant.access_token, grant.expires_at_ms);
    assert_eq!(p.access_token().await.unwrap(), grant.access_token);
    assert_eq!(
        fake.hits(Route::AuthRefresh),
        0,
        "no /refresh round trip after a login"
    );
    assert!(!cache.exists(), "prime is memory-only");
    assert!(
        p.last_refresh_ms().is_none(),
        "a primed token is not a refresh"
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);

    // the file appears only after a real refresh
    let fresh = p.force_refresh().await.unwrap();
    assert_ne!(fresh, grant.access_token);
    assert_eq!(fake.hits(Route::AuthRefresh), 1);
    assert!(cache.exists());
    assert_eq!(mode(&cache), 0o600);
    assert!(p.last_refresh_ms().is_some());

    // a primed token that is about to expire is refreshed like any other
    let p = TokenProvider::new(
        http(),
        fake.auth(),
        grant.refresh_token.clone(),
        AuthClient::Device,
        None,
    );
    p.prime("at-short", gclone::util::now_ms() + 10_000);
    assert_ne!(p.access_token().await.unwrap(), "at-short");
}

#[tokio::test]
async fn without_a_cache_file_nothing_is_written() {
    let fake = FakeDrive::start().await;
    let (_tmp, dir) = private_dir();
    let p = provider(&fake, None);
    p.prime("at-primed", gclone::util::now_ms() + 3_600_000);
    assert_eq!(p.access_token().await.unwrap(), "at-primed");
    p.force_refresh().await.unwrap();
    p.access_token().await.unwrap();
    assert_eq!(fake.hits(Route::AuthRefresh), 1);
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    // memory-only: the next instance refreshes again
    provider(&fake, None).access_token().await.unwrap();
    assert_eq!(fake.hits(Route::AuthRefresh), 2);

    // a cache path whose directory does not exist: tokens still work, nothing is created
    let missing = dir.join("no-such-dir").join("token.json");
    let p = provider(&fake, Some(&missing));
    p.access_token().await.unwrap();
    assert!(!missing.exists() && !missing.parent().unwrap().exists());
}

#[tokio::test]
async fn an_insecure_cache_file_is_ignored_and_replaced() {
    let fake = FakeDrive::start().await;
    let good = |token: &str| {
        json!({ "access_token": token, "expires_at_ms": gclone::util::now_ms() + 3_000_000, "refreshed_at_ms": 5 })
            .to_string()
            .into_bytes()
    };

    // 0644 (and 0640, 0604): readable by others → not used, replaced by a 0600 file
    for bits in [0o644, 0o640, 0o604, 0o660] {
        let (_tmp, dir) = private_dir();
        let cache = dir.join("token.json");
        std::fs::write(&cache, good("at-planted")).unwrap();
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(bits)).unwrap();
        let p = provider(&fake, Some(&cache));
        assert!(
            p.last_refresh_ms().is_none(),
            "{bits:o}: nothing was loaded"
        );
        let hits = fake.hits(Route::AuthRefresh);
        let token = p.access_token().await.unwrap();
        assert_ne!(token, "at-planted", "{bits:o}");
        assert_eq!(fake.hits(Route::AuthRefresh), hits + 1);
        assert_eq!(mode(&cache), 0o600, "{bits:o}: replaced, not chmod-ed");
        assert_eq!(
            provider(&fake, Some(&cache)).access_token().await.unwrap(),
            token
        );
    }

    // a private file is used
    let (_tmp, dir) = private_dir();
    let cache = dir.join("token.json");
    gclone::util::write_atomic(&cache, &good("at-kept"), 0o600).unwrap();
    assert_eq!(
        provider(&fake, Some(&cache)).access_token().await.unwrap(),
        "at-kept"
    );

    // … unless its directory is open to others (§8.1)
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_ne!(
        provider(&fake, Some(&cache)).access_token().await.unwrap(),
        "at-kept"
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    // a symlink is not followed; garbage and other JSON are not a cache
    let target = dir.join("elsewhere.json");
    gclone::util::write_atomic(&target, &good("at-linked"), 0o600).unwrap();
    let link = dir.join("link.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_ne!(
        provider(&fake, Some(&link)).access_token().await.unwrap(),
        "at-linked"
    );
    for garbage in [&b"not json"[..], b"{}", b"[]", br#"{"access_token":5}"#] {
        gclone::util::write_atomic(&cache, garbage, 0o600).unwrap();
        let p = provider(&fake, Some(&cache));
        assert!(p.access_token().await.unwrap().starts_with("at-"));
    }
}

#[tokio::test]
async fn concurrent_callers_share_one_refresh() {
    let fake = FakeDrive::start().await;
    let p = Arc::new(provider(&fake, None));
    let calls = (0..24).map(|_| {
        let p = p.clone();
        tokio::spawn(async move { p.access_token().await.unwrap() })
    });
    let tokens: Vec<String> = futures_util::future::join_all(calls)
        .await
        .into_iter()
        .map(|t| t.unwrap())
        .collect();
    assert_eq!(fake.hits(Route::AuthRefresh), 1, "single-flight");
    assert!(tokens.iter().all(|t| *t == tokens[0]));

    // the same for requests that all got a 401 with that token
    let calls = (0..24).map(|_| {
        let p = p.clone();
        tokio::spawn(async move { p.force_refresh().await.unwrap() })
    });
    let fresh: Vec<String> = futures_util::future::join_all(calls)
        .await
        .into_iter()
        .map(|t| t.unwrap())
        .collect();
    assert_eq!(fake.hits(Route::AuthRefresh), 2);
    assert!(fresh.iter().all(|t| *t == fresh[0] && *t != tokens[0]));

    // an error reaches every waiting caller and is not cached
    fake.revoke_refresh_token();
    let failed = Arc::new(AtomicBool::new(true));
    for _ in 0..3 {
        failed.fetch_and(
            matches!(p.force_refresh().await, Err(AuthError::Expired)),
            Ordering::SeqCst,
        );
    }
    assert!(failed.load(Ordering::SeqCst));
}

// ---------------------------------------------------------------------------------------------
// The contract fixture worker/test/contract.json (§16.5)
// ---------------------------------------------------------------------------------------------

const GIVEN: [&str; 23] = [
    "none",
    "pending",
    "slow_down",
    "denied",
    "expired",
    "used",
    "approved",
    "approved_expiring",
    "approved_other_account",
    "approved_no_drive_scope",
    "approved_wide_scope",
    "approved_no_id_token",
    "refresh_token",
    "refresh_revoked",
    "refresh_wide_scope",
    "legacy_token",
    "legacy_unconfigured",
    "legacy_half_set",
    "legacy_half_set_device_token",
    "client_broken",
    "google_down",
    "rate_limited",
    "unconfigured",
];

const REQUIRED_CASES: [&str; 48] = [
    "start_ok",
    "start_client_invalid",
    "start_upstream",
    "start_rate_limited",
    "start_unconfigured",
    "start_wrong_content_type",
    "start_get",
    "poll_pending",
    "poll_slow_down",
    "poll_denied",
    "poll_expired",
    "poll_used",
    "poll_ok",
    "poll_expiring",
    "poll_email_not_allowed",
    "poll_scope_missing",
    "poll_scope_not_allowed",
    "poll_grant_unusable",
    "poll_client_invalid",
    "poll_upstream",
    "poll_rate_limited",
    "poll_unconfigured",
    "poll_wrong_content_type",
    "poll_too_large",
    "poll_not_json",
    "poll_missing_field",
    "poll_malformed_code",
    "poll_get",
    "refresh_ok",
    "refresh_legacy_ok",
    "refresh_legacy_unconfigured",
    "refresh_legacy_half_set",
    "refresh_half_set_device_ok",
    "refresh_bad_client",
    "refresh_invalid_grant",
    "refresh_malformed_token",
    "refresh_scope_not_allowed",
    "refresh_client_invalid",
    "refresh_upstream",
    "refresh_rate_limited",
    "refresh_unconfigured",
    "refresh_get",
    "not_found",
    // the routes of the browser sign-in before 0.2.0 are gone
    "login_gone",
    "callback_gone",
    "token_gone",
    // delivered beyond the required list
    "start_not_json",
    "refresh_missing_field",
];

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Contract {
    version: u32,
    cases: Vec<Case>,
}

/// `request` and `response` stay raw so that the runner — not the loader — refuses what it
/// does not know, case by case.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    given: String,
    request: Value,
    response: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WantedRequest {
    method: String,
    path: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    json: Option<Value>,
    body: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WantedResponse {
    status: u16,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    json: Option<serde_json::Map<String, Value>>,
}

fn contract() -> Contract {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/worker/test/contract.json"
    ))
    .expect("worker/test/contract.json (written by WP8)");
    serde_json::from_str(&text).expect("contract.json in the format of SPEC §16.5")
}

/// What the fake answered to a case's request.
struct Answered {
    status: u16,
    content_type: String,
    retry_after: Option<String>,
    body: Vec<u8>,
}

fn placeholders(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find('<') {
        rest = &rest[at + 1..];
        if let Some(end) = rest.find('>') {
            let name = &rest[..end];
            if !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
                found.push(format!("<{name}>"));
            }
        }
    }
    found
}

/// Reproduces one case against a fresh fake's auth routes with a plain HTTP client and checks
/// the answer. `Err` names the first thing that is wrong — or that this runner does not know.
async fn run_case(case: &Case) -> Result<Answered, String> {
    let request: WantedRequest = serde_json::from_value(case.request.clone())
        .map_err(|e| format!("request: unknown key or shape: {e}"))?;
    let want: WantedResponse = serde_json::from_value(case.response.clone())
        .map_err(|e| format!("response: unknown key or shape: {e}"))?;
    let given = case.given.as_str();
    if !GIVEN.contains(&given) {
        return Err(format!("unknown given {given:?}"));
    }
    if request.json.is_some() && request.body.is_some() {
        return Err("both json and body".into());
    }
    let route = match request.path.as_str() {
        "/device/start" => Some(Route::AuthStart),
        "/device/poll" => Some(Route::AuthPoll),
        "/refresh" => Some(Route::AuthRefresh),
        _ => None,
    };
    let fake = FakeDrive::start().await;
    let (ep, client) = (fake.auth(), http());
    // No redirect following: what the Worker answers is what is compared.
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Placeholders this side produces from its own implementation — before the given state.
    let request_text = case.request.to_string();
    let mut values: BTreeMap<&str, String> = BTreeMap::new();
    if request_text.contains("<device_code>") {
        match given {
            "approved_other_account" => fake.set_login_email("stranger@example.com"),
            "approved_no_drive_scope" => {
                fake.set_granted_scope("openid https://www.googleapis.com/auth/userinfo.email")
            }
            "approved_wide_scope" => fake.set_granted_scope(WIDE_SCOPE),
            "approved_expiring" => fake.set_refresh_expires_in(Some(604_799)),
            "approved_no_id_token" => fake.omit_id_token(),
            _ => {}
        }
        let started = auth::device_start(&client, &ep)
            .await
            .map_err(|e| e.to_string())?;
        match given {
            "slow_down" => fake.slow_down(1),
            "denied" => fake.deny(&started.user_code),
            "expired" => fake.expire_codes(),
            "used" => {
                fake.approve(&started.user_code);
                wait(&ep, &started).await.map_err(|e| e.to_string())?;
            }
            g if g.starts_with("approved") => fake.approve(&started.user_code),
            _ => {}
        }
        values.insert("<device_code>", started.device_code);
    }
    if request_text.contains("<refresh_token>") {
        let token = match given {
            "legacy_token" | "legacy_unconfigured" => {
                fake.set_legacy_client(given == "legacy_token");
                fake.add_legacy_token()
            }
            "legacy_half_set" => {
                fake.set_legacy_client_half_set();
                fake.add_legacy_token()
            }
            _ => {
                if given == "legacy_half_set_device_token" {
                    fake.set_legacy_client_half_set();
                }
                try_login(&fake)
                    .await
                    .map_err(|e| e.to_string())?
                    .refresh_token
            }
        };
        values.insert("<refresh_token>", token);
        if given == "refresh_revoked" {
            fake.revoke_refresh_token();
        }
        if given == "refresh_wide_scope" {
            fake.set_granted_scope(WIDE_SCOPE);
        }
    }
    if let Some(unknown) = placeholders(&request_text)
        .into_iter()
        .find(|p| !values.contains_key(p.as_str()))
    {
        return Err(format!("unknown placeholder {unknown}"));
    }
    let fill = |text: &str| {
        values
            .iter()
            .fold(text.to_string(), |t, (name, value)| t.replace(name, value))
    };

    // The given state that affects only the case's own request.
    let inject = |status: u16, code: &str| match route {
        Some(route) => {
            fake.fail_next(route, 1, status, code);
            Ok(())
        }
        None => Err(format!(
            "given {given:?} on a path without a route: {}",
            request.path
        )),
    };
    match given {
        "client_broken" => fake.break_client(),
        "google_down" => inject(502, "upstream_error")?,
        "rate_limited" => inject(429, "rate_limited")?,
        "unconfigured" => inject(500, "server_misconfigured")?,
        _ => {}
    }

    let method =
        reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|e| e.to_string())?;
    let mut builder = http.request(method, format!("{}{}", ep.base, request.path));
    for (name, value) in &request.headers {
        builder = builder.header(name, fill(value));
    }
    if let Some(json) = &request.json {
        builder = builder.body(fill(&json.to_string()));
    }
    if let Some(body) = &request.body {
        builder = builder.body(fill(body));
    }
    let response = builder.send().await.map_err(|e| e.to_string())?;

    // --- compare
    let status = response.status().as_u16();
    if status != want.status {
        return Err(format!("status {status}, expected {}", want.status));
    }
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    for (name, value) in &want.headers {
        if *name != name.to_lowercase() {
            return Err(format!("header name {name} is not lower-case"));
        }
        match header(name) {
            None => return Err(format!("header {name} is missing")),
            Some(got) if value != "<string>" && got != *value => {
                return Err(format!("header {name}: {got:?}, expected {value:?}"));
            }
            Some(_) => {}
        }
    }
    if let Some(got) = header("location") {
        return Err(format!("an unexpected Location header: {got}"));
    }
    let answered = Answered {
        status,
        content_type: header("content-type").unwrap_or_default(),
        retry_after: header("retry-after"),
        body: response.bytes().await.map_err(|e| e.to_string())?.to_vec(),
    };
    if let Some(expected) = &want.json {
        let got: Value = serde_json::from_slice(&answered.body)
            .map_err(|e| format!("the body is not JSON: {e}"))?;
        let got = got.as_object().ok_or("the body is not a JSON object")?;
        let (got_keys, want_keys): (Vec<_>, Vec<_>) =
            (got.keys().collect(), expected.keys().collect());
        if got_keys != want_keys {
            return Err(format!(
                "key set {got_keys:?}, expected exactly {want_keys:?}"
            ));
        }
        for (key, expected) in expected {
            let ok = match expected.as_str() {
                Some("<string>") => got[key].is_string(),
                Some("<number>") => got[key].is_number(),
                Some(other) if placeholders(other) == [other] => {
                    return Err(format!("unknown matcher {other}"));
                }
                _ => got[key] == *expected,
            };
            if !ok {
                return Err(format!("json.{key}: {}, expected {expected}", got[key]));
            }
        }
    }
    Ok(answered)
}

/// What the mapping table of §2.4 assigns to an answer of one of the three routes.
#[derive(Debug, PartialEq)]
enum Mapped {
    /// `/device/start` answered a code.
    Started,
    Tokens {
        refresh_expires_in: Option<u64>,
    },
    Expired,
    Timeout,
    LoginFailed,
    NotAllowed,
    ScopeMissing,
    Denied,
    WorkerMisconfigured,
    Network,
}

fn mapped_error(e: &AuthError) -> Mapped {
    match e {
        AuthError::Expired => Mapped::Expired,
        AuthError::Timeout => Mapped::Timeout,
        AuthError::LoginFailed(_) => Mapped::LoginFailed,
        AuthError::NotAllowed(_) => Mapped::NotAllowed,
        AuthError::ScopeMissing => Mapped::ScopeMissing,
        AuthError::Denied(_) => Mapped::Denied,
        AuthError::WorkerMisconfigured(_) => Mapped::WorkerMisconfigured,
        AuthError::Network(_) => Mapped::Network,
        other => panic!("an error outside the mapping table: {other:?}"),
    }
}

/// How many requests the client may send before it gives its result.
#[derive(Debug)]
enum Requests {
    Exactly(usize),
    /// A poll that is repeated until the code runs out.
    Several,
}

/// The table, written out independently of `auth/login.rs`. The poll replay uses a code that
/// lives 300 ms and is polled every 10 ms: "keeps polling" ends in `Timeout` (nobody came) or
/// `Network` (the polls failed).
fn table(route: Route, status: u16, body: &Value) -> (Mapped, Requests) {
    use Requests::{Exactly, Several};
    let code = body.get("error").and_then(Value::as_str).unwrap_or("");
    let poll = route == Route::AuthPoll;
    match (status, code) {
        (200, _) if route == Route::AuthStart => (Mapped::Started, Exactly(1)),
        (200, _) => {
            let refresh_expires_in = body.get("refresh_token_expires_in").and_then(Value::as_u64);
            (Mapped::Tokens { refresh_expires_in }, Exactly(1))
        }
        (400, "authorization_pending") if poll => (Mapped::Timeout, Several),
        // the interval grows by 5 s, past the end of the code
        (400, "slow_down") if poll => (Mapped::Timeout, Exactly(1)),
        (400, "expired_token") if poll => (Mapped::Timeout, Exactly(1)),
        (400, "invalid_grant") if poll => (Mapped::LoginFailed, Exactly(1)),
        (400, "invalid_grant") if route == Route::AuthRefresh => (Mapped::Expired, Exactly(1)),
        // the grant was issued and could not be handed out: final, never polled again
        (403, "grant_unusable") if poll => (Mapped::LoginFailed, Exactly(1)),
        (403, "email_not_allowed") => (Mapped::NotAllowed, Exactly(1)),
        (403, "scope_missing") => (Mapped::ScopeMissing, Exactly(1)),
        (403, "scope_not_allowed") => (Mapped::Denied, Exactly(1)),
        (403, "access_denied") => (Mapped::Denied, Exactly(1)),
        (500, "client_invalid" | "server_misconfigured") => {
            (Mapped::WorkerMisconfigured, Exactly(1))
        }
        // a poll waits Retry-After (here: longer than the code lives); the others retry once
        (429, _) if poll => (Mapped::Network, Exactly(1)),
        (429, _) => (Mapped::Network, Exactly(2)),
        // a poll goes on; /device/start and /refresh: five tries
        (500..=599, _) if poll => (Mapped::Network, Several),
        (500..=599, _) => (Mapped::Network, Exactly(5)),
        _ => (Mapped::Network, Exactly(1)),
    }
}

/// Feeds a recorded answer through the Rust client and compares with the table.
async fn check_client_mapping(name: String, route: Route, answered: Answered) {
    let headers: Vec<(&str, &str)> = answered
        .retry_after
        .iter()
        .map(|v| ("retry-after", v.as_str()))
        .collect();
    let (server, ep) = stub(
        answered.status,
        &answered.content_type,
        &answered.body,
        &headers,
    )
    .await;
    let body: Value = serde_json::from_slice(&answered.body).unwrap_or(Value::Null);
    let (want, requests) = table(route, answered.status, &body);
    let tokens = |r: Result<Option<u64>, AuthError>| match r {
        Ok(refresh_expires_in) => Mapped::Tokens { refresh_expires_in },
        Err(e) => mapped_error(&e),
    };
    let got = match route {
        Route::AuthStart => match auth::device_start(&http(), &ep).await {
            Ok(_) => Mapped::Started,
            Err(e) => mapped_error(&e),
        },
        Route::AuthPoll => tokens(
            wait(&ep, &code("dc-contract-xxxxxxxxxxxx", 300))
                .await
                .map(|grant| grant.refresh_expires_in),
        ),
        _ => tokens(
            auth::refresh(&http(), &ep, "rt-contract", AuthClient::Device)
                .await
                .map(|_| None),
        ),
    };
    assert_eq!(
        got, want,
        "case {name}: the client's result for a {} answer",
        answered.status
    );
    let sent = stub_hits(&server).await;
    match requests {
        Requests::Exactly(n) => assert_eq!(sent, n, "case {name}: requests sent"),
        Requests::Several => assert!(sent >= 3, "case {name}: {sent} requests sent"),
    }
}

#[tokio::test]
async fn contract_fixture_matches_the_fake_and_the_client() {
    let contract = contract();
    assert_eq!(contract.version, 2);

    let names: Vec<&str> = contract.cases.iter().map(|c| c.name.as_str()).collect();
    let unique: std::collections::HashSet<&&str> = names.iter().collect();
    assert_eq!(unique.len(), names.len(), "case names repeat");
    let missing: Vec<&&str> = REQUIRED_CASES
        .iter()
        .filter(|c| !names.contains(c))
        .collect();
    assert!(missing.is_empty(), "the fixture lacks {missing:?}");

    // Every case against the fake's routes; every answer of a route through the client.
    let mut replays = Vec::new();
    for case in &contract.cases {
        let answered = run_case(case)
            .await
            .unwrap_or_else(|why| panic!("case {} (given {}): {why}", case.name, case.given));
        let route = match case.request["path"].as_str().unwrap_or("") {
            "/device/start" => Route::AuthStart,
            "/device/poll" => Route::AuthPoll,
            "/refresh" => Route::AuthRefresh,
            _ => continue,
        };
        replays.push(check_client_mapping(case.name.clone(), route, answered));
    }
    assert!(replays.len() >= 44, "every case of a route is replayed");
    futures_util::future::join_all(replays).await;
}

#[tokio::test]
async fn contract_runner_refuses_what_it_does_not_know_and_notices_wrong_answers() {
    let contract = contract();
    let base: Case = serde_json::from_value(json!({
        "name": "x", "given": "none",
        "request": { "method": "GET", "path": "/nothing-here" },
        "response": { "status": 404 }
    }))
    .unwrap();
    run_case(&base).await.unwrap();
    let with = |patch: fn(&mut Case)| {
        let mut case = base.clone();
        patch(&mut case);
        case
    };
    let refused = |case: Case, why: &'static str| async move {
        match run_case(&case).await {
            Ok(_) => panic!("the runner accepted: {why}"),
            Err(e) => assert!(e.contains(why), "{e:?} should mention {why:?}"),
        }
    };
    refused(with(|c| c.given = "moon_phase".into()), "unknown given").await;
    refused(
        with(|c| c.response["body_matches"] = json!("x")),
        "unknown key",
    )
    .await;
    refused(
        with(|c| c.response["location"] = json!("http://.+")),
        "unknown key",
    )
    .await;
    refused(with(|c| c.request["cookies"] = json!({})), "unknown key").await;
    refused(with(|c| c.request["query"] = json!({})), "unknown key").await;
    refused(
        with(|c| c.request["json"] = json!({ "refresh_token": "<grant>" })),
        "unknown placeholder",
    )
    .await;
    refused(
        with(|c| c.given = "google_down".into()),
        "path without a route",
    )
    .await;
    assert!(
        serde_json::from_value::<Case>(
            json!({ "name": "x", "given": "none", "request": {}, "response": {}, "note": 1 })
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<Contract>(json!({ "version": 2, "cases": [], "vector": {} }))
            .is_err()
    );

    let poll_get = contract
        .cases
        .iter()
        .find(|c| c.name == "poll_get")
        .unwrap()
        .clone();
    let wrong = |patch: fn(&mut Case)| {
        let mut case = poll_get.clone();
        patch(&mut case);
        case
    };
    run_case(&poll_get).await.unwrap();
    refused(wrong(|c| c.response["status"] = json!(404)), "status").await;
    refused(
        wrong(|c| c.response["headers"]["allow"] = json!("GET")),
        "header allow",
    )
    .await;
    refused(
        wrong(|c| c.response["headers"]["x-missing"] = json!("<string>")),
        "missing",
    )
    .await;
    refused(
        wrong(|c| c.response["headers"]["Allow"] = json!("POST")),
        "lower-case",
    )
    .await;
    refused(
        wrong(|c| c.response["json"] = json!({ "error": "method_not_allowed" })),
        "key set",
    )
    .await;
    refused(
        wrong(|c| c.response["json"]["error"] = json!("not_found")),
        "json.error",
    )
    .await;
    refused(
        wrong(|c| c.response["json"]["message"] = json!("<number>")),
        "json.message",
    )
    .await;
    refused(
        wrong(|c| c.response["json"]["message"] = json!("<bool>")),
        "unknown matcher",
    )
    .await;
    // a state the fake is not in: the fixture's answer for it does not come
    let pending = contract
        .cases
        .iter()
        .find(|c| c.name == "poll_pending")
        .unwrap()
        .clone();
    let mut denied = pending.clone();
    denied.given = "denied".into();
    refused(denied, "status").await;
}

//! WP3 acceptance (SPEC §12.1), auth side: the device's part of the login (§2.4), token
//! handling, and the contract fixture `worker/test/contract.json` (§16.5) — all against the
//! fake auth Worker of `FakeDrive`. No network beyond 127.0.0.1.

#[path = "support/fake_drive.rs"]
mod fake_drive;

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fake_drive::{FakeDrive, Route, page_links};
use gclone::auth::{
    self, AccessGrant, AuthEndpoints, InteractiveOpts, LoginGrant, PASTE_PREFIX, Pkce,
    SCOPE_DRIVE_FILE, TokenProvider,
};
use gclone::error::AuthError;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use wiremock::{Mock, MockServer, ResponseTemplate};

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const STATE: &str = "AAAAAAAAAAAAAAAAAAAAAA";
/// What Google grants when the `scope` of the authorization URL was widened on its way to the user.
const WIDE_SCOPE: &str = "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/drive";

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

fn http() -> reqwest::Client {
    auth::http_client().unwrap()
}

/// `LoginGrant` and `AccessGrant` have no `Debug` (they hold tokens), so no `unwrap_err`.
fn err<T>(r: Result<T, AuthError>) -> AuthError {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

/// What a login printed, and the URL it showed.
#[derive(Clone, Default)]
struct Printed(Arc<Mutex<Vec<String>>>);

impl Printed {
    fn text(&self) -> String {
        self.0.lock().unwrap().join("\n")
    }

    fn url(&self) -> Option<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .find(|l| l.starts_with("http"))
            .cloned()
    }

    async fn wait_for_url(&self) -> String {
        for _ in 0..2000 {
            if let Some(url) = self.url() {
                return url;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the login printed no URL: {}", self.text());
    }

    fn printer(&self) -> Box<dyn Fn(&str) + Send + Sync> {
        let lines = self.0.clone();
        Box::new(move |s| lines.lock().unwrap().push(s.to_string()))
    }
}

fn opts(
    printed: &Printed,
    no_browser: bool,
    open: impl Fn(&str) -> bool + Send + Sync + 'static,
) -> InteractiveOpts {
    InteractiveOpts {
        no_browser,
        timeout: Duration::from_secs(30),
        print: printed.printer(),
        open: Box::new(open),
        paste: None,
    }
}

type Login = tokio::task::JoinHandle<Result<LoginGrant, AuthError>>;

fn spawn_login(fake: &FakeDrive, opts: InteractiveOpts) -> Login {
    let ep = fake.auth();
    tokio::spawn(async move { auth::login_interactive(&http(), &ep, opts).await })
}

/// Browser flow whose `open` hands the URL to the fake user; the page the "browser" ends on
/// arrives on the returned channel.
fn browser_login(fake: &FakeDrive, printed: &Printed) -> (Login, mpsc::UnboundedReceiver<String>) {
    let (pages, rx) = mpsc::unbounded_channel();
    let user = fake.clone();
    let open = move |url: &str| {
        let (user, url, pages) = (user.clone(), url.to_string(), pages.clone());
        tokio::spawn(async move {
            let _ = pages.send(user.browse(&url).await);
        });
        true
    };
    (spawn_login(fake, opts(printed, false, open)), rx)
}

/// A grant for `pkce`, obtained the way a headless login would: through the fake's pages.
async fn grant_for(fake: &FakeDrive, pkce: &Pkce) -> String {
    let pasted = fake
        .browse(&auth::login_url(&fake.auth(), pkce, None))
        .await;
    auth::parse_pasted(&pasted)
        .unwrap_or_else(|_| panic!("no paste code on the final page: {pasted}"))
}

async fn login_tokens(fake: &FakeDrive) -> LoginGrant {
    let pkce = Pkce::generate();
    let grant = grant_for(fake, &pkce).await;
    auth::redeem(&http(), &fake.auth(), &grant, &pkce.verifier)
        .await
        .unwrap()
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
// PKCE, check code, URLs
// ---------------------------------------------------------------------------------------------

#[test]
fn pkce_challenge_and_check_code_vector() {
    let pkce = Pkce::from_verifier(VERIFIER, STATE);
    assert_eq!(
        pkce.challenge, CHALLENGE,
        "challenge = base64url(SHA-256(verifier))"
    );
    assert_eq!(pkce.check_code(), "D2KC-JCJY");
    assert_eq!(
        (pkce.verifier.as_str(), pkce.state.as_str()),
        (VERIFIER, STATE)
    );

    let (a, b) = (Pkce::generate(), Pkce::generate());
    for p in [&a, &b] {
        assert_eq!(
            (p.verifier.len(), p.challenge.len(), p.state.len()),
            (43, 43, 22)
        );
        let url_safe = |s: &str| {
            s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        };
        assert!(url_safe(&p.verifier) && url_safe(&p.challenge) && url_safe(&p.state));
        assert_eq!(p.challenge, Pkce::from_verifier(&p.verifier, "").challenge);
        let code = p.check_code();
        assert_eq!(code.len(), 9);
        assert_eq!(code.as_bytes()[4], b'-');
        assert!(
            code.bytes()
                .all(|c| c == b'-' || gclone::util::CROCKFORD.contains(&c)),
            "{code}"
        );
    }
    assert_ne!(a.verifier, b.verifier);
    assert_ne!(a.state, b.state);
}

#[test]
fn login_url_shapes() {
    let ep = AuthEndpoints {
        base: "https://auth.example/base".into(),
        revoke_url: String::new(),
    };
    let pkce = Pkce::from_verifier(VERIFIER, STATE);
    assert_eq!(
        auth::login_url(&ep, &pkce, Some(8123)),
        format!("https://auth.example/base/login?challenge={CHALLENGE}&port=8123&state={STATE}")
    );
    assert_eq!(
        auth::login_url(&ep, &pkce, None),
        format!("https://auth.example/base/login?challenge={CHALLENGE}"),
        "headless: no port, no state"
    );
}

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

#[test]
fn pasted_and_loopback_parsing() {
    assert_eq!(auth::parse_pasted(" gclone-code1_g-7 \r\n").unwrap(), "g-7");
    assert!(matches!(
        auth::parse_pasted("g-7"),
        Err(AuthError::LoginFailed(_))
    ));
    assert_eq!(
        auth::parse_loopback("code=g-7&state=s", "s").unwrap(),
        "g-7"
    );
    assert!(matches!(
        auth::parse_loopback("code=g-7&state=t", "s"),
        Err(AuthError::StateMismatch)
    ));
    assert!(
        matches!(auth::parse_loopback("error=access_denied&state=s", "s"), Err(AuthError::Denied(e)) if e == "access_denied")
    );
    assert_eq!(PASTE_PREFIX, "gclone-code1_");
}

// ---------------------------------------------------------------------------------------------
// browser flow
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn browser_flow_signs_in() {
    let fake = FakeDrive::start().await;
    let printed = Printed::default();
    let (login, mut pages) = browser_login(&fake, &printed);
    let page = pages.recv().await.unwrap();
    // The page says "connected" only once the redeem has succeeded.
    assert!(page.contains("gclone is connected"), "{page}");
    assert_eq!(
        fake.issued_refresh_tokens(),
        ["rt-1"],
        "redeemed before the page was served"
    );
    assert_eq!(fake.hits(Route::AuthToken), 1);

    let grant = login.await.unwrap().unwrap();
    assert_eq!(grant.refresh_token, "rt-1");
    assert_eq!(grant.email, "me@example.com");
    assert!(grant.scope.split(' ').any(|s| s == SCOPE_DRIVE_FILE));
    assert!(grant.access_token.starts_with("at-"));
    assert!(grant.refresh_expires_in.is_none());
    let in_an_hour = gclone::util::now_ms() + 3_599_000;
    assert!(grant.expires_at_ms.abs_diff(in_an_hour) < 10_000);

    // The terminal shows the URL and the check code of the page the fake served — which was a
    // confirmation page (200), not a redirect: `browse` insists on that.
    let text = printed.text();
    let url = printed.url().expect("the URL is printed as well");
    assert!(
        url.starts_with(&format!("{}/login?challenge=", fake.auth().base)),
        "{url}"
    );
    assert!(url.contains("&port=") && url.contains("&state="));
    let code = fake.last_check_code().unwrap();
    assert!(text.contains(&code), "check code {code} not in: {text}");
    assert_eq!(fake.hits(Route::AuthLogin), 1);

    // The new login works on Drive.
    let tokens = fake.token_provider_for(&grant.refresh_token);
    tokens.prime(&grant.access_token, grant.expires_at_ms);
    assert_eq!(tokens.access_token().await.unwrap(), grant.access_token);
    assert_eq!(fake.hits(Route::AuthRefresh), 0);
}

#[tokio::test]
async fn loopback_listener_is_local_and_ignores_stray_requests() {
    let fake = FakeDrive::start().await;
    let printed = Printed::default();
    // The browser "opens" but the user is slow: the test drives the listener by hand first.
    let login = spawn_login(&fake, opts(&printed, false, |_| true));
    let url = printed.wait_for_url().await;
    let port: u16 = url
        .split("&port=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let local = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    let get = |path: &str| {
        let request = client.get(format!("{local}{path}"));
        async move {
            let r = request.send().await.unwrap();
            (r.status().as_u16(), r.text().await.unwrap())
        }
    };

    // 127.0.0.1 only: not on ::1, not on this machine's other addresses.
    assert!(
        tokio::net::TcpStream::connect(("::1", port)).await.is_err(),
        "the listener must not be on ::1"
    );
    let outward = std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("192.0.2.1:9").and_then(|()| s.local_addr()))
        .map(|a| a.ip())
        .ok()
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified());
    if let Some(ip) = outward {
        let attempt = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect((ip, port)),
        )
        .await;
        assert!(
            !matches!(attempt, Ok(Ok(_))),
            "the listener must not be reachable on {ip}"
        );
    }

    // Requests that are not the answer: 404, and the login keeps waiting.
    for path in [
        "/favicon.ico",
        "/",
        "/?foo=1",
        "/other?code=x&state=y",
        "/favicon.ico?code=x",
    ] {
        let (status, body) = get(path).await;
        assert_eq!(status, 404, "{path}");
        assert!(!body.contains("connected"));
    }
    let post = client
        .post(format!("{local}/?code=x&state=y"))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 404, "only GET carries the answer");
    // A wrong state: 400, and the login keeps waiting.
    for path in [
        "/?code=g-1&state=wrong",
        "/?code=g-1",
        "/?error=access_denied&state=wrong",
    ] {
        let (status, body) = get(path).await;
        assert_eq!(status, 400, "{path}");
        assert!(!body.contains("connected"));
    }
    // A connection that never sends a request does not block the others.
    let _idle = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    assert_eq!(get("/favicon.ico").await.0, 404);
    assert!(!login.is_finished());
    assert_eq!(
        fake.hits(Route::AuthToken),
        0,
        "nothing was redeemed for a stray request"
    );

    // The Worker's redirect with a tampered state: 400 again — then the real one completes.
    fake.tamper_loopback_state_once();
    let page = fake.browse(&url).await;
    assert!(
        page.contains("does not belong") && !page.contains("connected"),
        "{page}"
    );
    assert!(!login.is_finished());
    let page = fake.browse(&url).await;
    assert!(page.contains("gclone is connected"), "{page}");
    let grant = login.await.unwrap().unwrap();
    assert_eq!(grant.refresh_token, "rt-1");
    assert_eq!(fake.hits(Route::AuthToken), 1);
    // The listener is gone with the login.
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
    );
}

/// A browser sends every cookie it holds for host 127.0.0.1 — on any port — with the redirect to
/// the loopback listener. Only the request line matters: however large the headers are, the
/// sign-in is redeemed and the page is served (the listener used to drop a request whose head
/// passed 16 KiB, and the login then waited out its ten minutes).
#[tokio::test]
async fn loopback_answer_with_huge_headers_still_signs_in() {
    let fake = FakeDrive::start().await;
    let printed = Printed::default();
    let login = spawn_login(&fake, opts(&printed, false, |_| true));
    let url = printed.wait_for_url().await;
    // The walk a browser makes, by hand, up to the redirect to the loopback address.
    let client = http();
    let confirmation = client.get(&url).send().await.unwrap();
    let check_code = fake.last_check_code().unwrap();
    let redirect = walk_consent(&client, confirmation, true, &check_code)
        .await
        .unwrap();
    assert_eq!(redirect.status(), 302);
    let loopback = redirect.headers()["location"].to_str().unwrap().to_string();
    assert!(loopback.starts_with("http://127.0.0.1:"), "{loopback}");

    let cookies = |request: reqwest::RequestBuilder, count: usize| {
        (0..count).fold(request, |request, i| {
            request.header("cookie", format!("session{i}={}", "x".repeat(4000)))
        })
    };

    // A request line that cannot be a sign-in answer is refused with a page, not dropped —
    // and the login keeps waiting.
    let long = format!("{loopback}&pad={}", "p".repeat(20_000));
    let refused = cookies(client.get(&long), 2).send().await.unwrap();
    assert_eq!(refused.status(), 414);
    assert!(!refused.text().await.unwrap().contains("connected"));
    assert!(!login.is_finished());
    assert_eq!(fake.hits(Route::AuthToken), 0);

    // 240 KiB of cookies in front of nothing that matters.
    let answered = cookies(client.get(&loopback), 60).send().await.unwrap();
    assert_eq!(answered.status(), 200);
    let page = answered.text().await.unwrap();
    assert!(page.contains("gclone is connected"), "{page}");
    let grant = login.await.unwrap().unwrap();
    assert_eq!(grant.refresh_token, "rt-1");
    assert_eq!(fake.hits(Route::AuthToken), 1);
}

#[tokio::test]
async fn denied_consent_ends_the_browser_flow() {
    let fake = FakeDrive::start().await;
    fake.deny_consent_once();
    let printed = Printed::default();
    let (login, mut pages) = browser_login(&fake, &printed);
    let page = pages.recv().await.unwrap();
    assert!(
        page.contains("could not sign in") && !page.contains("connected"),
        "{page}"
    );
    let e = err(login.await.unwrap());
    assert!(
        matches!(&e, AuthError::Denied(reason) if reason == "access_denied"),
        "{e:?}"
    );
    assert_eq!(fake.hits(Route::AuthToken), 0);
    assert!(fake.issued_refresh_tokens().is_empty());
}

#[tokio::test]
async fn the_page_does_not_say_connected_when_the_redeem_fails() {
    // the Worker is down at /token
    let fake = FakeDrive::start().await;
    fake.fail_next(Route::AuthToken, 1, 502, "upstream_error");
    let (login, mut pages) = browser_login(&fake, &Printed::default());
    let page = pages.recv().await.unwrap();
    assert!(
        page.contains("could not sign in") && !page.contains("connected"),
        "{page}"
    );
    assert!(matches!(err(login.await.unwrap()), AuthError::Network(_)));
    assert_eq!(fake.hits(Route::AuthToken), 1);

    // the account is not on the allowlist
    let fake = FakeDrive::start().await;
    fake.set_login_email("other@example.com");
    let (login, mut pages) = browser_login(&fake, &Printed::default());
    let page = pages.recv().await.unwrap();
    assert!(!page.contains("connected"), "{page}");
    let e = err(login.await.unwrap());
    assert!(
        matches!(&e, AuthError::NotAllowed(msg) if msg.contains("other@example.com")),
        "{e:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn browser_flow_times_out_when_nothing_arrives() {
    let ep = AuthEndpoints {
        base: "http://127.0.0.1:9/auth".into(),
        revoke_url: "http://127.0.0.1:9/revoke".into(),
    };
    let printed = Printed::default();
    let mut o = opts(&printed, false, |_| true);
    o.timeout = gclone::consts::AUTH_TIMEOUT;
    let started = tokio::time::Instant::now();
    let e = err(auth::login_interactive(&http(), &ep, o).await);
    assert!(matches!(e, AuthError::Timeout), "{e:?}");
    assert!(started.elapsed() >= Duration::from_secs(600));
    assert!(printed.url().is_some());
}

// ---------------------------------------------------------------------------------------------
// headless flow
// ---------------------------------------------------------------------------------------------

/// A headless login fed through a paste channel; `open` must not be called unless `no_browser`
/// is false.
fn headless_login(
    fake: &FakeDrive,
    printed: &Printed,
    no_browser: bool,
) -> (Login, mpsc::Sender<String>, Arc<AtomicUsize>) {
    let opened = Arc::new(AtomicUsize::new(0));
    let count = opened.clone();
    let mut o = opts(printed, no_browser, move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        false
    });
    let (tx, rx) = mpsc::channel(8);
    o.paste = Some(rx);
    (spawn_login(fake, o), tx, opened)
}

#[tokio::test]
async fn headless_flow_redeems_a_pasted_code() {
    let fake = FakeDrive::start().await;
    let printed = Printed::default();
    let (login, paste, opened) = headless_login(&fake, &printed, true);
    let url = printed.wait_for_url().await;
    assert!(!url.contains("port=") && !url.contains("state="), "{url}");
    assert!(url.starts_with(&format!("{}/login?challenge=", fake.auth().base)));

    let code = fake.browse(&url).await;
    assert!(code.starts_with(PASTE_PREFIX), "{code}");
    // The check code in the terminal is the one on the confirmation page.
    assert!(
        printed.text().contains(&fake.last_check_code().unwrap()),
        "{}",
        printed.text()
    );

    // Pasted with a line break in the middle and stray whitespace around.
    let (a, b) = code.split_at(code.len() / 2);
    paste.send("   ".to_string()).await.unwrap();
    paste.send(format!("  {a} \r\n\t{b}  \n")).await.unwrap();
    let grant = login.await.unwrap().unwrap();
    assert_eq!(grant.refresh_token, "rt-1");
    assert_eq!(grant.email, "me@example.com");
    assert_eq!(
        opened.load(Ordering::SeqCst),
        0,
        "--no-browser never opens one"
    );
    assert_eq!(fake.hits(Route::AuthToken), 1);
}

#[tokio::test]
async fn headless_flow_gives_up_after_three_wrong_pastes() {
    let fake = FakeDrive::start().await;
    let printed = Printed::default();
    let (login, paste, _) = headless_login(&fake, &printed, true);
    for garbage in [
        "hello",
        "",
        "gclone-code2_abc",
        "   ",
        "4/0AfakeGoogleCode",
        "never read",
    ] {
        paste.send(garbage.to_string()).await.unwrap();
    }
    let e = err(login.await.unwrap());
    assert!(
        matches!(&e, AuthError::LoginFailed(msg) if msg.contains("not a gclone sign-in code")),
        "{e:?}"
    );
    assert_eq!(
        fake.hits(Route::AuthToken),
        0,
        "garbage is never sent to the Worker"
    );
    assert_eq!(
        printed
            .text()
            .matches("That is not a gclone sign-in code")
            .count(),
        2,
        "asked again twice"
    );
}

#[tokio::test]
async fn a_browser_that_does_not_open_falls_back_to_the_headless_flow() {
    let fake = FakeDrive::start().await;
    let printed = Printed::default();
    let (login, paste, opened) = headless_login(&fake, &printed, false);
    let url = printed.wait_for_url().await;
    assert_eq!(opened.load(Ordering::SeqCst), 1);
    assert!(
        !url.contains("port="),
        "the fallback prints the headless URL only: {url}"
    );
    assert_eq!(
        printed.text().matches("http").count(),
        1,
        "one URL, not two: {}",
        printed.text()
    );
    paste.send(fake.browse(&url).await).await.unwrap();
    assert_eq!(login.await.unwrap().unwrap().refresh_token, "rt-1");
}

#[tokio::test]
async fn headless_flow_without_a_terminal_fails() {
    let fake = FakeDrive::start().await;
    let printed = Printed::default();
    let e =
        err(auth::login_interactive(&http(), &fake.auth(), opts(&printed, true, |_| true)).await);
    assert!(
        matches!(&e, AuthError::LoginFailed(msg) if msg.contains("no terminal")),
        "{e:?}"
    );
    assert!(
        printed.url().is_none(),
        "nothing is asked of a user who cannot answer"
    );

    // input that ends before a code arrives
    let (login, paste, _) = headless_login(&fake, &Printed::default(), true);
    drop(paste);
    assert!(matches!(
        err(login.await.unwrap()),
        AuthError::LoginFailed(_)
    ));

    // a denied consent in paste mode leaves nothing to paste; a wrong code is refused by /token
    fake.deny_consent_once();
    let printed = Printed::default();
    let (login, paste, _) = headless_login(&fake, &printed, true);
    let page = fake.browse(&printed.wait_for_url().await).await;
    assert!(page.contains("access_denied") && !page.contains(PASTE_PREFIX));
    paste.send(format!("{PASTE_PREFIX}g-999")).await.unwrap();
    let e = err(login.await.unwrap());
    assert!(
        matches!(&e, AuthError::LoginFailed(msg) if msg.contains("expired or was already used")),
        "{e:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// redeem
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn redeem_binds_the_grant_to_the_verifier_and_uses_it_once() {
    let fake = FakeDrive::start().await;
    let (http, ep) = (http(), fake.auth());
    let pkce = Pkce::generate();
    let grant = grant_for(&fake, &pkce).await;

    let other = Pkce::generate();
    let e = err(auth::redeem(&http, &ep, &grant, &other.verifier).await);
    assert!(
        matches!(&e, AuthError::LoginFailed(msg) if msg == "the sign-in code expired or was already used"),
        "{e:?}"
    );
    // The failed attempt did not burn the grant.
    let tokens = auth::redeem(&http, &ep, &grant, &pkce.verifier)
        .await
        .unwrap();
    assert_eq!(tokens.refresh_token, "rt-1");
    let seen = fake.requests(Route::AuthToken);
    assert_eq!(
        (seen[1].method.as_str(), seen[1].path.as_str()),
        ("POST", "/auth/token")
    );
    assert_eq!(
        seen[1].json,
        Some(json!({ "code": grant, "verifier": pkce.verifier }))
    );
    assert!(seen[1].headers["content-type"].starts_with("application/json"));
    assert!(seen[1].headers["user-agent"].starts_with("gclone/"));

    // reused
    assert!(matches!(
        err(auth::redeem(&http, &ep, &grant, &pkce.verifier).await),
        AuthError::LoginFailed(_)
    ));
    // expired
    let pkce = Pkce::generate();
    let grant = grant_for(&fake, &pkce).await;
    fake.expire_grants();
    assert!(matches!(
        err(auth::redeem(&http, &ep, &grant, &pkce.verifier).await),
        AuthError::LoginFailed(_)
    ));
    // never issued
    assert!(matches!(
        err(auth::redeem(&http, &ep, "g-12345", &pkce.verifier).await),
        AuthError::LoginFailed(_)
    ));
    assert_eq!(fake.issued_refresh_tokens(), ["rt-1"]);
}

#[tokio::test]
async fn redeem_maps_the_workers_refusals() {
    let fake = FakeDrive::start().await;
    let (http, ep) = (http(), fake.auth());

    fake.set_login_email("other@example.com");
    let pkce = Pkce::generate();
    let grant = grant_for(&fake, &pkce).await;
    let e = err(auth::redeem(&http, &ep, &grant, &pkce.verifier).await);
    assert!(
        matches!(&e, AuthError::NotAllowed(msg) if msg.contains("other@example.com")),
        "{e:?}"
    );
    // an allowlist entry in another case matches
    fake.set_login_email("Me@Example.com");
    fake.set_allowed_emails(&["someone@example.com", " ME@example.COM "]);
    assert_eq!(login_tokens(&fake).await.email, "Me@Example.com");
    fake.set_login_email("me@example.com");
    fake.set_allowed_emails(&["me@example.com"]);

    fake.set_granted_scope("openid");
    let pkce = Pkce::generate();
    let grant = grant_for(&fake, &pkce).await;
    assert!(matches!(
        err(auth::redeem(&http, &ep, &grant, &pkce.verifier).await),
        AuthError::ScopeMissing
    ));
    // More than gclone's scopes: the Worker hands out nothing, on /token …
    fake.set_granted_scope(WIDE_SCOPE);
    let issued_before = fake.issued_refresh_tokens().len();
    let pkce = Pkce::generate();
    let grant = grant_for(&fake, &pkce).await;
    let e = err(auth::redeem(&http, &ep, &grant, &pkce.verifier).await);
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
    assert!(
        auth::refresh(&http, &ep, &tokens.refresh_token)
            .await
            .is_ok()
    );
    fake.set_granted_scope(WIDE_SCOPE);
    let e = err(auth::refresh(&http, &ep, &tokens.refresh_token).await);
    assert!(matches!(e, AuthError::Denied(_)), "{e:?}");
    fake.set_granted_scope(&format!("openid {SCOPE_DRIVE_FILE}"));

    fake.break_client();
    let pkce = Pkce::generate();
    let grant = grant_for(&fake, &pkce).await;
    let e = err(auth::redeem(&http, &ep, &grant, &pkce.verifier).await);
    assert!(matches!(e, AuthError::WorkerMisconfigured(_)), "{e:?}");

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
    assert!(matches!(
        err(auth::redeem(&http, &ep, "g", VERIFIER).await),
        AuthError::ScopeMissing
    ));
    // … and refuses a 200 answer that is not the promised shape.
    for body in [
        json!({ "access_token": "a", "expires_in": 1, "scope": SCOPE_DRIVE_FILE, "email": "e" }),
        json!([1]),
        json!("ok"),
    ] {
        let (_server, ep) = stub(200, "application/json", body.to_string().as_bytes(), &[]).await;
        let e = err(auth::redeem(&http, &ep, "g", VERIFIER).await);
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
    let e = err(auth::redeem(&http, &ep, "g", VERIFIER).await);
    assert!(
        matches!(&e, AuthError::Denied(msg) if msg == "org_internal"),
        "{e:?}"
    );
}

#[tokio::test]
async fn redeem_passes_refresh_token_expires_in_through() {
    let fake = FakeDrive::start().await;
    assert!(login_tokens(&fake).await.refresh_expires_in.is_none());
    fake.set_refresh_expires_in(Some(604_799));
    assert_eq!(login_tokens(&fake).await.refresh_expires_in, Some(604_799));
    fake.set_refresh_expires_in(None);
    assert!(login_tokens(&fake).await.refresh_expires_in.is_none());
}

#[tokio::test]
async fn token_route_is_not_retried_except_once_after_429() {
    let (http, pkce) = (http(), Pkce::generate());

    // 502: Google may have seen the code — never resend
    let fake = FakeDrive::start().await;
    let grant = grant_for(&fake, &pkce).await;
    fake.fail_next(Route::AuthToken, 1, 502, "upstream_error");
    assert!(matches!(
        err(auth::redeem(&http, &fake.auth(), &grant, &pkce.verifier).await),
        AuthError::Network(_)
    ));
    assert_eq!(fake.hits(Route::AuthToken), 1);
    // other 5xx, HTML included
    fake.fail_next_raw(Route::AuthToken, 1, 503, "<html>Service Unavailable</html>");
    assert!(matches!(
        err(auth::redeem(&http, &fake.auth(), &grant, &pkce.verifier).await),
        AuthError::Network(_)
    ));
    assert_eq!(fake.hits(Route::AuthToken), 2);

    // 429: answered before the grant was opened — one retry after Retry-After, which succeeds
    let fake = FakeDrive::start().await;
    let grant = grant_for(&fake, &pkce).await;
    fake.fail_next(Route::AuthToken, 1, 429, "rate_limited");
    let started = std::time::Instant::now();
    let tokens = auth::redeem(&http, &fake.auth(), &grant, &pkce.verifier)
        .await
        .unwrap();
    assert_eq!(tokens.refresh_token, "rt-1");
    assert_eq!(fake.hits(Route::AuthToken), 2);
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "Retry-After: 1 was honoured"
    );

    // two 429s in a row → Network
    let fake = FakeDrive::start().await;
    let grant = grant_for(&fake, &pkce).await;
    fake.fail_next(Route::AuthToken, 2, 429, "rate_limited");
    let e = err(auth::redeem(&http, &fake.auth(), &grant, &pkce.verifier).await);
    assert!(
        matches!(&e, AuthError::Network(msg) if msg.contains("rate-limiting")),
        "{e:?}"
    );
    assert_eq!(fake.hits(Route::AuthToken), 2);
    // the grant is still good afterwards
    assert_eq!(
        auth::redeem(&http, &fake.auth(), &grant, &pkce.verifier)
            .await
            .unwrap()
            .refresh_token,
        "rt-1"
    );

    // nothing listening → Network at once
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let ep = AuthEndpoints {
        base: format!("http://127.0.0.1:{closed}/auth"),
        revoke_url: String::new(),
    };
    assert!(matches!(
        err(auth::redeem(&http, &ep, "g", &pkce.verifier).await),
        AuthError::Network(_)
    ));
}

// ---------------------------------------------------------------------------------------------
// refresh, revoke
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn refresh_maps_the_workers_answers() {
    let fake = FakeDrive::start().await;
    let (http, ep) = (http(), fake.auth());
    let ok: AccessGrant = auth::refresh(&http, &ep, "rt-ok").await.unwrap();
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
    assert_eq!(seen.json, Some(json!({ "refresh_token": "rt-ok" })));

    // a token Google never issued; a string the Worker's pre-filter refuses
    assert!(matches!(
        err(auth::refresh(&http, &ep, "1//0unknown-but-well-formed-token").await),
        AuthError::Expired
    ));
    let e = err(auth::refresh(&http, &ep, "not a refresh token").await);
    assert!(
        matches!(&e, AuthError::Network(msg) if msg.contains("unexpected answer")),
        "{e:?}"
    );

    fake.revoke_refresh_token();
    assert!(matches!(
        err(auth::refresh(&http, &ep, "rt-ok").await),
        AuthError::Expired
    ));

    let fake = FakeDrive::start().await;
    fake.break_client();
    let e = err(auth::refresh(&http, &fake.auth(), "rt-ok").await);
    assert!(matches!(e, AuthError::WorkerMisconfigured(_)), "{e:?}");
    assert_eq!(
        fake.hits(Route::AuthRefresh),
        1,
        "a broken client is not retried"
    );
    fake.fail_next(Route::AuthRefresh, 1, 500, "server_misconfigured");
    assert!(matches!(
        err(auth::refresh(&http, &fake.auth(), "rt-ok").await),
        AuthError::WorkerMisconfigured(_)
    ));
}

#[tokio::test]
async fn refresh_retries_server_errors_and_one_429() {
    let http = http();
    // a 502 is retried and then succeeds; so is a 500 without a mapped code and an HTML 503
    let fake = FakeDrive::start().await;
    fake.fail_next(Route::AuthRefresh, 1, 502, "upstream_error");
    fake.fail_next(Route::AuthRefresh, 1, 500, "internal_error");
    fake.fail_next_raw(Route::AuthRefresh, 1, 503, "<html>down</html>");
    assert!(auth::refresh(&http, &fake.auth(), "rt-ok").await.is_ok());
    assert_eq!(fake.hits(Route::AuthRefresh), 4);

    // five failures are the end
    let fake = FakeDrive::start().await;
    fake.fail_next(Route::AuthRefresh, u32::MAX, 502, "upstream_error");
    let e = err(auth::refresh(&http, &fake.auth(), "rt-ok").await);
    assert!(
        matches!(&e, AuthError::Network(msg) if msg.contains("502")),
        "{e:?}"
    );
    assert_eq!(fake.hits(Route::AuthRefresh), 5);

    // one 429 is waited out, two are not
    let fake = FakeDrive::start().await;
    fake.fail_next(Route::AuthRefresh, 1, 429, "rate_limited");
    let started = std::time::Instant::now();
    assert!(auth::refresh(&http, &fake.auth(), "rt-ok").await.is_ok());
    assert_eq!(fake.hits(Route::AuthRefresh), 2);
    assert!(started.elapsed() >= Duration::from_millis(900));
    fake.fail_next(Route::AuthRefresh, 2, 429, "rate_limited");
    let e = err(auth::refresh(&http, &fake.auth(), "rt-ok").await);
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
        let e = err(auth::refresh(&http, &fake.auth(), "rt-ok").await);
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
    let pkce = Pkce::generate();
    let grant = grant_for(&fake, &pkce).await;
    fake.fail_next_raw(Route::AuthToken, 1, 302, "");
    let e = err(auth::redeem(&http, &fake.auth(), &grant, &pkce.verifier).await);
    assert!(
        matches!(&e, AuthError::Network(msg) if msg.contains("unexpected answer")),
        "{e:?}"
    );
    assert_eq!(fake.hits(Route::AuthToken), 1);
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
        assert!(auth::refresh(&http, &ep, &a.refresh_token).await.is_ok());
        assert!(auth::refresh(&http, &ep, &b.refresh_token).await.is_ok());
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
                err(auth::refresh(&http, &ep, token).await),
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
    assert!(auth::refresh(&http, &ep, &c.refresh_token).await.is_ok());

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
    let p = TokenProvider::new(http(), fake.auth(), grant.refresh_token.clone(), None);
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

const GIVEN: [&str; 16] = [
    "none",
    "consent_ok",
    "consent_denied",
    "grant",
    "grant_expired",
    "grant_other_account",
    "grant_no_drive_scope",
    "grant_wide_scope",
    "grant_expiring",
    "refresh_token",
    "refresh_revoked",
    "refresh_wide_scope",
    "client_broken",
    "google_down",
    "rate_limited",
    "unconfigured",
];

const REQUIRED_CASES: [&str; 36] = [
    "login_loopback",
    "login_paste",
    "login_bad_challenge",
    "loopback_grant",
    "loopback_denied",
    "paste_code",
    "token_ok",
    "token_expiring",
    "token_wrong_verifier",
    "token_expired_grant",
    "token_email_not_allowed",
    "token_scope_missing",
    "token_scope_not_allowed",
    "token_client_invalid",
    "token_upstream",
    "token_rate_limited",
    "token_unconfigured",
    "token_wrong_content_type",
    "token_too_large",
    "token_not_json",
    "token_missing_field",
    "token_get",
    "refresh_ok",
    "refresh_invalid_grant",
    "refresh_malformed_token",
    "refresh_scope_not_allowed",
    "refresh_client_invalid",
    "refresh_upstream",
    "refresh_rate_limited",
    "not_found",
    // delivered beyond the required list (§17.2)
    "login_bad_port",
    "login_missing_state",
    "paste_denied",
    "refresh_missing_field",
    "refresh_unconfigured",
    "refresh_get",
];

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Contract {
    version: u32,
    vector: Vector,
    cases: Vec<Case>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Vector {
    verifier: String,
    challenge: String,
    state: String,
    port: u16,
    check_code: String,
    email: String,
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
    query: Option<BTreeMap<String, String>>,
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
    location: Option<String>,
    #[serde(default)]
    body_contains: Vec<String>,
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

/// A regular expression must match `text` in full. Only what the fixture's `location`
/// patterns use is understood — literals, `\` escapes, `.`, `[...]` classes with ranges, and
/// the quantifiers `+ * ?`; anything else is an error, so the fixture cannot outgrow this.
fn regex_full_match(pattern: &str, text: &str) -> Result<bool, String> {
    enum Set {
        Any,
        Of(Vec<(char, char)>),
    }
    struct Atom {
        set: Set,
        min: usize,
        max: usize,
    }
    let inner = pattern.strip_prefix('^').unwrap_or(pattern);
    let inner = match inner.strip_suffix('$') {
        Some(body) if !body.ends_with('\\') => body,
        _ => inner,
    };
    let mut atoms: Vec<Atom> = Vec::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        let set = match c {
            '\\' => {
                let escaped = chars.next().ok_or("a pattern ends in a backslash")?;
                if escaped.is_ascii_alphanumeric() {
                    return Err(format!("unsupported escape \\{escaped}"));
                }
                Set::Of(vec![(escaped, escaped)])
            }
            '.' => Set::Any,
            '[' => {
                let mut ranges = Vec::new();
                if chars.peek() == Some(&'^') {
                    return Err("negated classes are not supported".into());
                }
                loop {
                    let mut lo = chars.next().ok_or("unterminated character class")?;
                    if lo == ']' {
                        break;
                    }
                    if lo == '\\' {
                        lo = chars.next().ok_or("unterminated character class")?;
                    }
                    if chars.peek() == Some(&'-') {
                        chars.next();
                        match chars.peek() {
                            Some(']') | None => ranges.extend([(lo, lo), ('-', '-')]),
                            Some(_) => ranges.push((lo, chars.next().unwrap())),
                        }
                    } else {
                        ranges.push((lo, lo));
                    }
                }
                Set::Of(ranges)
            }
            '(' | ')' | '|' | '{' | '}' | '^' | '$' | '+' | '*' | '?' => {
                return Err(format!(
                    "unsupported regular expression syntax {c:?} in {pattern}"
                ));
            }
            literal => Set::Of(vec![(literal, literal)]),
        };
        let (min, max) = match chars.peek() {
            Some('+') => (1, usize::MAX),
            Some('*') => (0, usize::MAX),
            Some('?') => (0, 1),
            _ => (1, 1),
        };
        if (min, max) != (1, 1) {
            chars.next();
        }
        atoms.push(Atom { set, min, max });
    }
    fn matches(atoms: &[Atom], text: &[char]) -> bool {
        let Some((atom, rest)) = atoms.split_first() else {
            return text.is_empty();
        };
        let fits = |c: char| match &atom.set {
            Set::Any => true,
            Set::Of(ranges) => ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&c)),
        };
        let longest = text.iter().take(atom.max).take_while(|c| fits(**c)).count();
        (atom.min..=longest)
            .rev()
            .any(|n| matches(rest, &text[n..]))
    }
    Ok(matches(&atoms, &text.chars().collect::<Vec<_>>()))
}

/// The walk from the `/login` answer to where the browser ends up (the 302 to the loopback
/// address, or the final page): follow the confirmation page's one link to "Google". When
/// Google granted access (`granted`), `/callback` must answer the second confirmation page —
/// never a redirect, never the paste code — showing `check_code`; its one link is followed too.
async fn walk_consent(
    http: &reqwest::Client,
    confirmation: reqwest::Response,
    granted: bool,
    check_code: &str,
) -> Result<reqwest::Response, String> {
    async fn page_and_link(
        page: reqwest::Response,
        what: &str,
    ) -> Result<(String, String), String> {
        if page.status() != 200 || page.headers().contains_key("location") {
            return Err(format!("{what} answered {}", page.status()));
        }
        let text = page.text().await.map_err(|e| e.to_string())?;
        let links = page_links(&text);
        match links.as_slice() {
            [link] => Ok((text.clone(), link.clone())),
            _ => Err(format!(
                "{what} must have exactly one link, found {links:?}"
            )),
        }
    }
    let get = |url: String| async move { http.get(url).send().await.map_err(|e| e.to_string()) };
    let (_, to_google) = page_and_link(confirmation, "the confirmation page").await?;
    let back = get(to_google).await?;
    if !granted {
        return Ok(back);
    }
    let (page, finish) = page_and_link(back, "the confirmation page after Google").await?;
    if page.contains(PASTE_PREFIX) || !page.contains(check_code) {
        return Err(format!(
            "the page after Google must show the check code {check_code} and no paste code: {page}"
        ));
    }
    get(finish).await
}

async fn fixture_grant(
    fake: &FakeDrive,
    http: &reqwest::Client,
    v: &Vector,
) -> Result<String, String> {
    let url = format!(
        "{}/login?challenge={}&port={}&state={}",
        fake.auth().base,
        v.challenge,
        v.port,
        v.state
    );
    let confirmation = http.get(url).send().await.map_err(|e| e.to_string())?;
    let redirect = walk_consent(http, confirmation, true, &v.check_code).await?;
    let location = redirect
        .headers()
        .get("location")
        .and_then(|l| l.to_str().ok())
        .unwrap_or("")
        .to_string();
    let query = location.split_once('?').map(|(_, q)| q).unwrap_or("");
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == "code")
        .map(|(_, code)| code.into_owned())
        .ok_or_else(|| format!("no grant in the loopback redirect {location:?}"))
}

/// Reproduces one case against a fresh fake's auth routes with a plain HTTP client and checks
/// the answer. `Err` names the first thing that is wrong — or that this runner does not know.
async fn run_case(v: &Vector, case: &Case) -> Result<Answered, String> {
    let request: WantedRequest = serde_json::from_value(case.request.clone())
        .map_err(|e| format!("request: unknown key or shape: {e}"))?;
    let want: WantedResponse = serde_json::from_value(case.response.clone())
        .map_err(|e| format!("response: unknown key or shape: {e}"))?;
    if !GIVEN.contains(&case.given.as_str()) {
        return Err(format!("unknown given {:?}", case.given));
    }
    if request.json.is_some() && request.body.is_some() {
        return Err("both json and body".into());
    }
    let route = match request.path.as_str() {
        "/login" => Some(Route::AuthLogin),
        "/token" => Some(Route::AuthToken),
        "/refresh" => Some(Route::AuthRefresh),
        _ => None,
    };
    let fake = FakeDrive::start().await;
    let base = fake.auth().base;
    // No redirect following: what the Worker answers is what is compared.
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Placeholders this side produces from its own implementation — before the given state.
    let request_text = case.request.to_string();
    let mut values: BTreeMap<&str, String> = BTreeMap::from([
        ("<verifier>", v.verifier.clone()),
        ("<challenge>", v.challenge.clone()),
        ("<state>", v.state.clone()),
        ("<port>", v.port.to_string()),
        (
            "<other_verifier>",
            "another-verifier_another-verifier_another-verifier".to_string(),
        ),
    ]);
    if request_text.contains("<grant>") {
        match case.given.as_str() {
            "grant_other_account" => fake.set_login_email("stranger@example.com"),
            "grant_no_drive_scope" => {
                fake.set_granted_scope("openid https://www.googleapis.com/auth/userinfo.email")
            }
            "grant_wide_scope" => fake.set_granted_scope(WIDE_SCOPE),
            "grant_expiring" => fake.set_refresh_expires_in(Some(604_799)),
            _ => {}
        }
        values.insert("<grant>", fixture_grant(&fake, &http, v).await?);
        if case.given == "grant_expired" {
            fake.expire_grants();
        }
    }
    if request_text.contains("<refresh_token>") {
        let grant = fixture_grant(&fake, &http, v).await?;
        let tokens = auth::redeem(&http, &fake.auth(), &grant, &v.verifier)
            .await
            .map_err(|e| e.to_string())?;
        values.insert("<refresh_token>", tokens.refresh_token);
        if case.given == "refresh_revoked" {
            fake.revoke_refresh_token();
        }
        if case.given == "refresh_wide_scope" {
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
            "given {:?} on a path without a route: {}",
            case.given, request.path
        )),
    };
    match case.given.as_str() {
        "client_broken" => fake.break_client(),
        "google_down" => inject(502, "upstream_error")?,
        "rate_limited" => inject(429, "rate_limited")?,
        "unconfigured" => inject(500, "server_misconfigured")?,
        "consent_denied" => fake.deny_consent_once(),
        _ => {}
    }

    let mut url = format!("{base}{}", request.path);
    if let Some(query) = &request.query {
        let mut pairs = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in query {
            pairs.append_pair(name, &fill(value));
        }
        url = format!("{url}?{}", pairs.finish());
    }
    let method =
        reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|e| e.to_string())?;
    let mut builder = http.request(method, url);
    for (name, value) in &request.headers {
        builder = builder.header(name, fill(value));
    }
    if let Some(json) = &request.json {
        builder = builder.body(fill(&json.to_string()));
    }
    if let Some(body) = &request.body {
        builder = builder.body(fill(body));
    }
    let mut response = builder.send().await.map_err(|e| e.to_string())?;
    if matches!(case.given.as_str(), "consent_ok" | "consent_denied") {
        // The request was the device's /login URL; the expected answer is where the browser
        // ends up after the walk.
        let granted = case.given == "consent_ok";
        response = walk_consent(&http, response, granted, &v.check_code).await?;
    }

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
    match (&want.location, header("location")) {
        (None, None) => {}
        (None, Some(got)) => return Err(format!("an unexpected Location header: {got}")),
        (Some(pattern), got) => {
            let got = got.unwrap_or_default();
            if !regex_full_match(pattern, &got)? {
                return Err(format!("Location {got:?} does not match {pattern}"));
            }
        }
    }
    let answered = Answered {
        status,
        content_type: header("content-type").unwrap_or_default(),
        retry_after: header("retry-after"),
        body: response.bytes().await.map_err(|e| e.to_string())?.to_vec(),
    };
    let text = String::from_utf8_lossy(&answered.body);
    for part in &want.body_contains {
        if !text.contains(part.as_str()) {
            return Err(format!("the body does not contain {part:?}"));
        }
    }
    if let Some(expected) = &want.json {
        let got: Value =
            serde_json::from_str(&text).map_err(|e| format!("the body is not JSON: {e}"))?;
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

/// What the mapping table of §2.4 assigns to an answer of `/token` or `/refresh`.
#[derive(Debug, PartialEq)]
enum Mapped {
    Tokens { refresh_expires_in: Option<u64> },
    Expired,
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
        AuthError::LoginFailed(_) => Mapped::LoginFailed,
        AuthError::NotAllowed(_) => Mapped::NotAllowed,
        AuthError::ScopeMissing => Mapped::ScopeMissing,
        AuthError::Denied(_) => Mapped::Denied,
        AuthError::WorkerMisconfigured(_) => Mapped::WorkerMisconfigured,
        AuthError::Network(_) => Mapped::Network,
        other => panic!("an error outside the mapping table: {other:?}"),
    }
}

/// The table, written out independently of `auth/login.rs`: (expected result, requests the
/// client may send before it gives that result).
fn table(token_route: bool, status: u16, body: &Value) -> (Mapped, usize) {
    let code = body.get("error").and_then(Value::as_str).unwrap_or("");
    match (status, code) {
        (200, _) => {
            let refresh_expires_in = body.get("refresh_token_expires_in").and_then(Value::as_u64);
            (Mapped::Tokens { refresh_expires_in }, 1)
        }
        (400, "invalid_grant") if token_route => (Mapped::LoginFailed, 1),
        (400, "invalid_grant") => (Mapped::Expired, 1),
        (403, "email_not_allowed") => (Mapped::NotAllowed, 1),
        (403, "scope_missing") => (Mapped::ScopeMissing, 1),
        (403, "scope_not_allowed") => (Mapped::Denied, 1),
        (403, "access_denied") => (Mapped::Denied, 1),
        (500, "client_invalid" | "server_misconfigured") => (Mapped::WorkerMisconfigured, 1),
        // wait Retry-After, retry once
        (429, _) => (Mapped::Network, 2),
        // /token: at once; /refresh: five tries
        (500..=599, _) => (Mapped::Network, if token_route { 1 } else { 5 }),
        _ => (Mapped::Network, 1),
    }
}

/// Feeds a recorded answer through the Rust client and compares with the table.
async fn check_client_mapping(name: String, token_route: bool, answered: Answered) {
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
    let (want, requests) = table(token_route, answered.status, &body);
    let got = if token_route {
        match auth::redeem(&http(), &ep, "g-1", VERIFIER).await {
            Ok(grant) => Mapped::Tokens {
                refresh_expires_in: grant.refresh_expires_in,
            },
            Err(e) => mapped_error(&e),
        }
    } else {
        match auth::refresh(&http(), &ep, "rt-contract").await {
            Ok(_) => Mapped::Tokens {
                refresh_expires_in: None,
            },
            Err(e) => mapped_error(&e),
        }
    };
    assert_eq!(
        got, want,
        "case {name}: the client's result for a {} answer",
        answered.status
    );
    assert_eq!(
        stub_hits(&server).await,
        requests,
        "case {name}: requests sent"
    );
}

#[tokio::test]
async fn contract_fixture_matches_the_fake_and_the_client() {
    let contract = contract();
    assert_eq!(contract.version, 1);
    let v = &contract.vector;
    let pkce = Pkce::from_verifier(&v.verifier, &v.state);
    assert_eq!(pkce.challenge, v.challenge);
    assert_eq!(pkce.check_code(), v.check_code);
    assert_eq!(
        (v.verifier.as_str(), v.challenge.as_str(), v.state.as_str()),
        (VERIFIER, CHALLENGE, STATE)
    );
    assert_eq!((v.port, v.email.as_str()), (8123, "me@example.com"));

    let names: Vec<&str> = contract.cases.iter().map(|c| c.name.as_str()).collect();
    let unique: std::collections::HashSet<&&str> = names.iter().collect();
    assert_eq!(unique.len(), names.len(), "case names repeat");
    let missing: Vec<&&str> = REQUIRED_CASES
        .iter()
        .filter(|c| !names.contains(c))
        .collect();
    assert!(missing.is_empty(), "the fixture lacks {missing:?}");

    // Every case against the fake's routes; every /token and /refresh answer through the client.
    let mut replays = Vec::new();
    for case in &contract.cases {
        let answered = run_case(v, case)
            .await
            .unwrap_or_else(|why| panic!("case {} (given {}): {why}", case.name, case.given));
        let path = case.request["path"].as_str().unwrap_or("");
        if matches!(path, "/token" | "/refresh") {
            replays.push(check_client_mapping(
                case.name.clone(),
                path == "/token",
                answered,
            ));
        }
    }
    assert!(
        replays.len() >= 21,
        "every /token and /refresh case is replayed"
    );
    futures_util::future::join_all(replays).await;
}

#[tokio::test]
async fn contract_runner_refuses_what_it_does_not_know_and_notices_wrong_answers() {
    let contract = contract();
    let v = &contract.vector;
    let base: Case = serde_json::from_value(json!({
        "name": "x", "given": "none",
        "request": { "method": "GET", "path": "/nothing-here" },
        "response": { "status": 404 }
    }))
    .unwrap();
    run_case(v, &base).await.unwrap();
    let with = |patch: fn(&mut Case)| {
        let mut case = base.clone();
        patch(&mut case);
        case
    };
    let refused = |case: Case, why: &'static str| async move {
        match run_case(v, &case).await {
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
    refused(with(|c| c.request["cookies"] = json!({})), "unknown key").await;
    refused(
        with(|c| c.request["query"] = json!({ "a": "<nonce>" })),
        "unknown placeholder",
    )
    .await;
    refused(
        with(|c| c.response["location"] = json!("(a|b)")),
        "unsupported regular expression",
    )
    .await;
    assert!(
        serde_json::from_value::<Case>(
            json!({ "name": "x", "given": "none", "request": {}, "response": {}, "note": 1 })
        )
        .is_err()
    );

    let token_get = contract
        .cases
        .iter()
        .find(|c| c.name == "token_get")
        .unwrap()
        .clone();
    let wrong = |patch: fn(&mut Case)| {
        let mut case = token_get.clone();
        patch(&mut case);
        case
    };
    run_case(v, &token_get).await.unwrap();
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
    refused(
        wrong(|c| c.response["location"] = json!("http://.+")),
        "Location",
    )
    .await;
    refused(
        wrong(|c| c.response["body_contains"] = json!(["no such text"])),
        "does not contain",
    )
    .await;
    // a redirect where the fixture expects none
    let loopback = contract
        .cases
        .iter()
        .find(|c| c.name == "loopback_grant")
        .unwrap()
        .clone();
    let mut no_location = loopback.clone();
    no_location
        .response
        .as_object_mut()
        .unwrap()
        .remove("location");
    refused(no_location, "unexpected Location").await;
    let mut other_port = loopback;
    other_port.response["location"] =
        json!("^http://127\\.0\\.0\\.1:9999/\\?code=[A-Za-z0-9_-]+&state=AAAAAAAAAAAAAAAAAAAAAA$");
    refused(other_port, "does not match").await;
}

#[test]
fn the_fixture_regex_subset() {
    let m = |p: &str, t: &str| regex_full_match(p, t).unwrap();
    let grant = r"^http://127\.0\.0\.1:8123/\?code=[A-Za-z0-9_-]+&state=AAAAAAAAAAAAAAAAAAAAAA$";
    assert!(m(
        grant,
        "http://127.0.0.1:8123/?code=g-3&state=AAAAAAAAAAAAAAAAAAAAAA"
    ));
    assert!(
        !m(
            grant,
            "http://127.0.0.1:8123/?code=&state=AAAAAAAAAAAAAAAAAAAAAA"
        ),
        "+ needs one"
    );
    assert!(
        !m(
            grant,
            "http://127x0.0.1:8123/?code=g&state=AAAAAAAAAAAAAAAAAAAAAA"
        ),
        "an escaped dot is a dot"
    );
    assert!(
        !m(
            grant,
            "http://127.0.0.1:8123/?code=g.3&state=AAAAAAAAAAAAAAAAAAAAAA"
        ),
        "the class is closed"
    );
    assert!(
        !m(
            grant,
            "xhttp://127.0.0.1:8123/?code=g&state=AAAAAAAAAAAAAAAAAAAAAA"
        ),
        "in full"
    );
    assert!(
        !m(
            grant,
            "http://127.0.0.1:8123/?code=g&state=AAAAAAAAAAAAAAAAAAAAAAB"
        ),
        "in full"
    );
    assert!(m(
        r"/\?error=access_denied&state=.*",
        "/?error=access_denied&state=xyz"
    ));
    assert!(m("ab?c*[x-z]", "acccz") && m("ab?c*[x-z]", "abx") && !m("ab?c*[x-z]", "abbx"));
    assert!(m("[a-]+", "a-a") && !m("[a-]+", "b"));
    for unsupported in ["(a)", "a|b", "a{2}", r"\d+", "[^a]"] {
        assert!(regex_full_match(unsupported, "a").is_err(), "{unsupported}");
    }
}

//! `gclone web` over real HTTP (SPEC §7.4, §12.1): every test spawns the built binary with
//! `web --no-browser` on a free loopback port and talks to it over a plain TCP socket, so that
//! every header — `Host`, `Origin`, `Cookie` — is exactly what the test wrote.
//!
//! Vaults are directories (`--vault-dir`), except in the one Drive test, which runs the viewer
//! against `FakeDrive`. No test opens a browser.

#[path = "support/fake_drive.rs"]
mod fake_drive;

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fake_drive::{FakeDrive, Route};

const BIN: &str = env!("CARGO_BIN_EXE_gclone");
const PASS: &str = "correct horse battery staple";
/// What the viewer says without the session.
const USE_THE_LINK: &str = "open the link that `gclone web` printed";

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct Lab {
    tmp: tempfile::TempDir,
}

impl Lab {
    fn new() -> Lab {
        Lab {
            tmp: tempfile::tempdir().expect("temp dir"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }

    fn pass(&self) -> String {
        let path = self.path("pass");
        std::fs::write(&path, format!("{PASS}\n")).expect("write");
        s(&path)
    }

    fn device(&self, name: &str) -> Device {
        Device {
            config: self.path(&format!("{name}-config")),
            state: self.path(&format!("{name}-state")),
            home: self.path("home"),
            env: Vec::new(),
        }
    }

    /// A device connected to the lab's directory vault (created by the first one).
    fn connected(&self, name: &str) -> Device {
        let d = self.device(name);
        let (vault, pass) = (s(&self.path("vault")), self.pass());
        d.ok(&[
            "login",
            "--vault-dir",
            &vault,
            "--passphrase-file",
            &pass,
            "--device-name",
            name,
        ]);
        d
    }

    /// The data objects of the directory vault, largest first.
    fn blobs(&self) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let data = self.path("vault").join("gclone").join("data");
        for folder in std::fs::read_dir(data).expect("data folder") {
            for object in std::fs::read_dir(folder.expect("entry").path()).expect("folder") {
                let path = object.expect("entry").path();
                found.push((std::fs::metadata(&path).expect("stat").len(), path));
            }
        }
        found.sort();
        found.into_iter().rev().map(|(_, path)| path).collect()
    }
}

fn s(p: &Path) -> String {
    p.to_str().expect("UTF-8 path").to_string()
}

fn pattern(seed: u8, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    blake3::Hasher::new()
        .update(&[seed])
        .finalize_xof()
        .fill(&mut buf);
    buf
}

fn write(path: &Path, content: &[u8]) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, content).expect("write");
}

#[derive(Clone)]
struct Device {
    config: PathBuf,
    state: PathBuf,
    home: PathBuf,
    env: Vec<(String, String)>,
}

impl Device {
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env("GCLONE_CONFIG_DIR", &self.config)
            .env("GCLONE_STATE_DIR", &self.state)
            .env("GCLONE_TEST_FAST_KDF", "1")
            // No Secure Enclave trial in a spawned gclone (§8.2); see tests/keystore.rs.
            .env("GCLONE_KEYSTORE_TRIAL", "0")
            .env("HOME", &self.home)
            .env("TZ", "UTC")
            .env_remove("GCLONE_AUTH_URL")
            .env_remove("GCLONE_LOG")
            .envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::null());
        cmd
    }

    /// `(exit code, stdout, stderr)`.
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let out = self.command(args).output().expect("spawn gclone");
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert!(
            !stderr.contains("panicked"),
            "the binary panicked:\n{stderr}"
        );
        (out.status.code().unwrap_or(-1), stdout, stderr)
    }

    #[track_caller]
    fn ok(&self, args: &[&str]) -> String {
        let (code, stdout, stderr) = self.run(args);
        assert_eq!(
            code, 0,
            "{args:?}\n--- stdout\n{stdout}\n--- stderr\n{stderr}"
        );
        stdout
    }

    /// The vault's state directory (`<state root>/<vault id>`).
    fn vault_state(&self) -> PathBuf {
        let config = std::fs::read(self.config.join("config.json")).expect("config.json");
        let config: serde_json::Value = serde_json::from_slice(&config).expect("json");
        self.state
            .join(config["vault_id"].as_str().expect("vault_id"))
    }
}

/// One HTTP response, as received.
struct Res {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Res {
    /// The one header of that name (lower case); panics if it is sent twice.
    #[track_caller]
    fn header(&self, name: &str) -> Option<&str> {
        let mut found = self.headers.iter().filter(|(n, _)| n == name);
        let value = found.next().map(|(_, v)| v.as_str());
        assert!(found.next().is_none(), "{name} is sent twice");
        value
    }

    #[track_caller]
    fn has(&self, name: &str, value: &str) -> &Res {
        assert_eq!(self.header(name), Some(value), "{name}");
        self
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    #[track_caller]
    fn json(&self) -> serde_json::Value {
        assert_eq!(self.status, 200, "{}", self.text());
        self.has("content-type", "application/json");
        serde_json::from_slice(&self.body).expect("JSON body")
    }

    /// The body is as long as `Content-Length` promised.
    fn complete(&self) -> bool {
        self.header("content-length")
            .and_then(|l| l.parse::<usize>().ok())
            .is_some_and(|l| l == self.body.len())
    }
}

/// Sends `request` to the viewer and reads the answer until the server closes the connection
/// (every request asks for that). A connection that is cut gives what arrived before the cut.
fn exchange(port: u16, request: &[u8]) -> Res {
    try_exchange(port, request, Duration::from_secs(60)).expect("an answer from the viewer")
}

/// As `exchange`; `None` if the viewer does not accept the connection or sends no response
/// head within `patience` — it has ended, or it is stopped.
fn try_exchange(port: u16, request: &[u8], patience: Duration) -> Option<Res> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(patience)).expect("timeout");
    stream.write_all(request).ok()?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    }
    raw.windows(4)
        .any(|w| w == b"\r\n\r\n")
        .then(|| parse(&raw))
}

fn parse(raw: &[u8]) -> Res {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no response head in {:?}", String::from_utf8_lossy(raw)));
    let head = std::str::from_utf8(&raw[..end]).expect("ASCII head");
    let mut lines = head.split("\r\n");
    let status = lines.next().expect("status line");
    assert!(status.starts_with("HTTP/1."), "{status}");
    let headers = lines
        .map(|line| {
            let (name, value) = line.split_once(':').expect("header line");
            (name.to_ascii_lowercase(), value.trim().to_string())
        })
        .collect();
    Res {
        status: status[9..12].parse().expect("status code"),
        headers,
        body: raw[end + 4..].to_vec(),
    }
}

/// A running `gclone web --no-browser`.
struct Viewer {
    child: Option<Child>,
    /// Kept open: the viewer may print again.
    stdout: std::io::BufReader<std::process::ChildStdout>,
    port: u16,
    /// The one-time link the viewer printed, as the path and query of its URL.
    link: String,
    /// `name=value` once `sign_in` has exchanged the link.
    cookie: String,
    /// `/s-<random>/`, the cookie's path: where the page, the API and the files live.
    prefix: String,
    /// What the viewer wrote to stderr, at `-vv`.
    log: PathBuf,
}

impl Viewer {
    /// The command of a viewer that logs to a file of its own; stdin is not a terminal.
    fn command(d: &Device, lab: &Lab, args: &[&str]) -> (Command, PathBuf) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let log = lab.path(&format!("viewer-{n}.log"));
        let mut command = d.command(args);
        command
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(&log).expect("log file"));
        (command, log)
    }

    /// Starts the viewer and waits for its link; nothing is sent yet.
    fn spawn(d: &Device, lab: &Lab) -> Viewer {
        let (mut command, log) = Viewer::command(d, lab, &["-vv", "web", "--no-browser"]);
        Viewer::launched(command.spawn().expect("spawn gclone web"), log)
    }

    /// A viewer that was just spawned with its stdout piped: waits for its link.
    fn launched(mut child: Child, log: PathBuf) -> Viewer {
        let stdout = std::io::BufReader::new(child.stdout.take().expect("stdout"));
        let mut viewer = Viewer {
            child: Some(child),
            stdout,
            port: 0,
            link: String::new(),
            cookie: String::new(),
            prefix: String::new(),
            log,
        };
        let printed = viewer.next_link();
        assert!(printed.contains("read-only"), "{printed}");
        viewer
    }

    /// Reads the viewer's stdout up to the next link, which becomes `self.link`; returns
    /// what was printed on the way.
    fn next_link(&mut self) -> String {
        let mut printed = String::new();
        loop {
            let mut line = String::new();
            if self.stdout.read_line(&mut line).expect("stdout") == 0 {
                if let Some(child) = &mut self.child {
                    let _ = child.wait();
                }
                panic!(
                    "gclone web ended without a link\n--- stdout\n{printed}\n--- stderr\n{}",
                    std::fs::read_to_string(&self.log).unwrap_or_default()
                );
            }
            printed.push_str(&line);
            if let Some(url) = line.trim().strip_prefix("http://127.0.0.1:") {
                let (port, link) = url.split_once('/').expect("port/path");
                self.port = port.parse().expect("port");
                self.link = format!("/{link}");
                return printed;
            }
        }
    }

    /// Starts the viewer and follows its link, as the browser would.
    fn start(d: &Device, lab: &Lab) -> Viewer {
        let mut viewer = Viewer::spawn(d, lab);
        viewer.sign_in();
        viewer
    }

    /// Follows the link as a browser does that was handed it by the user (typed, pasted,
    /// opened from a terminal): a redirect to the session's own path, and the cookie for it.
    #[track_caller]
    fn sign_in(&mut self) {
        let res = self.send("GET", &self.link, &[("Sec-Fetch-Site", "none")]);
        assert_eq!(res.status, 303, "{}", res.text());
        self.take_session(&res);
        res.has("location", &self.prefix);
    }

    /// The cookie of an answer to the link, and the path it is scoped to.
    #[track_caller]
    fn take_session(&mut self, res: &Res) {
        let cookie = res.header("set-cookie").expect("a cookie");
        let (pair, attributes) = cookie.split_once("; ").expect("attributes");
        let path = attributes
            .strip_prefix("Path=")
            .and_then(|rest| rest.strip_suffix("; HttpOnly; SameSite=Strict"))
            .unwrap_or_else(|| panic!("the cookie's attributes: {attributes}"));
        // 128 random bits, base64url.
        let random = path
            .strip_prefix("/s-")
            .and_then(|rest| rest.strip_suffix('/'))
            .unwrap_or_else(|| panic!("the cookie's path: {path}"));
        assert_eq!(random.len(), 22, "{path}");
        assert!(
            random
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "{path}"
        );
        self.cookie = pair.to_string();
        self.prefix = path.to_string();
    }

    /// `route` (`/api/info`, `/file?…`, `/`) under the session's prefix.
    fn at(&self, route: &str) -> String {
        format!("{}{route}", self.prefix.trim_end_matches('/'))
    }

    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// The key of the one-time link.
    fn key(&self) -> &str {
        self.link.strip_prefix("/?k=").expect("/?k=KEY")
    }

    /// One request with exactly these headers, plus `Host` (unless given) and
    /// `Connection: close`.
    fn send(&self, method: &str, target: &str, headers: &[(&str, &str)]) -> Res {
        let mut request = format!("{method} {target} HTTP/1.1\r\nConnection: close\r\n");
        if !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host")) {
            request.push_str(&format!("Host: {}\r\n", self.host()));
        }
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        exchange(self.port, request.as_bytes())
    }

    /// A request of the signed-in browser. A `target` that is a route (`/…`) is addressed
    /// under the session's prefix; an absolute one is sent as it is.
    fn with(&self, method: &str, target: &str, headers: &[(&str, &str)]) -> Res {
        let mut all = vec![("Cookie", self.cookie.as_str())];
        all.extend_from_slice(headers);
        match target.starts_with('/') {
            true => self.send(method, &self.at(target), &all),
            false => self.send(method, target, &all),
        }
    }

    /// `GET route` of the signed-in browser with these raw header lines (no line ends) after
    /// `Host` and `Connection` — for bytes a `&str` cannot hold. The cookie is not added.
    fn raw(&self, route: &str, lines: &[&[u8]]) -> Res {
        let mut request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.at(route),
            self.host()
        )
        .into_bytes();
        for line in lines {
            request.extend_from_slice(line);
            request.extend_from_slice(b"\r\n");
        }
        request.extend_from_slice(b"\r\n");
        exchange(self.port, &request)
    }

    fn get(&self, target: &str) -> Res {
        self.with("GET", target, &[])
    }

    #[track_caller]
    fn json(&self, target: &str) -> serde_json::Value {
        self.get(target).json()
    }

    /// The names of a listing, in the order served.
    #[track_caller]
    fn names(&self, query: &str) -> Vec<String> {
        let listing = self.json(&format!("/api/list?{query}"));
        let entries = listing["entries"].as_array().expect("entries");
        entries
            .iter()
            .map(|e| e["name"].as_str().expect("name").to_string())
            .collect()
    }

    /// `POST /api/refresh` → its `refresh` object.
    #[track_caller]
    fn refresh(&self) -> serde_json::Value {
        let origin = format!("http://{}", self.host());
        self.with("POST", "/api/refresh", &[("Origin", &origin)])
            .json()["refresh"]
            .clone()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).expect("viewer log")
    }

    /// Ctrl-C; the exit code.
    fn interrupt(mut self) -> Option<i32> {
        let mut child = self.child.take().expect("running");
        // SAFETY: signals the child this test spawned and still owns.
        assert_eq!(
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) },
            0
        );
        child.wait().expect("wait").code()
    }

    /// Waits for the viewer to end by itself; its exit code.
    #[track_caller]
    fn ended(mut self) -> Option<i32> {
        let mut child = self.child.take().expect("running");
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = child.try_wait().expect("wait") {
                return status.code();
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the viewer is still running\n{}", self.log());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Viewer {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Percent-encodes a query value.
fn enc(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'/' => {
                (b as char).to_string()
            }
            b => format!("%{b:02X}"),
        })
        .collect()
}

fn file(path: &str) -> String {
    format!("/file?path={}", enc(path))
}

/// A vault with one device `a` that pushed `tree` (made by the closure) to the vault root.
fn vault_with(tree: impl FnOnce(&Path)) -> (Lab, Device) {
    let lab = Lab::new();
    let a = lab.connected("a");
    let src = lab.path("src");
    std::fs::create_dir_all(&src).expect("mkdir");
    tree(&src);
    a.ok(&["copy", &s(&src), ":"]);
    (lab, a)
}

const BIG: usize = 1_300_000;

/// A packed small file, an empty one, a blob of its own that spans twenty chunks, nested and
/// empty directories.
fn small_tree(root: &Path) {
    write(&root.join("docs/a.txt"), b"alpha\n");
    write(&root.join("docs/empty"), b"");
    write(&root.join("docs/big.bin"), &pattern(1, BIG));
    write(&root.join("docs/sub/b.txt"), b"bravo\n");
    write(&root.join("docs/sub/deep/c.bin"), &pattern(2, 70_000));
    std::fs::create_dir_all(root.join("hollow")).expect("mkdir");
}

// ---------------------------------------------------------------------------------------------
// The session secret, Host and Origin
// ---------------------------------------------------------------------------------------------

#[test]
fn the_session_secret_guards_every_route() {
    let (lab, a) = vault_with(small_tree);
    let mut v = Viewer::spawn(&a, &lab);
    let routes = [
        "/",
        "/assets/app.css",
        "/assets/app.js",
        "/assets/icon.svg",
        "/api/info",
        "/api/list",
        "/api/list?path=docs",
        "/api/stat?path=docs/a.txt",
        "/api/search?q=a",
        "/api/versions?path=docs/a.txt",
        "/api/deleted",
        "/api/timeline",
        "/file?path=docs/a.txt",
    ];
    let others = ["/nope", "/assets/", "/api/refresh", "/favicon.ico"];
    let key = v.key().to_string();
    let refused = |res: &Res, what: &str| {
        assert_eq!(res.status, 403, "{what}");
        res.has("content-type", "text/plain; charset=utf-8")
            .has("cache-control", "no-store");
        assert!(res.header("set-cookie").is_none(), "{what}");
        let text = res.text();
        assert!(
            text.contains(USE_THE_LINK)
                || text.contains("used already")
                || text.contains("not a valid link"),
            "{what}: {text}"
        );
        // Nothing of the vault, of the page or of the secrets is in a refusal.
        for leak in ["alpha", "docs", "<html", "gclone_web_", "/s-", key.as_str()] {
            assert!(!text.contains(leak), "{what}: {text}");
        }
    };

    // Without the cookie: nothing, on any route, with any method — known or not.
    for route in routes.iter().chain(&others) {
        for method in ["GET", "HEAD", "POST"] {
            let res = v.send(method, route, &[]);
            if method == "HEAD" {
                assert_eq!(res.status, 403, "{method} {route}");
            } else {
                refused(&res, &format!("{method} {route}"));
            }
        }
    }
    // A wrong key, the key in the wrong place.
    refused(
        &v.send("GET", "/?k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &[]),
        "wrong key",
    );
    refused(&v.send("GET", "/?k=", &[]), "empty key");
    let elsewhere = format!("/api/info?k={}", v.key());
    refused(&v.send("GET", &elsewhere, &[]), "the key on another route");
    refused(&v.send("POST", &v.link, &[]), "the key with POST");
    let head = v.send("HEAD", &v.link, &[]);
    assert_eq!(head.status, 403, "the key with HEAD");
    assert!(head.header("set-cookie").is_none());
    // The key as a cookie is not the key either.
    let as_cookie = format!("gclone_web_{}={}", v.port, v.key());
    refused(
        &v.send("GET", "/", &[("Cookie", &as_cookie)]),
        "the key as the cookie",
    );

    // The secrets are long enough: 192 bits in the link, 256 in the cookie.
    assert_eq!(v.key().len(), 32, "{}", v.key());
    // The link, once: the cookie, and a redirect to the session's path — without the key.
    v.sign_in();
    let (name, value) = v.cookie.split_once('=').expect("name=value");
    let secret = value.to_string();
    assert_eq!(name, format!("gclone_web_{}", v.port));
    assert_eq!(value.len(), 43);
    assert_ne!(value, v.key(), "the cookie is not the link's key");
    assert!(!v.prefix.contains(v.key()) && !v.prefix.contains(value));
    // ... and never again: a second use says that somebody was there first, and what to do.
    for headers in [
        &[][..],
        &[("Sec-Fetch-Site", "none")][..],
        &[("Cookie", v.cookie.as_str())][..],
    ] {
        let again = v.send("GET", &v.link, headers);
        refused(&again, "the link a second time");
        let text = again.text();
        assert!(text.contains("used already"), "{text}");
        assert!(text.contains("another program on this machine"), "{text}");
        assert!(text.contains("stop `gclone web` (Ctrl-C)"), "{text}");
    }
    // A key that never was one is not "used".
    let unknown = v.send("GET", "/?k=whatever", &[("Cookie", &v.cookie)]);
    refused(&unknown, "no key of this viewer");
    assert!(unknown.text().contains("not a valid link"));

    // The cookie alone is not enough either: outside the session's path there is nothing,
    // and under the path nothing without the cookie.
    let wrong = format!("gclone_web_{}={}", v.port, "A".repeat(43));
    for route in routes.iter().chain(&others) {
        refused(
            &v.send("GET", route, &[("Cookie", &v.cookie)]),
            &format!("{route} outside the session's path"),
        );
        refused(
            &v.send("GET", &v.at(route), &[]),
            &format!("{route} without the cookie"),
        );
        refused(
            &v.send("GET", &v.at(route), &[("Cookie", &wrong)]),
            &format!("{route} with a wrong cookie"),
        );
    }
    let bare = v.prefix.trim_end_matches('/').to_string();
    refused(
        &v.send("GET", &bare, &[("Cookie", &v.cookie)]),
        "the path without its slash",
    );
    let other_path = format!("/s-{}/api/info", "A".repeat(22));
    refused(
        &v.send("GET", &other_path, &[("Cookie", &v.cookie)]),
        "another session's path",
    );

    // With the cookie, under the path: everything.
    for route in routes {
        let res = v.get(route);
        assert_eq!(res.status, 200, "{route}: {}", res.text());
        res.has("cache-control", "no-store")
            .has("x-content-type-options", "nosniff")
            .has("referrer-policy", "no-referrer")
            .has("cross-origin-resource-policy", "same-origin");
        assert!(res.complete(), "{route}");
        assert!(res.header("content-security-policy").is_some(), "{route}");
        assert!(res.header("set-cookie").is_none(), "{route}");
        let head = v.with("HEAD", route, &[]);
        assert_eq!(head.status, 200, "HEAD {route}");
        assert!(head.body.is_empty(), "HEAD {route}");
        assert_eq!(
            head.header("content-length"),
            res.header("content-length"),
            "HEAD {route}"
        );
    }
    assert_eq!(v.get("/nope").status, 404);
    assert_eq!(v.get("/assets/").status, 404);
    assert_eq!(v.get("/assets/app.js.map").status, 404);
    assert_eq!(v.get("/favicon.ico").status, 404);

    // The page: one document, its own script and style, a strict policy.
    let page = v.get("/");
    page.has("content-type", "text/html; charset=utf-8")
        .has("content-security-policy", gclone::web::PAGE_CSP);
    assert_eq!(page.body, gclone::web::INDEX_HTML.as_bytes());
    v.get("/assets/app.js")
        .has("content-type", "text/javascript; charset=utf-8");
    v.get("/assets/app.css")
        .has("content-type", "text/css; charset=utf-8");
    v.get("/assets/icon.svg")
        .has("content-type", "image/svg+xml");

    // Neither secret reached the log, at -vv; of a request it shows the method and the
    // route, never the query (the link's key, the names of files).
    let log = v.log();
    assert!(log.contains("web: GET /api/list\n"), "{log}");
    assert!(log.contains("web: GET /\n"), "{log}");
    for secret in [key.as_str(), secret.as_str()] {
        assert!(!log.contains(secret), "the log contains {secret:?}:\n{log}");
    }
    for line in log.lines().filter(|line| line.contains("web:")) {
        assert!(!line.contains('?') && !line.contains("a.txt"), "{line}");
    }
}

/// The cookie is scoped to the session's random path, so the browser shows it to no other
/// server on the loopback host (cookies are not separated by port); and it is found among
/// whatever cookies those other servers set — the browser sends them all in one header.
#[test]
fn the_cookie_is_scoped_to_its_session_and_found_among_foreign_cookies() {
    let (lab, a) = vault_with(small_tree);
    let v = Viewer::start(&a, &lab);
    let w = Viewer::start(&a, &lab);
    // Two viewers, two paths, two secrets.
    assert_ne!(v.prefix, w.prefix);
    assert_ne!(
        v.cookie.split_once('=').expect("pair").1,
        w.cookie.split_once('=').expect("pair").1
    );
    assert_eq!(
        w.send("GET", &w.at("/api/info"), &[("Cookie", &v.cookie)])
            .status,
        403
    );

    let cookie = v.cookie.as_bytes();
    let line = |before: &[u8], after: &[u8]| [b"Cookie: ", before, cookie, after].concat();
    for (what, header) in [
        ("alone", line(b"", b"")),
        ("after another", line(b"theme=dark; ", b"")),
        ("without the space", line(b"theme=dark;", b";x=y")),
        // Chrome and Firefox put non-ASCII cookie values on the wire as UTF-8.
        (
            "after a UTF-8 value",
            line("display_name=J\u{fc}rgen; ".as_bytes(), b""),
        ),
        (
            "before a UTF-8 value",
            line(b"", "; city=K\u{f6}ln".as_bytes()),
        ),
        ("after bytes that are no text", line(b"\xff\xfe=1; ", b"")),
        ("after a pair without a value", line(b"flag; =; ", b"; ")),
    ] {
        let res = v.raw("/api/info", &[&header]);
        assert_eq!(res.status, 200, "{what}: {}", res.text());
    }
    // Two Cookie headers.
    assert_eq!(
        v.raw(
            "/api/info",
            &[b"Cookie: display_name=J\xc3\xbcrgen", &line(b"", b"")]
        )
        .status,
        200
    );
    // The value has to be the whole secret, under the right name.
    let (name, secret) = v.cookie.split_once('=').expect("pair");
    for wrong in [
        format!("Cookie: {name}={}", &secret[..42]),
        format!("Cookie: {name}={secret}A"),
        format!("Cookie: x{name}={secret}"),
        format!("Cookie: {name}x={secret}"),
        format!("Cookie: other={secret}"),
        format!("Cookie: {name}"),
        "Cookie: \u{fc}".to_string(),
    ] {
        let res = v.raw("/api/info", &[wrong.as_bytes()]);
        assert_eq!(res.status, 403, "{wrong}");
    }
}

/// `Origin` and `Sec-Fetch-Site` decide whether a request is this page's own: a value the
/// server cannot read, or a second header, is refused — never taken for "not there".
#[test]
fn unreadable_or_repeated_origin_headers_are_refused() {
    let (lab, a) = vault_with(small_tree);
    let v = Viewer::start(&a, &lab);
    let cookie = format!("Cookie: {}", v.cookie);
    let own = format!("Origin: http://{}", v.host());
    let ask = |lines: &[&[u8]]| {
        let mut all: Vec<&[u8]> = vec![cookie.as_bytes()];
        all.extend_from_slice(lines);
        v.raw("/file?path=docs/a.txt", &all)
    };
    assert_eq!(ask(&[]).status, 200);
    assert_eq!(ask(&[own.as_bytes()]).status, 200);
    assert_eq!(
        ask(&[own.as_bytes(), b"Sec-Fetch-Site: same-origin"]).status,
        200
    );
    for (what, lines) in [
        ("Origin that is no text", vec![&b"Origin: \xff"[..]]),
        (
            "Origin with a UTF-8 host",
            vec!["Origin: http://b\u{fc}cher.example".as_bytes()],
        ),
        (
            "Origin twice, the own one first",
            vec![own.as_bytes(), b"Origin: http://evil.example"],
        ),
        (
            "Origin twice, both the own",
            vec![own.as_bytes(), own.as_bytes()],
        ),
        (
            "Sec-Fetch-Site that is no text",
            vec![&b"Sec-Fetch-Site: \xffcross-site"[..]],
        ),
        (
            "Sec-Fetch-Site twice",
            vec![
                &b"Sec-Fetch-Site: same-origin"[..],
                b"Sec-Fetch-Site: cross-site",
            ],
        ),
        (
            "Sec-Fetch-Site twice, both fine",
            vec![&b"Sec-Fetch-Site: none"[..], b"Sec-Fetch-Site: none"],
        ),
    ] {
        let res = ask(&lines);
        assert_eq!(res.status, 403, "{what}");
        assert!(!res.text().contains("alpha"), "{what}");
    }
}

/// 64 KiB of request head (SPEC §7.4) — the number is enforced, not only hyper's buffer.
#[test]
fn request_heads_are_limited_to_64_kib() {
    let (lab, a) = vault_with(small_tree);
    let v = Viewer::start(&a, &lab);
    let head = |bytes: usize| v.with("GET", "/api/info", &[("X-Padding", &"a".repeat(bytes))]);
    assert_eq!(head(1_000).status, 200);
    assert_eq!(head(60 * 1024).status, 200);
    for too_large in [70_000, 100_000, 200_000] {
        let res = head(too_large);
        assert_eq!(res.status, 431, "{too_large}");
        assert!(!res.text().contains("gclone_web_"), "{}", res.text());
    }
    // Many small headers count as one large one does.
    let many: Vec<(String, String)> = (0..700)
        .map(|i| (format!("X-Padding-{i}"), "a".repeat(90)))
        .collect();
    let many: Vec<(&str, &str)> = many.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
    assert_eq!(v.with("GET", "/api/info", &many).status, 431);
    assert_eq!(v.with("GET", "/api/info", &many[..90]).status, 200);
    // A request line of that size is refused as well, and the server is still there.
    let long = format!("/api/list?path={}", "a".repeat(70_000));
    assert!(matches!(v.get(&long).status, 414 | 431));
    assert_eq!(v.get("/api/info").status, 200);
}

#[test]
fn host_and_origin_are_checked() {
    let (lab, a) = vault_with(small_tree);
    let mut v = Viewer::spawn(&a, &lab);
    let port = v.port;
    let own = format!("http://127.0.0.1:{port}");

    // A page of another site that follows the link in an <img> or a fetch gets nothing — and
    // does not use the key up.
    for headers in [
        vec![
            ("Sec-Fetch-Site", "cross-site"),
            ("Sec-Fetch-Mode", "no-cors"),
            ("Sec-Fetch-Dest", "image"),
        ],
        vec![
            ("Sec-Fetch-Site", "cross-site"),
            ("Sec-Fetch-Mode", "cors"),
            ("Sec-Fetch-Dest", "empty"),
        ],
        vec![
            ("Sec-Fetch-Site", "same-site"),
            ("Sec-Fetch-Mode", "no-cors"),
            ("Sec-Fetch-Dest", "script"),
        ],
        vec![("Origin", "http://evil.example")],
        vec![("Origin", "null")],
        vec![
            ("Origin", "http://evil.example"),
            ("Sec-Fetch-Site", "cross-site"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Dest", "document"),
        ],
    ] {
        let res = v.send("GET", &v.link, &headers);
        assert_eq!(res.status, 403, "{headers:?}");
        assert!(res.header("set-cookie").is_none(), "{headers:?}");
    }
    let wrong_host = v.send("GET", &v.link, &[("Host", "evil.example")]);
    assert_eq!(wrong_host.status, 403);
    assert!(wrong_host.header("set-cookie").is_none());
    // The key is still good.
    v.sign_in();

    let with = |headers: &[(&str, &str)]| v.with("GET", "/api/info", headers).status;
    // Host: the loopback names with this port, and nothing else.
    for (host, expected) in [
        (format!("127.0.0.1:{port}"), 200),
        (format!("localhost:{port}"), 200),
        (format!("LocalHost:{port}"), 200),
        (format!("[::1]:{port}"), 200),
        ("127.0.0.1".to_string(), 403),
        (format!("127.0.0.1:{}", port.wrapping_add(1).max(1)), 403),
        (format!("evil.example:{port}"), 403),
        (format!("127.0.0.1.evil.example:{port}"), 403),
        (format!("127.0.0.1:{port}.evil.example"), 403),
        (format!("0.0.0.0:{port}"), 403),
        (format!("user@127.0.0.1:{port}"), 403),
        (String::new(), 403),
    ] {
        assert_eq!(with(&[("Host", &host)]), expected, "Host: {host:?}");
    }
    let rebound = v.with("GET", "/api/info", &[("Host", "evil.example")]);
    assert!(rebound.text().contains("answers only as http://127.0.0.1:"));
    // Two Host headers, none (HTTP/1.0), and an absolute request target naming another host.
    assert_eq!(with(&[("Host", &v.host()), ("Host", "evil.example")]), 403);
    let no_host = format!(
        "GET {} HTTP/1.0\r\nCookie: {}\r\n\r\n",
        v.at("/api/info"),
        v.cookie
    );
    assert_eq!(exchange(port, no_host.as_bytes()).status, 403);
    assert_eq!(
        v.with("GET", "http://evil.example/api/info", &[]).status,
        403
    );
    let absolute = format!("{own}{}", v.at("/api/info"));
    assert_eq!(v.with("GET", &absolute, &[]).status, 200);

    // Origin and Sec-Fetch-Site: this server, or no page at all.
    for (headers, expected) in [
        (vec![("Origin", own.as_str())], 200),
        (vec![("Sec-Fetch-Site", "same-origin")], 200),
        (vec![("Sec-Fetch-Site", "none")], 200),
        (
            vec![("Origin", own.as_str()), ("Sec-Fetch-Site", "same-origin")],
            200,
        ),
        (vec![("Origin", "http://evil.example")], 403),
        (vec![("Origin", "null")], 403),
        (vec![("Origin", "http://127.0.0.1")], 403),
        (vec![("Origin", "http://127.0.0.1:1")], 403),
        (vec![("Sec-Fetch-Site", "cross-site")], 403),
        (vec![("Sec-Fetch-Site", "same-site")], 403),
        (
            vec![("Origin", own.as_str()), ("Sec-Fetch-Site", "cross-site")],
            403,
        ),
    ] {
        assert_eq!(with(&headers), expected, "{headers:?}");
        // Files and the refresh action are held to the same rule.
        let file = v.with("GET", "/file?path=docs/a.txt", &headers);
        assert_eq!(file.status, expected, "{headers:?}");
        if expected == 403 {
            assert!(!file.text().contains("alpha"));
            assert_eq!(
                v.with("POST", "/api/refresh", &headers).status,
                403,
                "{headers:?}"
            );
        }
    }
    let https_origin = format!("https://127.0.0.1:{port}");
    assert_eq!(with(&[("Origin", &https_origin)]), 403);

    // Methods.
    for (method, target, allow) in [
        ("POST", "/api/list", "GET, HEAD"),
        ("POST", "/api/versions?path=docs/a.txt", "GET, HEAD"),
        ("POST", "/api/deleted", "GET, HEAD"),
        ("DELETE", "/api/timeline", "GET, HEAD"),
        ("PUT", "/file?path=docs/a.txt", "GET, HEAD"),
        ("DELETE", "/file?path=docs/a.txt", "GET, HEAD"),
        ("POST", "/", "GET, HEAD"),
        ("GET", "/api/refresh", "POST"),
        ("HEAD", "/api/refresh", "POST"),
    ] {
        let res = v.with(method, target, &[]);
        assert_eq!(res.status, 405, "{method} {target}");
        res.has("allow", allow);
    }
    assert_eq!(
        v.get(&file("docs/a.txt")).body,
        b"alpha\n",
        "nothing was deleted"
    );

    // IPv6 loopback, where the machine has it and the port was free.
    if let Ok(mut six) = TcpStream::connect(("::1", port)) {
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: [::1]:{port}\r\nConnection: close\r\nCookie: {}\r\n\r\n",
            v.at("/api/info"),
            v.cookie
        );
        six.write_all(request.as_bytes()).expect("send");
        let mut raw = Vec::new();
        six.read_to_end(&mut raw).expect("read");
        assert_eq!(parse(&raw).status, 200);
    }
}

/// A link that the browser reaches through a navigation another site began — a terminal in a
/// browser tab, the page gclone hands to the browser launcher — or without saying how it got
/// there: `SameSite=Strict` would keep the new cookie out of a redirect, so the answer is a
/// page that goes to the session's path by itself.
#[test]
fn a_link_followed_from_another_site_still_signs_in() {
    let (lab, a) = vault_with(small_tree);
    for headers in [
        vec![
            ("Sec-Fetch-Site", "cross-site"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Dest", "document"),
        ],
        // A browser that sends no fetch metadata.
        vec![],
    ] {
        let mut v = Viewer::spawn(&a, &lab);
        let res = v.send("GET", &v.link, &headers);
        assert_eq!(res.status, 200, "{}", res.text());
        res.has("content-type", "text/html; charset=utf-8")
            .has("referrer-policy", "no-referrer")
            .has("cache-control", "no-store")
            .has(
                "content-security-policy",
                "default-src 'none'; frame-ancestors 'none'",
            );
        v.take_session(&res);
        let page = res.text();
        let refresh = format!(
            r#"<meta http-equiv="refresh" content="0;url={}">"#,
            v.prefix
        );
        assert!(page.contains(&refresh), "{page}");
        assert!(
            !page.contains(v.key()) && !page.contains("<script"),
            "{page}"
        );
        assert!(!page.contains(v.cookie.split_once('=').expect("pair").1));
        assert_eq!(v.get("/api/info").status, 200);
        assert_eq!(v.get("/").status, 200);
        // Once.
        assert_eq!(v.send("GET", &v.link, &headers).status, 403);
    }
    // The browser says that the navigation is this origin's own: a redirect.
    let mut v = Viewer::spawn(&a, &lab);
    let res = v.send("GET", &v.link, &[("Sec-Fetch-Site", "same-origin")]);
    assert_eq!(res.status, 303);
    v.take_session(&res);
    res.has("location", &v.prefix);
}

#[tokio::test]
async fn the_server_listens_on_loopback_only() {
    let (listeners, port) = gclone::web::bind(0).await.expect("bind");
    assert!(port > 0);
    assert!(!listeners.is_empty() && listeners.len() <= 2);
    for listener in &listeners {
        let addr = listener.local_addr().expect("address");
        assert!(addr.ip().is_loopback(), "{addr}");
        assert_eq!(addr.port(), port);
    }
    // A taken port is an error, not another port.
    let taken = gclone::web::bind(port).await;
    assert!(taken.is_err());
}

// ---------------------------------------------------------------------------------------------
// Listing, search
// ---------------------------------------------------------------------------------------------

#[test]
fn listing_sorting_and_search() {
    let (lab, a) = vault_with(|root| {
        small_tree(root);
        for (name, len, age_days) in [
            ("img10.png", 300, 3),
            ("Img2.png", 100, 1),
            ("img1.png", 200, 2),
            ("zeta.txt", 100, 9),
            ("Alpha.txt", 5000, 5),
        ] {
            let path = root.join("mixed").join(name);
            write(&path, &pattern(len as u8, len));
            let mtime = filetime::FileTime::from_unix_time(1_700_000_000 - age_days * 86_400, 0);
            filetime::set_file_mtime(&path, mtime).expect("mtime");
        }
        write(&root.join("mixed/Zoo/inside.txt"), b"x");
        write(&root.join("mixed/apes/inside.txt"), b"x");
        write(&root.join("Ünï/Größe 🎉.txt"), "größe\n".as_bytes());
        write(&root.join("Ünï/he said \"hi\" & left.txt"), b"q");
        for i in 0..25 {
            write(&root.join(format!("many/n{i}.txt")), b"n");
        }
    });
    let v = Viewer::start(&a, &lab);

    // The root: directories only, in natural order (case-insensitive), implied ones included.
    let root = v.json("/api/list");
    assert_eq!(root["path"], "");
    assert_eq!(
        (root["sort"].as_str(), root["order"].as_str()),
        (Some("name"), Some("asc"))
    );
    assert_eq!(root["total"], 5);
    assert_eq!(v.names(""), ["docs", "hollow", "many", "mixed", "Ünï"]);
    let docs = &root["entries"][0];
    assert_eq!(
        docs,
        &serde_json::json!({"name": "docs", "dir": true, "kind": "folder", "size": null, "mtime_ms": null})
    );

    // Directories first in every order; names by natural order; equal keys by name.
    let mixed = |query: &str| v.names(&format!("path=mixed&{query}"));
    assert_eq!(
        mixed(""),
        [
            "apes",
            "Zoo",
            "Alpha.txt",
            "img1.png",
            "Img2.png",
            "img10.png",
            "zeta.txt"
        ]
    );
    assert_eq!(mixed("sort=name&order=asc"), mixed(""));
    assert_eq!(
        mixed("sort=name&order=desc"),
        [
            "Zoo",
            "apes",
            "zeta.txt",
            "img10.png",
            "Img2.png",
            "img1.png",
            "Alpha.txt"
        ]
    );
    assert_eq!(
        mixed("sort=size"),
        [
            "apes",
            "Zoo",
            "Img2.png",
            "zeta.txt",
            "img1.png",
            "img10.png",
            "Alpha.txt"
        ]
    );
    assert_eq!(
        mixed("sort=size&order=desc"),
        [
            "apes",
            "Zoo",
            "Alpha.txt",
            "img10.png",
            "img1.png",
            "Img2.png",
            "zeta.txt"
        ]
    );
    assert_eq!(
        mixed("sort=mtime"),
        [
            "apes",
            "Zoo",
            "zeta.txt",
            "Alpha.txt",
            "img10.png",
            "img1.png",
            "Img2.png"
        ]
    );
    assert_eq!(
        mixed("sort=mtime&order=desc"),
        [
            "apes",
            "Zoo",
            "Img2.png",
            "img1.png",
            "img10.png",
            "Alpha.txt",
            "zeta.txt"
        ]
    );
    let entry = &v.json("/api/list?path=mixed&sort=size&order=desc")["entries"][2];
    assert_eq!(
        entry,
        &serde_json::json!({"name": "Alpha.txt", "dir": false, "kind": "text", "size": 5000,
            "mtime_ms": (1_700_000_000i64 - 5 * 86_400) * 1000})
    );
    assert_eq!(
        v.json("/api/list?path=mixed")["entries"][3]["kind"],
        "image"
    );

    // Pages: `total` is the directory, `entries` the window.
    let page = v.json("/api/list?path=many&offset=20&limit=3");
    assert_eq!(
        (page["total"].as_u64(), page["offset"].as_u64()),
        (Some(25), Some(20))
    );
    assert_eq!(
        v.names("path=many&offset=20&limit=3"),
        ["n20.txt", "n21.txt", "n22.txt"]
    );
    assert_eq!(v.names("path=many&offset=23").len(), 2);
    assert!(v.names("path=many&offset=25").is_empty());
    assert!(v.names("path=many&offset=999999").is_empty());
    assert_eq!(v.names("path=many").len(), 25);

    // An empty directory, a nested one, one that is not there, a file.
    assert_eq!(v.json("/api/list?path=hollow")["total"], 0);
    assert_eq!(v.names("path=docs/sub"), ["deep", "b.txt"]);
    assert_eq!(v.names(&format!("path={}", enc("Ünï"))).len(), 2);
    for (missing, expected) in [
        ("path=nope", 404),
        ("path=docs/a.txt", 404),
        ("path=docs/su", 404),
    ] {
        let res = v.get(&format!("/api/list?{missing}"));
        assert_eq!(res.status, expected, "{missing}");
        assert!(res.text().contains("There is no folder"), "{}", res.text());
    }

    // Malformed input is refused, never repaired.
    for bad in [
        "path=../docs",
        "path=docs/..",
        "path=docs/./sub",
        "path=/docs",
        "path=docs/",
        "path=docs//sub",
        "path=a%00b",
        "path=%ff",
        "path=%zz",
        "path=docs&path=many",
        "sort=date",
        "order=up",
        "offset=-1",
        "offset=1.5",
        "limit=0",
        "limit=5001",
        "limit=abc",
        "limit=+5",
    ] {
        let res = v.get(&format!("/api/list?{bad}"));
        assert_eq!(res.status, 400, "{bad}: {}", res.text());
        res.has("content-type", "text/plain; charset=utf-8");
    }
    let long = format!("path={}", "a".repeat(5000));
    assert_eq!(v.get(&format!("/api/list?{long}")).status, 400);

    // stat
    assert_eq!(
        v.json("/api/stat?path=docs/big.bin")["size"].as_u64(),
        Some(BIG as u64)
    );
    assert_eq!(
        v.json("/api/stat?path=docs/big.bin")["path"],
        "docs/big.bin"
    );
    assert_eq!(v.json("/api/stat?path=docs")["dir"], true);
    assert_eq!(v.json("/api/stat?path=hollow")["kind"], "folder");
    assert_eq!(v.get("/api/stat?path=nope").status, 404);
    assert_eq!(v.get("/api/stat").status, 400);
    assert_eq!(v.get("/api/stat?path=").status, 400);

    // Search: names, not paths; any case; directories; the whole vault.
    let search = |q: &str| -> (Vec<String>, bool) {
        let found = v.json(&format!("/api/search?q={}", enc(q)));
        let hits = found["hits"].as_array().expect("hits");
        (
            hits.iter()
                .map(|h| h["path"].as_str().expect("path").to_string())
                .collect(),
            found["more"].as_bool().expect("more"),
        )
    };
    // In the order of a listing: by name, digits as numbers, whatever the case.
    assert_eq!(
        search("IMG"),
        (
            vec![
                "mixed/img1.png".to_string(),
                "mixed/Img2.png".into(),
                "mixed/img10.png".into()
            ],
            false
        )
    );
    assert_eq!(
        search("inside").0,
        ["mixed/Zoo/inside.txt", "mixed/apes/inside.txt"]
    );
    assert_eq!(search("zoo").0, ["mixed/Zoo"]);
    assert_eq!(search("DEEP").0, ["docs/sub/deep"]);
    assert_eq!(search("hollow").0, ["hollow"]);
    assert_eq!(search("größe").0, ["Ünï/Größe 🎉.txt"]);
    assert_eq!(search("🎉").0, ["Ünï/Größe 🎉.txt"]);
    // Typed decomposed (NFD), stored composed.
    assert_eq!(search("gro\u{308}ße").0, ["Ünï/Größe 🎉.txt"]);
    assert_eq!(search("\"hi\" &").0, ["Ünï/he said \"hi\" & left.txt"]);
    assert_eq!(search("  zeta  ").0, ["mixed/zeta.txt"]);
    for nothing in ["", "   ", "docs/a", "no such thing"] {
        assert_eq!(search(nothing), (Vec::new(), false), "{nothing:?}");
    }
    let hit = &v.json("/api/search?q=alpha.txt")["hits"][0];
    assert_eq!(
        (
            hit["name"].as_str(),
            hit["size"].as_u64(),
            hit["kind"].as_str(),
            hit["dir"].as_bool()
        ),
        (Some("Alpha.txt"), Some(5000), Some("text"), Some(false))
    );
    // The cap: as many as asked for, and the note that there are more.
    let capped = v.json("/api/search?q=n&limit=5");
    assert_eq!(capped["hits"].as_array().expect("hits").len(), 5);
    assert_eq!(capped["more"], true);
    let all = v.json("/api/search?q=.txt&limit=1000");
    assert_eq!(all["more"], false);
    assert_eq!(all["hits"].as_array().expect("hits").len(), 33);
    assert_eq!(v.get("/api/search").status, 400);
    assert_eq!(v.get("/api/search?q=a&limit=1001").status, 400);

    // The summary: what `status` and `about` know, without a call to the store.
    let info = v.json("/api/info");
    assert_eq!(info["vault"], "gclone");
    assert_eq!(info["backend"], "dir");
    assert_eq!(info["device"], "a");
    assert_eq!(info["read_only"], true);
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(info["files"], 39);
    assert_eq!(info["last_change_by"], "a");
    assert!(info["last_change_ms"].as_u64().is_some());
    assert_eq!(info["refresh"]["ok"], true);
    assert!(info["refresh"]["note"].is_null());
}

/// The matches of a search are ordered by the server, by the rule of a folder listing: the
/// same entries come in the same order in both, for every sort key and direction.
#[test]
fn search_orders_its_matches_as_a_folder_does() {
    let (lab, a) = vault_with(|root| {
        for (i, name) in [
            "#qq hash",
            "100% qq",
            "?q=qq query",
            "a&b=qq",
            "\u{c4}rger qq",
            "arger qq",
            "Zebra QQ",
            "qq2",
            "qq10",
            "QQ1",
            "qq 02",
            "_qq",
            "~qq",
            "[qq]",
        ]
        .iter()
        .enumerate()
        {
            let path = root.join("same").join(name);
            // Sizes and times that repeat, so that ties are broken by name.
            write(&path, &pattern(i as u8, 100 * (i % 4)));
            let mtime = filetime::FileTime::from_unix_time(1_700_000_000 + (i as i64 % 3) * 60, 0);
            filetime::set_file_mtime(&path, mtime).expect("mtime");
        }
        write(&root.join("same/qq folder/x"), b"x");
        write(&root.join("same/#qq folder/x"), b"x");
        write(&root.join("same/QQ Folder 2/x"), b"x");
        // A match elsewhere with a name that is also in `same`: told apart by the path.
        write(&root.join("else/qq2"), b"elsewhere");
    });
    let v = Viewer::start(&a, &lab);
    for sort in ["name", "size", "mtime"] {
        for order in ["asc", "desc"] {
            let listed = v.names(&format!("path=same&sort={sort}&order={order}"));
            assert_eq!(listed.len(), 17);
            let found = v.json(&format!("/api/search?q=qq&sort={sort}&order={order}"));
            assert_eq!(
                (found["sort"].as_str(), found["order"].as_str()),
                (Some(sort), Some(order))
            );
            let hits = found["hits"].as_array().expect("hits");
            let inside: Vec<String> = hits
                .iter()
                .filter_map(|h| h["path"].as_str().expect("path").strip_prefix("same/"))
                .map(str::to_string)
                .collect();
            assert_eq!(inside, listed, "sort={sort} order={order}");
            assert_eq!(hits.len(), listed.len() + 1, "and the one elsewhere");
            // Folders first in a search as in a folder.
            let dirs: Vec<bool> = hits.iter().map(|h| h["dir"] == true).collect();
            assert!(dirs.is_sorted_by(|a, b| a >= b), "{dirs:?}");
        }
    }
    // The default is the listing's default; equal names are ordered by their paths.
    let found = v.json("/api/search?q=qq2");
    assert_eq!(
        (found["sort"].as_str(), found["order"].as_str()),
        (Some("name"), Some("asc"))
    );
    let paths: Vec<&str> = found["hits"]
        .as_array()
        .expect("hits")
        .iter()
        .map(|h| h["path"].as_str().expect("path"))
        .collect();
    assert_eq!(paths, ["else/qq2", "same/qq2"]);
    for bad in ["sort=date", "order=up", "sort=name&sort=size"] {
        assert_eq!(
            v.get(&format!("/api/search?q=qq&{bad}")).status,
            400,
            "{bad}"
        );
    }
}

/// The page fetches files by ids, not by paths: no file name is in an address the browser
/// may keep (a tab's address, the download list). An id is the path, sealed by this viewer.
#[test]
fn files_are_addressed_by_opaque_ids() {
    const NAME: &str = "names/Geheime Steuererkl\u{e4}rung 2025.txt";
    let (lab, a) = vault_with(|root| {
        small_tree(root);
        write(&root.join(NAME), b"secret name\n");
    });
    let v = Viewer::start(&a, &lab);
    let stat = v.json(&format!("/api/stat?path={}", enc(NAME)));
    let id = stat["id"].as_str().expect("an id").to_string();
    // Nothing of the name is readable in it, and it is the same every time.
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "{id}"
    );
    for part in ["names", "Geheime", "Steuer", "2025", "txt"] {
        assert!(!id.contains(part), "{id}");
    }
    let plain = gclone::util::unb64url(&id).expect("base64url");
    assert!(!plain.windows(7).any(|w| w == b"Geheime"));
    assert_eq!(v.json(&format!("/api/stat?path={}", enc(NAME)))["id"], id);
    // Directories have none; neither do the rows of listings and searches (the page asks
    // for the one file it opens).
    assert!(v.json("/api/stat?path=docs")["id"].is_null());
    assert!(
        v.json("/api/list?path=docs")["entries"][0]
            .get("id")
            .is_none()
    );
    assert!(v.json("/api/search?q=a.txt")["hits"][0].get("id").is_none());

    let by_id = v.get(&format!("/file?id={id}"));
    assert_eq!(
        (by_id.status, by_id.body.as_slice()),
        (200, &b"secret name\n"[..])
    );
    by_id.has("content-type", "text/plain; charset=utf-8");
    // A file that is shown carries no name: a browser would make it the title of a tab.
    by_id.has("content-disposition", "inline");
    let download = v.with("HEAD", &format!("/file?id={id}&dl=1"), &[]);
    let disposition = download
        .header("content-disposition")
        .expect("a disposition");
    assert!(
        disposition.starts_with("attachment; ") && disposition.contains("Steuererkl%C3%A4rung"),
        "{disposition}"
    );
    let part = v.with("GET", &format!("/file?id={id}"), &[("Range", "bytes=0-5")]);
    assert_eq!((part.status, part.body.as_slice()), (206, &b"secret"[..]));
    let big = v.json("/api/stat?path=docs/big.bin")["id"]
        .as_str()
        .expect("an id")
        .to_string();
    assert!(v.get(&format!("/file?id={big}")).body == pattern(1, BIG));

    // An id that this viewer did not give out — changed, cut, another viewer's, a path.
    let other = Viewer::start(&a, &lab);
    let foreign = other.json(&format!("/api/stat?path={}", enc(NAME)))["id"]
        .as_str()
        .expect("an id")
        .to_string();
    assert_ne!(foreign, id, "every viewer seals with a key of its own");
    let mut changed = id.clone().into_bytes();
    let last = changed.len() - 1;
    changed[last] = if changed[last] == b'A' { b'B' } else { b'A' };
    let changed = String::from_utf8(changed).expect("ASCII");
    for bad in [
        foreign.as_str(),
        changed.as_str(),
        &id[..id.len() - 4],
        "docs/a.txt",
        "",
        "AAAA",
        "%ff",
    ] {
        let res = v.get(&format!("/file?id={bad}"));
        assert_eq!(res.status, 400, "{bad}: {}", res.text());
        assert!(!res.text().contains("secret name"));
    }
    assert_eq!(v.get(&format!("/file?id={id}&path=docs/a.txt")).status, 400);
    assert_eq!(v.get(&format!("/file?id={id}&id={id}")).status, 400);
    // The file is gone from the index: the id names nothing any more.
    a.ok(&["rm", &format!(":{NAME}")]);
    assert_eq!(v.get(&format!("/file?id={id}")).status, 404);
}

#[test]
fn an_empty_vault() {
    let lab = Lab::new();
    let a = lab.connected("a");
    let v = Viewer::start(&a, &lab);
    let root = v.json("/api/list");
    assert_eq!(root["total"], 0);
    assert_eq!(root["entries"], serde_json::json!([]));
    let info = v.json("/api/info");
    assert_eq!(
        (info["files"].as_u64(), info["bytes"].as_u64()),
        (Some(0), Some(0))
    );
    assert_eq!(v.json("/api/search?q=a")["hits"], serde_json::json!([]));
    assert_eq!(v.get("/file?path=a").status, 404);
    assert_eq!(v.get("/").status, 200);
}

// ---------------------------------------------------------------------------------------------
// File content
// ---------------------------------------------------------------------------------------------

#[test]
fn file_content_ranges_and_conditionals() {
    let (lab, a) = vault_with(small_tree);
    let v = Viewer::start(&a, &lab);
    let big = pattern(1, BIG);
    let big_url = file("docs/big.bin");
    let tag = format!("\"{}\"", blake3::hash(&big).to_hex());

    // The whole file: a blob of its own, twenty chunks.
    let res = v.get(&big_url);
    assert_eq!(res.status, 200);
    res.has("content-length", &BIG.to_string())
        .has("accept-ranges", "bytes")
        .has("etag", &tag)
        .has("cache-control", "no-store")
        .has("x-content-type-options", "nosniff");
    assert!(res.header("content-range").is_none());
    assert!(res.body == big, "the bytes of the file");

    // HEAD: the same head, no body, no download.
    let head = v.with("HEAD", &big_url, &[]);
    assert_eq!(head.status, 200);
    head.has("content-length", &BIG.to_string())
        .has("accept-ranges", "bytes")
        .has("etag", &tag);
    assert!(head.body.is_empty());

    // Ranges: first byte, last byte, across a chunk boundary, a suffix, open-ended, clamped.
    let ranged = |range: &str| v.with("GET", &big_url, &[("Range", range)]);
    for (range, start, end) in [
        ("bytes=0-0", 0, 1),
        ("bytes=0-99", 0, 100),
        ("bytes=65530-65545", 65_530, 65_546),
        ("bytes=65536-131071", 65_536, 131_072),
        ("bytes=1299999-1299999", BIG - 1, BIG),
        ("bytes=-100", BIG - 100, BIG),
        ("bytes=-5000000", 0, BIG),
        ("bytes=1299990-", BIG - 10, BIG),
        ("bytes=1299990-9999999", BIG - 10, BIG),
        ("bytes=0-", 0, BIG),
        ("bytes=600000-800000", 600_000, 800_001),
    ] {
        let res = ranged(range);
        assert_eq!(res.status, 206, "{range}");
        res.has("content-range", &format!("bytes {start}-{}/{BIG}", end - 1))
            .has("content-length", &(end - start).to_string())
            .has("accept-ranges", "bytes")
            .has("etag", &tag);
        assert!(res.body == big[start..end], "{range}");
    }
    // Past the end: 416 with the size.
    for range in [
        "bytes=1300000-",
        "bytes=1300000-1300005",
        "bytes=99999999-",
        "bytes=-0",
    ] {
        let res = ranged(range);
        assert_eq!(res.status, 416, "{range}");
        res.has("content-range", &format!("bytes */{BIG}"));
        assert!(res.body.len() < 100, "{range}");
    }
    // Several ranges are answered with the whole file (200), as is anything that is not a
    // byte range this server understands.
    for range in [
        "bytes=0-1,5-6",
        "bytes=5-1",
        "bytes=a-b",
        "lines=0-5",
        "bytes=-",
    ] {
        let res = v.with("HEAD", &big_url, &[("Range", range)]);
        assert_eq!(res.status, 200, "{range}");
        res.has("content-length", &BIG.to_string());
        assert!(res.header("content-range").is_none(), "{range}");
    }
    let multi = ranged("bytes=0-1,5-6");
    assert_eq!(multi.status, 200);
    assert!(multi.body == big);
    // `Range` belongs to GET (RFC 9110 §14.2): HEAD describes the whole file whatever range
    // comes with it — one that fits, one past the end, one with a matching `If-Range`.
    for headers in [
        vec![("Range", "bytes=10-19")],
        vec![("Range", "bytes=0-0")],
        vec![("Range", "bytes=99999999-")],
        vec![("Range", "bytes=-0")],
        vec![("Range", "bytes=10-19"), ("If-Range", tag.as_str())],
    ] {
        let head = v.with("HEAD", &big_url, &headers);
        assert_eq!(head.status, 200, "{headers:?}");
        head.has("content-length", &BIG.to_string())
            .has("accept-ranges", "bytes")
            .has("etag", &tag);
        assert!(head.header("content-range").is_none(), "{headers:?}");
        assert!(head.body.is_empty());
    }
    let empty_head = v.with("HEAD", &file("docs/empty"), &[("Range", "bytes=0-")]);
    assert_eq!(empty_head.status, 200);
    empty_head.has("content-length", "0");

    // The entity tag is the content hash; If-None-Match → 304 without a body.
    for candidate in [
        tag.clone(),
        format!("W/{tag}"),
        format!("\"x\", {tag}"),
        "*".into(),
    ] {
        let res = v.with("GET", &big_url, &[("If-None-Match", &candidate)]);
        assert_eq!(res.status, 304, "{candidate}");
        res.has("etag", &tag);
        assert!(res.body.is_empty());
    }
    let other = v.with("HEAD", &big_url, &[("If-None-Match", "\"0123\"")]);
    assert_eq!(other.status, 200);
    // If-Range: the range holds for this version only.
    let same = v.with(
        "GET",
        &big_url,
        &[("Range", "bytes=0-9"), ("If-Range", &tag)],
    );
    assert_eq!(same.status, 206);
    assert_eq!(same.body, big[..10]);
    let stale = v.with(
        "HEAD",
        &big_url,
        &[("Range", "bytes=0-9"), ("If-Range", "\"0123\"")],
    );
    assert_eq!(stale.status, 200);
    stale.has("content-length", &BIG.to_string());

    // A small file out of a pack, whole and in part.
    let small = v.get(&file("docs/a.txt"));
    assert_eq!(
        (small.status, small.body.as_slice()),
        (200, &b"alpha\n"[..])
    );
    small.has(
        "etag",
        &format!("\"{}\"", blake3::hash(b"alpha\n").to_hex()),
    );
    let part = v.with("GET", &file("docs/a.txt"), &[("Range", "bytes=1-3")]);
    assert_eq!((part.status, part.body.as_slice()), (206, &b"lph"[..]));
    part.has("content-range", "bytes 1-3/6");
    let other_member = v.get(&file("docs/sub/b.txt"));
    assert_eq!(other_member.body, b"bravo\n");
    assert_eq!(v.get(&file("docs/sub/deep/c.bin")).body, pattern(2, 70_000));

    // An empty file: 200 and nothing; no range of it exists.
    let empty = v.get(&file("docs/empty"));
    assert_eq!(empty.status, 200);
    empty
        .has("content-length", "0")
        .has("accept-ranges", "bytes");
    assert!(empty.body.is_empty());
    let none = v.with("GET", &file("docs/empty"), &[("Range", "bytes=0-")]);
    assert_eq!(none.status, 416);
    none.has("content-range", "bytes */0");

    // Not a file.
    for (target, status) in [
        ("/file?path=docs", 404),
        ("/file?path=hollow", 404),
        ("/file?path=docs/nope.txt", 404),
        ("/file", 400),
        ("/file?path=", 400),
        ("/file?path=../a", 400),
        ("/file?path=docs/a.txt&dl=yes", 400),
    ] {
        assert_eq!(v.get(target).status, status, "{target}");
    }

    // What was sent is in the download ledger, as after `cat`.
    let about = a.ok(&["about"]);
    assert!(about.contains("down in the last 24 h"), "{about}");
    assert!(!about.contains(" 0 B down"), "{about}");
}

#[test]
fn vault_files_are_served_as_untrusted_content() {
    const NAMES: [&str; 4] = [
        "he said \"hi\"; it's.txt",
        "größe 🎉.pdf",
        "line\nbreak\ttab.txt",
        "100% [1] #2 ?.txt",
    ];
    let (lab, a) = vault_with(|root| {
        write(
            &root.join("w/page.html"),
            b"<script>alert(document.cookie)</script><h1>hi</h1>",
        );
        write(
            &root.join("w/page.xhtml"),
            b"<html xmlns=\"http://www.w3.org/1999/xhtml\"/>",
        );
        write(&root.join("w/app.js"), b"alert(1)");
        write(
            &root.join("w/drawing.svg"),
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
        );
        write(&root.join("w/doc.pdf"), b"%PDF-1.4\n%%EOF\n");
        write(&root.join("w/notes.txt"), b"plain");
        write(&root.join("w/photo.PNG"), b"\x89PNG\r\n\x1a\n");
        write(&root.join("w/song.mp3"), b"ID3");
        write(&root.join("w/clip.mp4"), b"\0\0\0\x18ftypmp42");
        write(&root.join("w/blob.xyz"), b"<html><script>alert(1)</script>");
        write(&root.join("w/noext"), b"<html>");
        write(&root.join("w/archive.zip"), b"PK");
        write(&root.join("w/fake.png.html"), b"<html>");
        for name in NAMES {
            write(&root.join("names").join(name), b"x");
        }
    });
    let v = Viewer::start(&a, &lab);
    const SANDBOX: &str = "sandbox; default-src 'none'";
    const TEXT: &str = "text/plain; charset=utf-8";

    for (name, content_type, inline, csp_has) in [
        // Active content is never served as what it is.
        ("page.html", TEXT, true, SANDBOX),
        ("page.xhtml", TEXT, true, SANDBOX),
        ("app.js", TEXT, true, SANDBOX),
        ("fake.png.html", TEXT, true, SANDBOX),
        // SVG keeps its type for <img> and is sandboxed as a document.
        ("drawing.svg", "image/svg+xml", true, SANDBOX),
        // PDF: no sandbox (browsers refuse to show a PDF in one), nothing else allowed.
        (
            "doc.pdf",
            "application/pdf",
            true,
            "default-src 'none'; frame-ancestors 'self'",
        ),
        ("notes.txt", TEXT, true, SANDBOX),
        ("photo.PNG", "image/png", true, SANDBOX),
        ("song.mp3", "audio/mpeg", true, SANDBOX),
        ("clip.mp4", "video/mp4", true, SANDBOX),
        // Everything else is a download.
        ("blob.xyz", "application/octet-stream", false, SANDBOX),
        ("noext", "application/octet-stream", false, SANDBOX),
        ("archive.zip", "application/octet-stream", false, SANDBOX),
    ] {
        let target = file(&format!("w/{name}"));
        let res = v.get(&target);
        assert_eq!(res.status, 200, "{name}");
        res.has("content-type", content_type)
            .has("x-content-type-options", "nosniff")
            .has("cache-control", "no-store")
            .has("cross-origin-resource-policy", "same-origin");
        let csp = res.header("content-security-policy").expect("a policy");
        assert!(csp.starts_with(csp_has), "{name}: {csp}");
        assert!(csp.contains("default-src 'none'"), "{name}: {csp}");
        assert!(
            !csp.contains("script-src") && !csp.contains("'self' 'unsafe"),
            "{name}: {csp}"
        );
        assert_eq!(
            csp.starts_with("sandbox;"),
            name != "doc.pdf",
            "{name}: {csp}"
        );
        // Shown: `inline` and nothing else (the name would become a tab's title and an entry
        // of the browser's history). Not shown: an attachment, with the name to save under.
        let disposition = res.header("content-disposition").expect("a disposition");
        if inline {
            assert_eq!(disposition, "inline", "{name}");
        } else {
            assert!(
                disposition.starts_with("attachment; "),
                "{name}: {disposition}"
            );
            assert!(
                disposition.contains(&format!("filename=\"{name}\"")),
                "{disposition}"
            );
        }
        // The download link: always an attachment with the name, same type and policy.
        let download = v.with("HEAD", &format!("{target}&dl=1"), &[]);
        download.has("content-type", content_type);
        let forced = download
            .header("content-disposition")
            .expect("a disposition");
        assert!(forced.starts_with("attachment; "), "{name}: {forced}");
        assert!(
            forced.contains(&format!("filename=\"{name}\"")),
            "{name}: {forced}"
        );
    }

    // Names in Content-Disposition: an ASCII stand-in, and the real name percent-encoded.
    for (name, expected) in [
        (
            NAMES[0],
            "attachment; filename=\"he said _hi__ it's.txt\"; filename*=UTF-8''he%20said%20%22hi%22%3B%20it%27s.txt",
        ),
        (
            NAMES[1],
            "attachment; filename=\"gr__e _.pdf\"; filename*=UTF-8''gr%C3%B6%C3%9Fe%20%F0%9F%8E%89.pdf",
        ),
        (
            NAMES[2],
            "attachment; filename=\"line_break_tab.txt\"; filename*=UTF-8''line%0Abreak%09tab.txt",
        ),
        (
            NAMES[3],
            "attachment; filename=\"100_ [1] #2 ?.txt\"; filename*=UTF-8''100%25%20%5B1%5D%20#2%20%3F.txt",
        ),
    ] {
        let res = v.get(&file(&format!("names/{name}")));
        assert_eq!(res.status, 200, "{name:?}");
        res.has("content-disposition", "inline");
        assert_eq!(res.body, b"x");
        let saved = v.get(&format!("{}&dl=1", file(&format!("names/{name}"))));
        assert_eq!(saved.status, 200, "{name:?}");
        saved.has("content-disposition", expected);
        assert_eq!(saved.body, b"x");
        // The listing gives the name back as it is.
        assert!(
            v.names("path=names").contains(&name.to_string()),
            "{name:?}"
        );
    }
    let stat = v.json(&format!(
        "/api/stat?path={}",
        enc("names/line\nbreak\ttab.txt")
    ));
    assert_eq!(stat["name"], "line\nbreak\ttab.txt");
}

#[test]
fn a_missing_or_damaged_blob_is_a_readable_error() {
    let (lab, a) = vault_with(small_tree);
    let v = Viewer::start(&a, &lab);
    let big = pattern(1, BIG);
    let big_url = file("docs/big.bin");
    let blob = lab.blobs().remove(0);
    let stored = std::fs::read(&blob).expect("blob");
    assert!(stored.len() > BIG);
    let damaged = |at: usize| {
        let mut bytes = stored.clone();
        bytes[at] ^= 0x40;
        std::fs::write(&blob, bytes).expect("write");
    };

    // Damage in the first chunk: nothing was sent yet, so the answer is an error with a text.
    damaged(200);
    let res = v.get(&big_url);
    assert_eq!(res.status, 502, "{}", res.text());
    res.has("content-type", "text/plain; charset=utf-8");
    assert!(
        res.text()
            .starts_with("The file could not be read from the vault: "),
        "{}",
        res.text()
    );
    assert!(res.header("etag").is_none() && res.header("content-disposition").is_none());
    // A range that does not touch the damage is served.
    let tail = v.with("GET", &big_url, &[("Range", "bytes=1000000-1000009")]);
    assert_eq!(
        (tail.status, tail.body.as_slice()),
        (206, &big[1_000_000..1_000_010])
    );

    // Damage further in: what was verified before it arrives, then the connection is cut —
    // the download never looks complete, and no unverified byte is sent.
    damaged(1_000_000);
    let res = v.get(&big_url);
    assert_eq!(res.status, 200);
    res.has("content-length", &BIG.to_string());
    assert!(!res.complete(), "{} bytes arrived", res.body.len());
    assert!(res.body.len() < 1_000_000);
    assert!(res.body == big[..res.body.len()], "only verified plaintext");

    // The blob is gone.
    std::fs::remove_file(&blob).expect("remove");
    let res = v.get(&big_url);
    assert_eq!(res.status, 502);
    let text = res.text();
    assert!(
        text.starts_with("The file could not be read from the vault: blob "),
        "{text}"
    );
    assert!(text.trim_end().ends_with("is missing"), "{text}");
    // HEAD asks the index only.
    assert_eq!(v.with("HEAD", &big_url, &[]).status, 200);
    // The rest of the vault is unaffected, and so is the server.
    assert_eq!(v.get(&file("docs/a.txt")).body, b"alpha\n");

    // Back in place: served again.
    std::fs::write(&blob, &stored).expect("restore");
    assert!(v.get(&big_url).body == big);
    assert!(!v.log().contains("panicked"));
}

/// Sixteen streams at a time, each holding a download; a client that goes away gives its
/// stream back at once.
#[test]
fn stalled_clients_are_bounded_and_a_disconnect_stops_the_stream() {
    // Larger than everything that buffers between the store and a client that does not read.
    const HUGE: usize = 48 * 1024 * 1024;
    let (lab, a) = vault_with(|root| {
        write(&root.join("huge.bin"), &pattern(9, HUGE));
        write(&root.join("small.txt"), b"still here\n");
    });
    let v = Viewer::start(&a, &lab);
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nCookie: {}\r\n\r\n",
        v.at("/file?path=huge.bin"),
        v.host(),
        v.cookie
    );
    // Clients that ask for the file, read its first bytes, and then just sit there.
    let stalled: Vec<TcpStream> = (0..gclone::web::STREAMS_MAX)
        .map(|_| {
            let mut stream = TcpStream::connect(("127.0.0.1", v.port)).expect("connect");
            stream.write_all(request.as_bytes()).expect("send");
            let mut first = [0u8; 4096];
            stream.read_exact(&mut first).expect("the first bytes");
            assert!(first.starts_with(b"HTTP/1.1 200 OK\r\n"));
            stream
        })
        .collect();
    std::thread::sleep(Duration::from_millis(300));

    // One more is told to come back; what needs no stream is served meanwhile.
    assert_eq!(v.json("/api/list")["total"], 2);
    assert_eq!(v.with("HEAD", "/file?path=huge.bin", &[]).status, 200);
    let started = Instant::now();
    let refused = v.get("/file?path=small.txt");
    assert_eq!(refused.status, 503, "{}", refused.text());
    refused.has("retry-after", "2");
    assert!(
        started.elapsed() >= Duration::from_secs(4),
        "it waited for a free stream first"
    );

    // The clients go away mid-file: their downloads end, and the streams are free again.
    drop(stalled);
    let started = Instant::now();
    let served = loop {
        let res = v.get("/file?path=small.txt");
        if res.status == 200 || started.elapsed() > Duration::from_secs(4) {
            break res;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(
        (served.status, served.body.as_slice()),
        (200, &b"still here\n"[..])
    );
    // All sixteen, not just one.
    let again: Vec<Res> = (0..gclone::web::STREAMS_MAX)
        .map(|_| v.with("GET", "/file?path=huge.bin", &[("Range", "bytes=0-9")]))
        .collect();
    assert!(
        again
            .iter()
            .all(|res| res.status == 206 && res.body == pattern(9, 10))
    );
    let whole = v.get("/file?path=huge.bin");
    assert!(whole.complete() && whole.body == pattern(9, HUGE));
}

// ---------------------------------------------------------------------------------------------
// Other gclone processes
// ---------------------------------------------------------------------------------------------

#[test]
fn refresh_shows_another_devices_upload_and_the_viewer_holds_no_lock() {
    let (lab, a) = vault_with(small_tree);
    let b = lab.connected("b");
    let v = Viewer::start(&a, &lab);
    assert_eq!(v.names(""), ["docs", "hollow"]);

    // Another device uploads; this replica does not know yet.
    let src = lab.path("from-b");
    write(&src.join("new.txt"), b"uploaded by b\n");
    b.ok(&["copy", &s(&src), ":from-b"]);
    assert_eq!(v.names(""), ["docs", "hollow"]);
    assert_eq!(v.get("/file?path=from-b/new.txt").status, 404);

    // Refresh: the new segment is applied, and the file is there.
    let refreshed = v.refresh();
    assert_eq!(refreshed["ok"], true, "{refreshed}");
    assert!(
        refreshed["applied"].as_u64().expect("applied") >= 1,
        "{refreshed}"
    );
    assert!(refreshed["note"].is_null(), "{refreshed}");
    assert_eq!(v.names(""), ["docs", "from-b", "hollow"]);
    assert_eq!(v.get("/file?path=from-b/new.txt").body, b"uploaded by b\n");
    assert_eq!(v.json("/api/info")["last_change_by"], "b");
    // Nothing new: nothing applied.
    assert_eq!(v.refresh()["applied"], 0);

    // The viewer holds no lock between requests: a command that needs the exclusive lock on
    // the same device runs at once, and what it changed in the shared replica shows without a
    // refresh.
    let started = Instant::now();
    a.ok(&["mkdir", ":made-while-serving"]);
    a.ok(&["rm", ":docs/a.txt"]);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "no waiting for a lock"
    );
    assert_eq!(
        v.names(""),
        ["docs", "from-b", "hollow", "made-while-serving"]
    );
    assert_eq!(v.get("/file?path=docs/a.txt").status, 404);

    // While another gclone holds the lock, a refresh says so and changes nothing; queries and
    // downloads go on.
    let lock =
        gclone::state::lock_exclusive(&a.vault_state(), Duration::from_secs(1)).expect("lock");
    let busy = v.refresh();
    assert_eq!(busy["ok"], false, "{busy}");
    let note = busy["note"].as_str().expect("a note");
    assert!(note.contains("another gclone is running"), "{note}");
    assert_eq!(v.json("/api/info")["refresh"]["ok"], false);
    assert_eq!(v.names("path=docs/sub"), ["deep", "b.txt"]);
    assert_eq!(v.get("/file?path=docs/sub/b.txt").body, b"bravo\n");
    drop(lock);
    assert_eq!(v.refresh()["ok"], true);

    // The viewer changed nothing in the vault: a second device sees exactly what the commands
    // above made, and every blob checks out.
    let listing = b.ok(&["ls", "-R", ":"]);
    assert!(
        listing.contains("made-while-serving/") && !listing.contains("a.txt"),
        "{listing}"
    );
    assert!(b.ok(&["check"]).contains("all good"));
}

#[test]
fn start_errors_are_those_of_ls_and_ctrl_c_exits_0() {
    let lab = Lab::new();
    let fresh = lab.device("fresh");
    // Not connected: the same text and exit code as `ls`.
    let (code, stdout, stderr) = fresh.run(&["web", "--no-browser"]);
    let ls = fresh.run(&["ls"]);
    assert_eq!((code, stderr.as_str()), (4, ls.2.as_str()));
    assert_eq!(ls.0, 4);
    assert!(stderr.contains("This device is not connected"), "{stderr}");
    assert!(stdout.is_empty(), "no link without a vault: {stdout}");

    let a = lab.connected("a");
    // A port that is taken.
    let taken = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = taken.local_addr().expect("address").port().to_string();
    let (code, stdout, stderr) = a.run(&["web", "--no-browser", "--port", &port]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains(&format!("cannot listen on 127.0.0.1:{port}")),
        "{stderr}"
    );
    assert!(stdout.is_empty(), "{stdout}");
    drop(taken);
    // There is no way to ask for another address.
    for args in [
        &["web", "--bind", "0.0.0.0"][..],
        &["web", "--host", "0.0.0.0"],
        &["web", "--port", "0"],
    ] {
        assert_eq!(a.run(args).0, 2, "{args:?}");
    }
    assert_eq!(a.run(&["web", "--json", "--no-browser"]).0, 2);

    // Ctrl-C ends the viewer: exit 0, the port is closed, and the lock was not held.
    let v = Viewer::start(&a, &lab);
    let port = v.port;
    assert_eq!(v.get("/api/info").status, 200);
    assert_eq!(v.interrupt(), Some(0));
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());

    // Signed out: `ls` and `web` agree again.
    a.ok(&["logout"]);
    let (code, _, stderr) = a.run(&["web", "--no-browser"]);
    assert_eq!((code, stderr), (4, a.run(&["ls"]).2));
}

/// `gclone logout` ends a running viewer: it keeps keys and backend in memory, and would go
/// on serving the files of a device whose access the user has just taken away.
#[test]
fn logout_ends_a_running_viewer() {
    let (lab, a) = vault_with(small_tree);
    let v = Viewer::start(&a, &lab);
    assert_eq!(v.get(&file("docs/a.txt")).body, b"alpha\n");
    // Signing in again to the same vault on this device changes nothing for the viewer.
    let (vault, pass) = (s(&lab.path("vault")), lab.pass());
    a.ok(&["login", "--vault-dir", &vault, "--passphrase-file", &pass]);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(v.get(&file("docs/a.txt")).body, b"alpha\n");

    let out = a.ok(&["logout"]);
    assert!(out.contains("Signed out on this device."), "{out}");
    // From here on no route serves: an answer, if the viewer is still there to give one,
    // says why.
    let port = v.port;
    for route in ["/file?path=docs/a.txt", "/api/list", "/api/info", "/"] {
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nCookie: {}\r\n\r\n",
            v.at(route),
            v.host(),
            v.cookie
        );
        if let Some(res) = try_exchange(port, request.as_bytes(), Duration::from_secs(10)) {
            assert_eq!(res.status, 403, "{route}: {}", res.text());
            let text = res.text();
            assert!(text.contains("The viewer has stopped"), "{route}: {text}");
            assert!(!text.contains("alpha"), "{route}: {text}");
        }
    }
    // ... and the process ends by itself, saying so, with the exit code of "not signed in".
    let log = v.log.clone();
    assert_eq!(v.ended(), Some(4));
    let log = std::fs::read_to_string(log).expect("log");
    assert!(
        log.contains("The viewer has stopped: this device was signed out"),
        "{log}"
    );
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    // Nothing of the login came back.
    assert!(!a.state.join("secrets.json").exists());
    assert!(!a.state.join("token.json").exists());
}

/// `gclone keystore use` moves the secrets between `secrets.json` and `secrets.sealed` under
/// a running viewer (§8.3): the file it watched goes away and the same login is still there.
/// That is no sign-out — `gclone logout` is, from either store.
#[test]
fn the_viewer_survives_the_key_store_moves_and_ends_on_logout() {
    let (lab, mut a) = vault_with(small_tree);
    a.env
        .push(("GCLONE_TEST_KEYSTORE_SEALER".into(), "fake".into()));
    let v = Viewer::start(&a, &lab);
    assert_eq!(v.get(&file("docs/a.txt")).body, b"alpha\n");
    let pass = lab.pass();
    for round in 0..2 {
        a.ok(&[
            "keystore",
            "use",
            "enclave",
            "--yes",
            "--passphrase-file",
            &pass,
        ]);
        assert!(!a.state.join("secrets.json").exists());
        assert!(a.state.join("secrets.sealed").exists());
        // Longer than the guard's interval: it has looked, and found the same login.
        std::thread::sleep(Duration::from_millis(2300));
        assert_eq!(v.get(&file("docs/a.txt")).body, b"alpha\n", "round {round}");
        assert_eq!(v.refresh()["ok"], true);
        a.ok(&["keystore", "use", "file"]);
        assert!(a.state.join("secrets.json").exists());
        std::thread::sleep(Duration::from_millis(2300));
        assert_eq!(v.get(&file("docs/a.txt")).body, b"alpha\n", "round {round}");
    }
    // A sealed store that cannot be read at the moment the guard looks (here: the file is
    // damaged) is not a sign-out; the viewer looks again and goes on once it reads again.
    a.ok(&[
        "keystore",
        "use",
        "enclave",
        "--yes",
        "--passphrase-file",
        &pass,
    ]);
    std::thread::sleep(Duration::from_millis(1500));
    let sealed = a.state.join("secrets.sealed");
    let good = std::fs::read(&sealed).expect("sealed");
    std::fs::write(&sealed, b"{ not what it was").expect("damage");
    std::thread::sleep(Duration::from_millis(2300));
    assert_eq!(v.get(&file("docs/a.txt")).body, b"alpha\n");
    std::fs::write(&sealed, &good).expect("repair");
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(v.get(&file("docs/a.txt")).body, b"alpha\n");

    // Signed out of the sealed store: the viewer ends, as it does for the plain file.
    let out = a.ok(&["logout"]);
    assert!(out.contains("Signed out on this device."), "{out}");
    let log = v.log.clone();
    assert_eq!(v.ended(), Some(4));
    let log = std::fs::read_to_string(log).expect("log");
    assert!(
        log.contains("The viewer has stopped: this device was signed out"),
        "{log}"
    );
    assert!(!a.state.join("secrets.json").exists());
    assert!(!a.state.join("secrets.sealed").exists());
}

/// `logout --forget` under a running viewer: the viewer ends, and what a refresh in its last
/// moment does is nothing — the state directory with its plaintext index is not written back.
#[test]
fn logout_forget_ends_the_viewer_and_nothing_is_written_back() {
    let (lab, a) = vault_with(small_tree);
    let state = a.vault_state();
    let v = Viewer::start(&a, &lab);
    assert_eq!(v.refresh()["ok"], true);
    assert!(state.join("state.db").exists());

    a.ok(&["logout", "--yes", "--forget"]);
    assert!(!state.exists());
    // The refresh action, while the viewer is still there to take it — again and again
    // until it has gone.
    let port = v.port;
    let request = |method: &str, route: &str| {
        format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nCookie: {}\r\nOrigin: http://{}\r\n\r\n",
            v.at(route),
            v.host(),
            v.cookie,
            v.host()
        )
    };
    let patience = Duration::from_secs(10);
    while let Some(res) = try_exchange(port, request("POST", "/api/refresh").as_bytes(), patience) {
        assert_eq!(res.status, 403, "{}", res.text());
        assert!(res.text().contains("The viewer has stopped"));
        for route in ["/api/list", "/file?path=docs/a.txt"] {
            if let Some(res) = try_exchange(port, request("GET", route).as_bytes(), patience) {
                assert_eq!(res.status, 403, "{route}: {}", res.text());
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let log = v.log.clone();
    assert_eq!(v.ended(), Some(4));
    let log = std::fs::read_to_string(log).expect("log");
    assert!(log.contains("The viewer has stopped"), "{log}");
    // Nothing was written back: no state directory, no replica, no index cache, no login.
    assert!(!state.exists(), "the state directory is back");
    // (What stays in the state root holds nothing of the vault or the login: the backup tag
    // and the lock file of the key store, §8.1 and §8.3.)
    let left: Vec<_> = std::fs::read_dir(&a.state)
        .expect("state root")
        .map(|e| e.expect("entry").file_name())
        .filter(|name| name != "CACHEDIR.TAG" && name != "secrets.lock")
        .collect();
    assert!(left.is_empty(), "{left:?}");
    assert!(!a.config.join("config.json").exists());
    assert_eq!(a.run(&["ls"]).0, 4);
}

// ---------------------------------------------------------------------------------------------
// The terminal
// ---------------------------------------------------------------------------------------------

/// A pseudo-terminal: `(master, slave)`.
fn open_pty() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
    use std::os::fd::{FromRawFd as _, OwnedFd};
    let (mut master, mut slave) = (0, 0);
    // SAFETY: openpty only writes the two descriptors, which are owned right below.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: both descriptors were just opened and belong to nobody else.
    unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
}

/// Reads what the terminal shows — the echo of what the test types — and throws it away,
/// until the terminal is gone. Somebody has to: a session leader does not finish exiting
/// while output waits in its terminal (macOS), and the test would wait for it for ever.
fn drain(master: &std::os::fd::OwnedFd) {
    let mut terminal = std::fs::File::from(master.try_clone().expect("dup"));
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while matches!(terminal.read(&mut buf), Ok(n) if n > 0) {}
    });
}

/// In the child, before `exec`: a session of its own whose controlling terminal is stdin.
fn own_terminal() -> std::io::Result<()> {
    // SAFETY: async-signal-safe calls on the child's own process and descriptors.
    unsafe {
        if libc::setsid() < 0 || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Enter in the viewer's terminal: a new link **and** a new session — whoever used the link
/// before, and every cookie handed out so far, is shut out.
#[test]
fn enter_makes_a_new_link_and_ends_the_sessions_before_it() {
    use std::os::unix::process::CommandExt as _;
    const HUGE: usize = 48 * 1024 * 1024;
    let (lab, a) = vault_with(|root| {
        small_tree(root);
        write(&root.join("huge.bin"), &pattern(9, HUGE));
    });
    let (master, slave) = open_pty();
    let (mut command, log) = Viewer::command(&a, &lab, &["-vv", "web", "--no-browser"]);
    command.stdin(Stdio::from(slave));
    // SAFETY: `own_terminal` only makes async-signal-safe calls.
    unsafe { command.pre_exec(own_terminal) };
    let mut v = Viewer::launched(command.spawn().expect("spawn gclone web"), log);
    drain(&master);
    let mut terminal = std::fs::File::from(master);

    v.sign_in();
    let (first_link, first_cookie, first_prefix) =
        (v.link.clone(), v.cookie.clone(), v.prefix.clone());
    let first_at = |route: &str| format!("{}{route}", first_prefix.trim_end_matches('/'));
    assert_eq!(v.get("/api/info").status, 200);
    // The used link says how to shut the other one out: here, with Enter.
    let used = v.send("GET", &first_link, &[]);
    assert!(
        used.text()
            .contains("press Enter in the terminal where `gclone web` runs"),
        "{}",
        used.text()
    );
    // A download of the first session that is under way: a client that does not read on.
    let mut stalled = TcpStream::connect(("127.0.0.1", v.port)).expect("connect");
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nCookie: {}\r\n\r\n",
        v.at("/file?path=huge.bin"),
        v.host(),
        v.cookie
    );
    stalled.write_all(request.as_bytes()).expect("send");
    let mut first = [0u8; 4096];
    stalled.read_exact(&mut first).expect("the first bytes");
    assert!(first.starts_with(b"HTTP/1.1 200 OK\r\n"));

    terminal.write_all(b"\n").expect("Enter");
    let printed = v.next_link();
    assert!(
        printed.contains("Every link and every browser session from before has stopped working"),
        "{printed}"
    );
    assert_ne!(v.link, first_link);

    // The session from before is over, on every route, before the new link is even used.
    for route in ["/api/info", "/file?path=docs/a.txt", "/"] {
        let res = v.send("GET", &first_at(route), &[("Cookie", &first_cookie)]);
        assert_eq!(res.status, 403, "{route}");
        assert!(res.text().contains(USE_THE_LINK), "{}", res.text());
    }
    // ... and so is its download: the connection is cut short of the file.
    stalled
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");
    let mut rest = Vec::new();
    let _ = stalled.read_to_end(&mut rest);
    assert!(
        first.len() + rest.len() < HUGE,
        "the download of the ended session went on to its end"
    );
    assert_eq!(v.send("GET", &first_link, &[]).status, 403);

    v.sign_in();
    assert_ne!(v.prefix, first_prefix);
    assert_ne!(v.cookie, first_cookie);
    assert_eq!(v.get(&file("docs/a.txt")).body, b"alpha\n");
    // Neither the old cookie under the new path nor the new cookie under the old one.
    assert_eq!(
        v.send("GET", &v.at("/api/info"), &[("Cookie", &first_cookie)])
            .status,
        403
    );
    assert_eq!(
        v.send("GET", &first_at("/api/info"), &[("Cookie", &v.cookie)])
            .status,
        403
    );
    // Enter twice: the link in between was never used, and is not valid any more.
    terminal.write_all(b"\n").expect("Enter");
    v.next_link();
    let unused = v.link.clone();
    terminal.write_all(b"\n").expect("Enter");
    v.next_link();
    let replaced = v.send("GET", &unused, &[]);
    assert_eq!(replaced.status, 403);
    assert!(replaced.text().contains("not a valid link"));
    v.sign_in();
    assert_eq!(v.get("/api/info").status, 200);
    assert_eq!(v.interrupt(), Some(0));
}

/// `gclone web --no-browser &`: a background job of its terminal. Its read of the terminal
/// for "press Enter" must not stop it (SIGTTIN) — the link it printed has to answer.
#[test]
fn a_viewer_in_the_background_of_its_terminal_keeps_serving() {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    let (lab, a) = vault_with(small_tree);
    let (master, slave) = open_pty();
    let (mut command, log) = Viewer::command(&a, &lab, &["-vv", "web", "--no-browser"]);
    command.stdin(Stdio::from(slave));
    // The viewer has to be a background process group of a session whose leader is alive
    // and in the foreground (a process group without such a parent is "orphaned" and gets
    // an error instead of the signal). So the spawned process becomes the session leader
    // with the terminal, forks, and stays behind doing nothing; its child, in a group of
    // its own, is the one that goes on to `exec` gclone — as a shell's `&` job would.
    let mut pid_pipe = [0; 2];
    // SAFETY: pipe writes the two descriptors.
    assert_eq!(unsafe { libc::pipe(pid_pipe.as_mut_ptr()) }, 0);
    let (pid_read, pid_write) = (pid_pipe[0], pid_pipe[1]);
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        command.pre_exec(move || {
            own_terminal()?;
            let pid = libc::fork();
            if pid < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if pid > 0 {
                libc::setpgid(pid, pid);
                let bytes = pid.to_ne_bytes();
                libc::write(pid_write, bytes.as_ptr().cast(), bytes.len());
                // Everything but the terminal and stdout/stderr, the pipe on which the test
                // waits for `exec` included.
                for fd in 3..1024 {
                    libc::close(fd);
                }
                loop {
                    libc::pause();
                }
            }
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let child = command.spawn().expect("spawn");
    // SAFETY: the write end belongs to the children now.
    unsafe { libc::close(pid_write) };
    let mut bytes = [0u8; 4];
    // SAFETY: reads four bytes into a buffer of four from a descriptor this test owns.
    let n = unsafe { libc::read(pid_read, bytes.as_mut_ptr().cast(), bytes.len()) };
    assert_eq!(n, 4, "the pid of the viewer");
    // SAFETY: as above.
    unsafe { libc::close(pid_read) };
    let viewer_pid = libc::pid_t::from_ne_bytes(bytes);
    struct Kill(libc::pid_t);
    impl Drop for Kill {
        fn drop(&mut self) {
            // SAFETY: signals the process this test started.
            unsafe { libc::kill(self.0, libc::SIGKILL) };
        }
    }
    let _kill = Kill(viewer_pid);

    let mut v = Viewer::launched(child, log);
    drain(&master);
    // The viewer is not in the foreground of the terminal.
    // SAFETY: reads the terminal's foreground group.
    let foreground = unsafe { libc::tcgetpgrp(master.as_raw_fd()) };
    assert!(foreground > 0, "the terminal has a foreground group");
    assert_ne!(foreground, viewer_pid, "the viewer is a background job");
    // It answers — now, and after it had time to try the terminal more than once.
    for wait in [0, 2500] {
        std::thread::sleep(Duration::from_millis(wait));
        let request = format!(
            "GET /nope HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            v.host()
        );
        let res = try_exchange(v.port, request.as_bytes(), Duration::from_secs(5));
        let res = res.expect("the viewer is stopped: it does not answer");
        assert_eq!(res.status, 403);
        // No Enter to press here: the text names the other way to a new link.
        assert!(
            res.text().contains("stop `gclone web` (Ctrl-C)"),
            "{}",
            res.text()
        );
    }
    v.sign_in();
    assert_eq!(v.get(&file("docs/a.txt")).body, b"alpha\n");
    // A line typed in the terminal goes to the foreground, not to the viewer: no new link,
    // and the session stays.
    std::fs::File::from(master).write_all(b"\n").expect("Enter");
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(v.get("/api/info").status, 200);
}

/// When gclone opens the browser itself, the link's key must not be in an argument list —
/// those are readable by every account of the machine. The launcher gets the path of a
/// private page that leads to the link; the page is gone once the link is used.
#[test]
fn the_browser_is_handed_a_private_page_not_the_link() {
    use std::os::unix::fs::PermissionsExt as _;
    let (lab, a) = vault_with(small_tree);
    let handed = lab.path("handed-to-the-launcher");
    let start = || {
        let _ = std::fs::remove_file(&handed);
        let (mut command, log) = Viewer::command(&a, &lab, &["-vv", "web"]);
        command
            // What the launcher would get is written to this file; nothing is launched.
            .env("GCLONE_TEST_BROWSER", &handed)
            .env("DISPLAY", ":0")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("SSH_CONNECTION")
            .env_remove("SSH_TTY");
        let mut child = command.spawn().expect("spawn gclone web");
        let mut stdout = std::io::BufReader::new(child.stdout.take().expect("stdout"));
        let mut first = String::new();
        stdout.read_line(&mut first).expect("stdout");
        let deadline = Instant::now() + Duration::from_secs(20);
        while !handed.exists() {
            assert!(
                Instant::now() < deadline,
                "nothing was handed to a launcher"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(50));
        let argument = std::fs::read_to_string(&handed).expect("the launcher's argument");
        (child, stdout, first, PathBuf::from(argument), log)
    };

    let (mut child, _stdout, printed, page, log) = start();
    // The terminal shows no link in this mode, and the launcher's argument is a file.
    assert!(printed.contains("opening it in your browser"), "{printed}");
    assert!(!printed.contains("k="), "{printed}");
    let port: u16 = printed
        .split_once("on 127.0.0.1:")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .and_then(|port| port.parse().ok())
        .unwrap_or_else(|| panic!("the port in {printed:?}"));
    assert_eq!(page, a.state.join(format!("web-open-{port}.html")));
    let argument = page.to_string_lossy().into_owned();
    assert!(
        !argument.contains("k=") && !argument.contains("http"),
        "{argument}"
    );
    // As private as the secrets beside it.
    let mode = |path: &Path| std::fs::metadata(path).expect("stat").permissions().mode() & 0o777;
    assert_eq!(mode(&page), 0o600);
    assert_eq!(mode(&a.state), 0o700);
    let html = std::fs::read_to_string(&page).expect("the launch page");
    let link = html
        .split_once("content=\"0;url=")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(link, _)| link.to_string())
        .unwrap_or_else(|| panic!("the link in {html}"));
    let target = link
        .strip_prefix(&format!("http://127.0.0.1:{port}"))
        .unwrap_or_else(|| panic!("{link}"));
    let key = target.strip_prefix("/?k=").expect("/?k=KEY");
    assert_eq!(key.len(), 32);
    assert!(html.contains(r#"<meta name="referrer" content="no-referrer">"#));
    assert!(!html.contains("<script"));
    // The key is in no log either.
    assert!(!std::fs::read_to_string(&log).expect("log").contains(key));

    // The browser arrives from that page: a navigation that a `file:` page began.
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\
         Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\n\r\n"
    );
    let res = exchange(port, request.as_bytes());
    assert_eq!(res.status, 200, "{}", res.text());
    assert!(res.header("set-cookie").is_some());
    // Used: the page that held the link is gone.
    assert!(!page.exists(), "the launch page is still there");
    // SAFETY: signals the child this test spawned and still owns.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) };
    assert_eq!(child.wait().expect("wait").code(), Some(0));

    // A link that nobody used: the page goes when the viewer does.
    let (mut child, _stdout, _, page, _) = start();
    assert!(page.exists());
    // SAFETY: as above.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) };
    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert!(!page.exists(), "the launch page outlived the viewer");
}

// ---------------------------------------------------------------------------------------------
// Drive
// ---------------------------------------------------------------------------------------------

/// Runs a `login` against `FakeDrive` and plays the user who enters the code at "Google".
async fn drive_login(fake: &FakeDrive, d: &Device, args: &[&str]) {
    let mut child = d
        .command(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gclone");
    let stderr = std::io::BufReader::new(child.stderr.take().expect("stderr"));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        for line in stderr.lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let mut shown = String::new();
    while let Some(line) = rx.recv().await {
        if let Some(code) = line.strip_prefix("and enter the code  ") {
            fake.approve(code);
        }
        shown.push_str(&line);
        shown.push('\n');
    }
    let status = tokio::task::spawn_blocking(move || child.wait().expect("wait"))
        .await
        .expect("join");
    assert!(status.success(), "{args:?}:\n{shown}");
}

/// The viewer over Drive: an access token that stops working while the server runs — tokens
/// live an hour, the server may run for days — is replaced on demand, for downloads and for
/// the refresh; a login that ended is reported in the page and does not end the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drive_mode_tokens_are_renewed_while_the_viewer_runs() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let pass = lab.pass();
    let mut a = lab.device("a");
    a.env = vec![
        ("GCLONE_TEST_DRIVE_API".into(), fake.base().to_string()),
        (
            "GCLONE_TEST_DRIVE_UPLOAD".into(),
            format!("{}/upload", fake.base()),
        ),
    ];
    let auth_url = format!("{}/auth", fake.base());
    drive_login(
        &fake,
        &a,
        &[
            "login",
            &auth_url,
            "--no-browser",
            "--passphrase-file",
            &pass,
            "--device-name",
            "mbp",
        ],
    )
    .await;
    let src = lab.path("src");
    small_tree(&src);
    let big = pattern(1, BIG);

    tokio::task::block_in_place(|| {
        a.ok(&["copy", &s(&src), ":"]);
        let v = Viewer::start(&a, &lab);
        assert_eq!(v.json("/api/info")["backend"], "drive");
        assert_eq!(v.names(""), ["docs", "hollow"]);
        let renewals = || fake.hits(Route::AuthRefresh);
        let before = renewals();
        assert!(v.get(&file("docs/big.bin")).body == big);
        assert_eq!(v.get(&file("docs/a.txt")).body, b"alpha\n");
        assert_eq!(renewals(), before, "a token that works is not renewed");

        // The token is refused in the middle of the server's life: one renewal, and the
        // download goes on.
        fake.unauthorized_once(Route::Media);
        let res = v.with(
            "GET",
            &file("docs/big.bin"),
            &[("Range", "bytes=65530-65545")],
        );
        assert_eq!(
            (res.status, res.body.as_slice()),
            (206, &big[65_530..65_546])
        );
        assert_eq!(renewals(), before + 1);
        // The same for the refresh action.
        fake.unauthorized_once(Route::List);
        let refreshed = v.refresh();
        assert_eq!(refreshed["ok"], true, "{refreshed}");
        assert_eq!(renewals(), before + 2);

        // Google ends the login: the refresh says what the command line would say, the
        // replica is still browsable, and the server is still there.
        fake.revoke_refresh_token();
        fake.unauthorized_once(Route::List);
        let ended = v.refresh();
        assert_eq!(ended["ok"], false, "{ended}");
        let note = ended["note"].as_str().expect("a note");
        assert!(note.contains("Run `gclone login`"), "{note}");
        assert_eq!(v.names("path=docs/sub"), ["deep", "b.txt"]);
        assert_eq!(v.json("/api/info")["refresh"]["ok"], false);
        // Nothing of the tokens is in the viewer's log.
        let secrets = std::fs::read_to_string(a.state.join("secrets.json")).expect("secrets");
        let secrets: serde_json::Value = serde_json::from_str(&secrets).expect("json");
        let token = secrets["refresh_token"].as_str().expect("refresh token");
        assert!(!v.log().contains(token));
    });
}

// ---------------------------------------------------------------------------------------------
// The time machine (§7.4): versions, deleted files, the vault at an earlier moment
// ---------------------------------------------------------------------------------------------

const DAY_MS: u64 = 86_400_000;
const WINDOW_MS: u64 = 25 * DAY_MS;
const ODD: &str = "docs/odd name's #1 %.txt";
const FIRST: &[u8] = b"first\n";
const SECOND: &[u8] = b"second version\n";
const THIRD: &[u8] = b"the third and current\n";

/// Longer than the resolution of every clock involved: two runs of gclone on either side of
/// it are at different times, whatever the vault directory's file system records.
fn pause() {
    std::thread::sleep(Duration::from_millis(1_100));
}

struct WithHistory {
    lab: Lab,
    a: Device,
    /// The blob that holds the second version of `docs/notes.md`, and nothing else.
    second_blob: PathBuf,
}

/// A vault whose index holds history, made by runs of gclone more than a second apart: three
/// versions of `docs/notes.md` (and two of a file with an odd name), a deleted file, a deleted
/// folder, a moved file, and a file that came last.
fn vault_with_history() -> WithHistory {
    let (lab, a) = vault_with(|root| {
        small_tree(root);
        write(&root.join("docs/notes.md"), FIRST);
        write(&root.join(ODD), b"odd one\n");
        write(&root.join("old/x.txt"), b"x\n");
        write(&root.join("old/deep/y.txt"), b"y\n");
        write(&root.join("moved.txt"), b"moving\n");
    });
    let src = lab.path("src");
    let before = lab.blobs();
    pause();
    write(&src.join("docs/notes.md"), SECOND);
    a.ok(&["copy", &s(&src), ":"]);
    let mut new: Vec<PathBuf> = lab
        .blobs()
        .into_iter()
        .filter(|blob| !before.contains(blob))
        .collect();
    assert_eq!(new.len(), 1, "one upload, one blob");
    pause();
    write(&src.join("docs/notes.md"), THIRD);
    write(&src.join(ODD), b"odd two\n");
    a.ok(&["copy", &s(&src), ":"]);
    pause();
    a.ok(&["rm", ":docs/sub/b.txt"]);
    a.ok(&["rm", "-r", ":old"]);
    a.ok(&["mv", ":moved.txt", ":docs/moved-here.txt"]);
    pause();
    for gone in ["docs/sub/b.txt", "moved.txt"] {
        std::fs::remove_file(src.join(gone)).expect("remove");
    }
    std::fs::remove_dir_all(src.join("old")).expect("remove");
    write(&src.join("late.txt"), b"late\n");
    a.ok(&["copy", &s(&src), ":"]);
    WithHistory {
        lab,
        a,
        second_blob: new.remove(0),
    }
}

fn u(value: &serde_json::Value) -> u64 {
    value
        .as_u64()
        .unwrap_or_else(|| panic!("a number: {value}"))
}

/// `name → entry` of a listing or of search hits.
fn by_name(entries: &serde_json::Value) -> std::collections::BTreeMap<String, serde_json::Value> {
    entries
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| (e["name"].as_str().expect("name").to_owned(), e.clone()))
        .collect()
}

/// Every table of the device's replica but the download ledger, as text.
fn replica_dump(d: &Device) -> String {
    use rusqlite::types::ValueRef;
    let db = rusqlite::Connection::open_with_flags(
        d.vault_state().join("state.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("state.db");
    let mut out = String::new();
    let mut tables = db
        .prepare("SELECT name, sql FROM sqlite_master ORDER BY name")
        .expect("prepare");
    let listed: Vec<(String, Option<String>)> = tables
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();
    for (name, sql) in listed {
        out.push_str(&format!("-- {name}: {sql:?}\n"));
        if name == "ledger" || sql.is_none_or(|sql| !sql.starts_with("CREATE TABLE")) {
            continue;
        }
        let mut rows = db
            .prepare(&format!("SELECT * FROM {name}"))
            .expect("prepare");
        let columns = rows.column_count();
        let mut found = rows.query([]).expect("query");
        let mut lines = Vec::new();
        while let Some(row) = found.next().expect("row") {
            let mut line = String::new();
            for i in 0..columns {
                match row.get_ref(i).expect("value") {
                    ValueRef::Null => line.push_str("NULL|"),
                    ValueRef::Integer(n) => line.push_str(&format!("{n}|")),
                    ValueRef::Real(x) => line.push_str(&format!("{x}|")),
                    ValueRef::Text(t) => {
                        line.push_str(&format!("{:?}|", String::from_utf8_lossy(t)));
                    }
                    ValueRef::Blob(b) => line.push_str(&format!("x{}|", gclone::util::hex(b))),
                }
            }
            lines.push(line);
        }
        lines.sort();
        out.push_str(&lines.join("\n"));
        out.push('\n');
    }
    out
}

/// Every file below the vault directory, with its size.
fn store_files(lab: &Lab) -> Vec<(PathBuf, u64)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, u64)>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            let meta = std::fs::symlink_metadata(&path).expect("stat");
            if meta.is_dir() {
                walk(&path, out);
            } else {
                out.push((path, meta.len()));
            }
        }
    }
    let mut out = Vec::new();
    walk(&lab.path("vault"), &mut out);
    out.sort();
    out
}

#[test]
fn the_versions_of_a_file_are_listed_and_served() {
    let WithHistory {
        lab,
        a,
        second_blob,
    } = vault_with_history();
    let v = Viewer::start(&a, &lab);
    let before = replica_dump(&a);
    let listed = v.json("/api/versions?path=docs/notes.md");
    assert_eq!(listed["path"], "docs/notes.md");
    assert_eq!(
        (&listed["deleted"], &listed["more"]),
        (&false.into(), &false.into())
    );
    assert_eq!(u(&listed["now_ms"]) - u(&listed["from_ms"]), WINDOW_MS);
    let rows = listed["versions"].as_array().expect("versions").clone();
    let sizes: Vec<u64> = rows.iter().map(|r| u(&r["size"])).collect();
    assert_eq!(
        sizes,
        [THIRD.len() as u64, SECOND.len() as u64, FIRST.len() as u64]
    );
    let (third, second, first) = (&rows[0], &rows[1], &rows[2]);
    assert_eq!(third["current"], true);
    for key in ["until_ms", "by", "why", "restore"] {
        assert!(third.get(key).is_none(), "{key}: {third}");
    }
    for old in [second, first] {
        assert!(old.get("current").is_none());
        assert_eq!(
            (&old["why"], &old["by"]),
            (&"overwritten".into(), &"a".into())
        );
        assert_eq!(old["written_by"], "a");
        let command = format!(
            "gclone restore :docs/notes.md --version @{}",
            old["v"].as_str().expect("v")
        );
        assert_eq!(old["restore"], command);
    }
    // A version that took another one's place came exactly when that one went; the first
    // upload replaced nothing — its time is an estimate, and not after the truth.
    assert!(u(&first["until_ms"]) + 1_000 < u(&second["until_ms"]));
    assert_eq!(third["written_ms"], second["until_ms"]);
    assert_eq!(second["written_ms"], first["until_ms"]);
    assert!(third.get("written_approx").is_none() && second.get("written_approx").is_none());
    assert_eq!(first["written_approx"], true);
    assert!(u(&first["written_ms"]) + 1_000 < u(&first["until_ms"]));
    assert!(u(&first["written_ms"]) > u(&listed["from_ms"]));

    // Every version is a file like any other: `stat` by its id, then the bytes by the opaque
    // id that gives.
    let hash = |bytes: &[u8]| format!("\"{}\"", blake3::hash(bytes).to_hex());
    let mut ids = Vec::new();
    for (row, bytes) in rows.iter().zip([THIRD, SECOND, FIRST]) {
        let version = row["v"].as_str().expect("v");
        assert_eq!(version.len(), 12, "{version}");
        let stat = v.json(&format!("/api/stat?path=docs/notes.md&v={version}"));
        assert_eq!(stat["v"], version);
        assert_eq!(
            (u(&stat["size"]), &stat["kind"]),
            (bytes.len() as u64, &"text".into())
        );
        match row.get("current") {
            Some(_) => assert!(stat.get("since").is_none(), "{stat}"),
            None => assert_eq!(stat["since"], "changed"),
        }
        let id = stat["id"].as_str().expect("an id").to_owned();
        let res = v.get(&format!("/file?id={id}"));
        assert_eq!((res.status, res.body.as_slice()), (200, bytes));
        res.has("etag", &hash(bytes));
        ids.push(id);
    }
    // The ids are opaque, each its own, and none is the id of the file as it is now — even
    // the one that names the version that is current.
    let current = v.json("/api/stat?path=docs/notes.md");
    assert!(current.get("v").is_none() && current.get("since").is_none());
    let current_id = current["id"].as_str().expect("an id").to_owned();
    let mut distinct: Vec<&String> = ids.iter().chain([&current_id]).collect();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), 4);
    for id in &ids {
        assert!(id.len() > 60 && !id.contains("notes"), "{id}");
    }
    // A version id is not a file id, and the other way round.
    let version = second["v"].as_str().expect("v");
    assert_eq!(v.get(&format!("/file?id={version}")).status, 400);
    assert_eq!(
        v.get(&format!("/api/stat?path=docs/notes.md&v={current_id}"))
            .status,
        400
    );

    // An earlier version is served exactly as a current file is: ranges, conditionals, and
    // the headers of untrusted content, from the name alone.
    let old = format!("/file?id={}", ids[1]);
    let now = format!("/file?id={current_id}");
    let (was, is) = (v.get(&old), v.get(&now));
    for name in [
        "content-type",
        "content-security-policy",
        "content-disposition",
        "accept-ranges",
        "cache-control",
        "x-content-type-options",
        "cross-origin-resource-policy",
        "referrer-policy",
    ] {
        assert_eq!(was.header(name), is.header(name), "{name}");
        assert!(was.header(name).is_some(), "{name}");
    }
    was.has("content-type", "text/plain; charset=utf-8");
    let tag = hash(SECOND);
    let part = v.with("GET", &old, &[("Range", "bytes=7-13")]);
    assert_eq!((part.status, part.body.as_slice()), (206, &b"version"[..]));
    part.has("content-range", "bytes 7-13/15").has("etag", &tag);
    assert_eq!(v.with("GET", &old, &[("If-None-Match", &tag)]).status, 304);
    let other = v.with(
        "GET",
        &old,
        &[("Range", "bytes=0-0"), ("If-Range", &hash(THIRD))],
    );
    assert_eq!((other.status, other.body.as_slice()), (200, SECOND));
    assert_eq!(v.with("GET", &old, &[("Range", "bytes=99-")]).status, 416);
    let head = v.with("HEAD", &format!("{old}&dl=1"), &[]);
    head.has("content-length", "15");
    let disposition = head.header("content-disposition").expect("a disposition");
    assert!(
        disposition.starts_with("attachment; ") && disposition.contains("notes.md"),
        "{disposition}"
    );

    // What is asked for wrongly, and what is not there.
    for (bad, status) in [
        ("/api/versions", 400),
        ("/api/versions?path=", 400),
        ("/api/versions?path=/abs", 400),
        ("/api/versions?path=docs/notes.md&at=yesterday", 400),
        ("/api/stat?path=docs/notes.md&v=xyz", 400),
        ("/api/stat?path=docs/notes.md&v=0123456789AB", 400),
        ("/api/stat?path=docs/notes.md&v=0123456789abc", 400),
        ("/api/stat?path=docs/notes.md&v=", 400),
        ("/api/stat?path=docs/notes.md&v=0123456789ab", 404),
        ("/api/stat?path=docs/a.txt&v=0123456789ab", 404),
    ] {
        let res = v.get(bad);
        assert_eq!(res.status, status, "{bad}: {}", res.text());
    }
    let both = format!("/api/stat?path=docs/notes.md&v={version}&at=1");
    let res = v.get(&both);
    assert_eq!((res.status, res.text().trim()), (400, "at or v, not both"));
    assert_eq!(
        v.get("/api/stat?path=docs/notes.md&v=0123456789ab")
            .text()
            .trim(),
        "This version is no longer kept."
    );
    // An id names its path: the same id under another path is nothing.
    assert_eq!(
        v.get(&format!("/api/stat?path=docs/a.txt&v={version}"))
            .status,
        404
    );
    // A file without history, a folder, a path nobody wrote: the current version, or none.
    let plain = v.json("/api/versions?path=docs/a.txt");
    assert_eq!(plain["versions"].as_array().expect("versions").len(), 1);
    for nothing in ["docs", "no/such/file"] {
        let empty = v.json(&format!("/api/versions?path={nothing}"));
        assert_eq!(empty["deleted"], true, "{nothing}");
        assert!(empty["versions"].as_array().expect("versions").is_empty());
    }
    // The odd name: its command is quoted for a shell.
    let odd = v.json(&format!("/api/versions?path={}", enc(ODD)));
    assert_eq!(
        odd["versions"][1]["restore"],
        format!(
            "gclone restore ':docs/odd name'\\''s #1 %.txt' --version @{}",
            odd["versions"][1]["v"].as_str().expect("v")
        )
    );

    // The viewer wrote nothing: the replica is what it was, table by table.
    assert_eq!(replica_dump(&a), before);

    // Another gclone changes the file while the viewer runs: the list follows without a
    // refresh, and every id handed out before still names its bytes — the id that named the
    // current version now names an earlier one.
    pause();
    let src = lab.path("src");
    write(&src.join("docs/notes.md"), b"a fourth\n");
    a.ok(&["copy", &s(&src), ":"]);
    let listed = v.json("/api/versions?path=docs/notes.md");
    let rows = listed["versions"].as_array().expect("versions");
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[1]["v"], third["v"]);
    assert_eq!(rows[1]["written_ms"], second["until_ms"]);
    for (id, bytes) in ids.iter().zip([THIRD, SECOND, FIRST]) {
        assert_eq!(v.get(&format!("/file?id={id}")).body, bytes);
    }
    assert_eq!(v.get(&now).body, b"a fourth\n");
    // The file is removed: its current id names nothing, its versions are all still there.
    a.ok(&["rm", ":docs/notes.md"]);
    assert_eq!(v.get(&now).status, 404);
    let listed = v.json("/api/versions?path=docs/notes.md");
    assert_eq!(listed["deleted"], true);
    let rows = listed["versions"].as_array().expect("versions");
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0]["why"], "deleted");
    assert!(rows.iter().all(|r| r.get("current").is_none()));
    assert_eq!(v.get(&format!("/file?id={}", ids[0])).body, THIRD);

    // A blob that sits in the store's trash: the version is served or refused in words, and
    // the viewer does not take it out of the trash — the store is what it was.
    {
        use gclone::backend::{Backend as _, DirBackend};
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let name = second_blob
            .file_name()
            .and_then(|n| n.to_str())
            .expect("name");
        runtime.block_on(async {
            let backend = DirBackend::open(&lab.path("vault")).expect("vault");
            let found = backend.find_by_name(name).await.expect("find");
            assert_eq!(found.len(), 1);
            backend.trash(&found[0].handle).await.expect("trash");
        });
        assert!(!second_blob.exists());
        let trashed = store_files(&lab);
        let res = v.get(&old);
        match res.status {
            200 => assert_eq!(res.body, SECOND),
            502 => assert!(
                res.text()
                    .starts_with("The file could not be read from the vault: "),
                "{}",
                res.text()
            ),
            other => panic!("{other}: {}", res.text()),
        }
        assert_eq!(
            store_files(&lab),
            trashed,
            "nothing was taken out of the trash"
        );
        // Purged: the sentence the command line would print. HEAD asks the index only.
        let in_trash = trashed
            .iter()
            .find(|(path, _)| path.file_name() == second_blob.file_name())
            .expect("the trashed blob");
        std::fs::remove_file(&in_trash.0).expect("purge");
        let res = v.get(&old);
        assert_eq!(res.status, 502, "{}", res.text());
        let text = res.text();
        assert!(
            text.starts_with("The file could not be read from the vault: blob ")
                && text.trim_end().ends_with("is missing"),
            "{text}"
        );
        assert_eq!(v.with("HEAD", &old, &[]).status, 200);
    }

    // The window: a version removed more than 25 days ago is neither listed nor served,
    // whoever still holds its id. (Another process writes the replica: here, the test.)
    {
        let db = rusqlite::Connection::open(a.vault_state().join("state.db")).expect("state.db");
        let moved = db
            .execute(
                "UPDATE removed SET removed_ms = removed_ms - ?1 \
                 WHERE path = 'docs/notes.md' AND size IN (?2, ?3)",
                rusqlite::params![
                    (WINDOW_MS + 60_000) as i64,
                    FIRST.len() as i64,
                    THIRD.len() as i64
                ],
            )
            .expect("update");
        assert_eq!(moved, 2);
    }
    let listed = v.json("/api/versions?path=docs/notes.md");
    let sizes: Vec<u64> = listed["versions"]
        .as_array()
        .expect("versions")
        .iter()
        .map(|r| u(&r["size"]))
        .collect();
    assert_eq!(sizes, [9, SECOND.len() as u64]);
    for gone in [&ids[0], &ids[2]] {
        let res = v.get(&format!("/file?id={gone}"));
        assert_eq!(res.status, 404, "{}", res.text());
        assert_eq!(res.text().trim(), "This version is no longer kept.");
    }
    let stat = v.get(&format!(
        "/api/stat?path=docs/notes.md&v={}",
        first["v"].as_str().expect("v")
    ));
    assert_eq!(stat.status, 404);
    assert!(!v.log().contains("panicked"));
}

/// What the index has no time for (§7.4). A folder made with `mkdir` brings no upload: it is
/// shown from the last its device did before, and says that it may have come later — until
/// the device's next recorded change. A file put over another one with `copy --force`, from
/// bytes the vault holds already, supersedes nothing and uploads nothing: it is there from
/// when the old version went (not from that earlier moment, in the old content's place),
/// and the old version reads "overwritten".
#[test]
fn entries_without_a_time_are_marked_and_a_forced_copy_does_not_hide_what_was_there() {
    let WithHistory { lab, a, .. } = vault_with_history();
    pause();
    a.ok(&["mkdir", ":plans"]);
    pause();
    // The bytes of `late.txt`, from a directory that never was in sync with the vault.
    let other = lab.path("other");
    write(&other.join("docs/notes.md"), b"late\n");
    let out = a.ok(&["copy", "--force", &s(&other), ":"]);
    assert!(out.contains("reused"), "{out}");
    let v = Viewer::start(&a, &lab);
    let versions = v.json("/api/versions?path=docs/notes.md");
    let rows = versions["versions"].as_array().expect("versions");
    assert_eq!(u(&rows[0]["size"]), 5, "{versions}");
    let replaced = u(&rows[1]["until_ms"]);
    assert_eq!(
        (&rows[1]["why"], u(&rows[1]["size"])),
        (&"overwritten".into(), THIRD.len() as u64),
        "{versions}"
    );
    assert_eq!(u(&rows[0]["written_ms"]), replaced, "{versions}");
    // Until then the old content, with nothing to doubt; from then on the new one.
    let before = v.json(&format!("/api/stat?path=docs/notes.md&at={}", replaced - 1));
    assert_eq!(u(&before["size"]), THIRD.len() as u64, "{before}");
    assert!(before.get("approx").is_none(), "{before}");
    let old = v.get(&format!(
        "/file?id={}",
        before["id"].as_str().expect("an id")
    ));
    assert_eq!((old.status, old.body.as_slice()), (200, THIRD));
    let after = v.json(&format!("/api/stat?path=docs/notes.md&at={replaced}"));
    assert_eq!(u(&after["size"]), 5, "{after}");
    assert!(after.get("approx").is_none(), "{after}");

    // The folder: listed with the mark before the device's next recorded change — here the
    // op that removed the old notes — and without it from then on.
    for (at, approx) in [(replaced - 1, true), (replaced, false)] {
        let root = by_name(&v.json(&format!("/api/list?at={at}"))["entries"]);
        let plans = &root["plans"];
        assert_eq!(plans["dir"], true);
        assert_eq!(plans.get("approx").is_some(), approx, "at {at}: {plans}");
        let stat = v.json(&format!("/api/stat?path=plans&at={at}"));
        assert_eq!(stat.get("approx").is_some(), approx, "at {at}: {stat}");
        let found = v.json(&format!("/api/search?q=plans&at={at}"));
        assert_eq!(
            found["hits"][0].get("approx").is_some(),
            approx,
            "at {at}: {found}"
        );
        assert!(root["docs"].get("approx").is_none());
    }
    // The present has no such mark.
    let now = by_name(&v.json("/api/list")["entries"]);
    assert!(now["plans"].get("approx").is_none());
}

#[test]
fn the_vault_at_an_earlier_moment_and_what_was_deleted() {
    let WithHistory { lab, a, .. } = vault_with_history();
    let v = Viewer::start(&a, &lab);
    let before = replica_dump(&a);
    let store = store_files(&lab);
    let versions = v.json("/api/versions?path=docs/notes.md");
    // When the first version gave way to the second, and the second to the third.
    let second_came = u(&versions["versions"][2]["until_ms"]);
    let third_came = u(&versions["versions"][1]["until_ms"]);

    // The timeline: the moments inside the window, by time; the exact ones are the times the
    // versions list shows, and the uploads that replaced nothing are estimates.
    let timeline = v.json("/api/timeline");
    assert_eq!(u(&timeline["now_ms"]) - u(&timeline["from_ms"]), WINDOW_MS);
    assert_eq!(timeline["devices"], serde_json::json!(["a"]));
    let moments: Vec<(u64, u64, u64, u64)> = timeline["moments"]
        .as_array()
        .expect("moments")
        .iter()
        .map(|m| (u(&m[0]), u(&m[1]), u(&m[2]), u(&m[3])))
        .collect();
    assert!(moments.windows(2).all(|w| w[0].0 <= w[1].0), "{moments:?}");
    assert!(
        moments
            .iter()
            .all(|m| m.2 == 0 && m.0 > u(&timeline["from_ms"]))
    );
    assert!(moments.contains(&(second_came, 1, 0, 0)), "{moments:?}");
    assert!(moments.contains(&(third_came, 2, 0, 0)), "{moments:?}");
    let (first, last) = (moments[0], moments[moments.len() - 1]);
    // The first upload: every file with content. The last: one late file.
    assert_eq!((first.1, first.3), (9, 1), "{moments:?}");
    assert_eq!((last.1, last.3), (1, 1), "{moments:?}");
    assert!(first.0 < second_came && last.0 > third_came);
    // The removals: one file, the folder's two, the move.
    let exact: Vec<u64> = moments.iter().filter(|m| m.3 == 0).map(|m| m.1).collect();
    assert_eq!(exact, [1, 2, 1, 2, 1], "{moments:?}");

    // Just before the second version came: the first is there, and says what became of it.
    let then = second_came - 1;
    let docs = v.json(&format!("/api/list?path=docs&at={then}"));
    assert_eq!(u(&docs["at"]), then);
    assert_eq!(
        (&docs["path"], &docs["sort"], &docs["order"]),
        (&"docs".into(), &"name".into(), &"asc".into())
    );
    let rows = by_name(&docs["entries"]);
    assert_eq!(u(&rows["notes.md"]["size"]), FIRST.len() as u64);
    assert_eq!(rows["notes.md"]["since"], "changed");
    assert_eq!(rows[&ODD["docs/".len()..]]["since"], "changed");
    assert!(rows["a.txt"].get("since").is_none(), "the same today");
    assert!(
        rows["sub"].get("since").is_none(),
        "a folder that is still there"
    );
    assert!(!rows.contains_key("moved-here.txt"));
    // Rows carry neither an id nor a version: `stat` hands those out.
    assert!(
        rows.values()
            .all(|r| r.get("id").is_none() && r.get("v").is_none())
    );
    // At the moment itself the second version is there; later the third, as today.
    let at = |t: u64| by_name(&v.json(&format!("/api/list?path=docs&at={t}"))["entries"]);
    assert_eq!(u(&at(second_came)["notes.md"]["size"]), SECOND.len() as u64);
    assert_eq!(
        u(&at(third_came - 1)["notes.md"]["size"]),
        SECOND.len() as u64
    );
    let third = at(third_came);
    assert_eq!(u(&third["notes.md"]["size"]), THIRD.len() as u64);
    assert!(third["notes.md"].get("since").is_none());
    assert!(third["sub"].get("since").is_none());

    // The root then: the folder that was deleted since and the file that was moved away are
    // there and say so; the file that came late is not.
    let root = by_name(&v.json(&format!("/api/list?at={then}"))["entries"]);
    let names: Vec<&str> = root.keys().map(String::as_str).collect();
    assert_eq!(names, ["docs", "hollow", "moved.txt", "old"]);
    assert_eq!(root["old"]["since"], "deleted");
    assert_eq!(
        (&root["old"]["dir"], &root["old"]["kind"]),
        (&true.into(), &"folder".into())
    );
    assert_eq!(root["moved.txt"]["since"], "deleted");
    assert!(root["docs"].get("since").is_none() && root["hollow"].get("since").is_none());
    let sub = by_name(&v.json(&format!("/api/list?path=docs/sub&at={then}"))["entries"]);
    assert_eq!(sub["b.txt"]["since"], "deleted");
    let old = v.json(&format!(
        "/api/list?path=old&at={then}&sort=size&order=desc"
    ));
    assert_eq!(old["total"], 2);
    assert_eq!(old["entries"][0]["name"], "deep");
    assert_eq!(old["entries"][1]["name"], "x.txt");
    // Pages, as in the present.
    let page = v.json(&format!("/api/list?at={then}&offset=1&limit=2"));
    assert_eq!((&page["total"], &page["offset"]), (&4.into(), &1.into()));
    let names: Vec<&str> = page["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["hollow", "old"], "folders first");

    // `stat` then: the version that was there, by an id of its own — which still gives
    // those bytes.
    let stat = v.json(&format!("/api/stat?path=docs/notes.md&at={then}"));
    assert_eq!(stat["v"], versions["versions"][2]["v"]);
    assert_eq!(
        (&stat["since"], &stat["path"]),
        (&"changed".into(), &"docs/notes.md".into())
    );
    let id = stat["id"].as_str().expect("an id");
    assert_eq!(v.get(&format!("/file?id={id}")).body, FIRST);
    // Also for a file that is the same today: the id pins the version shown.
    let same = v.json(&format!("/api/stat?path=docs/a.txt&at={then}"));
    assert!(same.get("since").is_none());
    let pinned = same["id"].as_str().expect("an id");
    assert_ne!(pinned, v.json("/api/stat?path=docs/a.txt")["id"]);
    assert_eq!(v.get(&format!("/file?id={pinned}")).body, b"alpha\n");
    let gone = v.json(&format!("/api/stat?path=old/deep/y.txt&at={then}"));
    assert_eq!(gone["since"], "deleted");
    assert_eq!(
        v.get(&format!("/file?id={}", gone["id"].as_str().expect("an id")))
            .body,
        b"y\n"
    );
    let folder = v.json(&format!("/api/stat?path=old&at={then}"));
    assert_eq!(
        (&folder["dir"], &folder["since"]),
        (&true.into(), &"deleted".into())
    );
    assert!(folder.get("id").is_none() && folder.get("v").is_none());
    for nothing in ["late.txt", "docs/moved-here.txt", "nope"] {
        let res = v.get(&format!("/api/stat?path={nothing}&at={then}"));
        assert_eq!(res.status, 404, "{nothing}");
        assert_eq!(
            res.text().trim(),
            format!("There was nothing at {nothing:?} in the vault at that time.")
        );
    }

    // A search then finds what was there then, by the rule of the present.
    let found = v.json(&format!("/api/search?q=txt&at={then}"));
    assert_eq!(u(&found["at"]), then);
    let hits: Vec<(&str, Option<&str>)> = found["hits"]
        .as_array()
        .expect("hits")
        .iter()
        .map(|h| (h["path"].as_str().expect("path"), h["since"].as_str()))
        .collect();
    assert_eq!(
        hits,
        [
            ("docs/a.txt", None),
            ("docs/sub/b.txt", Some("deleted")),
            ("moved.txt", Some("deleted")),
            (ODD, Some("changed")),
            ("old/x.txt", Some("deleted")),
            ("old/deep/y.txt", Some("deleted")),
        ]
    );
    let folders = v.json(&format!("/api/search?q=old&at={then}"));
    assert_eq!(folders["hits"][0]["path"], "old");
    assert_eq!(folders["hits"][0]["since"], "deleted");
    assert!(
        v.json("/api/search?q=old")["hits"]
            .as_array()
            .expect("hits")
            .is_empty()
    );

    // A folder that was not there then: no error — the place stays — and the nearest folder
    // that was.
    for (path, t, nearest) in [
        ("old/deep/nothing/at/all", then, "old/deep"),
        ("old/deep", u(&timeline["now_ms"]) + 5_000, ""),
        ("docs/a.txt", then, "docs"),
    ] {
        let absent = v.json(&format!("/api/list?path={path}&at={t}"));
        assert_eq!(absent["absent"], true, "{path}");
        assert_eq!(absent["nearest"], nearest, "{path}");
        assert_eq!(
            (&absent["total"], absent["entries"].as_array().map(Vec::len)),
            (&0.into(), Some(0))
        );
    }
    assert_eq!(
        v.get("/api/list?path=old").status,
        404,
        "without a time: no such folder"
    );

    // `at` is a time in milliseconds, moved into the window and echoed.
    for bad in ["", "abc", "-1", "1.5", "+5", "12345678901234567", "1e5"] {
        for route in [
            "/api/list?",
            "/api/search?q=a&",
            "/api/stat?path=docs&",
            "/api/versions?path=docs&",
        ] {
            let res = v.get(&format!("{route}at={bad}"));
            assert_eq!(res.status, 400, "{route}at={bad}");
            assert_eq!(
                res.text().trim(),
                "at is a time in milliseconds: up to 16 digits"
            );
        }
    }
    let (from, now) = (u(&timeline["from_ms"]), u(&timeline["now_ms"]));
    let early = u(&v.json("/api/list?at=0")["at"]);
    assert!(
        (from..from + 60_000).contains(&early),
        "{early} against {from}"
    );
    let late = v.json("/api/list?at=9999999999999999");
    assert!((now..now + 60_000).contains(&u(&late["at"])));
    // "Now", asked for as a time, is the present: the same entries, without a mark.
    let mut present = v.json("/api/list");
    present["at"] = late["at"].clone();
    assert_eq!(late, present);
    let mut hits = v.json("/api/search?q=a");
    let then_hits = v.json("/api/search?q=a&at=9999999999999999");
    hits["at"] = then_hits["at"].clone();
    assert_eq!(then_hits, hits);

    // The versions list marks what was there at the moment the page shows.
    let marked = v.json(&format!("/api/versions?path=docs/notes.md&at={then}"));
    let shown: Vec<bool> = marked["versions"]
        .as_array()
        .expect("versions")
        .iter()
        .map(|r| r.get("shown").is_some())
        .collect();
    assert_eq!(shown, [false, false, true]);

    // What was deleted from a folder and is kept: a file with its last version …
    let deleted = v.json("/api/deleted?path=docs/sub");
    assert_eq!(
        (&deleted["path"], &deleted["gone"], &deleted["total"]),
        (&"docs/sub".into(), &false.into(), &1.into())
    );
    assert!(deleted.get("restore").is_none() && deleted.get("as_it_was_ms").is_none());
    let row = &deleted["entries"][0];
    assert_eq!(
        (&row["name"], &row["kind"], u(&row["size"])),
        (&"b.txt".into(), &"text".into(), 6)
    );
    assert_eq!(
        (&row["gone"]["by"], &row["gone"]["why"]),
        (&"a".into(), &"deleted".into())
    );
    assert!(u(&row["gone"]["ms"]) > third_came);
    let version = row["v"].as_str().expect("v");
    let stat = v.json(&format!("/api/stat?path=docs/sub/b.txt&v={version}"));
    assert_eq!(stat["since"], "deleted");
    assert_eq!(
        v.get(&format!("/file?id={}", stat["id"].as_str().expect("an id")))
            .body,
        b"bravo\n"
    );
    // … a folder with the number of files kept under it, a file that was moved away …
    let root = v.json("/api/deleted");
    let rows = by_name(&root["entries"]);
    let names: Vec<&str> = root["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["old", "moved.txt"], "folders first");
    assert_eq!(
        (&rows["old"]["dir"], &rows["old"]["files"]),
        (&true.into(), &2.into())
    );
    assert!(rows["old"].get("gone").is_none() && rows["old"].get("files_more").is_none());
    assert_eq!(rows["moved.txt"]["gone"]["why"], "deleted");
    // … in the order and the pages of a listing.
    let page = v.json("/api/deleted?sort=name&order=desc&offset=1&limit=1");
    assert_eq!(
        (&page["total"], &page["entries"][0]["name"]),
        (&2.into(), &"moved.txt".into())
    );
    // A folder that is gone: its content, the command, and the moment to see it at.
    let gone = v.json("/api/deleted?path=old");
    assert_eq!(gone["gone"], true);
    assert_eq!(gone["restore"], "gclone restore -r :old");
    let names: Vec<&str> = gone["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["deep", "x.txt"]);
    let as_it_was = u(&gone["as_it_was_ms"]);
    let was = by_name(&v.json(&format!("/api/list?path=old&at={as_it_was}"))["entries"]);
    assert_eq!(was.len(), 2);
    assert_eq!(
        v.json(&format!("/api/list?path=old&at={}", as_it_was + 1))["absent"],
        true
    );
    // Nothing deleted, no such folder, a file, a wrong question.
    assert_eq!(v.json("/api/deleted?path=docs")["total"], 0);
    for (bad, status) in [
        ("/api/deleted?path=nope", 404),
        ("/api/deleted?path=docs/a.txt", 404),
        ("/api/deleted?path=/abs", 400),
        ("/api/deleted?limit=0", 400),
        ("/api/deleted?sort=date", 400),
        ("/api/deleted?offset=x", 400),
    ] {
        assert_eq!(v.get(bad).status, status, "{bad}");
    }

    // Nothing of all this wrote anything: not to the replica (the download ledger aside),
    // not to the store.
    assert_eq!(replica_dump(&a), before);
    assert_eq!(store_files(&lab), store);
    // The log shows routes, never a path, a time or a version.
    let log = v.log();
    assert!(log.contains("GET /api/versions") && log.contains("GET /api/deleted"));
    assert!(log.contains("GET /api/timeline"));
    for leak in ["notes.md", "at=", "v=", version] {
        assert!(!log.contains(leak), "{leak}");
    }
    assert!(!log.contains("panicked"));
}

//! `gclone serve restic`, the built binary (SPEC §13 "restic"): against `FakeDrive`, spoken to
//! by a test client over its pipes (B1–B9) and by the real restic (E1–E17).
//!
//! The restic tests need restic 0.17 or later — `GCLONE_TEST_RESTIC` names the binary, else
//! `restic` on `PATH`. Without it they are skipped with a note on stderr; with
//! `GCLONE_REQUIRE_RESTIC=1` (CI) a missing restic is a failure.
//!
//! A device is a pair of config and state directories, signed in at the fake auth Worker.
//! Nothing here touches the real Google Drive or the configuration of the user who runs the
//! tests: restic and gclone get a cleared environment with their own `HOME`.

#[path = "support/fake_drive.rs"]
mod fake_drive;
#[path = "support/h2.rs"]
mod h2;
#[path = "support/prng.rs"]
mod prng;

use std::collections::{BTreeMap, HashSet};
use std::io::{BufRead as _, Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use fake_drive::{FakeDrive, Route};
use gclone::backend::{Backend as _, Handle, stream_body};
use h2::{H2, sha};

const BIN: &str = env!("CARGO_BIN_EXE_gclone");
const PASS: &str = "correct horse battery staple";
/// A command that is expected to fail must fail "within seconds": restic retries what it takes
/// for temporary for 15 minutes. The bound is generous; it only tells the two apart.
const PROMPT: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------------------------

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
    took: Duration,
}

impl Out {
    fn of(out: std::process::Output, took: Duration) -> Out {
        Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            took,
        }
    }

    #[track_caller]
    fn ok(self) -> Out {
        assert_eq!(
            self.code, 0,
            "exit code\n--- stdout\n{}\n--- stderr\n{}",
            self.stdout, self.stderr
        );
        self
    }

    /// Failed, and did not take the time of a retry loop to do so.
    #[track_caller]
    fn failed_promptly(self) -> Out {
        assert_ne!(
            self.code, 0,
            "should have failed\n--- stdout\n{}\n--- stderr\n{}",
            self.stdout, self.stderr
        );
        assert!(
            self.took < PROMPT,
            "took {:?}\n--- stderr\n{}",
            self.took,
            self.stderr
        );
        self
    }

    /// Nothing from gclone reached the user: restic shows every stderr line of its backend
    /// program prefixed `rclone: `.
    #[track_caller]
    fn quiet(self) -> Out {
        let from_gclone = |text: &str| text.lines().any(|line| line.starts_with("rclone: "));
        assert!(
            !from_gclone(&self.stderr) && !from_gclone(&self.stdout),
            "gclone wrote to stderr\n--- stdout\n{}\n--- stderr\n{}",
            self.stdout,
            self.stderr
        );
        self
    }

    #[track_caller]
    fn sane(self) -> Out {
        assert!(
            !self.stderr.contains("panicked") && self.code != 101,
            "a panic:\n{}",
            self.stderr
        );
        self
    }
}

#[derive(Clone)]
struct Device {
    config: PathBuf,
    state: PathBuf,
    home: PathBuf,
    env: Vec<(String, String)>,
}

impl Device {
    /// The environment a gclone of this device needs — also when restic starts it.
    fn vars(&self) -> Vec<(String, String)> {
        let dir = |p: &Path| p.to_str().expect("UTF-8 path").to_string();
        let mut vars = vec![
            ("GCLONE_CONFIG_DIR".to_string(), dir(&self.config)),
            ("GCLONE_STATE_DIR".to_string(), dir(&self.state)),
            ("GCLONE_TEST_FAST_KDF".to_string(), "1".to_string()),
            ("GCLONE_TEST_FAST_PACER".to_string(), "1".to_string()),
            // No Secure Enclave trial in a spawned gclone (§8.2); see tests/keystore.rs.
            ("GCLONE_KEYSTORE_TRIAL".to_string(), "0".to_string()),
            ("HOME".to_string(), dir(&self.home)),
            ("TZ".to_string(), "UTC".to_string()),
        ];
        vars.extend(self.env.iter().cloned());
        vars
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env_remove("GCLONE_AUTH_URL")
            .env_remove("GCLONE_LOG")
            .envs(self.vars())
            .stdin(Stdio::null());
        cmd
    }

    #[track_caller]
    fn run(&self, args: &[&str]) -> Out {
        let started = Instant::now();
        let out = self.command(args).output().expect("spawn gclone");
        Out::of(out, started.elapsed()).sane()
    }

    fn secrets_file(&self) -> PathBuf {
        self.state.join("secrets.json")
    }
}

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

    /// A device for `FakeDrive`, not signed in yet.
    fn device(&self, fake: &FakeDrive, name: &str) -> Device {
        let home = self.path("home");
        std::fs::create_dir_all(&home).expect("home");
        Device {
            config: self.path(&format!("{name}-config")),
            state: self.path(&format!("{name}-state")),
            home,
            env: vec![
                ("GCLONE_TEST_DRIVE_API".into(), fake.base().to_string()),
                (
                    "GCLONE_TEST_DRIVE_UPLOAD".into(),
                    format!("{}/upload", fake.base()),
                ),
                (
                    "GCLONE_TEST_REVOKE_URL".into(),
                    format!("{}/revoke", fake.base()),
                ),
            ],
        }
    }

    /// A device that went through `gclone login` (which also creates or attaches the vault).
    async fn signed_in(&self, fake: &FakeDrive, name: &str) -> Device {
        let d = self.device(fake, name);
        let pass = self.path("pass");
        std::fs::write(&pass, format!("{PASS}\n")).expect("passphrase file");
        let auth = format!("{}/auth", fake.base());
        let pass = pass.to_str().unwrap().to_string();
        let args = ["login", &auth, "--no-browser", "--passphrase-file", &pass];
        drive_login(fake, &d, &args).await.ok();
        d
    }

    /// Files of the given sizes under `dir`, from the seeded PRNG.
    fn tree(&self, dir: &str, seed: u64, files: &[(&str, usize)]) -> PathBuf {
        let root = self.path(dir);
        let mut rng = prng::Prng::new(seed);
        for (name, len) in files {
            let file = root.join(name);
            std::fs::create_dir_all(file.parent().unwrap()).expect("dir");
            std::fs::write(&file, rng.bytes(*len)).expect("write");
        }
        root
    }
}

/// Runs a `login` and plays the user: reads the code the binary prints and enters it at the
/// fake "Google".
async fn drive_login(fake: &FakeDrive, d: &Device, args: &[&str]) -> Out {
    let started = Instant::now();
    let mut child = d
        .command(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gclone");
    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    let stdout = std::thread::spawn(move || std::io::read_to_string(stdout).expect("stdout"));
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let stderr = std::thread::spawn(move || {
        let mut all = String::new();
        for line in std::io::BufReader::new(stderr).lines() {
            let line = line.expect("stderr");
            all.push_str(&line);
            all.push('\n');
            let _ = tx.send(line);
        }
        all
    });
    loop {
        match rx.try_recv() {
            Ok(line) => {
                if let Some(code) = line.strip_prefix("and enter the code  ") {
                    fake.approve(code);
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                tokio::time::sleep(Duration::from_millis(20)).await
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
        }
    }
    let status = tokio::task::spawn_blocking(move || child.wait().expect("wait"))
        .await
        .expect("join");
    Out {
        code: status.code().unwrap_or(-1),
        stdout: stdout.join().expect("stdout thread"),
        stderr: stderr.join().expect("stderr thread"),
        took: started.elapsed(),
    }
    .sane()
}

/// Every request the fake has seen, of any kind.
fn requests_seen(fake: &FakeDrive) -> u64 {
    use Route::*;
    let all = [
        AuthStart,
        AuthPoll,
        AuthRefresh,
        Revoke,
        GenerateIds,
        CreateFolder,
        Multipart,
        ResumableInit,
        SessionPut,
        Media,
        Stat,
        List,
        Patch,
        Delete,
        About,
    ];
    all.into_iter().map(|route| fake.hits(route)).sum()
}

fn signal(pid: u32, signal: i32) {
    // SAFETY: sends a signal to a child process of this test.
    let sent = unsafe { libc::kill(pid as i32, signal) };
    assert_eq!(sent, 0, "kill({pid}, {signal})");
}

/// Waits for a child to end; `None` if it is still running after `patience`.
fn wait(child: &mut Child, patience: Duration) -> Option<i32> {
    let deadline = Instant::now() + patience;
    loop {
        match child.try_wait().expect("wait") {
            Some(status) => return Some(status.code().unwrap_or(-1)),
            None if Instant::now() >= deadline => return None,
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

/// A pseudo-terminal: the end a program sees as its terminal, and the end that keeps it open.
fn pty() -> (std::fs::File, OwnedFd) {
    use std::os::fd::FromRawFd as _;
    use std::ptr::null_mut;
    let (mut ours, mut theirs) = (-1, -1);
    // No name wanted, default settings and size (typed: the last two are `*const` on Linux).
    let name = null_mut::<libc::c_char>();
    let (settings, size) = (null_mut::<libc::termios>(), null_mut::<libc::winsize>());
    // SAFETY: openpty stores two new descriptors; each gets its owner right below.
    let made = unsafe { libc::openpty(&mut ours, &mut theirs, name, settings, size) };
    assert_eq!(made, 0, "openpty");
    // SAFETY: both are open descriptors nothing else knows.
    unsafe {
        (
            std::fs::File::from_raw_fd(theirs),
            OwnedFd::from_raw_fd(ours),
        )
    }
}

/// Collects a child's stderr while it runs.
fn collect(stderr: impl std::io::Read + Send + 'static) -> Arc<Mutex<String>> {
    let seen = Arc::new(Mutex::new(String::new()));
    let sink = seen.clone();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr).lines() {
            let Ok(line) = line else { return };
            let mut all = sink.lock().unwrap();
            all.push_str(&line);
            all.push('\n');
        }
    });
    seen
}

// ---------------------------------------------------------------------------------------------
// `gclone serve restic --stdio` as a child, with a test client where restic would be
// ---------------------------------------------------------------------------------------------

struct Stdio2 {
    child: Child,
    h: H2,
    stderr: Arc<Mutex<String>>,
}

impl Stdio2 {
    async fn start(d: &Device, args: &[&str]) -> Stdio2 {
        let mut child = d
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn gclone");
        let to_child: std::fs::File = OwnedFd::from(child.stdin.take().unwrap()).into();
        let from_child: std::fs::File = OwnedFd::from(child.stdout.take().unwrap()).into();
        let stderr = collect(child.stderr.take().unwrap());
        let io = tokio::io::join(
            tokio::fs::File::from_std(from_child),
            tokio::fs::File::from_std(to_child),
        );
        Stdio2 {
            child,
            h: H2::over(io).await,
            stderr,
        }
    }

    fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    fn running(&mut self) -> bool {
        self.child.try_wait().expect("wait").is_none()
    }

    /// Closes the pipe, as restic does by exiting: the exit code and everything on stderr.
    async fn close(self) -> (Option<i32>, String) {
        self.h.close().await;
        let mut child = self.child;
        let code = tokio::task::spawn_blocking(move || wait(&mut child, Duration::from_secs(10)))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let stderr = self.stderr.lock().unwrap().clone();
        (code, stderr)
    }
}

/// B1, B2: stdout carries the protocol and nothing else, no request leaves before restic asks
/// for something real, and the process ends with the pipe.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_is_protocol_only_and_ends_with_the_pipe() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let d = lab.signed_in(&fake, "a").await;
    for verbose in [&[][..], &["-vvv"][..]] {
        let before = requests_seen(&fake);
        let mut args = verbose.to_vec();
        args.extend(["serve", "restic", "--stdio", "main"]);
        let mut s = Stdio2::start(&d, &args).await;
        // restic's readiness probe: any answer will do, and it must not wait for Drive.
        assert_eq!(s.h.get("/file-2026821414756312606").await.status, 404);
        assert_eq!(requests_seen(&fake), before, "nothing was asked of anyone");
        assert!(s.running());

        // Real requests: the stream stays intact whatever is logged.
        assert_eq!(s.h.head("/config").await.status, 404);
        s.h.create().await;
        let pack = prng::Prng::new(1).bytes(6 << 20);
        let path = s.h.save("data", &pack).await;
        assert_eq!(s.h.get(&path).await.bytes(), &pack[..]);
        let lock = s.h.save("locks", b"a lock").await;
        assert_eq!(s.h.delete(&lock).await.status, 200);
        assert_eq!(s.h.delete(&path).await.status, 200);

        let closed = Instant::now();
        let (code, stderr) = s.close().await;
        assert_eq!(code, Some(0), "{stderr}");
        assert!(closed.elapsed() < Duration::from_secs(5));
        match verbose.is_empty() {
            true => assert_eq!(stderr, "", "silent unless something is wrong"),
            false => assert!(stderr.contains("restic: GET /file-"), "{stderr}"),
        }
        // Start over for the second round.
        let other = fake.backend();
        let repo = fake
            .path(&["gclone-restic", "main"])
            .expect("the repository folder");
        other.trash(&Handle(repo)).await.unwrap();
    }
}

/// B3: start-up errors are one line and an exit code; a signed-in device needs nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_start_up() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let fresh = lab.device(&fake, "fresh");
    let out = fresh.run(&["serve", "restic", "--stdio", "main"]);
    assert_eq!(out.code, 4, "{}", out.stderr);
    assert_eq!(out.stdout, "");
    assert_eq!(out.stderr.lines().count(), 1, "{}", out.stderr);
    assert!(
        out.stderr.contains("not signed in to Google"),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("gclone login"), "{}", out.stderr);
    let out = fresh.run(&["serve", "restic", "--port", "18765"]);
    assert_eq!(out.code, 4, "{}", out.stderr);

    // Usage errors: exit 2, before anything else.
    for bad in ["Main", "a/b", "..", ""] {
        let out = fresh.run(&["serve", "restic", "--stdio", bad]);
        assert_eq!(out.code, 2, "{bad:?}: {}", out.stderr);
        assert_eq!(out.stdout, "");
    }
    assert!(
        fresh
            .run(&["serve", "restic", "--stdio", "Main"])
            .stderr
            .contains("a repository name is 1 to 63 characters")
    );
    assert_eq!(
        fresh
            .run(&["--json", "serve", "restic", "--stdio", "x"])
            .code,
        2
    );

    // `--stdio` at a terminal — a person typed it, not restic — is a usage error that names
    // the command to use, whichever of the two ends is the terminal; and it comes before the
    // sign-in is looked at (this device has none: that would be exit 4).
    let (terminal, _other_end) = pty();
    let end = || Stdio::from(terminal.try_clone().expect("clone"));
    for (stdin, stdout) in [
        (end(), end()),
        (end(), Stdio::piped()),
        (Stdio::null(), end()),
    ] {
        let mut cmd = fresh.command(&["serve", "restic", "--stdio", "main"]);
        cmd.stdin(stdin).stdout(stdout).stderr(Stdio::piped());
        let out = Out::of(cmd.output().expect("spawn gclone"), Duration::ZERO).sane();
        assert_eq!(out.code, 2, "{}", out.stderr);
        assert!(
            out.stderr
                .contains("restic -o rclone.program=gclone -r rclone:NAME"),
            "{}",
            out.stderr
        );
    }

    // Signed in, but no vault attached and no key cached: `config.json` gone, `keys: []` —
    // the state after a `gclone login` that was stopped at the passphrase question.
    let d = lab.signed_in(&fake, "a").await;
    std::fs::remove_file(d.config.join("config.json")).expect("config.json");
    let file = d.secrets_file();
    let mut secrets: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    secrets["keys"] = serde_json::json!([]);
    std::fs::write(&file, serde_json::to_vec(&secrets).unwrap()).unwrap();
    let state_files = |d: &Device| -> HashSet<String> {
        let entries = std::fs::read_dir(&d.state).unwrap();
        entries
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    };
    let before = state_files(&d);
    let s = Stdio2::start(&d, &["serve", "restic", "--stdio", "main"]).await;
    assert_eq!(s.h.get("/file-1").await.status, 404);
    s.h.create().await;
    let key = s.h.save("keys", b"a key").await;
    assert_eq!(s.h.get(&key).await.bytes(), b"a key");
    let res = s.h.get("/keys/").await;
    assert!(String::from_utf8_lossy(res.bytes()).contains(&sha(b"a key")));
    let (code, stderr) = s.close().await;
    assert_eq!((code, stderr.as_str()), (Some(0), ""));
    // Nothing but the shared access-token cache was written: no state, no lock, no config.
    let made: Vec<String> = state_files(&d).difference(&before).cloned().collect();
    assert_eq!(made, ["token.json"]);
    assert!(!d.config.join("config.json").exists());
}

/// B4: in stdio mode the signals that stop restic do not stop gclone — restic still needs it
/// to remove its lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_ignores_the_signals_that_stop_restic() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let d = lab.signed_in(&fake, "a").await;
    let mut s = Stdio2::start(&d, &["serve", "restic", "--stdio", "main"]).await;
    s.h.create().await;
    let lock = s.h.save("locks", b"the lock of a backup").await;
    for sig in [
        libc::SIGTERM,
        libc::SIGINT,
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGTERM,
    ] {
        signal(s.child.id(), sig);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(s.running(), "signal {sig} ended gclone");
    }
    assert_eq!(s.h.delete(&lock).await.status, 200);
    let res = s.h.get("/locks/").await;
    assert_eq!((res.status, res.bytes()), (200, &b"[]"[..]));
    let (code, stderr) = s.close().await;
    assert_eq!((code, stderr.as_str()), (Some(0), ""));
}

/// B6: a login that Google no longer accepts is an answer, not an exit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_with_a_dead_login() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let d = lab.signed_in(&fake, "a").await;
    let _ = std::fs::remove_file(d.state.join("token.json"));
    fake.revoke_refresh_token();
    let mut s = Stdio2::start(&d, &["serve", "restic", "--stdio", "main"]).await;
    assert_eq!(s.h.get("/file-1").await.status, 404);
    for _ in 0..3 {
        assert_eq!(s.h.head("/config").await.status, 401);
    }
    assert_eq!(s.h.get("/locks/").await.status, 401);
    assert!(s.running());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let stderr = s.stderr();
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 2, "one line per kind of request:\n{stderr}");
    assert!(lines.iter().all(|l| l.starts_with("gclone: ")), "{stderr}");
    assert!(stderr.contains("gclone login"), "{stderr}");
    let (code, _) = s.close().await;
    assert_eq!(code, Some(0));
}

/// B7 (the R5 path, end to end): a cached file that was deleted for good answers 404 from
/// Drive; gclone lists the folder again and answers what is there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_after_a_permanent_delete() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let d = lab.signed_in(&fake, "a").await;
    let s = Stdio2::start(&d, &["serve", "restic", "--stdio", "main"]).await;
    s.h.create().await;
    let pack = prng::Prng::new(2).bytes(100_000);
    let path = s.h.save("data", &pack).await;
    let shard = fake
        .path(&["gclone-restic", "main", "data", &sha(&pack)[..2]])
        .expect("the shard folder");
    let [stored] = fake.children(&shard).try_into().expect("one pack");

    // Another machine trashes it: still served (a trashed file downloads by ID) until a
    // listing — then gone.
    let other = fake.backend();
    other.trash(&Handle(stored.id.clone())).await.unwrap();
    assert_eq!(s.h.get(&path).await.bytes(), &pack[..]);
    other.untrash(&Handle(stored.id.clone())).await.unwrap();

    // Deleted for good: Drive says 404, gclone lists the shard and answers 404.
    other.delete(&Handle(stored.id.clone())).await.unwrap();
    let lists = |fake: &FakeDrive| {
        let all = fake.requests(Route::List).into_iter();
        all.filter(|r| r.param("q").is_some_and(|q| q.contains(&shard)))
            .count()
    };
    let before = lists(&fake);
    assert_eq!(s.h.get(&path).await.status, 404);
    assert_eq!(lists(&fake), before + 1);
    let media = fake.requests(Route::Media);
    assert!(media.last().unwrap().path.contains(&stored.id));
    // Uploaded again by someone: served from the new object.
    let id = other.new_ids(1).await.unwrap().remove(0);
    let name = sha(&pack);
    other
        .put(
            &id,
            &Handle(shard.clone()),
            &name,
            stream_body(pack.clone().into()),
        )
        .await
        .unwrap();
    assert_eq!(s.h.range(&path, "bytes=10-19").await.bytes(), &pack[10..20]);
    let (code, stderr) = s.close().await;
    assert_eq!((code, stderr.as_str()), (Some(0), ""));
}

/// B8: the pipe closes while an upload is stored and not yet answered — restic was interrupted
/// while it created its lock, and will never know the lock's name. gclone takes the lock back
/// before it exits. An index in the same place stays: another machine may have found it in a
/// listing already and left out, in its own backup, the blobs it describes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_takes_back_an_unanswered_upload_before_it_exits() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let d = lab.signed_in(&fake, "a").await;
    let s = Stdio2::start(&d, &["serve", "restic", "--stdio", "main"]).await;
    s.h.create().await;
    let folder = |ty: &str| {
        let found = fake.path(&["gclone-restic", "main", ty]);
        found.unwrap_or_else(|| panic!("no folder {ty}"))
    };
    let (locks, indexes) = (folder("locks"), folder("index"));
    // No listing shows what is uploaded from now on: the files are stored, and the requests
    // wait for the listings that would confirm them.
    fake.set_list_lag(u32::MAX);
    let lock = b"the lock of a restic that is interrupted";
    let index = b"the index of a restic that is interrupted";
    let mut pending = Vec::new();
    for (ty, bytes) in [("locks", &lock[..]), ("index", &index[..])] {
        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(format!("http://localhost/{ty}/{}", sha(bytes)))
            .body(h2::full(bytes))
            .unwrap();
        pending.push(tokio::spawn(s.h.send.clone().send_request(req)));
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while fake.children(&locks).is_empty() || fake.children(&indexes).is_empty() {
        assert!(Instant::now() < deadline, "the files were not uploaded");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!fake.children(&locks)[0].trashed);

    pending.into_iter().for_each(|request| request.abort());
    let (code, stderr) = s.close().await;
    assert_eq!((code, stderr.as_str()), (Some(0), ""));
    let [left] = fake.children(&locks).try_into().expect("one object");
    assert!(left.trashed, "the lock was left behind");
    let [kept] = fake.children(&indexes).try_into().expect("one object");
    assert!(!kept.trashed, "the index was taken back");
    assert_eq!(fake.object(&kept.id).unwrap(), index);
}

/// B9: Drive answers `404` to the listing of a folder that is there. That is not an empty
/// listing — "no snapshots" would let `prune` remove every pack, "no locks" hide another
/// machine's lock — and not "no such repository": restic gets a `503` and asks again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_with_a_listing_that_drive_does_not_find() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let d = lab.signed_in(&fake, "a").await;
    let s = Stdio2::start(&d, &["serve", "restic", "--stdio", "main"]).await;
    s.h.create().await;
    assert_eq!(s.h.post("/config", b"the config").await.status, 200);
    s.h.save("snapshots", b"a snapshot").await;
    s.h.save("locks", b"a lock").await;
    s.h.save("data", &prng::Prng::new(3).bytes(50_000)).await;
    let not_found = || fake.fail_next(Route::List, 1, 404, "notFound");
    for ty in ["snapshots", "locks", "data", "index", "keys"] {
        let path = format!("/{ty}/");
        let truth = s.h.get(&path).await;
        assert_eq!(truth.status, 200, "{ty}");
        let empty = matches!(ty, "index" | "keys");
        assert_eq!(truth.bytes() == b"[]", empty, "{ty}");
        not_found();
        let res = s.h.get(&path).await;
        assert_eq!(res.status, 503, "{ty}: {:?}", res.body);
        let again = s.h.get(&path).await;
        assert_eq!((again.status, again.bytes()), (200, truth.bytes()), "{ty}");
    }
    // The way down to the repository: not "there is none" (`restic init` would make another).
    not_found();
    assert_eq!(s.h.head("/config").await.status, 503);
    assert_eq!(s.h.head("/config").await.status, 200);
    // A file no listing has shown yet: not "no such file".
    let absent = format!("/snapshots/{}", sha(b"never uploaded"));
    not_found();
    assert_eq!(s.h.get(&absent).await.status, 503);
    assert_eq!(s.h.get(&absent).await.status, 404);
    let (code, stderr) = s.close().await;
    assert_eq!(code, Some(0));
    assert!(
        stderr.contains("GET main:snapshots/: Drive answered \"not found\" to a listing"),
        "{stderr}"
    );
}

// ---------------------------------------------------------------------------------------------
// `gclone serve restic --port N`
// ---------------------------------------------------------------------------------------------

fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    probe.local_addr().unwrap().port()
}

struct Listening {
    child: Child,
    port: u16,
    token: String,
    lines: Vec<String>,
}

impl Listening {
    /// Starts the listener and reads the four lines it prints.
    fn start(d: &Device, extra: &[&str]) -> Listening {
        Listening::start_with(d, extra, |_| {})
    }

    /// The same, with a last word on how the process is started.
    fn start_with(d: &Device, extra: &[&str], prepare: impl FnOnce(&mut Command)) -> Listening {
        let port = free_port();
        let port_text = port.to_string();
        let mut args = vec!["serve", "restic", "--port", &port_text];
        args.extend(extra);
        let mut command = d.command(&args);
        prepare(&mut command);
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn gclone");
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut lines = Vec::new();
        for _ in 0..4 {
            let mut line = String::new();
            stdout.read_line(&mut line).expect("a line");
            lines.push(line.trim_end().to_string());
        }
        let token = lines[2]
            .strip_prefix("export RESTIC_REST_PASSWORD=")
            .unwrap_or_else(|| panic!("no token in {lines:?}"))
            .to_string();
        Listening {
            child,
            port,
            token,
            lines,
        }
    }

    fn stderr(&mut self) -> String {
        let mut text = String::new();
        if let Some(mut stderr) = self.child.stderr.take() {
            stderr.read_to_string(&mut text).expect("stderr");
        }
        text
    }
}

impl Drop for Listening {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The listener and the key store (§8.2, §8.3): `gclone keystore use` moves the secrets under
/// a running listener, which is no sign-out; a listener started on a sealed device reads the
/// login from `secrets.sealed` and writes nothing but the token cache; and the trial of a
/// device on the plain file runs from `serve restic` too, writing its record and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_listener_and_the_key_store() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let mut d = lab.signed_in(&fake, "a").await;
    d.env
        .push(("GCLONE_TEST_KEYSTORE_SEALER".into(), "fake".into()));
    let names = |d: &Device| {
        let mut names: Vec<String> = std::fs::read_dir(&d.state)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.file_type().unwrap().is_file())
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    };
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let request = |l: &Listening| {
        http.post(format!("http://127.0.0.1:{}/main/?create=true", l.port))
            .basic_auth("gclone", Some(l.token.clone()))
            .send()
    };
    let enclave = [
        "keystore",
        "use",
        "enclave",
        "--yes",
        "--skip-passphrase-check",
    ];

    let mut l = Listening::start(&d, &[]);
    assert_eq!(request(&l).await.unwrap().status(), 200);
    for _ in 0..2 {
        d.run(&enclave).ok();
        assert!(!d.secrets_file().exists());
        // Longer than the watcher's interval.
        tokio::time::sleep(Duration::from_millis(2300)).await;
        assert_eq!(wait(&mut l.child, Duration::ZERO), None, "still serving");
        assert_eq!(request(&l).await.unwrap().status(), 200);
        d.run(&["keystore", "use", "file"]).ok();
        tokio::time::sleep(Duration::from_millis(2300)).await;
        assert_eq!(wait(&mut l.child, Duration::ZERO), None, "still serving");
    }
    drop(l);

    // Started on a sealed device: the login comes out of secrets.sealed, and the only file
    // the server writes is the token cache.
    d.run(&enclave).ok();
    let _ = std::fs::remove_file(d.state.join("token.json"));
    let before = names(&d);
    assert!(
        before.contains(&"secrets.sealed".to_string())
            && !before.contains(&"secrets.json".to_string())
    );
    let sealed_before = std::fs::read(d.state.join("secrets.sealed")).unwrap();
    let mut l = Listening::start(&d, &[]);
    assert_eq!(request(&l).await.unwrap().status(), 200);
    let mut expected = before.clone();
    expected.push("token.json".into());
    expected.sort();
    assert_eq!(names(&d), expected);
    assert_eq!(
        std::fs::read(d.state.join("secrets.sealed")).unwrap(),
        sealed_before
    );
    // `gclone logout` of the sealed device ends it: exit 4.
    d.run(&["logout"]).ok();
    assert_eq!(wait(&mut l.child, Duration::from_secs(10)), Some(4));
    assert!(l.stderr().contains("this device was signed out: stopped"));

    // A device on the plain file, with the trial on: `serve restic` is a run like any other —
    // it is the run a scheduler makes — and writes the trial's record, and nothing else new.
    let mut t = lab.signed_in(&fake, "b").await;
    t.env
        .push(("GCLONE_TEST_KEYSTORE_SEALER".into(), "fake".into()));
    t.env.push(("GCLONE_KEYSTORE_TRIAL".into(), "1".into()));
    t.env.push(("GCLONE_TEST_SESSION".into(), "0x2".into()));
    let _ = std::fs::remove_file(t.state.join("token.json"));
    let before = names(&t);
    let secrets_before = std::fs::read(t.secrets_file()).unwrap();
    let l = Listening::start(&t, &[]);
    assert_eq!(request(&l).await.unwrap().status(), 200);
    let mut expected = before.clone();
    expected.extend([
        "keystore-trial.json".to_string(),
        // the lock every change of the record is made under (§8.2)
        "keystore-trial.lock".to_string(),
        "token.json".to_string(),
    ]);
    expected.sort();
    assert_eq!(names(&t), expected);
    assert_eq!(std::fs::read(t.secrets_file()).unwrap(), secrets_before);
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(t.state.join("keystore-trial.json")).unwrap())
            .unwrap();
    assert_eq!(
        record["ok"][0]["session"], "0x2",
        "the scheduler's session is in the record"
    );
}

/// B5.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_listener_process() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let d = lab.signed_in(&fake, "a").await;
    let mut l = Listening::start(&d, &[]);
    let port = l.port;
    assert_eq!(
        l.lines,
        [
            format!("Serving restic repositories on http://127.0.0.1:{port}/NAME/ — Ctrl-C stops."),
            "export RESTIC_REST_USERNAME=gclone".to_string(),
            format!("export RESTIC_REST_PASSWORD={}", l.token),
            format!("restic -r rest:http://127.0.0.1:{port}/NAME/ snapshots"),
        ]
    );
    assert_eq!(l.token.len(), 32);
    assert!(l.token.bytes().all(|b| b.is_ascii_hexdigit()));

    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = |path: &str| format!("http://127.0.0.1:{port}{path}");
    let anonymous = http.get(url("/main/config")).send().await.unwrap();
    assert_eq!(anonymous.status(), 401);
    let token = l.token.clone();
    let auth = move |req: reqwest::RequestBuilder| req.basic_auth("gclone", Some(token.clone()));
    let res = auth(http.post(url("/main/?create=true")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = auth(http.post(url("/main/config")).body("cfg"))
        .send()
        .await;
    assert_eq!(res.unwrap().status(), 200);
    let res = auth(http.get(url("/main/config"))).send().await.unwrap();
    assert_eq!(res.text().await.unwrap(), "cfg");
    // The other loopback address answers as well, where the machine has one.
    if let Ok(res) = auth(http.get(format!("http://[::1]:{port}/main/config")))
        .send()
        .await
    {
        assert_eq!(res.status(), 200);
    }

    // `gclone logout` on this device ends it: exit 4.
    d.run(&["logout"]).ok();
    assert_eq!(wait(&mut l.child, Duration::from_secs(10)), Some(4));
    let stderr = l.stderr();
    assert!(
        stderr.contains("this device was signed out: stopped"),
        "{stderr}"
    );

    // Ctrl-C ends it: exit 0. A new start has a new token.
    let d = lab.signed_in(&fake, "b").await;
    let mut l2 = Listening::start(&d, &["--append-only"]);
    assert_ne!(l2.token, l.token);
    let token = l2.token.clone();
    let auth2 = move |req: reqwest::RequestBuilder| req.basic_auth("x", Some(token.clone()));
    let old = auth(http.get(format!("http://127.0.0.1:{}/main/config", l2.port)));
    assert_eq!(old.send().await.unwrap().status(), 401, "the old token");
    let res = auth2(http.delete(format!("http://127.0.0.1:{}/main/config", l2.port)));
    assert_eq!(res.send().await.unwrap().status(), 403, "--append-only");
    signal(l2.child.id(), libc::SIGINT);
    assert_eq!(wait(&mut l2.child, Duration::from_secs(10)), Some(0));
    assert_eq!(l2.stderr(), "");

    // SIGTERM — a service manager, `kill`, `docker stop` — ends it the same way: exit 0,
    // after the uploads nobody was answered for were taken back.
    let mut l3 = Listening::start(&d, &[]);
    let locks = fake
        .path(&["gclone-restic", "main", "locks"])
        .expect("the locks folder");
    fake.set_list_lag(u32::MAX);
    let lock = b"a lock no listing confirms";
    let request = http
        .post(format!(
            "http://127.0.0.1:{}/main/locks/{}",
            l3.port,
            sha(lock)
        ))
        .basic_auth("gclone", Some(l3.token.clone()))
        .body(lock.to_vec());
    let pending = tokio::spawn(request.send());
    let deadline = Instant::now() + Duration::from_secs(30);
    while fake.children(&locks).is_empty() {
        assert!(Instant::now() < deadline, "the lock was not uploaded");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!fake.children(&locks)[0].trashed);
    signal(l3.child.id(), libc::SIGTERM);
    assert_eq!(wait(&mut l3.child, Duration::from_secs(15)), Some(0));
    assert_eq!(l3.stderr(), "");
    let [left] = fake.children(&locks).try_into().expect("one object");
    assert!(left.trashed, "SIGTERM left the unanswered lock behind");
    pending.abort();
    fake.set_list_lag(0);
    // SIGHUP: the terminal it was started in closed.
    let mut l4 = Listening::start(&d, &[]);
    signal(l4.child.id(), libc::SIGHUP);
    assert_eq!(wait(&mut l4.child, Duration::from_secs(10)), Some(0));
    assert_eq!(l4.stderr(), "");
    // Started under `nohup`, it ignores SIGHUP as it was told to.
    let mut l5 = Listening::start_with(&d, &[], |command| {
        use std::os::unix::process::CommandExt as _;
        // SAFETY: between fork and exec, one async-signal-safe call.
        unsafe {
            command.pre_exec(|| {
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
                Ok(())
            })
        };
    });
    signal(l5.child.id(), libc::SIGHUP);
    assert_eq!(wait(&mut l5.child, Duration::from_secs(1)), None);
    let res = http.get(format!("http://127.0.0.1:{}/main/config", l5.port));
    assert_eq!(res.send().await.unwrap().status(), 401, "still serving");
    signal(l5.child.id(), libc::SIGTERM);
    assert_eq!(wait(&mut l5.child, Duration::from_secs(10)), Some(0));

    // A port whose IPv6 loopback address someone else holds: the listener does not start —
    // restic sends the token unasked, and `localhost` may mean `::1`.
    let Ok(v6) = std::net::TcpListener::bind(("::1", 0)) else {
        return;
    };
    let taken = v6.local_addr().unwrap().port();
    if std::net::TcpListener::bind(("127.0.0.1", taken)).is_err() {
        return;
    }
    let out = d.run(&["serve", "restic", "--port", &taken.to_string()]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(
        out.stderr
            .contains(&format!("port {taken} is in use on [::1]")),
        "{}",
        out.stderr
    );
    assert_eq!(out.stdout, "", "no token was printed");
}

// ---------------------------------------------------------------------------------------------
// The real restic
// ---------------------------------------------------------------------------------------------

/// `restic X.Y.Z …` → at least 0.17.
fn new_enough(version_line: &str) -> bool {
    let mut words = version_line.split_whitespace();
    if words.next() != Some("restic") {
        return false;
    }
    let mut numbers = words.next().unwrap_or("").split('.');
    let mut number = || numbers.next().and_then(|n| n.parse::<u32>().ok());
    matches!((number(), number()), (Some(major), Some(minor)) if (major, minor) >= (0, 17))
}

fn find_restic() -> Option<PathBuf> {
    static FOUND: OnceLock<Option<PathBuf>> = OnceLock::new();
    FOUND
        .get_or_init(|| {
            // `GCLONE_TEST_RESTIC` names the binary; only without it is `PATH` searched.
            let candidates: Vec<PathBuf> = match std::env::var_os("GCLONE_TEST_RESTIC") {
                Some(named) => vec![PathBuf::from(named)],
                None => {
                    let path = std::env::var_os("PATH").unwrap_or_default();
                    let dirs = std::env::split_paths(&path);
                    dirs.map(|dir| dir.join("restic")).collect()
                }
            };
            candidates.into_iter().find(|candidate| {
                let version = Command::new(candidate).arg("version").output();
                version.is_ok_and(|out| {
                    out.status.success() && new_enough(&String::from_utf8_lossy(&out.stdout))
                })
            })
        })
        .clone()
}

/// How restic reaches the repository.
#[derive(Clone)]
enum Via {
    /// `-o rclone.program=gclone -r rclone:<repo>`: the short form, with restic's default
    /// arguments (`serve restic --stdio --b2-hard-delete <repo>`).
    Stdio(&'static str),
    /// `-o rclone.args="serve restic --stdio --append-only"`.
    AppendOnly(&'static str),
    /// Another program in gclone's place (a wrapper script).
    Program(String, &'static str),
    /// `rest:http://127.0.0.1:<port>/<repo>/`, with or without the token.
    Rest(u16, &'static str, Option<String>),
}

#[derive(Clone)]
struct Restic {
    bin: PathBuf,
    /// Options for every run (`-o …`).
    opts: Vec<&'static str>,
    /// Where restic runs: backups name their sources relative to it.
    cwd: PathBuf,
    cache: PathBuf,
    tmp: PathBuf,
}

/// The restic to test with — or `None`, with a note that stays visible (a direct write: the
/// test harness captures what `eprintln!` prints).
fn restic(test: &str, lab: &Lab) -> Option<Restic> {
    let Some(bin) = find_restic() else {
        if std::env::var("GCLONE_REQUIRE_RESTIC").as_deref() == Ok("1") {
            panic!("GCLONE_REQUIRE_RESTIC=1, and restic 0.17 or later was not found");
        }
        let note = format!("note: restic 0.17 or later is not installed — skipped: {test}\n");
        let _ = std::io::stderr().write_all(note.as_bytes());
        return None;
    };
    let (cache, tmp) = (lab.path("restic-cache"), lab.path("restic-tmp"));
    std::fs::create_dir_all(&cache).expect("cache dir");
    std::fs::create_dir_all(&tmp).expect("tmp dir");
    Some(Restic {
        bin,
        opts: Vec::new(),
        cwd: lab.tmp.path().to_path_buf(),
        cache,
        tmp,
    })
}

impl Restic {
    fn command(&self, d: &Device, via: &Via, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.bin);
        let bin_dir = Path::new(BIN).parent().expect("the binary's directory");
        let path = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(bin_dir.to_path_buf()).chain(std::env::split_paths(&path)),
        )
        .expect("PATH");
        // Nothing of the environment of whoever runs the tests reaches restic or gclone.
        cmd.env_clear()
            .env("PATH", path)
            .env("RESTIC_PASSWORD", "the password of the test repository")
            .env("RESTIC_CACHE_DIR", &self.cache)
            .env("RESTIC_PACK_SIZE", "4")
            .env("TMPDIR", &self.tmp)
            .envs(d.vars())
            .current_dir(&self.cwd)
            .stdin(Stdio::null())
            .args(&self.opts);
        match via {
            Via::Stdio(repo) => {
                cmd.args([
                    "-o",
                    "rclone.program=gclone",
                    "-r",
                    &format!("rclone:{repo}"),
                ]);
            }
            Via::AppendOnly(repo) => {
                cmd.args(["-o", "rclone.program=gclone"])
                    .args(["-o", "rclone.args=serve restic --stdio --append-only"])
                    .args(["-r", &format!("rclone:{repo}")]);
            }
            Via::Program(program, repo) => {
                cmd.args(["-o", &format!("rclone.program={program}")])
                    .args(["-r", &format!("rclone:{repo}")]);
            }
            Via::Rest(port, repo, token) => {
                cmd.args(["-r", &format!("rest:http://127.0.0.1:{port}/{repo}/")]);
                if let Some(token) = token {
                    cmd.env("RESTIC_REST_USERNAME", "gclone")
                        .env("RESTIC_REST_PASSWORD", token);
                }
            }
        }
        cmd.args(args);
        cmd
    }

    async fn run(&self, d: &Device, via: &Via, args: &[&str]) -> Out {
        let mut cmd = self.command(d, via, args);
        let started = Instant::now();
        let out = tokio::task::spawn_blocking(move || cmd.output().expect("spawn restic"))
            .await
            .expect("join");
        Out::of(out, started.elapsed()).sane()
    }

    /// The IDs of the repository's snapshots.
    async fn snapshots(&self, d: &Device, via: &Via) -> Vec<String> {
        let out = self.run(d, via, &["snapshots", "--json"]).await.ok();
        let listed: Vec<serde_json::Value> = serde_json::from_str(out.stdout.trim())
            .unwrap_or_else(|e| panic!("{e}: {}", out.stdout));
        let ids = listed.iter().map(|s| s["id"].as_str().unwrap().to_string());
        ids.collect()
    }
}

/// Every file below `root`, by relative path.
fn read_tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(&path, root, out);
            } else {
                let rel = path.strip_prefix(root).unwrap().to_path_buf();
                out.insert(rel, std::fs::read(&path).expect("read"));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

#[track_caller]
fn assert_same_tree(a: &Path, b: &Path) {
    let (a, b) = (read_tree(a), read_tree(b));
    let names = |t: &BTreeMap<PathBuf, Vec<u8>>| t.keys().cloned().collect::<Vec<_>>();
    assert_eq!(names(&a), names(&b));
    for (name, bytes) in &a {
        assert!(b[name] == *bytes, "{} differs", name.display());
    }
    assert!(!a.is_empty());
}

/// The files of a repository on the fake, as another machine would find them.
struct OnDrive<'a> {
    fake: &'a FakeDrive,
    repo: &'a str,
}

impl OnDrive<'_> {
    fn folder(&self, sub: &[&str]) -> String {
        let mut path = vec!["gclone-restic", self.repo];
        path.extend(sub);
        self.fake
            .path(&path)
            .unwrap_or_else(|| panic!("no folder {path:?} on the fake"))
    }

    /// Files directly in a type folder, those in the trash included.
    fn files(&self, ty: &str) -> Vec<fake_drive::Child> {
        let all = self.fake.children(&self.folder(&[ty])).into_iter();
        all.filter(|c| !c.is_folder).collect()
    }

    fn live(&self, ty: &str) -> Vec<fake_drive::Child> {
        self.files(ty).into_iter().filter(|c| !c.trashed).collect()
    }

    /// Every pack with its shard folder's ID, those in the trash included.
    fn packs(&self) -> Vec<(String, fake_drive::Child)> {
        let mut out = Vec::new();
        for shard in self.fake.children(&self.folder(&["data"])) {
            for pack in self.fake.children(&shard.id) {
                out.push((shard.id.clone(), pack));
            }
        }
        out
    }

    fn live_packs(&self) -> Vec<(String, fake_drive::Child)> {
        let all = self.packs().into_iter();
        all.filter(|(_, p)| !p.trashed).collect()
    }

    /// No name is held by two objects that are not in the trash.
    #[track_caller]
    fn assert_no_duplicates(&self) {
        let mut seen = HashSet::new();
        for (_, pack) in self.live_packs() {
            assert!(
                seen.insert(pack.name.clone()),
                "two live objects named {}",
                pack.name
            );
        }
        for ty in ["keys", "locks", "snapshots", "index"] {
            let mut seen = HashSet::new();
            for file in self.live(ty) {
                assert!(
                    seen.insert(file.name.clone()),
                    "two live {ty} named {}",
                    file.name
                );
            }
        }
    }
}

/// New data of this size makes restic write at least one pack above 4 MiB (`RESTIC_PACK_SIZE=4`):
/// restic spreads the blobs of a run over two packers and uploads one when it reaches the pack
/// size, so less than twice that may end as two packs below it.
const STREAMED: usize = 10 << 20;

/// More than [`STREAMED`] in all: a backup of it has a pack that takes the streamed path.
const DATA: [(&str, usize); 4] = [
    ("big.bin", 6 << 20),
    ("medium.bin", 3 << 20),
    ("sub/dir/small.bin", (5 << 19) + 12345),
    ("notes.txt", 2000),
];

/// E1 and E2: the whole workflow, what it leaves on Drive, and the vault beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_workflow() {
    let lab = Lab::new();
    let Some(r) = restic("restic_workflow", &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let via = Via::Stdio("main");

    // The device's vault has files of its own.
    let docs = lab.tree("docs", 7, &[("a.txt", 5000), ("deep/b.bin", 300_000)]);
    d.run(&["copy", docs.to_str().unwrap(), ":docs"]).ok();
    let vault_listing = d.run(&["ls", "-l", "-R", ":"]).ok().stdout;
    let vault_gc = d.run(&["gc", "-n", "--orphans"]);
    let vault_status = d.run(&["status"]).ok();

    let src = lab.tree("src", 1, &DATA);
    r.run(&d, &via, &["init"]).await.ok().quiet();
    r.run(&d, &via, &["backup", "src"]).await.ok().quiet();
    assert_eq!(r.snapshots(&d, &via).await.len(), 1);
    std::fs::write(src.join("notes.txt"), "changed\n").unwrap();
    std::fs::write(src.join("new.bin"), prng::Prng::new(2).bytes(1 << 20)).unwrap();
    r.run(&d, &via, &["backup", "src"]).await.ok().quiet();
    assert_eq!(r.snapshots(&d, &via).await.len(), 2);

    let out = lab.path("restored");
    let target = out.to_str().unwrap();
    r.run(&d, &via, &["restore", "latest", "--target", target])
        .await
        .ok()
        .quiet();
    assert_same_tree(&src, &out.join("src"));
    r.run(&d, &via, &["check", "--read-data"])
        .await
        .ok()
        .quiet();
    r.run(&d, &via, &["forget", "--keep-last", "1", "--prune"])
        .await
        .ok()
        .quiet();
    r.run(&d, &via, &["check"]).await.ok().quiet();
    assert_eq!(r.snapshots(&d, &via).await.len(), 1);
    r.run(&d, &via, &["stats"]).await.ok().quiet();

    // On Drive: restic's own local layout, 256 shard folders, nothing else.
    let on = OnDrive {
        fake: &fake,
        repo: "main",
    };
    let top: Vec<(String, bool)> = fake
        .children(&on.folder(&[]))
        .into_iter()
        .filter(|c| !c.trashed)
        .map(|c| (c.name, c.is_folder))
        .collect();
    let expected = [
        ("config", false),
        ("data", true),
        ("index", true),
        ("keys", true),
        ("locks", true),
        ("snapshots", true),
    ];
    let mut sorted = top.clone();
    sorted.sort();
    assert_eq!(sorted, expected.map(|(n, f)| (n.to_string(), f)));
    let shards = fake.children(&on.folder(&["data"]));
    let names: HashSet<String> = shards.iter().map(|c| c.name.clone()).collect();
    assert_eq!(shards.len(), 256);
    assert!((0..256).all(|i| names.contains(&format!("{i:02x}"))));
    assert!(shards.iter().all(|c| c.is_folder && !c.trashed));

    // Every file is named by the SHA-256 of its bytes, in the folder its name belongs to.
    let packs = on.live_packs();
    assert!(!packs.is_empty());
    for (shard, pack) in &packs {
        let bytes = fake.object(&pack.id).unwrap();
        assert_eq!(sha(&bytes), pack.name);
        let folder = shards.iter().find(|c| c.id == *shard).unwrap();
        assert_eq!(folder.name, pack.name[..2]);
    }
    for ty in ["keys", "snapshots", "index"] {
        for file in on.live(ty) {
            assert_eq!(sha(&fake.object(&file.id).unwrap()), file.name, "{ty}");
        }
    }
    on.assert_no_duplicates();
    assert!(
        fake.hits(Route::ResumableInit) > 0,
        "packs above 4 MiB went up streamed"
    );
    // Deleted means: in the Drive trash. Nothing was deleted for good; no lock is left.
    assert_eq!(on.live("snapshots").len(), 1);
    assert_eq!(on.files("snapshots").len(), 2);
    assert!(
        on.packs().iter().any(|(_, p)| p.trashed),
        "prune trashed packs"
    );
    assert!(on.files("locks").len() > 5 && on.live("locks").is_empty());
    assert_eq!(fake.hits(Route::Delete), 0);

    // E2: the vault never noticed.
    d.run(&["check"]).ok();
    assert_eq!(d.run(&["ls", "-l", "-R", ":"]).ok().stdout, vault_listing);
    let gc = d.run(&["gc", "-n", "--orphans"]);
    assert_eq!((gc.code, gc.stdout), (vault_gc.code, vault_gc.stdout));
    let status = d.run(&["status"]).ok();
    assert_eq!(status.stderr, vault_status.stderr);
    let back = lab.path("docs-back");
    d.run(&["copy", ":docs", back.to_str().unwrap()]).ok();
    assert_same_tree(&docs, &back);
}

/// A restic that holds its lock: `backup --stdin` with its input kept open.
struct Held {
    child: Child,
    input: Option<std::process::ChildStdin>,
    stderr: Arc<Mutex<String>>,
}

impl Held {
    fn start(r: &Restic, d: &Device, via: &Via, on: &OnDrive<'_>) -> Held {
        let mut cmd = r.command(
            d,
            via,
            &["backup", "--stdin", "--stdin-filename", "held.bin"],
        );
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn restic");
        let mut input = child.stdin.take().unwrap();
        input.write_all(&[7u8; 4096]).expect("write");
        let stderr = collect(child.stderr.take().unwrap());
        let deadline = Instant::now() + Duration::from_secs(60);
        while on.live("locks").is_empty() {
            assert!(
                Instant::now() < deadline,
                "no lock: {}",
                stderr.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Held {
            child,
            input: Some(input),
            stderr,
        }
    }

    /// Ends the input: restic finishes its backup.
    fn finish(mut self) -> i32 {
        drop(self.input.take());
        wait(&mut self.child, Duration::from_secs(120)).expect("restic ends")
    }
}

/// E3: two restic processes, each with its own gclone, and restic's locks between them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_locks_between_two_processes() {
    let lab = Lab::new();
    let Some(r) = restic("restic_locks_between_two_processes", &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let via = Via::Stdio("main");
    r.run(&d, &via, &["init"]).await.ok();
    let on = OnDrive {
        fake: &fake,
        repo: "main",
    };

    let held = Held::start(&r, &d, &via, &on);
    assert_eq!(on.live("locks").len(), 1);
    // A shared lock goes with another shared lock …
    r.run(&d, &via, &["snapshots"]).await.ok();
    // … and not with an exclusive one: the other process's lock is seen at once.
    let refused = r.run(&d, &via, &["check"]).await.failed_promptly();
    assert!(refused.stderr.contains("locked"), "{}", refused.stderr);
    assert_eq!(
        on.live("locks").len(),
        1,
        "the refused lock was removed again"
    );

    let stderr = held.stderr.clone();
    assert_eq!(held.finish(), 0, "{}", stderr.lock().unwrap());
    assert!(on.live("locks").is_empty());
    r.run(&d, &via, &["check"]).await.ok();
    assert_eq!(r.snapshots(&d, &via).await.len(), 1);
    assert!(on.live("locks").is_empty());
}

/// E4: listings that lag behind uploads. A lock is acknowledged when a listing shows it, and
/// packs are listed before their index is acknowledged — so the next command finds them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_with_lagging_listings() {
    let lab = Lab::new();
    let Some(r) = restic("restic_with_lagging_listings", &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let via = Via::Stdio("main");
    r.run(&d, &via, &["init"]).await.ok();
    let on = OnDrive {
        fake: &fake,
        repo: "main",
    };
    let locks = on.folder(&["locks"]);
    lab.tree("src", 3, &DATA);
    let uploads_before = fake.requests(Route::Multipart).len();

    fake.set_list_lag(3);
    r.run(&d, &via, &["backup", "src"]).await.ok().quiet();

    // The backup's lock: created, then listed until a listing showed it, then removed.
    let created = fake
        .requests(Route::Multipart)
        .into_iter()
        .skip(uploads_before);
    let is_lock = |r: &fake_drive::Seen| {
        let parents = r
            .json
            .as_ref()
            .and_then(|j| j["parents"].as_array().cloned());
        parents.is_some_and(|p| p.iter().any(|id| id.as_str() == Some(locks.as_str())))
    };
    let lock = created
        .into_iter()
        .find(is_lock)
        .expect("a lock was uploaded");
    let id = lock.json.as_ref().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let trashed = fake.requests(Route::Patch).into_iter();
    let trashed = trashed
        .rev()
        .find(|r| r.path.ends_with(&id))
        .expect("the lock was removed");
    let listings = fake.requests(Route::List).into_iter();
    let between = listings
        .filter(|r| r.at > lock.at && r.at < trashed.at)
        .filter(|r| r.param("q").is_some_and(|q| q.contains(&locks)))
        .count();
    assert!(
        between >= 4,
        "{between} listings of locks/ while the lock was held"
    );

    // Directly afterwards, the lag still on.
    std::fs::write(lab.path("src/notes.txt"), "second run\n").unwrap();
    r.run(&d, &via, &["backup", "src"]).await.ok().quiet();
    r.run(&d, &via, &["forget", "--keep-last", "1", "--prune"])
        .await
        .ok()
        .quiet();
    r.run(&d, &via, &["check", "--read-data"])
        .await
        .ok()
        .quiet();
    assert_eq!(r.snapshots(&d, &via).await.len(), 1);
    on.assert_no_duplicates();
}

/// E5: what another machine deletes shows in the next listing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_after_a_foreign_delete() {
    let lab = Lab::new();
    let Some(r) = restic("restic_after_a_foreign_delete", &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let via = Via::Stdio("main");
    r.run(&d, &via, &["init"]).await.ok();
    lab.tree("src", 4, &DATA);
    r.run(&d, &via, &["backup", "src"]).await.ok();
    let on = OnDrive {
        fake: &fake,
        repo: "main",
    };
    let (shard, pack) = on
        .live_packs()
        .into_iter()
        .max_by_key(|(_, p)| p.size)
        .unwrap();

    // Trashed elsewhere: the listing is fresh, and `check` sees the hole.
    let other = fake.backend();
    other.trash(&Handle(pack.id.clone())).await.unwrap();
    r.run(&d, &via, &["check"]).await.failed_promptly();
    other.untrash(&Handle(pack.id.clone())).await.unwrap();
    r.run(&d, &via, &["check"]).await.ok();

    // Deleted for good: one load of that pack fails, promptly, after a look at its folder.
    other.delete(&Handle(pack.id.clone())).await.unwrap();
    let lists = |fake: &FakeDrive| {
        let all = fake.requests(Route::List).into_iter();
        all.filter(|r| r.param("q").is_some_and(|q| q.contains(&shard)))
            .count()
    };
    let before = lists(&fake);
    r.run(&d, &via, &["cat", "pack", &pack.name])
        .await
        .failed_promptly();
    assert!(lists(&fake) > before);
    r.run(&d, &via, &["check"]).await.failed_promptly();
}

/// E6: two objects of one name on Drive are one file to restic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_with_duplicate_names() {
    let lab = Lab::new();
    let Some(r) = restic("restic_with_duplicate_names", &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let via = Via::Stdio("main");
    r.run(&d, &via, &["init"]).await.ok();
    lab.tree("src", 5, &DATA);
    r.run(&d, &via, &["backup", "src"]).await.ok();
    let on = OnDrive {
        fake: &fake,
        repo: "main",
    };

    // Another machine uploads two of the packs a second time, and an index.
    let other = fake.backend();
    let mut doubled = Vec::new();
    for (shard, pack) in on.live_packs().into_iter().take(2) {
        let bytes = fake.object(&pack.id).unwrap();
        let id = other.new_ids(1).await.unwrap().remove(0);
        let folder = Handle(shard.clone());
        other
            .put(&id, &folder, &pack.name, stream_body(bytes.into()))
            .await
            .unwrap();
        doubled.push((shard, pack.name));
    }
    let index = on.live("index").remove(0);
    let id = other.new_ids(1).await.unwrap().remove(0);
    let bytes = fake.object(&index.id).unwrap();
    other
        .put(
            &id,
            &Handle(on.folder(&["index"])),
            &index.name,
            stream_body(bytes.into()),
        )
        .await
        .unwrap();

    r.run(&d, &via, &["check", "--read-data"])
        .await
        .ok()
        .quiet();
    r.run(&d, &via, &["prune"]).await.ok().quiet();
    let out = lab.path("restored");
    r.run(
        &d,
        &via,
        &["restore", "latest", "--target", out.to_str().unwrap()],
    )
    .await
    .ok();
    assert_same_tree(&lab.path("src"), &out.join("src"));

    // Forget everything: both copies of each go to the trash.
    let ids = r.snapshots(&d, &via).await;
    let mut args = vec!["forget", "--prune"];
    args.extend(ids.iter().map(String::as_str));
    r.run(&d, &via, &args).await.ok().quiet();
    assert!(on.live_packs().is_empty(), "{:?}", on.live_packs());
    for (shard, name) in doubled {
        let copies: Vec<_> = fake
            .children(&shard)
            .into_iter()
            .filter(|c| c.name == name)
            .collect();
        assert_eq!(copies.len(), 2);
        assert!(copies.iter().all(|c| c.trashed));
    }
    assert!(
        on.files("index")
            .iter()
            .filter(|c| c.name == index.name)
            .all(|c| c.trashed)
    );
}

/// Some file went up under two Drive IDs: restic sent a request again, and gclone made a new
/// upload of it (the Drive client's own retries keep the ID).
fn sent_again(fake: &FakeDrive, route: Route) -> bool {
    let mut ids: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for request in fake.requests(route) {
        let Some(json) = request.json else { continue };
        let text = |key: &str| json[key].as_str().unwrap_or("").to_string();
        ids.entry(text("name")).or_default().insert(text("id"));
    }
    ids.values().any(|ids| ids.len() > 1)
}

/// E7: uploads that fail on the way to Drive. restic retries; nothing is left twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_with_interrupted_uploads() {
    let lab = Lab::new();
    let Some(r) = restic("restic_with_interrupted_uploads", &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let via = Via::Stdio("main");
    r.run(&d, &via, &["init"]).await.ok();
    let src = lab.tree("src", 6, &DATA);
    let on = OnDrive {
        fake: &fake,
        repo: "main",
    };

    // One upload at a time, so that the failures below all meet the same one.
    let one = Restic {
        opts: vec!["-o", "rclone.connections=1"],
        ..r.clone()
    };

    // The streamed upload of a pack breaks ten times in a row: as often as the Drive client
    // tries by itself, so restic sees a failed request and sends it again.
    fake.fail_next(Route::SessionPut, 10, 503, "backendError");
    one.run(&d, &via, &["backup", "src"]).await.ok();
    assert!(fake.hits(Route::SessionPut) > 10);
    assert!(
        sent_again(&fake, Route::ResumableInit),
        "restic repeated the upload"
    );
    on.assert_no_duplicates();

    // The same for the one-request upload of small files (the first one is restic's lock).
    std::fs::write(src.join("more.bin"), prng::Prng::new(8).bytes(700_000)).unwrap();
    fake.fail_next(Route::Multipart, 12, 503, "backendError");
    one.run(&d, &via, &["backup", "src"]).await.ok();
    assert!(
        sent_again(&fake, Route::Multipart),
        "restic repeated the upload"
    );
    on.assert_no_duplicates();

    let out = lab.path("restored");
    r.run(
        &d,
        &via,
        &["restore", "latest", "--target", out.to_str().unwrap()],
    )
    .await
    .ok();
    assert_same_tree(&src, &out.join("src"));
    r.run(&d, &via, &["check", "--read-data"])
        .await
        .ok()
        .quiet();
    assert!(on.live("locks").is_empty());
}

/// E8: `--append-only`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_append_only() {
    let lab = Lab::new();
    let Some(r) = restic("restic_append_only", &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let via = Via::AppendOnly("main");
    r.run(&d, &via, &["init"]).await.ok().quiet();
    let src = lab.tree("src", 9, &DATA);
    r.run(&d, &via, &["backup", "src"]).await.ok().quiet();
    std::fs::write(src.join("notes.txt"), "again\n").unwrap();
    r.run(&d, &via, &["backup", "src"]).await.ok().quiet();
    r.run(&d, &via, &["check"]).await.ok().quiet();
    let on = OnDrive {
        fake: &fake,
        repo: "main",
    };
    assert!(on.live("locks").is_empty(), "locks can be deleted");

    // Everything that deletes is refused — promptly: 403 is not retried for long.
    r.run(&d, &via, &["forget", "--keep-last", "1", "--prune"])
        .await
        .failed_promptly();
    assert_eq!(r.snapshots(&d, &via).await.len(), 2);
    let trashed_outside_locks = |on: &OnDrive<'_>| {
        let small = ["keys", "snapshots", "index"].map(|ty| on.files(ty));
        let small = small.into_iter().flatten().filter(|c| c.trashed).count();
        small + on.packs().iter().filter(|(_, p)| p.trashed).count()
    };
    assert_eq!(trashed_outside_locks(&on), 0);
    assert_eq!(
        fake.children(&on.folder(&[]))
            .iter()
            .filter(|c| c.trashed)
            .count(),
        0
    );

    // An upload fails; restic's DELETE before its retry is refused; the retry succeeds.
    // (`STREAMED` of new data: a pack above 4 MiB, which goes up in a session.)
    std::fs::write(src.join("more.bin"), prng::Prng::new(10).bytes(STREAMED)).unwrap();
    let one = Restic {
        opts: vec!["-o", "rclone.connections=1"],
        ..r.clone()
    };
    fake.fail_next(Route::SessionPut, 10, 503, "backendError");
    one.run(&d, &via, &["backup", "src"]).await.ok();
    assert!(
        sent_again(&fake, Route::ResumableInit),
        "restic repeated the upload"
    );
    on.assert_no_duplicates();
    r.run(&d, &via, &["check", "--read-data"])
        .await
        .ok()
        .quiet();
    // The same repository without the flag: everything works.
    let free = Via::Stdio("main");
    r.run(&d, &free, &["forget", "--keep-last", "1", "--prune"])
        .await
        .ok()
        .quiet();
    assert_eq!(r.snapshots(&d, &free).await.len(), 1);
}

/// E9: restic's `rest:` backend against the loopback listener.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_through_the_listener() {
    let lab = Lab::new();
    let Some(r) = restic("restic_through_the_listener", &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let l = Listening::start(&d, &[]);
    let via = Via::Rest(l.port, "main", Some(l.token.clone()));
    r.run(&d, &via, &["init"]).await.ok();
    let src = lab.tree("src", 11, &DATA);
    r.run(&d, &via, &["backup", "src"]).await.ok();
    let out = lab.path("restored");
    r.run(
        &d,
        &via,
        &["restore", "latest", "--target", out.to_str().unwrap()],
    )
    .await
    .ok();
    assert_same_tree(&src, &out.join("src"));
    r.run(&d, &via, &["check", "--read-data"]).await.ok();
    r.run(&d, &via, &["forget", "--keep-last", "1", "--prune"])
        .await
        .ok();

    // Without the token, or with a wrong one: nothing, and at once.
    let anonymous = Via::Rest(l.port, "main", None);
    r.run(&d, &anonymous, &["snapshots"])
        .await
        .failed_promptly();
    let wrong = Via::Rest(l.port, "main", Some("0".repeat(32)));
    r.run(&d, &wrong, &["snapshots"]).await.failed_promptly();
    // The same repository through the pipe.
    assert_eq!(r.snapshots(&d, &Via::Stdio("main")).await.len(), 1);
}

/// E10: two backups into one repository at the same time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_concurrent_backups() {
    let lab = Lab::new();
    let Some(r) = restic("restic_concurrent_backups", &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let via = Via::Stdio("main");
    r.run(&d, &via, &["init"]).await.ok();
    lab.tree("one", 12, &DATA);
    lab.tree("two", 13, &DATA);
    // Two caches: two machines.
    let mut r2 = r.clone();
    r2.cache = lab.path("restic-cache-2");
    std::fs::create_dir_all(&r2.cache).unwrap();
    let (a, b) = tokio::join!(
        r.run(&d, &via, &["backup", "one"]),
        r2.run(&d, &via, &["backup", "two"])
    );
    a.ok().quiet();
    b.ok().quiet();
    assert_eq!(r.snapshots(&d, &via).await.len(), 2);
    r.run(&d, &via, &["check", "--read-data"])
        .await
        .ok()
        .quiet();
    let on = OnDrive {
        fake: &fake,
        repo: "main",
    };
    let shards = fake.children(&on.folder(&["data"]));
    assert_eq!(shards.len(), 256, "uploads never create folders");
    on.assert_no_duplicates();
    let listed = r.run(&d, &via, &["snapshots", "--json"]).await.ok().stdout;
    let listed: Vec<serde_json::Value> = serde_json::from_str(listed.trim()).unwrap();
    for snapshot in listed {
        let (id, path) = (
            snapshot["id"].as_str().unwrap(),
            snapshot["paths"][0].as_str().unwrap(),
        );
        let tree = Path::new(path).file_name().unwrap().to_str().unwrap();
        let out = lab.path(&format!("restored-{tree}"));
        r.run(
            &d,
            &via,
            &["restore", id, "--target", out.to_str().unwrap()],
        )
        .await
        .ok();
        assert_same_tree(&lab.path(tree), &out.join(tree));
    }
}

/// E11: two top-level `gclone-restic` folders — what two machines leave that initialise two
/// repositories on a fresh account at the same moment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_with_two_roots() {
    let lab = Lab::new();
    let Some(r) = restic("restic_with_two_roots", &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let (mine, theirs) = (Via::Stdio("mine"), Via::Stdio("other"));
    r.run(&d, &mine, &["init"]).await.ok();

    let other = fake.backend();
    let mut ids = other.new_ids(3).await.unwrap().into_iter();
    let (root, repo, stray) = (
        ids.next().unwrap(),
        ids.next().unwrap(),
        ids.next().unwrap(),
    );
    other
        .create_folder(&root, &Handle::top(), "gclone-restic")
        .await
        .unwrap();
    other.create_folder(&repo, &root, "other").await.unwrap();

    // `init` completes the tree where the folder is: in the second root.
    r.run(&d, &theirs, &["init"]).await.ok().quiet();
    let made = fake.children(&repo.0);
    assert!(made.iter().any(|c| c.name == "data" && c.is_folder));
    assert!(made.iter().any(|c| c.name == "config" && !c.is_folder));
    lab.tree("src", 14, &[("a.bin", 1 << 20), ("b.txt", 100)]);
    for via in [&mine, &theirs] {
        r.run(&d, via, &["backup", "src"]).await.ok().quiet();
        r.run(&d, via, &["check"]).await.ok().quiet();
        assert_eq!(r.snapshots(&d, via).await.len(), 1);
    }

    // The same name in both roots: no pick — an explicit error, at once.
    other.create_folder(&stray, &root, "mine").await.unwrap();
    let refused = r.run(&d, &mine, &["snapshots"]).await.failed_promptly();
    assert!(
        refused
            .stderr
            .contains("two folders named mine in gclone-restic"),
        "{}",
        refused.stderr
    );
    r.run(&d, &theirs, &["snapshots"]).await.ok().quiet();
}

/// E12: a broken tree ends a run within seconds, and nothing is deleted on the strength of
/// a listing that could not be made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_with_a_broken_layout() {
    let lab = Lab::new();
    let Some(r) = restic("restic_with_a_broken_layout", &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let via = Via::Stdio("main");
    r.run(&d, &via, &["init"]).await.ok();
    let src = lab.tree("src", 15, &[("a.bin", 2 << 20), ("b.txt", 100)]);
    r.run(&d, &via, &["backup", "src"]).await.ok();
    std::fs::write(src.join("b.txt"), "changed").unwrap();
    r.run(&d, &via, &["backup", "src"]).await.ok();
    let on = OnDrive {
        fake: &fake,
        repo: "main",
    };
    let other = fake.backend();

    // `snapshots/` in the trash: "no snapshots" would make prune remove every pack.
    let snapshots = Handle(on.folder(&["snapshots"]));
    other.trash(&snapshots).await.unwrap();
    let trashes = fake.hits(Route::Patch);
    let refused = r.run(&d, &via, &["snapshots"]).await.failed_promptly();
    assert!(refused.stderr.contains("restore it"), "{}", refused.stderr);
    r.run(&d, &via, &["forget", "--keep-last", "1", "--prune"])
        .await
        .failed_promptly();
    r.run(&d, &via, &["prune"]).await.failed_promptly();
    assert_eq!(fake.hits(Route::Patch), trashes, "nothing was trashed");
    other.untrash(&snapshots).await.unwrap();
    assert_eq!(r.snapshots(&d, &via).await.len(), 2);

    // The whole repository in the trash.
    let repo = Handle(on.folder(&[]));
    other.trash(&repo).await.unwrap();
    let trashes = fake.hits(Route::Patch);
    r.run(&d, &via, &["snapshots"]).await.failed_promptly();
    r.run(&d, &via, &["forget", "--keep-last", "1", "--prune"])
        .await
        .failed_promptly();
    assert_eq!(fake.hits(Route::Patch), trashes);
    other.untrash(&repo).await.unwrap();
    r.run(&d, &via, &["check"]).await.ok();
}

/// E13: a service manager stops the unit — SIGTERM to restic and to gclone alike. restic
/// still gets its lock removed, because gclone stays until the pipe closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_and_gclone_are_signalled_together() {
    use std::os::unix::fs::PermissionsExt as _;
    let lab = Lab::new();
    let Some(r) = restic("restic_and_gclone_are_signalled_together", &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    r.run(&d, &Via::Stdio("main"), &["init"]).await.ok();
    let on = OnDrive {
        fake: &fake,
        repo: "main",
    };

    // The backend program: a script that says which process gclone is.
    let (script, pid_file) = (lab.path("gclone-wrapper"), lab.path("gclone.pid"));
    let text = format!(
        "#!/bin/sh\necho $$ > '{}'\nexec gclone \"$@\"\n",
        pid_file.display()
    );
    std::fs::write(&script, text).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let via = Via::Program(script.to_str().unwrap().to_string(), "main");

    let mut held = Held::start(&r, &d, &via, &on);
    assert_eq!(on.live("locks").len(), 1);
    // The lock is on Drive before restic has its answer. A restic signalled between gclone's
    // commit and that answer gives up on a lock that stays (nobody can tell whether it read
    // the answer); that is not what this test is about, so restic gets time to read it.
    std::thread::sleep(Duration::from_secs(2));
    let gclone: u32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    signal(gclone, libc::SIGTERM);
    signal(held.child.id(), libc::SIGTERM);
    // restic, interrupted while it reads its input, stays until that input ends.
    drop(held.input.take());
    let ended = wait(&mut held.child, Duration::from_secs(90));
    assert!(
        ended.is_some(),
        "restic did not end: {}",
        held.stderr.lock().unwrap()
    );
    assert_ne!(ended, Some(0), "the backup was interrupted");
    // gclone ends with the pipe — after restic, which does not wait for it: a lock restic
    // was still creating when the signal came is taken back by gclone in that time.
    let deadline = Instant::now() + Duration::from_secs(15);
    // SAFETY: signal 0 only asks whether the process exists.
    while unsafe { libc::kill(gclone as i32, 0) } == 0 {
        assert!(Instant::now() < deadline, "gclone outlived restic");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        on.live("locks").is_empty(),
        "the lock was left behind: {}",
        held.stderr.lock().unwrap()
    );
    r.run(&d, &Via::Stdio("main"), &["check"]).await.ok();
}

/// A prepared restic command, run to its end.
async fn finish(mut cmd: Command) -> Out {
    let started = Instant::now();
    let out = tokio::task::spawn_blocking(move || cmd.output().expect("spawn restic"))
        .await
        .expect("join");
    Out::of(out, started.elapsed()).sane()
}

/// A second machine's restic: its own cache.
fn second(r: &Restic, lab: &Lab) -> Restic {
    let mut other = r.clone();
    other.cache = lab.path("restic-cache-2");
    std::fs::create_dir_all(&other.cache).expect("cache dir");
    other
}

/// E14: two `restic init` runs for one name, the second one started while the first is
/// between its folders and its config. One repository comes of it and the other init fails:
/// the `DELETE config` restic sends after its refused upload does not take the winner's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_inits_at_the_same_time() {
    let lab = Lab::new();
    let Some(r) = restic("restic_inits_at_the_same_time", &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let r2 = second(&r, &lab);
    let passwords = ["the password of machine a", "the password of machine b"];
    for (round, name) in ["r0", "r1"].into_iter().enumerate() {
        // The folders are there — the first init made them — and nothing else yet.
        let s = Stdio2::start(&d, &["serve", "restic", "--stdio", name]).await;
        s.h.create().await;
        s.close().await;
        let via = Via::Stdio(name);
        let mut a = r.command(&d, &via, &["init"]);
        a.env("RESTIC_PASSWORD", passwords[0]);
        let mut b = r2.command(&d, &via, &["init"]);
        b.env("RESTIC_PASSWORD", passwords[1]);
        let delay = Duration::from_millis(60 * round as u64);
        let later = async {
            tokio::time::sleep(delay).await;
            finish(b).await
        };
        let (a, b) = tokio::join!(finish(a), later);
        let outs = [a, b];
        let report = format!(
            "round {round}\n--- a: {}\n{}{}\n--- b: {}\n{}{}",
            outs[0].code,
            outs[0].stdout,
            outs[0].stderr,
            outs[1].code,
            outs[1].stdout,
            outs[1].stderr
        );
        let won: Vec<usize> = (0..2).filter(|i| outs[*i].code == 0).collect();
        assert_eq!(won.len(), 1, "one init succeeds, and only one\n{report}");
        let (winner, loser) = (won[0], 1 - won[0]);
        assert!(outs[loser].took < PROMPT, "{report}");
        if outs[loser].stderr.contains("(403)") {
            // Refused at its config: gclone says what happened, and what is left to do.
            let said = &outs[loser].stderr;
            assert!(
                said.contains("that one is kept") && said.contains("restic key remove"),
                "{report}"
            );
        }

        // One config, the winner's, and the winner's password opens the repository.
        let on = OnDrive {
            fake: &fake,
            repo: name,
        };
        let top = fake.children(&on.folder(&[])).into_iter();
        let configs: Vec<_> = top.filter(|c| c.name == "config" && !c.trashed).collect();
        assert_eq!(configs.len(), 1, "{report}");
        let created = outs[winner].stdout.split_whitespace();
        let id = created
            .skip_while(|word| *word != "repository")
            .nth(1)
            .unwrap_or_else(|| panic!("no repository id\n{report}"));
        let mut open = r.command(&d, &via, &["cat", "config"]);
        open.env("RESTIC_PASSWORD", passwords[winner]);
        let opened = finish(open).await.ok();
        let config: serde_json::Value = serde_json::from_str(opened.stdout.trim()).unwrap();
        assert!(config["id"].as_str().unwrap().starts_with(id), "{report}");

        // The key the other init wrote is left; the remedy the note names works.
        let keys = on.live("keys").len();
        assert!((1..=2).contains(&keys), "{keys} keys\n{report}");
        if keys == 2 {
            let mut list = r.command(&d, &via, &["key", "list", "--json"]);
            list.env("RESTIC_PASSWORD", passwords[winner]);
            let listed = finish(list).await.ok();
            let listed: Vec<serde_json::Value> = serde_json::from_str(listed.stdout.trim())
                .unwrap_or_else(|e| panic!("{e}: {}", listed.stdout));
            let stray = listed.iter().find(|key| key["current"] == false);
            let stray = stray.expect("the other init's key")["id"].as_str().unwrap();
            let mut remove = r.command(&d, &via, &["key", "remove", stray]);
            remove.env("RESTIC_PASSWORD", passwords[winner]);
            finish(remove).await.ok();
            assert_eq!(on.live("keys").len(), 1);
        }
        let mut check = r.command(&d, &via, &["check"]);
        check.env("RESTIC_PASSWORD", passwords[winner]);
        finish(check).await.ok();
    }
}

/// E15: `--port`. A backup through the listener is interrupted after some packs; another
/// machine prunes them, as it may: no index names them. The listener's next backups are not
/// held to those packs — what it remembers about packs ends with the run that uploaded them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_through_the_listener_after_an_interrupted_backup() {
    let lab = Lab::new();
    let test = "restic_through_the_listener_after_an_interrupted_backup";
    let Some(r) = restic(test, &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let l = Listening::start(&d, &[]);
    let via = Via::Rest(l.port, "main", Some(l.token.clone()));
    let (r2, elsewhere) = (second(&r, &lab), Via::Stdio("main"));
    r.run(&d, &via, &["init"]).await.ok();
    let src = lab.tree("src", 16, &[("a.bin", 1 << 20)]);
    r.run(&d, &via, &["backup", "src"]).await.ok();
    let on = OnDrive {
        fake: &fake,
        repo: "main",
    };

    // Ctrl-C after three packs: restic removes its lock and writes no index.
    std::fs::write(src.join("big.bin"), prng::Prng::new(17).bytes(64 << 20)).unwrap();
    let before = on.live_packs().len();
    let mut child = r
        .command(&d, &via, &["backup", "src"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn restic");
    let stderr = collect(child.stderr.take().unwrap());
    let deadline = Instant::now() + Duration::from_secs(120);
    while on.live_packs().len() < before + 3 {
        let said = stderr.lock().unwrap().clone();
        assert!(Instant::now() < deadline, "no packs: {said}");
        let ended = child.try_wait().expect("wait");
        assert!(ended.is_none(), "the backup ended by itself: {said}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    signal(child.id(), libc::SIGINT);
    let code = tokio::task::spawn_blocking(move || wait(&mut child, Duration::from_secs(120)))
        .await
        .unwrap();
    assert_eq!(code, Some(130), "{}", stderr.lock().unwrap());
    assert!(on.live("locks").is_empty());
    let left = on.live_packs().len();
    assert!(left > before);
    r2.run(&d, &elsewhere, &["prune"]).await.ok();
    assert!(on.live_packs().len() < left, "the prune removed nothing");

    std::fs::write(src.join("big.bin"), prng::Prng::new(18).bytes(2 << 20)).unwrap();
    for round in 0..2 {
        let more = prng::Prng::new(19 + round).bytes(300_000);
        std::fs::write(src.join("more.bin"), more).unwrap();
        r.run(&d, &via, &["backup", "src"]).await.ok();
    }

    // The same for a pack that came without any lock, and went the same way.
    let pack = prng::Prng::new(21).bytes(100_000);
    let name = sha(&pack);
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let res = http
        .post(format!("http://127.0.0.1:{}/main/data/{name}", l.port))
        .basic_auth("gclone", Some(l.token.clone()))
        .body(pack)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let stray = on.live_packs().into_iter().find(|(_, p)| p.name == name);
    let stray = Handle(stray.expect("the pack").1.id);
    fake.backend().trash(&stray).await.unwrap();
    for round in 0..2 {
        let more = prng::Prng::new(22 + round).bytes(300_000);
        std::fs::write(src.join("more.bin"), more).unwrap();
        r.run(&d, &via, &["backup", "src"]).await.ok();
    }
    assert_eq!(r.snapshots(&d, &via).await.len(), 5);
    r2.run(&d, &elsewhere, &["check", "--read-data"]).await.ok();
    let out = lab.path("restored");
    let target = out.to_str().unwrap();
    r.run(&d, &via, &["restore", "latest", "--target", target])
        .await
        .ok();
    assert_same_tree(&src, &out.join("src"));
}

/// E16: `--port`. What `forget --prune` removed through the listener is restored from the
/// Drive trash by hand: it is back for the running listener as it is for every other machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_through_the_listener_after_a_restore_from_the_trash() {
    let lab = Lab::new();
    let test = "restic_through_the_listener_after_a_restore_from_the_trash";
    let Some(r) = restic(test, &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let l = Listening::start(&d, &[]);
    let via = Via::Rest(l.port, "main", Some(l.token.clone()));
    r.run(&d, &via, &["init"]).await.ok();
    let src = lab.tree("src", 23, &DATA);
    let first = lab.tree("first", 23, &DATA);
    r.run(&d, &via, &["backup", "src"]).await.ok();
    let oldest = r.snapshots(&d, &via).await.remove(0);
    std::fs::remove_file(src.join("big.bin")).unwrap();
    std::fs::write(src.join("notes.txt"), "the second version").unwrap();
    r.run(&d, &via, &["backup", "src"]).await.ok();
    r.run(&d, &via, &["forget", "--keep-last", "1", "--prune"])
        .await
        .ok();
    // The repository is looked at once more: the listings after the deletes are without
    // what was deleted. (Without one, a restored file is back half a minute after it was
    // deleted: until then a listing that shows it is taken for one that lags.)
    r.run(&d, &via, &["check"]).await.ok();
    assert_eq!(r.snapshots(&d, &via).await.len(), 1);

    // "Restore" in drive.google.com, for everything that prune and forget trashed.
    let on = OnDrive {
        fake: &fake,
        repo: "main",
    };
    let other = fake.backend();
    let mut trashed: Vec<String> = Vec::new();
    for ty in ["snapshots", "index"] {
        trashed.extend(on.files(ty).into_iter().filter(|c| c.trashed).map(|c| c.id));
    }
    let packs = on.packs().into_iter();
    trashed.extend(packs.filter(|(_, p)| p.trashed).map(|(_, p)| p.id));
    assert!(trashed.len() >= 3, "a snapshot, an index, a pack");
    for id in trashed {
        other.untrash(&Handle(id)).await.unwrap();
    }

    let (r2, elsewhere) = (second(&r, &lab), Via::Stdio("main"));
    assert_eq!(r2.snapshots(&d, &elsewhere).await.len(), 2);
    assert_eq!(r.snapshots(&d, &via).await.len(), 2, "through the listener");
    r.run(&d, &via, &["check", "--read-data"]).await.ok();
    let out = lab.path("restored");
    let target = out.to_str().unwrap();
    r.run(&d, &via, &["restore", &oldest, "--target", target])
        .await
        .ok();
    assert_same_tree(&first, &out.join("src"));
}

/// E17: machine A's index is on Drive, and its restic dies before the index was acknowledged.
/// Machine B has backed up the same files meanwhile and left out what that index describes.
/// The index stays — B's snapshot can be restored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restic_keeps_an_index_another_machine_has_seen() {
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    let lab = Lab::new();
    let test = "restic_keeps_an_index_another_machine_has_seen";
    let Some(r) = restic(test, &lab) else {
        return;
    };
    let fake = FakeDrive::start().await;
    let d = lab.signed_in(&fake, "a").await;
    let plain = Via::Stdio("main");
    r.run(&d, &plain, &["init"]).await.ok();
    let on = OnDrive {
        fake: &fake,
        repo: "main",
    };
    // Machine A's backend program says which process its gclone is.
    let (script, pid_file) = (lab.path("gclone-wrapper"), lab.path("gclone.pid"));
    let text = format!(
        "#!/bin/sh\necho $$ > '{}'\nexec gclone \"$@\"\n",
        pid_file.display()
    );
    std::fs::write(&script, text).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let machine_a = Via::Program(script.to_str().unwrap().to_string(), "main");
    let r2 = second(&r, &lab);
    let src = lab.tree("src", 24, &[("a.bin", 3 << 20), ("b.bin", 2 << 20)]);

    // Listings lag behind new objects by 300 listings; other traffic on the account makes
    // them catch up.
    let other = fake.backend();
    let busy = Arc::new(AtomicBool::new(true));
    let traffic = tokio::spawn({
        let busy = busy.clone();
        async move {
            while busy.load(Ordering::SeqCst) {
                let _ = other.list(&Handle::top()).await;
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    });
    fake.set_list_lag(300);
    let mut a = r
        .command(&d, &machine_a, &["backup", "src"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn restic");
    let said = collect(a.stderr.take().unwrap());
    let deadline = Instant::now() + Duration::from_secs(120);
    while on.live("index").is_empty() {
        assert!(
            Instant::now() < deadline,
            "no index: {}",
            said.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    // A's gclone stands still from here: its index is stored and not acknowledged.
    let gclone: u32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    signal(gclone, libc::SIGSTOP);
    fake.set_list_lag(0);
    let index = on.live("index").remove(0);
    tokio::time::sleep(Duration::from_secs(3)).await;
    busy.store(false, Ordering::SeqCst);
    traffic.await.unwrap();
    assert!(
        a.try_wait().unwrap().is_none(),
        "A's backup ended: {}",
        said.lock().unwrap()
    );

    // Machine B backs up the same files: everything is in A's index already.
    let saved = r2.run(&d, &plain, &["backup", "src"]).await.ok();
    assert!(
        saved.stdout.contains("Added to the repository: 0 B"),
        "{}",
        saved.stdout
    );

    // A's restic dies — power, `kill -9`, the OOM killer — and its gclone runs on to its end.
    signal(a.id(), libc::SIGKILL);
    let _ = a.wait();
    signal(gclone, libc::SIGCONT);
    let deadline = Instant::now() + Duration::from_secs(30);
    // SAFETY: signal 0 only asks whether the process exists.
    while unsafe { libc::kill(gclone as i32, 0) } == 0 {
        assert!(Instant::now() < deadline, "gclone outlived restic");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let all = on.files("index").into_iter();
    let now = all.filter(|c| c.id == index.id).collect::<Vec<_>>();
    assert!(!now[0].trashed, "A's index was taken back");

    r2.run(&d, &plain, &["unlock", "--remove-all"]).await.ok();
    r2.run(&d, &plain, &["check", "--read-data"]).await.ok();
    let out = lab.path("restored");
    let target = out.to_str().unwrap();
    r2.run(&d, &plain, &["restore", "latest", "--target", target])
        .await
        .ok();
    assert_same_tree(&src, &out.join("src"));
}

#[test]
fn restic_versions() {
    for (line, ok) in [
        (
            "restic 0.19.1 compiled with go1.26.10 on darwin/arm64",
            true,
        ),
        ("restic 0.17.0 compiled with go1.22 on linux/amd64", true),
        ("restic 1.0.0", true),
        ("restic 0.16.5 compiled with go1.21 on linux/amd64", false),
        ("restic 0.9", false),
        ("rustic 0.19.1", false),
        ("", false),
    ] {
        assert_eq!(new_enough(line), ok, "{line:?}");
    }
}

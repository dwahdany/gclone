//! The device key store through the `gclone` binary (SPEC §8.2, §8.3, §17.28, §17.30):
//! the sealed store as a Mac's default — a login that seals from the start, the move that
//! follows a passed trial, its crash points and its opt-outs —, `gclone keystore`, the two
//! moves of `keystore use` and their crash points, a sealed store that does not open, the
//! trial, and — where there is one — the real Secure Enclave.
//!
//! Every test spawns the built debug binary against a directory vault. The sealer is the
//! stand-in of `GCLONE_TEST_KEYSTORE_SEALER=fake` (§7.1); a "Mac" is the name in
//! `GCLONE_TEST_KEYSTORE_MACHINE`. Two kinds of device: [`Lab::device`] runs with
//! `GCLONE_KEYSTORE_TRIAL=0` — nothing happens there that the test did not ask for, which is
//! also how a device looks that gclone 0.5.0 left on the plain file — and [`Lab::mac`] runs
//! as an owner's Mac does, with the sealed store as the default. No test touches hardware,
//! except those whose names start with `hardware_`, and they store nothing outside their temp
//! directories.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_gclone");
const PASS: &str = "correct horse battery staple";

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    #[track_caller]
    fn code(self, expected: i32) -> Out {
        assert_eq!(
            self.code, expected,
            "exit code\n--- stdout\n{}\n--- stderr\n{}",
            self.stdout, self.stderr
        );
        self
    }

    #[track_caller]
    fn ok(self) -> Out {
        self.code(0)
    }

    #[track_caller]
    fn has(self, needle: &str) -> Out {
        assert!(
            self.stdout.contains(needle) || self.stderr.contains(needle),
            "output lacks {needle:?}\n--- stdout\n{}\n--- stderr\n{}",
            self.stdout,
            self.stderr
        );
        self
    }

    #[track_caller]
    fn lacks(self, needle: &str) -> Out {
        assert!(
            !self.stdout.contains(needle) && !self.stderr.contains(needle),
            "output has {needle:?}\n--- stdout\n{}\n--- stderr\n{}",
            self.stdout,
            self.stderr
        );
        self
    }
}

struct Lab {
    tmp: tempfile::TempDir,
}

#[derive(Clone)]
struct Device {
    config: PathBuf,
    state: PathBuf,
    home: PathBuf,
    vault: String,
    pass: String,
    env: Vec<(String, String)>,
}

fn s(p: &Path) -> String {
    p.to_str().expect("UTF-8 path").to_string()
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

    /// A Mac as its owner runs it (§17.30): no opt-out in the environment, so the sealed
    /// store is the default — in a terminal of the boot `boot-a`, at the test clock's start.
    fn mac(&self, name: &str) -> Device {
        at(
            &self.device(name).without("GCLONE_KEYSTORE_TRIAL"),
            0,
            "boot-a",
            "0x2030",
        )
    }

    /// [`Lab::mac`], connected to the vault, with one file in it.
    fn connected_mac(&self, name: &str) -> Device {
        let d = self.mac(name);
        d.login().ok();
        self.seed(&d, name);
        d
    }

    /// One file in the vault, through `d`.
    fn seed(&self, d: &Device, name: &str) {
        let tree = self.path(&format!("{name}-tree"));
        std::fs::create_dir_all(&tree).expect("tree");
        std::fs::write(tree.join("a.txt"), b"alpha\n").expect("file");
        d.run(&["copy", &s(&tree), ":docs"]).ok();
    }

    /// A device on the plain file — as gclone 0.5.0 left every Mac — whose trial needs one
    /// more run to pass: it opened its test value on two days, in a terminal and from a
    /// scheduler, in the boot `boot-a`. The next run on another day in another boot
    /// (`at(&d, 2, "boot-b", …)`) completes it. Returns the device as its owner runs it and
    /// the bytes of its `secrets.json`.
    fn nearly_passed(&self, name: &str) -> (Device, Vec<u8>) {
        let quiet = self.connected(name);
        let original = read(&quiet.plain());
        let d = quiet.without("GCLONE_KEYSTORE_TRIAL");
        at(&d, 0, "boot-a", "0x2030").works();
        at(&d, 1, "boot-a", "0x2").works();
        assert_eq!(read(&d.plain()), original, "nothing moves before the bar");
        assert!(!d.sealed().exists() && !d.note_owed());
        (d, original)
    }

    /// A device of the lab's one directory vault, not signed in yet. Its sealer is the
    /// stand-in, as machine `mac-1`; no trial, no sealing and no move unless a test asks for
    /// them (`GCLONE_KEYSTORE_TRIAL=0`).
    fn device(&self, name: &str) -> Device {
        let home = self.path("home");
        std::fs::create_dir_all(&home).expect("home");
        let pass = self.path("pass");
        std::fs::write(&pass, format!("{PASS}\n")).expect("passphrase file");
        Device {
            config: self.path(&format!("{name}-config")),
            state: self.path(&format!("{name}-state")),
            home,
            vault: s(&self.path("vault")),
            pass: s(&pass),
            env: vec![
                ("GCLONE_TEST_KEYSTORE_SEALER".into(), "fake".into()),
                ("GCLONE_TEST_KEYSTORE_MACHINE".into(), "mac-1".into()),
                ("GCLONE_KEYSTORE_TRIAL".into(), "0".into()),
                // … for these runs only: the marker that makes the variable hold for the
                // whole device (`keystore-trial.off`) is not left, so that a test can prepare
                // a device and look at it without deciding its fate. The tests of the
                // variable itself take this away ([`Device::owner_sets_trial_off`]).
                ("GCLONE_TEST_KEYSTORE_NO_MARKER".into(), "1".into()),
            ],
        }
    }

    /// A device that is connected to the vault, with one file in it.
    fn connected(&self, name: &str) -> Device {
        let d = self.device(name);
        d.login().ok();
        let tree = self.path(&format!("{name}-tree"));
        std::fs::create_dir_all(&tree).expect("tree");
        std::fs::write(tree.join("a.txt"), b"alpha\n").expect("file");
        d.run(&["copy", &s(&tree), ":docs"]).ok();
        d
    }
}

impl Device {
    fn with(&self, vars: &[(&str, &str)]) -> Device {
        let mut d = self.clone();
        for (name, value) in vars {
            d.env.retain(|(n, _)| n != name);
            d.env.push((name.to_string(), value.to_string()));
        }
        d
    }

    fn without(&self, name: &str) -> Device {
        let mut d = self.clone();
        d.env.retain(|(n, _)| n != name);
        d
    }

    /// This device as a run whose owner set `GCLONE_KEYSTORE_TRIAL=0` — a scheduler's job,
    /// say — with nothing of the test harness in between.
    fn owner_sets_trial_off(&self) -> Device {
        self.with(&[("GCLONE_KEYSTORE_TRIAL", "0")])
            .without("GCLONE_TEST_KEYSTORE_NO_MARKER")
    }

    /// A run with `GCLONE_KEYSTORE_TRIAL=0` left its marker (`keystore-trial.off`).
    fn trial_off_marked(&self) -> bool {
        self.state.join("keystore-trial.off").exists()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env("GCLONE_CONFIG_DIR", &self.config)
            .env("GCLONE_STATE_DIR", &self.state)
            .env("GCLONE_TEST_FAST_KDF", "1")
            .env("HOME", &self.home)
            .env("TZ", "UTC")
            .env_remove("GCLONE_AUTH_URL")
            .env_remove("GCLONE_LOG")
            .env_remove("GCLONE_KEYSTORE_TRIAL")
            .env_remove("GCLONE_TEST_KEYSTORE_SEALER")
            .env_remove("GCLONE_TEST_KEYSTORE_FAIL")
            .env_remove("GCLONE_TEST_KEYSTORE_STOP")
            .env_remove("GCLONE_TEST_KEYSTORE_NO_MARKER")
            .env_remove("GCLONE_TEST_KEYSTORE_WAIT_MS")
            .envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::null());
        cmd
    }

    #[track_caller]
    fn run(&self, args: &[&str]) -> Out {
        let out = self.command(args).output().expect("spawn gclone");
        let out = Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        };
        assert!(
            !out.stderr.contains("panicked") && out.code != 101,
            "the binary panicked:\n{}",
            out.stderr
        );
        out
    }

    fn login(&self) -> Out {
        self.run(&[
            "login",
            "--vault-dir",
            &self.vault,
            "--passphrase-file",
            &self.pass,
        ])
    }

    fn use_enclave(&self) -> Out {
        self.run(&[
            "keystore",
            "use",
            "enclave",
            "--yes",
            "--passphrase-file",
            &self.pass,
        ])
    }

    fn plain(&self) -> PathBuf {
        self.state.join("secrets.json")
    }

    fn sealed(&self) -> PathBuf {
        self.state.join("secrets.sealed")
    }

    /// The note about an automatic move is owed (`keystore-note.due`).
    fn note_owed(&self) -> bool {
        self.state.join("keystore-note.due").exists()
    }

    fn choice(&self) -> Option<String> {
        let bytes = std::fs::read(self.state.join("keystore.json")).ok()?;
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("keystore.json");
        Some(json["store"].as_str().expect("store").to_string())
    }

    /// The names in the state root, without the vault's own state directory.
    fn files(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.state)
            .expect("state root")
            .map(|e| e.expect("entry"))
            .filter(|e| !e.file_type().expect("type").is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The device works: the vault's listing is there.
    #[track_caller]
    fn works(&self) {
        self.run(&["ls", ":docs"]).ok().has("a.txt");
    }

    /// `gclone logout`, and then: no secrets file, no sealed file, no temp copy of anything.
    #[track_caller]
    fn logout_leaves_nothing(&self) {
        self.run(&["logout"]).ok().has("Signed out on this device.");
        let left = self.files();
        for name in &left {
            assert!(
                !name.starts_with("secrets.json")
                    && !name.starts_with("secrets.sealed")
                    && !name.contains(".tmp-")
                    && name != "token.json",
                "left behind after logout: {left:?}"
            );
        }
        self.run(&["ls"]).code(4);
        self.run(&["logout"]).ok().has("nothing to do");
    }
}

const DAY: u64 = 86_400_000;
/// The test clock's day 0.
const START: u64 = 1_794_400_000_000;
const MOVE_NOTE: &str = "note: this device's login and vault key are now kept in secrets.sealed";

/// `d` on day `day` of the test clock, in the boot `boot` and the session `session`
/// (`0x2030`: a terminal; `0x2`: a scheduler, without graphic access).
fn at(d: &Device, day: u64, boot: &str, session: &str) -> Device {
    d.with(&[
        ("GCLONE_TEST_NOW_MS", &(START + day * DAY).to_string()),
        ("GCLONE_TEST_BOOT", boot),
        ("GCLONE_TEST_SESSION", session),
    ])
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o7777
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// ---------------------------------------------------------------------------------------------
// The sealed store is a Mac's default (§17.30)
// ---------------------------------------------------------------------------------------------

/// A first login on a Mac: the secrets are sealed from the start — no `secrets.json` at any
/// point, no command, no question, no choice on file — and the device simply works.
#[test]
fn a_fresh_login_on_a_mac_is_sealed_from_the_start() {
    let lab = Lab::new();
    let d = lab.mac("a");
    d.login()
        .ok()
        .has("Vault created.")
        .has("This device's login and key are sealed by this Mac's Secure Enclave (secrets.sealed)")
        .has("`gclone login` and the passphrase connect it again")
        .has("`gclone keystore use file` keeps a plain file instead");
    assert_eq!(
        d.files(),
        ["CACHEDIR.TAG", "secrets.lock", "secrets.sealed"],
        "what a login leaves in the state root of a Mac"
    );
    assert_eq!(mode(&d.sealed()), 0o600);
    let sealed = String::from_utf8(read(&d.sealed())).unwrap();
    let envelope: serde_json::Value = serde_json::from_str(&sealed).unwrap();
    assert_eq!(envelope["store"], "enclave");
    assert!(envelope["vault_id"].is_string(), "it holds the keys");
    lab.seed(&d, "a");
    d.works();
    d.run(&["status"])
        .ok()
        .has("Key store    Secure Enclave of this Mac (secrets.sealed)")
        .lacks("warning:");
    d.run(&["keystore"])
        .ok()
        .has("Key store    Secure Enclave of this Mac (secrets.sealed)")
        .has("Choice       none made: the sealed store wherever this Mac's Secure Enclave can be used")
        .lacks("warning:");
    let json: serde_json::Value =
        serde_json::from_str(&d.run(&["keystore", "--json"]).ok().stdout).unwrap();
    assert_eq!(json["key_store"]["store"], "enclave");
    assert_eq!(json["key_store"]["choice"], serde_json::Value::Null);
    assert_eq!(json["key_store"]["path"], s(&d.sealed()));
    d.run(&["keystore", "check"])
        .ok()
        .has("secrets.sealed opens in this session");
    // A login on a connected device changes nothing and says nothing about it again.
    d.login()
        .ok()
        .lacks("are sealed by this Mac's Secure Enclave");
    assert!(d.sealed().exists() && !d.plain().exists());
    // Days and restarts later: no trial for a device that is sealed, and nothing owed.
    at(&d, 3, "boot-b", "0x2").works();
    assert!(!d.state.join("keystore-trial.json").exists());
    assert!(!d.note_owed());
    // A second device of the same vault, on another Mac: sealed there, by that Mac.
    let other = Device {
        config: lab.path("b-config"),
        state: lab.path("b-state"),
        ..d.with(&[("GCLONE_TEST_KEYSTORE_MACHINE", "mac-2")])
    };
    other
        .login()
        .ok()
        .has("sealed by this Mac's Secure Enclave");
    assert!(other.sealed().exists() && !other.plain().exists());
    other.works();
    // The way back, and out: a logout of a sealed device leaves no secret, and the next
    // login is sealed again.
    d.logout_leaves_nothing();
    assert_eq!(d.choice(), None);
    d.login().ok().has("sealed by this Mac's Secure Enclave");
    assert!(d.sealed().exists() && !d.plain().exists());
    d.works();
    let before = read(&d.sealed());
    d.run(&["keystore", "use", "file"]).ok();
    assert!(d.plain().exists() && !d.sealed().exists());
    let plain: serde_json::Value = serde_json::from_slice(&read(&d.plain())).unwrap();
    assert_eq!(plain["version"], 1, "the version-1 file gclone 0.4.0 reads");
    assert!(plain["keys"][0]["key"].is_string());
    assert!(
        !String::from_utf8(before)
            .unwrap()
            .contains(plain["keys"][0]["key"].as_str().unwrap()),
        "the vault key was not in the sealed file"
    );
    d.works();
    d.logout_leaves_nothing();
}

/// The saves of a login that seals, killed before and after the rename: no plain copy is
/// left by either, the same command again completes, and a logout leaves nothing.
#[test]
fn every_crash_point_of_a_login_that_seals_from_the_start() {
    for point in ["save-locked", "save-sealed-temp", "save-sealed-done"] {
        let lab = Lab::new();
        let d = lab.mac("a");
        killed_at(
            &d,
            point,
            &[
                "login",
                "--vault-dir",
                &d.vault,
                "--passphrase-file",
                &d.pass,
            ],
        );
        assert!(!d.plain().exists(), "{point}: {:?}", d.files());
        assert!(
            d.files()
                .iter()
                .all(|name| !name.starts_with(".secrets.json.tmp-")),
            "{point}: no plain copy under a temp name: {:?}",
            d.files()
        );
        assert_eq!(d.sealed().exists(), point == "save-sealed-done", "{point}");
        if point == "save-sealed-done" {
            d.run(&["ls"]).ok();
        } else {
            d.run(&["ls"]).code(4);
        }
        d.login().ok();
        assert!(d.sealed().exists() && !d.plain().exists(), "{point}");
        assert!(
            d.files().iter().all(|name| !name.contains(".tmp-")),
            "{point}: {:?}",
            d.files()
        );
        d.run(&["ls"]).ok();
        d.logout_leaves_nothing();
    }
}

/// Where the Secure Enclave cannot be used — no enclave, a virtual machine, a session
/// without access, a build without a sealer — a login goes to the plain file without a
/// word, and one line of `gclone status` and `gclone keystore` says why.
#[test]
fn a_login_without_a_usable_secure_enclave_keeps_the_plain_file_and_status_says_why() {
    let lab = Lab::new();
    // A desktop session that cannot make a key: the machine has no usable Secure Enclave.
    let d = lab
        .mac("a")
        .with(&[("GCLONE_TEST_KEYSTORE_FAIL", "create")]);
    let out = d.login().ok().has("Vault created.");
    out.lacks("Secure Enclave")
        .lacks("warning:")
        .lacks("sealed");
    assert_eq!(
        d.files(),
        [
            "CACHEDIR.TAG",
            "keystore-trial.json",
            "keystore-trial.lock",
            "secrets.json",
            "secrets.lock"
        ]
    );
    assert_eq!(mode(&d.plain()), 0o600);
    lab.seed(&d, "a");
    d.works();
    for command in [&["status"][..], &["keystore"]] {
        d.run(command)
            .ok()
            .has("Key store    plain file secrets.json (0600) — no Secure Enclave on this machine");
    }
    d.run(&["keystore"])
        .ok()
        .has("no Secure Enclave key could be made in session 0x2030 (with graphic access)")
        .has("fake sealer: no key can be made on this machine");
    assert_eq!(d.choice(), None);

    // The same from a scheduler's session: that session, not the machine.
    let lab = Lab::new();
    let cron =
        at(&lab.mac("b"), 0, "boot-a", "0x2").with(&[("GCLONE_TEST_KEYSTORE_FAIL", "create")]);
    cron.login().ok().lacks("Secure Enclave");
    assert!(cron.plain().exists() && !cron.sealed().exists());
    cron.run(&["keystore"]).ok().has(
        "Key store    plain file secrets.json (0600) — no Secure Enclave key could be made in \
         session 0x2 (without graphic access) on 2026-11-",
    );

    // A key can be made and nothing opens with it.
    let lab = Lab::new();
    let d = lab.mac("c").with(&[("GCLONE_TEST_KEYSTORE_FAIL", "open")]);
    d.login().ok().lacks("Secure Enclave");
    assert!(d.plain().exists() && !d.sealed().exists());
    d.run(&["keystore"])
        .ok()
        .has("Key store    plain file secrets.json (0600) — no Secure Enclave")
        .has("fake sealer: this session cannot use the key store");

    // A build without a sealer (a debug build without the test switch; Linux is the same
    // with another reason): the plain file, and `gclone keystore` names the reason.
    let lab = Lab::new();
    let d = lab.mac("d").without("GCLONE_TEST_KEYSTORE_SEALER");
    d.login().ok().lacks("Secure Enclave");
    assert_eq!(
        d.files(),
        ["CACHEDIR.TAG", "secrets.json", "secrets.lock"],
        "nothing but the plain file"
    );
    let status = d.run(&["status"]).ok();
    assert!(
        status
            .stdout
            .lines()
            .any(|l| l == "Key store    plain file secrets.json (0600)"),
        "{}",
        status.stdout
    );
    d.run(&["keystore"])
        .ok()
        .has("Sealed store not available: this is a debug build of gclone");
}

/// Killed at any point of the move that nobody asked for: the device keeps working with the
/// same secrets at every point, the next run finishes the move by itself, the note is told
/// once, and the way back gives the bytes there were.
#[test]
fn every_crash_point_of_the_automatic_move() {
    for (point, plain_after, sealed_after, owed_after) in [
        ("enclave-sealed-temp", true, false, false),
        ("enclave-sealed-done", true, true, false),
        ("enclave-note-owed", true, true, true),
        ("enclave-plain-removed", false, true, true),
    ] {
        let lab = Lab::new();
        let (d, original) = lab.nearly_passed("a");
        let completes = at(&d, 2, "boot-b", "0x2");
        killed_at(&completes, point, &["ls", ":docs"]);
        assert_eq!(d.plain().exists(), plain_after, "{point}");
        assert_eq!(d.sealed().exists(), sealed_after, "{point}");
        assert_eq!(d.note_owed(), owed_after, "{point}");
        assert_eq!(d.choice(), None, "{point}");
        if plain_after {
            assert_eq!(
                read(&d.plain()),
                original,
                "{point}: secrets.json is untouched"
            );
        }
        // A reader that takes no step of its own (the trial switched off in its environment)
        // finds the same secrets, whichever file they are in — and finishes nothing.
        let reader = d.with(&[("GCLONE_KEYSTORE_TRIAL", "0")]);
        reader.works();
        assert_eq!(d.plain().exists(), plain_after, "{point}");
        if plain_after && sealed_after {
            reader
                .run(&["status"])
                .ok()
                .has("secrets.json and secrets.sealed both exist (an interrupted move")
                .has("a move that gclone began by itself is finished by the next run");
            // The note says "the plain secrets.json is gone": it is not shown, and stays
            // owed, while that file is still what the device works from.
            reader
                .with(&[("GCLONE_TEST_NOTES", "1")])
                .run(&["ls", ":docs"])
                .ok()
                .lacks(MOVE_NOTE);
            assert_eq!(
                d.note_owed(),
                owed_after,
                "{point}: the note is not used up"
            );
        }
        if !plain_after {
            // The move was complete but for the trial's record: the report reads the two
            // files, and nothing claims another key.
            reader
                .run(&["keystore"])
                .ok()
                .has("Key store    Secure Enclave of this Mac (secrets.sealed)")
                .has("Trial        ended: its key holds the secrets")
                .lacks("warning:");
        }
        // The next run of the owner's finishes it.
        completes.works();
        assert!(
            d.sealed().exists() && !d.plain().exists(),
            "{point}: {:?}",
            d.files()
        );
        assert!(d.note_owed(), "{point}");
        assert_eq!(d.choice(), None, "{point}");
        assert!(
            d.files().iter().all(|name| !name.contains(".tmp-")),
            "{point}: {:?}",
            d.files()
        );
        // The trial's record is ended — also where the move was cut off after the plain
        // file had gone and the run that "finishes" finds nothing left to move.
        let record = trial(&d);
        assert!(record["moved_ms"].is_u64(), "{point}: {record}");
        assert!(
            record.get("key").is_none() && record.get("canary").is_none(),
            "{point}: {record}"
        );
        completes.works();
        // Told once, to a person.
        let person = at(&d, 2, "boot-b", "0x2030").with(&[("GCLONE_TEST_NOTES", "1")]);
        person.run(&["ls", ":docs"]).ok().has(MOVE_NOTE);
        person.run(&["ls", ":docs"]).ok().lacks("note:");
        person
            .run(&["status"])
            .ok()
            .has("Key store    Secure Enclave of this Mac (secrets.sealed)")
            .lacks("warning:");
        // … and back gives the bytes there were.
        person.run(&["keystore", "use", "file"]).ok();
        assert_eq!(read(&d.plain()), original, "{point}");
        person.logout_leaves_nothing();
    }
}

/// Many gclone processes start in the minute the trial passes — a scheduled sync, `serve
/// restic`, a status line: every one of them answers, exactly one moves the secrets, readers
/// beside them never find the device signed out, and one note is owed.
#[test]
fn processes_racing_to_move_and_readers_beside_them() {
    for round in 0..4 {
        let lab = Lab::new();
        let (d, original) = lab.nearly_passed("a");
        let completes = at(&d, 2, "boot-b", "0x2");
        let stop = std::sync::atomic::AtomicBool::new(false);
        let reads = std::sync::atomic::AtomicU64::new(0);
        std::thread::scope(|scope| {
            // Readers that take no step themselves: what any other program of the owner's
            // sees while the move happens.
            let reader = d.with(&[("GCLONE_KEYSTORE_TRIAL", "0")]);
            for n in 0..4 {
                let (reader, stop, reads) = (reader.clone(), &stop, &reads);
                scope.spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        if n % 2 == 0 {
                            let out = reader.run(&["ls", ":docs"]);
                            assert_eq!(out.code, 0, "ls failed during the move:\n{}", out.stderr);
                            assert!(out.stdout.contains("a.txt"), "{}", out.stdout);
                        } else {
                            let out = reader.run(&["keystore", "--json"]);
                            assert_eq!(out.code, 0, "{}", out.stderr);
                            let json: serde_json::Value =
                                serde_json::from_str(&out.stdout).expect("JSON");
                            let store = json["key_store"]["store"].as_str().unwrap().to_string();
                            assert!(store == "file" || store == "enclave", "{}", out.stdout);
                            assert_eq!(json["key_store"]["usable"], true, "{}", out.stdout);
                        }
                        reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                });
            }
            // Eight runs at once, each of which finds the trial passed.
            let running: Vec<_> = (0..8)
                .map(|_| {
                    completes
                        .command(&["ls", ":docs"])
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .expect("spawn gclone")
                })
                .collect();
            for child in running {
                let out = child.wait_with_output().expect("wait");
                let stderr = String::from_utf8_lossy(&out.stderr);
                assert!(out.status.success(), "round {round}: {stderr}");
                assert!(
                    String::from_utf8_lossy(&out.stdout).contains("a.txt"),
                    "round {round}"
                );
                assert!(!stderr.contains("panicked"), "{stderr}");
            }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        assert!(reads.load(std::sync::atomic::Ordering::Relaxed) >= 4);
        assert!(
            d.sealed().exists() && !d.plain().exists(),
            "round {round}: {:?}",
            d.files()
        );
        assert!(d.note_owed(), "round {round}");
        assert_eq!(d.choice(), None);
        assert!(
            d.files().iter().all(|name| !name.contains(".tmp-")),
            "round {round}: {:?}",
            d.files()
        );
        // One move: the sealed file holds the trial's key and the bytes there were.
        let sealed: serde_json::Value = serde_json::from_slice(&read(&d.sealed())).unwrap();
        let record = trial(&d);
        assert_eq!(record["public"], sealed["public"], "round {round}");
        assert!(record["moved_ms"].is_u64() && record.get("key").is_none());
        completes.works();
        completes.run(&["keystore", "use", "file"]).ok();
        assert_eq!(read(&d.plain()), original, "round {round}");
    }
}

// ---------------------------------------------------------------------------------------------
// The move and the way back
// ---------------------------------------------------------------------------------------------

#[test]
fn the_move_to_the_sealed_store_and_back() {
    let lab = Lab::new();
    let d = lab.connected("a");
    let original = read(&d.plain());
    assert_eq!(
        d.files(),
        ["CACHEDIR.TAG", "secrets.json", "secrets.lock"],
        "what a login leaves in the state root"
    );
    let tag = String::from_utf8(read(&d.state.join("CACHEDIR.TAG"))).unwrap();
    assert!(
        tag.starts_with("Signature: 8a477f597d28d172789f06886806bc55\n"),
        "{tag}"
    );
    d.run(&["status"])
        .ok()
        .has("Key store    plain file secrets.json (0600)");

    let out = d.use_enclave().ok();
    let out = out
        .has("The passphrase opens the vault's keyfile.")
        .has("the passphrase you just entered is the only way back")
        .has("Older gclone binaries on this Mac")
        .has("Run `gclone keystore check` from your scheduler")
        .has("are now sealed by the");
    out.has("secrets.json was removed. `gclone keystore use file` moves everything back.");
    assert_eq!(
        d.files(),
        [
            "CACHEDIR.TAG",
            "keystore.json",
            "secrets.lock",
            "secrets.sealed"
        ]
    );
    assert_eq!(mode(&d.sealed()), 0o600);
    assert_eq!(mode(&d.state.join("keystore.json")), 0o600);
    assert_eq!(d.choice().as_deref(), Some("enclave"));
    let sealed = String::from_utf8(read(&d.sealed())).unwrap();
    let key_in_plain =
        serde_json::from_slice::<serde_json::Value>(&original).unwrap()["keys"][0]["key"]
            .as_str()
            .unwrap()
            .to_string();
    assert!(
        !sealed.contains(&key_in_plain),
        "the vault key is not in the sealed file"
    );

    // Everything works as before, from the sealed store.
    d.works();
    d.run(&["status"])
        .ok()
        .has("Key store    Secure Enclave of this Mac (secrets.sealed)");
    let tree = lab.path("more");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("b.txt"), b"bravo\n").unwrap();
    d.run(&["copy", &s(&tree), ":docs"]).ok();
    assert_eq!(d.run(&["cat", ":docs/b.txt"]).ok().stdout, "bravo\n");
    d.run(&["keystore"])
        .ok()
        .has("Key store    Secure Enclave of this Mac (secrets.sealed)")
        .has("Choice       the Secure Enclave");
    let json: serde_json::Value =
        serde_json::from_str(&d.run(&["keystore", "--json"]).ok().stdout).expect("one JSON object");
    assert_eq!(json["key_store"]["store"], "enclave");
    assert_eq!(json["key_store"]["choice"], "enclave");
    assert_eq!(json["key_store"]["both_present"], false);
    assert_eq!(json["key_store"]["path"], s(&d.sealed()));
    d.run(&["keystore", "check"])
        .ok()
        .has("secrets.sealed opens in this session")
        .has("The Secure Enclave is usable in this session.");
    // Again: it is there already.
    d.use_enclave().ok().has("already sealed");
    // A login on a connected directory-vault device changes nothing.
    d.login().ok();
    assert!(!d.plain().exists());

    // On another Mac the file is worth nothing — and nothing is changed by trying.
    let elsewhere = d.with(&[("GCLONE_TEST_KEYSTORE_MACHINE", "mac-2")]);
    let before = read(&d.sealed());
    elsewhere
        .run(&["ls"])
        .code(4)
        .has("sealed for another Mac")
        .has("Run `gclone login`; it asks for the passphrase");
    assert_eq!(read(&d.sealed()), before);

    // Back: byte for byte the version-1 file that gclone 0.4.0 reads.
    d.run(&["keystore", "use", "file"])
        .ok()
        .has("are back in the plain file")
        .has("secrets.sealed was removed");
    assert_eq!(read(&d.plain()), original);
    assert_eq!(mode(&d.plain()), 0o600);
    assert_eq!(
        d.files(),
        [
            "CACHEDIR.TAG",
            "keystore.json",
            "secrets.json",
            "secrets.lock"
        ]
    );
    assert_eq!(d.choice().as_deref(), Some("file"));
    d.works();
    d.run(&["status"])
        .ok()
        .has("Key store    plain file secrets.json (0600) — kept by choice");
    d.run(&["keystore", "use", "file"])
        .ok()
        .has("already; nothing was moved");

    // And there again, then out: a logout of a sealed device leaves no secret.
    d.use_enclave().ok();
    d.logout_leaves_nothing();
    assert_eq!(
        d.choice().as_deref(),
        Some("enclave"),
        "the choice is no secret: it stays"
    );
    // The next login of a device that chose the sealed store seals at once.
    d.login().ok();
    assert!(d.sealed().exists() && !d.plain().exists());
    d.works();
    d.logout_leaves_nothing();
}

#[test]
fn the_move_is_refused_where_it_cannot_be_safe() {
    let lab = Lab::new();
    let d = lab.connected("a");
    let original = read(&d.plain());
    let unchanged = |d: &Device| {
        assert_eq!(read(&d.plain()), original);
        assert!(!d.sealed().exists());
        assert_eq!(d.choice(), None);
    };

    // No terminal and no --yes: a usage error before anything happens.
    d.run(&["keystore", "use", "enclave", "--passphrase-file", &d.pass])
        .code(2)
        .has("asks for a confirmation");
    unchanged(&d);

    // The wrong passphrase: nothing is written, and the text names the remedy.
    let wrong = lab.path("wrong");
    std::fs::write(&wrong, "not the passphrase at all\n").unwrap();
    d.run(&[
        "keystore",
        "use",
        "enclave",
        "--yes",
        "--passphrase-file",
        &s(&wrong),
    ])
    .code(4)
    .has("Wrong passphrase.")
    .has("Nothing was changed.")
    .has("`gclone passwd` on this device sets a new one now");
    unchanged(&d);

    // No passphrase given and no terminal to ask on.
    d.run(&["keystore", "use", "enclave", "--yes"])
        .code(2)
        .has("--passphrase-file");
    unchanged(&d);

    // A build or a machine without a sealer (a debug build without the test switch).
    d.without("GCLONE_TEST_KEYSTORE_SEALER")
        .use_enclave()
        .code(1)
        .has("Not possible here")
        .has("debug build");
    unchanged(&d);
    // No Secure Enclave key can be made in this session.
    d.with(&[("GCLONE_TEST_KEYSTORE_FAIL", "create")])
        .use_enclave()
        .code(1)
        .has("can be made and used in this session")
        .has("Nothing was changed");
    unchanged(&d);
    // It can be made but nothing opens (a session without access).
    d.with(&[("GCLONE_TEST_KEYSTORE_FAIL", "open")])
        .use_enclave()
        .code(1)
        .has("Nothing was changed");
    unchanged(&d);

    // Options of the other direction.
    d.run(&["keystore", "use", "enclave", "--yes", "--discard-sealed"])
        .code(2);
    d.run(&["keystore", "use", "file", "--passphrase-file", &d.pass])
        .code(2);
    unchanged(&d);

    // No keyfile on the store: the passphrase could not bring the device back.
    let mut removed = 0;
    for entry in walk(Path::new(&d.vault)) {
        let name = entry.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("gclone-key-") {
            std::fs::remove_file(&entry).unwrap();
            removed += 1;
        }
    }
    assert!(removed >= 1, "the vault directory holds a keyfile");
    d.use_enclave()
        .code(1)
        .has("There is no keyfile on the store")
        .has("Run `gclone passwd` first");
    unchanged(&d);
    // … and `gclone passwd` is the remedy: with a keyfile again, the move works. The check
    // can also be skipped, with a warning.
    let new_pass = lab.path("new-pass");
    std::fs::write(&new_pass, "a brand new passphrase, longer\n").unwrap();
    d.run(&["passwd", "--passphrase-file", &s(&new_pass)]).ok();
    d.use_enclave().code(4).has("Wrong passphrase.");
    unchanged(&d);
    d.run(&[
        "keystore",
        "use",
        "enclave",
        "--yes",
        "--skip-passphrase-check",
    ])
    .ok()
    .has("was NOT checked");
    assert!(d.sealed().exists() && !d.plain().exists());
    d.works();

    // A device that is not connected, and one that is signed out.
    let fresh = lab.device("fresh");
    fresh.use_enclave().code(4).has("not connected");
    d.logout_leaves_nothing();
    d.use_enclave().code(4).has("signed out");
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("entry");
        if entry.file_type().expect("type").is_dir() {
            out.extend(walk(&entry.path()));
        } else {
            out.push(entry.path());
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// A sealed store that does not open (F1 of the review)
// ---------------------------------------------------------------------------------------------

#[test]
fn login_puts_the_key_back_when_the_sealed_store_is_dead_and_never_before() {
    let lab = Lab::new();
    let d = lab.connected("a");
    d.use_enclave().ok();
    let sealed = read(&d.sealed());
    // The same files on another Mac: a restore onto new hardware, an enclave that was reset.
    let dead = d.with(&[("GCLONE_TEST_KEYSTORE_MACHINE", "mac-2")]);
    for command in [
        &["ls"][..],
        &["status"],
        &["copy", &d.home.to_string_lossy(), ":x"],
    ] {
        dead.run(command)
            .code(4)
            .has("This Mac's Secure Enclave cannot open this device's sealed key (secrets.sealed)")
            .has("the stored key cannot be used any more")
            .has("Run `gclone login`; it asks for the passphrase")
            .has("connects this device again")
            .has("The sealed file is kept until that login has the key again.");
    }
    dead.run(&["keystore"])
        .ok()
        .has("Key store    secrets.sealed — cannot be opened here")
        .has("sealed for another Mac");
    dead.run(&["keystore", "check"])
        .code(1)
        .has("secrets.sealed does NOT open");
    dead.run(&["keystore", "use", "file"])
        .code(1)
        .has("Nothing can be moved");
    assert_eq!(read(&d.sealed()), sealed);

    // A login with the wrong passphrase, and one whose passphrase prompt is abandoned (no
    // terminal, no file): the sealed file is byte for byte what it was.
    let wrong = lab.path("wrong");
    std::fs::write(&wrong, "not the passphrase at all\n").unwrap();
    dead.run(&[
        "login",
        "--vault-dir",
        &d.vault,
        "--passphrase-file",
        &s(&wrong),
    ])
    .code(4)
    .has("the stored key cannot be used any more")
    .has("Wrong passphrase.");
    assert_eq!(read(&d.sealed()), sealed);
    assert!(!d.plain().exists());
    dead.run(&["login", "--vault-dir", &d.vault]).code(2);
    assert_eq!(read(&d.sealed()), sealed);
    assert!(!d.plain().exists());

    // The login with the passphrase completes and leaves exactly one store: the choice was
    // `enclave`, so the key is sealed again — to a key of THIS Mac (§17.30; it used to end in
    // the plain file with a warning and wait for `keystore use enclave`).
    dead.login()
        .ok()
        .has("Connected to vault")
        .has("sealed by this Mac's Secure Enclave (secrets.sealed)")
        .lacks("was saved to the plain file");
    assert!(d.sealed().exists() && !d.plain().exists());
    let now: serde_json::Value = serde_json::from_slice(&read(&d.sealed())).unwrap();
    let then: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
    assert_ne!(
        now["public"], then["public"],
        "a key of the Mac it is on now"
    );
    dead.works();
    dead.use_enclave().ok().has("already sealed");
    // Where that Mac's Secure Enclave cannot be used either, the login ends in the plain
    // file and says so: the owner chose the sealed store.
    d.run(&["ls"]).code(4);
    let nowhere = d.with(&[
        ("GCLONE_TEST_KEYSTORE_MACHINE", "mac-3"),
        ("GCLONE_TEST_KEYSTORE_FAIL", "create"),
    ]);
    nowhere
        .login()
        .ok()
        .has("was saved to the plain file secrets.json although the sealed key store was chosen");
    assert!(d.plain().exists() && !d.sealed().exists());
    nowhere.works();
    nowhere.logout_leaves_nothing();
}

/// The sealed store is the default, so a sealed file that stops opening must never be a dead
/// end (§17.30): the files came to another Mac by a migration or from a backup, or the
/// Secure Enclave was reset. Every command says plainly that this Mac cannot open the sealed
/// key and that `gclone login` reconnects the device — exit 4, as for a device that is not
/// connected — and that login, with the passphrase, seals again on the Mac it runs on.
#[test]
fn an_unopenable_sealed_store_says_so_and_a_login_reconnects_the_device() {
    let lab = Lab::new();
    let d = lab.connected_mac("a");
    assert!(d.sealed().exists() && !d.plain().exists());
    assert_eq!(d.choice(), None, "nobody chose anything");
    let sealed = read(&d.sealed());

    let moved = d.with(&[("GCLONE_TEST_KEYSTORE_MACHINE", "mac-2")]);
    let home = s(&d.home);
    for command in [&["ls"][..], &["status"], &["copy", &home, ":x"]] {
        moved
            .run(command)
            .code(4)
            .has("This Mac's Secure Enclave cannot open this device's sealed key (secrets.sealed)")
            .has("a migration or from a backup")
            .has("Run `gclone login`; it asks for the passphrase")
            .has("for a vault on Google Drive it signs in to Google first")
            .has("connects this device again");
    }
    moved
        .run(&["keystore"])
        .ok()
        .has("Key store    secrets.sealed — cannot be opened here")
        .has("Run `gclone login`");
    assert_eq!(read(&d.sealed()), sealed, "nothing was changed by asking");
    // Not the passphrase: nothing changes, and the device can still be reconnected.
    let wrong = lab.path("wrong");
    std::fs::write(&wrong, "not the passphrase at all\n").unwrap();
    moved
        .run(&[
            "login",
            "--vault-dir",
            &d.vault,
            "--passphrase-file",
            &s(&wrong),
        ])
        .code(4)
        .has("Wrong passphrase.");
    assert_eq!(read(&d.sealed()), sealed);
    assert!(!d.plain().exists());
    // The passphrase: connected again, sealed again — by this Mac — and no plain file left.
    moved
        .login()
        .ok()
        .has("Connected to vault")
        .has("sealed by this Mac's Secure Enclave (secrets.sealed)");
    assert!(
        d.sealed().exists() && !d.plain().exists(),
        "{:?}",
        d.files()
    );
    assert_ne!(read(&d.sealed()), sealed);
    assert_eq!(d.choice(), None);
    assert!(d.files().iter().all(|name| !name.contains(".tmp-")));
    moved.works();
    moved
        .run(&["status"])
        .ok()
        .has("Key store    Secure Enclave of this Mac (secrets.sealed)")
        .lacks("warning: the secrets are sealed to a key");
    // … and the first Mac, should the files ever get back there, is told the same.
    d.run(&["ls"]).code(4).has("Run `gclone login`");

    // A session of the same Mac that cannot use the Secure Enclave is told something else:
    // not to sign in again, and how to make that session work.
    moved
        .with(&[("GCLONE_TEST_KEYSTORE_FAIL", "open")])
        .run(&["ls"])
        .code(4)
        .has("The Secure Enclave cannot be used in this session")
        .has("Do not sign in again")
        .has("`gclone keystore use file` — from a session where it works")
        .lacks("gclone login");
    moved.logout_leaves_nothing();
}

/// The Secure Enclave cannot be used in THIS session: nothing may send the user to `gclone
/// login`, which would throw away a key that is intact.
#[test]
fn a_session_without_the_enclave_is_never_told_to_sign_in_again() {
    let lab = Lab::new();
    let d = lab.connected("a");
    d.use_enclave().ok();
    let sealed = read(&d.sealed());
    let session = d.with(&[("GCLONE_TEST_KEYSTORE_FAIL", "open")]);
    for command in [&["ls"][..], &["status"], &["about"]] {
        session
            .run(command)
            .code(4)
            .has("The Secure Enclave cannot be used in this session")
            .has("`gclone keystore check` shows what this session can do")
            .has("Do not sign in again: the stored key is probably intact.")
            .lacks("gclone login");
    }
    session
        .run(&["keystore", "check"])
        .code(1)
        .has("FAILED")
        .has("NOT fully usable in this session");
    assert_eq!(read(&d.sealed()), sealed);
    // In a session that works, nothing was lost.
    d.works();
}

// ---------------------------------------------------------------------------------------------
// Crash points
// ---------------------------------------------------------------------------------------------

/// Runs `args` with a stop point and expects the process to end there.
#[track_caller]
fn killed_at(d: &Device, point: &str, args: &[&str]) {
    let out = d.with(&[("GCLONE_TEST_KEYSTORE_STOP", point)]).run(args);
    assert_eq!(
        out.code, 137,
        "{point}: the stop point was not reached\n--- stdout\n{}\n--- stderr\n{}",
        out.stdout, out.stderr
    );
}

/// Killed at any point of `keystore use enclave`: the device keeps working with the same
/// secrets, nothing finishes the move behind the user's back, the same command run again
/// completes, and a logout then leaves nothing.
#[test]
fn every_crash_point_of_the_move_to_the_enclave() {
    let lab = Lab::new();
    for (n, (point, both_after)) in [
        ("enclave-sealed-temp", false),
        ("enclave-sealed-done", true),
        ("enclave-choice-temp", true),
        ("enclave-choice-done", true),
        ("enclave-plain-removed", false),
    ]
    .into_iter()
    .enumerate()
    {
        let lab_dir = format!("e{n}");
        let d = Device {
            vault: s(&lab.path(&format!("{lab_dir}-vault"))),
            ..lab.device(&lab_dir)
        };
        d.login().ok();
        let tree = lab.path(&format!("{lab_dir}-tree"));
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("a.txt"), b"alpha\n").unwrap();
        d.run(&["copy", &s(&tree), ":docs"]).ok();
        let original = read(&d.plain());

        let args = [
            "keystore",
            "use",
            "enclave",
            "--yes",
            "--passphrase-file",
            &d.pass,
        ];
        killed_at(&d, point, &args);
        let moved = point == "enclave-plain-removed";
        assert_eq!(d.plain().exists(), !moved, "{point}");
        assert_eq!(d.sealed().exists(), both_after || moved, "{point}");
        if !moved {
            assert_eq!(
                read(&d.plain()),
                original,
                "{point}: secrets.json is untouched"
            );
        }
        // The same secrets, whichever file they are in now.
        d.works();
        if both_after {
            d.run(&["status"])
                .ok()
                .has("secrets.json and secrets.sealed both exist (an interrupted move");
            // Nothing finishes it automatically: more commands, and both are still there.
            d.works();
            assert!(d.plain().exists() && d.sealed().exists(), "{point}");
        }
        // The same command again completes.
        d.use_enclave().ok();
        assert!(d.sealed().exists() && !d.plain().exists(), "{point}");
        assert_eq!(d.choice().as_deref(), Some("enclave"));
        assert!(
            d.files().iter().all(|name| !name.contains(".tmp-")),
            "{point}: {:?}",
            d.files()
        );
        d.works();
        // … and back gives the bytes there were.
        d.run(&["keystore", "use", "file"]).ok();
        assert_eq!(read(&d.plain()), original, "{point}");
        d.use_enclave().ok();
        d.logout_leaves_nothing();
    }
}

/// Killed at any point of `keystore use file`. An interrupted opt-out is never undone by a
/// later command: the choice stays `file` once it is written.
#[test]
fn every_crash_point_of_the_move_back_to_the_file() {
    let lab = Lab::new();
    for (n, (point, choice_written, plain_after)) in [
        ("file-choice-temp", false, false),
        ("file-choice-done", true, false),
        ("file-plain-temp", true, false),
        ("file-plain-done", true, true),
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("f{n}");
        let d = Device {
            vault: s(&lab.path(&format!("{name}-vault"))),
            ..lab.device(&name)
        };
        d.login().ok();
        let tree = lab.path(&format!("{name}-tree"));
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("a.txt"), b"alpha\n").unwrap();
        d.run(&["copy", &s(&tree), ":docs"]).ok();
        let original = read(&d.plain());
        d.use_enclave().ok();

        killed_at(&d, point, &["keystore", "use", "file"]);
        assert!(
            d.sealed().exists(),
            "{point}: the sealed file is removed last"
        );
        assert_eq!(d.plain().exists(), plain_after, "{point}");
        let expected_choice = if choice_written { "file" } else { "enclave" };
        assert_eq!(d.choice().as_deref(), Some(expected_choice), "{point}");
        // The device is still working — sealed, or on the plain file that was just written.
        d.works();
        if choice_written && !plain_after {
            d.run(&["status"])
                .ok()
                .has("Run `gclone keystore use file` again");
        }
        // Later commands undo nothing: the choice stays, and a plain file that exists stays.
        d.works();
        d.run(&["status"]).ok();
        assert_eq!(d.choice().as_deref(), Some(expected_choice), "{point}");
        assert_eq!(d.plain().exists(), plain_after, "{point}");
        if plain_after {
            assert_eq!(read(&d.plain()), original, "{point}");
        }

        // The same command again completes.
        d.run(&["keystore", "use", "file"]).ok();
        assert_eq!(read(&d.plain()), original, "{point}");
        assert!(!d.sealed().exists(), "{point}");
        assert_eq!(d.choice().as_deref(), Some("file"));
        assert!(
            d.files().iter().all(|name| !name.contains(".tmp-")),
            "{point}: {:?}",
            d.files()
        );
        d.works();
        d.logout_leaves_nothing();
    }
}

/// Killed inside a save of `login`, and inside `logout`.
#[test]
fn every_crash_point_of_the_saves_of_login_and_of_logout() {
    let lab = Lab::new();

    // A first login whose save to the plain file is killed before or after the rename.
    for (n, point) in ["save-locked", "save-plain-temp", "save-plain-done"]
        .into_iter()
        .enumerate()
    {
        let name = format!("p{n}");
        let d = Device {
            vault: s(&lab.path(&format!("{name}-vault"))),
            ..lab.device(&name)
        };
        killed_at(
            &d,
            point,
            &[
                "login",
                "--vault-dir",
                &d.vault,
                "--passphrase-file",
                &d.pass,
            ],
        );
        assert_eq!(d.plain().exists(), point == "save-plain-done", "{point}");
        // The same command again completes (the vault exists: it attaches).
        d.login().ok();
        d.run(&["ls"]).ok();
        d.logout_leaves_nothing();
    }

    // A login on a signed-out device that chose the sealed store: the save into a new
    // sealed file is killed before or after its rename.
    for (n, point) in ["save-sealed-temp", "save-sealed-done"]
        .into_iter()
        .enumerate()
    {
        let name = format!("s{n}");
        let d = Device {
            vault: s(&lab.path(&format!("{name}-vault"))),
            ..lab.device(&name)
        };
        d.login().ok();
        d.use_enclave().ok();
        d.run(&["logout"]).ok();
        killed_at(
            &d,
            point,
            &[
                "login",
                "--vault-dir",
                &d.vault,
                "--passphrase-file",
                &d.pass,
            ],
        );
        assert!(!d.plain().exists(), "{point}");
        assert_eq!(d.sealed().exists(), point == "save-sealed-done", "{point}");
        if point == "save-sealed-done" {
            d.run(&["ls"]).ok();
        } else {
            d.run(&["ls"]).code(4);
        }
        d.login().ok();
        assert!(d.sealed().exists() && !d.plain().exists(), "{point}");
        d.run(&["ls"]).ok();
        d.logout_leaves_nothing();
    }

    // A dead sealed file, and the login that has the key again is killed between its save to
    // the plain file and the removal of the sealed one: readers use the plain file, and the
    // next login or `keystore use` removes the sealed one.
    {
        let d = lab.connected("dead");
        d.use_enclave().ok();
        let dead = d.with(&[("GCLONE_TEST_KEYSTORE_MACHINE", "mac-2")]);
        killed_at(
            &dead,
            "save-plain-done",
            &[
                "login",
                "--vault-dir",
                &d.vault,
                "--passphrase-file",
                &d.pass,
            ],
        );
        assert!(d.plain().exists() && d.sealed().exists());
        dead.works();
        dead.run(&["status"]).ok().has("both exist");
        dead.run(&["keystore", "use", "file"])
            .code(1)
            .has("does not open")
            .has("--discard-sealed");
        dead.run(&["keystore", "use", "file", "--discard-sealed"])
            .ok()
            .has("removed as asked");
        assert!(d.plain().exists() && !d.sealed().exists());
        dead.works();
        dead.logout_leaves_nothing();
    }

    // `logout`, killed after the temp copies went and after the plain file went: the next
    // logout still finds the device signed in and finishes.
    for (n, (point, sealed_device)) in [
        ("delete-leftovers-done", false),
        ("delete-plain-done", false),
        ("delete-leftovers-done", true),
        ("delete-plain-done", true),
    ]
    .into_iter()
    .enumerate()
    {
        let d = lab.connected(&format!("l{n}"));
        if sealed_device {
            d.use_enclave().ok();
        }
        // what an interrupted write left earlier
        std::fs::write(
            d.state.join(".secrets.json.tmp-0011223344556677"),
            b"a copy",
        )
        .unwrap();
        std::fs::write(
            d.state.join(".secrets.sealed.tmp-0011223344556677"),
            b"a copy",
        )
        .unwrap();
        killed_at(&d, point, &["logout"]);
        assert!(
            d.files().iter().all(|name| !name.contains(".tmp-")),
            "{point}"
        );
        d.logout_leaves_nothing_or_already(point, sealed_device);
    }
}

impl Device {
    /// After a `logout` that was killed half-way: the next one finishes, whatever is left.
    #[track_caller]
    fn logout_leaves_nothing_or_already(&self, point: &str, sealed_device: bool) {
        let signed_in = self.plain().exists() || self.sealed().exists();
        let expect_signed_in = sealed_device || point == "delete-leftovers-done";
        assert_eq!(
            signed_in, expect_signed_in,
            "{point}, sealed: {sealed_device}"
        );
        let out = self.run(&["logout"]).ok();
        if signed_in {
            out.has("Signed out on this device.");
        } else {
            out.has("Not signed in on this device");
        }
        assert!(!self.plain().exists() && !self.sealed().exists());
        self.run(&["ls"]).code(4);
    }
}

// ---------------------------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------------------------

/// Eight processes read in a loop while another moves the secrets back and forth: no reader
/// ever finds the device signed out, and none gets an error.
#[test]
fn readers_in_other_processes_never_see_a_signed_out_device_during_moves() {
    let lab = Lab::new();
    let d = lab.connected("a");
    let stop = std::sync::atomic::AtomicBool::new(false);
    let reads = std::sync::atomic::AtomicU64::new(0);
    let mut pairs = 0;
    std::thread::scope(|scope| {
        for reader in 0..8 {
            let (d, stop, reads) = (&d, &stop, &reads);
            scope.spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    if reader % 2 == 0 {
                        // The vault's listing: config, secrets, keys, replica.
                        let out = d.run(&["ls", ":docs"]);
                        assert_eq!(out.code, 0, "ls failed during a move:\n{}", out.stderr);
                        assert!(out.stdout.contains("a.txt"), "{}", out.stdout);
                    } else {
                        // Where the secrets are: never "none", never unusable.
                        let out = d.run(&["keystore", "--json"]);
                        assert_eq!(out.code, 0, "{}", out.stderr);
                        let json: serde_json::Value =
                            serde_json::from_str(&out.stdout).expect("JSON");
                        let store = json["key_store"]["store"].as_str().unwrap().to_string();
                        assert!(store == "file" || store == "enclave", "{}", out.stdout);
                        assert_eq!(json["key_store"]["usable"], true, "{}", out.stdout);
                    }
                    reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            });
        }
        let until = Instant::now() + Duration::from_secs(6);
        while Instant::now() < until || pairs < 3 {
            d.run(&[
                "keystore",
                "use",
                "enclave",
                "--yes",
                "--skip-passphrase-check",
            ])
            .ok();
            d.run(&["keystore", "use", "file"]).ok();
            pairs += 1;
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    });
    let reads = reads.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        pairs >= 3 && reads >= 40,
        "{pairs} move pairs, {reads} reads"
    );
    d.works();
}

/// `login` (twice) and a move at the same time: one consistent state.
#[test]
fn two_logins_and_a_move_at_once_end_in_one_consistent_state() {
    let lab = Lab::new();
    for round in 0..4 {
        let name = format!("c{round}");
        let d = Device {
            vault: s(&lab.path(&format!("{name}-vault"))),
            ..lab.device(&name)
        };
        d.login().ok();
        let tree = lab.path(&format!("{name}-tree"));
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("a.txt"), b"alpha\n").unwrap();
        d.run(&["copy", &s(&tree), ":docs"]).ok();
        // A second device of the same state root would be the same device: the two logins
        // are `logout` + `login` sequences racing with the move.
        std::thread::scope(|scope| {
            let relogin = || {
                let out = d.login();
                assert!(out.code == 0, "{}", out.stderr);
            };
            scope.spawn(relogin);
            scope.spawn(relogin);
            scope.spawn(|| {
                let out = d.run(&[
                    "keystore",
                    "use",
                    "enclave",
                    "--yes",
                    "--skip-passphrase-check",
                ]);
                assert!(
                    out.code == 0 || out.stderr.contains("Run the command again"),
                    "{}",
                    out.stderr
                );
            });
        });
        d.works();
        let (plain, sealed) = (d.plain().exists(), d.sealed().exists());
        assert!(
            plain != sealed,
            "exactly one store: plain {plain}, sealed {sealed}"
        );
        assert!(d.files().iter().all(|name| !name.contains(".tmp-")));
        d.logout_leaves_nothing();
    }
}

// ---------------------------------------------------------------------------------------------
// The trial and the notes
// ---------------------------------------------------------------------------------------------

fn trial(d: &Device) -> serde_json::Value {
    serde_json::from_slice(&read(&d.state.join("keystore-trial.json"))).expect("trial record")
}

/// A device on the plain file — every Mac that ran gclone 0.5.0 — is tested and then moved
/// (§17.30): the trial records days, boots and sessions and touches nothing; the run that
/// completes it moves the secrets into the sealed store, to the trial's own key, without a
/// command, a passphrase or a question; and a person is told once.
#[test]
fn the_trial_records_days_boots_and_sessions_and_then_the_secrets_move_by_themselves() {
    let lab = Lab::new();
    let quiet = lab.connected("a");
    assert!(
        !quiet.state.join("keystore-trial.json").exists(),
        "GCLONE_KEYSTORE_TRIAL=0"
    );
    let original = read(&quiet.plain());
    let d = quiet.without("GCLONE_KEYSTORE_TRIAL");
    let at = |day: u64, boot: &str, session: &str| at(&d, day, boot, session);
    let unmoved = |what: &str| {
        assert_eq!(
            read(&d.plain()),
            original,
            "{what}: secrets.json is untouched"
        );
        assert!(!d.sealed().exists() && !d.note_owed(), "{what}");
        assert_eq!(d.choice(), None, "{what}");
    };

    // Day 0, in a terminal. Every command that loads the secrets takes a step.
    at(0, "boot-a", "0x2030").works();
    let record = trial(&d);
    assert_eq!(record["version"], 1);
    assert_eq!(record["created_boot"], "boot-a");
    assert_eq!(record["ok"].as_array().unwrap().len(), 1);
    assert_eq!(record["failure_count"], 0);
    for member in ["public", "key", "canary", "canary_hash"] {
        assert!(record[member].is_string(), "{member}");
    }
    assert_eq!(mode(&d.state.join("keystore-trial.json")), 0o600);
    let text = String::from_utf8(read(&d.state.join("keystore-trial.json"))).unwrap();
    let key = serde_json::from_slice::<serde_json::Value>(&original).unwrap()["keys"][0]["key"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        !text.contains(&key),
        "the vault key is not in the trial record"
    );
    unmoved("day 0");
    at(0, "boot-a", "0x2030")
        .run(&["status"])
        .ok()
        .has("Key store    plain file secrets.json (0600) — Secure Enclave trial: 1 of 3 days, no restart seen yet");
    at(0, "boot-a", "0x2030")
        .run(&["keystore"])
        .ok()
        .has("Choice       none made: the sealed store wherever this Mac's Secure Enclave can be used")
        .has("the test value opened on 1 day(s) (complete with 3 that are 48 hours apart); no restart seen yet; 0 failure(s)");

    // The same day from cron, the next day, a clock jump without a restart: days enough, and
    // nothing moves — a restart has not been seen.
    at(0, "boot-a", "0x2").works();
    at(1, "boot-a", "0x2030").works();
    unmoved("two days");
    at(40, "boot-a", "0x2030")
        .with(&[("GCLONE_TEST_NOTES", "1")])
        .run(&["status"])
        .ok()
        .has("Secure Enclave trial: 3 days, no restart seen yet")
        .lacks("note:");
    unmoved("three days without a restart");
    let trial_key = trial(&d)["key"].clone();
    assert!(trial_key.is_string());

    // Another boot: the trial is complete, and the very run that completes it moves the
    // secrets. It is a scheduler's run: nobody is there to read a note, so it is owed.
    let completes = at(41, "boot-b", "0x2");
    completes.works();
    assert!(
        d.sealed().exists() && !d.plain().exists(),
        "{:?}",
        d.files()
    );
    assert_eq!(mode(&d.sealed()), 0o600);
    assert_eq!(d.choice(), None, "the choice file is the owner's");
    assert!(d.note_owed());
    assert!(d.files().iter().all(|name| !name.contains(".tmp-")));
    let sealed: serde_json::Value = serde_json::from_slice(&read(&d.sealed())).unwrap();
    assert_eq!(
        sealed["key"], trial_key,
        "sealed to the key the trial exercised"
    );
    assert!(
        !String::from_utf8(read(&d.sealed())).unwrap().contains(&key),
        "the vault key is not in the sealed file"
    );
    let after = trial(&d);
    assert!(after.get("key").is_none() && after.get("canary").is_none());
    assert!(after["moved_ms"].is_u64());
    assert_eq!(after["public"], sealed["public"]);
    // Everything works as before, from the sealed store — in that scheduler and elsewhere.
    completes.works();
    completes.run(&["ls", ":docs"]).ok().lacks("note:");
    assert!(d.note_owed(), "still owed: no terminal yet");

    // A person at a terminal: told once.
    let person = at(41, "boot-b", "0x2030").with(&[("GCLONE_TEST_NOTES", "1")]);
    let told = person.run(&["ls", ":docs"]).ok();
    let told = told
        .has(MOVE_NOTE)
        .has("which only this Mac's Secure Enclave can open")
        .has("`gclone login` and your passphrase connect it again")
        .has("`gclone keystore use file` moves back to the plain file");
    drop(told);
    assert!(!d.note_owed());
    person.run(&["ls", ":docs"]).ok().lacks("note:");
    person
        .run(&["status"])
        .ok()
        .has("Key store    Secure Enclave of this Mac (secrets.sealed)")
        .lacks("warning:");
    let shown = person.run(&["keystore"]).ok();
    shown
        .has("Key store    Secure Enclave of this Mac (secrets.sealed)")
        .has("Choice       none made: the sealed store wherever this Mac's Secure Enclave can be used")
        .has("Trial        ended: its key holds the secrets (4 days, a restart survived)")
        .has("0x2 (without graphic access)")
        .has("0x2030 (with graphic access)")
        .lacks("warning:");
    let json: serde_json::Value =
        serde_json::from_str(&person.run(&["keystore", "--json"]).ok().stdout).unwrap();
    assert_eq!(json["key_store"]["store"], "enclave");
    assert_eq!(json["key_store"]["choice"], serde_json::Value::Null);
    assert_eq!(json["key_store"]["usable"], true);
    assert_eq!(json["key_store"]["trial"]["moved"], true);
    assert_eq!(json["key_store"]["trial"]["key_holds_secrets"], true);
    assert_eq!(json["key_store"]["trial"]["days"], 4);
    assert_eq!(json["key_store"]["trial"]["restart"], true);
    assert_eq!(
        json["key_store"]["trial"]["sessions"],
        serde_json::json!(["0x2", "0x2030"])
    );
    person
        .run(&["keystore", "check"])
        .ok()
        .has("secrets.sealed opens in this session");
    // A sealed device has no trial: its record is not written to any more.
    let written = read(&d.state.join("keystore-trial.json"));
    at(45, "boot-c", "0x2030").works();
    assert_eq!(read(&d.state.join("keystore-trial.json")), written);

    // The way back gives the bytes there were, and is remembered.
    at(45, "boot-c", "0x2030")
        .run(&["keystore", "use", "file"])
        .ok()
        .has("are back in the plain file")
        .has("nothing is moved by itself — not after a later login either");
    assert_eq!(read(&d.plain()), original);
    assert_eq!(d.choice().as_deref(), Some("file"));
    at(46, "boot-c", "0x2030").works();
    at(47, "boot-d", "0x2030").works();
    assert_eq!(read(&d.state.join("keystore-trial.json")), written);
    assert_eq!(read(&d.plain()), original);
    assert!(!d.sealed().exists() && !d.note_owed());
}

/// The bar exists so that a scheduled run is never broken by a store that stops opening
/// there: one failure of the trial, in any session, keeps the secrets in the plain file —
/// until somebody looked and started a new trial, which has to pass in full.
#[test]
fn a_failure_on_the_trials_record_keeps_the_secrets_in_the_plain_file() {
    let lab = Lab::new();
    let (d, original) = lab.nearly_passed("a");
    // The scheduler's session cannot open the test value on day 1.
    let cron_fails = at(&d, 1, "boot-a", "0x2").with(&[("GCLONE_TEST_KEYSTORE_FAIL", "open")]);
    cron_fails.works();
    let record = trial(&d);
    assert_eq!(record["failure_count"], 1);
    assert_eq!(record["failures"][0]["session"], "0x2");
    assert_eq!(record["failures"][0]["fresh_key_ok"], false);
    // Three days and a restart, in a terminal where everything works: nothing moves.
    for (day, boot) in [(2, "boot-b"), (3, "boot-b"), (9, "boot-c")] {
        at(&d, day, boot, "0x2030").works();
        assert_eq!(read(&d.plain()), original, "day {day}");
        assert!(!d.sealed().exists() && !d.note_owed(), "day {day}");
    }
    at(&d, 9, "boot-c", "0x2030")
        .run(&["status"])
        .ok()
        .has("Secure Enclave trial: 5 days, a restart survived, 1 failure")
        .has("warning: the Secure Enclave trial failed 1 time(s) in a session without graphic access")
        .has("Nothing is moved into the sealed store while a failure is on its record")
        .has("`gclone keystore check --new-trial` starts a new trial");
    at(&d, 9, "boot-c", "0x2030")
        .run(&["keystore"])
        .ok()
        .has("a failure never clears by itself, and nothing is moved while one is on record");

    // Somebody looked: a new trial starts a new key and record, and has to pass in full.
    at(&d, 9, "boot-c", "0x2030")
        .run(&["keystore", "check", "--new-trial"])
        .ok()
        .has("a new key and a new record were started");
    let fresh = trial(&d);
    assert_eq!(fresh["failure_count"], 0);
    assert_eq!(fresh["ok"].as_array().unwrap().len(), 1);
    assert_ne!(fresh["key"], record["key"]);
    at(&d, 10, "boot-c", "0x2").works();
    at(&d, 11, "boot-c", "0x2030").works();
    assert_eq!(
        read(&d.plain()),
        original,
        "three days, no restart since the new key"
    );
    at(&d, 11, "boot-d", "0x2030").works();
    assert!(d.sealed().exists() && !d.plain().exists());
    let sealed: serde_json::Value = serde_json::from_slice(&read(&d.sealed())).unwrap();
    assert_eq!(sealed["key"], fresh["key"], "the new trial's key");
    d.run(&["keystore", "use", "file"]).ok();
    assert_eq!(read(&d.plain()), original);
}

/// The move never happens from a process that cannot open the trial's key itself: the run
/// that would complete the trial, in a session where the stored key does not open, moves
/// nothing — it adds a failure, which stops every later run as well.
#[test]
fn a_run_that_cannot_open_the_trials_key_moves_nothing() {
    for fail in ["open", "open-stored", "hang"] {
        let lab = Lab::new();
        let (d, original) = lab.nearly_passed("a");
        let completes = at(&d, 2, "boot-b", "0x2");
        completes
            .with(&[("GCLONE_TEST_KEYSTORE_FAIL", fail)])
            .works();
        assert_eq!(read(&d.plain()), original, "{fail}");
        assert!(!d.sealed().exists() && !d.note_owed(), "{fail}");
        let record = trial(&d);
        assert_eq!(record["failure_count"], 1, "{fail}");
        assert_eq!(record["failures"][0]["session"], "0x2");
        assert_eq!(
            record["failures"][0]["timed_out"]
                .as_bool()
                .unwrap_or(false),
            fail == "hang"
        );
        // A terminal where the key opens, on the same day and later: the failure stands.
        at(&d, 2, "boot-b", "0x2030").works();
        at(&d, 3, "boot-b", "0x2030").works();
        assert_eq!(read(&d.plain()), original, "{fail}");
        assert!(!d.sealed().exists(), "{fail}");
        at(&d, 3, "boot-b", "0x2030")
            .run(&["status"])
            .ok()
            .has("warning: the Secure Enclave trial failed 1 time(s) in a session without graphic access");
    }
}

/// `GCLONE_KEYSTORE_TRIAL=0` in a run's environment: no trial step, no move and no sealing
/// at a login in that run — and, because a run that must not depend on the Secure Enclave is
/// not protected by being the one run the test never sees, in no other run of this device
/// either: a run with the variable that uses the plain `secrets.json` leaves a marker, and
/// while it is there nothing is tested, sealed or moved. `status` says why; `gclone keystore
/// use enclave` and `gclone keystore check --new-trial` take the marker away.
#[test]
fn the_environment_switch_keeps_the_plain_file_for_the_whole_device() {
    let lab = Lab::new();
    let (d, original) = lab.nearly_passed("a");
    let record = read(&d.state.join("keystore-trial.json"));
    assert!(!d.trial_off_marked());
    let job = at(&d, 2, "boot-b", "0x2").owner_sets_trial_off();
    // `gclone keystore` alone loads no secrets: it speaks for its own run.
    job.run(&["keystore"]).ok().has(
        "Choice       none made; GCLONE_KEYSTORE_TRIAL=0 is set here: nothing is sealed or moved",
    );
    assert!(!d.trial_off_marked());
    // The job runs — on the day and in the boot that would have completed the trial.
    job.works();
    assert!(d.trial_off_marked(), "{:?}", d.files());
    assert_eq!(mode(&d.state.join("keystore-trial.off")), 0o600);
    job.with(&[("GCLONE_TEST_NOTES", "1")])
        .run(&["status"])
        .ok()
        .has("Key store    plain file secrets.json (0600) — kept: a run with GCLONE_KEYSTORE_TRIAL=0 uses this device")
        .has("`gclone keystore use enclave` moves the secrets")
        .lacks("note:");
    let json: serde_json::Value =
        serde_json::from_str(&job.run(&["keystore", "--json"]).ok().stdout).unwrap();
    assert_eq!(json["key_store"]["trial_disabled"], true);
    assert_eq!(json["key_store"]["trial_off_marker"], true);
    assert_eq!(read(&d.plain()), original);
    assert!(!d.sealed().exists() && !d.note_owed());
    assert_eq!(
        read(&d.state.join("keystore-trial.json")),
        record,
        "no step was taken"
    );

    // A run WITHOUT the variable, the same day: it does not complete the trial behind the
    // job's back, and it says why.
    let on = at(&d, 2, "boot-b", "0x2030");
    on.works();
    assert_eq!(read(&d.plain()), original);
    assert!(!d.sealed().exists() && !d.note_owed());
    assert_eq!(
        read(&d.state.join("keystore-trial.json")),
        record,
        "no step in a run without the variable either"
    );
    on.run(&["status"])
        .ok()
        .has("Key store    plain file secrets.json (0600) — kept: a run with GCLONE_KEYSTORE_TRIAL=0 uses this device");
    on.run(&["keystore"])
        .ok()
        .has("Choice       none made; a run with GCLONE_KEYSTORE_TRIAL=0 uses this device")
        .has("`gclone keystore check --new-trial`");
    let json: serde_json::Value =
        serde_json::from_str(&on.run(&["keystore", "--json"]).ok().stdout).unwrap();
    assert_eq!(json["key_store"]["trial_disabled"], false);
    assert_eq!(json["key_store"]["trial_off_marker"], true);
    // A login after a logout stays on the plain file as well — in a run with the variable
    // and in one without.
    for run in [&job, &on] {
        run.run(&["logout"]).ok();
        assert!(d.trial_off_marked(), "the marker is no secret: it stays");
        run.login()
            .ok()
            .lacks("sealed by this Mac's Secure Enclave");
        assert!(d.plain().exists() && !d.sealed().exists());
    }
    // Days and a restart later: still.
    for (day, boot) in [(3, "boot-b"), (4, "boot-c"), (5, "boot-c")] {
        at(&d, day, boot, "0x2030").works();
        assert!(d.plain().exists() && !d.sealed().exists());
    }

    // `gclone keystore check --new-trial` takes the marker away and starts a trial …
    let later = at(&d, 6, "boot-c", "0x2030");
    later
        .run(&["keystore", "check", "--new-trial"])
        .ok()
        .has("a new key and a new record were started");
    assert!(!d.trial_off_marked());
    later
        .run(&["status"])
        .ok()
        .has("Secure Enclave trial: 1 of 3 days");
    // … and the job's next run puts it back.
    at(&d, 6, "boot-c", "0x2").owner_sets_trial_off().works();
    assert!(d.trial_off_marked());
    // `gclone keystore use enclave` is the owner's word against it: moved at once, and the
    // marker goes.
    later.use_enclave().ok().has("are now sealed by the");
    assert!(d.sealed().exists() && !d.plain().exists());
    assert!(!d.trial_off_marked());
    // A sealed store is read with the variable set, like any other — and that leaves no
    // marker: there is no plain file to keep.
    let job = at(&d, 7, "boot-c", "0x2").owner_sets_trial_off();
    job.works();
    job.run(&["status"])
        .ok()
        .has("Key store    Secure Enclave of this Mac (secrets.sealed)");
    assert!(!d.trial_off_marked());
}

/// What the variable is for. A scheduler's job runs every day with `GCLONE_KEYSTORE_TRIAL=0`
/// in a session that cannot use the Secure Enclave; its owner runs gclone in a terminal every
/// day without it. The variable used to make the job invisible to the test: the terminal's
/// runs passed the bar and removed `secrets.json`, and the job failed with exit 4 from then
/// on. Now the job's first run settles it for the device.
#[test]
fn a_job_that_sets_the_switch_is_not_broken_by_the_runs_that_do_not() {
    let lab = Lab::new();
    let quiet = lab.connected("a");
    let original = read(&quiet.plain());
    let d = quiet.without("GCLONE_KEYSTORE_TRIAL");
    let job = |day: u64, boot: &str| {
        at(&d, day, boot, "0x2")
            .owner_sets_trial_off()
            .with(&[("GCLONE_TEST_KEYSTORE_FAIL", "open")])
    };
    for (day, boot) in [
        (0, "boot-a"),
        (1, "boot-a"),
        (2, "boot-b"),
        (3, "boot-b"),
        (4, "boot-c"),
    ] {
        job(day, boot).works();
        at(&d, day, boot, "0x2030").works();
        assert_eq!(read(&d.plain()), original, "day {day}");
        assert!(!d.sealed().exists() && !d.note_owed(), "day {day}");
    }
    job(5, "boot-c").works();
    assert!(
        !d.state.join("keystore-trial.json").exists(),
        "nothing was tested"
    );
    at(&d, 5, "boot-c", "0x2030")
        .run(&["status"])
        .ok()
        .has("kept: a run with GCLONE_KEYSTORE_TRIAL=0 uses this device");
}

/// `gclone keystore use file` is remembered: no trial, no move and no sealing afterwards —
/// not after a logout and a new login either — until `gclone keystore use enclave`.
#[test]
fn the_plain_file_by_choice_stays_also_after_a_later_login() {
    let lab = Lab::new();
    let d = lab.connected_mac("a");
    assert!(d.sealed().exists() && !d.plain().exists());
    d.run(&["keystore", "use", "file"])
        .ok()
        .has("are back in the plain file")
        .has("`gclone keystore use enclave` changes that");
    assert!(d.plain().exists() && !d.sealed().exists());
    assert_eq!(d.choice().as_deref(), Some("file"));
    let original = read(&d.plain());
    // Days, a restart, a scheduler: nothing — not even a trial record.
    for (day, boot, session) in [
        (1, "boot-a", "0x2"),
        (2, "boot-b", "0x2030"),
        (3, "boot-b", "0x2030"),
        (4, "boot-c", "0x2"),
    ] {
        at(&d, day, boot, session).works();
        assert_eq!(read(&d.plain()), original);
        assert!(!d.sealed().exists() && !d.note_owed());
    }
    assert!(!d.state.join("keystore-trial.json").exists());
    at(&d, 4, "boot-c", "0x2030")
        .run(&["status"])
        .ok()
        .has("Key store    plain file secrets.json (0600) — kept by choice");
    // A logout and a login: the plain file again, without a word about sealing.
    let later = at(&d, 5, "boot-c", "0x2030");
    later.run(&["logout"]).ok();
    assert_eq!(d.choice().as_deref(), Some("file"), "the choice stays");
    later
        .login()
        .ok()
        .lacks("sealed by this Mac's Secure Enclave");
    assert!(d.plain().exists() && !d.sealed().exists());
    at(&d, 6, "boot-d", "0x2030").works();
    assert!(d.plain().exists() && !d.sealed().exists());
    // The owner's command opts back in, at once.
    later.use_enclave().ok().has("are now sealed by the");
    assert!(d.sealed().exists() && !d.plain().exists());
    assert_eq!(d.choice().as_deref(), Some("enclave"));
    later.run(&["logout"]).ok();
    later
        .login()
        .ok()
        .has("sealed by this Mac's Secure Enclave");
    assert!(d.sealed().exists() && !d.plain().exists());
}

/// The trial's evidence is evidence for the trial's key. At the move the trial's test value
/// does not open (stored blobs fail, new keys work): the secrets are sealed to a key made at
/// that moment, the command says so — and so does every later look. `gclone keystore` used to
/// print "Trial ended: its key holds the secrets (3 days, a restart survived)" from then on.
#[test]
fn a_move_that_could_not_use_the_trials_key_never_borrows_its_evidence() {
    const DAY: u64 = 86_400_000;
    let start: u64 = 1_794_400_000_000;
    let lab = Lab::new();
    let d = lab.connected("a").without("GCLONE_KEYSTORE_TRIAL");
    let at = |day: u64, boot: &str, session: &str| {
        d.with(&[
            ("GCLONE_TEST_NOW_MS", &(start + day * DAY).to_string()),
            ("GCLONE_TEST_BOOT", boot),
            ("GCLONE_TEST_SESSION", session),
        ])
    };
    // A trial with evidence that has not passed yet (a passed one is followed by the move
    // itself, to the trial's key): three days and a scheduler, no restart.
    at(0, "boot-a", "0x2030").works();
    at(1, "boot-a", "0x2").works();
    at(2, "boot-a", "0x2030").works();
    at(2, "boot-a", "0x2030")
        .run(&["status"])
        .ok()
        .has("Secure Enclave trial: 3 days, no restart seen yet");
    assert!(d.plain().exists() && !d.sealed().exists());
    let trial_public = trial(&d)["public"].clone();

    at(2, "boot-a", "0x2030")
        .with(&[("GCLONE_TEST_KEYSTORE_FAIL", "open-stored")])
        .use_enclave()
        .ok()
        .has("the Secure Enclave trial has no evidence for the key that will be used (a new key, made now)");
    let sealed: serde_json::Value = serde_json::from_slice(&read(&d.sealed())).unwrap();
    assert_ne!(sealed["public"], trial_public, "sealed to another key");
    assert_eq!(trial(&d)["public"], trial_public);

    let shown = at(3, "boot-b", "0x2030").run(&["keystore"]).ok();
    let shown = shown
        .has("Trial        ended at the move — the secrets were sealed to a NEW key made then")
        .has("the trial's evidence (3 days, no restart seen) belongs to another key")
        .has("warning: the secrets are sealed to a key that was made at the move");
    shown.lacks("its key holds the secrets");
    at(3, "boot-b", "0x2030")
        .run(&["status"])
        .ok()
        .has("warning: the secrets are sealed to a key that was made at the move");
    let json: serde_json::Value = serde_json::from_str(
        &at(3, "boot-b", "0x2030")
            .run(&["keystore", "--json"])
            .ok()
            .stdout,
    )
    .unwrap();
    assert_eq!(json["key_store"]["trial"]["key_holds_secrets"], false);
    assert_eq!(json["key_store"]["trial"]["moved"], true);
    d.works();
}

/// The trial changes nothing about what commands do — also on a machine without the
/// hardware, and where the record cannot be written.
#[test]
fn the_trial_never_gets_in_the_way() {
    let lab = Lab::new();
    let d = lab.connected("a").without("GCLONE_KEYSTORE_TRIAL");
    // A desktop session that cannot make a key: the machine has no usable Secure Enclave.
    let no_hardware = d.with(&[
        ("GCLONE_TEST_KEYSTORE_FAIL", "create"),
        ("GCLONE_TEST_SESSION", "0x2030"),
    ]);
    no_hardware.works();
    no_hardware
        .run(&["status"])
        .ok()
        .has("Key store    plain file secrets.json (0600) — no Secure Enclave on this machine");
    assert!(trial(&d)["unavailable"]["error"].is_string());
    assert_eq!(trial(&d)["unavailable"]["session"], "0x2030");
    no_hardware
        .run(&["keystore", "check"])
        .code(1)
        .has("FAILED");

    // A debug build without the switch: no trial at all, and the line says nothing of one.
    let plain_build = lab
        .connected("b")
        .without("GCLONE_KEYSTORE_TRIAL")
        .without("GCLONE_TEST_KEYSTORE_SEALER");
    plain_build.works();
    assert!(!plain_build.state.join("keystore-trial.json").exists());
    let status = plain_build.run(&["status"]).ok();
    assert!(
        status
            .stdout
            .lines()
            .any(|l| l == "Key store    plain file secrets.json (0600)"),
        "{}",
        status.stdout
    );
    plain_build
        .run(&["keystore", "check"])
        .code(1)
        .has("debug build");
}

/// The first step of the trial ran in a session that could not make a key — a scheduler's.
/// That says nothing about the Mac: `gclone status` in a terminal used to read "no Secure
/// Enclave on this machine" for up to seven days while `gclone keystore check` in the same
/// terminal found a usable enclave, and the trial did not start. The failure is the
/// session's: it is named with its session, the trial starts in the first session that can
/// make a key, and what the other session said stays in the record as a failure.
#[test]
fn a_session_that_cannot_make_a_key_is_not_the_machine() {
    const HOUR: u64 = 3_600_000;
    let start: u64 = 1_794_400_000_000;
    let lab = Lab::new();
    let d = lab.connected("a").without("GCLONE_KEYSTORE_TRIAL");
    let at = |ms: u64, session: &str| {
        d.with(&[
            ("GCLONE_TEST_NOW_MS", &(start + ms).to_string()),
            ("GCLONE_TEST_BOOT", "boot-a"),
            ("GCLONE_TEST_SESSION", session),
        ])
    };
    // The scheduler's session cannot make a key.
    let scheduler = at(0, "0x2").with(&[("GCLONE_TEST_KEYSTORE_FAIL", "create")]);
    scheduler.works();
    assert_eq!(trial(&d)["unavailable"]["session"], "0x2");
    let status = scheduler.run(&["status"]).ok();
    let status = status.has(
        "Key store    plain file secrets.json (0600) — no Secure Enclave key could be made in \
         session 0x2 (without graphic access) on 2026-11-",
    );
    status.lacks("no Secure Enclave on this machine");
    scheduler
        .run(&["keystore"])
        .ok()
        .has("no Secure Enclave key could be made in session 0x2 (without graphic access)")
        .has("that session only");

    // One hour later, the same boot, a terminal: the trial starts at once.
    let terminal = at(HOUR, "0x2030");
    terminal
        .run(&["keystore", "check"])
        .ok()
        .has("The Secure Enclave is usable in this session.");
    let status = terminal.run(&["status"]).ok();
    let status = status
        .has("Secure Enclave trial: 1 of 3 days, no restart seen yet, 1 failure")
        .has("warning: the Secure Enclave trial failed 1 time(s) in a session without graphic access");
    status.lacks("no Secure Enclave on this machine");
    let record = trial(&d);
    assert!(record["key"].is_string() && record.get("unavailable").is_none());
    assert_eq!(record["failure_count"], 1);
    assert_eq!(record["failures"][0]["session"], "0x2");
    terminal
        .run(&["keystore"])
        .ok()
        .has("in session 0x2 (without graphic access): no key could be made");
    // The scheduler's session, where no key can be made, opens nothing either: more failures,
    // never a silent "complete".
    let scheduler = at(2 * HOUR, "0x2").with(&[("GCLONE_TEST_KEYSTORE_FAIL", "open")]);
    scheduler.works();
    assert_eq!(trial(&d)["failure_count"], 2);
}

/// A call into the Secure Enclave that does not return (a scheduler session nobody measured,
/// a framework that waits for something) must not hold up a device that never chose the
/// sealed store: the trial's step used to run inline in every command, without a bound.
#[test]
fn a_trial_step_that_hangs_delays_one_command_by_a_bounded_time() {
    let lab = Lab::new();
    let d = lab.connected("a").without("GCLONE_KEYSTORE_TRIAL").with(&[
        ("GCLONE_TEST_BOOT", "boot-a"),
        ("GCLONE_TEST_SESSION", "0x2"),
    ]);
    let hangs = d.with(&[("GCLONE_TEST_KEYSTORE_FAIL", "hang")]);
    let before = std::time::Instant::now();
    hangs.works();
    let first = before.elapsed();
    assert!(
        first >= std::time::Duration::from_secs(2) && first < std::time::Duration::from_secs(20),
        "the first command waits for the bounded time, once: {first:?}"
    );
    let record = trial(&d);
    assert_eq!(record["failure_count"], 1);
    assert_eq!(record["failures"][0]["timed_out"], true);
    assert_eq!(record["failures"][0]["session"], "0x2");
    // The next commands in this boot and session do not try again: no wait at all.
    let before = std::time::Instant::now();
    hangs.works();
    hangs.run(&["status"]).ok().has(
        "warning: the Secure Enclave trial failed 1 time(s) in a session without graphic access",
    );
    assert!(
        before.elapsed() < std::time::Duration::from_millis(1900),
        "{:?}",
        before.elapsed()
    );
    assert_eq!(trial(&d)["failure_count"], 1);
    hangs
        .run(&["keystore"])
        .ok()
        .has("the call into the Secure Enclave did not return within 2 s")
        .has("this session is left alone for a day");
    // The opt-outs still work, and need no enclave call at all.
    hangs.run(&["keystore", "use", "file"]).ok();
    hangs.works();
}

/// The once-only note about older backups — the only unasked message that tells the owner
/// that Time Machine backups made before 0.5.0 hold the key in plain — must not be lost when
/// the first runs of 0.5.0 on a device overlap without a terminal (a scheduled sync and
/// `serve restic` in the same minute). "Owed" was a member of the trial's record, which each
/// of those processes rewrote from the copy it had loaded: with eight at once the note was
/// lost in about half of the rounds, for good.
#[cfg(target_os = "macos")]
#[test]
fn the_backup_note_survives_first_runs_that_overlap_without_a_terminal() {
    const ATTR: &str = "com.apple.metadata:com_apple_backup_excludeItem";
    let lab = Lab::new();
    for round in 0..6 {
        // A device that held a login before the state folder was excluded (an upgrade).
        let quiet = lab.connected(&format!("r{round}"));
        let removed = Command::new("/usr/bin/xattr")
            .args(["-d", ATTR])
            .arg(&quiet.state)
            .status()
            .expect("xattr");
        assert!(
            removed.success(),
            "the exclusion attribute was set by login"
        );
        let d = quiet.without("GCLONE_KEYSTORE_TRIAL");
        // The first runs: eight at once, none on a terminal.
        let running: Vec<_> = (0..8)
            .map(|_| {
                d.command(&["ls", ":docs"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn gclone")
            })
            .collect();
        for mut child in running {
            assert!(child.wait().expect("wait").success());
        }
        assert!(
            d.state.join("backup-note.due").exists(),
            "round {round}: the note is owed: {:?}",
            d.files()
        );
        // Later, a person at a terminal (the test switch stands in for it): shown, once.
        let person = d.with(&[("GCLONE_TEST_NOTES", "1")]);
        person
            .run(&["ls", ":docs"])
            .ok()
            .has("note: gclone's state folder is now left out of Time Machine backups")
            .has(
                "Backups made before today still contain secrets.json with the vault key in plain",
            );
        assert!(!d.state.join("backup-note.due").exists());
        person
            .run(&["ls", ":docs"])
            .ok()
            .lacks("left out of Time Machine");
        // The trial's record of those eight first runs is one trial, whole.
        let record = trial(&d);
        assert!(record["key"].is_string());
        assert_eq!(record["failure_count"], 0);
    }
}

/// The note about older backups has nothing to do with the trial: with `GCLONE_KEYSTORE_TRIAL=0`
/// in the scheduler's environment and no terminal at the first run, it was never owed and never
/// shown (§17.30) — the exclusion attribute was set by then, so it never became due again.
#[cfg(target_os = "macos")]
#[test]
fn the_backup_note_is_owed_and_shown_with_the_trial_switched_off() {
    const ATTR: &str = "com.apple.metadata:com_apple_backup_excludeItem";
    let lab = Lab::new();
    // A device that held a login before the state folder was excluded (an upgrade), and whose
    // every run has the trial switched off.
    let d = lab.connected("a");
    assert!(
        d.env
            .iter()
            .any(|(k, v)| k == "GCLONE_KEYSTORE_TRIAL" && v == "0")
    );
    let removed = Command::new("/usr/bin/xattr")
        .args(["-d", ATTR])
        .arg(&d.state)
        .status()
        .expect("xattr");
    assert!(
        removed.success(),
        "the exclusion attribute was set by login"
    );
    // The first run: no terminal.
    d.works();
    assert!(
        d.state.join("backup-note.due").exists(),
        "the note is owed: {:?}",
        d.files()
    );
    assert!(!d.state.join("keystore-trial.json").exists());
    // Later, a person at a terminal: shown, once.
    let person = d.with(&[("GCLONE_TEST_NOTES", "1")]);
    person
        .run(&["ls", ":docs"])
        .ok()
        .has("note: gclone's state folder is now left out of Time Machine backups")
        .has("Backups made before today still contain secrets.json with the vault key in plain");
    assert!(!d.state.join("backup-note.due").exists());
    person
        .run(&["ls", ":docs"])
        .ok()
        .lacks("left out of Time Machine");

    // And where the first run is on a terminal, it is shown at once and nothing is owed.
    let e = lab.connected("b");
    let removed = Command::new("/usr/bin/xattr")
        .args(["-d", ATTR])
        .arg(&e.state)
        .status()
        .expect("xattr");
    assert!(removed.success());
    e.with(&[("GCLONE_TEST_NOTES", "1")])
        .run(&["ls", ":docs"])
        .ok()
        .has("note: gclone's state folder is now left out of Time Machine backups");
    assert!(!e.state.join("backup-note.due").exists());
}

/// `gclone keystore use enclave` as the first command after a login on the plain file (or after
/// `gclone keystore check`, which stores nothing): the command picked a new key, and the load
/// it then made of the secrets started a trial with ANOTHER key — whose record the move
/// closed. `status` and `keystore` then warned for good that "the secrets are sealed to a key
/// that was made at the move … the trial's evidence belongs to another key", about a trial
/// that had no evidence at all (§17.30).
#[test]
fn a_move_as_the_first_command_after_login_leaves_no_warning_about_another_key() {
    let lab = Lab::new();
    for (n, check_first) in [false, true].into_iter().enumerate() {
        let name = format!("w{n}");
        // The login keeps the plain file (the trial is switched off for it) …
        let quiet = Device {
            vault: s(&lab.path(&format!("{name}-vault"))),
            ..lab.device(&name)
        };
        quiet.login().ok();
        assert!(quiet.plain().exists() && !quiet.sealed().exists());
        assert!(!quiet.state.join("keystore-trial.json").exists());
        // … and every later command runs as an owner's would, with the trial on.
        let d = quiet.without("GCLONE_KEYSTORE_TRIAL").with(&[
            ("GCLONE_TEST_BOOT", "boot-a"),
            ("GCLONE_TEST_SESSION", "0x2030"),
        ]);
        if check_first {
            d.run(&["keystore", "check"])
                .ok()
                .has("no trial key on this device");
            assert!(!d.state.join("keystore-trial.json").exists());
        }
        d.use_enclave().ok().has("are now sealed by the");
        assert!(d.sealed().exists() && !d.plain().exists());
        let sealed: serde_json::Value = serde_json::from_slice(&read(&d.sealed())).unwrap();
        let record = trial(&d);
        assert_eq!(
            record["public"], sealed["public"],
            "{name}: the one key of this run is the trial's and the secrets'"
        );
        for command in [&["status"][..], &["keystore"]] {
            d.run(command)
                .ok()
                .lacks("sealed to a key that was made at the move")
                .lacks("belongs to another key");
        }
        d.run(&["keystore"])
            .ok()
            .has("Trial        ended: its key holds the secrets");
        let json: serde_json::Value =
            serde_json::from_str(&d.run(&["keystore", "--json"]).ok().stdout).unwrap();
        assert_eq!(json["key_store"]["trial"]["key_holds_secrets"], true);
        d.run(&["ls"]).ok();
    }
}

/// What an interrupted command leaves beside a sealed store does not stay there unseen: a
/// plain temp copy of the secrets, a choice that still says `file`.
#[test]
fn leftovers_beside_a_sealed_store_are_reported_and_settled() {
    let lab = Lab::new();
    let d = lab.connected("a");
    let plain_copy = read(&d.plain());
    d.use_enclave().ok();
    assert!(d.sealed().exists() && !d.plain().exists());

    // A login killed between writing its temp file and the rename leaves this.
    let leftover = d.state.join(".secrets.json.tmp-e39388f231ce62ee");
    std::fs::write(&leftover, &plain_copy).unwrap();
    for command in [&["status"][..], &["keystore"]] {
        d.run(command)
            .ok()
            .has("Secure Enclave of this Mac (secrets.sealed)")
            .has("warning: 1 plain copy(ies) of this device's login and key from an interrupted write")
            .has("NOT worthless elsewhere");
    }
    let json: serde_json::Value =
        serde_json::from_str(&d.run(&["keystore", "--json"]).ok().stdout).unwrap();
    assert_eq!(json["key_store"]["plain_leftovers"], 1);
    let sealed = read(&d.sealed());
    d.use_enclave()
        .ok()
        .has("already sealed")
        .has("Nothing was moved.")
        .has("Removed 1 plain copy(ies) of the secrets");
    assert!(!leftover.exists());
    assert_eq!(read(&d.sealed()), sealed);
    d.run(&["status"]).ok().lacks("plain copy(ies)");

    // A logout removes such a copy too, and so does every save of a login (unit-tested:
    // `a_plain_temp_copy_of_the_secrets_is_reported_and_removed_by_the_next_save`).
    std::fs::write(&leftover, &plain_copy).unwrap();
    d.run(&["logout"]).ok();
    assert!(!leftover.exists(), "{:?}", d.files());
    d.login().ok();
    assert!(d.sealed().exists() && !d.plain().exists());

    // `use file`, killed after it recorded the choice: the secrets are still sealed, the
    // choice says `file`. `use enclave` used to answer "Nothing was changed" and leave it —
    // the warning stayed, and the next login after a logout went to the plain file.
    killed_at(&d, "file-choice-done", &["keystore", "use", "file"]);
    assert_eq!(d.choice().as_deref(), Some("file"));
    assert!(d.sealed().exists() && !d.plain().exists());
    d.run(&["status"])
        .ok()
        .has("Run `gclone keystore use file` again");
    d.use_enclave()
        .ok()
        .has("already sealed")
        .has("keystore.json now records the sealed store as this device's choice");
    assert_eq!(d.choice().as_deref(), Some("enclave"));
    d.run(&["status"])
        .ok()
        .lacks("Run `gclone keystore use file` again");
    d.run(&["logout"]).ok();
    d.login().ok();
    assert!(
        d.sealed().exists() && !d.plain().exists(),
        "the login after a logout is sealed again: {:?}",
        d.files()
    );
    d.works();

    // Several `use enclave` at once: one moves, the others find it done and say so.
    let e = lab.connected("b");
    let running: Vec<_> = (0..6)
        .map(|_| {
            e.command(&[
                "keystore",
                "use",
                "enclave",
                "--yes",
                "--passphrase-file",
                &e.pass,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn gclone")
        })
        .collect();
    let mut moved = 0;
    for child in running {
        let out = child.wait_with_output().expect("wait");
        let (stdout, stderr) = (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        );
        assert!(
            !stderr.contains("login changed"),
            "another move finished; nobody's login changed:\n{stderr}"
        );
        // A run that could not get the vault or the secrets lock in time says so (exit 1 or
        // 5); every other one ends well.
        if out.status.success() {
            assert!(
                stdout.contains("are now sealed by")
                    || stdout.contains("finished while this one ran")
                    || stdout.contains("already sealed"),
                "{stdout}\n{stderr}"
            );
            moved += usize::from(stdout.contains("are now sealed by"));
        } else {
            assert!(
                stderr.contains("another gclone") || stderr.contains("busy"),
                "{stdout}\n{stderr}"
            );
        }
    }
    assert_eq!(moved, 1, "exactly one run moved the secrets");
    assert!(e.sealed().exists() && !e.plain().exists());
    e.works();
}

// ---------------------------------------------------------------------------------------------
// An older gclone on the same machine
// ---------------------------------------------------------------------------------------------

/// What the released gclone 0.4.0 does beside the new files (§17.28, E10): it must go on
/// working while the device is on `secrets.json`, and what it does on a sealed device is what
/// the README says. Runs with a real v0.4.0 binary named by `GCLONE_TEST_OLD_GCLONE` (the
/// `gclone` of the v0.4.0 release archive for this machine); without one it prints a visible
/// note and passes.
#[test]
fn the_released_0_4_0_binary_beside_the_new_files() {
    let Some(old_bin) = std::env::var_os("GCLONE_TEST_OLD_GCLONE").filter(|v| !v.is_empty()) else {
        eprintln!("SKIPPED: GCLONE_TEST_OLD_GCLONE names no gclone 0.4.0 binary");
        return;
    };
    let lab = Lab::new();
    // The choice `enclave` is on file for most of this test (`keystore use enclave`), so the
    // device behaves as §17.28 describes whatever the default is; the default itself is the
    // last part.
    let d = lab.device("a").without("GCLONE_KEYSTORE_TRIAL");
    let old_on = |d: &Device, args: &[&str]| -> Out {
        let out = Command::new(&old_bin)
            .args(args)
            .env_clear()
            .env("GCLONE_CONFIG_DIR", &d.config)
            .env("GCLONE_STATE_DIR", &d.state)
            .env("HOME", &d.home)
            .env("TZ", "UTC")
            .stdin(Stdio::null())
            .output()
            .expect("spawn the old gclone");
        Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    };
    let old = |args: &[&str]| -> Out { old_on(&d, args) };
    old(&["--version"]).ok().has("gclone 0.4.0");
    // The vault and the device are made by the old binary (it knows no test switch: the
    // keyfile has the production KDF parameters, which both binaries accept).
    old(&[
        "login",
        "--vault-dir",
        &d.vault,
        "--passphrase-file",
        &d.pass,
    ])
    .ok();
    let tree = lab.path("a-tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"alpha\n").unwrap();
    old(&["copy", &s(&tree), ":docs"]).ok();
    assert_eq!(
        d.files(),
        ["secrets.json"],
        "what gclone 0.4.0 keeps in the state root"
    );

    // The device is on secrets.json, with every new file beside it: CACHEDIR.TAG, the lock,
    // the backup attribute (macOS), a trial record, a choice.
    d.works();
    d.run(&["keystore", "use", "file"]).ok();
    std::fs::remove_file(d.state.join("keystore.json")).unwrap();
    d.works();
    assert!(d.state.join("keystore-trial.json").exists());
    let plain = read(&d.plain());
    old(&["ls", ":docs"]).ok().has("a.txt");
    old(&["status"]).ok().has("Head");
    let tree = lab.path("old-tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("from-old.txt"), b"old\n").unwrap();
    old(&["copy", &s(&tree), ":docs"]).ok();
    d.run(&["ls", ":docs"]).ok().has("from-old.txt");
    assert_eq!(
        read(&d.plain()),
        plain,
        "the old binary left the secrets as they were"
    );

    // Sealed: the old binary says "not signed in" (exit 4), and its logout does nothing.
    d.use_enclave().ok();
    let sealed = read(&d.sealed());
    old(&["ls"]).code(4).has("not connected (signed out)");
    old(&["logout"])
        .ok()
        .has("Not signed in on this device; nothing to do.");
    assert_eq!(
        read(&d.sealed()),
        sealed,
        "an older logout does not sign a sealed device out"
    );
    d.works();

    // Its login on the sealed device writes secrets.json; the new binary then uses that
    // file, reports both, and settles it. Nothing is lost.
    old(&[
        "login",
        "--vault-dir",
        &d.vault,
        "--passphrase-file",
        &d.pass,
    ])
    .ok();
    assert!(d.plain().exists() && d.sealed().exists());
    assert_eq!(read(&d.plain()), plain, "byte for byte the version-1 file");
    d.works();
    d.run(&["status"])
        .ok()
        .has("secrets.json and secrets.sealed both exist");
    // Its logout removes secrets.json and leaves the sealed file: the device is still
    // signed in for the new binary.
    old(&["logout"]).ok().has("Signed out on this device.");
    assert!(!d.plain().exists());
    assert_eq!(read(&d.sealed()), sealed);
    d.works();
    // `logout --forget` of the old binary leaves the sealed file as well.
    old(&[
        "login",
        "--vault-dir",
        &d.vault,
        "--passphrase-file",
        &d.pass,
    ])
    .ok();
    old(&["logout", "--forget", "--yes"]).ok();
    assert_eq!(read(&d.sealed()), sealed);
    assert!(!d.plain().exists() && !d.config.join("config.json").exists());
    // The new binary's logout is what signs a sealed device out.
    d.run(&["logout"]).ok().has("Signed out on this device.");
    assert!(!d.sealed().exists());

    // The way back for a machine that also runs the old binary: `keystore use file`.
    d.login().ok();
    assert!(d.sealed().exists(), "the choice was `enclave`");
    d.run(&["keystore", "use", "file"]).ok();
    old(&["ls", ":docs"]).ok().has("from-old.txt");

    // §17.30, the README's upgrade note: a device that gclone 0.4.0 made, on a Mac that
    // then runs this version. While the trial runs the old binary works beside it; the run
    // that completes the trial moves the secrets, and from then on the old binary says "not
    // connected" — until `gclone keystore use file`, which gives back the file it wrote and
    // keeps it.
    let lab = Lab::new();
    let e = lab.device("b").without("GCLONE_KEYSTORE_TRIAL");
    old_on(
        &e,
        &[
            "login",
            "--vault-dir",
            &e.vault,
            "--passphrase-file",
            &e.pass,
        ],
    )
    .ok();
    let tree = lab.path("b-tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"alpha\n").unwrap();
    old_on(&e, &["copy", &s(&tree), ":docs"]).ok();
    let written_by_old = read(&e.plain());
    at(&e, 0, "boot-a", "0x2030").works();
    at(&e, 1, "boot-a", "0x2").works();
    old_on(&e, &["ls", ":docs"]).ok().has("a.txt");
    assert_eq!(read(&e.plain()), written_by_old);
    at(&e, 2, "boot-b", "0x2").works();
    assert!(e.sealed().exists() && !e.plain().exists());
    old_on(&e, &["ls", ":docs"])
        .code(4)
        .has("not connected (signed out)");
    at(&e, 2, "boot-b", "0x2").works();
    // The owner does what the old binary says and signs in with it: a `secrets.json` with
    // keys beside the sealed store. From then on this version tests and moves nothing by
    // itself here, and the old binary keeps working day after day — it used to be broken
    // again three days and a restart later, and again after the next sign-in.
    old_on(
        &e,
        &[
            "login",
            "--vault-dir",
            &e.vault,
            "--passphrase-file",
            &e.pass,
        ],
    )
    .ok();
    assert!(e.plain().exists() && e.sealed().exists());
    let by_old_login = read(&e.plain());
    for (day, boot, session) in [
        (3, "boot-b", "0x2030"),
        (4, "boot-b", "0x2"),
        (5, "boot-c", "0x2030"),
        (6, "boot-c", "0x2"),
    ] {
        at(&e, day, boot, session).works();
        assert_eq!(read(&e.plain()), by_old_login, "day {day}");
        assert!(e.sealed().exists());
        old_on(&e, &["ls", ":docs"]).ok().has("a.txt");
    }
    at(&e, 6, "boot-c", "0x2030")
        .run(&["status"])
        .ok()
        .has("kept: nothing is tested or moved while secrets.sealed lies beside it")
        .has("update it first");
    at(&e, 6, "boot-c", "0x2030")
        .run(&["keystore", "use", "file"])
        .ok();
    assert_eq!(
        read(&e.plain()),
        written_by_old,
        "byte for byte the file gclone 0.4.0 wrote"
    );
    old_on(&e, &["ls", ":docs"]).ok().has("a.txt");
    at(&e, 7, "boot-d", "0x2").works();
    assert!(e.plain().exists() && !e.sealed().exists(), "it stays");
    eprintln!("old binary: gclone 0.4.0 was run beside the new key-store files");
}

// ---------------------------------------------------------------------------------------------
// Hardware
// ---------------------------------------------------------------------------------------------

/// The whole path with the real Secure Enclave, in separate processes: seal in one, open in
/// others, sixteen at once. Runs where an enclave key can be made; elsewhere it prints a
/// visible note and passes, unless `GCLONE_REQUIRE_ENCLAVE=1` makes a skip a failure. The
/// keys are not permanent: nothing is stored outside the test's temp directory, and no
/// Keychain item is made.
/// Whether the real Secure Enclave can be used by `d` (whose sealer is `real`) in this
/// session. Where it cannot, a visible note — or, with `GCLONE_REQUIRE_ENCLAVE=1`, a failure.
fn real_enclave_usable(d: &Device) -> bool {
    let required = std::env::var("GCLONE_REQUIRE_ENCLAVE").is_ok_and(|v| v == "1");
    let skip = |why: &str| {
        assert!(!required, "GCLONE_REQUIRE_ENCLAVE=1, but: {why}");
        eprintln!("SKIPPED: no Secure Enclave on this machine ({why})");
        false
    };
    if !cfg!(target_os = "macos") {
        return skip("not macOS");
    }
    let check = d.run(&["keystore", "check"]);
    if check.code != 0 {
        return skip(
            check
                .stdout
                .lines()
                .find(|l| l.contains("FAILED"))
                .unwrap_or("no key"),
        );
    }
    check.has("a Secure Enclave key can be made and used in this session");
    true
}

/// The length of a base64url member of an envelope or a record.
fn b64_len(v: &serde_json::Value) -> usize {
    v.as_str().expect("a string member").len()
}

/// §17.30 with the real Secure Enclave, in separate processes: a login that seals from the
/// start; and a device on the plain file whose trial — a real enclave key, opened by every
/// run — passes on the test clock, after which a run moves the secrets by itself. Skips like
/// the test below. Nothing is stored outside the test's temp directories.
#[test]
fn hardware_a_mac_seals_a_login_and_moves_a_tested_device_by_itself() {
    let lab = Lab::new();
    let d = lab
        .mac("a")
        .with(&[("GCLONE_TEST_KEYSTORE_SEALER", "real")])
        .without("GCLONE_TEST_KEYSTORE_MACHINE");
    if !real_enclave_usable(&d) {
        return;
    }
    // A fresh login: sealed by the enclave from its first save, no plain file.
    d.login()
        .ok()
        .has("sealed by this Mac's Secure Enclave (secrets.sealed)");
    assert_eq!(
        d.files(),
        ["CACHEDIR.TAG", "secrets.lock", "secrets.sealed"]
    );
    let envelope: serde_json::Value = serde_json::from_slice(&read(&d.sealed())).unwrap();
    assert_eq!(envelope["alg"], "ecies-p256-x963-sha256-aesgcm");
    assert_eq!(b64_len(&envelope["public"]), 87);
    assert!(
        b64_len(&envelope["key"]) > 300,
        "an enclave blob, not a private key"
    );
    lab.seed(&d, "a");
    d.works();
    std::thread::scope(|scope| {
        for _ in 0..16 {
            scope.spawn(|| d.works());
        }
    });
    d.run(&["status"])
        .ok()
        .has("Key store    Secure Enclave of this Mac (secrets.sealed)")
        .lacks("warning:");
    d.run(&["keystore", "use", "file"]).ok();
    assert!(d.plain().exists() && !d.sealed().exists());
    d.logout_leaves_nothing();

    // A device on the plain file (a login with the switch set, as gclone 0.5.0 left every
    // Mac): the trial's key is a real enclave key, made in one process and opened in others.
    let lab = Lab::new();
    let quiet = lab.connected("b");
    let original = read(&quiet.plain());
    let e = quiet
        .without("GCLONE_KEYSTORE_TRIAL")
        .with(&[("GCLONE_TEST_KEYSTORE_SEALER", "real")])
        .without("GCLONE_TEST_KEYSTORE_MACHINE");
    at(&e, 0, "boot-a", "0x2030").works();
    let record = trial(&e);
    assert!(
        b64_len(&record["key"]) > 300,
        "the trial's key is an enclave blob"
    );
    at(&e, 1, "boot-a", "0x2").works();
    assert_eq!(read(&e.plain()), original, "nothing moves before the bar");
    assert!(!e.sealed().exists());
    // The run that completes the trial moves the secrets — while fifteen others start.
    let completes = at(&e, 2, "boot-b", "0x2");
    std::thread::scope(|scope| {
        for _ in 0..16 {
            scope.spawn(|| completes.works());
        }
    });
    assert!(
        e.sealed().exists() && !e.plain().exists(),
        "{:?}",
        e.files()
    );
    assert!(e.note_owed());
    assert_eq!(e.choice(), None);
    let envelope: serde_json::Value = serde_json::from_slice(&read(&e.sealed())).unwrap();
    assert_eq!(
        envelope["key"], record["key"],
        "sealed to the key the trial exercised"
    );
    assert_eq!(trial(&e)["public"], envelope["public"]);
    completes.works();
    at(&e, 2, "boot-b", "0x2030")
        .with(&[("GCLONE_TEST_NOTES", "1")])
        .run(&["ls", ":docs"])
        .ok()
        .has(MOVE_NOTE);
    completes
        .run(&["keystore"])
        .ok()
        .has("Trial        ended: its key holds the secrets (3 days, a restart survived)")
        .lacks("warning:");
    completes.run(&["keystore", "use", "file"]).ok();
    assert_eq!(read(&e.plain()), original);
    completes.logout_leaves_nothing();
    eprintln!("hardware: a login was sealed from the start, and a tested device moved by itself");
}

#[test]
fn hardware_the_binary_moves_a_device_into_the_secure_enclave_and_back() {
    let lab = Lab::new();
    let d = lab
        .connected("a")
        .with(&[("GCLONE_TEST_KEYSTORE_SEALER", "real")])
        .without("GCLONE_TEST_KEYSTORE_MACHINE");
    if !real_enclave_usable(&d) {
        return;
    }
    let original = read(&d.plain());

    d.use_enclave()
        .ok()
        .has("sealed by the Secure Enclave of this Mac");
    assert!(d.sealed().exists() && !d.plain().exists());
    let envelope: serde_json::Value = serde_json::from_slice(&read(&d.sealed())).unwrap();
    assert_eq!(envelope["alg"], "ecies-p256-x963-sha256-aesgcm");
    // 65 bytes of public key and a blob of some hundred bytes, as base64url without padding.
    assert_eq!(b64_len(&envelope["public"]), 87);
    assert!(
        b64_len(&envelope["key"]) > 300,
        "an enclave blob, not a private key"
    );

    // Other processes open it: one after the other, then sixteen at once.
    d.works();
    std::thread::scope(|scope| {
        for _ in 0..16 {
            scope.spawn(|| d.works());
        }
    });
    d.run(&["keystore", "check"])
        .ok()
        .has("secrets.sealed opens in this session");
    // One key for two sealings: a re-login seals a new document to the same key.
    d.run(&["logout"]).ok();
    d.login().ok();
    assert!(d.sealed().exists() && !d.plain().exists());
    d.works();

    // A damaged blob never opens to something else.
    let good = read(&d.sealed());
    let mut damaged: serde_json::Value = serde_json::from_slice(&good).unwrap();
    let key = damaged["key"].as_str().unwrap().to_string();
    let flipped = if key.as_bytes()[40] == b'A' { 'B' } else { 'A' };
    damaged["key"] = format!("{}{}{}", &key[..40], flipped, &key[41..]).into();
    std::fs::write(d.sealed(), serde_json::to_vec(&damaged).unwrap()).unwrap();
    d.run(&["ls"]).code(4).has("Run `gclone login`");
    std::fs::write(d.sealed(), &good).unwrap();
    d.works();

    // And back to the plain file.
    d.run(&["keystore", "use", "file"]).ok();
    let back: serde_json::Value = serde_json::from_slice(&read(&d.plain())).unwrap();
    let before: serde_json::Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(back["keys"], before["keys"]);
    d.logout_leaves_nothing();
    eprintln!("hardware: a device was moved into the Secure Enclave store and back");
}

// ---------------------------------------------------------------------------------------------
// What the review of 0.5.1 found (§17.30)
// ---------------------------------------------------------------------------------------------

/// `gclone keystore use enclave` is the one move that checks the way back first: the key
/// against the vault, the passphrase against a keyfile. Also on a device whose trial this
/// very run completes: the command used to load the secrets like every other command, that
/// load made the automatic move, and the command then found the device sealed, said
/// "Nothing was moved", blamed an interrupted `use file`, and exited 0 — with a wrong
/// passphrase.
#[test]
fn use_enclave_checks_the_passphrase_also_where_the_trial_has_passed() {
    let lab = Lab::new();
    let (d, original) = lab.nearly_passed("a");
    let wrong = lab.path("wrong");
    std::fs::write(&wrong, "not the passphrase at all\n").unwrap();
    let completes = at(&d, 2, "boot-b", "0x2030");
    completes
        .run(&[
            "keystore",
            "use",
            "enclave",
            "--yes",
            "--passphrase-file",
            &s(&wrong),
        ])
        .code(4)
        .has("Wrong passphrase.")
        .has("Nothing was changed.")
        .lacks("already sealed")
        .lacks("Nothing was moved")
        .lacks("keystore.json now records");
    assert_eq!(read(&d.plain()), original, "{:?}", d.files());
    assert!(!d.sealed().exists() && !d.note_owed());
    assert_eq!(d.choice(), None);
    // The step of the trial was taken by that run: the record is complete, and the command
    // — with the passphrase — moves the secrets to the trial's key and records the choice.
    let record = trial(&d);
    assert!(record["key"].is_string());
    completes
        .use_enclave()
        .ok()
        .has("The passphrase opens the vault's keyfile.")
        .has("The secrets are sealed to the same key.")
        .has("are now sealed by the");
    assert!(d.sealed().exists() && !d.plain().exists());
    assert_eq!(d.choice().as_deref(), Some("enclave"));
    assert!(!d.note_owed(), "the command said it itself");
    let sealed: serde_json::Value = serde_json::from_slice(&read(&d.sealed())).unwrap();
    assert_eq!(sealed["public"], record["public"]);
    for command in [&["status"][..], &["keystore"]] {
        completes.run(command).ok().lacks("warning:");
    }
    // On a device that is sealed already — by itself: no choice was on file — the command
    // says what it did to keystore.json without inventing an interrupted `use file`.
    let (e, _) = lab.nearly_passed("b");
    let completes = at(&e, 2, "boot-b", "0x2030");
    completes.works();
    assert!(e.sealed().exists() && !e.plain().exists());
    completes
        .use_enclave()
        .ok()
        .has("already sealed")
        .has("keystore.json now records the sealed store as this device's choice.")
        .lacks("interrupted");
    assert_eq!(e.choice().as_deref(), Some("enclave"));
}

/// A device that the automatic move sealed is broken in a session the trial never saw; its
/// owner signs in again from that very session, and the login — which cannot seal there —
/// puts the device back on the plain file. That session's failure is the one thing gclone
/// knows about it: the trial that starts afterwards begins with it, `status` warns, and
/// nothing moves again until somebody looked. (It used to be dropped: the second trial passed
/// in the terminal and broke the same session a second time.)
#[test]
fn a_device_repaired_after_a_session_broke_it_is_not_moved_a_second_time() {
    let lab = Lab::new();
    let (d, _) = lab.nearly_passed("a");
    at(&d, 2, "boot-b", "0x2030").works();
    assert!(d.sealed().exists() && !d.plain().exists());
    // An ssh login, say: a session the trial did not see, and it cannot use the enclave.
    let broken = |day: u64, boot: &str| {
        at(&d, day, boot, "0x1020").with(&[("GCLONE_TEST_KEYSTORE_FAIL", "open")])
    };
    broken(3, "boot-b")
        .run(&["ls"])
        .code(4)
        .has("The Secure Enclave cannot be used in this session");
    broken(3, "boot-b")
        .login()
        .ok()
        .lacks("sealed by this Mac's Secure Enclave");
    assert!(d.plain().exists() && !d.sealed().exists());
    assert!(
        !d.note_owed(),
        "the note of the first move is about a store that is gone"
    );
    let record = trial(&d);
    assert!(record.get("key").is_none() && record["moved_ms"].is_u64());
    assert_eq!(record["unavailable"]["session"], "0x1020");
    broken(3, "boot-b").works();

    // The terminal: a new trial starts — with that failure on it.
    let terminal = at(&d, 3, "boot-b", "0x2030");
    terminal.works();
    let record = trial(&d);
    assert!(record["key"].is_string(), "a new trial: {record}");
    assert_eq!(record["failure_count"], 1, "{record}");
    assert_eq!(record["failures"][0]["session"], "0x1020");
    assert!(record.get("unavailable").is_none());
    terminal
        .run(&["status"])
        .ok()
        .has("warning: the Secure Enclave trial failed 1 time(s) in a session without graphic access")
        .has("Nothing is moved into the sealed store while a failure is on its record");
    // Days and restarts in the terminal alone: nothing moves, and the session keeps working.
    for (day, boot) in [(4, "boot-b"), (5, "boot-c"), (6, "boot-c"), (7, "boot-d")] {
        at(&d, day, boot, "0x2030").works();
        assert!(d.plain().exists() && !d.sealed().exists(), "day {day}");
    }
    broken(7, "boot-d").works();
    // Somebody looked: a new trial, clean.
    at(&d, 7, "boot-d", "0x2030")
        .run(&["keystore", "check", "--new-trial"])
        .ok();
    assert_eq!(trial(&d)["failure_count"], 0);
}

/// A sealed device in a session where the call into the Secure Enclave does not return.
/// Before the move such a session lost two seconds once (the trial's step); after it — the
/// device still never having asked for the sealed store — every command stood still for
/// good, `status` and `keystore` included, and a `keystore use file` there held the secrets
/// lock against the session that could have repaired the device. Now each call into the
/// enclave is bounded: exit 4 with the text for a session that cannot use the enclave.
#[test]
fn a_sealed_device_whose_enclave_does_not_answer_fails_in_bounded_time() {
    let lab = Lab::new();
    let (d, original) = lab.nearly_passed("a");
    at(&d, 2, "boot-b", "0x2030").works();
    assert!(d.sealed().exists() && !d.plain().exists());
    let sealed = read(&d.sealed());
    let stuck = at(&d, 3, "boot-b", "0x1020").with(&[("GCLONE_TEST_KEYSTORE_FAIL", "hang")]);
    // The test's bound for most commands; the real one is shown once, below.
    let quick = stuck.with(&[("GCLONE_TEST_KEYSTORE_WAIT_MS", "400")]);
    let timed = |d: &Device, args: &[&str]| {
        let before = Instant::now();
        let out = d.run(args);
        (out, before.elapsed())
    };
    let within = Duration::from_secs(8);

    let (out, took) = timed(&quick, &["ls", ":docs"]);
    assert!(took < within, "ls: {took:?}");
    out.code(4)
        .has("The Secure Enclave cannot be used in this session (the Secure Enclave did not answer within 400 ms)")
        .has("Do not sign in again")
        .has("`gclone keystore use file` — from a session where it works")
        .lacks("gclone login");
    let (out, took) = timed(&quick, &["status"]);
    assert!(took < within, "status: {took:?}");
    out.code(4).has("the Secure Enclave did not answer");
    let (out, took) = timed(&quick, &["keystore"]);
    assert!(took < within, "keystore: {took:?}");
    out.ok()
        .has("Key store    secrets.sealed — cannot be opened here")
        .has("the Secure Enclave did not answer");
    let (out, took) = timed(&quick, &["keystore", "check"]);
    assert!(took < within, "keystore check: {took:?}");
    out.code(1)
        .has("New key      FAILED: the Secure Enclave did not answer")
        .has("secrets.sealed does NOT open");
    // `keystore use file` there fails — and lets go of the secrets lock.
    let (out, took) = timed(&quick, &["keystore", "use", "file"]);
    assert!(took < within, "keystore use file: {took:?}");
    out.code(1)
        .has("Nothing can be moved")
        .has("the Secure Enclave did not answer");
    assert_eq!(read(&d.sealed()), sealed, "nothing was changed");
    assert!(!d.plain().exists());
    assert_eq!(d.choice(), None);

    // The real bound, once: ten seconds, not for ever.
    let (out, took) = timed(&stuck, &["ls", ":docs"]);
    assert!(
        took >= Duration::from_secs(10) && took < Duration::from_secs(25),
        "{took:?}"
    );
    out.code(4)
        .has("the Secure Enclave did not answer within 10 s");

    // From a session that works, the device is as it was, and the way back is open.
    let fine = at(&d, 3, "boot-b", "0x2030");
    fine.works();
    fine.run(&["keystore", "use", "file"]).ok();
    assert_eq!(read(&d.plain()), original);
    quick.works();
}

/// `gclone logout` and `gclone login` in the middle of a trial do not jump its bar: the
/// device worked from `secrets.json` a moment ago, with whatever runs unattended on it, and
/// the trial has not seen a restart or all of that. The login goes to the plain file, the
/// trial goes on, and a session that cannot use the enclave still gets to say so.
#[test]
fn a_logout_and_a_login_in_the_middle_of_a_trial_do_not_jump_its_bar() {
    let lab = Lab::new();
    let (d, _) = lab.nearly_passed("a");
    let now = at(&d, 1, "boot-a", "0x2030");
    now.run(&["status"])
        .ok()
        .has("Secure Enclave trial: 2 of 3 days, no restart seen yet");
    let record = read(&d.state.join("keystore-trial.json"));
    now.run(&["logout"]).ok();
    now.login()
        .ok()
        .has("Connected to vault")
        .lacks("sealed by this Mac's Secure Enclave");
    assert!(
        d.plain().exists() && !d.sealed().exists(),
        "{:?}",
        d.files()
    );
    assert_eq!(
        read(&d.state.join("keystore-trial.json")),
        record,
        "the trial goes on as it was"
    );
    now.run(&["status"])
        .ok()
        .has("Key store    plain file secrets.json (0600) — Secure Enclave trial: 2 of 3 days, no restart seen yet")
        .lacks("warning:");
    // A job in a session the trial had not seen yet, which cannot use the enclave: it works
    // from the plain file and leaves the failure that stops the move.
    at(&d, 1, "boot-a", "0x1020")
        .with(&[("GCLONE_TEST_KEYSTORE_FAIL", "open")])
        .works();
    assert_eq!(trial(&d)["failure_count"], 1);
    at(&d, 2, "boot-b", "0x2030").works();
    assert!(d.plain().exists() && !d.sealed().exists());

    // Signing in again WITHOUT a logout, on a device that works from the plain file, changes
    // nothing either — the trial decides — also where no trial had begun yet (a device that
    // gclone 0.5.0 left, whose first command with this version is `login`).
    let quiet = lab.connected("b");
    let original = read(&quiet.plain());
    let e = at(
        &quiet.without("GCLONE_KEYSTORE_TRIAL"),
        0,
        "boot-a",
        "0x2030",
    );
    assert!(!e.state.join("keystore-trial.json").exists());
    e.login()
        .ok()
        .has("already connected")
        .lacks("sealed by this Mac's Secure Enclave");
    assert_eq!(read(&e.plain()), original, "byte for byte");
    assert!(!e.sealed().exists() && !e.note_owed());
    assert!(
        e.state.join("keystore-trial.json").exists(),
        "the trial began"
    );
    let (f, original) = lab.nearly_passed("c");
    at(&f, 1, "boot-a", "0x2030")
        .login()
        .ok()
        .lacks("sealed by this Mac's Secure Enclave");
    assert_eq!(read(&f.plain()), original, "byte for byte");
    assert!(!f.sealed().exists());
}

/// Three calendar days are not three days: a run at 23:59, one the next day and one at 00:01
/// of the day after are 24 hours and two minutes, in which a daily job has come around once
/// at best. The trial passes when its newest success is 48 hours after its first.
#[test]
fn three_calendar_days_within_little_more_than_one_do_not_pass_the_trial() {
    let lab = Lab::new();
    let quiet = lab.connected("a");
    let original = read(&quiet.plain());
    let d = quiet.without("GCLONE_KEYSTORE_TRIAL");
    let clock = |ms: u64, boot: &str| {
        d.with(&[
            ("GCLONE_TEST_NOW_MS", &ms.to_string()),
            ("GCLONE_TEST_BOOT", boot),
            ("GCLONE_TEST_SESSION", "0x2030"),
        ])
    };
    let minute = 60_000;
    // 00:00 UTC of the day after the test clock's start.
    let midnight = (START / DAY + 1) * DAY;
    clock(midnight - minute, "boot-a").works();
    clock(midnight + 60 * minute, "boot-b").works();
    let third = clock(midnight + DAY + minute, "boot-b");
    third.works();
    assert_eq!(read(&d.plain()), original, "{:?}", d.files());
    assert!(!d.sealed().exists() && !d.note_owed());
    third
        .run(&["status"])
        .ok()
        .has("Secure Enclave trial: 3 days, not yet 48 hours apart, a restart survived");
    let json: serde_json::Value =
        serde_json::from_str(&third.run(&["keystore", "--json"]).ok().stdout).unwrap();
    assert_eq!(json["key_store"]["trial"]["days"], 3);
    assert_eq!(json["key_store"]["trial"]["restart"], true);
    assert_eq!(json["key_store"]["trial"]["complete"], false);
    // Later the same day, short of 48 hours: still nothing.
    clock(midnight + DAY + 12 * 60 * minute, "boot-b").works();
    assert_eq!(read(&d.plain()), original);
    // 48 hours after the first success — the same day, boot and session as before: the run
    // that makes the trial old enough completes it, and moves.
    clock(midnight - minute + 2 * DAY, "boot-b").works();
    assert!(
        d.sealed().exists() && !d.plain().exists(),
        "{:?}",
        d.files()
    );
    assert!(d.note_owed());
}

/// After the automatic move, three ordinary things seal the secrets to a key made then: a
/// `logout` and a `login`; a `login` after the sealed key died (the files on another Mac —
/// the documented way back); `keystore use file` and `keystore use enclave`. None of them
/// leaves the record of the trial that ended at the first move as "evidence for another
/// key": `status` and `keystore` used to warn about that for good — "the secrets are sealed
/// to a key that was made at the move" — about a key made at a login.
#[test]
fn a_login_or_a_move_after_the_automatic_move_leaves_no_warning_about_another_key() {
    for case in [
        "logout, login",
        "another Mac, login",
        "use file, use enclave",
    ] {
        let lab = Lab::new();
        let (d, _) = lab.nearly_passed("a");
        let mine = at(&d, 2, "boot-b", "0x2");
        mine.works();
        assert!(d.sealed().exists() && !d.plain().exists(), "{case}");
        assert!(d.note_owed(), "{case}: moved without a terminal");
        mine.run(&["status"]).ok().lacks("warning:");
        let first: serde_json::Value = serde_json::from_slice(&read(&d.sealed())).unwrap();
        let after = match case {
            "logout, login" => {
                mine.run(&["logout"]).ok();
                assert!(
                    !d.note_owed(),
                    "{case}: a logout takes the owed note with it"
                );
                mine.login()
                    .ok()
                    .has("sealed by this Mac's Secure Enclave (secrets.sealed)");
                mine
            }
            "another Mac, login" => {
                let there = mine.with(&[("GCLONE_TEST_KEYSTORE_MACHINE", "mac-2")]);
                there
                    .run(&["ls"])
                    .code(4)
                    .has("This Mac's Secure Enclave cannot open this device's sealed key")
                    .has("Run `gclone login`");
                there
                    .login()
                    .ok()
                    .has("sealed by this Mac's Secure Enclave (secrets.sealed)");
                assert!(
                    !d.note_owed(),
                    "{case}: the login said itself where the secrets are"
                );
                there
            }
            _ => {
                mine.run(&["keystore", "use", "file"]).ok();
                mine.use_enclave().ok().has("are now sealed by the");
                mine
            }
        };
        assert!(
            d.sealed().exists() && !d.plain().exists(),
            "{case}: {:?}",
            d.files()
        );
        let now: serde_json::Value = serde_json::from_slice(&read(&d.sealed())).unwrap();
        assert_ne!(now["public"], first["public"], "{case}: a key made now");
        for (day, boot) in [(2, "boot-b"), (8, "boot-c")] {
            let later = at(&after, day, boot, "0x2030").with(&[("GCLONE_TEST_NOTES", "1")]);
            later
                .run(&["ls", ":docs"])
                .ok()
                .has("a.txt")
                .lacks(MOVE_NOTE);
            for command in [&["status"][..], &["keystore"]] {
                later
                    .run(command)
                    .ok()
                    .has("Secure Enclave of this Mac (secrets.sealed)")
                    .lacks("sealed to a key that was made at the move")
                    .lacks("belongs to another key")
                    .lacks("NEW key")
                    .lacks("warning:");
            }
            later
                .run(&["keystore"])
                .ok()
                .has("Trial        none: the secrets were sealed at a login, or by `gclone keystore use enclave`");
            let json: serde_json::Value =
                serde_json::from_str(&later.run(&["keystore", "--json"]).ok().stdout).unwrap();
            assert_eq!(
                json["key_store"]["trial"],
                serde_json::Value::Null,
                "{case}"
            );
        }
    }
}

/// What gclone 0.5.0 left behind `gclone keystore use enclave` as the first command after a
/// login: a trial record of one day, ended at a move to another key. After the upgrade
/// `status` and `keystore` went on warning about it for good. A trial that had only begun is
/// no evidence anybody could mistake: nothing warns, `gclone keystore` says what there is,
/// and `gclone keystore check --new-trial` forgets the record.
#[test]
fn a_record_that_0_5_0_left_at_its_move_is_not_warned_about_for_good() {
    let lab = Lab::new();
    let quiet = lab.connected("a");
    let d = at(
        &quiet.without("GCLONE_KEYSTORE_TRIAL"),
        0,
        "boot-a",
        "0x2030",
    );
    // The state, made the way 0.5.0 made it: a trial that has just begun, and a move that
    // cannot use its key.
    d.works();
    let trial_public = trial(&d)["public"].clone();
    d.with(&[("GCLONE_TEST_KEYSTORE_FAIL", "open-stored")])
        .use_enclave()
        .ok();
    let sealed: serde_json::Value = serde_json::from_slice(&read(&d.sealed())).unwrap();
    assert_ne!(sealed["public"], trial_public);
    let record = trial(&d);
    assert_eq!(record["public"], trial_public);
    assert!(record["moved_ms"].is_u64() && record["ok"].as_array().unwrap().len() == 1);

    for (day, boot) in [(0, "boot-a"), (6, "boot-b")] {
        let later = at(&d, day, boot, "0x2030");
        later.run(&["status"]).ok().lacks("warning:");
        later
            .run(&["keystore"])
            .ok()
            .has("Trial        none for the key that holds the secrets (a trial that had only begun ended when they were sealed)")
            .lacks("NEW key")
            .lacks("did not open at that moment")
            .lacks("warning:");
    }
    let json: serde_json::Value =
        serde_json::from_str(&d.run(&["keystore", "--json"]).ok().stdout).unwrap();
    assert_eq!(json["key_store"]["trial"]["key_holds_secrets"], false);
    // `--new-trial` on a sealed device forgets the record and starts nothing.
    d.run(&["keystore", "check", "--new-trial"])
        .ok()
        .has("the trial's record was discarded (this device's secrets are sealed");
    d.run(&["keystore"])
        .ok()
        .has("Trial        none: the secrets were sealed at a login, or by `gclone keystore use enclave`");
    let json: serde_json::Value =
        serde_json::from_str(&d.run(&["keystore", "--json"]).ok().stdout).unwrap();
    assert_eq!(json["key_store"]["trial"], serde_json::Value::Null);
    d.works();
}

/// An older gclone on the same Mac after the automatic move. gclone 0.4.0 says "not
/// connected", its owner signs in with it, and it writes a `secrets.json` with keys beside
/// `secrets.sealed`. This version then used to start a new trial and, three days and a
/// restart later, remove that file again — the older gclone's job broke a second time, and
/// a third. Now nothing is tested or moved while the two files lie side by side, and
/// `status` says what settles it. (With a real 0.4.0 binary:
/// `the_released_0_4_0_binary_beside_the_new_files`.)
#[test]
fn an_older_gclones_login_beside_the_sealed_store_is_not_moved_again() {
    let lab = Lab::new();
    let (d, original) = lab.nearly_passed("a");
    at(&d, 2, "boot-b", "0x2").works();
    assert!(d.sealed().exists() && !d.plain().exists());
    let sealed = read(&d.sealed());
    // What gclone 0.4.0's login writes for this login and key: the version-1 file.
    std::fs::write(d.plain(), &original).unwrap();
    std::fs::set_permissions(d.plain(), std::fs::Permissions::from_mode(0o600)).unwrap();
    let record = read(&d.state.join("keystore-trial.json"));
    for (day, boot, session) in [
        (3, "boot-b", "0x2030"),
        (4, "boot-b", "0x2"),
        (5, "boot-c", "0x2030"),
        (6, "boot-c", "0x2"),
        (9, "boot-d", "0x2030"),
    ] {
        at(&d, day, boot, session).works();
        assert_eq!(read(&d.plain()), original, "day {day}");
        assert_eq!(read(&d.sealed()), sealed, "day {day}");
    }
    assert_eq!(
        read(&d.state.join("keystore-trial.json")),
        record,
        "no new trial was started"
    );
    let later = at(&d, 9, "boot-d", "0x2030");
    later
        .run(&["status"])
        .ok()
        .has("Key store    plain file secrets.json (0600) — kept: nothing is tested or moved while secrets.sealed lies beside it")
        .has("secrets.json and secrets.sealed both exist (an interrupted move, or an older gclone signed in here)")
        .has("Until then gclone tests and moves nothing by itself here")
        .has("update it first")
        .lacks("finished by the next run")
        .lacks("Secure Enclave trial:");
    let json: serde_json::Value =
        serde_json::from_str(&later.run(&["keystore", "--json"]).ok().stdout).unwrap();
    assert_eq!(json["key_store"]["blocked_by_sealed"], true);
    // The owner settles it: the plain file for good (the older gclone stays in use) …
    later
        .run(&["keystore", "use", "file"])
        .ok()
        .has("a sealed copy of the same key");
    assert_eq!(read(&d.plain()), original);
    assert!(!d.sealed().exists());
    at(&d, 12, "boot-e", "0x2030").works();
    assert_eq!(read(&d.plain()), original);
    // … or, the older gclone updated, the sealed store at once.
    later.use_enclave().ok().has("are now sealed by the");
    assert!(d.sealed().exists() && !d.plain().exists());
    later.run(&["status"]).ok().lacks("warning:");
}

/// The marker of an owed note about a move (`keystore-note.due`) is unknown to gclone 0.5.0
/// and older: their `logout` leaves it. A login of this version then seals from the start
/// and says so — and the next run on a terminal used to add the note of the automatic move,
/// "gclone tested it over several days and a restart first; the plain secrets.json is gone",
/// about a store that the login had just begun.
#[test]
fn a_note_that_an_older_logout_left_owed_is_not_shown_about_a_new_login() {
    let lab = Lab::new();
    let (d, _) = lab.nearly_passed("a");
    at(&d, 2, "boot-b", "0x2").works();
    assert!(d.sealed().exists() && d.note_owed());
    // An older gclone's logout: the secrets go, the marker stays.
    std::fs::remove_file(d.sealed()).unwrap();
    assert!(d.note_owed());
    let person = at(&d, 3, "boot-b", "0x2030").with(&[("GCLONE_TEST_NOTES", "1")]);
    person
        .login()
        .ok()
        .has("sealed by this Mac's Secure Enclave (secrets.sealed)")
        .lacks(MOVE_NOTE);
    assert!(!d.note_owed(), "{:?}", d.files());
    person
        .run(&["ls", ":docs"])
        .ok()
        .has("a.txt")
        .lacks("note:");

    // This version's own logout takes the marker with it.
    let (e, _) = lab.nearly_passed("b");
    at(&e, 2, "boot-b", "0x2").works();
    assert!(e.note_owed());
    let person = at(&e, 3, "boot-b", "0x2030").with(&[("GCLONE_TEST_NOTES", "1")]);
    at(&e, 3, "boot-b", "0x2").run(&["logout"]).ok();
    assert!(!e.note_owed());
    person.login().ok().lacks(MOVE_NOTE);
    person.run(&["ls", ":docs"]).ok().lacks("note:");
}

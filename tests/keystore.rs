//! The device key store through the `gclone` binary (SPEC §8.2, §8.3, §17.28): `gclone
//! keystore`, the two moves and their crash points, a sealed store that does not open, the
//! trial, and — where there is one — the real Secure Enclave.
//!
//! Every test spawns the built debug binary against a directory vault. The sealer is the
//! stand-in of `GCLONE_TEST_KEYSTORE_SEALER=fake` (§7.1); a "Mac" is the name in
//! `GCLONE_TEST_KEYSTORE_MACHINE`. No test touches hardware, except the one whose name starts
//! with `hardware_`, and that one stores nothing outside its temp directory.

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

    /// A device of the lab's one directory vault, not signed in yet. Its sealer is the
    /// stand-in, as machine `mac-1`; no trial unless a test asks for one.
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
            .has("the stored key cannot be used any more")
            .has("Run `gclone login`; it asks for the passphrase.")
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

    // The login with the passphrase completes and leaves exactly one store. The choice was
    // `enclave`, and this login could not use the sealed file: it says where it ended.
    dead.login()
        .ok()
        .has("Connected to vault")
        .has("was saved to the plain file secrets.json although the sealed key store was chosen");
    assert!(d.plain().exists() && !d.sealed().exists());
    dead.works();
    // `keystore use enclave` moves it into this Mac's own store.
    dead.use_enclave().ok();
    assert!(d.sealed().exists() && !d.plain().exists());
    dead.works();
    dead.logout_leaves_nothing();
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

#[test]
fn the_trial_records_days_boots_and_sessions_and_the_move_takes_its_key() {
    const DAY: u64 = 86_400_000;
    let start: u64 = 1_794_400_000_000;
    let lab = Lab::new();
    let quiet = lab.connected("a");
    assert!(
        !quiet.state.join("keystore-trial.json").exists(),
        "GCLONE_KEYSTORE_TRIAL=0"
    );
    let original = read(&quiet.plain());
    let d = quiet.without("GCLONE_KEYSTORE_TRIAL");
    let at = |day: u64, boot: &str, session: &str| {
        d.with(&[
            ("GCLONE_TEST_NOW_MS", &(start + day * DAY).to_string()),
            ("GCLONE_TEST_BOOT", boot),
            ("GCLONE_TEST_SESSION", session),
        ])
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
    assert_eq!(
        read(&d.plain()),
        original,
        "the trial never touches the secrets"
    );
    at(0, "boot-a", "0x2030")
        .run(&["status"])
        .ok()
        .has("Key store    plain file secrets.json (0600) — Secure Enclave trial: 1 of 3 days, no restart seen yet");

    // The same day from cron, the next day, a clock jump without a restart.
    at(0, "boot-a", "0x2").works();
    at(1, "boot-a", "0x2030").works();
    at(40, "boot-a", "0x2030")
        .run(&["status"])
        .ok()
        .has("Secure Enclave trial: 3 days, no restart seen yet");
    // A restart: complete. The note is shown once, to a person.
    let complete = at(41, "boot-b", "0x2030");
    complete.works();
    complete
        .run(&["status"])
        .ok()
        .has("Secure Enclave trial complete: `gclone keystore use enclave`");
    let noted = complete
        .with(&[("GCLONE_TEST_NOTES", "1")])
        .run(&["ls"])
        .ok();
    let noted = noted
        .has("note: this Mac's Secure Enclave has opened gclone's test value on 4 days, across a restart")
        .has("`gclone keystore use file` keeps the plain file and silences this note.");
    drop(noted);
    complete
        .with(&[("GCLONE_TEST_NOTES", "1")])
        .run(&["ls"])
        .ok()
        .lacks("note: this Mac's Secure Enclave");
    assert!(trial(&d)["notes"]["ready_ms"].is_u64());
    let shown = complete.run(&["keystore"]).ok();
    shown
        .has("the test value opened on 4 day(s)")
        .has("a restart survived")
        .has("0x2 (without graphic access)")
        .has("0x2030 (with graphic access)");
    let json: serde_json::Value =
        serde_json::from_str(&complete.run(&["keystore", "--json"]).ok().stdout).unwrap();
    assert_eq!(json["key_store"]["trial"]["complete"], true);
    assert_eq!(json["key_store"]["trial"]["days"], 4);
    assert_eq!(json["key_store"]["trial"]["restart"], true);
    assert_eq!(
        json["key_store"]["trial"]["sessions"],
        serde_json::json!(["0x2", "0x2030"])
    );

    // `serve restic` and friends aside, a failure in one session is recorded and never
    // clears by itself — and the commands keep working: the trial decides nothing.
    let cron_fails = at(42, "boot-b", "0x2").with(&[("GCLONE_TEST_KEYSTORE_FAIL", "open")]);
    cron_fails.works();
    let record = trial(&d);
    assert_eq!(record["failure_count"], 1);
    assert_eq!(record["failures"][0]["session"], "0x2");
    assert_eq!(record["failures"][0]["fresh_key_ok"], false);
    at(43, "boot-b", "0x2030")
        .run(&["status"])
        .ok()
        .has("Secure Enclave trial: 5 days, a restart survived, 1 failure")
        .has("warning: the Secure Enclave trial failed 1 time(s) in a session without graphic access");
    // A new trial starts a new key and record.
    at(43, "boot-b", "0x2030")
        .run(&["keystore", "check", "--new-trial"])
        .ok()
        .has("a new key and a new record were started");
    let fresh = trial(&d);
    assert_eq!(fresh["failure_count"], 0);
    assert_eq!(fresh["ok"].as_array().unwrap().len(), 1);
    assert_ne!(fresh["key"], record["key"]);

    // The move seals the secrets to the trial's own key, and the record keeps the evidence.
    let trial_key = fresh["key"].clone();
    at(44, "boot-b", "0x2030")
        .use_enclave()
        .ok()
        .has("not seen by the trial");
    let sealed: serde_json::Value = serde_json::from_slice(&read(&d.sealed())).unwrap();
    assert_eq!(
        sealed["key"], trial_key,
        "sealed to the key the trial exercised"
    );
    let after = trial(&d);
    assert!(after.get("key").is_none() && after.get("canary").is_none());
    assert!(after["moved_ms"].is_u64());
    assert_eq!(after["ok"].as_array().unwrap().len(), 2);
    at(44, "boot-b", "0x2030")
        .run(&["keystore"])
        .ok()
        .has("Trial        ended: its key holds the secrets (2 days, no restart seen)");
    // A sealed device has no trial; back on the plain file by choice, none either.
    let written = read(&d.state.join("keystore-trial.json"));
    at(45, "boot-c", "0x2030").works();
    assert_eq!(read(&d.state.join("keystore-trial.json")), written);
    at(45, "boot-c", "0x2030")
        .run(&["keystore", "use", "file"])
        .ok();
    at(46, "boot-c", "0x2030").works();
    assert_eq!(read(&d.state.join("keystore-trial.json")), written);
    assert_eq!(read(&d.plain()), original);
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
    at(0, "boot-a", "0x2030").works();
    at(1, "boot-a", "0x2").works();
    at(2, "boot-b", "0x2030").works();
    at(2, "boot-b", "0x2030")
        .run(&["status"])
        .ok()
        .has("Secure Enclave trial complete");
    let trial_public = trial(&d)["public"].clone();

    at(2, "boot-b", "0x2030")
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
        .has("the trial's evidence (3 days, a restart survived) belongs to another key")
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
    let d = lab.device("a").without("GCLONE_KEYSTORE_TRIAL");
    let old = |args: &[&str]| -> Out {
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
#[test]
fn hardware_the_binary_moves_a_device_into_the_secure_enclave_and_back() {
    let required = std::env::var("GCLONE_REQUIRE_ENCLAVE").is_ok_and(|v| v == "1");
    let skip = |why: &str| {
        assert!(!required, "GCLONE_REQUIRE_ENCLAVE=1, but: {why}");
        eprintln!("SKIPPED: no Secure Enclave on this machine ({why})");
    };
    if !cfg!(target_os = "macos") {
        return skip("not macOS");
    }
    let lab = Lab::new();
    let d = lab
        .connected("a")
        .with(&[("GCLONE_TEST_KEYSTORE_SEALER", "real")])
        .without("GCLONE_TEST_KEYSTORE_MACHINE");
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
    let original = read(&d.plain());

    d.use_enclave()
        .ok()
        .has("sealed by the Secure Enclave of this Mac");
    assert!(d.sealed().exists() && !d.plain().exists());
    let envelope: serde_json::Value = serde_json::from_slice(&read(&d.sealed())).unwrap();
    assert_eq!(envelope["alg"], "ecies-p256-x963-sha256-aesgcm");
    let b64 = |v: &serde_json::Value| {
        use std::process::Command;
        let _ = Command::new("true");
        v.as_str().unwrap().len()
    };
    // 65 bytes of public key and a blob of some hundred bytes, as base64url without padding.
    assert_eq!(b64(&envelope["public"]), 87);
    assert!(
        b64(&envelope["key"]) > 300,
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

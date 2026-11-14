//! End-to-end tests of the `gclone` binary (SPEC §12.1 WP7, §13 item 8) — owned by WP7.
//!
//! Every test spawns the built debug binary. A "device" is one pair of config and state
//! directories (`GCLONE_CONFIG_DIR` / `GCLONE_STATE_DIR`): the login and the cached key live
//! under the state root. Vaults are directories (`--vault-dir`), except in `drive_mode`, which
//! drives the binary against `FakeDrive` — there every `login` passes `--no-browser` (no test
//! may open a browser) and the test plays the user: it reads the code the binary prints and
//! enters it at the fake "Google" (`FakeDrive::approve`).

#[path = "support/fake_drive.rs"]
mod fake_drive;

use std::collections::BTreeMap;
use std::io::{BufRead as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fake_drive::{FakeDrive, Route};

const BIN: &str = env!("CARGO_BIN_EXE_gclone");
const PASS: &str = "correct horse battery staple";
const NEW_PASS: &str = "a brand new passphrase, longer";

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
    fn stdout_has(self, needle: &str) -> Out {
        assert!(
            self.stdout.contains(needle),
            "stdout lacks {needle:?}\n--- stdout\n{}\n--- stderr\n{}",
            self.stdout,
            self.stderr
        );
        self
    }

    #[track_caller]
    fn stderr_has(self, needle: &str) -> Out {
        assert!(
            self.stderr.contains(needle),
            "stderr lacks {needle:?}\n--- stdout\n{}\n--- stderr\n{}",
            self.stdout,
            self.stderr
        );
        self
    }

    /// No command may ever die with a panic.
    #[track_caller]
    fn sane(self) -> Out {
        assert!(
            !self.stderr.contains("panicked"),
            "the binary panicked:\n{}",
            self.stderr
        );
        assert_ne!(self.code, 101, "the binary panicked:\n{}", self.stderr);
        // The tests capture both streams through pipes: nothing may be coloured there.
        assert!(
            !self.stdout.contains('\x1b') && !self.stderr.contains('\x1b'),
            "escape codes in piped output\n--- stdout\n{:?}\n--- stderr\n{:?}",
            self.stdout,
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
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env("GCLONE_CONFIG_DIR", &self.config)
            .env("GCLONE_STATE_DIR", &self.state)
            .env("GCLONE_TEST_FAST_KDF", "1")
            // No Secure Enclave trial in a spawned gclone (§8.2): what a test finds in the
            // state root is the same in every profile and on every machine. tests/keystore.rs
            // is where the key store is tested.
            .env("GCLONE_KEYSTORE_TRIAL", "0")
            .env("HOME", &self.home)
            .env("TZ", "UTC")
            .env_remove("GCLONE_AUTH_URL")
            .env_remove("GCLONE_LOG")
            .envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::null());
        cmd
    }

    #[track_caller]
    fn run(&self, args: &[&str]) -> Out {
        let out = self.command(args).output().expect("spawn gclone");
        Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
        .sane()
    }

    /// Raw bytes of stdout (for `cat`).
    #[track_caller]
    fn bytes(&self, args: &[&str]) -> Vec<u8> {
        let out = self.command(args).output().expect("spawn gclone");
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    fn secrets_file(&self) -> PathBuf {
        self.state.join("secrets.json")
    }

    fn token_file(&self) -> PathBuf {
        self.state.join("token.json")
    }

    fn config_file(&self) -> PathBuf {
        self.config.join("config.json")
    }

    fn json(&self, file: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(file).expect("read json")).expect("valid json")
    }

    /// The vault's state directory (`<state root>/<vault id>`).
    fn vault_state(&self) -> PathBuf {
        let id = self.json(&self.config_file())["vault_id"]
            .as_str()
            .expect("vault_id")
            .to_string();
        self.state.join(id)
    }

    /// `(name, id)` from the "This device" line of `status`.
    #[track_caller]
    fn identity(&self) -> (String, String) {
        let out = self.run(&["status"]).ok();
        let line = status_line(&out.stdout, "This device");
        let (name, id) = line.rsplit_once(" (").expect("This device  name (id)");
        (name.to_string(), id.trim_end_matches(')').to_string())
    }

    #[track_caller]
    fn head(&self) -> String {
        let out = self.run(&["status"]).ok();
        status_line(&out.stdout, "Head")
            .split_whitespace()
            .next()
            .expect("head value")
            .to_string()
    }
}

/// The text after a status label.
#[track_caller]
fn status_line(stdout: &str, label: &str) -> String {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(label))
        .unwrap_or_else(|| panic!("no {label:?} line in:\n{stdout}"))
        .trim()
        .to_string()
}

/// `head XXXX-XXXX` as printed at the end of an attaching `login`.
#[track_caller]
fn login_head(stdout: &str) -> String {
    let at = stdout.find("): head ").expect("login prints a head value") + "): head ".len();
    let head = &stdout[at..at + 9];
    assert!(is_head(head), "{head:?}");
    head.to_string()
}

fn is_head(s: &str) -> bool {
    let symbol = |c: char| c.is_ascii_digit() || c.is_ascii_uppercase();
    s.len() == 9
        && s.chars()
            .enumerate()
            .all(|(i, c)| if i == 4 { c == '-' } else { symbol(c) })
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

    fn device(&self, name: &str) -> Device {
        Device {
            config: self.path(&format!("{name}-config")),
            state: self.path(&format!("{name}-state")),
            home: self.path("home"),
            env: Vec::new(),
        }
    }

    fn file(&self, name: &str, content: &str) -> String {
        let path = self.path(name);
        std::fs::write(&path, content).expect("write file");
        s(&path)
    }

    /// The passphrase file most tests use.
    fn pass(&self) -> String {
        self.file("pass", &format!("{PASS}\n"))
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

/// A small tree with every kind of entry: a packed file, an empty file, a blob of its own, a
/// nested directory and an empty directory.
fn make_tree(root: &Path) {
    write(&root.join("a.txt"), b"alpha\n");
    write(&root.join("empty"), b"");
    write(&root.join("big.bin"), &pattern(1, 1_300_000));
    write(&root.join("sub/b.txt"), b"bravo\n");
    write(&root.join("sub/deep/c.bin"), &pattern(2, 70_000));
    std::fs::create_dir_all(root.join("hollow")).expect("mkdir");
}

/// Relative path → content (`None` for a directory). gclone's own dot files are left out.
fn snapshot(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    fn walk(dir: &Path, rel: &str, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("entry");
            let name = entry.file_name().into_string().expect("UTF-8 name");
            if name.starts_with(".gclone-") {
                continue;
            }
            let rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if entry.file_type().expect("type").is_dir() {
                out.insert(rel.clone(), None);
                walk(&entry.path(), &rel, out);
            } else {
                out.insert(rel, Some(std::fs::read(entry.path()).expect("read")));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, "", &mut out);
    out
}

fn copy_dir(from: &Path, to: &Path, skip: &[&str]) {
    std::fs::create_dir_all(to).expect("mkdir");
    for entry in std::fs::read_dir(from).expect("read_dir") {
        let entry = entry.expect("entry");
        let name = entry.file_name();
        if skip.iter().any(|s| name == *s) {
            continue;
        }
        let target = to.join(&name);
        if entry.file_type().expect("type").is_dir() {
            copy_dir(&entry.path(), &target, skip);
        } else {
            std::fs::copy(entry.path(), target).expect("copy");
        }
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o7777
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// Names of the vault's un-trashed keyfiles in a directory vault.
fn keyfiles(vault_root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(vault_root)
        .expect("read vault root")
        .map(|e| e.expect("entry").file_name().into_string().expect("name"))
        .filter(|n| n.starts_with("gclone-key-"))
        .collect();
    names.sort();
    names
}

/// A directory vault with one connected device that has pushed `make_tree` to `:docs`.
struct World {
    lab: Lab,
    vault: String,
    pass: String,
    src: PathBuf,
    a: Device,
}

fn world() -> World {
    let lab = Lab::new();
    let vault = s(&lab.path("vault"));
    let pass = lab.pass();
    let src = lab.path("src");
    make_tree(&src);
    let a = lab.device("a");
    a.run(&[
        "login",
        "--vault-dir",
        &vault,
        "--passphrase-file",
        &pass,
        "--device-name",
        "mbp",
    ])
    .ok()
    .stdout_has("Vault created. This device: \"mbp\".");
    a.run(&["copy", &s(&src), ":docs"]).ok();
    World {
        lab,
        vault,
        pass,
        src,
        a,
    }
}

impl World {
    /// Attaches one more device.
    #[track_caller]
    fn join(&self, name: &str) -> Device {
        let d = self.lab.device(name);
        d.run(&[
            "login",
            "--vault-dir",
            &self.vault,
            "--passphrase-file",
            &self.pass,
            "--device-name",
            name,
        ])
        .ok()
        .stdout_has("Connected to vault \"gclone\"");
        d
    }

    /// The vault folder itself (`DIR/<vault_name>`).
    fn vault_root(&self) -> PathBuf {
        Path::new(&self.vault).join("gclone")
    }
}

// ---------------------------------------------------------------------------------------------
// Directory mode: two devices, every command
// ---------------------------------------------------------------------------------------------

#[test]
fn two_devices_over_a_directory_vault() {
    let w = world();
    let (a, src) = (&w.a, &w.src);

    // The second device attaches; its output carries a head value to compare.
    let b = w.lab.device("b");
    let attached = b
        .run(&[
            "login",
            "--vault-dir",
            &w.vault,
            "--passphrase-file",
            &w.pass,
            "--device-name",
            "nas",
        ])
        .ok()
        .stdout_has("Connected to vault \"gclone\" (5 files). This device: \"nas\".")
        .stdout_has("Compare with `gclone status` on a device you trust")
        .stdout_has("5 files.");
    let head = login_head(&attached.stdout);
    // Once the first device has refreshed, both show the value the login printed.
    assert_eq!(a.head(), head);
    assert_eq!(b.head(), head);

    let out = w.lab.path("out");
    b.run(&["copy", ":docs", &s(&out)])
        .ok()
        .stdout_has("5 downloaded");
    assert_eq!(snapshot(src), snapshot(&out));
    assert_eq!(a.head(), b.head());

    // --- ls / tree / cat
    let listing = a.run(&["ls", ":docs"]).ok().stdout;
    assert_eq!(
        listing.lines().collect::<Vec<_>>(),
        ["a.txt", "big.bin", "empty", "hollow/", "sub/"]
    );
    let long = a.run(&["ls", "-l", ":docs"]).ok().stdout;
    let row = long
        .lines()
        .find(|l| l.ends_with("a.txt"))
        .expect("a.txt row");
    assert_eq!(row.split_whitespace().collect::<Vec<_>>()[..2], ["6", "B"]);
    assert!(
        row.contains("20") && row.contains(':'),
        "a date and a time: {row}"
    );
    assert!(
        long.lines()
            .any(|l| l.trim_start().starts_with('-') && l.ends_with("sub/"))
    );
    let recursive = a.run(&["ls", "-R", ":docs"]).ok().stdout;
    assert!(recursive.lines().any(|l| l == "sub/deep/c.bin"));
    assert!(recursive.lines().any(|l| l == "hollow/"));
    a.run(&["ls", ":docs/a.txt"]).ok().stdout_has("a.txt");
    a.run(&["ls", ":nope"]).code(1).stderr_has(":nope");

    let tree = a.run(&["tree"]).ok().stdout;
    assert!(tree.starts_with(":\n"), "{tree}");
    assert!(tree.contains("└── docs"));
    assert!(tree.contains("    ├── a.txt\n"), "{tree}");
    assert!(
        tree.contains("        └── deep\n            └── c.bin\n"),
        "{tree}"
    );
    assert!(tree.contains("4 directories, 5 files"), "{tree}");

    assert_eq!(a.bytes(&["cat", ":docs/a.txt"]), b"alpha\n");
    assert_eq!(
        a.bytes(&["cat", ":docs/a.txt", "--offset", "2", "--count", "3"]),
        b"pha"
    );
    let big = pattern(1, 1_300_000);
    assert_eq!(
        a.bytes(&[
            "cat",
            ":docs/big.bin",
            "--offset",
            "65530",
            "--count",
            "70000"
        ]),
        &big[65_530..135_530]
    );
    assert_eq!(
        a.bytes(&["cat", ":docs/big.bin", "--offset", "1299990"]),
        &big[1_299_990..]
    );
    assert_eq!(a.bytes(&["cat", ":docs/empty"]), b"");
    a.run(&["cat", ":docs/sub"])
        .code(2)
        .stderr_has("is a directory");
    a.run(&["cat", ":docs/absent"]).code(1);

    // --- mv / rm -r / restore
    a.run(&["mv", ":docs/a.txt", ":docs/renamed.txt"])
        .ok()
        .stdout_has("Moved :docs/a.txt to :docs/renamed.txt");
    a.run(&["mkdir", ":docs/new-dir"])
        .ok()
        .stdout_has("Created :docs/new-dir/");
    a.run(&["rm", ":docs/sub"]).code(2);
    a.run(&["rm", "-r", ":docs/sub"])
        .ok()
        .stdout_has("Removed 2 entries");
    let listing = a.run(&["ls", ":docs"]).ok().stdout;
    assert_eq!(
        listing.lines().collect::<Vec<_>>(),
        ["big.bin", "empty", "hollow/", "new-dir/", "renamed.txt"]
    );
    let versions = a
        .run(&["restore", "--list", ":docs/sub/b.txt"])
        .ok()
        .stdout_has("removed")
        .stdout_has("(deleted)")
        .stdout;
    let first = versions.lines().nth(1).expect("one version");
    assert!(first.trim_start().starts_with("1 "), "{first}");
    assert!(first.contains("6 B") && first.contains("mbp"), "{first}");
    a.run(&["restore", ":docs/sub/b.txt"])
        .ok()
        .stdout_has("Restored :docs/sub/b.txt");
    assert_eq!(a.bytes(&["cat", ":docs/sub/b.txt"]), b"bravo\n");
    a.run(&["restore", ":docs/never-there"]).code(1);
    a.run(&["restore", "--list", ":docs/never-there"])
        .ok()
        .stdout_has("No restorable version");

    // An overwritten version is listed as such and comes back with --version.
    let versions = w.lab.path("versions");
    write(&versions.join("f.txt"), b"first edition\n");
    a.run(&["copy", &s(&versions), ":versions"]).ok();
    write(&versions.join("f.txt"), b"the second edition\n");
    a.run(&["copy", &s(&versions), ":versions"]).ok();
    assert_eq!(
        a.bytes(&["cat", ":versions/f.txt"]),
        b"the second edition\n"
    );
    a.run(&["restore", "--list", ":versions/f.txt"])
        .ok()
        .stdout_has("(overwritten)");
    a.run(&["restore", ":versions/f.txt", "--version", "2"])
        .code(1);
    a.run(&["restore", ":versions/f.txt", "--version", "1"])
        .ok();
    assert_eq!(a.bytes(&["cat", ":versions/f.txt"]), b"first edition\n");

    // --- about / status
    a.run(&["about"])
        .ok()
        .stdout_has("Storage ")
        .stdout_has("Vault \"gclone\" ")
        .stdout_has(" files, ")
        .stdout_has("Index ")
        .stdout_has("last change ")
        .stdout_has("Transferred ")
        .stdout_has(" up, ")
        .stdout_has("in the last 24 h");
    let status = a.run(&["status"]).ok().stdout;
    assert!(status_line(&status, "Login").contains("directory vault"));
    assert!(status_line(&status, "Vault").starts_with("gclone ("));
    assert!(status_line(&status, "Vault").ends_with("format 1"));
    assert!(status_line(&status, "Head").ends_with("the same on every device that is up to date"));
    assert!(is_head(
        status_line(&status, "Head")
            .split_whitespace()
            .next()
            .unwrap()
    ));
    assert!(status_line(&status, "This device").starts_with("mbp ("));
    let devices = status_line(&status, "Devices");
    assert!(
        devices.contains("mbp (") && devices.contains("nas ("),
        "{devices}"
    );
    assert_eq!(status_line(&status, "Pending"), "none");
    let quiet = a.run(&["status", "-q"]).ok();
    assert_eq!(quiet.stdout, "", "status -q prints warnings only");

    // The other device follows with a sync and ends up with the same tree and head.
    b.run(&["sync", ":docs", &s(&out), "--yes"]).ok();
    let fresh = w.lab.path("fresh");
    a.run(&["copy", ":docs", &s(&fresh)]).ok();
    assert_eq!(snapshot(&out), snapshot(&fresh));
    assert_eq!(a.head(), b.head());

    // `login` again on a connected device changes nothing.
    let before = (
        std::fs::read(a.secrets_file()).unwrap(),
        std::fs::read(a.config_file()).unwrap(),
        a.head(),
    );
    a.run(&[
        "login",
        "--vault-dir",
        &w.vault,
        "--passphrase-file",
        &w.pass,
    ])
    .ok()
    .stdout_has("Nothing changed");
    a.run(&["login"]).ok().stdout_has("Nothing changed");
    let after = (
        std::fs::read(a.secrets_file()).unwrap(),
        std::fs::read(a.config_file()).unwrap(),
        a.head(),
    );
    assert!(before == after, "a repeated login must not change anything");
}

// ---------------------------------------------------------------------------------------------
// Passphrase rules, passwd, keyfile work bounds
// ---------------------------------------------------------------------------------------------

#[test]
fn passphrase_rules() {
    let w = world();
    let lab = &w.lab;

    // A wrong passphrase: exit 4, nothing stored.
    let wrong = lab.file("wrong", "this is not the passphrase\n");
    let b = lab.device("b");
    b.run(&[
        "login",
        "--vault-dir",
        &w.vault,
        "--passphrase-file",
        &wrong,
    ])
    .code(4)
    .stderr_has("Wrong passphrase");
    assert!(!b.secrets_file().exists(), "no key may be stored");
    assert!(!b.config_file().exists());
    b.run(&["ls"]).code(4);

    // Creating: 11 characters are refused, an empty file is refused (a passphrase is generated
    // only at the interactive prompt), and nothing is created.
    let other = s(&lab.path("other-vault"));
    let c = lab.device("c");
    for (name, content) in [("eleven", "elevenchars\n"), ("empty", ""), ("blank", "\n")] {
        let file = lab.file(name, content);
        let out = c
            .run(&["login", "--vault-dir", &other, "--passphrase-file", &file])
            .code(1)
            .stderr_has("at least 12 characters");
        assert!(!out.stdout.contains("Vault created"));
    }
    assert!(
        !Path::new(&other).join("gclone").exists(),
        "no vault folder"
    );
    assert!(!c.secrets_file().exists() && !c.config_file().exists());

    // No --passphrase-file and no terminal: a clear error, for creating and for attaching.
    c.run(&["login", "--vault-dir", &other])
        .code(2)
        .stderr_has("--passphrase-file");
    b.run(&["login", "--vault-dir", &w.vault])
        .code(2)
        .stderr_has("--passphrase-file");
    w.a.run(&["passwd"]).code(2).stderr_has("--passphrase-file");

    // A passphrase is never taken from argv: not as a positional, not as an option value.
    c.run(&["login", "--vault-dir", &other, PASS]).code(2);
    c.run(&["login", "--vault-dir", &other, "--passphrase", PASS])
        .code(2);
    c.run(&["passwd", PASS]).code(2);
    c.run(&["passwd", "--passphrase", PASS]).code(2);

    // The generated form is accepted in any spelling when entering it.
    let generated = lab.file("generated", "7K2M9-QXA41-TBZR8-D0HNW\n");
    let d = lab.device("d");
    let gen_vault = s(&lab.path("gen-vault"));
    d.run(&[
        "login",
        "--vault-dir",
        &gen_vault,
        "--passphrase-file",
        &generated,
    ])
    .ok();
    let sloppy = lab.file("sloppy", "7k2m9qxa41 tbzr8-doHNW\n");
    lab.device("e")
        .run(&[
            "login",
            "--vault-dir",
            &gen_vault,
            "--passphrase-file",
            &sloppy,
        ])
        .ok()
        .stdout_has("Connected to vault");

    // A TYPED passphrase that happens to have the shape of a generated one (26 letters, no
    // `u`) is set exactly as typed — what gclone 0.4.0 and a 0.4.0 hosted viewer make of it —
    // and the command says so. It then opens as typed, not in any other spelling.
    let words = lab.file("words", "the new victim passphrase long\n");
    let words_vault = s(&lab.path("words-vault"));
    let out = lab
        .device("f")
        .run(&[
            "login",
            "--vault-dir",
            &words_vault,
            "--passphrase-file",
            &words,
        ])
        .ok()
        .stderr_has("it is kept exactly as entered");
    assert!(!out.stderr.contains("the new victim"), "{}", out.stderr);
    lab.device("g")
        .run(&[
            "login",
            "--vault-dir",
            &words_vault,
            "--passphrase-file",
            &words,
        ])
        .ok()
        .stdout_has("Connected to vault");
    for other in [
        "The New Victim Passphrase Long\n",
        "THENE-WV1CT-1MPAS-SPHRA-SE10NG\n",
    ] {
        let file = lab.file("other-spelling", other);
        lab.device("h")
            .run(&[
                "login",
                "--vault-dir",
                &words_vault,
                "--passphrase-file",
                &file,
            ])
            .code(4)
            .stderr_has("Wrong passphrase");
    }
    // A generated passphrase in the form gclone displays: no note, any spelling opens.
    let long = lab.file("long", "7K2M9-QXA41-TBZR8-D0HNW-ABCDEF\n");
    let long_vault = s(&lab.path("long-vault"));
    let out = lab
        .device("i")
        .run(&[
            "login",
            "--vault-dir",
            &long_vault,
            "--passphrase-file",
            &long,
        ])
        .ok();
    assert!(!out.stderr.contains("kept exactly"), "{}", out.stderr);
    let sloppy = lab.file("sloppy-long", "7k2m9 qxa41 tbzr8 dohnw abcdef\n");
    lab.device("j")
        .run(&[
            "login",
            "--vault-dir",
            &long_vault,
            "--passphrase-file",
            &sloppy,
        ])
        .ok()
        .stdout_has("Connected to vault");
}

#[test]
fn several_vaults_and_an_orphan_folder() {
    let lab = Lab::new();
    let pass = lab.pass();
    let dir = lab.path("vaults");
    let dir_s = s(&dir);

    // A folder of the vault's name without a descriptor: what an interrupted creation leaves.
    std::fs::create_dir_all(&dir).unwrap();
    {
        use gclone::backend::{Backend as _, DirBackend, Handle};
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let backend = DirBackend::open(&dir).unwrap();
            // The root folder and its first child: creation died before the descriptor.
            let ids = backend.new_ids(2).await.unwrap();
            backend
                .create_folder(&ids[0], &Handle::top(), "gclone")
                .await
                .unwrap();
            backend
                .create_folder(&ids[1], &ids[0], "index")
                .await
                .unwrap();
        });
    }
    let a = lab.device("a");
    let out = a
        .run(&["login", "--vault-dir", &dir_s, "--passphrase-file", &pass])
        .code(1)
        .stderr_has("exists but holds no complete vault")
        .stderr_has("--vault-name");
    assert!(
        out.stderr
            .contains(&s(&std::fs::canonicalize(&dir).unwrap().join("gclone")))
    );
    assert!(!a.config_file().exists() && !a.secrets_file().exists());
    assert_eq!(
        std::fs::read_dir(&a.state).map(|d| d.count()).unwrap_or(0),
        0,
        "no state is kept for a vault that was never created"
    );
    for bad in ["", ".hidden", "a/b"] {
        a.run(&[
            "login",
            "--vault-dir",
            &dir_s,
            "--passphrase-file",
            &pass,
            "--vault-name",
            bad,
        ])
        .code(2);
    }
    a.run(&[
        "login",
        "--vault-dir",
        &dir_s,
        "--passphrase-file",
        &pass,
        "--vault-name",
        "first",
    ])
    .ok()
    .stdout_has("Vault created");

    // A second vault needs --new-vault; a plain login attaches to the one that exists.
    let b = lab.device("b");
    b.run(&[
        "login",
        "--vault-dir",
        &dir_s,
        "--passphrase-file",
        &pass,
        "--new-vault",
        "--vault-name",
        "second",
    ])
    .ok()
    .stdout_has("Vault created");
    let id_of = |d: &Device| {
        d.json(&d.config_file())["vault_id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (first, second) = (id_of(&a), id_of(&b));
    assert_ne!(first, second);
    assert_eq!(a.json(&a.config_file())["vault_name"], "first");
    assert_eq!(b.json(&b.config_file())["vault_name"], "second");

    // Several vaults and no terminal: an error that lists them and asks for --vault-id.
    let c = lab.device("c");
    c.run(&["login", "--vault-dir", &dir_s, "--passphrase-file", &pass])
        .code(2)
        .stderr_has("--vault-id")
        .stderr_has(&first)
        .stderr_has(&second)
        .stderr_has("\"first\"")
        .stderr_has("\"second\"");
    assert!(!c.config_file().exists());
    c.run(&[
        "login",
        "--vault-dir",
        &dir_s,
        "--passphrase-file",
        &pass,
        "--vault-id",
        "nonsense",
    ])
    .code(2);
    c.run(&[
        "login",
        "--vault-dir",
        &dir_s,
        "--passphrase-file",
        &pass,
        "--vault-id",
        &"0".repeat(32),
    ])
    .code(2)
    .stderr_has(&first);
    c.run(&[
        "login",
        "--vault-dir",
        &dir_s,
        "--passphrase-file",
        &pass,
        "--vault-id",
        &second.to_uppercase(),
    ])
    .ok()
    .stdout_has("Connected to vault \"second\"");
    assert_eq!(id_of(&c), second);
    // An attached device cannot be pointed at another vault without `logout --forget`.
    c.run(&["login", "--passphrase-file", &pass, "--vault-id", &first])
        .code(2)
        .stderr_has("gclone logout --forget");
    c.run(&["login", "--passphrase-file", &pass, "--new-vault"])
        .code(2)
        .stderr_has("gclone logout --forget");
}

/// Writes one line into a FIFO that a `login` reads as its `--passphrase-file`, waiting (with a
/// deadline) until the child has it open.
#[track_caller]
fn feed_fifo(fifo: &Path, line: &str) {
    use std::os::unix::fs::OpenOptionsExt as _;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        // Without a reader a non-blocking open for writing fails with ENXIO.
        let opened = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(fifo);
        match opened {
            Ok(mut f) => {
                f.write_all(line.as_bytes()).expect("write to the fifo");
                return;
            }
            Err(e) if e.raw_os_error() == Some(libc::ENXIO) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("the login never opened its passphrase file: {e}"),
        }
    }
}

/// §2.6 "two first devices", the losing side end to end (added by the integrator, SPEC §17.5):
/// a device whose discovery saw no vault creates one, finds an older vault right afterwards,
/// discards its own and attaches to the winner. The loser's discovery has to run before the
/// winner's vault exists, so its passphrase comes from a FIFO — `login` blocks on it after the
/// discovery, and the test creates the winner in between.
#[test]
fn a_lost_creation_race_switches_to_the_winner() {
    use std::io::Read as _;
    let lab = Lab::new();
    let pass = lab.pass();
    let dir = lab.path("vaults");
    let dir_s = s(&dir);
    let fifo = lab.path("fifo");
    let fifo_c = std::ffi::CString::new(s(&fifo)).unwrap();
    // SAFETY: a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);

    let b = lab.device("b");
    let mut child = b
        .command(&[
            "login",
            "--vault-dir",
            &dir_s,
            "--passphrase-file",
            &s(&fifo),
            "--vault-name",
            "late",
            "--device-name",
            "b",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gclone");
    let mut stderr = std::io::BufReader::new(child.stderr.take().expect("stderr"));
    let mut seen = String::new();
    let mut wait_for = |needle: &str| {
        loop {
            let mut line = String::new();
            let n = stderr.read_line(&mut line).expect("stderr");
            assert!(n > 0, "login ended before {needle:?}:\n{seen}");
            seen.push_str(&line);
            if line.contains(needle) {
                return;
            }
        }
    };
    // b's discovery found nothing; it now waits for the passphrase of the vault it will create.
    wait_for("No gclone vault found");

    // Meanwhile another device creates the vault.
    let a = lab.device("a");
    a.run(&[
        "login",
        "--vault-dir",
        &dir_s,
        "--passphrase-file",
        &pass,
        "--device-name",
        "a",
    ])
    .ok()
    .stdout_has("Vault created");

    // b creates its own vault with its own passphrase …
    feed_fifo(&fifo, "the passphrase chosen on b\n");
    wait_for("Creating vault \"late\"");
    // … loses, and asks for the passphrase of the winner.
    feed_fifo(&fifo, &format!("{PASS}\n"));
    stderr.read_to_string(&mut seen).expect("stderr");
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{seen}\n{stdout}");
    assert!(!seen.contains("panicked"), "{seen}");
    assert!(
        seen.contains("Another device created the vault a moment earlier")
            && seen.contains("NOT in use"),
        "{seen}"
    );
    assert!(
        stdout.contains("Connected to vault \"gclone\"") && !stdout.contains("Vault created"),
        "{stdout}"
    );

    // b is attached to a's vault, and nothing of its own vault is left: no folder in the
    // directory, no state directory, no key of it.
    let vault_id = |d: &Device| {
        d.json(&d.config_file())["vault_id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(vault_id(&a), vault_id(&b));
    assert_eq!(b.json(&b.config_file())["vault_name"], "gclone");
    assert!(!dir.join("late").exists(), "the losing vault was trashed");
    let mut state: Vec<String> = std::fs::read_dir(&b.state)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    state.sort();
    // The vault's state, the secrets, and what every login leaves beside them (§8.1, §8.3).
    let mut expected = [
        "CACHEDIR.TAG".to_string(),
        vault_id(&a),
        "secrets.json".to_string(),
        "secrets.lock".to_string(),
    ];
    expected.sort();
    assert_eq!(state, expected);
    b.run(&["ls"]).ok();
    assert_eq!(a.head(), b.head());
    let devices = status_line(&a.run(&["status"]).ok().stdout, "Devices");
    assert!(
        devices.contains("a (") && devices.contains("b ("),
        "{devices}"
    );

    // One vault is visible afterwards: a third device attaches without being asked which, with
    // the winner's passphrase — the one set on b opens nothing.
    let c = lab.device("c");
    let wrong = lab.file("pass-b", "the passphrase chosen on b\n");
    c.run(&["login", "--vault-dir", &dir_s, "--passphrase-file", &wrong])
        .code(4)
        .stderr_has("Wrong passphrase");
    c.run(&["login", "--vault-dir", &dir_s, "--passphrase-file", &pass])
        .ok()
        .stdout_has("Connected to vault \"gclone\"");
}

#[test]
fn passwd_writes_a_new_keyfile() {
    let w = world();
    let lab = &w.lab;
    let b = w.join("b");
    let new_pass = lab.file("new-pass", &format!("{NEW_PASS}\n"));
    assert_eq!(keyfiles(&w.vault_root()).len(), 1);

    w.a.run(&["passwd", "--passphrase-file", &new_pass])
        .ok()
        .stdout_has(
            "Passphrase changed. New devices need the new passphrase; connected devices are unaffected.",
        );
    let files = keyfiles(&w.vault_root());
    assert_eq!(files.len(), 1, "exactly one un-trashed keyfile: {files:?}");
    assert!(files[0].starts_with("gclone-key-00000002-"), "{files:?}");

    // Connected devices keep working without a prompt.
    b.run(&["ls", ":docs"]).ok().stdout_has("a.txt");
    w.a.run(&["ls", ":docs"]).ok();

    // A third device attaches with the new passphrase and not with the old one.
    let c = lab.device("c");
    c.run(&[
        "login",
        "--vault-dir",
        &w.vault,
        "--passphrase-file",
        &w.pass,
    ])
    .code(4)
    .stderr_has("Wrong passphrase");
    assert!(!c.secrets_file().exists());
    c.run(&[
        "login",
        "--vault-dir",
        &w.vault,
        "--passphrase-file",
        &new_pass,
    ])
    .ok()
    .stdout_has("Connected to vault");
    c.run(&["cat", ":docs/a.txt"]).ok().stdout_has("alpha");

    // A planted name with the highest possible generation: a plain error, no wrap, no panic.
    let planted = w.vault_root().join("gclone-key-ffffffff-00000000");
    let out = b.run(&["check"]).ok();
    assert!(
        !out.stderr.contains("under a keyfile's name"),
        "{}",
        out.stderr
    );
    std::fs::write(&planted, b"junk").unwrap();
    // Two objects under keyfile names — what a `passwd` that was killed between its put and
    // its retirement leaves too — are what `check` warns about.
    b.run(&["check"])
        .ok()
        .stderr_has("warning: 2 objects under a keyfile's name are in the vault folder: gclone-key-ffffffff-00000000, gclone-key-00000002-")
        .stderr_has("Run `gclone passwd` again");
    let out = b
        .run(&["passwd", "--passphrase-file", &w.pass])
        .code(1)
        .stderr_has("keyfile generation exhausted by gclone-key-ffffffff-00000000")
        .stderr_has("run `gclone passwd` again");
    assert!(!out.stderr.contains("overflow"));
    assert!(
        keyfiles(&w.vault_root())
            .iter()
            .any(|n| n.starts_with("gclone-key-00000002-"))
    );
    std::fs::remove_file(&planted).unwrap();
    b.run(&["passwd", "--passphrase-file", &w.pass]).ok();
    let files = keyfiles(&w.vault_root());
    assert_eq!(files.len(), 1, "{files:?}");
    assert!(files[0].starts_with("gclone-key-00000003-"), "{files:?}");
    lab.device("d")
        .run(&[
            "login",
            "--vault-dir",
            &w.vault,
            "--passphrase-file",
            &w.pass,
        ])
        .ok();
}

/// §2.7, §17.26 (audit I5, L8): `passwd` moves the old keyfile to the trash, where it opens
/// with the old passphrase for 30 more days; `--purge-old` (or a yes at the terminal) deletes
/// the retired keyfiles for good, the ones in the trash included. Either way the command says
/// what is left and that the key did not change — as a warning, which `-q` does not hide.
#[test]
fn passwd_can_delete_the_old_keyfiles_for_good() {
    let w = world();
    let root = w.vault_root();
    let lab = &w.lab;
    let trash = Path::new(&w.vault).join(".trash");
    let trashed_keyfiles = || -> Vec<String> {
        if !trash.exists() {
            return Vec::new();
        }
        files_under(&trash)
            .into_iter()
            .filter_map(|p| p.file_name()?.to_str().map(str::to_owned))
            .filter(|n| n.starts_with("gclone-key-"))
            .collect()
    };
    let second = lab.file("second-pass", "the second passphrase of this vault\n");
    let third = lab.file("third-pass", "the third passphrase of this vault\n");

    // The default: the old keyfile is in the trash, and the output says so — also with -q.
    let out =
        w.a.run(&["-q", "passwd", "--passphrase-file", &second])
            .ok()
            .stdout_has("Passphrase changed.")
            .stderr_has("warning: The old keyfile stays in the Drive trash for 30 days")
            .stderr_has("gclone passwd --purge-old")
            .stderr_has("The vault's key is unchanged")
            .stderr_has("There is no re-keying yet");
    assert!(!out.stdout.contains("Deleted for good"), "{}", out.stdout);
    assert_eq!(keyfiles(&root).len(), 1);
    let in_trash = trashed_keyfiles();
    assert_eq!(in_trash.len(), 1, "{in_trash:?}");
    assert!(in_trash[0].starts_with("gclone-key-00000001-"));

    // `--purge-old`: generation 2 is deleted from the folder and generation 1 from the trash.
    w.a.run(&["passwd", "--passphrase-file", &third, "--purge-old"])
        .ok()
        .stdout_has("Passphrase changed.")
        .stdout_has("Deleted for good: 1 old keyfile(s) in the vault folder, 1 in the Drive trash.")
        .stderr_has("warning: The old keyfiles are gone from this Google account, trash included")
        .stderr_has("Copies outside its reach stay what they were")
        .stderr_has("The vault's key is unchanged");
    let left = keyfiles(&root);
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(left[0].starts_with("gclone-key-00000003-"), "{left:?}");
    assert_eq!(trashed_keyfiles(), Vec::<String>::new());
    // Only the newest passphrase attaches a device; the vault itself is untouched.
    for old in [&w.pass, &second] {
        lab.device("x")
            .run(&["login", "--vault-dir", &w.vault, "--passphrase-file", old])
            .code(4)
            .stderr_has("Wrong passphrase");
    }
    let b = lab.device("b");
    b.run(&[
        "login",
        "--vault-dir",
        &w.vault,
        "--passphrase-file",
        &third,
    ])
    .ok();
    b.run(&["cat", ":docs/a.txt"]).ok().stdout_has("alpha");
    w.a.run(&["check"]).ok();

    // At a terminal, to a person who typed the passphrase, the question is asked — BEFORE
    // anything is written; the answer decides.
    let fourth = "the fourth passphrase of this vault";
    let typed = |pass: &'static str, answer: &'static str| {
        run_on_login_tty(
            &w.a,
            &["passwd"],
            &[
                ("New passphrase", pass),
                ("Repeat:", pass),
                ("no keeps a way back if the new one is lost. [y/N]", answer),
            ],
        )
    };
    let out = typed(fourth, "n")
        .ok()
        .stdout_has("Passphrase changed.")
        .stderr_has("The old keyfile stays in the Drive trash");
    let (question, changed) = (
        out.stderr.find("[y/N]").expect("the question"),
        out.stderr
            .find("The old keyfile stays")
            .expect("the caveat"),
    );
    assert!(question < changed, "{}", out.stderr);
    assert_eq!(trashed_keyfiles().len(), 1);
    let out = typed("the fifth passphrase of this vault", "y")
        .ok()
        .stdout_has(
            "Deleted for good: 1 old keyfile(s) in the vault folder, 1 in the Drive trash.",
        );
    assert!(
        out.stderr.contains("The old keyfiles are gone"),
        "{}",
        out.stderr
    );
    assert_eq!(trashed_keyfiles(), Vec::<String>::new());
    assert_eq!(keyfiles(&root).len(), 1);

    // With `--passphrase-file` nothing is asked, terminal or not (as in `login`): the
    // invocation that never waited for anybody still does not.
    let sixth = lab.file("sixth-pass", "the sixth passphrase of this vault\n");
    let out = run_on_login_tty(&w.a, &["passwd", "--passphrase-file", &sixth], &[])
        .ok()
        .stdout_has("Passphrase changed.")
        .stderr_has("The old keyfile stays in the Drive trash");
    assert!(!out.stderr.contains("[y/N]"), "{}", out.stderr);
    assert_eq!(trashed_keyfiles().len(), 1);
    assert_eq!(keyfiles(&root).len(), 1);
}

/// The purge question of `passwd` is asked before the new keyfile is written. It used to be
/// asked after the put and after "Passphrase changed." was printed, with the retirement of
/// the old keyfile waiting for the answer: Ctrl-C there (or the end of the ssh session) left
/// the old keyfile in the vault folder — not even in the trash — and the OLD passphrase went
/// on attaching new devices for good, under the words "Passphrase changed".
#[test]
fn an_interrupt_at_the_purge_question_of_passwd_changes_nothing() {
    let w = world();
    let root = w.vault_root();
    let before = keyfiles(&root);
    assert_eq!(before.len(), 1);
    let new = "a passphrase that never came to be";

    // Ctrl-C (the terminal's interrupt character) typed at the question.
    let out = run_on_login_tty(
        &w.a,
        &["passwd"],
        &[
            ("New passphrase", new),
            ("Repeat:", new),
            ("no keeps a way back if the new one is lost. [y/N]", "\u{3}"),
        ],
    );
    assert_ne!(out.code, 0, "interrupted: {}", out.stderr);
    assert!(
        !out.stdout.contains("Passphrase changed") && !out.stderr.contains("Passphrase changed"),
        "nothing was changed, and nothing says so:\n{}\n{}",
        out.stdout,
        out.stderr
    );
    // Exactly one keyfile is live, and it is the old one; nothing was trashed.
    assert_eq!(keyfiles(&root), before);
    assert!(!Path::new(&w.vault).join(".trash").exists());
    // The old passphrase is the passphrase; the one that was typed opens nothing.
    let pass_new = w.lab.file("never", &format!("{new}\n"));
    let c = w.lab.device("c");
    c.run(&[
        "login",
        "--vault-dir",
        &w.vault,
        "--passphrase-file",
        &pass_new,
    ])
    .code(4)
    .stderr_has("Wrong passphrase");
    c.run(&[
        "login",
        "--vault-dir",
        &w.vault,
        "--passphrase-file",
        &w.pass,
    ])
    .ok();

    // Declined (the default answer): the change runs through without another pause, and
    // exactly one keyfile is live — the new one — with the old one in the trash.
    run_on_login_tty(
        &w.a,
        &["passwd"],
        &[
            ("New passphrase", new),
            ("Repeat:", new),
            ("no keeps a way back if the new one is lost. [y/N]", ""),
        ],
    )
    .ok()
    .stdout_has("Passphrase changed.");
    let after = keyfiles(&root);
    assert_eq!(after.len(), 1, "{after:?}");
    assert!(after[0].starts_with("gclone-key-00000002-"), "{after:?}");
    let d = w.lab.device("d");
    d.run(&[
        "login",
        "--vault-dir",
        &w.vault,
        "--passphrase-file",
        &w.pass,
    ])
    .code(4)
    .stderr_has("Wrong passphrase");
    d.run(&[
        "login",
        "--vault-dir",
        &w.vault,
        "--passphrase-file",
        &pass_new,
    ])
    .ok();
}

/// `passwd --purge-old` after the current keyfile was moved to the trash by hand — the
/// obvious reaction to a leak, in drive.google.com. The purge used to delete from the trash
/// only generations below the new keyfile's, and the new generation was counted from the
/// keyfiles that were not in the trash: the new keyfile got generation 1 again, every trashed
/// keyfile — each opening with an old passphrase — survived, and the command still said "The
/// old keyfiles are gone from this Google account, trash included".
#[test]
fn passwd_purge_old_empties_the_trash_of_keyfiles_whatever_their_generation() {
    use gclone::backend::{Backend as _, DirBackend};
    let w = world();
    let root = w.vault_root();
    let trash = Path::new(&w.vault).join(".trash");
    let trashed_keyfiles = || -> Vec<String> {
        if !trash.exists() {
            return Vec::new();
        }
        let mut names: Vec<String> = files_under(&trash)
            .into_iter()
            .filter_map(|p| p.file_name()?.to_str().map(str::to_owned))
            .filter(|n| n.starts_with("gclone-key-"))
            .collect();
        names.sort();
        names
    };
    let second = w
        .lab
        .file("second-pass", "the second passphrase of this vault\n");
    let third = w
        .lab
        .file("third-pass", "the third passphrase of this vault\n");
    w.a.run(&["passwd", "--passphrase-file", &second]).ok();
    let live = keyfiles(&root);
    assert!(live[0].starts_with("gclone-key-00000002-"), "{live:?}");

    // The current keyfile goes to the trash by hand.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let backend = DirBackend::open(Path::new(&w.vault)).unwrap();
        let found = backend.find_by_name(&live[0]).await.unwrap();
        assert_eq!(found.len(), 1);
        backend.trash(&found[0].handle).await.unwrap();
    });
    assert_eq!(keyfiles(&root), Vec::<String>::new());
    let in_trash = trashed_keyfiles();
    assert_eq!(in_trash.len(), 2, "{in_trash:?}");

    w.a.run(&["passwd", "--passphrase-file", &third, "--purge-old"])
        .ok()
        .stdout_has("Passphrase changed.")
        .stdout_has("Deleted for good: 0 old keyfile(s) in the vault folder, 2 in the Drive trash.")
        .stderr_has("warning: The old keyfiles are gone from this Google account, trash included");
    // A generation is never used twice: the trash counted.
    let left = keyfiles(&root);
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(left[0].starts_with("gclone-key-00000003-"), "{left:?}");
    assert_eq!(trashed_keyfiles(), Vec::<String>::new());
    for old in [&w.pass, &second] {
        w.lab
            .device("x")
            .run(&["login", "--vault-dir", &w.vault, "--passphrase-file", old])
            .code(4)
            .stderr_has("Wrong passphrase");
    }
    w.lab
        .device("y")
        .run(&[
            "login",
            "--vault-dir",
            &w.vault,
            "--passphrase-file",
            &third,
        ])
        .ok();

    // Without `--purge-old` a hand-trashed keyfile stays where it is, and nothing is called
    // gone; the next generation still does not reuse a number.
    runtime.block_on(async {
        let backend = DirBackend::open(Path::new(&w.vault)).unwrap();
        let found = backend.find_by_name(&left[0]).await.unwrap();
        backend.trash(&found[0].handle).await.unwrap();
    });
    let out = w.a.run(&["passwd", "--passphrase-file", &second]).ok();
    assert!(!out.stderr.contains("are gone"), "{}", out.stderr);
    let left = keyfiles(&root);
    assert!(left[0].starts_with("gclone-key-00000004-"), "{left:?}");
    assert_eq!(trashed_keyfiles().len(), 1);
}

#[test]
fn keyfile_work_is_bounded() {
    let w = world();
    let root = w.vault_root();
    let real = keyfiles(&root);
    assert!(real[0].starts_with("gclone-key-00000001-"));
    let login = |d: &Device, extra: &[&str]| {
        let mut args = vec![
            "-vv",
            "login",
            "--vault-dir",
            &w.vault,
            "--passphrase-file",
            &w.pass,
        ];
        args.extend_from_slice(extra);
        d.run(&args)
    };
    let read = |out: &Out| {
        out.stderr
            .lines()
            .filter(|l| l.contains("reading keyfile candidate"))
            .count()
    };

    // Six junk objects under keyfile names of higher generations. They are looked at — 300
    // bytes each — and refused before any key derivation; they take no place among the
    // keyfiles that are tried, so the real one, seventh by its name, opens.
    let junk = |g: u32| root.join(format!("gclone-key-{g:08x}-0badf00d"));
    for g in 2..8 {
        std::fs::write(junk(g), pattern(g as u8, 300)).unwrap();
    }
    let b = w.lab.device("b");
    let out = login(&b, &[]).ok().stdout_has("Connected to vault");
    assert_eq!(read(&out), 7, "{}", out.stderr);
    assert!(out.stderr.contains("is not usable"), "{}", out.stderr);

    // An object that is larger than a keyfile can be is not even fetched.
    std::fs::write(junk(8), pattern(8, 70_000)).unwrap();
    let out = login(&w.lab.device("b2"), &[]).ok();
    assert_eq!(read(&out), 7, "{}", out.stderr);
    std::fs::remove_file(junk(8)).unwrap();

    // What is fetched is bounded: 32 objects. With 40 junk names in front of it the real
    // keyfile is not reached — and the message says that, not that the keyfile is missing.
    for g in 8..42 {
        std::fs::write(junk(g), pattern(g as u8, 300)).unwrap();
    }
    let c = w.lab.device("c");
    let out = login(&c, &[])
        .code(3)
        .stderr_has(
            "None of the 32 object(s) with keyfile names that this login looked at is a keyfile",
        )
        .stderr_has("9 more object(s) with keyfile names were not looked at")
        .stderr_has("gclone login --all-keyfiles")
        .stderr_has("gclone passwd");
    assert_eq!(read(&out), 32, "at most KEYFILE_LOOK_MAX objects are read");
    assert!(!out.stderr.contains("missing or damaged"), "{}", out.stderr);
    assert!(!c.secrets_file().exists() && !c.config_file().exists());
    // On request every one of them is looked at.
    let out = login(&c, &["--all-keyfiles"])
        .ok()
        .stdout_has("Connected to vault");
    assert_eq!(read(&out), 41, "{}", out.stderr);

    // A vault without any keyfile.
    for g in 2..42 {
        std::fs::remove_file(junk(g)).unwrap();
    }
    std::fs::remove_file(root.join(&real[0])).unwrap();
    login(&w.lab.device("d"), &[])
        .code(3)
        .stderr_has("keyfile is missing or damaged");
}

/// Regression (§2.6, §17.26, audit L10): four **well-formed** keyfiles planted under higher
/// generations — no secret is needed for that, the keyfile of any other vault will do — took
/// the four places a new device looks at. The real keyfile was never tried and the answer to
/// the right passphrase was "Wrong passphrase." (exit 4), with no hint that more keyfiles
/// exist: with no connected device left, the owner would conclude that the passphrase is lost.
#[test]
fn planted_keyfiles_do_not_make_the_right_passphrase_wrong() {
    let w = world();
    let root = w.vault_root();
    let real = keyfiles(&root);

    // The attacker's own vault, with his own passphrase; its keyfile, five times, under the
    // highest generations there are. (The name's hash is of the bytes: nothing to forge.)
    let his = w.lab.device("attacker");
    let his_vault = s(&w.lab.path("his-vault"));
    let his_pass = w.lab.file("his-pass", "the attacker's own passphrase\n");
    his.run(&[
        "login",
        "--vault-dir",
        &his_vault,
        "--passphrase-file",
        &his_pass,
    ])
    .ok();
    let his_root = Path::new(&his_vault).join("gclone");
    let his_keyfile = keyfiles(&his_root).remove(0);
    let h8 = his_keyfile.rsplit('-').next().unwrap().to_owned();
    let bytes = std::fs::read(his_root.join(&his_keyfile)).unwrap();
    let planted: Vec<PathBuf> = (0..5)
        .map(|i| root.join(format!("gclone-key-fffffff{i}-{h8}")))
        .collect();
    for path in &planted {
        std::fs::write(path, &bytes).unwrap();
    }
    let args = [
        "login",
        "--vault-dir",
        &w.vault,
        "--passphrase-file",
        &w.pass,
    ];

    // The right passphrase, read from a file: four keyfiles are asked (the work of one
    // attempt), and the answer is that keyfiles were left out — never "Wrong passphrase".
    let b = w.lab.device("b");
    let out = b
        .run(&args)
        .code(4)
        .stderr_has("The passphrase does not open the 4 newest keyfiles of this vault, and 2 older keyfiles were not tried")
        .stderr_has("gclone login --all-keyfiles");
    assert!(!out.stderr.contains("Wrong passphrase"), "{}", out.stderr);
    assert!(!b.secrets_file().exists() && !b.config_file().exists());
    // Asked for, every keyfile is tried: the real one opens.
    let mut all = args.to_vec();
    all.push("--all-keyfiles");
    b.run(&all).ok().stdout_has("Connected to vault");
    b.run(&["cat", ":docs/a.txt"]).ok().stdout_has("alpha");

    // A passphrase that is wrong for every keyfile is still called wrong — once all were asked.
    let wrong = w.lab.file("wrong-pass", "certainly not the passphrase\n");
    let c = w.lab.device("c");
    let out = c
        .run(&[
            "login",
            "--vault-dir",
            &w.vault,
            "--passphrase-file",
            &wrong,
        ])
        .code(4)
        .stderr_has("2 older keyfiles were not tried");
    assert!(!out.stderr.contains("Wrong passphrase"), "{}", out.stderr);
    c.run(&[
        "login",
        "--vault-dir",
        &w.vault,
        "--passphrase-file",
        &wrong,
        "--all-keyfiles",
    ])
    .code(4)
    .stderr_has("Wrong passphrase.");

    // At a terminal the question is asked, and a yes tries the rest with the same passphrase.
    let d = w.lab.device("d");
    let out = run_on_login_tty(
        &d,
        &["login", "--vault-dir", &w.vault],
        &[
            ("Passphrase:", PASS),
            (
                "Try it on the 2 older one(s) too (a key derivation each)? [y/N]",
                "y",
            ),
        ],
    )
    .ok()
    .stdout_has("Connected to vault");
    assert!(!out.stderr.contains("Wrong passphrase"), "{}", out.stderr);
    // Declined, the passphrase is asked again and nothing is called wrong; the third answer
    // says what was not tried.
    let e = w.lab.device("e");
    let out = run_on_login_tty(
        &e,
        &["login", "--vault-dir", &w.vault],
        &[
            ("Passphrase:", PASS),
            ("too (a key derivation each)? [y/N]", "n"),
            ("Passphrase:", "another guess entirely"),
            ("too (a key derivation each)? [y/N]", "n"),
            ("Passphrase:", "and a third one, also wrong"),
            ("too (a key derivation each)? [y/N]", "n"),
        ],
    )
    .code(4)
    .stderr_has("older keyfiles were not tried");
    assert!(!out.stderr.contains("Wrong passphrase"), "{}", out.stderr);

    // With three planted keyfiles the real one is the fourth: no question, no flag.
    for path in &planted[..2] {
        std::fs::remove_file(path).unwrap();
    }
    w.lab
        .device("f")
        .run(&args)
        .ok()
        .stdout_has("Connected to vault");
    // `passwd` on a connected device writes a keyfile ahead of them and retires the rest,
    // the planted ones included.
    for path in &planted[..2] {
        std::fs::write(path, &bytes).unwrap();
    }
    w.a.run(&["passwd", "--passphrase-file", &w.pass]).ok();
    let left = keyfiles(&root);
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(left[0].starts_with("gclone-key-fffffff5-"), "{left:?}");
    assert!(!left.contains(&real[0]));
    w.lab
        .device("g")
        .run(&args)
        .ok()
        .stdout_has("Connected to vault");
}

// ---------------------------------------------------------------------------------------------
// logout, interrupted ATTACH, strict secrets
// ---------------------------------------------------------------------------------------------

/// Stages one index op on `d` without publishing it (what a killed run leaves behind).
fn stage_an_op(d: &Device) {
    use gclone::config::{BackendCfg, Config, Paths};
    let paths = Paths {
        config_dir: d.config.clone(),
        state_root: d.state.clone(),
    };
    let BackendCfg::Dir { path } = &Config::load(&paths).unwrap().backend else {
        panic!("a directory vault")
    };
    let backend = gclone::backend::DirBackend::open(path).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(stage_an_op_on(d, backend));
}

/// `stage_an_op` for a device on any store (staging does not talk to it).
async fn stage_an_op_on<B: gclone::backend::Backend>(d: &Device, backend: B) {
    use gclone::config::{Config, Paths, secret_store};
    let paths = Paths {
        config_dir: d.config.clone(),
        state_root: d.state.clone(),
    };
    let config = Config::load(&paths).unwrap();
    let secrets = secret_store(&paths).load().unwrap().expect("signed in");
    let vault_id = config.vault_id_bytes().unwrap();
    let keys = secrets.keyring(vault_id).unwrap();
    let db = gclone::state::Db::open(&paths.db_file(&config.vault_id)).unwrap();
    let name = String::from_utf8(db.meta_get("device_name").unwrap().unwrap()).unwrap();
    let vault = gclone::index::Vault::open(
        Arc::new(backend),
        db,
        keys,
        gclone::index::OpenParams {
            vault_id,
            handles: config.handles(),
            device_name: name,
            cache_dir: paths.index_cache_dir(&config.vault_id),
            machine_fp: None,
        },
    )
    .await
    .unwrap();
    vault
        .stage(vec![gclone::types::OpDraft::Put {
            path: "staged-by-a-killed-run".into(),
            entry: gclone::types::Entry::dir(),
            base: None,
            origin: None,
            effect: None,
        }])
        .unwrap();
}

/// `logout` leaves nothing of a login in the state root: not a cached access token without its
/// secrets file, and not the temp copies of a write that was killed before its rename.
#[test]
fn logout_removes_leftover_login_files() {
    let w = world();
    let a = &w.a;
    let secrets_temp = a.state.join(".secrets.json.tmp-0011223344556677");
    let token_temp = a.state.join(".token.json.tmp-89abcdef01234567");
    let unrelated = a.state.join(".secrets.json.bak");
    let plant = |path: &Path, content: &[u8]| {
        std::fs::write(path, content).expect("write");
        chmod(path, 0o600);
    };

    // Signed in, with a cached access token and leftovers of two interrupted writes.
    plant(&secrets_temp, &std::fs::read(a.secrets_file()).unwrap());
    plant(&token_temp, b"{\"access_token\":\"at-old\"}");
    plant(&a.token_file(), b"{\"access_token\":\"at-live\"}");
    plant(&unrelated, b"not gclone's");
    a.run(&["logout"])
        .ok()
        .stdout_has("Signed out on this device.");
    for gone in [
        &a.secrets_file(),
        &a.token_file(),
        &secrets_temp,
        &token_temp,
    ] {
        assert!(!gone.exists(), "{} survived the logout", gone.display());
    }
    assert!(unrelated.exists(), "only gclone's own files are removed");
    a.run(&["logout"])
        .ok()
        .stdout_has("Not signed in on this device; nothing to do.");

    // Not signed in (no secrets.json) but an access token or a temp copy is still there —
    // after a logout that was killed between its two deletions, or a reader that refreshed
    // while the logout ran: the next logout removes them and says so.
    plant(&a.token_file(), b"{\"access_token\":\"at-live\"}");
    plant(&secrets_temp, b"{\"keys\":[]}");
    a.run(&["logout"])
        .ok()
        .stdout_has("Not signed in on this device; leftover files of an earlier login")
        .stdout_has("were removed");
    assert!(!a.token_file().exists() && !secrets_temp.exists());
    assert!(a.config_file().exists(), "config.json stays");
    a.run(&["logout"])
        .ok()
        .stdout_has("Not signed in on this device; nothing to do.");

    // The device still re-attaches.
    a.run(&["login", "--passphrase-file", &w.pass])
        .ok()
        .stdout_has("Connected to vault \"gclone\"");
}

#[test]
fn logout_and_login_again() {
    let w = world();
    let a = &w.a;
    let canonical_vault = s(&std::fs::canonicalize(&w.vault).unwrap());
    let (name, id) = a.identity();
    assert_eq!(name, "mbp");
    let state = a.vault_state();

    // Not signed in: exit 0.
    w.lab
        .device("never")
        .run(&["logout"])
        .ok()
        .stdout_has("Not signed in");

    a.run(&["logout"])
        .ok()
        .stdout_has("Signed out on this device.");
    assert!(!a.secrets_file().exists());
    assert!(!a.token_file().exists());
    assert!(a.config_file().exists(), "config.json stays");
    assert!(state.join("state.db").exists(), "the state directory stays");
    // NotLoggedIn — not Locked — for a directory vault too, and the hint names the directory.
    let out = a
        .run(&["ls"])
        .code(4)
        .stderr_has("not connected")
        .stderr_has(&format!("gclone login --vault-dir {canonical_vault}"));
    assert!(!out.stderr.contains("finish connecting"));
    a.run(&["logout"]).ok().stdout_has("Not signed in");

    // Switching to another directory needs `logout --forget` first.
    let elsewhere = s(&w.lab.path("elsewhere"));
    a.run(&[
        "login",
        "--vault-dir",
        &elsewhere,
        "--passphrase-file",
        &w.pass,
    ])
    .code(2)
    .stderr_has("gclone logout --forget")
    .stderr_has(&canonical_vault);
    assert!(
        !Path::new(&elsewhere).exists(),
        "nothing is created for a refused login"
    );
    a.run(&["login", "https://auth.example"])
        .code(2)
        .stderr_has("gclone logout --forget");

    // A plain `login` (no --vault-dir: the directory comes from config.json) continues as the
    // same device.
    a.run(&["login", "--passphrase-file", &w.pass])
        .ok()
        .stdout_has("Connected to vault \"gclone\"");
    assert_eq!(a.identity(), (name.clone(), id.clone()));
    assert_eq!(a.bytes(&["cat", ":docs/a.txt"]), b"alpha\n");
    let devices = status_line(&a.run(&["status"]).ok().stdout, "Devices");
    assert_eq!(devices.matches("mbp (").count(), 1, "{devices}");

    // --revoke has no meaning for a directory vault.
    a.run(&["logout", "--revoke", "--yes"]).code(2);
    assert!(a.secrets_file().exists());

    // --forget asks when unpublished changes exist.
    stage_an_op(a);
    a.run(&["logout", "--forget"])
        .code(5)
        .stderr_has("not published yet");
    assert!(a.secrets_file().exists() && a.config_file().exists() && state.exists());
    a.run(&["logout", "--forget", "--yes"])
        .ok()
        .stdout_has("Signed out on this device.");
    assert!(!a.secrets_file().exists());
    assert!(!a.config_file().exists(), "--forget removes config.json");
    assert!(
        !state.exists(),
        "--forget removes the vault's state directory"
    );
    a.run(&["ls"]).code(4).stderr_has("gclone login");

    // Forgotten: the device may now attach to another directory, as a new device.
    a.run(&[
        "login",
        "--vault-dir",
        &elsewhere,
        "--passphrase-file",
        &w.pass,
    ])
    .ok()
    .stdout_has("Vault created");
    assert_ne!(a.identity().1, id);
}

#[test]
fn an_interrupted_attach_leaves_the_device_unconnected() {
    let w = world();
    let index = w.vault_root().join("index");
    let b = w.lab.device("b");
    let login = [
        "login",
        "--vault-dir",
        w.vault.as_str(),
        "--passphrase-file",
        w.pass.as_str(),
        "--device-name",
        "nas",
    ];

    // The passphrase is accepted, but the device cannot register itself.
    chmod(&index, 0o555);
    let out = b.run(&login);
    chmod(&index, 0o755);
    assert_ne!(out.code, 0, "{}", out.stderr);
    assert!(!out.stderr.contains("Wrong passphrase"), "{}", out.stderr);
    assert!(!out.stdout.contains("Connected to vault"));
    // No key was saved and no config.json exists: the device does not count as connected.
    assert!(!b.config_file().exists());
    if b.secrets_file().exists() {
        assert_eq!(b.json(&b.secrets_file())["keys"], serde_json::json!([]));
    }
    b.run(&["ls"]).code(4);
    let devices = status_line(&w.a.run(&["status"]).ok().stdout, "Devices");
    assert!(!devices.contains("nas"), "{devices}");

    // The same command again succeeds, and the first device sees the new one — once.
    b.run(&login).ok().stdout_has("Connected to vault");
    let devices = status_line(&w.a.run(&["status"]).ok().stdout, "Devices");
    assert_eq!(devices.matches("nas (").count(), 1, "{devices}");
    assert_eq!(w.a.head(), b.head());
}

#[test]
fn secrets_are_loaded_strictly() {
    let w = world();
    let a = &w.a;

    // A directory vault's secrets hold a key and no login field — and load.
    let secrets = a.json(&a.secrets_file());
    for absent in [
        "auth_url",
        "refresh_token",
        "email",
        "consent_ms",
        "client_id",
        "client_secret",
    ] {
        assert!(secrets.get(absent).is_none(), "{absent} must be absent");
    }
    assert_eq!(secrets["version"], 1);
    assert_eq!(secrets["keys"].as_array().map(Vec::len), Some(1));
    a.run(&["ls"]).ok();

    let hint = |out: Out| {
        out.code(4)
            .stderr_has("readable by others")
            .stderr_has(&format!("chmod 700 {}", a.state.display()))
            .stderr_has(&format!("chmod 600 {}", a.secrets_file().display()))
            .stderr_has("treat the login and the key as exposed")
    };
    chmod(&a.secrets_file(), 0o644);
    let out = hint(a.run(&["ls", ":docs"]));
    assert_eq!(out.stdout, "", "nothing is read or shown");
    hint(a.run(&["status"]));
    hint(a.run(&["login", "--passphrase-file", &w.pass]));
    assert_eq!(
        mode(&a.secrets_file()),
        0o644,
        "nothing is repaired silently"
    );
    chmod(&a.secrets_file(), 0o600);
    a.run(&["ls", ":docs"]).ok().stdout_has("a.txt");

    chmod(&a.state, 0o755);
    hint(a.run(&["ls", ":docs"]));
    assert_eq!(mode(&a.state), 0o755);
    chmod(&a.state, 0o700);
    a.run(&["ls", ":docs"]).ok().stdout_has("a.txt");
}

// ---------------------------------------------------------------------------------------------
// Recovery drill, open policies, exit codes, modes, concurrency
// ---------------------------------------------------------------------------------------------

#[test]
fn recovery_drill_in_both_layouts() {
    let w = world();
    let lab = &w.lab;

    // (a) The outer directory, without the directory backend's id map.
    let outer = lab.path("copy-outer");
    copy_dir(
        Path::new(&w.vault),
        &outer,
        &[".gclone-dir-ids.json", ".gclone-tmp", ".trash"],
    );
    let r1 = lab.device("r1");
    r1.run(&[
        "login",
        "--vault-dir",
        &s(&outer),
        "--passphrase-file",
        &w.pass,
    ])
    .ok()
    .stdout_has("Connected to vault \"gclone\" (5 files)");
    let out1 = lab.path("out1");
    r1.run(&["copy", ":", &s(&out1)]).ok();
    assert_eq!(snapshot(&w.src), snapshot(&out1.join("docs")));

    // (b) Only the inner vault folder — what a web download yields.
    let inner = lab.path("copy-inner");
    copy_dir(&w.vault_root(), &inner, &[]);
    assert!(inner.join("gclone-vault.json").exists());
    let r2 = lab.device("r2");
    r2.run(&[
        "login",
        "--vault-dir",
        &s(&inner),
        "--passphrase-file",
        &w.pass,
    ])
    .ok()
    .stdout_has("Connected to vault \"gclone\" (5 files)");
    let out2 = lab.path("out2");
    r2.run(&["copy", ":", &s(&out2)]).ok();
    assert_eq!(snapshot(&w.src), snapshot(&out2.join("docs")));
    r2.run(&["status"]).ok();
}

#[test]
fn open_policies_with_an_index_gap() {
    let w = world();
    let b = w.join("b");
    w.a.run(&["mkdir", ":later"]).ok();
    b.run(&["ls"]).ok().stdout_has("later/");

    // Take away a segment that both devices have applied.
    let index = w.vault_root().join("index");
    let (_, a_id) = w.a.identity();
    let victim = std::fs::read_dir(&index)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .find(|n| n.starts_with(&format!("s-{a_id}-0000000000000002-")))
        .expect("the first device's second segment");
    std::fs::rename(index.join(&victim), w.lab.path("withheld")).unwrap();

    // Read-only commands warn and continue on the replica.
    let out = b.run(&["ls", ":docs"]).ok().stdout_has("a.txt");
    assert!(out.stderr.contains("warning:"), "{}", out.stderr);
    assert!(out.stderr.contains("gclone repair"), "{}", out.stderr);
    b.run(&["status"]).ok().stderr_has("warning:");
    assert_eq!(b.bytes(&["cat", ":docs/a.txt"]), b"alpha\n");
    // Mutating commands and gc refuse.
    b.run(&["sync", &s(&w.src), ":docs"])
        .code(3)
        .stderr_has("gclone repair");
    b.run(&["mkdir", ":x"]).code(3);
    b.run(&["gc"])
        .code(3)
        .stderr_has("gc needs a complete index");
    b.run(&["gc", "-n"]).code(3);
    // `repair` is not blocked by the state it repairs: this device still holds the segment.
    b.run(&["repair"])
        .ok()
        .stdout_has("Republished 1")
        .stdout_has(&victim)
        .stdout_has("Index repaired");
    assert!(index.join(&victim).exists());
    let out = b.run(&["ls", ":docs"]).ok();
    assert!(!out.stderr.contains("warning:"), "{}", out.stderr);
    b.run(&["sync", &s(&w.src), ":docs"]).ok();
    b.run(&["gc"]).ok().stdout_has("Trashed 0 dead blobs");
    w.a.run(&["ls"]).ok();
    assert_eq!(w.a.head(), b.head());
}

/// Every file under `dir`, sorted.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).expect("read dir") {
            let p = e.expect("entry").path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The newest index segment in the vault's `index` folder that device `id` wrote.
fn newest_segment_of(index: &Path, id: &str) -> PathBuf {
    let mut segments: Vec<PathBuf> = files_under(index)
        .into_iter()
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            name.starts_with(&format!("s-{id}-"))
        })
        .collect();
    // `s-<device>-<seq: 16 hex digits>-<h8>`: the names of one device sort by sequence number.
    segments.sort();
    segments.pop().expect("the device has written a segment")
}

/// Overwrites `file` in place with as many bytes of junk: what anyone who can write to the
/// vault folder can do to an object without holding the vault's key.
fn overwrite_with_junk(file: &Path) -> String {
    let len = std::fs::metadata(file).unwrap().len() as usize;
    std::fs::write(file, vec![0x41u8; len]).expect("overwrite");
    file.file_name().unwrap().to_str().unwrap().to_owned()
}

/// Regression (§17.26, audit L4): an index object overwritten under its own name silenced the
/// rollback alarm. The devices that had applied the object looked at the listed *name*, found
/// it, and said nothing — `status` clean, mutating commands exit 0 — while a device that had
/// not applied it was held on the older state. Plain deletion of the same object was loud.
#[test]
fn an_index_object_overwritten_under_its_name_is_noticed_and_repaired() {
    let w = world();
    let a = &w.a;
    let b = w.join("b");
    a.run(&["mkdir", ":secret-new-dir"]).ok();
    b.run(&["ls", ":"]).ok().stdout_has("secret-new-dir/");
    let index = w.vault_root().join("index");
    let (_, a_id) = a.identity();
    let tip = overwrite_with_junk(&newest_segment_of(&index, &a_id));

    // The two devices that had applied it: a warning on read-only commands, exit 3 on the rest.
    for d in [a, &b] {
        d.run(&["status"])
            .ok()
            .stderr_has("warning:")
            .stderr_has("rolled back")
            .stderr_has("gclone repair");
        d.run(&["ls", ":"]).ok().stdout_has("secret-new-dir/");
        d.run(&["mkdir", ":x"])
            .code(3)
            .stderr_has("rolled back")
            .stderr_has("gclone repair");
        d.run(&["gc"])
            .code(3)
            .stderr_has("gc needs a complete index");
    }

    // A device that attaches now is served the older state — and is told that an index object
    // failed verification, on every command; its gc refuses and names the object.
    let c = w.lab.device("c");
    c.run(&[
        "login",
        "--vault-dir",
        &w.vault,
        "--passphrase-file",
        &w.pass,
        "--device-name",
        "c",
    ])
    .ok()
    .stdout_has("Connected to vault \"gclone\"");
    let out = c.run(&["ls", ":"]).ok().stderr_has("failed verification");
    assert!(out.stderr.contains(&tip), "{}", out.stderr);
    assert!(!out.stdout.contains("secret-new-dir"), "{}", out.stdout);
    c.run(&["gc", "--orphans"])
        .code(3)
        .stderr_has("gc needs a complete index")
        .stderr_has(&tip);

    // One `repair` on a device that holds the object puts it back for everybody.
    b.run(&["repair"])
        .ok()
        .stdout_has("Republished 1")
        .stdout_has(&tip)
        .stdout_has("Index repaired");
    for d in [a, &b, &c] {
        let out = d.run(&["ls", ":"]).ok().stdout_has("secret-new-dir/");
        assert!(!out.stderr.contains("warning:"), "{}", out.stderr);
        d.run(&["gc"]).ok().stdout_has("Trashed 0 dead blobs");
    }
    a.run(&["mkdir", ":after"]).ok();
    b.run(&["ls", ":"]).ok().stdout_has("after/");
    c.run(&["status"]).ok();
    assert_eq!(a.head(), b.head());
    assert_eq!(a.head(), c.head());
}

/// Regression (§5.9, §17.26, audit L3): `gc` ran on a replica whose refresh had just ignored an
/// index object. The segment that records a new file fails verification for device c; fifteen
/// days later c's `gc --orphans` exited 0 with "Trashed 0 dead blobs (0 B), 1 orphans (…)" —
/// the blob of a file that is live on device a. It refuses now, in all three steps.
#[test]
fn gc_refuses_on_a_device_that_ignored_an_index_object() {
    let w = world();
    let a = &w.a;
    let c = w.join("c"); // attached before the upload below
    let data = w.vault_root().join("data");
    let before = files_under(&data);

    let more = w.lab.path("more");
    let content = pattern(77, 300_000);
    write(&more.join("precious.bin"), &content);
    a.run(&["copy", &s(&more), ":more"]).ok();
    let new_blobs: Vec<PathBuf> = files_under(&data)
        .into_iter()
        .filter(|p| !before.contains(p))
        .collect();
    assert_eq!(new_blobs.len(), 1, "one new blob for the one new file");
    let blob = &new_blobs[0];

    // Junk under the name of a's newest segment — the one that records the blob.
    let index = w.vault_root().join("index");
    let (_, a_id) = a.identity();
    let tip = overwrite_with_junk(&newest_segment_of(&index, &a_id));

    // Fifteen days pass (the directory backend's creation time is the file's mtime): for a
    // device that knows nothing of the blob it is an orphan past the grace.
    let then = std::time::SystemTime::now() - Duration::from_secs(15 * 86_400);
    std::fs::File::options()
        .write(true)
        .open(blob)
        .unwrap()
        .set_modified(then)
        .unwrap();

    for args in [
        &["gc", "--orphans"][..],
        &["gc"],
        &["gc", "--purge"],
        &["gc", "--orphans", "--purge"],
        &["gc", "-n", "--orphans", "--purge"],
    ] {
        let out = c
            .run(args)
            .code(3)
            .stderr_has("gc needs a complete index and did nothing")
            .stderr_has("failed verification")
            .stderr_has(&tip)
            .stderr_has("gclone repair");
        assert!(!out.stdout.contains("Trashed"), "{args:?}: {}", out.stdout);
        assert!(blob.exists(), "{args:?}: the live blob is where it was");
    }
    assert_eq!(a.bytes(&["cat", ":more/precious.bin"]), content);

    // After the repair, c knows the file; its sweep finds nothing to collect.
    a.run(&["repair"]).ok().stdout_has("Republished 1");
    c.run(&["gc", "--orphans", "--purge"])
        .ok()
        .stdout_has("Trashed 0 dead blobs (0 B), 0 orphans (0 B)");
    assert!(blob.exists());
    assert_eq!(c.bytes(&["cat", ":more/precious.bin"]), content);
}

/// Regression: a device that had run `gclone logout` could not log in again while its replica
/// had a Gap or Rollback verdict — ATTACH refreshed before it saved the key and gave up on the
/// verdict — and without a login it could not run `gclone repair`, which is the cure for
/// exactly these verdicts. The two error messages pointed at each other; the only way out,
/// `logout --forget`, deletes the index cache that `repair` republishes from.
#[test]
fn login_after_logout_works_while_the_index_needs_repair() {
    let w = world();
    let b = w.join("b");
    w.a.run(&["mkdir", ":later"]).ok();
    b.run(&["ls"]).ok().stdout_has("later/");

    // The vault loses a segment that b has applied (and still holds in its index cache).
    let index = w.vault_root().join("index");
    let (_, a_id) = w.a.identity();
    let victim = std::fs::read_dir(&index)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .find(|n| n.starts_with(&format!("s-{a_id}-0000000000000002-")))
        .expect("the first device's second segment");
    std::fs::rename(index.join(&victim), w.lab.path("withheld")).unwrap();
    b.run(&["mkdir", ":x"]).code(3).stderr_has("gclone repair");
    let (name, id) = {
        let out = b.run(&["status"]).ok();
        let line = status_line(&out.stdout, "This device");
        let (name, id) = line.rsplit_once(" (").unwrap();
        (name.to_string(), id.trim_end_matches(')').to_string())
    };

    b.run(&["logout"]).ok();
    b.run(&["repair"]).code(4);
    // The login completes — with the verdict as a warning and the way out.
    let out = b
        .run(&["login", "--passphrase-file", &w.pass])
        .ok()
        .stdout_has("Connected to vault \"gclone\"")
        .stderr_has("rolled back")
        .stderr_has("This device is connected")
        .stderr_has("gclone repair");
    assert!(
        !out.stdout.contains("Compare with `gclone status`"),
        "no head value is offered for comparison while the index is incomplete:\n{}",
        out.stdout
    );
    assert!(b.secrets_file().exists());
    // Still the same device, and still refused where everyone is refused …
    let out = b.run(&["status"]).ok();
    assert_eq!(
        status_line(&out.stdout, "This device"),
        format!("{name} ({id})")
    );
    b.run(&["mkdir", ":x"]).code(3).stderr_has("gclone repair");
    // … but `repair` runs now, and republishes what only this device's cache still holds.
    b.run(&["repair"])
        .ok()
        .stdout_has("Republished 1")
        .stdout_has(&victim)
        .stdout_has("Index repaired");
    assert!(index.join(&victim).exists());
    b.run(&["mkdir", ":x"]).ok();
    w.a.run(&["ls"]).ok().stdout_has("x/");
    assert_eq!(w.a.head(), b.head());

    // With the index whole again a login is the ordinary one.
    b.run(&["logout"]).ok();
    let out = b
        .run(&["login", "--passphrase-file", &w.pass])
        .ok()
        .stdout_has("Compare with `gclone status`");
    assert!(!out.stderr.contains("gclone repair"), "{}", out.stderr);
}

#[test]
fn exit_codes_json_and_dry_run() {
    let w = world();
    let (a, lab) = (&w.a, &w.lab);
    let src = s(&w.src);

    // 2: usage — clap's own and the ones found after parsing.
    a.run(&["frobnicate"]).code(2);
    a.run(&["copy", &src]).code(2);
    a.run(&["copy", &src, "also-local"])
        .code(2)
        .stderr_has("leading ':'");
    a.run(&["copy", ":a", ":b"]).code(2);
    a.run(&["ls", "not-remote"]).code(2);
    a.run(&["copy", &src, ":docs", "--transfers", "0"]).code(2);
    a.run(&["check", &src]).code(2);
    a.run(&["rm", ":"]).code(2);
    a.run(&["copy", &src, ":docs/a.txt"]).code(2);

    // 4: not connected, with the hint.
    let fresh = lab.device("fresh");
    fresh
        .run(&["ls"])
        .code(4)
        .stderr_has("This device is not connected")
        .stderr_has("gclone login");
    fresh.run(&["status"]).code(4);
    fresh.run(&["probe"]).code(4);
    a.run(&["probe"]).code(2).stderr_has("directory vault");
    fresh.run(&["copy", &src, ":docs"]).code(4);

    // 4: signed in but not unlocked — secrets with `keys: []` beside a config.json.
    let c = w.join("c");
    let mut secrets = c.json(&c.secrets_file());
    secrets["keys"] = serde_json::json!([]);
    std::fs::write(c.secrets_file(), serde_json::to_vec(&secrets).unwrap()).unwrap();
    assert_eq!(mode(&c.secrets_file()), 0o600);
    c.run(&["ls"]).code(4).stderr_has(
        "Run `gclone login` to finish connecting this device (it will ask for the passphrase).",
    );
    c.run(&["login", "--passphrase-file", &w.pass])
        .ok()
        .stdout_has("Connected to vault");
    c.run(&["ls"]).ok();

    // --json: NDJSON, ending in a summary event.
    let json_src = lab.path("json-src");
    write(&json_src.join("one.txt"), b"1");
    write(&json_src.join("two.txt"), b"22");
    let out = a
        .run(&["--json", "copy", &s(&json_src), ":json", "-v"])
        .ok();
    let events: Vec<serde_json::Value> = out
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}")))
        .collect();
    let last = events.last().expect("at least the summary");
    assert_eq!(last["event"], "summary");
    assert_eq!(last["uploaded"], 2);
    assert_eq!(last["bytes_up"], 3);
    assert_eq!(last["exit"], 0);
    for key in [
        "downloaded",
        "reused",
        "deleted",
        "skipped",
        "failed",
        "conflicts",
        "bytes_down",
    ] {
        assert!(last[key].is_u64(), "summary.{key}");
    }
    assert!(events.iter().all(|e| e["event"].is_string()));
    write(&json_src.join("three.txt"), b"333");
    let dry = a
        .run(&["--json", "sync", &s(&json_src), ":json2", "-n"])
        .ok();
    let events: Vec<serde_json::Value> = dry
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("NDJSON"))
        .collect();
    assert!(
        events
            .iter()
            .any(|e| e["event"] == "plan" && e["action"] == "upload" && e["path"] == "three.txt"),
        "{}",
        dry.stdout
    );
    assert_eq!(events.last().unwrap()["event"], "summary");

    // -n changes nothing in the vault.
    let before = snapshot(&w.vault_root());
    let more = lab.path("more");
    write(&more.join("new.txt"), b"new");
    a.run(&["copy", "-n", &s(&more), ":more"])
        .ok()
        .stdout_has("+ upload")
        .stdout_has("new.txt")
        .stdout_has("Would upload 1 (3 B). Nothing changed (dry run).");
    a.run(&["sync", "--dry-run", &s(&more), ":more"]).ok();
    a.run(&["gc", "-n", "--orphans", "--purge"])
        .ok()
        .stdout_has("Nothing changed (dry run)");
    assert!(
        before == snapshot(&w.vault_root()),
        "a dry run must not change the vault"
    );
    a.run(&["ls", ":more"]).code(1);

    // 6: partial — a local-only file in the destination of a sync is skipped, never deleted.
    let partial = lab.path("partial");
    write(&partial.join("only-here.txt"), b"mine");
    let out = a
        .run(&["sync", ":docs", &s(&partial)])
        .code(6)
        .stdout_has("skip")
        .stdout_has("only-here.txt");
    assert!(out.stdout.contains("1 skipped"), "{}", out.stdout);
    assert_eq!(
        std::fs::read(partial.join("only-here.txt")).unwrap(),
        b"mine"
    );
    assert_eq!(std::fs::read(partial.join("a.txt")).unwrap(), b"alpha\n");

    // 5: the delete guard without --yes (no terminal).
    let many = lab.path("many");
    for i in 0..12 {
        write(
            &many.join(format!("f{i:02}.txt")),
            format!("file {i}").as_bytes(),
        );
    }
    a.run(&["sync", &s(&many), ":many"]).ok();
    for i in 0..11 {
        std::fs::remove_file(many.join(format!("f{i:02}.txt"))).unwrap();
    }
    a.run(&["sync", &s(&many), ":many"])
        .code(5)
        .stderr_has("refusing to delete 11 of 12");
    assert_eq!(a.run(&["ls", ":many"]).ok().stdout.lines().count(), 12);
    a.run(&["sync", &s(&many), ":many", "--max-delete", "5"])
        .code(5);
    a.run(&["sync", &s(&many), ":many", "--yes"])
        .ok()
        .stdout_has("11 deleted");
    assert_eq!(a.run(&["ls", ":many"]).ok().stdout.trim(), "f11.txt");

    // 5: a changed root identity without --reset-pair / --keep-pair.
    let moved = lab.path("many-old");
    std::fs::rename(&many, &moved).unwrap();
    copy_dir(&moved, &many, &[]);
    a.run(&["copy", &s(&many), ":many"])
        .code(5)
        .stderr_has("not the directory last synced");
    a.run(&["copy", &s(&many), ":many", "--keep-pair"]).ok();
    a.run(&["copy", &s(&many), ":many"]).ok();

    // 3: check finds a damaged blob; 0 when everything is in place.
    a.run(&["check"]).ok().stdout_has("all good");
    a.run(&["check", &src, ":docs"]).ok().stdout_has("all good");
    a.run(&["check", "--download", ":docs"])
        .ok()
        .stdout_has("all good");
    write(&w.src.join("a.txt"), b"changed locally\n");
    a.run(&["check", &src, ":docs"]).code(3).stderr_has("a.txt");

    // An object in a data folder that the index does not know: while it is young it is, as
    // far as anyone can tell, another device's upload whose segment is not published yet —
    // blobs go first. `check` says that, and does not send the user to `gc`.
    let data = w.vault_root().join("data");
    let folder = std::fs::read_dir(&data)
        .expect("data folder")
        .next()
        .expect("a blob folder")
        .expect("entry")
        .path();
    let stray = folder.join("0123456789abcdef0123456789abcdef");
    write(&stray, b"not in the index yet");
    let out = a.run(&["check"]).ok().stdout_has("all good");
    out.stderr_has(
        "note: 1 recent object(s) in the data folders are not in the index yet — probably \
         another device's upload in progress; nothing to do (`gclone gc --orphans` only \
         collects such objects once they are older than 14 days)",
    );
    a.run(&["gc", "-n", "--orphans"])
        .ok()
        .stdout_has("0 orphans");
    // Past the grace period it is what `gc --orphans` is for.
    let old = filetime::FileTime::from_unix_time(
        filetime::FileTime::now().unix_seconds() - 15 * 86_400,
        0,
    );
    filetime::set_file_mtime(&stray, old).expect("mtime");
    let out = a.run(&["check"]).ok().stdout_has("all good");
    assert!(!out.stderr.contains("recent object"), "{}", out.stderr);
    out.stderr_has(
        "note: 1 object(s) in the data folders belong to no known blob and are older than 14 \
         days (leftovers of interrupted uploads); `gclone gc --orphans` collects them",
    );
    a.run(&["gc", "-n", "--orphans"])
        .ok()
        .stdout_has("1 orphans");
}

/// §17.14: `rm -r` says "restorable" and `restore` can do it for a directory; `mv` follows the
/// shell and replaces nothing unasked; a remote path that does not exist is an error for
/// everything that reads from it; `--json` is refused where it would print nothing.
#[test]
fn restore_mv_and_missing_paths_at_the_command_line() {
    let w = world();
    let (a, lab) = (&w.a, &w.lab);
    let src = s(&w.src);

    // --- rm -r names the command that undoes it, and that command works on the directory.
    a.run(&["rm", "-r", ":docs/sub"])
        .ok()
        .stdout_has("Removed 2 entries")
        .stdout_has("gclone restore -r :docs/sub");
    a.run(&["restore", "--list", ":docs/sub"])
        .ok()
        .stdout_has(":docs/sub/b.txt")
        .stdout_has(":docs/sub/deep/c.bin")
        .stdout_has("deleted")
        .stdout_has("2 files under :docs/sub can be restored");
    // From further up the same files show; the whole vault is `:`.
    a.run(&["restore", "--list", ":"])
        .ok()
        .stdout_has(":docs/sub/deep/c.bin");
    // Without -r a directory is not restored, and the answer is not "nothing restorable".
    a.run(&["restore", ":docs/sub"])
        .code(2)
        .stderr_has("gclone restore -r :docs/sub");
    a.run(&["ls", ":docs/sub"]).code(1);
    a.run(&["restore", "-r", ":docs/sub"])
        .ok()
        .stdout_has("Restored 2 files");
    assert_eq!(a.bytes(&["cat", ":docs/sub/b.txt"]), b"bravo\n");
    assert_eq!(
        a.bytes(&["cat", ":docs/sub/deep/c.bin"]),
        pattern(2, 70_000)
    );
    // Everything is back: nothing is left to restore there.
    a.run(&["restore", "--list", ":docs/sub"])
        .ok()
        .stdout_has("No restorable version");
    a.run(&["restore", "-r", ":docs/sub"]).code(1);
    // Several paths in one command; --version is for one file.
    a.run(&["rm", ":docs/a.txt", ":docs/empty"])
        .ok()
        .stdout_has("gclone restore :docs/a.txt :docs/empty");
    a.run(&["restore", ":docs/a.txt", ":docs/empty", "--version", "1"])
        .code(2);
    a.run(&["restore", ":docs/a.txt", ":docs/empty"])
        .ok()
        .stdout_has("Restored 2 files");
    assert_eq!(a.bytes(&["cat", ":docs/a.txt"]), b"alpha\n");
    // An overwritten file under a directory is listed as such and left alone by -r.
    write(&w.src.join("sub/b.txt"), b"bravo, second edition\n");
    a.run(&["copy", &src, ":docs"]).ok();
    a.run(&["restore", "--list", ":docs/sub"])
        .ok()
        .stdout_has("overwritten")
        .stdout_has("(0 deleted, 1 overwritten)");
    a.run(&["restore", "-r", ":docs/sub"])
        .code(1)
        .stderr_has("nothing under it is deleted");
    assert_eq!(
        a.bytes(&["cat", ":docs/sub/b.txt"]),
        b"bravo, second edition\n"
    );

    // --- mv: into an existing directory; nothing is replaced without --force.
    a.run(&["mv", ":docs/a.txt", ":docs/sub"])
        .ok()
        .stdout_has("Moved :docs/a.txt to :docs/sub/a.txt");
    a.run(&["mv", ":docs/sub/a.txt", ":docs/sub/b.txt"])
        .code(2)
        .stderr_has(":docs/sub/b.txt exists already")
        .stderr_has("--force");
    assert_eq!(
        a.bytes(&["cat", ":docs/sub/b.txt"]),
        b"bravo, second edition\n"
    );
    a.run(&["mv", "--force", ":docs/sub/a.txt", ":docs/sub/b.txt"])
        .ok()
        .stdout_has("Replaced 1 file there")
        .stdout_has("gclone restore --list :docs/sub/b.txt");
    assert_eq!(a.bytes(&["cat", ":docs/sub/b.txt"]), b"alpha\n");
    a.run(&["mv", ":docs/sub", ":docs/hollow"])
        .ok()
        .stdout_has("Moved :docs/sub to :docs/hollow/sub");
    a.run(&["mv", ":docs/hollow/sub", ":"])
        .ok()
        .stdout_has("Moved :docs/hollow/sub to :sub");
    a.run(&["mkdir", ":docs/hollow"])
        .ok()
        .stdout_has(":docs/hollow/ exists already");

    // --- reading from a remote path that is not there: an error, and nothing is created.
    let typo = lab.path("typo");
    a.run(&["copy", ":no/such/dir", &s(&typo)])
        .code(1)
        .stderr_has(":no/such/dir: no such directory in the vault");
    a.run(&["sync", ":docz", &s(&typo)]).code(1);
    a.run(&["sync", "-n", ":docz", &s(&typo)]).code(1);
    assert!(!typo.exists());
    a.run(&["check", "--download", ":no/such/dir"])
        .code(1)
        .stderr_has("no such file or directory in the vault");
    a.run(&["check", &src, ":docz"])
        .code(1)
        .stderr_has(":docz: no such directory in the vault");
    a.run(&["check", "--download", ":docs/big.bin"])
        .ok()
        .stdout_has("Checked 1 files: all good.");

    // --- --json exists for copy and sync; elsewhere it is refused instead of printing nothing.
    for args in [
        &["--json", "ls", ":"][..],
        &["status", "--json"],
        &["about", "--json"],
    ] {
        let out = a
            .run(args)
            .code(2)
            .stderr_has("--json is supported by copy, sync and `gclone keystore` only");
        assert_eq!(out.stdout, "");
    }

    // --- a file as the source: said, with the way to fetch one file.
    a.run(&["copy", &s(&w.src.join("a.txt")), ":single"])
        .code(2)
        .stderr_has("is not a directory: copy and sync transfer the contents of a directory")
        .stderr_has("gclone cat");
    a.run(&["copy", "", ":single"])
        .code(2)
        .stderr_has("empty string");

    // --- a run that only creates directories says so.
    let dirs = lab.path("dirs");
    std::fs::create_dir_all(dirs.join("inner")).unwrap();
    a.run(&["sync", "-n", &s(&dirs), ":dirs"])
        .ok()
        .stdout_has("+ mkdir")
        .stdout_has("Would create 1 directory. Nothing changed (dry run).");
    a.run(&["sync", &s(&dirs), ":dirs"])
        .ok()
        .stdout_has("1 directory created");

    // --- "not connected" names the command that works on this machine.
    let mut fresh = lab.device("fresh");
    if option_env!("GCLONE_DEFAULT_AUTH_URL").is_none() {
        fresh
            .run(&["ls"])
            .code(4)
            .stderr_has("Run `gclone login <AUTH_URL>`");
    }
    fresh
        .env
        .push(("GCLONE_AUTH_URL".into(), "https://auth.example.org".into()));
    fresh
        .run(&["ls"])
        .code(4)
        .stderr_has("Run `gclone login` (or");
}

/// §17.14: off a terminal the error text is all there is — every guard names the flag that
/// answers it, `--max-delete` is a limit that `--yes` does not lift, and the skips that `sync`
/// repeats forever come with the way out.
#[test]
fn guards_and_skips_name_the_way_out() {
    let w = world();
    let (a, lab) = (&w.a, &w.lab);

    // --- the delete guard and --max-delete
    let many = lab.path("many");
    for i in 0..12 {
        write(
            &many.join(format!("f{i:02}.txt")),
            format!("file {i}").as_bytes(),
        );
    }
    a.run(&["sync", &s(&many), ":many"]).ok();
    for i in 0..11 {
        std::fs::remove_file(many.join(format!("f{i:02}.txt"))).unwrap();
    }
    a.run(&["sync", &s(&many), ":many"])
        .code(5)
        .stderr_has("refusing to delete 11 of 12")
        .stderr_has("pass --yes");
    // --yes confirms the default limit, never an explicit --max-delete.
    a.run(&["sync", &s(&many), ":many", "--max-delete", "5", "--yes"])
        .code(5)
        .stderr_has("refusing to delete 11 files: --max-delete 5 allows no more")
        .stderr_has("raise --max-delete");
    assert_eq!(a.run(&["ls", ":many"]).ok().stdout.lines().count(), 12);
    a.run(&["sync", "-n", &s(&many), ":many", "--max-delete", "5"])
        .ok()
        .stderr_has("--max-delete 5 refuses that");
    a.run(&["sync", "-n", &s(&many), ":many"])
        .ok()
        .stderr_has("needs --yes");
    // Within the limit it runs without a question, and says where the deleted files are.
    a.run(&["sync", &s(&many), ":many", "--max-delete", "11"])
        .ok()
        .stdout_has("11 deleted")
        .stderr_has("gclone restore --list :many");
    assert_eq!(a.run(&["ls", ":many"]).ok().stdout.trim(), "f11.txt");
    a.run(&["restore", "-r", ":many"])
        .ok()
        .stdout_has("Restored 11 files");

    // --- a replaced root: both answers are named, with the paths.
    let moved = lab.path("many-old");
    std::fs::rename(&many, &moved).unwrap();
    copy_dir(&moved, &many, &[]);
    a.run(&["copy", &s(&many), ":many"])
        .code(5)
        .stderr_has("is not the directory last synced with :many")
        .stderr_has("--keep-pair")
        .stderr_has("--reset-pair");

    // --- a source that is not there is not "empty", and only sync is offered --force.
    let gone = s(&lab.path("no-such-source"));
    a.run(&["sync", &gone, ":many"])
        .code(5)
        .stderr_has("no-such-source does not exist")
        .stderr_has("--force");
    let out = a
        .run(&["copy", &gone, ":many"])
        .code(5)
        .stderr_has("does not exist");
    assert!(!out.stderr.contains("--force"), "{}", out.stderr);
    // An emptied source that was synced before.
    let emptied = lab.path("emptied");
    write(&emptied.join("only.txt"), b"only");
    a.run(&["sync", &s(&emptied), ":emptied"]).ok();
    std::fs::remove_file(emptied.join("only.txt")).unwrap();
    a.run(&["sync", &s(&emptied), ":emptied"])
        .code(5)
        .stderr_has("is empty although it was synced with :emptied before")
        .stderr_has("--force");

    // --- entries that exist only at the destination: kept on every run, with the way out.
    let (up1, up2) = (lab.path("up1"), lab.path("up2"));
    write(&up1.join("a"), b"a");
    write(&up2.join("b"), b"b");
    write(&up2.join("c"), b"c");
    a.run(&["copy", &s(&up2), ":mix"]).ok();
    for force in [&[][..], &["--force"]] {
        let mut args = vec!["sync"];
        args.extend_from_slice(force);
        args.extend_from_slice(&[up1.to_str().unwrap(), ":mix"]);
        a.run(&args)
            .code(6)
            .stdout_has("only in the vault and never synced here")
            .stderr_has("2 entries exist only in the vault")
            .stderr_has("--force does not either")
            .stderr_has(&format!("gclone copy :mix {}", s(&up1)));
    }
    // -q hides the skip lines; the reasons then go to stderr, since the run exits 6 over them.
    let quiet = a
        .run(&["-q", "sync", &s(&up1), ":mix"])
        .code(6)
        .stderr_has("warning: skipped b: only in the vault");
    assert!(!quiet.stdout.contains("! skip"), "{}", quiet.stdout);
    // The other direction.
    let down = lab.path("precious");
    write(&down.join("mine.txt"), b"mine");
    a.run(&["sync", ":mix", &s(&down)])
        .code(6)
        .stdout_has("only local and never synced")
        .stderr_has("1 entry exists only in the local directory")
        .stderr_has(&format!("gclone copy {} :mix", s(&down)));
    assert_eq!(std::fs::read(down.join("mine.txt")).unwrap(), b"mine");
    // The hint's remedy is one: after the copy the sync is clean.
    a.run(&["copy", ":mix", &s(&up1)]).ok();
    a.run(&["sync", &s(&up1), ":mix"]).ok();
}

#[test]
fn file_modes_and_places() {
    let w = world();
    let a = &w.a;
    let state = a.vault_state();

    for file in [a.secrets_file(), a.config_file(), state.join("state.db")] {
        assert_eq!(mode(&file), 0o600, "{}", file.display());
    }
    for dir in [
        a.config.clone(),
        a.state.clone(),
        state.clone(),
        state.join("index-cache"),
    ] {
        assert_eq!(mode(&dir), 0o700, "{}", dir.display());
    }
    for entry in std::fs::read_dir(&state).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            assert_eq!(mode(&path), 0o600, "{}", path.display());
        }
    }

    // The secrets live under the state root; the config directory holds config.json only, and
    // nothing in it is a secret.
    assert!(a.secrets_file().starts_with(&a.state));
    let in_config: Vec<String> = std::fs::read_dir(&a.config)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(in_config, ["config.json"]);
    let config = std::fs::read_to_string(a.config_file()).unwrap();
    for secret in ["key", "token", "passphrase", "client_secret"] {
        assert!(
            !config.contains(&format!("\"{secret}")),
            "config.json holds {secret:?}"
        );
    }
    let config = a.json(&a.config_file());
    assert_eq!(config["version"], 1);
    assert_eq!(config["vault_name"], "gclone");
    assert_eq!(config["backend"]["kind"], "dir");
    assert!(
        config.get("auth_url").is_none(),
        "no auth_url for a directory vault"
    );
    for key in ["vault_id", "root_id", "index_id", "data_id"] {
        assert!(config[key].is_string(), "{key}");
    }
    let secrets = std::fs::read_to_string(a.secrets_file()).unwrap();
    assert!(!secrets.contains("client_id") && !secrets.contains("client_secret"));
    assert!(!secrets.contains(PASS), "the passphrase is never stored");
    assert!(
        !a.token_file().exists(),
        "a directory vault has no access token"
    );
}

#[test]
fn concurrent_commands() {
    let w = world();
    let a = &w.a;
    // Another gclone holds the vault's process lock.
    let lock = gclone::state::lock_exclusive(&a.vault_state(), Duration::ZERO).expect("lock");

    let started = Instant::now();
    a.run(&["mkdir", ":blocked"])
        .code(1)
        .stderr_has("another gclone is running");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "it must not hang"
    );
    a.run(&["copy", &s(&w.src), ":docs"])
        .code(1)
        .stderr_has("another gclone is running");

    // Read-only commands use the replica as it is.
    let out = a
        .run(&["ls", ":docs"])
        .ok()
        .stdout_has("a.txt")
        .stderr_has("note: index not refreshed (another gclone is running)");
    assert!(!out.stdout.contains("blocked"));
    a.run(&["status"])
        .ok()
        .stderr_has("index not refreshed (another gclone is running)");

    // … also while the lock holder is inside a long write transaction (a rebuild from a
    // snapshot, a batch of applied segments). Regression: opening the vault always wrote to
    // state.db (device name, machine fingerprint), waited out SQLite's busy timeout and failed
    // with "local state database: database is locked" instead of listing the replica.
    let holder = rusqlite::Connection::open(a.vault_state().join("state.db")).unwrap();
    holder
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO ledger VALUES (1, 1, 1);")
        .unwrap();
    let started = Instant::now();
    let out = a
        .run(&["ls", ":docs"])
        .ok()
        .stdout_has("a.txt")
        .stderr_has("note: index not refreshed (another gclone is running)");
    assert!(!out.stderr.contains("database is locked"), "{}", out.stderr);
    a.run(&["tree", ":docs"]).ok().stdout_has("a.txt");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "a reader does not wait for the writer: {:?}",
        started.elapsed()
    );
    holder.execute_batch("ROLLBACK").unwrap();
    drop(holder);

    drop(lock);
    a.run(&["mkdir", ":blocked"]).ok();
    let out = a.run(&["ls"]).ok().stdout_has("blocked/");
    assert!(!out.stderr.contains("not refreshed"));
}

/// Regression: log lines were coloured although stderr was a pipe or a file.
#[test]
fn log_lines_in_a_pipe_carry_no_escape_codes() {
    let w = world();
    // A damaged index object makes the library log a warning while a new device attaches; the
    // harness reads stderr through a pipe, and `sane` refuses escape codes there.
    let index = w.vault_root().join("index");
    let seg = std::fs::read_dir(&index)
        .expect("index dir")
        .map(|e| e.expect("entry").path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("s-"))
        })
        .expect("a segment");
    let mut bytes = std::fs::read(&seg).expect("read segment");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 1;
    std::fs::write(&seg, bytes).expect("write segment");
    let b = w.lab.device("b");
    let out = b.run(&[
        "login",
        "--vault-dir",
        &w.vault,
        "--passphrase-file",
        &w.pass,
        "--device-name",
        "b",
    ]);
    assert!(
        out.stderr.contains("WARN") && out.stderr.contains("corrupt index object"),
        "expected a logged warning about the damaged index object:\n{}\n{}",
        out.stdout,
        out.stderr
    );
}

/// An index object written in a format this build does not read is a version mismatch, not
/// damage: it is not skipped with a warning about authentication — commands that change the
/// vault stop with exit 3, read-only commands say why they show an older state.
#[test]
fn an_index_object_of_a_newer_format_is_not_ignored() {
    let w = world();
    let a = &w.a;
    let index = w.vault_root().join("index");
    let seg = std::fs::read_dir(&index)
        .expect("index dir")
        .map(|e| e.expect("entry").path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("s-"))
        })
        .expect("a segment");
    // A copy of a real segment whose header names stream suite 2, under the name that matches
    // its content — what a later release could write into this vault.
    let mut bytes = std::fs::read(&seg).expect("read segment");
    bytes[4] = 0x02;
    let h8 = &blake3::hash(&bytes).to_hex()[..8];
    let name = format!("s-0909090909090909-0000000000000001-{h8}");
    let newer = index.join(&name);
    std::fs::write(&newer, bytes).expect("write object");

    let out = a
        .run(&["mkdir", ":made"])
        .code(3)
        .stderr_has(&name)
        .stderr_has("in a format this gclone cannot read (unsupported stream suite)")
        .stderr_has("needs a newer gclone")
        .stderr_has("Update gclone on this device.");
    assert!(!out.stderr.contains("failed verification"));
    a.run(&["ls"])
        .ok()
        .stderr_has("needs a newer gclone")
        .stderr_has("Showing the last state this device has seen");
    a.run(&["repair"]).code(3).stderr_has(&name);

    std::fs::remove_file(&newer).expect("remove object");
    a.run(&["mkdir", ":made"]).ok();
    let out = a.run(&["ls"]).ok().stdout_has("made/");
    assert!(!out.stderr.contains("newer gclone"));
}

#[test]
fn default_paths_are_xdg_under_home() {
    let lab = Lab::new();
    let home = lab.path("home");
    std::fs::create_dir_all(&home).unwrap();
    let pass = lab.pass();
    let run = |args: &[&str]| {
        let out = Command::new(BIN)
            .args(args)
            .env("HOME", &home)
            .env("GCLONE_TEST_FAST_KDF", "1")
            .env("GCLONE_KEYSTORE_TRIAL", "0")
            .env_remove("GCLONE_CONFIG_DIR")
            .env_remove("GCLONE_STATE_DIR")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_STATE_HOME")
            .stdin(Stdio::null())
            .output()
            .expect("spawn gclone");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&[
        "login",
        "--vault-dir",
        &s(&lab.path("vault")),
        "--passphrase-file",
        &pass,
    ]);
    run(&["ls"]);
    let config = home.join(".config/gclone");
    let state = home.join(".local/state/gclone");
    assert!(config.join("config.json").is_file());
    assert!(state.join("secrets.json").is_file());
    assert!(
        !config.join("secrets.json").exists(),
        "no secret under ~/.config"
    );
    assert_eq!(mode(&config), 0o700);
    assert_eq!(mode(&state), 0o700);
}

/// The obvious backup: the home directory as the sync root, with gclone's configuration and
/// state at their default places inside it (§5.5.3, §8.1).
#[test]
fn gclones_own_directories_under_the_sync_root_are_not_synced() {
    let lab = Lab::new();
    let pass = lab.pass();
    let device = |home: &Path| Device {
        config: home.join(".config/gclone"),
        state: home.join(".local/state/gclone"),
        home: home.to_path_buf(),
        env: Vec::new(),
    };
    let own = [
        "secrets.json",
        "config.json",
        "state.db",
        "index-cache",
        "keyfile",
    ];

    // Device A: its home holds the config, the state and the vault directory itself.
    let home_a = lab.path("homeA");
    std::fs::create_dir_all(home_a.join("Backups")).unwrap();
    let vault = s(&home_a.join("Backups/vault"));
    let a = device(&home_a);
    let login = |d: &Device, name: &str| {
        d.run(&[
            "login",
            "--vault-dir",
            &vault,
            "--passphrase-file",
            &pass,
            "--device-name",
            name,
        ])
        .ok();
    };
    login(&a, "A");
    write(&home_a.join("Documents/note.txt"), b"hello");
    write(&home_a.join(".config/other/app.toml"), b"x = 1\n");
    a.run(&["copy", &s(&home_a), ":home"])
        .ok()
        .stdout_has("2 uploaded")
        .stderr_has("gclone's own files are not synced")
        .stderr_has(".local/state/gclone");
    let listing = a.run(&["ls", "-R", ":home"]).ok().stdout;
    assert!(listing.contains("note.txt") && listing.contains("app.toml"));
    for name in own {
        assert!(!listing.contains(name), "{name} was uploaded:\n{listing}");
    }
    // The run does not feed on its own writes: a second one has nothing to do.
    a.run(&["sync", &s(&home_a), ":home"])
        .ok()
        .stdout_has("nothing to transfer");

    // A root inside one of the directories is refused before anything happens.
    for (src, dst) in [
        (s(&a.state), ":x".to_string()),
        (s(&a.vault_state()), ":x".to_string()),
        (s(&a.config), ":x".to_string()),
        (vault.clone(), ":x".to_string()),
        (":home".to_string(), s(&a.state.join("restore/here"))),
    ] {
        a.run(&["copy", &src, &dst])
            .code(2)
            .stderr_has("where gclone keeps its own files");
    }
    assert!(!a.state.join("restore").exists());

    // The remote can hold such files all the same — uploaded by a device whose own
    // directories are elsewhere, or by a version that did not exclude them.
    let c = lab.device("c");
    login(&c, "C");
    let tree = lab.path("treeC");
    write(&tree.join(".local/state/gclone/secrets.json"), b"not B's");
    write(&tree.join(".local/state/gclone/token.json"), b"not B's");
    write(&tree.join(".config/gclone/config.json"), b"not B's");
    write(&tree.join("Documents/from-c.txt"), b"c");
    c.run(&["copy", &s(&tree), ":home"])
        .ok()
        .stdout_has("4 uploaded");

    // Device B restores the backup into its own home: its login, its state and its device
    // identity are untouched, and nothing of gclone's arrives.
    let home_b = lab.path("homeB");
    let b = device(&home_b);
    login(&b, "B");
    let identity = b.identity();
    let secrets = std::fs::read(b.secrets_file()).unwrap();
    let config = std::fs::read(b.config_file()).unwrap();
    // The live database of this vault, under the path another device's copy would have.
    write(
        &tree
            .join(".local/state/gclone")
            .join(b.vault_state().file_name().unwrap())
            .join("state.db"),
        b"not B's database",
    );
    c.run(&["copy", &s(&tree), ":home"])
        .ok()
        .stdout_has("1 uploaded");
    b.run(&["copy", ":home", &s(&home_b)])
        .ok()
        .stdout_has("3 downloaded")
        .stderr_has("gclone's own files are not synced");
    assert_eq!(
        std::fs::read(home_b.join("Documents/note.txt")).unwrap(),
        b"hello"
    );
    assert_eq!(
        std::fs::read(home_b.join("Documents/from-c.txt")).unwrap(),
        b"c"
    );
    assert_eq!(std::fs::read(b.secrets_file()).unwrap(), secrets);
    assert_eq!(std::fs::read(b.config_file()).unwrap(), config);
    assert!(!b.token_file().exists());
    assert_eq!(mode(&b.vault_state().join("state.db")), 0o600);
    assert_eq!(b.identity(), identity);
    let after = snapshot(&home_b);
    let stray: Vec<&String> = after.keys().filter(|k| k.contains("conflict")).collect();
    assert!(stray.is_empty(), "{stray:?}");
    b.run(&["status"]).ok();
    // In sync mode the hidden rows are neither deleted remotely nor reported as skips.
    b.run(&["sync", &s(&home_b), ":home"]).ok();
    let listing = b.run(&["ls", "-R", ":home"]).ok().stdout;
    assert!(listing.contains("secrets.json"), "{listing}");
}

/// Ctrl-C while `login` polls for the code to be entered: exit 130, and nothing is left behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ctrl_c_exits_130() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let d = lab.device("a");
    let auth_url = format!("{}/auth", fake.base());
    let mut child = d
        .command(&["login", &auth_url, "--no-browser"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gclone");
    let stderr = child.stderr.take().expect("stderr");
    let (status, polls) = tokio::task::spawn_blocking(move || {
        let mut lines = std::io::BufReader::new(stderr).lines();
        let waiting = lines
            .by_ref()
            .map(|l| l.expect("stderr"))
            .any(|l| l.contains("waiting…"));
        assert!(waiting, "the login shows the code and waits");
        // Nobody enters the code; the login is polling by now.
        std::thread::sleep(Duration::from_millis(200));
        // SAFETY: signals the child this test spawned and still owns.
        assert_eq!(
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) },
            0
        );
        (child.wait().expect("wait"), lines.count())
    })
    .await
    .expect("join");
    assert_eq!(status.code(), Some(130));
    assert_eq!(polls, 0, "nothing more was printed");
    assert!(fake.hits(Route::AuthPoll) > 0);
    assert!(fake.issued_refresh_tokens().is_empty());
    assert!(!d.secrets_file().exists());
}

// ---------------------------------------------------------------------------------------------
// Drive mode against FakeDrive
// ---------------------------------------------------------------------------------------------

async fn run_async(d: &Device, args: &[&str]) -> Out {
    let (d, args) = (
        d.clone(),
        args.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
    );
    tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        d.run(&args)
    })
    .await
    .expect("join")
}

/// Runs a `login` that may ask for a sign-in: reads the code the binary prints and plays the
/// user, who enters it at the fake "Google" and approves (`FakeDrive::approve`) as the account
/// of `set_login_email`.
async fn drive_login(fake: &FakeDrive, d: &Device, args: &[&str]) -> Out {
    let mut child = d
        .command(args)
        .stdin(Stdio::null())
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
    let mut signed_in = false;
    loop {
        match rx.try_recv() {
            Ok(line) => {
                if let Some(code) = line.strip_prefix("and enter the code  ") {
                    assert!(!signed_in, "one sign-in per run");
                    signed_in = true;
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
    }
    .sane()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drive_mode() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let pass = lab.pass();
    let auth_url = format!("{}/auth", fake.base());
    let device = |name: &str| {
        let mut d = lab.device(name);
        d.env = vec![
            ("GCLONE_TEST_DRIVE_API".into(), fake.base().to_string()),
            (
                "GCLONE_TEST_DRIVE_UPLOAD".into(),
                format!("{}/upload", fake.base()),
            ),
            (
                "GCLONE_TEST_REVOKE_URL".into(),
                format!("{}/revoke", fake.base()),
            ),
        ];
        d
    };
    let (a, b) = (device("a"), device("b"));
    let refresh_token = |d: &Device| {
        d.json(&d.secrets_file())["refresh_token"]
            .as_str()
            .expect("refresh_token")
            .to_string()
    };

    // A URL that is not https (and not loopback) is refused before any request.
    run_async(
        &a,
        &[
            "login",
            "http://example.com",
            "--no-browser",
            "--passphrase-file",
            &pass,
        ],
    )
    .await
    .code(4)
    .stderr_has("The auth Worker URL must be https://")
    .stderr_has("http://example.com");
    run_async(&a, &["login", "--no-browser", "--passphrase-file", &pass])
        .await
        .code(4)
        .stderr_has("gclone login <AUTH_URL>");
    assert_eq!(fake.hits(Route::AuthStart) + fake.hits(Route::AuthPoll), 0);
    assert!(!a.secrets_file().exists());

    // --- first device: sign in, create the vault
    let out = drive_login(
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
    .await
    .ok()
    .stdout_has("Signed in as me@example.com.")
    .stdout_has("Vault created. This device: \"mbp\".")
    .stderr_has("To sign in, open  https://www.google.com/device")
    .stderr_has("(enter only a code shown in this terminal; waiting…)");
    let user_code = fake.last_user_code().expect("a login was started");
    assert!(
        out.stderr
            .contains(&format!("and enter the code  {user_code}\n")),
        "the terminal shows the code Google expects:\n{}",
        out.stderr
    );
    assert!(!a.token_file().exists(), "login never writes token.json");

    // --- second device: the same command attaches
    let out = drive_login(
        &fake,
        &b,
        &[
            "login",
            &auth_url,
            "--no-browser",
            "--passphrase-file",
            &pass,
            "--device-name",
            "nas",
        ],
    )
    .await
    .ok()
    .stdout_has("Signed in as me@example.com.")
    .stdout_has("Connected to vault \"gclone\" (0 files). This device: \"nas\".");
    let head = login_head(&out.stdout);
    assert!(!b.token_file().exists());
    let issued = fake.issued_refresh_tokens();
    assert_eq!(issued.len(), 2);
    assert_ne!(
        issued[0], issued[1],
        "every device has its own refresh token"
    );
    assert_eq!(refresh_token(&a), issued[0]);
    assert_eq!(refresh_token(&b), issued[1]);

    // Secrets and config of a Drive vault; nothing secret under the config directory.
    let secrets = a.json(&a.secrets_file());
    assert_eq!(secrets["auth_url"], auth_url.as_str());
    assert_eq!(secrets["email"], "me@example.com");
    assert_eq!(secrets["client"], "device");
    assert!(secrets["consent_ms"].is_u64());
    assert!(secrets["refresh_expires_at_ms"].is_null());
    assert!(secrets.get("client_id").is_none() && secrets.get("client_secret").is_none());
    let config = a.json(&a.config_file());
    assert_eq!(config["backend"], serde_json::json!({ "kind": "drive" }));
    assert_eq!(config["auth_url"], auth_url.as_str());
    let config_text = std::fs::read_to_string(a.config_file()).unwrap();
    assert!(!config_text.contains(&issued[0]) && !config_text.contains("\"keys\""));
    assert_eq!(mode(&a.secrets_file()), 0o600);
    assert_eq!(mode(&a.config_file()), 0o600);

    // --- copy up on one device, down on the other
    let src = lab.path("src");
    make_tree(&src);
    let out = run_async(&a, &["-vv", "copy", &s(&src), ":docs", "--transfers", "2"])
        .await
        .ok()
        .stdout_has("5 uploaded");
    assert!(
        out.stderr.contains("transfers=2"),
        "--transfers reaches the backend configuration:\n{}",
        out.stderr
    );
    // The first command that makes a real refresh writes the token cache — 0600, state root.
    assert!(a.token_file().exists());
    assert_eq!(mode(&a.token_file()), 0o600);
    let down = lab.path("down");
    run_async(&b, &["copy", ":docs", &s(&down)])
        .await
        .ok()
        .stdout_has("5 downloaded");
    assert_eq!(snapshot(&src), snapshot(&down));
    let status = run_async(&a, &["status"]).await.ok().stdout;
    let login = status_line(&status, "Login");
    assert!(login.starts_with("ok — me@example.com via "), "{login}");
    assert!(
        login.contains(&auth_url) && login.contains("last refresh"),
        "{login}"
    );
    assert_eq!(a.head(), b.head());
    assert_ne!(a.head(), head, "the head moved with the upload");
    run_async(&a, &["about"])
        .await
        .ok()
        .stdout_has("Drive storage ");
    let probes = run_async(&a, &["probe"]).await;
    assert!(probes.code == 0 || probes.code == 1, "{}", probes.stderr);
    assert!(
        probes.stdout.lines().count() >= 6,
        "one line per probe row:\n{}",
        probes.stdout
    );

    // --- the login expires: every command says so, `login` (no URL) repairs it
    fake.revoke_refresh_token();
    run_async(&a, &["ls"])
        .await
        .code(4)
        .stderr_has("Google no longer accepts this device's login")
        .stderr_has("Run `gclone login`.");
    drive_login(&fake, &a, &["login", "--no-browser"])
        .await
        .ok()
        .stdout_has("Signed in again as me@example.com. Vault unchanged.");
    assert!(!a.token_file().exists(), "no token cache after a login");
    assert_eq!(refresh_token(&a), fake.issued_refresh_tokens()[2]);
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");
    assert!(a.token_file().exists());

    // --- re-login with the wrong Google account: the vault is not visible to that login
    fake.revoke_refresh_token();
    let secrets_before = std::fs::read(a.secrets_file()).unwrap();
    fake.fail_next(Route::Stat, 1, 403, "appNotAuthorizedToFile");
    drive_login(&fake, &a, &["login", "--no-browser"])
        .await
        .code(4)
        .stderr_has("The Google login just made (signed in as me@example.com) cannot see the vault this device is attached to")
        .stderr_has("Nothing was changed on this device, and the new sign-in was not kept.")
        .stderr_has("worker/README.md");
    assert!(
        std::fs::read(a.secrets_file()).unwrap() == secrets_before,
        "the previous refresh token stays on file"
    );
    assert!(
        !a.token_file().exists(),
        "no access token of the wrong login is left behind"
    );
    let out = run_async(&a, &["ls"])
        .await
        .code(4)
        .stderr_has("Run `gclone login`.");
    assert!(
        !out.stderr.contains("cannot see the vault"),
        "{}",
        out.stderr
    );
    drive_login(&fake, &a, &["login", "--no-browser"])
        .await
        .ok()
        .stdout_has("Signed in again");
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");
    // A login that still works is kept: no sign-in, nothing changes.
    let secrets_before = std::fs::read(a.secrets_file()).unwrap();
    let logins = fake.hits(Route::AuthStart);
    run_async(&a, &["login"])
        .await
        .ok()
        .stdout_has("Already signed in as me@example.com.")
        .stdout_has("Vault unchanged.");
    assert_eq!(fake.hits(Route::AuthStart), logins);
    assert!(std::fs::read(a.secrets_file()).unwrap() == secrets_before);

    // --- logout, then login without a URL: the same device again
    let identity = a.identity();
    run_async(&a, &["logout"])
        .await
        .ok()
        .stdout_has("Signed out on this device.")
        .stdout_has("The Google token was discarded, not revoked")
        .stdout_has("gclone logout --revoke");
    assert!(!a.secrets_file().exists() && !a.token_file().exists());
    assert!(a.config_file().exists());
    assert!(fake.revoked().is_empty(), "a plain logout revokes nothing");
    let out = run_async(&a, &["ls"])
        .await
        .code(4)
        .stderr_has("This device is not connected (signed out). Run `gclone login`.");
    assert!(!out.stderr.contains("--vault-dir"));
    run_async(
        &a,
        &[
            "login",
            "--vault-dir",
            &s(&lab.path("dir-vault")),
            "--passphrase-file",
            &pass,
        ],
    )
    .await
    .code(2)
    .stderr_has("gclone logout --forget");
    drive_login(
        &fake,
        &a,
        &["login", "--no-browser", "--passphrase-file", &pass],
    )
    .await
    .ok()
    .stdout_has("Signed in as me@example.com.")
    .stdout_has("Connected to vault \"gclone\" (5 files). This device: \"mbp\".");
    assert!(!a.token_file().exists());
    assert_eq!(
        a.identity(),
        identity,
        "the same device id as before the logout"
    );

    // --- an expiring login (OAuth app in Testing) is refused, unless explicitly allowed
    fake.set_refresh_expires_in(Some(604_799));
    let c = device("c");
    drive_login(
        &fake,
        &c,
        &[
            "login",
            &auth_url,
            "--no-browser",
            "--passphrase-file",
            &pass,
        ],
    )
    .await
    .code(4)
    .stderr_has("Google will expire this login in 7 days")
    .stderr_has("still in Testing")
    .stderr_has("Publish app");
    assert!(!c.secrets_file().exists(), "nothing is stored");
    assert!(!c.config_file().exists() && !c.token_file().exists());
    drive_login(
        &fake,
        &c,
        &[
            "login",
            &auth_url,
            "--no-browser",
            "--passphrase-file",
            &pass,
            "--allow-expiring-login",
            "--device-name",
            "third",
        ],
    )
    .await
    .ok()
    .stdout_has("Connected to vault");
    let expires = c.json(&c.secrets_file())["refresh_expires_at_ms"]
        .as_u64()
        .expect("the expiry lands in secrets.json");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(expires > now + 6 * 86_400_000 && expires < now + 8 * 86_400_000);
    run_async(&c, &["status"]).await.ok().stderr_has(
        "Login expires in 7 days (OAuth app in Testing? → Publish app, then `gclone login`)",
    );
    fake.set_refresh_expires_in(None);

    // --- sign out everywhere (the second device's login died with the revocations above)
    run_async(&b, &["ls"]).await.code(4);
    drive_login(&fake, &b, &["login", "--no-browser"])
        .await
        .ok()
        .stdout_has("Signed in again as me@example.com. Vault unchanged.");
    run_async(&b, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");
    let token = refresh_token(&b);
    run_async(&b, &["logout", "--revoke"])
        .await
        .code(2)
        .stderr_has("--yes");
    assert!(fake.revoked().is_empty() && b.secrets_file().exists());
    run_async(&b, &["logout", "--revoke", "--yes"])
        .await
        .ok()
        .stderr_has("This ends the Google login of ALL your gclone devices")
        .stderr_has("keep a web download of the vault folder first")
        .stdout_has("Signed out on this device.")
        .stdout_has("Google revoked the login of all your gclone devices");
    assert_eq!(fake.revoked(), [token]);
    assert!(!b.secrets_file().exists() && !b.token_file().exists());
    // Revocation is grant-wide: the other devices are signed out too.
    run_async(&a, &["ls"])
        .await
        .code(4)
        .stderr_has("Run `gclone login`.");
}

/// The final-pass smoke test, kept as a regression test: the binary against `FakeDrive` over
/// HTTP with a varied tree — an empty file, packed small files, a file above 20 MiB (a
/// resumable upload of more than one part), Unicode names, nested and empty directories —
/// between two devices, then modify / delete / rename, sync again, and `check`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drive_mode_varied_tree_round_trip() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let pass = lab.pass();
    let auth_url = format!("{}/auth", fake.base());
    let device = |name: &str| {
        let mut d = lab.device(name);
        d.env = vec![
            ("GCLONE_TEST_DRIVE_API".into(), fake.base().to_string()),
            (
                "GCLONE_TEST_DRIVE_UPLOAD".into(),
                format!("{}/upload", fake.base()),
            ),
        ];
        d
    };
    let (a, b) = (device("a"), device("b"));
    for (d, name) in [(&a, "mbp"), (&b, "nas")] {
        drive_login(
            &fake,
            d,
            &[
                "login",
                &auth_url,
                "--no-browser",
                "--passphrase-file",
                &pass,
                "--device-name",
                name,
            ],
        )
        .await
        .ok();
    }

    let src = lab.path("src");
    const BIG: usize = 21 * 1024 * 1024 + 4321;
    write(&src.join("empty.txt"), b"");
    write(&src.join("small.txt"), b"hello\n");
    write(&src.join("one-byte"), b"a");
    write(&src.join("big.bin"), &pattern(7, BIG));
    write(&src.join("medium.bin"), &pattern(8, 5_000_000));
    write(&src.join("nested/deep/deeper/leaf.txt"), b"leaf\n");
    write(&src.join("nested/deep/s70k.bin"), &pattern(9, 70_000));
    write(&src.join("dir with spaces/file with spaces.txt"), b"sp\n");
    write(
        &src.join("ünïcödé/日本語/ファイル.txt"),
        "ユニコード\n".as_bytes(),
    );
    write(&src.join("ünïcödé/smile 😀.txt"), b"emoji\n");
    write(&src.join("ünïcödé/привет.md"), "кириллица\n".as_bytes());
    for i in 0..40 {
        write(
            &src.join(format!("nested/f{i}.txt")),
            &pattern(100 + i as u8, 300 + i),
        );
    }
    std::fs::create_dir_all(src.join("hollow")).expect("mkdir");
    let files = 11 + 40;

    // --- up from the first device; a second run has nothing to do
    run_async(&a, &["sync", &s(&src), ":data"])
        .await
        .ok()
        .stdout_has(&format!("{files} uploaded"));
    assert!(
        fake.session_requests().len() >= 2,
        "the 21 MiB file went up as a resumable upload of several parts: {:?}",
        fake.session_requests()
    );
    run_async(&a, &["sync", &s(&src), ":data"])
        .await
        .ok()
        .stdout_has("nothing to transfer");

    // --- down on the second device: the trees are equal
    let dst = lab.path("dst");
    run_async(&b, &["sync", ":data", &s(&dst)])
        .await
        .ok()
        .stdout_has(&format!("{files} downloaded"));
    assert_eq!(snapshot(&src), snapshot(&dst));
    run_async(&b, &["sync", ":data", &s(&dst)])
        .await
        .ok()
        .stdout_has("nothing to transfer");
    assert_eq!(a.head(), b.head());

    // --- modify, delete, rename (a file and a directory), add; sync again
    let mut big = pattern(7, BIG);
    big.extend_from_slice(b"appended");
    write(&src.join("big.bin"), &big);
    write(&src.join("small.txt"), b"hello\nmodified\n");
    std::fs::remove_file(src.join("nested/f7.txt")).expect("rm");
    std::fs::remove_file(src.join("nested/deep/s70k.bin")).expect("rm");
    std::fs::rename(src.join("medium.bin"), src.join("renamed-medium.bin")).expect("mv");
    std::fs::rename(src.join("ünïcödé"), src.join("юникод")).expect("mv");
    write(&src.join("nested/brand-new.txt"), b"new\n");
    std::fs::remove_dir(src.join("hollow")).expect("rmdir");
    run_async(&a, &["sync", &s(&src), ":data"])
        .await
        .ok()
        // big.bin, small.txt, brand-new.txt; the four renamed files cost no upload.
        .stdout_has("3 uploaded")
        .stdout_has("4 reused");
    run_async(&b, &["sync", ":data", &s(&dst)]).await.ok();
    assert_eq!(snapshot(&src), snapshot(&dst));
    assert_eq!(a.head(), b.head());

    // --- every check is clean, on both devices
    run_async(&a, &["check"]).await.ok().stdout_has("all good");
    run_async(&b, &["check", "--download"])
        .await
        .ok()
        .stdout_has("all good");
    run_async(&b, &["check", &s(&dst), ":data"])
        .await
        .ok()
        .stdout_has("all good");
    let cat = b.bytes(&[
        "cat",
        ":data/big.bin",
        "--offset",
        "22000000",
        "--count",
        "777",
    ]);
    assert_eq!(cat, big[22_000_000..22_000_777]);
}

// ---------------------------------------------------------------------------------------------
// Drive mode: an unreachable auth Worker, the wrong Google account, `logout --revoke --forget`
// ---------------------------------------------------------------------------------------------

/// The high-severity finding of the second key-store review (§8.2, §17.28). A sealed device;
/// the Secure Enclave answers with an error and then works again — a transient failure, a few
/// seconds of it are enough. Every command says "the stored key cannot be used any more …
/// Run `gclone login`"; that login finds "no usable secrets", signs in at Google, and saves
/// the grant WITHOUT a key before it asks for the passphrase. By then the sealed file opened
/// again, and the keyless document was re-sealed over it: the only copy of the vault key on
/// the device was gone before the passphrase was asked — a wrong, forgotten or abandoned
/// passphrase left the device locked. (Drive vaults only: a directory vault has no keyless
/// save.) Sealed keys are never replaced by a document without keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drive_mode_a_transient_enclave_failure_during_login_keeps_the_sealed_key() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let pass = lab.pass();
    let auth_url = format!("{}/auth", fake.base());
    let mut a = drive_device(&lab, &fake, "a");
    a.env
        .push(("GCLONE_TEST_KEYSTORE_SEALER".into(), "fake".into()));
    let login = [
        "login",
        &auth_url,
        "--no-browser",
        "--passphrase-file",
        &pass,
    ];
    drive_login(&fake, &a, &login).await.ok();
    let src = lab.path("src");
    make_tree(&src);
    run_async(&a, &["copy", &s(&src), ":docs"]).await.ok();
    let sealed = a.state.join("secrets.sealed");
    let use_enclave = [
        "keystore",
        "use",
        "enclave",
        "--yes",
        "--passphrase-file",
        &pass,
    ];
    run_async(&a, &use_enclave).await.ok();
    assert!(sealed.exists() && !a.secrets_file().exists());
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");
    let sealed_before = std::fs::read(&sealed).unwrap();
    let flaky = |fail: &str| {
        let mut d = a.clone();
        d.env
            .push(("GCLONE_TEST_KEYSTORE_FAIL".into(), fail.to_string()));
        d
    };

    // One failed call is not a dead key: the stored key is tried a second time, and the
    // command simply works. Nobody is sent to `gclone login`.
    let out = run_async(&flaky("open-first"), &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");
    assert!(!out.stderr.contains("gclone login"), "{}", out.stderr);

    // Two in a row: the command says what it has to say …
    run_async(&flaky("open-first-2"), &["ls", ":docs"])
        .await
        .code(4)
        .stderr_has("the stored key cannot be used any more")
        .stderr_has("tried twice")
        .stderr_has("The sealed file is kept until that login has the key again.");
    assert_eq!(std::fs::read(&sealed).unwrap(), sealed_before);

    // … and the login it sends the owner to — with the enclave failing twice and working
    // from then on, and with a WRONG passphrase — keeps that promise.
    let wrong = lab.file("wrong-pass", "not the passphrase at all\n");
    let out = drive_login(
        &fake,
        &flaky("open-first-2"),
        &[
            "login",
            &auth_url,
            "--no-browser",
            "--passphrase-file",
            &wrong,
        ],
    )
    .await
    .code(4)
    .stderr_has("the stored key cannot be used any more")
    .stderr_has("Wrong passphrase.");
    assert!(out.stdout.contains("Signed in"), "{}", out.stdout);
    assert_eq!(
        std::fs::read(&sealed).unwrap(),
        sealed_before,
        "secrets.sealed is byte for byte what it was"
    );
    // The login just made lies in secrets.json without a key; the key is where it was. The
    // device works, and says where its two halves are.
    assert_eq!(
        a.json(&a.secrets_file())["keys"].as_array().unwrap().len(),
        0
    );
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");
    run_async(&a, &["cat", ":docs/a.txt"])
        .await
        .ok()
        .stdout_has("alpha");
    run_async(&a, &["keystore"]).await.ok().stdout_has(
        "Secure Enclave of this Mac (secrets.sealed) for the key, secrets.json for the login",
    );

    // The same with a passphrase prompt that is abandoned (no terminal, no file).
    let out = drive_login(
        &fake,
        &flaky("open-first-2"),
        &["login", &auth_url, "--no-browser"],
    )
    .await;
    assert_ne!(out.code, 0, "{}", out.stderr);
    assert_eq!(std::fs::read(&sealed).unwrap(), sealed_before);
    run_async(&a, &["ls", ":docs"]).await.ok();

    // A login with the passphrase settles the two files into one.
    drive_login(&fake, &a, &login).await.ok();
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");
    assert!(a.secrets_file().exists() != sealed.exists(), "one store");
}

/// §17.30: on a Mac the sealed store is the default, and a login seals from its first save.
/// For a Drive vault that first save is the grant alone, written before the passphrase is
/// asked: killed right after it, the device holds a sealed login without a key and no plain
/// file — and the login that follows seals the keys to the same key. No `secrets.json` at any
/// point, no choice on file, no command.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drive_mode_a_login_on_a_mac_is_sealed_from_its_first_save() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let pass = lab.pass();
    let auth_url = format!("{}/auth", fake.base());
    let mut a = drive_device(&lab, &fake, "a");
    // A Mac as its owner runs it: the stand-in for the Secure Enclave, and no opt-out in the
    // environment (the harness sets one for every other test).
    for (name, value) in [
        ("GCLONE_TEST_KEYSTORE_SEALER", "fake"),
        ("GCLONE_KEYSTORE_TRIAL", "1"),
        ("GCLONE_TEST_BOOT", "boot-a"),
        ("GCLONE_TEST_SESSION", "0x2030"),
    ] {
        a.env.push((name.into(), value.into()));
    }
    let login = [
        "login",
        &auth_url,
        "--no-browser",
        "--passphrase-file",
        &pass,
    ];
    let sealed = a.state.join("secrets.sealed");
    let names = |d: &Device| -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&d.state)
            .expect("state root")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };

    // Killed right after the first save — the grant, before the passphrase is asked.
    let mut killed = a.clone();
    killed.env.push((
        "GCLONE_TEST_KEYSTORE_STOP".into(),
        "save-sealed-done".into(),
    ));
    let out = drive_login(&fake, &killed, &login).await;
    assert_eq!(
        out.code, 137,
        "the stop point of the first save\n{}",
        out.stderr
    );
    assert!(
        sealed.exists() && !a.secrets_file().exists(),
        "{:?}",
        names(&a)
    );
    assert!(
        names(&a).iter().all(|name| !name.contains("secrets.json")),
        "no plain copy, not under a temp name either: {:?}",
        names(&a)
    );
    let envelope = a.json(&sealed);
    assert_eq!(envelope["store"], "enclave");
    assert!(
        envelope.get("vault_id").is_none(),
        "the sealed document holds the login and no key yet"
    );
    let first_key = envelope["public"].clone();
    let members: Vec<&str> = envelope
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        members,
        [
            "alg",
            "key",
            "public",
            "sealed",
            "sealed_ms",
            "store",
            "version"
        ],
        "an envelope: no member of a secrets document in plain"
    );

    // The login again: it finds its grant in the sealed store, asks for nothing twice, and
    // seals the keys to the same key.
    let out = drive_login(&fake, &a, &login).await.ok();
    assert!(
        out.stderr
            .contains("This device's login and key are sealed by this Mac's Secure Enclave"),
        "{}",
        out.stderr
    );
    assert!(
        sealed.exists() && !a.secrets_file().exists(),
        "{:?}",
        names(&a)
    );
    let envelope = a.json(&sealed);
    assert_eq!(envelope["public"], first_key, "one key for both saves");
    assert!(envelope["vault_id"].is_string(), "it holds the keys now");
    assert!(!a.state.join("keystore.json").exists(), "nobody chose");
    assert!(names(&a).iter().all(|name| !name.contains(".tmp-")));
    let src = lab.path("src");
    make_tree(&src);
    run_async(&a, &["copy", &s(&src), ":docs"]).await.ok();
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");
    run_async(&a, &["status"])
        .await
        .ok()
        .stdout_has("Key store    Secure Enclave of this Mac (secrets.sealed)");

    // A second device, in one go: sealed as well, with the vault's key from the keyfile.
    let mut b = drive_device(&lab, &fake, "b");
    b.env = a.env.clone();
    b.env
        .push(("GCLONE_TEST_KEYSTORE_MACHINE".into(), "mac-2".into()));
    drive_login(&fake, &b, &login).await.ok();
    assert!(b.state.join("secrets.sealed").exists() && !b.secrets_file().exists());
    run_async(&b, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");
    // A logout of either leaves no secret behind.
    run_async(&a, &["logout"]).await.ok();
    assert!(!sealed.exists() && !a.secrets_file().exists());
}

/// F2 of the key-store review (§8.2, §17.28): the device's secrets are sealed, an older gclone
/// says "not signed in", its `login` signs in and writes `secrets.json` with the login and no
/// key — and its passphrase prompt is abandoned. The key stays where it is: every command
/// keeps working with the login just made and the sealed keys, nothing is deleted, and a
/// later `login` settles the two files.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drive_mode_a_keyless_login_file_beside_the_sealed_store() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let pass = lab.pass();
    let auth_url = format!("{}/auth", fake.base());
    let mut a = drive_device(&lab, &fake, "a");
    a.env
        .push(("GCLONE_TEST_KEYSTORE_SEALER".into(), "fake".into()));
    let login = [
        "login",
        &auth_url,
        "--no-browser",
        "--passphrase-file",
        &pass,
    ];
    drive_login(&fake, &a, &login).await.ok();
    let src = lab.path("src");
    make_tree(&src);
    run_async(&a, &["copy", &s(&src), ":docs"]).await.ok();
    let original = a.json(&a.secrets_file());
    assert_eq!(original["keys"].as_array().unwrap().len(), 1);

    let sealed = a.state.join("secrets.sealed");
    run_async(
        &a,
        &[
            "keystore",
            "use",
            "enclave",
            "--yes",
            "--passphrase-file",
            &pass,
        ],
    )
    .await
    .ok();
    assert!(sealed.exists() && !a.secrets_file().exists());
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");
    let sealed_before = std::fs::read(&sealed).unwrap();

    // What gclone 0.4.0 writes after the sign-in and before it asks for the passphrase
    // (its login.rs: `keys: []`): the login alone.
    let mut keyless = original.clone();
    keyless["keys"] = serde_json::json!([]);
    keyless["min_epoch"] = serde_json::json!(0);
    let write_keyless = |a: &Device| {
        std::fs::write(
            a.secrets_file(),
            serde_json::to_vec_pretty(&keyless).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(a.secrets_file(), std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    write_keyless(&a);

    // Every command keeps working: the login of secrets.json, the keys of secrets.sealed.
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");
    let more = lab.path("more");
    write(&more.join("later.txt"), b"later\n");
    run_async(&a, &["copy", &s(&more), ":docs"]).await.ok();
    assert_eq!(a.bytes(&["cat", ":docs/later.txt"]), b"later\n");
    run_async(&a, &["status"])
        .await
        .ok()
        .stdout_has("Key store    Secure Enclave of this Mac (secrets.sealed) for the key, secrets.json for the login")
        .stderr_has("secrets.json holds a login without a key (an older gclone signed in here)");
    // Nothing was merged on disk, and nothing was removed.
    assert_eq!(std::fs::read(&sealed).unwrap(), sealed_before);
    assert_eq!(a.json(&a.secrets_file())["keys"], serde_json::json!([]));
    // The move refuses to guess; `login` is how the two files are settled.
    run_async(
        &a,
        &[
            "keystore",
            "use",
            "enclave",
            "--yes",
            "--passphrase-file",
            &pass,
        ],
    )
    .await
    .code(1)
    .stderr_has("Run `gclone login` first");
    assert_eq!(std::fs::read(&sealed).unwrap(), sealed_before);

    // The sealed keys are for the vault they were sealed for: with another vault in
    // config.json there is no merged view, and the command says what it says for a login
    // without a key.
    let config = a.json(&a.config_file());
    let mut elsewhere = config.clone();
    elsewhere["vault_id"] = "ffeeddccbbaa99887766554433221100".into();
    std::fs::write(a.config_file(), serde_json::to_vec(&elsewhere).unwrap()).unwrap();
    run_async(&a, &["ls", ":docs"])
        .await
        .code(4)
        .stderr_has("Run `gclone login` to finish connecting this device");
    std::fs::write(a.config_file(), serde_json::to_vec(&config).unwrap()).unwrap();
    assert_eq!(std::fs::read(&sealed).unwrap(), sealed_before);

    // `keystore use file` writes the merged view as one plain file …
    run_async(&a, &["keystore", "use", "file"])
        .await
        .ok()
        .stdout_has("are now one plain file");
    assert!(!sealed.exists());
    assert_eq!(a.json(&a.secrets_file())["keys"], original["keys"]);
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("later.txt");

    // … and so does a later `login`, which has the passphrase: back in the sealed store,
    // the keyless file beside it again, then the login that settles it.
    run_async(
        &a,
        &[
            "keystore",
            "use",
            "enclave",
            "--yes",
            "--passphrase-file",
            &pass,
        ],
    )
    .await
    .ok();
    write_keyless(&a);
    let out = drive_login(&fake, &a, &login).await.ok();
    // Exactly one store — and, the sealed store being what this device uses, the sealed one
    // (§17.30: the login's saves made the two files one plain file, and its end moved that
    // into the sealed store again; it used to stay in secrets.json).
    assert!(
        sealed.exists() && !a.secrets_file().exists(),
        "exactly one store, the sealed one"
    );
    assert!(
        out.stderr
            .contains("This device's login and key are sealed by this Mac's Secure Enclave"),
        "{}",
        out.stderr
    );
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("later.txt");
    run_async(&a, &["status"])
        .await
        .ok()
        .stdout_has("Key store    Secure Enclave of this Mac (secrets.sealed)");
    run_async(&a, &["keystore", "use", "file"]).await.ok();
    assert_eq!(a.json(&a.secrets_file())["keys"], original["keys"]);
}

/// A device for `FakeDrive`, as in `drive_mode`.
fn drive_device(lab: &Lab, fake: &FakeDrive, name: &str) -> Device {
    let mut d = lab.device(name);
    d.env = vec![
        ("GCLONE_TEST_DRIVE_API".into(), fake.base().to_string()),
        (
            "GCLONE_TEST_DRIVE_UPLOAD".into(),
            format!("{}/upload", fake.base()),
        ),
        (
            "GCLONE_TEST_REVOKE_URL".into(),
            format!("{}/revoke", fake.base()),
        ),
    ];
    d
}

/// Runs the binary on a pseudo-terminal — stdin and stderr are the terminal, stdout is a pipe —
/// and types `answer` when `prompt` shows up, in the given order. `Out::stderr` is everything
/// the terminal showed (the echo of the answers included).
fn run_on_tty(d: &Device, args: &[&str], answers: &[(&str, &str)]) -> Out {
    run_on_a_terminal(d, args, answers, false)
}

/// As [`run_on_tty`], with the pseudo-terminal as the **controlling** terminal of the binary:
/// a passphrase is read from `/dev/tty` and from nowhere else, so a prompt for one needs it.
fn run_on_login_tty(d: &Device, args: &[&str], answers: &[(&str, &str)]) -> Out {
    run_on_a_terminal(d, args, answers, true)
}

fn run_on_a_terminal(
    d: &Device,
    args: &[&str],
    answers: &[(&str, &str)],
    controlling: bool,
) -> Out {
    use std::io::Read as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::process::CommandExt as _;

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
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    // SAFETY: fcntl on a descriptor this function owns.
    let rc = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
    assert_eq!(rc, 0, "fcntl: {}", std::io::Error::last_os_error());

    let mut command = d.command(args);
    command
        .stdin(Stdio::from(slave.try_clone().expect("dup")))
        .stderr(Stdio::from(slave.try_clone().expect("dup")))
        .stdout(Stdio::piped());
    if controlling {
        // SAFETY: the closure runs in the forked child before exec and makes only the two
        // async-signal-safe calls: a new session, with descriptor 0 (the slave side, by then)
        // as its controlling terminal.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = command.spawn().expect("spawn gclone");
    let stdout = child.stdout.take().expect("stdout");
    let stdout = std::thread::spawn(move || std::io::read_to_string(stdout).expect("stdout"));

    let terminal = std::fs::File::from(master);
    let mut shown = String::new();
    let (mut searched, mut next) = (0, 0);
    let deadline = Instant::now() + Duration::from_secs(120);
    let read_available = |shown: &mut String| {
        let mut buf = [0u8; 4096];
        loop {
            match (&terminal).read(&mut buf) {
                Ok(n) if n > 0 => shown.push_str(&String::from_utf8_lossy(&buf[..n])),
                _ => return,
            }
        }
    };
    let status = loop {
        read_available(&mut shown);
        if let Some((prompt, answer)) = answers.get(next)
            && let Some(at) = shown[searched..].find(prompt)
        {
            searched += at + prompt.len();
            next += 1;
            (&terminal)
                .write_all(format!("{answer}\n").as_bytes())
                .expect("type the answer");
        }
        if let Some(status) = child.try_wait().expect("wait") {
            // The slave side is still open here (`slave`), so nothing written is lost.
            read_available(&mut shown);
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "gclone {args:?} did not finish on the terminal; it showed:\n{shown}"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(slave);
    assert_eq!(
        next,
        answers.len(),
        "not every prompt appeared; the terminal showed:\n{shown}"
    );
    let out = Out {
        code: status.code().unwrap_or(-1),
        stdout: stdout.join().expect("stdout thread"),
        stderr: shown,
    };
    assert!(
        !out.stderr.contains("panicked") && out.code != 101,
        "the binary panicked:\n{}",
        out.stderr
    );
    out
}

async fn run_on_tty_async(d: &Device, args: &[&str], answers: &[(&str, &str)]) -> Out {
    let d = d.clone();
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let answers: Vec<(String, String)> = answers
        .iter()
        .map(|(p, a)| (p.to_string(), a.to_string()))
        .collect();
    tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let answers: Vec<(&str, &str)> = answers
            .iter()
            .map(|(p, a)| (p.as_str(), a.as_str()))
            .collect();
        run_on_tty(&d, &args, &answers)
    })
    .await
    .expect("join")
}

/// §9.10 / §17.9: an auth Worker that cannot be reached is a network condition, not a dead
/// login. Read-only commands show the replica with a warning — also when no access token is
/// cached any more (an hour after the last refresh) — and mutating commands fail with exit 4.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drive_mode_read_only_commands_survive_an_unreachable_auth_worker() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let pass = lab.pass();
    let auth_url = format!("{}/auth", fake.base());
    let a = drive_device(&lab, &fake, "a");
    drive_login(
        &fake,
        &a,
        &[
            "login",
            &auth_url,
            "--no-browser",
            "--passphrase-file",
            &pass,
        ],
    )
    .await
    .ok();
    let src = lab.path("src");
    make_tree(&src);
    run_async(&a, &["copy", &s(&src), ":docs"]).await.ok();
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");

    // The cached access token is gone (expired, in real life) and the Worker answers 503.
    std::fs::remove_file(a.token_file()).expect("token.json was written by the copy");
    fake.fail_next(Route::AuthRefresh, u32::MAX, 503, "upstream_error");
    let refreshes = fake.hits(Route::AuthRefresh);
    let out = run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt")
        .stdout_has("big.bin")
        .stderr_has("could not reach the auth Worker")
        .stderr_has("Showing the last state this device has seen.");
    assert!(
        !out.stderr.contains("gclone login"),
        "nothing is wrong with the login:\n{}",
        out.stderr
    );
    assert!(
        fake.hits(Route::AuthRefresh) > refreshes,
        "the Worker was asked"
    );
    assert!(!a.token_file().exists());

    // A command that has to publish cannot work from the replica: exit 4, naming the Worker.
    run_async(&a, &["mkdir", ":new"])
        .await
        .code(4)
        .stderr_has("Could not reach the auth Worker at ")
        .stderr_has(&auth_url);
}

/// §17.18, the move from the browser sign-in of gclone before 0.2.0 (the Worker's legacy OAuth
/// client) to the device sign-in: a `secrets.json` without `client` goes on working while the
/// Worker has the legacy secrets; `gclone login` replaces that login, and only once the new one
/// sees the vault — a new login that does not changes nothing on the device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drive_mode_a_login_of_the_legacy_client_is_replaced_by_gclone_login() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let pass = lab.pass();
    let auth_url = format!("{}/auth", fake.base());
    let a = drive_device(&lab, &fake, "a");
    drive_login(
        &fake,
        &a,
        &[
            "login",
            &auth_url,
            "--no-browser",
            "--passphrase-file",
            &pass,
        ],
    )
    .await
    .ok()
    .stdout_has("Vault created.");
    let src = lab.path("src");
    make_tree(&src);
    run_async(&a, &["copy", &s(&src), ":docs"]).await.ok();
    let identity = a.identity();
    let last_refresh = || {
        let seen = fake.requests(Route::AuthRefresh);
        seen.last().expect("a refresh").json.clone().expect("JSON")
    };
    let forget_access_token = || {
        let _ = std::fs::remove_file(a.token_file());
    };

    // The device as 0.1.0 left it: a refresh token of the legacy client, and no `client` field.
    let legacy_token = fake.add_legacy_token();
    let mut old = a.json(&a.secrets_file());
    old.as_object_mut().unwrap().remove("client");
    old["refresh_token"] = legacy_token.clone().into();
    std::fs::write(a.secrets_file(), serde_json::to_vec(&old).unwrap()).unwrap();
    let legacy_secrets = std::fs::read(a.secrets_file()).unwrap();
    forget_access_token();

    // --- the Worker has the legacy secrets: every command works as before, and the device
    // names no client on /refresh
    fake.set_legacy_client(true);
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");
    assert_eq!(
        last_refresh(),
        serde_json::json!({ "refresh_token": legacy_token })
    );
    run_async(&a, &["status"])
        .await
        .ok()
        .stderr_has("browser sign-in of gclone before 0.2.0; run `gclone login` to renew it");

    // --- `gclone login` signs in again although that login works — but a new login that
    // cannot see the vault (unverified: whether Google shows the files of one OAuth client to
    // another client of the same project) is not kept, and nothing on the device changes.
    fake.fail_next(Route::Stat, 1, 403, "appNotAuthorizedToFile");
    let out = drive_login(&fake, &a, &["login", "--no-browser"])
        .await
        .code(4)
        .stderr_has("browser sign-in of gclone before 0.2.0")
        .stderr_has("The Google login just made (signed in as me@example.com) cannot see the vault this device is attached to")
        .stderr_has("this device keeps its previous login")
        .stderr_has("GOOGLE_LEGACY_CLIENT_ID")
        .stderr_has("\"Moving from the browser sign-in\" in worker/README.md");
    assert!(!out.stdout.contains("Already signed in"), "{}", out.stdout);
    assert!(
        std::fs::read(a.secrets_file()).unwrap() == legacy_secrets,
        "the previous login stays on file, byte for byte"
    );
    assert!(a.config_file().exists() && a.vault_state().join("state.db").exists());
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");
    assert_eq!(a.identity(), identity);

    // --- only one of the two legacy secrets is on the Worker (its owner is between two
    // `wrangler secret` commands): the device is told that, not to log in again
    fake.set_legacy_client_half_set();
    forget_access_token();
    let out = run_async(&a, &["ls"])
        .await
        .code(4)
        .stderr_has("Only one of GOOGLE_LEGACY_CLIENT_ID and GOOGLE_LEGACY_CLIENT_SECRET is set");
    assert!(!out.stderr.contains("Run `gclone login`"), "{}", out.stderr);
    assert!(std::fs::read(a.secrets_file()).unwrap() == legacy_secrets);

    // --- the legacy secrets were deleted from the Worker: the old login is over, and the
    // message names the cause — the Worker, not Google, ended it
    fake.set_legacy_client(false);
    forget_access_token();
    let out = run_async(&a, &["ls"]).await.code(4).stderr_has(
        "This device's login was made with the browser sign-in of gclone before 0.2.0, and \
             the auth Worker no longer serves it (or Google ended it). Run `gclone login`.",
    );
    assert!(
        !out.stderr.contains("Google no longer accepts"),
        "{}",
        out.stderr
    );
    assert!(std::fs::read(a.secrets_file()).unwrap() == legacy_secrets);

    // --- `gclone login`: the device sign-in; the vault, the key and the device stay
    let issued = fake.issued_refresh_tokens().len();
    drive_login(&fake, &a, &["login", "--no-browser"])
        .await
        .ok()
        .stdout_has("Signed in again as me@example.com. Vault unchanged.");
    let new = a.json(&a.secrets_file());
    assert_eq!(new["client"], "device");
    assert_eq!(
        new["refresh_token"],
        fake.issued_refresh_tokens()[issued].as_str(),
        "the token of this run's sign-in"
    );
    assert_eq!(new["keys"], old["keys"]);
    assert!(!a.token_file().exists(), "no token cache after a login");
    assert_eq!(a.identity(), identity);
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");
    assert_eq!(last_refresh()["client"], "device");
    let status = run_async(&a, &["status"]).await.ok();
    assert!(!status.stderr.contains("before 0.2.0"), "{}", status.stderr);
    // From now on `gclone login` keeps the login, like any other that works.
    let logins = fake.hits(Route::AuthStart);
    run_async(&a, &["login"])
        .await
        .ok()
        .stdout_has("Already signed in as me@example.com.");
    assert_eq!(fake.hits(Route::AuthStart), logins);
    // … and when that login ends, the message is the usual one: it is not a legacy login.
    fake.revoke_refresh_token();
    let _ = std::fs::remove_file(a.token_file());
    let out = run_async(&a, &["ls"])
        .await
        .code(4)
        .stderr_has("Google no longer accepts this device's login");
    assert!(!out.stderr.contains("before 0.2.0"), "{}", out.stderr);
}

/// §17.18: a device that signed in with gclone before 0.2.0 and never got attached to a vault
/// (`secrets.json` with a login of the legacy client and no key, no `config.json`). `gclone
/// login` signs in again through the device client. If that login sees no vault, the device
/// does not go on to create one — the vault made through the old client may only be invisible
/// to the new one — and the old login, which cannot be issued again, stays on file. If it does
/// see the vault, the device attaches as usual.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drive_mode_a_legacy_login_without_a_vault_does_not_create_a_second_one() {
    let lab = Lab::new();
    let pass = lab.pass();
    // What 0.1.0 left on a device whose `login` stopped before the vault part.
    let signed_in_before_0_2_0 = |d: &Device, fake: &FakeDrive| {
        gclone::util::create_dir_private(&d.state).unwrap();
        let secrets = serde_json::json!({
            "version": 1, "auth_url": format!("{}/auth", fake.base()),
            "refresh_token": fake.add_legacy_token(), "email": "me@example.com",
            "consent_ms": 1_700_000_000_000u64, "refresh_expires_at_ms": null,
            "keys": [], "min_epoch": 0
        });
        gclone::util::write_atomic(&d.secrets_file(), secrets.to_string().as_bytes(), 0o600)
            .unwrap();
        std::fs::read(d.secrets_file()).unwrap()
    };

    // --- the new login sees no vault (a Drive without one stands in for "not visible")
    let fake = FakeDrive::start().await;
    fake.set_legacy_client(true);
    let b = drive_device(&lab, &fake, "b");
    let before = signed_in_before_0_2_0(&b, &fake);
    let out = drive_login(
        &fake,
        &b,
        &["login", "--no-browser", "--passphrase-file", &pass],
    )
    .await
    .code(4)
    .stderr_has("browser sign-in of gclone before 0.2.0")
    .stderr_has("The Google login just made (signed in as me@example.com) sees no gclone vault")
    .stderr_has("the previous login stays on file")
    .stderr_has("`gclone login --new-vault`");
    assert!(!out.stdout.contains("Vault created"), "{}", out.stdout);
    assert!(
        std::fs::read(b.secrets_file()).unwrap() == before,
        "the legacy login stays on file, byte for byte"
    );
    assert!(!b.config_file().exists());
    assert!(fake.object_ids().is_empty(), "nothing was created on Drive");
    // Asked for by name, a vault is created — and only then is the old login given up.
    drive_login(
        &fake,
        &b,
        &[
            "login",
            "--no-browser",
            "--new-vault",
            "--passphrase-file",
            &pass,
        ],
    )
    .await
    .ok()
    .stdout_has("Vault created.");
    assert_eq!(b.json(&b.secrets_file())["client"], "device");

    // --- the new login does see the vault: the device attaches, and the new login is kept
    let fake = FakeDrive::start().await;
    fake.set_legacy_client(true);
    let auth_url = format!("{}/auth", fake.base());
    let a = drive_device(&lab, &fake, "a");
    drive_login(
        &fake,
        &a,
        &[
            "login",
            &auth_url,
            "--no-browser",
            "--passphrase-file",
            &pass,
        ],
    )
    .await
    .ok()
    .stdout_has("Vault created.");
    let c = drive_device(&lab, &fake, "c");
    signed_in_before_0_2_0(&c, &fake);
    let issued = fake.issued_refresh_tokens().len();
    drive_login(
        &fake,
        &c,
        &["login", "--no-browser", "--passphrase-file", &pass],
    )
    .await
    .ok()
    .stdout_has("Signed in as me@example.com.");
    let attached = c.json(&c.secrets_file());
    assert_eq!(attached["client"], "device");
    assert_eq!(
        attached["refresh_token"],
        fake.issued_refresh_tokens()[issued].as_str()
    );
    assert_eq!(
        c.json(&c.config_file())["vault_id"],
        a.json(&a.config_file())["vault_id"]
    );
}

/// §2.6 A.4 / §17.9: on a device that is attached to a vault but holds no key (after `logout`),
/// a sign-in with another allow-listed Google account is not kept — the next `gclone login`
/// asks again instead of finding a login that "works". And where a login on file is kept
/// although it cannot see the vault, the error names the way out (`gclone logout` first).
/// Then §2.7 / §17.9: `logout --revoke --forget` asks everything before it revokes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drive_mode_wrong_account_after_logout_and_revoke_forget_order() {
    let fake = FakeDrive::start().await;
    let lab = Lab::new();
    let pass = lab.pass();
    let auth_url = format!("{}/auth", fake.base());
    let a = drive_device(&lab, &fake, "a");
    let secrets_of = |d: &Device| d.json(&d.secrets_file());
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
    .await
    .ok()
    .stdout_has("Vault created.");
    let src = lab.path("src");
    make_tree(&src);
    run_async(&a, &["copy", &s(&src), ":docs"]).await.ok();
    let identity = a.identity();

    // --- signed out; the next sign-in is made with ANOTHER allow-listed Google account
    fake.set_allowed_emails(&["me@example.com", "second@example.com"]);
    run_async(&a, &["logout"]).await.ok();
    assert!(!a.secrets_file().exists() && a.config_file().exists());
    fake.set_login_email("second@example.com");
    // What that account's token gets under `drive.file`: the vault's files are not there.
    fake.fail_next(Route::Media, 1, 404, "notFound");
    let out = drive_login(
        &fake,
        &a,
        &["login", "--no-browser", "--passphrase-file", &pass],
    )
    .await
    .code(4)
    .stdout_has("Signed in as second@example.com.")
    .stderr_has("The Google login just made (signed in as second@example.com) cannot see the vault this device is attached to")
    .stderr_has("the new sign-in was not kept")
    .stderr_has("run `gclone login` again and choose the right one");
    assert!(
        !out.stderr.contains("gclone logout` first"),
        "nothing was kept, so there is nothing to log out of:\n{}",
        out.stderr
    );
    assert!(
        !a.secrets_file().exists(),
        "a login that cannot see the attached vault is not kept"
    );
    assert!(!a.token_file().exists());

    // `gclone login` again: a new interactive sign-in, this time with the right account.
    fake.set_login_email("me@example.com");
    let logins = fake.hits(Route::AuthStart);
    drive_login(
        &fake,
        &a,
        &["login", "--no-browser", "--passphrase-file", &pass],
    )
    .await
    .ok()
    .stdout_has("Signed in as me@example.com.")
    .stdout_has("Connected to vault \"gclone\" (5 files). This device: \"mbp\".");
    assert_eq!(
        fake.hits(Route::AuthStart),
        logins + 1,
        "the user was asked to sign in again"
    );
    assert_eq!(secrets_of(&a)["email"], "me@example.com");
    assert_eq!(a.identity(), identity);

    // --- a login on file that works but cannot see the vault: `gclone login` keeps it (A.2)
    // and never asks, so the error has to name `gclone logout`. First without a cached key
    // (step B.2) …
    let connected = std::fs::read(a.secrets_file()).unwrap();
    let mut unlocked = secrets_of(&a);
    unlocked["keys"] = serde_json::json!([]);
    std::fs::write(a.secrets_file(), serde_json::to_vec(&unlocked).unwrap()).unwrap();
    fake.fail_next(Route::Media, 1, 404, "notFound");
    let logins = fake.hits(Route::AuthStart);
    run_async(&a, &["login", "--passphrase-file", &pass])
        .await
        .code(4)
        .stdout_has("Already signed in as me@example.com.")
        .stderr_has("This Google login cannot see the vault this device is attached to")
        .stderr_has("This device is signed in as me@example.com")
        .stderr_has("run `gclone logout` first, then `gclone login`");
    // … then on a connected device (step B.1).
    std::fs::write(a.secrets_file(), &connected).unwrap();
    fake.fail_next(Route::Stat, 1, 403, "appNotAuthorizedToFile");
    run_async(&a, &["login"])
        .await
        .code(4)
        .stdout_has("Already signed in as me@example.com.")
        .stderr_has("This Google login cannot see the vault this device is attached to")
        .stderr_has("run `gclone logout` first, then `gclone login`");
    assert_eq!(fake.hits(Route::AuthStart), logins, "nobody was asked");
    assert!(std::fs::read(a.secrets_file()).unwrap() == connected);
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");

    // --- `logout --revoke --forget` with unpublished changes, on a terminal: the question
    // that can still stop the command comes BEFORE the revoke, which cannot be taken back.
    stage_an_op_on(&a, fake.backend()).await;
    let token = secrets_of(&a)["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_string();
    let state = a.vault_state();
    let out = run_on_tty_async(
        &a,
        &["logout", "--revoke", "--forget"],
        &[
            ("Continue? [y/N]", "y"),
            ("Forget this device's vault state anyway? [y/N]", "n"),
        ],
    )
    .await
    .code(5)
    .stderr_has("This ends the Google login of ALL your gclone devices")
    .stderr_has("1 change(s) made on this device are not published yet")
    .stderr_has("nothing was revoked and nothing was removed");
    assert!(out.stdout.is_empty(), "{}", out.stdout);
    assert!(
        fake.revoked().is_empty(),
        "declining the second question must leave every device signed in"
    );
    assert_eq!(fake.hits(Route::Revoke), 0);
    assert!(a.secrets_file().exists() && a.config_file().exists() && state.exists());
    // The login still works — also for the hint "run any gclone command to publish them".
    run_async(&a, &["ls", ":docs"])
        .await
        .ok()
        .stdout_has("a.txt");

    // Declining the first question: nothing is asked about the unpublished changes.
    let out = run_on_tty_async(
        &a,
        &["logout", "--revoke", "--forget"],
        &[("Continue? [y/N]", "n")],
    )
    .await
    .code(1)
    .stdout_has("Nothing was revoked and nothing was removed.");
    assert!(!out.stderr.contains("not published yet"), "{}", out.stderr);
    assert!(fake.revoked().is_empty() && a.secrets_file().exists());

    // Both confirmed: revoked, signed out, forgotten.
    run_on_tty_async(
        &a,
        &["logout", "--revoke", "--forget"],
        &[
            ("Continue? [y/N]", "y"),
            ("Forget this device's vault state anyway? [y/N]", "y"),
        ],
    )
    .await
    .ok()
    .stdout_has("Signed out on this device.")
    .stdout_has("Google revoked the login of all your gclone devices")
    .stdout_has("This device's vault configuration and local state were removed.");
    assert_eq!(fake.revoked(), [token]);
    assert!(!a.secrets_file().exists() && !a.config_file().exists() && !state.exists());
}

/// §5.9, §17.26 (audit L5): every age `gc` judges by is measured on the store's clock, which is
/// this device's clock plus whatever the `Date` header of Drive's answers says. A store whose
/// clock stands a grace period ahead would make everything removed today collectable — and
/// with `--purge` deleted for good. Beyond a day of difference `gc` does nothing (exit 5).
#[tokio::test(flavor = "multi_thread")]
async fn gc_does_not_follow_a_store_clock_that_is_far_from_the_devices() {
    let lab = Lab::new();
    let pass = lab.pass();
    let fake = FakeDrive::start().await;
    let auth_url = format!("{}/auth", fake.base());
    let mut a = drive_device(&lab, &fake, "a");
    a.env.push(("GCLONE_TEST_FAST_PACER".into(), "1".into()));
    drive_login(
        &fake,
        &a,
        &[
            "login",
            &auth_url,
            "--no-browser",
            "--passphrase-file",
            &pass,
        ],
    )
    .await
    .ok()
    .stdout_has("Vault created.");
    run_async(&a, &["gc", "--orphans", "--purge"])
        .await
        .ok()
        .stdout_has("Trashed 0 dead blobs");

    // (`Date` has one-second resolution: an hour more than whole days.)
    for (skew_hours, text) in [
        (40 * 24 + 1, "40 d ahead of"),
        (-31 * 24 - 1, "31 d behind"),
    ] {
        fake.set_date_skew_ms(skew_hours * 3_600_000);
        for args in [&["gc"][..], &["gc", "--orphans", "--purge"], &["gc", "-n"]] {
            let out = run_async(&a, args)
                .await
                .code(5)
                .stderr_has("safety guard: the store's clock is")
                .stderr_has(text)
                .stderr_has("gc did nothing");
            assert!(!out.stdout.contains("Trashed"), "{}", out.stdout);
        }
        // Everything else works on as before.
        run_async(&a, &["ls", ":"]).await.ok();
    }
    fake.set_date_skew_ms(0);
    run_async(&a, &["gc"])
        .await
        .ok()
        .stdout_has("Trashed 0 dead blobs");
}

/// A file replaced with `copy --force` from a directory that was never in sync with it: the
/// new version supersedes nothing, and the old one goes with the op that resolves the two.
/// `restore --list` says "overwritten" for it — the path never was empty — as the viewer does
/// (`past::why`).
#[test]
fn a_version_replaced_with_force_is_listed_as_overwritten() {
    let w = world();
    let a = &w.a;
    let one = w.lab.path("forced-one");
    write(&one.join("f.txt"), b"first\n");
    a.run(&["copy", &s(&one), ":forced"]).ok();
    let two = w.lab.path("forced-two");
    write(&two.join("f.txt"), b"the second one\n");
    a.run(&["copy", "--force", &s(&two), ":forced"]).ok();
    assert_eq!(
        a.run(&["cat", ":forced/f.txt"]).ok().stdout,
        "the second one\n"
    );
    let listed = a.run(&["restore", "--list", ":forced/f.txt"]).ok().stdout;
    let lines: Vec<&str> = listed.lines().collect();
    assert_eq!(lines.len(), 2, "{listed}");
    assert!(lines[1].contains("(overwritten)"), "{listed}");
    // A deleted file still says so.
    a.run(&["rm", ":forced/f.txt"]).ok();
    let listed = a.run(&["restore", "--list", ":forced/f.txt"]).ok().stdout;
    let lines: Vec<&str> = listed.lines().collect();
    assert_eq!(lines.len(), 3, "{listed}");
    assert!(lines[1].contains("(deleted)"), "{listed}");
    assert!(lines[2].contains("(overwritten)"), "{listed}");
}

/// `restore --list` names every version by an id, and `--version @ID` restores exactly that
/// version — also after a newer version has appeared, which moves every position K by one
/// (§5.5.4). The id is the one the viewer's "Versions" panel puts into the command it shows.
#[test]
fn restore_takes_the_id_of_a_version() {
    let w = world();
    let a = &w.a;
    let dir = w.lab.path("editions");
    for text in ["first\n", "the second\n", "and the third one\n"] {
        write(&dir.join("f.txt"), text.as_bytes());
        a.run(&["copy", &s(&dir), ":ed"]).ok();
    }
    let listed = a.run(&["restore", "--list", ":ed/f.txt"]).ok().stdout;
    let lines: Vec<&str> = listed.lines().collect();
    assert_eq!(lines.len(), 3, "{listed}");
    // The header, and per version: K, removed, size, by, why, id.
    let header: Vec<&str> = lines[0].split_whitespace().collect();
    assert_eq!(header, ["K", "removed", "size", "by", "id"]);
    let id_of = |line: &str| {
        let id = line.split_whitespace().last().expect("an id column");
        assert!(line.contains("(overwritten)"), "{line}");
        assert!(id.len() == 13 && id.starts_with('@'), "{line}");
        assert!(
            id[1..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{line}"
        );
        id.to_owned()
    };
    // The columns line up: the id starts where the header says.
    let at = lines[0].find("id").expect("the id column");
    assert!(
        lines[1..].iter().all(|l| l.find('@') == Some(at)),
        "{listed}"
    );
    // Newest first: K = 1 is "the second", K = 2 is "first".
    let (second, first) = (id_of(lines[1]), id_of(lines[2]));
    assert!(lines[1].trim_start().starts_with("1 ") && lines[1].contains("11 B"));
    assert!(lines[2].trim_start().starts_with("2 ") && lines[2].contains("6 B"));
    assert_ne!(first, second);

    // A newer version appears: every K moves, no id does.
    write(&dir.join("f.txt"), b"a fourth, to move the numbers\n");
    a.run(&["copy", &s(&dir), ":ed"]).ok();
    let listed = a.run(&["restore", "--list", ":ed/f.txt"]).ok().stdout;
    let lines: Vec<&str> = listed.lines().collect();
    assert_eq!(lines.len(), 4, "{listed}");
    assert_eq!(
        (id_of(lines[2]), id_of(lines[3])),
        (second.clone(), first.clone())
    );
    // The id restores the version it named before; the old position would not.
    a.run(&["restore", ":ed/f.txt", "--version", &first])
        .ok()
        .stdout_has("Restored :ed/f.txt (6 B");
    assert_eq!(a.bytes(&["cat", ":ed/f.txt"]), b"first\n");
    a.run(&["restore", ":ed/f.txt", "--version", &second]).ok();
    assert_eq!(a.bytes(&["cat", ":ed/f.txt"]), b"the second\n");
    // A position still works as it did.
    a.run(&["restore", ":ed/f.txt", "--version", "1"]).ok();
    assert_eq!(a.bytes(&["cat", ":ed/f.txt"]), b"first\n");

    // An id no version has, and one of another file: the error that names --list.
    let other = a.run(&["restore", "--list", ":docs/big.bin"]).ok().stdout;
    assert!(other.contains("No restorable version"), "{other}");
    for unknown in ["@0123456789ab", "@ffffffffffff"] {
        a.run(&["restore", ":ed/f.txt", "--version", unknown])
            .code(1)
            .stderr_has(&format!("there is no version {unknown}"))
            .stderr_has("gclone restore --list :ed/f.txt");
    }
    a.run(&["restore", ":docs/a.txt", "--version", &first])
        .code(1)
        .stderr_has("no restorable version");
    // What is no id and no position is a usage error, before anything is opened.
    for bad in [
        "@",
        "@123",
        "@0123456789AB",
        "@0123456789abc",
        "@zzzzzzzzzzzz",
        "0",
        "-1",
        "x",
    ] {
        let out = a
            .run(&["restore", ":ed/f.txt", &format!("--version={bad}")])
            .code(2);
        assert!(
            out.stderr.contains("--list") || out.stderr.contains("12 hexadecimal digits"),
            "{bad}: {}",
            out.stderr
        );
    }
    // As before: one file, and not together with --list.
    a.run(&["restore", ":ed/f.txt", ":docs/a.txt", "--version", &first])
        .code(2);
    a.run(&["restore", "--list", ":ed/f.txt", "--version", &first])
        .code(2);
    assert_eq!(a.bytes(&["cat", ":ed/f.txt"]), b"first\n");
}

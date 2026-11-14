//! Unit tests of the layered key store: every row of the load table, of the save table and of
//! the two moves (SPEC §8.2), with the stand-in sealer. No hardware is touched.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::seal::{FakeFail, FakeSealer};
use super::*;
use crate::config::{BackendCfg, KeyEntry};

const VAULT: &str = "00112233445566778899aabbccddeeff";
const OTHER_VAULT: &str = "ffeeddccbbaa99887766554433221100";
/// What must never show up in an error text or in the sealed file.
const KEY_TEXT: &str = "S3CR3TkeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const TOKEN_TEXT: &str = "1//0S3CR3T-refresh-token";

fn paths(root: &Path) -> Paths {
    let p = Paths {
        config_dir: root.join("config"),
        state_root: root.join("state"),
    };
    util::create_dir_private(&p.state_root).unwrap();
    p
}

fn attach(p: &Paths, vault_id: &str) {
    Config {
        version: 1,
        vault_id: vault_id.into(),
        vault_name: "v".into(),
        backend: BackendCfg::Drive,
        auth_url: Some("https://auth.example".into()),
        root_id: "r".into(),
        index_id: "i".into(),
        data_id: "d".into(),
    }
    .save(p)
    .unwrap();
}

fn store_on(p: &Paths, machine: &str, fail: Option<FakeFail>) -> LayeredStore {
    LayeredStore::with_sealer(p, Ok(Arc::new(FakeSealer::new(machine, fail))), false)
}

fn store(p: &Paths) -> LayeredStore {
    store_on(p, "mac", None)
}

fn no_sealer(p: &Paths, why: NoSealer) -> LayeredStore {
    LayeredStore::with_sealer(p, Err(why), false)
}

fn login() -> Secrets {
    let mut s = Secrets::empty();
    s.auth_url = Some("https://auth.example".into());
    s.refresh_token = Some(TOKEN_TEXT.into());
    s.email = Some("user@example.com".into());
    s.client = crate::auth::AuthClient::Device;
    s
}

fn with_keys(mut s: Secrets, key: &str) -> Secrets {
    s.keys = vec![KeyEntry {
        epoch: 1,
        key: key.into(),
    }];
    s.min_epoch = 1;
    s
}

fn full() -> Secrets {
    with_keys(login(), KEY_TEXT)
}

fn plain(p: &Paths) -> FileSecretStore {
    FileSecretStore {
        path: p.secrets_file(),
    }
}

/// Puts `secrets` into `secrets.sealed` as machine `machine` would, with no `secrets.json`.
fn seal_on(p: &Paths, machine: &str, secrets: &Secrets) {
    assert!(!p.secrets_file().exists());
    std::fs::write(p.keystore_file(), br#"{"version":1,"store":"enclave"}"#).unwrap();
    std::fs::set_permissions(p.keystore_file(), std::fs::Permissions::from_mode(0o600)).unwrap();
    store_on(p, machine, None).save(secrets).unwrap();
    std::fs::remove_file(p.keystore_file()).unwrap();
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
}

fn bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn unavailable(result: Result<Option<Loaded>, ConfigError>) -> String {
    match result {
        Err(ConfigError::KeyStoreUnavailable(text)) => text,
        Err(e) => panic!("another error: {e}"),
        Ok(_) => panic!("the sealed store must not have opened"),
    }
}

fn source(s: &LayeredStore) -> Option<Source> {
    s.resolve().unwrap().map(|l| l.source)
}

fn files(p: &Paths) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(&p.state_root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------------------------
// the envelope and the choice file
// ---------------------------------------------------------------------------------------------

#[test]
fn the_sealed_file_is_a_private_envelope_that_holds_nothing_in_plain() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    seal_on(&p, "mac", &full());
    assert_eq!(mode(&p.sealed_file()), 0o600);
    let text = String::from_utf8(bytes(&p.sealed_file())).unwrap();
    assert!(
        !text.contains(KEY_TEXT) && !text.contains(TOKEN_TEXT),
        "{text}"
    );
    assert!(!text.contains("user@example.com"));
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["store"], "enclave");
    assert_eq!(json["alg"], "ecies-p256-x963-sha256-aesgcm");
    assert_eq!(json["vault_id"], VAULT);
    assert!(json["sealed_ms"].as_u64().unwrap() > 0);
    for member in ["public", "key", "sealed"] {
        assert!(
            util::unb64url(json[member].as_str().unwrap()).is_some(),
            "{member}"
        );
    }

    // What is sealed is a secrets.json document, byte for byte what the plain store writes.
    let s = store(&p);
    let opened = s
        .open_sealed(&s.read_sealed().unwrap().unwrap())
        .ok()
        .unwrap();
    plain(&p).save(&full()).unwrap();
    assert_eq!(opened.document.as_slice(), bytes(&p.secrets_file()));
    assert!(same_keys(&opened.secrets, &full()));

    // A document without keys names no vault (the first save of a login on a signed-out
    // device that chose the sealed store).
    s.delete().unwrap();
    write_choice(&p, STORE_ENCLAVE, "t").unwrap();
    s.save(&login()).unwrap();
    assert!(!p.secrets_file().exists());
    let json: serde_json::Value = serde_json::from_slice(&bytes(&p.sealed_file())).unwrap();
    assert!(json.get("vault_id").is_none());
}

#[test]
fn an_unknown_version_store_or_algorithm_is_refused_by_name_never_guessed() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    seal_on(&p, "mac", &full());
    let good: serde_json::Value = serde_json::from_slice(&bytes(&p.sealed_file())).unwrap();
    let s = store(&p);
    assert_eq!(source(&s), Some(Source::Sealed));
    for (member, value) in [
        ("version", serde_json::json!(2)),
        ("store", serde_json::json!("keychain")),
        ("alg", serde_json::json!("xchacha20-poly1305")),
        ("key", serde_json::json!("not base64 !")),
        ("sealed", serde_json::json!(7)),
    ] {
        let mut bad = good.clone();
        bad[member] = value;
        std::fs::write(p.sealed_file(), serde_json::to_vec(&bad).unwrap()).unwrap();
        let text = unavailable(s.resolve());
        assert!(
            text.contains("secrets.sealed")
                && text.contains("damaged or was written by a newer gclone"),
            "{member}: {text}"
        );
        assert!(
            text.contains("Use that gclone, or run `gclone login`"),
            "{text}"
        );
    }
    for junk in [&b"not json"[..], b"", b"{}"] {
        std::fs::write(p.sealed_file(), junk).unwrap();
        assert!(unavailable(s.resolve()).contains("damaged or was written by a newer gclone"));
    }
}

#[test]
fn an_error_about_the_sealed_file_never_quotes_what_is_in_it() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    let s = store(&p);
    for text in [
        format!(r#"{{"version": "{KEY_TEXT}"}}"#),
        format!(r#"{{"version": 1, "store": "enclave", "alg": 3, "key": "{KEY_TEXT}"}}"#),
        format!(r#"{{"version": 1, "store": "{TOKEN_TEXT}"#),
        format!("{KEY_TEXT} {TOKEN_TEXT}"),
    ] {
        std::fs::write(p.sealed_file(), text).unwrap();
        std::fs::set_permissions(p.sealed_file(), std::fs::Permissions::from_mode(0o600)).unwrap();
        let said = unavailable(s.resolve());
        assert!(!said.contains("S3CR3T"), "{said}");
    }
    // a sealed document that is not a secrets document: opened, and still not quoted
    let sealer = FakeSealer::new("mac", None);
    let (blob, public) = seal::Sealer::create(&sealer).unwrap();
    let inner = format!(r#"{{"version": 1, "keys": "{KEY_TEXT}"}}"#);
    let envelope = s
        .envelope_for(&sealer, &blob, &public, inner.as_bytes(), false)
        .unwrap();
    std::fs::write(p.sealed_file(), &*envelope).unwrap();
    // (another FakeSealer object of the same machine opens it)
    let said = unavailable(s.resolve());
    assert!(!said.contains("S3CR3T"), "{said}");
    assert!(said.contains("damaged"), "{said}");
}

#[test]
fn the_sealed_file_is_read_as_strictly_as_the_plain_one() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    seal_on(&p, "mac", &full());
    let s = store(&p);
    for open_mode in [0o644, 0o640, 0o604] {
        std::fs::set_permissions(p.sealed_file(), std::fs::Permissions::from_mode(open_mode))
            .unwrap();
        match s.resolve() {
            Err(ConfigError::InsecurePermissions(path)) => {
                assert_eq!(path, p.sealed_file().display().to_string())
            }
            _ => panic!("mode {open_mode:o} must be refused"),
        }
    }
    std::fs::set_permissions(p.sealed_file(), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(source(&s), Some(Source::Sealed));

    std::fs::set_permissions(&p.state_root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        s.resolve(),
        Err(ConfigError::InsecurePermissions(_))
    ));
    std::fs::set_permissions(&p.state_root, std::fs::Permissions::from_mode(0o700)).unwrap();

    // a symlink in its place
    let elsewhere = tmp.path().join("elsewhere.sealed");
    std::fs::rename(p.sealed_file(), &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, p.sealed_file()).unwrap();
    assert!(matches!(
        s.resolve(),
        Err(ConfigError::InsecurePermissions(_))
    ));
    std::fs::remove_file(p.sealed_file()).unwrap();

    // too large to be ours
    std::fs::write(p.sealed_file(), vec![b' '; 1024 * 1024 + 1]).unwrap();
    std::fs::set_permissions(p.sealed_file(), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(s.resolve(), Err(ConfigError::Json(_))));
}

#[test]
fn the_choice_file_states() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    assert_eq!(read_choice(&p), Choice::Unset);
    write_choice(&p, STORE_FILE, "t").unwrap();
    assert_eq!(read_choice(&p), Choice::File);
    assert_eq!(mode(&p.keystore_file()), 0o600);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes(&p.keystore_file())).unwrap(),
        serde_json::json!({ "version": 1, "store": "file" })
    );
    write_choice(&p, STORE_ENCLAVE, "t").unwrap();
    assert_eq!(read_choice(&p), Choice::Enclave);

    for junk in [
        &br#"{"version":1,"store":"keychain"}"#[..],
        br#"{"version":2,"store":"file"}"#,
        b"not json",
    ] {
        std::fs::write(p.keystore_file(), junk).unwrap();
        assert!(matches!(read_choice(&p), Choice::Unreadable(_)), "{junk:?}");
    }
    write_choice(&p, STORE_FILE, "t").unwrap();
    std::fs::set_permissions(p.keystore_file(), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(read_choice(&p), Choice::Unreadable(_)));

    // An unreadable choice never blocks a read; it suspends the trial and is reported.
    plain(&p).save(&full()).unwrap();
    let s = store(&p);
    assert_eq!(source(&s), Some(Source::Plain));
    let r = report(&p);
    assert!(r.line().contains("trial suspended"), "{}", r.line());
    assert!(
        r.warnings()
            .iter()
            .any(|w| w.contains("keystore.json cannot be used"))
    );
}

// ---------------------------------------------------------------------------------------------
// the load table
// ---------------------------------------------------------------------------------------------

#[test]
fn load_nothing_plain_alone_and_sealed_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    let s = store(&p);
    assert!(s.resolve().unwrap().is_none());
    assert!(s.load().unwrap().is_none());
    assert!(!p.secrets_lock().exists(), "a reader creates no lock file");

    // also where no state root exists at all
    let empty = Paths {
        config_dir: tmp.path().join("c2"),
        state_root: tmp.path().join("s2"),
    };
    assert!(store(&empty).load().unwrap().is_none());
    assert!(!empty.state_root.exists());

    plain(&p).save(&full()).unwrap();
    let loaded = s.resolve().unwrap().unwrap();
    assert_eq!(loaded.source, Source::Plain);
    assert!(same_keys(&loaded.secrets, &full()));
    std::fs::remove_file(p.secrets_file()).unwrap();

    seal_on(&p, "mac", &full());
    let loaded = s.resolve().unwrap().unwrap();
    assert_eq!(loaded.source, Source::Sealed);
    assert!(same_keys(&loaded.secrets, &full()));
    assert_eq!(loaded.secrets.refresh_token.as_deref(), Some(TOKEN_TEXT));
    assert_eq!(
        s.load().unwrap().unwrap().email.as_deref(),
        Some("user@example.com")
    );
}

/// `secrets.json` with keys is the answer whatever lies beside it: the sealed file is not
/// even opened.
#[test]
fn load_a_plain_file_with_keys_wins_and_the_sealed_file_is_not_opened() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    seal_on(
        &p,
        "mac",
        &with_keys(login(), "another-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    );
    plain(&p).save(&full()).unwrap();
    // A sealer that refuses everything: it is never asked.
    let s = store_on(&p, "mac", Some(FakeFail::Open));
    let loaded = s.resolve().unwrap().unwrap();
    assert_eq!(loaded.source, Source::Plain);
    assert!(same_keys(&loaded.secrets, &full()));
    assert!(loaded.sealed_problem.is_none());
    // garbage beside it changes nothing either
    std::fs::write(p.sealed_file(), b"garbage").unwrap();
    assert_eq!(source(&s), Some(Source::Plain));
    // but an insecure secrets.json is that error, whatever the sealed file is
    std::fs::set_permissions(p.secrets_file(), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        s.resolve(),
        Err(ConfigError::InsecurePermissions(_))
    ));
}

/// F1 of the review: a sealed store that does not open is an error that says what to do —
/// and the text depends on whether a fresh key works.
#[test]
fn load_a_sealed_store_that_does_not_open_says_which_kind() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    seal_on(&p, "another-mac", &full());

    // The stored key fails, a fresh key works: sealed for another Mac. `gclone login`.
    let dead = unavailable(store(&p).resolve());
    assert!(dead.contains("sealed for another Mac"), "{dead}");
    assert!(
        dead.contains("Run `gclone login`; it asks for the passphrase"),
        "{dead}"
    );
    assert!(dead.contains("The sealed file is kept"), "{dead}");
    // §17.30: said plainly — this Mac cannot open the sealed key, and a login (the Google
    // sign-in, the passphrase) is the way back.
    assert!(
        dead.starts_with(
            "This Mac's Secure Enclave cannot open this device's sealed key (secrets.sealed)"
        ),
        "{dead}"
    );
    assert!(
        dead.contains("a migration or from a backup")
            && dead.contains("it signs in to Google first")
            && dead.contains("connects this device again"),
        "{dead}"
    );
    match store(&p).load() {
        Err(e @ ConfigError::KeyStoreUnavailable(_)) => {
            assert_eq!(crate::error::exit_code(&e.into()), 4)
        }
        _ => panic!("load must fail"),
    }

    // Nothing opens in this session, a fresh key included: never "sign in again".
    let session = unavailable(store_on(&p, "another-mac", Some(FakeFail::Open)).resolve());
    assert!(
        session.contains("cannot be used in this session"),
        "{session}"
    );
    assert!(session.contains("Do not sign in again"), "{session}");
    assert!(session.contains("gclone keystore check"), "{session}");
    assert!(!session.contains("gclone login"), "{session}");
    // The way out that needs no enclave in this session.
    assert!(
        session.contains("`gclone keystore use file` — from a session where it works"),
        "{session}"
    );

    // The stored key is dead on the Mac that made it (an enclave that was reset).
    let reset = unavailable(store_on(&p, "another-mac", Some(FakeFail::OpenStored)).resolve());
    assert!(reset.contains("Run `gclone login`"), "{reset}");

    // A machine or a build without any sealer.
    let linux = unavailable(no_sealer(&p, NoSealer::NotMac).resolve());
    assert!(linux.contains("this machine cannot open that file") && linux.contains("gclone login"));
    let debug = unavailable(no_sealer(&p, NoSealer::DebugBuild).resolve());
    assert!(
        debug.contains("debug build") && debug.contains("Nothing was changed"),
        "{debug}"
    );
}

/// F2 of the review: an older gclone signs in on a sealed device and writes a keyless
/// `secrets.json`. The key stays where it is and works with the login just made.
#[test]
fn load_a_keyless_plain_file_beside_the_sealed_one() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    seal_on(&p, "mac", &full());
    let sealed_before = bytes(&p.sealed_file());
    // What gclone 0.4.0 writes before it asks for the passphrase.
    let mut newer_login = login();
    newer_login.refresh_token = Some("1//the-login-just-made".into());
    plain(&p).save(&newer_login).unwrap();

    let s = store(&p);
    let loaded = s.resolve().unwrap().unwrap();
    assert_eq!(loaded.source, Source::Merged);
    assert_eq!(
        loaded.secrets.refresh_token.as_deref(),
        Some("1//the-login-just-made")
    );
    assert!(same_keys(&loaded.secrets, &full()));
    assert_eq!(loaded.secrets.min_epoch, 1);
    // in memory only: neither file changed
    assert_eq!(bytes(&p.sealed_file()), sealed_before);
    assert!(plain(&p).load().unwrap().unwrap().keys.is_empty());

    // The keys are for the vault they were sealed for, and for no other.
    attach(&p, OTHER_VAULT);
    let loaded = s.resolve().unwrap().unwrap();
    assert_eq!(loaded.source, Source::Plain);
    assert!(
        loaded.secrets.keys.is_empty(),
        "not merged: the command reports Locked"
    );
    Config::delete(&p).unwrap();
    assert_eq!(source(&s), Some(Source::Plain));
    attach(&p, VAULT);
    assert_eq!(source(&s), Some(Source::Merged));

    // A keyless file without a login (nothing a gclone writes) is not merged either.
    plain(&p).save(&Secrets::empty()).unwrap();
    assert_eq!(source(&s), Some(Source::Plain));

    // The sealed file does not open: the plain one answers, with the cause as a note.
    plain(&p).save(&newer_login).unwrap();
    let elsewhere = store_on(&p, "another-mac", None);
    let loaded = elsewhere.resolve().unwrap().unwrap();
    assert_eq!(loaded.source, Source::Plain);
    assert!(loaded.secrets.keys.is_empty());
    assert!(
        loaded
            .sealed_problem
            .unwrap()
            .contains("cannot be used here")
    );
    assert_eq!(
        bytes(&p.sealed_file()),
        sealed_before,
        "never removed, never written"
    );

    // A sealed document without keys beside a keyless plain file: the plain file. (The one
    // save that may put a keyless document in the place of sealed keys names those keys.)
    std::fs::remove_file(p.secrets_file()).unwrap();
    s.save_dropping_keys(&login(), &full()).unwrap();
    assert!(!p.secrets_file().exists());
    plain(&p).save(&newer_login).unwrap();
    let loaded = s.resolve().unwrap().unwrap();
    assert_eq!(loaded.source, Source::Plain);
    assert_eq!(
        loaded.secrets.refresh_token.as_deref(),
        Some("1//the-login-just-made")
    );
}

// ---------------------------------------------------------------------------------------------
// the save table
// ---------------------------------------------------------------------------------------------

#[test]
fn save_goes_to_the_plain_file_where_it_exists_or_nothing_was_chosen() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    let s = store(&p);
    // nothing there, no choice: the plain file, as before
    s.save(&login()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert_eq!(mode(&p.secrets_file()), 0o600);
    assert_eq!(mode(&p.state_root), 0o700);
    assert_eq!(mode(&p.secrets_lock()), 0o600);
    // the version-1 file, byte for byte what the plain store writes
    let written = bytes(&p.secrets_file());
    plain(&p).save(&login()).unwrap();
    assert_eq!(bytes(&p.secrets_file()), written);
    // it exists: every later save goes there, whatever the choice says
    write_choice(&p, STORE_ENCLAVE, "t").unwrap();
    s.save(&full()).unwrap();
    assert!(!p.sealed_file().exists());
    assert!(same_keys(&plain(&p).load().unwrap().unwrap(), &full()));
    // the choice `file`, on a signed-out device
    s.delete().unwrap();
    write_choice(&p, STORE_FILE, "t").unwrap();
    s.save(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert!(files(&p).contains(&"CACHEDIR.TAG".to_string()));
}

#[test]
fn save_seals_at_once_on_a_signed_out_device_that_chose_the_enclave() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    write_choice(&p, STORE_ENCLAVE, "t").unwrap();
    let s = store(&p);
    // the two saves of a login: first the login alone, then with the keys
    s.save(&login()).unwrap();
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
    assert!(source(&s) == Some(Source::Sealed));
    let first: serde_json::Value = serde_json::from_slice(&bytes(&p.sealed_file())).unwrap();
    s.save_proven(&full()).unwrap();
    assert!(!p.secrets_file().exists());
    let second: serde_json::Value = serde_json::from_slice(&bytes(&p.sealed_file())).unwrap();
    assert_eq!(
        first["key"], second["key"],
        "the same key: it was opened in this process"
    );
    assert_eq!(first["public"], second["public"]);
    assert_ne!(first["sealed"], second["sealed"]);
    assert!(same_keys(&s.load().unwrap().unwrap(), &full()));

    // No key can be made here: the plain file, and the choice stays.
    s.delete().unwrap();
    let none = store_on(&p, "mac", Some(FakeFail::Create));
    none.save(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert_eq!(read_choice(&p), Choice::Enclave);
    // …and a process without a sealer at all
    none.delete().unwrap();
    no_sealer(&p, NoSealer::NotMac).save(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
}

/// The high-severity finding of the review: `gclone login` saves the grant WITHOUT a key
/// before it asks for the passphrase. On a sealed device whose enclave failed once — so that
/// the login's own look at the sealed file found "no usable secrets" — and worked again by
/// the time of that save, the keyless document was re-sealed over the file: the only copy of
/// the vault key on the device was gone before the passphrase was asked, and a wrong or
/// abandoned passphrase left the device locked. Sealed keys are never replaced by a document
/// without keys.
#[test]
fn a_keyless_save_never_replaces_sealed_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    seal_on(&p, "mac", &full());
    let sealed_before = bytes(&p.sealed_file());
    let mut new_login = login();
    new_login.refresh_token = Some("1//the-login-just-made".into());

    // The stored key answers with an error twice — the look and its one second try — and
    // works from then on: the load says "cannot be used", the save a moment later could open
    // the file.
    let flaky = store_on(&p, "mac", Some(FakeFail::OpenFirst(2)));
    let said = unavailable(flaky.resolve());
    assert!(said.contains("Run `gclone login`"), "{said}");
    flaky.save(&new_login).unwrap();
    assert_eq!(
        bytes(&p.sealed_file()),
        sealed_before,
        "the sealed file is byte for byte what it was"
    );
    // The login went to secrets.json, without a key; with the sealed keys beside it that is
    // the merged view: the device works, with the login just made.
    assert!(plain(&p).load().unwrap().unwrap().keys.is_empty());
    let loaded = store(&p).resolve().unwrap().unwrap();
    assert_eq!(loaded.source, Source::Merged);
    assert!(same_keys(&loaded.secrets, &full()));
    assert_eq!(
        loaded.secrets.refresh_token.as_deref(),
        Some("1//the-login-just-made")
    );

    // The same save on a store that opens at once: the same answer. It is the rule, not
    // the failure, that keeps the keys.
    std::fs::remove_file(p.secrets_file()).unwrap();
    let s = store(&p);
    s.save(&new_login).unwrap();
    assert_eq!(bytes(&p.sealed_file()), sealed_before);
    assert_eq!(source(&s), Some(Source::Merged));
    // The login that has the passphrase ends in one file again.
    s.save_proven(&with_keys(new_login.clone(), KEY_TEXT))
        .unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());

    // One transient failure alone is not even reported: the stored key is tried once more.
    let p = paths(&tmp.path().join("once"));
    attach(&p, VAULT);
    seal_on(&p, "mac", &full());
    let once = store_on(&p, "mac", Some(FakeFail::OpenFirst(1)));
    let loaded = once.resolve().unwrap().unwrap();
    assert_eq!(loaded.source, Source::Sealed);
    assert!(same_keys(&loaded.secrets, &full()));

    // Giving up sealed keys takes naming them: other keys than the named ones stay.
    let sealed_before = bytes(&p.sealed_file());
    let s = store(&p);
    s.save_dropping_keys(&login(), &with_keys(login(), "b3RoZXIga2V5cw"))
        .unwrap();
    assert_eq!(bytes(&p.sealed_file()), sealed_before);
    assert!(p.secrets_file().exists());
    std::fs::remove_file(p.secrets_file()).unwrap();
    s.save_dropping_keys(&login(), &full()).unwrap();
    assert_ne!(bytes(&p.sealed_file()), sealed_before);
    assert!(!p.secrets_file().exists());
    assert!(s.load().unwrap().unwrap().keys.is_empty());
    // A sealed document without keys has nothing to lose: a keyless save stays in it, and
    // so does the save that brings the keys.
    s.save(&new_login).unwrap();
    assert!(!p.secrets_file().exists());
    s.save_proven(&full()).unwrap();
    assert!(!p.secrets_file().exists());
    assert!(same_keys(&s.load().unwrap().unwrap(), &full()));
}

/// A plain copy of the secrets under a temp name — what a write killed before its rename
/// leaves — does not stay beside the store unseen: the next save removes it, and until then
/// the report counts it and warns.
#[test]
fn a_plain_temp_copy_of_the_secrets_is_reported_and_removed_by_the_next_save() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    seal_on(&p, "unit-test-machine", &full());
    assert_eq!(plain_leftovers(&p), 0);
    assert!(report(&p).warnings().is_empty());
    let leftover = p.state_root.join(".secrets.json.tmp-e39388f231ce62ee");
    std::fs::write(&leftover, to_json("secrets.json", &full()).unwrap()).unwrap();
    // Not ours: another file's temp, a name that only looks like one.
    std::fs::write(p.state_root.join(".token.json.tmp-e39388f231ce62ee"), b"x").unwrap();
    std::fs::write(p.state_root.join(".secrets.json.tmp-short"), b"x").unwrap();
    assert_eq!(plain_leftovers(&p), 1);
    let r = report(&p);
    assert_eq!(r.line(), "Secure Enclave of this Mac (secrets.sealed)");
    assert_eq!(r.plain_leftovers, 1);
    assert_eq!(r.json(&p)["key_store"]["plain_leftovers"], 1);
    let warnings = r.warnings();
    assert!(
        warnings.iter().any(|w| w.contains("1 plain copy(ies)")
            && w.contains("NOT worthless")
            && w.contains("gclone keystore use enclave")),
        "{warnings:?}"
    );

    // `keystore use enclave` on a device that is sealed already settles it — and puts a
    // choice right that an interrupted `use file` left at `file`.
    write_choice(&p, STORE_FILE, "t").unwrap();
    let s = LayeredStore::with_sealer(&p, sealer(), false);
    assert!(settle_sealed(&s).unwrap());
    assert!(!leftover.exists());
    assert_eq!(read_choice(&p), Choice::Enclave);
    assert!(report(&p).warnings().is_empty());
    assert!(p.state_root.join(".secrets.json.tmp-short").exists());

    // A save (login) removes it as well, whatever store it writes to.
    std::fs::write(&leftover, b"copy").unwrap();
    s.save(&full()).unwrap();
    assert!(!leftover.exists());
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());

    // On the plain file nothing is settled by `settle_sealed`, and the warning names `file`.
    let p = paths(&tmp.path().join("plain"));
    plain(&p).save(&full()).unwrap();
    let leftover = p.state_root.join(".secrets.json.tmp-0011223344556677");
    std::fs::write(&leftover, b"copy").unwrap();
    let s = LayeredStore::with_sealer(&p, sealer(), false);
    assert!(!settle_sealed(&s).unwrap());
    assert!(leftover.exists());
    let warnings = report(&p).warnings();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("gclone keystore use file") && !w.contains("NOT worthless")),
        "{warnings:?}"
    );
}

/// A sealed file that does not open is never written to: the save goes to the plain file.
#[test]
fn save_never_writes_to_a_sealed_file_it_could_not_open() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    seal_on(&p, "another-mac", &full());
    let sealed_before = bytes(&p.sealed_file());
    let s = store(&p);

    // the keyless save of a login that has not asked for the passphrase yet
    s.save(&login()).unwrap();
    assert_eq!(bytes(&p.sealed_file()), sealed_before);
    assert!(plain(&p).load().unwrap().unwrap().keys.is_empty());
    // keys that were NOT just proven, and a sealed file that does not open: it stays
    s.save(&full()).unwrap();
    assert_eq!(bytes(&p.sealed_file()), sealed_before);
    // the login that has the key again removes it
    s.save_proven(&full()).unwrap();
    assert!(!p.sealed_file().exists());
    assert!(same_keys(&plain(&p).load().unwrap().unwrap(), &full()));
}

#[test]
fn save_removes_a_sealed_copy_only_when_the_plain_file_holds_the_same_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    let s = store(&p);

    // a sealed copy of the same keys (an interrupted move): gone after the next save
    seal_on(&p, "mac", &full());
    plain(&p).save(&login()).unwrap();
    s.save(&login()).unwrap();
    assert!(p.sealed_file().exists(), "a keyless save removes nothing");
    s.save(&full()).unwrap();
    assert!(!p.sealed_file().exists());

    // a sealed file with OTHER keys, and keys that were not proven in this run: it stays
    std::fs::remove_file(p.secrets_file()).unwrap();
    seal_on(
        &p,
        "mac",
        &with_keys(login(), "another-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    );
    plain(&p).save(&login()).unwrap();
    s.save(&full()).unwrap();
    assert!(p.sealed_file().exists());
    // proven: it goes
    s.save_proven(&full()).unwrap();
    assert!(!p.sealed_file().exists());
}

#[test]
fn save_into_the_sealed_store_falls_back_to_the_plain_file_when_sealing_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    seal_on(&p, "mac", &login());
    // The file opens, so the save aims at it — with a sealer whose output for the new
    // document does not open again: the check before anything is written catches it.
    struct Lying(FakeSealer);
    impl seal::Sealer for Lying {
        fn name(&self) -> &'static str {
            "lying"
        }
        fn create(&self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), SealError> {
            self.0.create()
        }
        fn seal(&self, public: &[u8], plain: &[u8]) -> Result<Vec<u8>, SealError> {
            let mut sealed = self.0.seal(public, plain)?;
            // only the secrets document is damaged; the first open (of the file) works
            if plain.len() > 200 {
                *sealed.last_mut().unwrap() ^= 1;
            }
            Ok(sealed)
        }
        fn open(
            &self,
            blob: &[u8],
            public: &[u8],
            sealed: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, SealError> {
            self.0.open(blob, public, sealed)
        }
    }
    let sealed_before = bytes(&p.sealed_file());
    let lying =
        LayeredStore::with_sealer(&p, Ok(Arc::new(Lying(FakeSealer::new("mac", None)))), false);
    lying.save_proven(&full()).unwrap();
    // nothing was renamed into place; the secrets went to the plain file, which holds the
    // keys from a keyfile — so the sealed file, now obsolete, is gone
    assert!(same_keys(&plain(&p).load().unwrap().unwrap(), &full()));
    assert!(!p.sealed_file().exists());
    assert_ne!(sealed_before.len(), 0);
    assert_eq!(source(&store(&p)), Some(Source::Plain));
}

#[test]
fn the_state_root_must_be_private_before_anything_is_saved() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    std::fs::set_permissions(&p.state_root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        store(&p).save(&full()),
        Err(ConfigError::InsecurePermissions(_))
    ));
    assert!(!p.secrets_file().exists() && !p.secrets_lock().exists());
}

// ---------------------------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------------------------

#[test]
fn delete_removes_both_files_the_token_and_every_temp_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    seal_on(&p, "mac", &full());
    plain(&p).save(&full()).unwrap();
    write_choice(&p, STORE_ENCLAVE, "t").unwrap();
    std::fs::write(p.trial_file(), br#"{"version":1}"#).unwrap();
    std::fs::write(p.token_file(), b"{}").unwrap();
    for name in [
        ".secrets.json.tmp-0011223344556677",
        ".secrets.sealed.tmp-0011223344556677",
        ".token.json.tmp-0011223344556677",
        ".keystore-trial.json.tmp-0011223344556677",
    ] {
        std::fs::write(p.state_root.join(name), b"a full copy").unwrap();
    }
    let unrelated = p.state_root.join(".other.tmp-0011223344556677");
    std::fs::write(&unrelated, b"x").unwrap();

    // even where the sealed file does not open
    store_on(&p, "another-mac", Some(FakeFail::Open))
        .delete()
        .unwrap();
    assert_eq!(
        files(&p),
        [
            ".other.tmp-0011223344556677",
            "CACHEDIR.TAG",
            "keystore-trial.json",
            "keystore.json",
            "secrets.lock"
        ],
        "a choice and a record stay; no secret does"
    );
    store(&p).delete().unwrap();
    assert!(store(&p).load().unwrap().is_none());

    // nothing to delete, no state root at all: fine, and nothing is created
    let empty = Paths {
        config_dir: tmp.path().join("c2"),
        state_root: tmp.path().join("s2"),
    };
    store(&empty).delete().unwrap();
    assert!(!empty.state_root.exists());
    assert!(!remove_leftovers(&empty).unwrap());
    std::fs::write(p.token_file(), b"{}").unwrap();
    assert!(remove_leftovers(&p).unwrap());
    assert!(!remove_leftovers(&p).unwrap());
}

#[test]
fn a_writer_that_cannot_get_the_lock_changes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    let held = lock_exclusive(&p, Duration::ZERO).unwrap();
    assert!(matches!(
        lock_exclusive(&p, Duration::from_millis(60)),
        Err(ConfigError::KeyStoreBusy)
    ));
    assert!(lock_shared(&p, Duration::from_millis(60)).is_none());
    drop(held);
    let shared = lock_shared(&p, Duration::ZERO).expect("free now");
    assert!(lock_shared(&p, Duration::ZERO).is_some(), "readers share");
    assert!(matches!(
        lock_exclusive(&p, Duration::ZERO),
        Err(ConfigError::KeyStoreBusy)
    ));
    drop(shared);
    lock_exclusive(&p, Duration::ZERO).unwrap();
}

// ---------------------------------------------------------------------------------------------
// gclone keystore use enclave
// ---------------------------------------------------------------------------------------------

fn new_key(machine: &str) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    // The fake's keys are plain data: a key made by one object opens with another object of
    // the same machine.
    seal::Sealer::create(&FakeSealer::new(machine, None)).unwrap()
}

#[test]
fn the_move_to_the_enclave_seals_verifies_and_only_then_removes_the_plain_file() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    let s = store(&p);
    s.save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    std::fs::write(
        p.state_root.join(".secrets.sealed.tmp-0011223344556677"),
        b"old",
    )
    .unwrap();
    // a trial whose key takes the secrets
    trial::step(&p, &FakeSealer::new("mac", None));
    let record = trial::load_or_new(&p);
    let (blob, public) = record.key_for_secrets().unwrap();

    move_to_enclave(&s, &document, &blob, &public, MoveBy::Command).unwrap();
    assert_eq!(
        files(&p),
        [
            "CACHEDIR.TAG",
            "keystore-trial.json",
            "keystore-trial.lock",
            "keystore.json",
            "secrets.lock",
            "secrets.sealed"
        ]
    );
    // The trial's key took the secrets, and the report says so from the two files.
    let r = report_with(&p, &s);
    assert_eq!(r.trial_key_holds_secrets, Some(true));
    assert!(r.trial.as_ref().unwrap().moved);
    assert!(r.warnings().is_empty(), "{:?}", r.warnings());
    assert_eq!(read_choice(&p), Choice::Enclave);
    let loaded = s.resolve().unwrap().unwrap();
    assert_eq!(loaded.source, Source::Sealed);
    let opened = s
        .open_sealed(&s.read_sealed().unwrap().unwrap())
        .ok()
        .unwrap();
    assert_eq!(
        opened.document.as_slice(),
        document,
        "the exact bytes of secrets.json"
    );
    assert_eq!(opened.envelope.vault_id.as_deref(), Some(VAULT));
    assert_eq!(
        opened.envelope.key,
        record.key.clone().unwrap(),
        "sealed to the trial's key"
    );
    // the trial's record stays as the evidence, without the key
    let after = trial::load_or_new(&p);
    assert!(after.key.is_none() && after.canary.is_none() && after.moved_ms.is_some());
    assert_eq!(after.ok, record.ok);

    // a later save (a re-login) stays in the sealed store
    let mut renewed = full();
    renewed.refresh_token = Some("1//renewed".into());
    s.save(&renewed).unwrap();
    assert!(!p.secrets_file().exists());
    assert_eq!(
        s.load().unwrap().unwrap().refresh_token.as_deref(),
        Some("1//renewed")
    );
}

/// The trial's evidence belongs to the trial's key. When that key could not be used at the
/// move — its test value did not open at that very moment — the secrets are sealed to a key
/// made then, about which the trial says nothing: `gclone keystore` used to go on reporting
/// "its key holds the secrets (N days, a restart survived)".
#[test]
fn a_move_to_a_new_key_is_not_reported_as_the_trials_key() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    let s = store(&p);
    s.save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    trial::step(&p, &FakeSealer::new("mac", None));
    // The trial has seen a second day: a record that somebody could take for evidence.
    assert!(trial::update(&p, |record| {
        let entry = trial::OkEntry {
            day: record.ok[0].day + 1,
            boot: record.created_boot.clone().unwrap(),
            session: "0x2".into(),
        };
        record.ok.push(entry);
        true
    }));
    let trial_public = trial::load_or_new(&p).public.clone().unwrap();
    assert_eq!(
        report_with(&p, &s).trial_key_holds_secrets,
        None,
        "no sealed file"
    );

    // `choose_key` could not use the trial's key: a new one.
    let (blob, public) = new_key("mac");
    move_to_enclave(&s, &document, &blob, &public, MoveBy::Command).unwrap();
    let record = trial::load_or_new(&p);
    assert!(record.moved_ms.is_some() && record.key.is_none());
    assert_eq!(
        record.public.as_deref(),
        Some(trial_public.as_str()),
        "the record says whose evidence it is"
    );
    let sealed: serde_json::Value = serde_json::from_slice(&bytes(&p.sealed_file())).unwrap();
    assert_ne!(sealed["public"], trial_public.as_str());
    let r = report_with(&p, &s);
    assert_eq!(r.store, Where::Sealed);
    assert_eq!(r.trial_key_holds_secrets, Some(false));
    assert_eq!(r.json(&p)["key_store"]["trial"]["key_holds_secrets"], false);
    assert!(r.trial_evidence_is_for_another_key());
    let warnings = r.warnings();
    assert!(
        warnings.iter().any(|w| w.contains(
            "made at the move, not to the Secure Enclave trial's key: the trial's record"
        ) && w
            .contains("`gclone keystore check --new-trial` forgets the old record")
            && !w.contains("did not open at that moment")),
        "{warnings:?}"
    );

    // A trial that had only begun — one day, no restart — is no evidence anybody could
    // mistake: what gclone 0.5.0 left behind `keystore use enclave` as the first command
    // after a login, for good. The files say the same; nothing warns.
    let p = paths(&tmp.path().join("begun"));
    attach(&p, VAULT);
    let s = store(&p);
    s.save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    trial::step(&p, &FakeSealer::new("mac", None));
    let (blob, public) = new_key("mac");
    move_to_enclave(&s, &document, &blob, &public, MoveBy::Command).unwrap();
    let r = report_with(&p, &s);
    assert_eq!(r.trial_key_holds_secrets, Some(false));
    assert!(r.trial.as_ref().is_some_and(|t| t.moved && t.days == 1));
    assert!(!r.trial_evidence_is_for_another_key());
    assert!(r.warnings().is_empty(), "{:?}", r.warnings());
}

/// Two `keystore use enclave` at once: the one that comes second finds the move done, and
/// says so — not "this device's login changed".
#[test]
fn a_move_that_finds_the_secrets_sealed_already_says_so() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    let s = store(&p);
    s.save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    let (blob, public) = new_key("mac");
    move_to_enclave(&s, &document, &blob, &public, MoveBy::Command).unwrap();
    let sealed = bytes(&p.sealed_file());
    let (blob, public) = new_key("mac");
    assert!(matches!(
        move_to_enclave(&s, &document, &blob, &public, MoveBy::Command),
        Err(MoveError::AlreadySealed)
    ));
    assert_eq!(bytes(&p.sealed_file()), sealed, "untouched");
    // A sealed file that does not open here is not "already sealed".
    assert!(matches!(
        move_to_enclave(
            &store_on(&p, "another-mac", None),
            &document,
            &blob,
            &public,
            MoveBy::Command
        ),
        Err(MoveError::Changed)
    ));
    // Neither file: the login is gone.
    s.delete().unwrap();
    assert!(matches!(
        move_to_enclave(&s, &document, &blob, &public, MoveBy::Command),
        Err(MoveError::Changed)
    ));
}

#[test]
fn the_move_to_the_enclave_stops_when_the_plain_file_changed_or_holds_no_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    let s = store(&p);
    s.save(&full()).unwrap();
    let looked_at = bytes(&p.secrets_file());
    let (blob, public) = new_key("mac");

    // another login wrote the file after the command looked at it
    let mut other = full();
    other.refresh_token = Some("1//another".into());
    s.save(&other).unwrap();
    assert!(matches!(
        move_to_enclave(&s, &looked_at, &blob, &public, MoveBy::Command),
        Err(MoveError::Changed)
    ));
    // gone meanwhile (a logout)
    s.delete().unwrap();
    assert!(matches!(
        move_to_enclave(&s, &looked_at, &blob, &public, MoveBy::Command),
        Err(MoveError::Changed)
    ));
    // a keyless file is nothing to move
    s.save(&login()).unwrap();
    let keyless = bytes(&p.secrets_file());
    assert!(matches!(
        move_to_enclave(&s, &keyless, &blob, &public, MoveBy::Command),
        Err(MoveError::Changed)
    ));
    assert!(!p.sealed_file().exists() && !p.keystore_file().exists());

    // no sealer
    s.save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    assert!(matches!(
        move_to_enclave(
            &no_sealer(&p, NoSealer::NotMac),
            &document,
            &blob,
            &public,
            MoveBy::Command
        ),
        Err(MoveError::Refused(_))
    ));
    // the lock is held by another writer
    let held = lock_exclusive(&p, Duration::ZERO).unwrap();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(100));
            drop(held);
        });
        // waits for it, then moves
        move_to_enclave(&s, &document, &blob, &public, MoveBy::Command).unwrap();
    });
}

/// Every failing sub-step of the move leaves `secrets.json` and no `secrets.sealed`.
#[test]
fn a_failed_move_to_the_enclave_leaves_the_plain_file_and_no_sealed_file() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    let s = store(&p);
    s.save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    let check_unchanged = || {
        assert_eq!(bytes(&p.secrets_file()), document);
        assert!(!p.sealed_file().exists());
        assert_eq!(read_choice(&p), Choice::Unset);
        assert_eq!(source(&store(&p)), Some(Source::Plain));
    };

    // a key of another machine: the in-memory open fails (5.2)
    let (blob, public) = new_key("another-mac");
    match move_to_enclave(&s, &document, &blob, &public, MoveBy::Command) {
        Err(MoveError::Refused(text)) => {
            assert!(text.contains("Nothing was changed"), "{text}");
            assert!(!text.contains("S3CR3T"), "{text}");
        }
        other => panic!("{other:?}"),
    }
    check_unchanged();

    // a blob that is not the key of `public` (the pitfall of the real framework)
    let (blob, _) = new_key("mac");
    let (_, public) = new_key("mac");
    assert!(matches!(
        move_to_enclave(&s, &document, &blob, &public, MoveBy::Command),
        Err(MoveError::Refused(_))
    ));
    check_unchanged();

    // the session loses the store between the seal and the read-back (5.4)
    let (blob, public) = new_key("mac");
    let flaky = store_on(&p, "mac", Some(FakeFail::Open));
    assert!(matches!(
        move_to_enclave(&flaky, &document, &blob, &public, MoveBy::Command),
        Err(MoveError::Refused(_))
    ));
    check_unchanged();

    // a sealed file that was there before a failing run is gone too — secrets.json holds
    // the keys, which is the condition for removing it
    seal_on_beside(&p, "mac", &full());
    let (blob, public) = new_key("another-mac");
    assert!(move_to_enclave(&s, &document, &blob, &public, MoveBy::Command).is_err());
    check_unchanged();
}

/// A sealed file beside an existing `secrets.json` (what an interrupted move leaves).
fn seal_on_beside(p: &Paths, machine: &str, secrets: &Secrets) {
    let aside = p.state_root.join("secrets.json.aside");
    std::fs::rename(p.secrets_file(), &aside).unwrap();
    seal_on(p, machine, secrets);
    std::fs::rename(&aside, p.secrets_file()).unwrap();
}

// ---------------------------------------------------------------------------------------------
// gclone keystore use file
// ---------------------------------------------------------------------------------------------

#[test]
fn use_file_moves_a_sealed_store_back_to_the_frozen_plain_format() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    let s = store(&p);
    s.save(&full()).unwrap();
    let original = bytes(&p.secrets_file());
    let (blob, public) = new_key("mac");
    move_to_enclave(&s, &original, &blob, &public, MoveBy::Command).unwrap();

    assert_eq!(move_to_file(&s, false).unwrap(), ToFile::Moved);
    assert_eq!(read_choice(&p), Choice::File);
    assert!(!p.sealed_file().exists());
    assert_eq!(mode(&p.secrets_file()), 0o600);
    // Downgrade: byte for byte the version-1 file an older gclone wrote and reads.
    assert_eq!(bytes(&p.secrets_file()), original);
    let back = plain(&p).load().unwrap().unwrap();
    assert!(back.has_login() && same_keys(&back, &full()));
    assert_eq!(back.client, crate::auth::AuthClient::Device);
    assert_eq!(source(&s), Some(Source::Plain));

    // again: nothing moves
    assert_eq!(move_to_file(&s, false).unwrap(), ToFile::AlreadyPlain);
    // a signed-out device: only the choice
    s.delete().unwrap();
    std::fs::remove_file(p.keystore_file()).unwrap();
    assert_eq!(move_to_file(&s, false).unwrap(), ToFile::NotSignedIn);
    assert_eq!(read_choice(&p), Choice::File);
}

#[test]
fn use_file_with_both_files_present() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    let s = store(&p);

    // equal keys (an interrupted move): the sealed copy goes
    s.save(&full()).unwrap();
    seal_on_beside(&p, "mac", &full());
    assert_eq!(move_to_file(&s, false).unwrap(), ToFile::SealedCopyRemoved);
    assert!(!p.sealed_file().exists() && p.secrets_file().exists());

    // other keys: stop and say so; --discard-sealed removes it
    seal_on_beside(
        &p,
        "mac",
        &with_keys(login(), "another-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    );
    let sealed_before = bytes(&p.sealed_file());
    match move_to_file(&s, false) {
        Err(MoveError::Refused(text)) => {
            assert!(
                text.contains("OTHER keys") && text.contains("--discard-sealed"),
                "{text}"
            )
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(bytes(&p.sealed_file()), sealed_before);
    assert_eq!(
        read_choice(&p),
        Choice::Unset,
        "nothing was changed, the choice included"
    );
    assert_eq!(move_to_file(&s, true).unwrap(), ToFile::SealedDiscarded);
    assert!(!p.sealed_file().exists());

    // does not open: the same
    seal_on_beside(&p, "another-mac", &full());
    match move_to_file(&s, false) {
        Err(MoveError::Refused(text)) => assert!(text.contains("does not open"), "{text}"),
        other => panic!("{other:?}"),
    }
    assert!(p.sealed_file().exists());
    assert_eq!(move_to_file(&s, true).unwrap(), ToFile::SealedDiscarded);
    assert!(same_keys(&s.load().unwrap().unwrap(), &full()));
}

#[test]
fn use_file_writes_the_merged_view_and_refuses_what_cannot_be_moved() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    let s = store(&p);
    seal_on(&p, "mac", &full());
    let mut newer_login = login();
    newer_login.refresh_token = Some("1//the-login-just-made".into());
    plain(&p).save(&newer_login).unwrap();

    // another vault: not merged, nothing changed
    attach(&p, OTHER_VAULT);
    let (plain_before, sealed_before) = (bytes(&p.secrets_file()), bytes(&p.sealed_file()));
    assert!(matches!(move_to_file(&s, true), Err(MoveError::Refused(_))));
    assert_eq!(bytes(&p.secrets_file()), plain_before);
    assert_eq!(bytes(&p.sealed_file()), sealed_before);
    // the sealed file does not open: nothing can be moved, and --discard-sealed does not
    // remove the only copy of the key
    attach(&p, VAULT);
    assert!(matches!(
        move_to_file(&store_on(&p, "another-mac", None), true),
        Err(MoveError::Refused(_))
    ));
    assert_eq!(bytes(&p.sealed_file()), sealed_before);
    assert_eq!(read_choice(&p), Choice::Unset);

    assert_eq!(move_to_file(&s, false).unwrap(), ToFile::Merged);
    assert!(!p.sealed_file().exists());
    let merged = plain(&p).load().unwrap().unwrap();
    assert_eq!(
        merged.refresh_token.as_deref(),
        Some("1//the-login-just-made")
    );
    assert!(same_keys(&merged, &full()));

    // a sealed store alone that does not open: stop, with the text of the load error
    std::fs::remove_file(p.secrets_file()).unwrap();
    std::fs::remove_file(p.keystore_file()).unwrap();
    seal_on(&p, "another-mac", &full());
    match move_to_file(&s, true) {
        Err(MoveError::Refused(text)) => {
            assert!(
                text.starts_with("Nothing can be moved") && text.contains("gclone login"),
                "{text}"
            )
        }
        other => panic!("{other:?}"),
    }
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
    assert_eq!(read_choice(&p), Choice::Unset);
}

// ---------------------------------------------------------------------------------------------
// the trial never changes what load returns
// ---------------------------------------------------------------------------------------------

#[test]
fn the_trial_runs_from_load_on_the_plain_file_and_never_changes_the_answer() {
    let tmp = tempfile::tempdir().unwrap();
    let sealers: [(Option<FakeFail>, bool); 4] = [
        (None, true),
        (Some(FakeFail::Create), true),
        (Some(FakeFail::Open), true),
        (Some(FakeFail::OpenStored), true),
    ];
    for (n, (fail, _)) in sealers.iter().enumerate() {
        let p = paths(&tmp.path().join(n.to_string()));
        attach(&p, VAULT);
        plain(&p).save(&full()).unwrap();
        let with_trial =
            LayeredStore::with_sealer(&p, Ok(Arc::new(FakeSealer::new("mac", *fail))), true);
        let loaded = with_trial.load().unwrap().unwrap();
        assert!(same_keys(&loaded, &full()));
        assert!(p.trial_file().exists(), "{fail:?}: the record");
        assert!(p.secrets_file().exists() && !p.sealed_file().exists());
        assert_eq!(read_choice(&p), Choice::Unset, "the trial makes no choice");
        let text = String::from_utf8(bytes(&p.trial_file())).unwrap();
        assert!(
            !text.contains("S3CR3T"),
            "no vault key and no token in the record"
        );
    }

    // A call into the enclave that does not return: the load answers after the bounded wait,
    // and the record says what happened.
    let p = paths(&tmp.path().join("hang"));
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    let hangs = LayeredStore::with_sealer(
        &p,
        Ok(Arc::new(FakeSealer::new("mac", Some(FakeFail::Hang)))),
        true,
    );
    let before = std::time::Instant::now();
    assert!(same_keys(&hangs.load().unwrap().unwrap(), &full()));
    let waited = before.elapsed();
    assert!(
        waited >= trial::STEP_WAIT && waited < trial::STEP_WAIT * 3,
        "{waited:?}"
    );
    let record = trial::load_or_new(&p);
    assert_eq!(record.failure_count, 1);
    assert!(record.failures[0].timed_out);

    // The choice `file`: no trial. A sealed device: no trial. No sealer: no trial.
    let no_trial = |p: &Paths| match trial::load(p) {
        trial::Stored::Absent => true,
        trial::Stored::Record(record) => record.key.is_none() && record.ok.is_empty(),
        trial::Stored::Unreadable => false,
    };
    let p = paths(&tmp.path().join("file"));
    plain(&p).save(&full()).unwrap();
    write_choice(&p, STORE_FILE, "t").unwrap();
    let chosen = LayeredStore::with_sealer(&p, Ok(Arc::new(FakeSealer::new("mac", None))), true);
    chosen.load().unwrap().unwrap();
    assert!(no_trial(&p));

    let p = paths(&tmp.path().join("sealed"));
    attach(&p, VAULT);
    seal_on(&p, "mac", &full());
    let sealed = LayeredStore::with_sealer(&p, Ok(Arc::new(FakeSealer::new("mac", None))), true);
    sealed.load().unwrap().unwrap();
    assert!(no_trial(&p));

    let p = paths(&tmp.path().join("linux"));
    plain(&p).save(&full()).unwrap();
    LayeredStore::with_sealer(&p, Err(NoSealer::NotMac), true)
        .load()
        .unwrap()
        .unwrap();
    assert!(no_trial(&p));
    assert!(
        p.state_root.join("CACHEDIR.TAG").exists(),
        "the backup tag, on every platform"
    );

    // A state root that cannot be written to: the load answers all the same.
    let p = paths(&tmp.path().join("readonly"));
    plain(&p).save(&full()).unwrap();
    std::fs::set_permissions(&p.state_root, std::fs::Permissions::from_mode(0o500)).unwrap();
    let readonly = LayeredStore::with_sealer(&p, Ok(Arc::new(FakeSealer::new("mac", None))), true);
    assert!(same_keys(&readonly.load().unwrap().unwrap(), &full()));
    std::fs::set_permissions(&p.state_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(no_trial(&p));
}

// ---------------------------------------------------------------------------------------------
// status and report
// ---------------------------------------------------------------------------------------------

#[test]
fn the_status_line_and_warnings_for_every_state() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    // `report` uses the test process's own stand-in machine.
    let s = LayeredStore::with_sealer(&p, sealer(), false);
    let sealer = sealer().unwrap();
    let r = report(&p);
    assert_eq!(r.line(), "none — this device is not signed in");
    assert!(r.warnings().is_empty());
    assert_eq!(r.json(&p)["key_store"]["store"], "none");

    s.save(&full()).unwrap();
    let r = report(&p);
    assert_eq!(
        r.line(),
        "plain file secrets.json (0600) — Secure Enclave trial not started yet"
    );
    assert!(r.cachedir_tag);

    trial::step(&p, sealer.as_ref());
    let r = report(&p);
    assert_eq!(
        r.line(),
        "plain file secrets.json (0600) — Secure Enclave trial: 1 of 3 days, no restart seen yet"
    );
    let json = r.json(&p);
    assert_eq!(json["key_store"]["store"], "file");
    assert_eq!(json["key_store"]["choice"], serde_json::Value::Null);
    assert_eq!(json["key_store"]["trial"]["days"], 1);
    assert_eq!(json["key_store"]["trial"]["restart"], false);
    assert_eq!(json["key_store"]["trial"]["complete"], false);
    assert_eq!(json["key_store"]["both_present"], false);
    assert_eq!(
        json["key_store"]["path"],
        p.secrets_file().display().to_string()
    );

    // complete
    let mut record = trial::load_or_new(&p);
    let created = record.created_boot.clone().unwrap();
    let day = record.ok[0].day;
    for (d, boot) in [(day + 1, created.as_str()), (day + 2, "another-boot")] {
        record.ok.push(trial::OkEntry {
            day: d,
            boot: boot.into(),
            session: "0x2030".into(),
        });
    }
    // three calendar days, a restart — and less than 48 hours
    record.last_ok_ms = record.created_ms.map(|ms| ms + trial::MIN_AGE_MS - 1);
    trial::save(&p, &record).unwrap();
    let r = report(&p);
    assert_eq!(
        r.line(),
        "plain file secrets.json (0600) — Secure Enclave trial: 3 days, not yet 48 hours apart, \
         a restart survived"
    );
    assert_eq!(r.json(&p)["key_store"]["trial"]["complete"], false);
    assert_eq!(r.json(&p)["key_store"]["trial"]["aged"], false);
    record.last_ok_ms = record.created_ms.map(|ms| ms + trial::MIN_AGE_MS);
    trial::save(&p, &record).unwrap();
    let r = report(&p);
    assert_eq!(
        r.line(),
        "plain file secrets.json (0600) — Secure Enclave trial complete: the next run that can \
         open the test value moves the secrets into the sealed store"
    );
    assert_eq!(r.json(&p)["key_store"]["trial"]["complete"], true);

    // a failure
    record.failure_count = 2;
    record.failures.push(trial::Failure {
        ms: 1_794_400_000_000,
        boot: created,
        session: "0x2".into(),
        fresh_key_ok: true,
        error: "token error -3".into(),
        timed_out: false,
    });
    trial::save(&p, &record).unwrap();
    let r = report(&p);
    assert_eq!(
        r.line(),
        "plain file secrets.json (0600) — Secure Enclave trial: 3 days, a restart survived, 2 failures"
    );
    let warnings = r.warnings();
    assert_eq!(warnings.len(), 1);
    assert!(
        warnings[0].starts_with(
            "the Secure Enclave trial failed 2 time(s) in a session without graphic access (last: 2026-11-"
        ),
        "{}",
        warnings[0]
    );
    assert!(
        warnings[0].contains("Nothing is moved into the sealed store while a failure is on"),
        "{}",
        warnings[0]
    );

    // kept by choice: no trial talk, no warning
    write_choice(&p, STORE_FILE, "t").unwrap();
    let r = report(&p);
    assert_eq!(r.line(), "plain file secrets.json (0600) — kept by choice");
    assert!(r.warnings().is_empty());
    assert_eq!(r.json(&p)["key_store"]["choice"], "file");

    // No key could be made. That is "no Secure Enclave on this machine" when a desktop
    // session said so; any other session speaks for itself, with its date.
    std::fs::remove_file(p.keystore_file()).unwrap();
    std::fs::remove_file(p.trial_file()).unwrap();
    trial::step(&p, &FakeSealer::new("x", Some(FakeFail::Create)));
    let mut record = trial::load_or_new(&p);
    let mut unavailable = record.unavailable.clone().expect("recorded");
    unavailable.session = "0x2030".into();
    record.unavailable = Some(unavailable.clone());
    trial::save(&p, &record).unwrap();
    assert_eq!(
        report(&p).line(),
        "plain file secrets.json (0600) — no Secure Enclave on this machine"
    );
    unavailable.session = "0x2".into();
    unavailable.ms = 1_794_400_000_000;
    record.unavailable = Some(unavailable);
    trial::save(&p, &record).unwrap();
    let r = report(&p);
    assert!(
        r.line().starts_with(
            "plain file secrets.json (0600) — no Secure Enclave key could be made in session \
             0x2 (without graphic access) on 2026-11-"
        ),
        "{}",
        r.line()
    );
    assert!(!r.line().contains("on this machine"));
    assert_eq!(
        r.json(&p)["key_store"]["trial"]["unavailable_session"],
        "0x2"
    );
    std::fs::remove_file(p.trial_file()).unwrap();

    // both files, the sealed one under the key of the trial that is running: a move that
    // gclone began by itself, and the next run finishes it
    let document = bytes(&p.secrets_file());
    let passed = passed_trial(&p, "unit-test-machine");
    let (blob, public) = passed.key_for_secrets().unwrap();
    let envelope = s
        .envelope_for(sealer.as_ref(), &blob, &public, &document, true)
        .unwrap();
    s.write_sealed(&envelope, "t").unwrap();
    let r = report(&p);
    assert!(r.both_present && r.sealed_differs.is_none() && !r.blocked_by_sealed);
    assert!(
        r.line().contains("trial complete: the next run"),
        "{}",
        r.line()
    );
    let warnings = r.warnings();
    assert!(
        warnings.iter().any(|w| w
            == "secrets.json and secrets.sealed both exist (an interrupted move, or an older \
                gclone signed in here). gclone uses secrets.json. `gclone keystore use file` or \
                `gclone keystore use enclave` settles it; a move that gclone began by itself is \
                finished by the next run."),
        "{warnings:?}"
    );
    assert_eq!(r.json(&p)["key_store"]["both_present"], true);
    assert_eq!(r.json(&p)["key_store"]["blocked_by_sealed"], false);

    // both files, the sealed one under any other key (an interrupted `keystore use`; the
    // store of an earlier sealing, with the secrets.json of an older gclone's login beside
    // it): nothing is tested or moved, and neither line promises a move
    let (blob, public) = sealer.create().unwrap();
    let envelope = s
        .envelope_for(sealer.as_ref(), &blob, &public, &document, true)
        .unwrap();
    s.write_sealed(&envelope, "t").unwrap();
    for with_trial in [true, false] {
        if !with_trial {
            std::fs::remove_file(p.trial_file()).unwrap();
        }
        let r = report(&p);
        assert!(r.both_present && r.sealed_differs.is_none() && r.blocked_by_sealed);
        assert_eq!(
            r.line(),
            "plain file secrets.json (0600) — kept: nothing is tested or moved while \
             secrets.sealed lies beside it"
        );
        let warnings = r.warnings();
        assert!(
            warnings.iter().any(|w| w
                == "secrets.json and secrets.sealed both exist (an interrupted move, or an \
                    older gclone signed in here). gclone uses secrets.json. `gclone keystore \
                    use file` or `gclone keystore use enclave` settles it. Until then gclone \
                    tests and moves nothing by itself here; if an older gclone uses this device \
                    (0.4.0 and before read only secrets.json), update it first, or keep the \
                    plain file with `gclone keystore use file`."),
            "{warnings:?}"
        );
        assert_eq!(r.json(&p)["key_store"]["blocked_by_sealed"], true);
    }

    // both files, and the sealed one does not open here, beside a trial that has passed:
    // "the next run moves" was untrue — every run refuses — and `use file` alone refuses too
    let good = bytes(&p.sealed_file());
    passed_trial(&p, "unit-test-machine");
    let elsewhere = FakeSealer::new("another-mac", None);
    let (blob, public) = seal::Sealer::create(&elsewhere).unwrap();
    let envelope = s
        .envelope_for(&elsewhere, &blob, &public, &document, true)
        .unwrap();
    s.write_sealed(&envelope, "t").unwrap();
    let r = report(&p);
    assert!(r.trial.as_ref().is_some_and(|t| t.complete));
    assert!(r.both_present && r.sealed_differs.is_some() && r.blocked_by_sealed);
    assert!(!r.line().contains("the next run"), "{}", r.line());
    assert!(
        r.line().contains("kept: nothing is tested or moved"),
        "{}",
        r.line()
    );
    let warnings = r.warnings();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("secrets.sealed is not a copy of it")
                && w.contains(
                    "`gclone keystore use file --discard-sealed` removes secrets.sealed, `gclone \
                 keystore use enclave` replaces it. Until then gclone tests and moves nothing"
                )
                && !w.contains("finished by the next run")),
        "{warnings:?}"
    );
    // … and so it is: the automatic move refuses, `use file` wants the flag.
    match automatic_move(
        &LayeredStore::with_sealer(&p, super::sealer(), false).sealed_by_default(true),
    ) {
        AutoMove::Kept(why) => assert!(why.contains("does not open"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(
        matches!(move_to_file(&s, false), Err(MoveError::Refused(text)) if text.contains("--discard-sealed"))
    );
    assert_eq!(read_choice(&p), Choice::Unset);
    std::fs::remove_file(p.trial_file()).unwrap();
    std::fs::write(p.sealed_file(), &good).unwrap();

    // sealed alone
    std::fs::remove_file(p.secrets_file()).unwrap();
    write_choice(&p, STORE_ENCLAVE, "t").unwrap();
    let r = report(&p);
    assert_eq!(r.line(), "Secure Enclave of this Mac (secrets.sealed)");
    assert!(r.warnings().is_empty(), "{:?}", r.warnings());
    let json = r.json(&p);
    assert_eq!(json["key_store"]["store"], "enclave");
    assert_eq!(json["key_store"]["choice"], "enclave");
    assert_eq!(json["key_store"]["usable"], true);
    // the choice and the store differ (an interrupted `use file`)
    write_choice(&p, STORE_FILE, "t").unwrap();
    assert!(
        report(&p)
            .warnings()
            .iter()
            .any(|w| w.contains("Run `gclone keystore use file` again"))
    );

    // merged
    write_choice(&p, STORE_ENCLAVE, "t").unwrap();
    plain(&p).save(&login()).unwrap();
    let r = report(&p);
    assert!(
        r.line().contains("secrets.json for the login"),
        "{}",
        r.line()
    );
    assert!(
        r.warnings()
            .iter()
            .any(|w| w.contains("an older gclone signed in here"))
    );

    // sealed and unusable
    std::fs::remove_file(p.secrets_file()).unwrap();
    std::fs::write(p.sealed_file(), b"junk").unwrap();
    let r = report(&p);
    assert_eq!(r.line(), "secrets.sealed — cannot be opened here");
    assert!(matches!(&r.store, Where::SealedUnusable(text) if text.contains("damaged")));
    assert_eq!(r.json(&p)["key_store"]["usable"], false);

    // on S although the enclave was chosen
    std::fs::remove_file(p.sealed_file()).unwrap();
    plain(&p).save(&full()).unwrap();
    let r = report(&p);
    assert!(
        r.warnings()
            .iter()
            .any(|w| w.contains("the sealed store was chosen")),
        "{:?}",
        r.warnings()
    );
}

#[test]
fn a_process_without_a_sealer_reports_the_plain_file_and_nothing_to_try() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    plain(&p).save(&full()).unwrap();
    let mut r = report(&p);
    r.sealer = Err(NoSealer::NotMac);
    assert_eq!(r.line(), "plain file secrets.json (0600)");
    assert!(NoSealer::NotMac.text().contains("Secure Enclave of a Mac"));
}

// ---------------------------------------------------------------------------------------------
// the sealed store as the default (§17.30)
// ---------------------------------------------------------------------------------------------

/// A store whose default is the sealed store, as the binary's is.
fn default_store_on(p: &Paths, machine: &str, fail: Option<FakeFail>) -> LayeredStore {
    store_on(p, machine, fail).sealed_by_default(true)
}

fn default_store(p: &Paths) -> LayeredStore {
    default_store_on(p, "mac", None)
}

fn sealed_public(p: &Paths) -> String {
    let envelope: serde_json::Value = serde_json::from_slice(&bytes(&p.sealed_file())).unwrap();
    envelope["public"].as_str().unwrap().to_string()
}

/// A trial of `machine` that has passed: three days that are 48 hours apart, a second boot,
/// no failure.
fn passed_trial(p: &Paths, machine: &str) -> trial::Record {
    trial::step(p, &FakeSealer::new(machine, None));
    let mut record = trial::load_or_new(p);
    let created = record.created_boot.clone().unwrap();
    let day = record.ok[0].day;
    for (d, boot) in [(day + 1, created.as_str()), (day + 2, "another-boot")] {
        record.ok.push(trial::OkEntry {
            day: d,
            boot: boot.into(),
            session: "0x2".into(),
        });
    }
    record.last_ok_ms = record.created_ms.map(|ms| ms + trial::MIN_AGE_MS);
    trial::save(p, &record).unwrap();
    assert!(record.summary().complete);
    record
}

/// A login on a Mac seals its secrets from the start: both of its saves go to
/// `secrets.sealed`, no plain file is ever written, and no choice is recorded — the choice
/// file is the owner's.
#[test]
fn a_login_seals_from_the_start_where_the_sealed_store_is_the_default() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(&tmp.path().join("fresh"));
    attach(&p, VAULT);
    let s = default_store(&p);
    // the two saves of a login: first the login alone, then with the keys
    s.save(&login()).unwrap();
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
    assert_eq!(mode(&p.sealed_file()), 0o600);
    let first = sealed_public(&p);
    s.save_proven(&full()).unwrap();
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
    assert_eq!(sealed_public(&p), first, "the same key for both saves");
    assert_eq!(source(&s), Some(Source::Sealed));
    assert!(same_keys(&s.load().unwrap().unwrap(), &full()));
    assert_eq!(read_choice(&p), Choice::Unset, "nobody chose anything");
    assert!(!p.trial_file().exists(), "a login starts no trial");
    assert!(!p.move_note_file().exists());
    assert!(files(&p).iter().all(|name| !name.contains(".tmp-")));
    let text = String::from_utf8(bytes(&p.sealed_file())).unwrap();
    assert!(!text.contains("S3CR3T"), "nothing in plain");
    let r = report_with(&p, &s);
    assert_eq!(r.line(), "Secure Enclave of this Mac (secrets.sealed)");
    assert!(r.warnings().is_empty(), "{:?}", r.warnings());

    // A directory vault's login has one save, with the keys.
    let p = paths(&tmp.path().join("dir"));
    attach(&p, VAULT);
    let s = default_store(&p);
    s.save_proven(&with_keys(Secrets::empty(), KEY_TEXT))
        .unwrap();
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());

    // A trial that has passed on this Mac, and whose move has not happened yet (the device
    // was signed out in between), lends its key — the key its evidence is about — and ends:
    // the record says whose key took the secrets.
    let p = paths(&tmp.path().join("trial"));
    attach(&p, VAULT);
    let trial_public = passed_trial(&p, "mac").public.clone().unwrap();
    let s = default_store(&p);
    s.save_proven(&full()).unwrap();
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
    assert_eq!(sealed_public(&p), trial_public);
    let record = trial::load_or_new(&p);
    assert!(record.moved_ms.is_some() && record.key.is_none());
    let r = report_with(&p, &s);
    assert_eq!(r.trial_key_holds_secrets, Some(true));
    assert!(r.warnings().is_empty(), "{:?}", r.warnings());
    // … and where this process cannot open that key, the login does not seal to another one:
    // the plain file, as for the automatic move.
    let p = paths(&tmp.path().join("trial-elsewhere"));
    attach(&p, VAULT);
    passed_trial(&p, "mac");
    let s = default_store_on(&p, "mac", Some(FakeFail::OpenStored));
    s.save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert!(matches!(
        seal_after_login(&s, false),
        AfterLogin::Plain(Some(why)) if why.contains("did not open in this process")
    ));
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());

    // The owner chose the plain file: it stays, also for a login after a logout.
    let p = paths(&tmp.path().join("file"));
    attach(&p, VAULT);
    write_choice(&p, STORE_FILE, "t").unwrap();
    let s = default_store(&p);
    s.save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    s.delete().unwrap();
    s.save(&login()).unwrap();
    s.save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert_eq!(read_choice(&p), Choice::File);

    // A choice file that cannot be read counts as "no choice", with everything unasked
    // suspended.
    let p = paths(&tmp.path().join("unreadable"));
    attach(&p, VAULT);
    std::fs::write(p.keystore_file(), b"{ not json").unwrap();
    std::fs::set_permissions(p.keystore_file(), std::fs::Permissions::from_mode(0o600)).unwrap();
    default_store(&p).save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());

    // The stores of unit tests (and of nothing else) have the default switched off.
    let p = paths(&tmp.path().join("off"));
    attach(&p, VAULT);
    store(&p).save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
}

/// Where the Secure Enclave cannot be used, a login goes to the plain file without a word,
/// and the reason is on record for `gclone status` and `gclone keystore`.
#[test]
fn a_login_falls_back_to_the_plain_file_and_the_reason_is_on_record() {
    let tmp = tempfile::tempdir().unwrap();

    // No key can be made here (no Secure Enclave, a virtual machine).
    let p = paths(&tmp.path().join("create"));
    attach(&p, VAULT);
    let s = default_store_on(&p, "mac", Some(FakeFail::Create));
    s.save(&login()).unwrap();
    s.save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert_eq!(source(&s), Some(Source::Plain));
    let record = trial::load_or_new(&p);
    let unavailable = record.unavailable.clone().expect("the reason is recorded");
    assert!(
        unavailable.error.contains("no key can be made"),
        "{unavailable:?}"
    );
    assert_eq!(unavailable.session, trial::Moment::now().session);
    let line = report_with(&p, &s).line();
    assert!(
        line.starts_with("plain file secrets.json (0600) — no Secure Enclave"),
        "{line}"
    );

    // A key can be made and nothing opens with it (a session without access).
    let p = paths(&tmp.path().join("open"));
    attach(&p, VAULT);
    let s = default_store_on(&p, "mac", Some(FakeFail::Open));
    s.save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert!(trial::load_or_new(&p).unavailable.is_some());

    // The key is fine and what it seals does not open again: nothing is renamed into place.
    struct Lying(FakeSealer);
    impl seal::Sealer for Lying {
        fn name(&self) -> &'static str {
            "lying"
        }
        fn create(&self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), SealError> {
            self.0.create()
        }
        fn seal(&self, public: &[u8], plain: &[u8]) -> Result<Vec<u8>, SealError> {
            let mut sealed = self.0.seal(public, plain)?;
            if plain.len() > 200 {
                *sealed.last_mut().unwrap() ^= 1;
            }
            Ok(sealed)
        }
        fn open(
            &self,
            blob: &[u8],
            public: &[u8],
            sealed: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, SealError> {
            self.0.open(blob, public, sealed)
        }
    }
    let p = paths(&tmp.path().join("lying"));
    attach(&p, VAULT);
    let s = LayeredStore::with_sealer(&p, Ok(Arc::new(Lying(FakeSealer::new("mac", None)))), false)
        .sealed_by_default(true);
    s.save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert!(files(&p).iter().all(|name| !name.contains(".tmp-")));
    assert!(trial::load_or_new(&p).unavailable.is_some());

    // The first call into the enclave does not come back: the login is held up for the
    // bounded wait and goes to the plain file.
    let p = paths(&tmp.path().join("hang"));
    attach(&p, VAULT);
    let s = default_store_on(&p, "mac", Some(FakeFail::Hang));
    let before = Instant::now();
    s.save_proven(&full()).unwrap();
    let waited = before.elapsed();
    assert!(
        waited >= trial::STEP_WAIT && waited < trial::STEP_WAIT * 3,
        "{waited:?}"
    );
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    let record = trial::load_or_new(&p);
    assert!(record.failures[0].timed_out && record.unavailable.is_some());

    // A process without a sealer (Linux; a debug build): the plain file, and nothing to
    // record.
    let p = paths(&tmp.path().join("linux"));
    attach(&p, VAULT);
    let s = no_sealer(&p, NoSealer::NotMac).sealed_by_default(true);
    s.save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert!(!p.trial_file().exists());
    assert_eq!(report_with(&p, &s).line(), "plain file secrets.json (0600)");

    // The trial's record of this Mac holds a failure (some session could not open the test
    // value): a login does not seal over that evidence — the plain file, until somebody
    // looked (`gclone keystore check --new-trial`).
    let p = paths(&tmp.path().join("failure"));
    attach(&p, VAULT);
    trial::step(&p, &FakeSealer::new("mac", None));
    trial::step(&p, &FakeSealer::new("mac", Some(FakeFail::Open)));
    assert_eq!(trial::load_or_new(&p).failure_count, 1);
    let s = default_store(&p);
    s.save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert!(matches!(
        seal_after_login(&s, false),
        AfterLogin::Plain(Some(why)) if why.contains("holds a failure")
    ));
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    // … unless the owner chose the sealed store.
    s.delete().unwrap();
    write_choice(&p, STORE_ENCLAVE, "t").unwrap();
    s.save_proven(&full()).unwrap();
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
}

/// The move that nobody asked for: nothing before the trial has passed, then the whole
/// sequence of `keystore use enclave` — to the trial's own key, without a choice on file —
/// and a note that is owed.
#[test]
fn the_automatic_move_waits_for_a_passed_trial_and_seals_to_its_key() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    let s = default_store(&p);
    let untouched = |what: &str| {
        assert_eq!(bytes(&p.secrets_file()), document, "{what}");
        assert!(!p.sealed_file().exists(), "{what}");
        assert!(!p.move_note_file().exists(), "{what}");
        assert_eq!(read_choice(&p), Choice::Unset, "{what}");
    };

    // No trial yet; a trial of one day; three days without a restart; a restart and a
    // failure: not due.
    assert_eq!(automatic_move(&s), AutoMove::NotDue);
    untouched("no trial");
    trial::step(&p, &FakeSealer::new("mac", None));
    assert_eq!(automatic_move(&s), AutoMove::NotDue);
    untouched("one day");
    let mut record = trial::load_or_new(&p);
    let created = record.created_boot.clone().unwrap();
    let day = record.ok[0].day;
    for d in [day + 1, day + 2, day + 3] {
        record.ok.push(trial::OkEntry {
            day: d,
            boot: created.clone(),
            session: "0x2030".into(),
        });
    }
    trial::save(&p, &record).unwrap();
    assert_eq!(automatic_move(&s), AutoMove::NotDue);
    untouched("four days, no restart");
    record.ok.truncate(1);
    record.ok.push(trial::OkEntry {
        day: day + 1,
        boot: "another-boot".into(),
        session: "0x2030".into(),
    });
    trial::save(&p, &record).unwrap();
    assert_eq!(automatic_move(&s), AutoMove::NotDue);
    untouched("a restart, two days");
    record.ok.push(trial::OkEntry {
        day: day + 2,
        boot: "another-boot".into(),
        session: "0x2".into(),
    });
    trial::save(&p, &record).unwrap();
    assert_eq!(automatic_move(&s), AutoMove::NotDue);
    untouched("three calendar days and a restart, the age unknown");
    record.last_ok_ms = record.created_ms.map(|ms| ms + trial::MIN_AGE_MS - 1);
    trial::save(&p, &record).unwrap();
    assert_eq!(automatic_move(&s), AutoMove::NotDue);
    untouched("three calendar days within less than 48 hours");
    record.last_ok_ms = record.created_ms.map(|ms| ms + trial::MIN_AGE_MS);
    let passed = record.clone();
    record.failure_count = 1;
    trial::save(&p, &record).unwrap();
    assert_eq!(automatic_move(&s), AutoMove::NotDue);
    untouched("three days, a restart, and a failure");

    // The trial has passed — and still nothing moves …
    trial::save(&p, &passed).unwrap();
    // … from a process that cannot open the trial's key itself (rule 6): a dead blob, a
    // session without access;
    for fail in [FakeFail::OpenStored, FakeFail::Open] {
        match automatic_move(&default_store_on(&p, "mac", Some(fail))) {
            AutoMove::Kept(why) => {
                assert!(why.contains("did not open in this process"), "{why}")
            }
            other => panic!("{fail:?}: {other:?}"),
        }
        untouched("the key does not open here");
    }
    match automatic_move(&default_store_on(&p, "another-mac", None)) {
        AutoMove::Kept(why) => assert!(why.contains("did not open in this process"), "{why}"),
        other => panic!("{other:?}"),
    }
    untouched("another Mac");
    // … on a machine or in a build without a sealer;
    assert_eq!(
        automatic_move(&no_sealer(&p, NoSealer::NotMac).sealed_by_default(true)),
        AutoMove::NotDue
    );
    // … where the default is switched off (unit tests of other modules);
    assert_eq!(automatic_move(&store(&p)), AutoMove::NotDue);
    // … while another gclone holds the secrets lock (one try, no wait);
    {
        let _held = lock_exclusive(&p, Duration::ZERO).unwrap();
        let before = Instant::now();
        assert_eq!(automatic_move(&s), AutoMove::Busy);
        assert!(before.elapsed() < Duration::from_secs(1));
    }
    untouched("the lock is held");
    // … where the choice file cannot be read;
    std::fs::write(p.keystore_file(), b"{ not json").unwrap();
    std::fs::set_permissions(p.keystore_file(), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(automatic_move(&s), AutoMove::NotDue);
    std::fs::remove_file(p.keystore_file()).unwrap();
    untouched("an unreadable choice");
    // … and never after `gclone keystore use file`.
    assert_eq!(move_to_file(&s, false).unwrap(), ToFile::AlreadyPlain);
    assert_eq!(read_choice(&p), Choice::File);
    assert_eq!(automatic_move(&s), AutoMove::NotDue);
    assert_eq!(bytes(&p.secrets_file()), document);
    assert!(!p.sealed_file().exists() && !p.move_note_file().exists());
    std::fs::remove_file(p.keystore_file()).unwrap();

    // Now it moves.
    assert_eq!(automatic_move(&s), AutoMove::Moved);
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
    assert_eq!(mode(&p.sealed_file()), 0o600);
    assert_eq!(
        read_choice(&p),
        Choice::Unset,
        "no choice is recorded for the owner"
    );
    assert!(p.move_note_file().exists(), "the note is owed");
    assert_eq!(mode(&p.move_note_file()), 0o600);
    assert!(files(&p).iter().all(|name| !name.contains(".tmp-")));
    let opened = s
        .open_sealed(&s.read_sealed().unwrap().unwrap())
        .ok()
        .unwrap();
    assert_eq!(
        opened.document.as_slice(),
        document,
        "the exact bytes of secrets.json"
    );
    assert_eq!(
        opened.envelope.key,
        passed.key.clone().unwrap(),
        "sealed to the trial's own key"
    );
    assert_eq!(opened.envelope.vault_id.as_deref(), Some(VAULT));
    let after = trial::load_or_new(&p);
    assert!(after.moved_ms.is_some() && after.key.is_none());
    assert_eq!(after.ok, passed.ok, "the evidence stays");
    let r = report_with(&p, &s);
    assert_eq!(r.store, Where::Sealed);
    assert_eq!(r.trial_key_holds_secrets, Some(true));
    assert!(r.warnings().is_empty(), "{:?}", r.warnings());
    assert_eq!(r.json(&p)["key_store"]["choice"], serde_json::Value::Null);
    // Again: nothing to do, and nothing changes.
    let sealed = bytes(&p.sealed_file());
    assert_eq!(automatic_move(&s), AutoMove::NotDue);
    assert_eq!(bytes(&p.sealed_file()), sealed);
    // A later login stays sealed; a logout takes the owed note with it.
    let mut renewed = full();
    renewed.refresh_token = Some("1//renewed".into());
    s.save(&renewed).unwrap();
    assert!(!p.secrets_file().exists());

    // The way back gives the bytes there were, takes the owed note away, and is remembered:
    // no move afterwards, although the old record is complete and a login follows.
    s.save(&full()).unwrap();
    assert_eq!(move_to_file(&s, false).unwrap(), ToFile::Moved);
    assert_eq!(bytes(&p.secrets_file()), document);
    assert!(!p.move_note_file().exists());
    trial::save(&p, &passed).unwrap();
    assert_eq!(automatic_move(&s), AutoMove::NotDue);
    s.delete().unwrap();
    s.save_proven(&full()).unwrap();
    assert_eq!(automatic_move(&s), AutoMove::NotDue);
    assert_eq!(seal_after_login(&s, false), AfterLogin::Plain(None));
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
}

/// A sealed file beside the plain one. A move that was cut off after its rename left a copy
/// of the same keys: the next run finishes. Anything else — other keys, a file that does not
/// open — may be the only copy of another state, and only the owner's command gives it up.
#[test]
fn the_automatic_move_finishes_its_own_and_leaves_a_foreign_sealed_file_alone() {
    let tmp = tempfile::tempdir().unwrap();

    // the same keys, sealed to the trial's key: what a killed automatic move leaves
    let p = paths(&tmp.path().join("same"));
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    let record = passed_trial(&p, "mac");
    let s = default_store(&p);
    let (blob, public) = record.key_for_secrets().unwrap();
    let envelope = s
        .envelope_for(
            &FakeSealer::new("mac", None),
            &blob,
            &public,
            &document,
            true,
        )
        .unwrap();
    s.write_sealed(&envelope, "t").unwrap();
    assert_eq!(source(&s), Some(Source::Plain), "readers use secrets.json");
    assert_eq!(automatic_move(&s), AutoMove::Moved);
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
    assert!(same_keys(&s.load().unwrap().unwrap(), &full()));
    assert_eq!(move_to_file(&s, false).unwrap(), ToFile::Moved);
    assert_eq!(bytes(&p.secrets_file()), document);

    // other keys
    let p = paths(&tmp.path().join("other"));
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    // (the helper's save would lend — and end — a trial that is running: it comes first)
    seal_on_beside(
        &p,
        "mac",
        &with_keys(login(), "AnotherKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    );
    passed_trial(&p, "mac");
    let beside = bytes(&p.sealed_file());
    let s = default_store(&p);
    match automatic_move(&s) {
        AutoMove::Kept(why) => assert!(why.contains("other keys"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(bytes(&p.secrets_file()), document);
    assert_eq!(bytes(&p.sealed_file()), beside);
    assert!(!p.move_note_file().exists());

    // a sealed file of another Mac
    let p = paths(&tmp.path().join("dead"));
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    seal_on_beside(&p, "another-mac", &full());
    passed_trial(&p, "mac");
    let beside = bytes(&p.sealed_file());
    let s = default_store(&p);
    match automatic_move(&s) {
        AutoMove::Kept(why) => assert!(why.contains("does not open"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(bytes(&p.secrets_file()), document);
    assert_eq!(bytes(&p.sealed_file()), beside);
    // The owner's command does settle it.
    let (blob, public) = new_key("mac");
    move_to_enclave(&s, &document, &blob, &public, MoveBy::Command).unwrap();
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
}

/// The move happens from `load`, once the step of this very process has opened the test
/// value — and `load` returns what it would have returned anyway.
#[test]
fn a_load_moves_the_secrets_once_the_trial_has_passed() {
    let tmp = tempfile::tempdir().unwrap();
    let live = |p: &Paths, fail: Option<FakeFail>| {
        LayeredStore::with_sealer(p, Ok(Arc::new(FakeSealer::new("mac", fail))), true)
            .sealed_by_default(true)
    };

    // Not before the bar: the first loads start and continue the trial, nothing else.
    let p = paths(&tmp.path().join("young"));
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    assert!(same_keys(&live(&p, None).load().unwrap().unwrap(), &full()));
    assert!(p.trial_file().exists());
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());

    // Passed: the load that follows moves.
    let p = paths(&tmp.path().join("passed"));
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    let record = passed_trial(&p, "mac");
    let loaded = live(&p, None).load().unwrap().unwrap();
    assert!(same_keys(&loaded, &full()));
    assert_eq!(loaded.refresh_token.as_deref(), Some(TOKEN_TEXT));
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
    assert_eq!(sealed_public(&p), record.public.clone().unwrap());
    assert_eq!(read_choice(&p), Choice::Unset);
    assert!(
        p.move_note_file().exists(),
        "owed: no test is a person at a terminal"
    );
    assert!(same_keys(&store(&p).load().unwrap().unwrap(), &full()));

    // Passed, and this process's session cannot open the key: the step records a failure
    // and nothing moves — now or later.
    let p = paths(&tmp.path().join("session"));
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    passed_trial(&p, "mac");
    assert!(same_keys(
        &live(&p, Some(FakeFail::Open)).load().unwrap().unwrap(),
        &full()
    ));
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert_eq!(trial::load_or_new(&p).failure_count, 1);
    assert_eq!(automatic_move(&default_store(&p)), AutoMove::NotDue);

    // Passed, and the call into the enclave does not come back: the load answers after the
    // bounded wait, with a failure on record and nothing moved.
    let p = paths(&tmp.path().join("hang"));
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    passed_trial(&p, "mac");
    let before = Instant::now();
    assert!(same_keys(
        &live(&p, Some(FakeFail::Hang)).load().unwrap().unwrap(),
        &full()
    ));
    let waited = before.elapsed();
    assert!(
        waited >= trial::STEP_WAIT && waited < trial::STEP_WAIT * 3,
        "{waited:?}"
    );
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert!(trial::load_or_new(&p).failures[0].timed_out);

    // A keyless plain file (a login that has not got to the passphrase): the trial goes on,
    // nothing is moved.
    let p = paths(&tmp.path().join("keyless"));
    attach(&p, VAULT);
    plain(&p).save(&login()).unwrap();
    passed_trial(&p, "mac");
    live(&p, None).load().unwrap().unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());

    // The default switched off (the stores of other modules' unit tests): the trial runs,
    // nothing moves.
    let p = paths(&tmp.path().join("off"));
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    passed_trial(&p, "mac");
    LayeredStore::with_sealer(&p, Ok(Arc::new(FakeSealer::new("mac", None))), true)
        .load()
        .unwrap()
        .unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
}

/// The end of a login: what ended in the plain file although the sealed store is the
/// default is moved at once, to a key that opened a value in this process.
#[test]
fn the_end_of_a_login_moves_what_ended_in_the_plain_file() {
    let tmp = tempfile::tempdir().unwrap();

    // A sealed file of another Mac (the files came by a migration): the login's saves go to
    // the plain file and remove it; the end of the login seals again, here.
    let p = paths(&tmp.path().join("dead"));
    attach(&p, VAULT);
    seal_on(&p, "another-mac", &full());
    let dead_public = sealed_public(&p);
    let s = default_store(&p);
    s.save(&login()).unwrap();
    assert!(
        p.secrets_file().exists(),
        "a keyless login never takes the place of sealed keys"
    );
    s.save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    let document = bytes(&p.secrets_file());
    assert_eq!(seal_after_login(&s, false), AfterLogin::Moved);
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
    assert_ne!(sealed_public(&p), dead_public, "a key of this Mac");
    assert_eq!(read_choice(&p), Choice::Unset);
    assert!(
        !p.move_note_file().exists(),
        "the login says it itself: nothing is owed"
    );
    let opened = s
        .open_sealed(&s.read_sealed().unwrap().unwrap())
        .ok()
        .unwrap();
    assert_eq!(opened.document.as_slice(), document);
    assert_eq!(seal_after_login(&s, false), AfterLogin::Sealed);

    // No key can be made in this session: the plain file stays, the reason is on record.
    let p = paths(&tmp.path().join("create"));
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    let s = default_store_on(&p, "mac", Some(FakeFail::Create));
    assert!(matches!(
        seal_after_login(&s, false),
        AfterLogin::Plain(Some(_))
    ));
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert!(trial::load_or_new(&p).unavailable.is_some());

    // Not signed in, a keyless login, the plain file by choice, no sealer: nothing.
    let p = paths(&tmp.path().join("none"));
    attach(&p, VAULT);
    let s = default_store(&p);
    assert_eq!(seal_after_login(&s, false), AfterLogin::Plain(None));
    plain(&p).save(&login()).unwrap();
    assert_eq!(seal_after_login(&s, false), AfterLogin::Plain(None));
    plain(&p).save(&full()).unwrap();
    write_choice(&p, STORE_FILE, "t").unwrap();
    assert_eq!(seal_after_login(&s, false), AfterLogin::Plain(None));
    std::fs::remove_file(p.keystore_file()).unwrap();
    assert_eq!(
        seal_after_login(
            &no_sealer(&p, NoSealer::DebugBuild).sealed_by_default(true),
            false
        ),
        AfterLogin::Plain(None)
    );
    assert_eq!(seal_after_login(&store(&p), false), AfterLogin::Plain(None));
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
}

/// Many processes find the trial passed at the same moment: one moves, the others find the
/// lock taken or the move done, and readers never see a signed-out device.
#[test]
fn automatic_moves_at_once_move_once_and_readers_always_find_the_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    for round in 0..12 {
        let p = paths(&tmp.path().join(round.to_string()));
        attach(&p, VAULT);
        plain(&p).save(&full()).unwrap();
        let document = bytes(&p.secrets_file());
        passed_trial(&p, "mac");
        let stop = AtomicBool::new(false);
        let moved = AtomicU64::new(0);
        let reads = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    let s = store(&p);
                    while !stop.load(Ordering::Relaxed) {
                        match s.resolve() {
                            Ok(Some(loaded)) => assert!(same_keys(&loaded.secrets, &full())),
                            Ok(None) => panic!("a reader found the device signed out"),
                            Err(e) => panic!("a reader failed: {e}"),
                        }
                        assert!(p.secrets_present(), "the watchers' look");
                        reads.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
            let movers: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| match automatic_move(&default_store(&p)) {
                        AutoMove::Moved => {
                            moved.fetch_add(1, Ordering::Relaxed);
                        }
                        AutoMove::Busy | AutoMove::NotDue => {}
                        AutoMove::Kept(why) => panic!("{why}"),
                    })
                })
                .collect();
            for mover in movers {
                mover.join().unwrap();
            }
            stop.store(true, Ordering::Relaxed);
        });
        assert_eq!(moved.load(Ordering::Relaxed), 1, "round {round}");
        assert!(reads.load(Ordering::Relaxed) > 0);
        assert!(p.sealed_file().exists() && !p.secrets_file().exists());
        let s = store(&p);
        let opened = s
            .open_sealed(&s.read_sealed().unwrap().unwrap())
            .ok()
            .unwrap();
        assert_eq!(opened.document.as_slice(), document);
        assert!(files(&p).iter().all(|name| !name.contains(".tmp-")));
    }
}

/// A login (two saves) and the automatic move at once: one store at the end, readable, with
/// one of the logins whole — the move takes the file it looked at or sees that it changed.
#[test]
fn a_login_and_the_automatic_move_at_once_leave_one_consistent_state() {
    let tmp = tempfile::tempdir().unwrap();
    for round in 0..20 {
        let p = paths(&tmp.path().join(round.to_string()));
        attach(&p, VAULT);
        plain(&p).save(&full()).unwrap();
        passed_trial(&p, "mac");
        let mut renewed = full();
        renewed.refresh_token = Some("1//renewed".into());
        std::thread::scope(|scope| {
            scope.spawn(|| default_store(&p).save(&renewed).unwrap());
            scope.spawn(|| {
                let _ = automatic_move(&default_store(&p));
            });
            scope.spawn(|| {
                let _ = automatic_move(&default_store(&p));
            });
        });
        let s = default_store(&p);
        let loaded = s.resolve().unwrap().expect("signed in");
        assert!(same_keys(&loaded.secrets, &full()));
        let token = loaded.secrets.refresh_token.clone().unwrap();
        assert!([TOKEN_TEXT, "1//renewed"].contains(&token.as_str()));
        let (plain_there, sealed_there) = (p.secrets_file().exists(), p.sealed_file().exists());
        assert!(
            plain_there != sealed_there,
            "round {round}: plain {plain_there}, sealed {sealed_there}"
        );
        if plain_there {
            // The save came first and the moves found the lock taken or the file changed:
            // the next run moves.
            assert_eq!(token, "1//renewed");
            assert_eq!(automatic_move(&s), AutoMove::Moved);
        }
        assert!(files(&p).iter().all(|name| !name.contains(".tmp-")));
    }
}

// ---------------------------------------------------------------------------------------------
// concurrency
// ---------------------------------------------------------------------------------------------

/// Readers never find "not signed in" and never get an error while a writer moves the
/// secrets back and forth: the new file exists before the old one is removed, and a reader
/// that found neither looks again (§8.3).
#[test]
fn readers_always_find_the_secrets_while_they_are_moved_back_and_forth() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    store(&p).save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    let (blob, public) = new_key("mac");
    let stop = AtomicBool::new(false);
    let (reads, moves) = (AtomicU64::new(0), AtomicU64::new(0));
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                let s = store(&p);
                while !stop.load(Ordering::Relaxed) {
                    let loaded = match s.resolve() {
                        Ok(Some(loaded)) => loaded,
                        Ok(None) => panic!("a reader found the device signed out"),
                        Err(e) => panic!("a reader failed: {e}"),
                    };
                    assert!(same_keys(&loaded.secrets, &full()));
                    assert!(p.secrets_present(), "the watchers' look");
                    reads.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
        let s = store(&p);
        let until = Instant::now() + Duration::from_millis(1500);
        while Instant::now() < until {
            move_to_enclave(&s, &document, &blob, &public, MoveBy::Command).unwrap();
            assert_eq!(move_to_file(&s, false).unwrap(), ToFile::Moved);
            moves.fetch_add(1, Ordering::Relaxed);
        }
        stop.store(true, Ordering::Relaxed);
    });
    assert!(moves.load(Ordering::Relaxed) >= 5, "{moves:?} move pairs");
    assert!(reads.load(Ordering::Relaxed) >= 100, "{reads:?} reads");
    assert_eq!(bytes(&p.secrets_file()), document);
}

/// Two saves of a login and a move at once end in one consistent state: one store, readable,
/// holding one of the two logins whole.
#[test]
fn two_saves_and_a_move_at_once_leave_one_consistent_state() {
    let tmp = tempfile::tempdir().unwrap();
    for round in 0..20 {
        let p = paths(&tmp.path().join(round.to_string()));
        attach(&p, VAULT);
        store(&p).save(&full()).unwrap();
        let document = bytes(&p.secrets_file());
        let (blob, public) = new_key("mac");
        let mut a = full();
        a.refresh_token = Some("1//login-a".into());
        let mut b = full();
        b.refresh_token = Some("1//login-b".into());
        std::thread::scope(|scope| {
            scope.spawn(|| store(&p).save(&a).unwrap());
            scope.spawn(|| store(&p).save(&b).unwrap());
            scope.spawn(|| {
                // Either it moves the file it looked at, or it sees that the file changed.
                match move_to_enclave(&store(&p), &document, &blob, &public, MoveBy::Command) {
                    Ok(()) | Err(MoveError::Changed) => {}
                    Err(e) => panic!("{e:?}"),
                }
            });
        });
        let s = store(&p);
        let loaded = s.resolve().unwrap().expect("signed in");
        assert!(same_keys(&loaded.secrets, &full()));
        let token = loaded.secrets.refresh_token.clone().unwrap();
        assert!(
            [TOKEN_TEXT, "1//login-a", "1//login-b"].contains(&token.as_str()),
            "{token}"
        );
        let (plain_there, sealed_there) = (p.secrets_file().exists(), p.sealed_file().exists());
        assert!(plain_there || sealed_there);
        if plain_there && sealed_there {
            // Only possible when a save came after the move: the plain file holds the keys,
            // and the sealed copy holds the same ones.
            assert_eq!(loaded.source, Source::Plain);
            let opened = s
                .open_sealed(&s.read_sealed().unwrap().unwrap())
                .ok()
                .unwrap();
            assert!(same_keys(&opened.secrets, &full()));
        }
        assert!(
            files(&p).iter().all(|name| !name.contains(".tmp-")),
            "{:?}",
            files(&p)
        );
    }
}

// ---------------------------------------------------------------------------------------------
// what the review of 0.5.1 found (§17.30)
// ---------------------------------------------------------------------------------------------

/// A `gclone logout` and a `gclone login` in the middle of a trial do not jump its bar: the
/// device was working from `secrets.json` a moment ago, with whatever runs unattended on it,
/// and the trial has not seen a restart or all of that yet. The login goes to the plain file
/// and the trial goes on — as for a login without the logout.
#[test]
fn a_login_in_the_middle_of_a_trial_stays_on_the_plain_file() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    let s = default_store(&p);
    plain(&p).save(&full()).unwrap();
    trial::step(&p, &FakeSealer::new("mac", None));
    let running = bytes(&p.trial_file());
    assert!(trial_undecided(&p));
    // logout, login (a Drive login: two saves)
    s.delete().unwrap();
    assert!(trial_undecided(&p), "the record stays over a logout");
    s.save(&login()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    s.save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    // the end of that login: the trial was running when it began
    assert!(matches!(
        seal_after_login(&s, true),
        AfterLogin::Plain(Some(why)) if why.contains("has not passed yet")
    ));
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert_eq!(
        bytes(&p.trial_file()),
        running,
        "the trial goes on untouched"
    );
    let r = report_with(&p, &s);
    assert!(
        r.line().contains("Secure Enclave trial: 1 of 3 days"),
        "{}",
        r.line()
    );
    assert!(r.warnings().is_empty(), "{:?}", r.warnings());

    // Three calendar days and a restart within less than 48 hours are "not passed" too.
    let mut record = trial::load_or_new(&p);
    for day in 1..3 {
        record.ok.push(trial::OkEntry {
            day: record.ok[0].day + day,
            boot: "another-boot".into(),
            session: "0x2".into(),
        });
    }
    record.last_ok_ms = record.created_ms.map(|ms| ms + trial::MIN_AGE_MS - 1);
    trial::save(&p, &record).unwrap();
    assert!(trial_undecided(&p));
    s.delete().unwrap();
    s.save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());

    // Passed: not undecided any more, and a login lends the trial's key.
    record.last_ok_ms = record.created_ms.map(|ms| ms + trial::MIN_AGE_MS);
    trial::save(&p, &record).unwrap();
    assert!(!trial_undecided(&p));
    s.delete().unwrap();
    s.save_proven(&full()).unwrap();
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
    assert_eq!(sealed_public(&p), record.public.clone().unwrap());

    // A record beside a sealed store is no trial that could decide anything: a login on a
    // device whose sealed key died is not held back by one.
    let p = paths(&tmp.path().join("stale"));
    attach(&p, VAULT);
    seal_on(&p, "another-mac", &full());
    trial::step(&p, &FakeSealer::new("another-mac", None));
    assert!(!trial_undecided(&p), "sealed alone");
    std::fs::remove_file(p.sealed_file()).unwrap();
    assert!(trial_undecided(&p), "signed out, a trial on record");

    // A trial that this login's own loads started (none was running when it began) does
    // not hold the end of the login back: its key takes the secrets.
    let p = paths(&tmp.path().join("own"));
    attach(&p, VAULT);
    let s = default_store(&p);
    plain(&p).save(&full()).unwrap();
    trial::step(&p, &FakeSealer::new("mac", None));
    let trial_public = trial::load_or_new(&p).public.clone().unwrap();
    assert_eq!(seal_after_login(&s, false), AfterLogin::Moved);
    assert_eq!(sealed_public(&p), trial_public);
    assert!(report_with(&p, &s).warnings().is_empty());

    // The owner's choice `enclave` seals whatever the trial is at.
    let p = paths(&tmp.path().join("chosen"));
    attach(&p, VAULT);
    let s = default_store(&p);
    trial::step(&p, &FakeSealer::new("mac", None));
    write_choice(&p, STORE_ENCLAVE, "t").unwrap();
    s.save_proven(&full()).unwrap();
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
}

/// A device that was moved by itself, and then: (1) `logout` and `login`; (2) the sealed key
/// dies (the files on another Mac) and a login reconnects the device; (3) `keystore use
/// file` and `keystore use enclave`. Each seals to a key made then — and none leaves the
/// record of the trial that ended at the first move behind as "evidence for another key":
/// `status` and `keystore` warned about that for good.
#[test]
fn a_later_login_or_move_leaves_no_warning_about_the_ended_trial() {
    let tmp = tempfile::tempdir().unwrap();
    let moved_device = |name: &str| {
        let p = paths(&tmp.path().join(name));
        attach(&p, VAULT);
        plain(&p).save(&full()).unwrap();
        let record = passed_trial(&p, "mac");
        let s = default_store(&p);
        assert_eq!(automatic_move(&s), AutoMove::Moved);
        let r = report_with(&p, &s);
        assert_eq!(r.trial_key_holds_secrets, Some(true));
        assert!(r.warnings().is_empty(), "{:?}", r.warnings());
        (p, record.public.clone().unwrap())
    };
    let clean = |p: &Paths, s: &LayeredStore, old_key: &str, what: &str| {
        assert!(
            p.sealed_file().exists() && !p.secrets_file().exists(),
            "{what}"
        );
        assert_ne!(sealed_public(p), old_key, "{what}: a key made now");
        let r = report_with(p, s);
        assert_eq!(r.store, Where::Sealed, "{what}");
        assert!(r.trial.is_none(), "{what}: {:?}", r.trial);
        assert_eq!(r.trial_key_holds_secrets, None, "{what}");
        assert!(r.warnings().is_empty(), "{what}: {:?}", r.warnings());
        assert_eq!(r.json(p)["key_store"]["trial"], serde_json::Value::Null);
        assert!(trial::load_or_new(p).is_blank(), "{what}");
    };

    // (1) logout, login
    let (p, old_key) = moved_device("relogin");
    let s = default_store(&p);
    s.delete().unwrap();
    assert!(!p.move_note_file().exists());
    s.save(&login()).unwrap();
    s.save_proven(&full()).unwrap();
    assert_eq!(seal_after_login(&s, false), AfterLogin::Sealed);
    clean(&p, &s, &old_key, "logout and login");

    // (2) the files on another Mac: the login's saves go to the plain file, its end seals
    let (p, old_key) = moved_device("migrated");
    let s = default_store_on(&p, "mac-2", None);
    unavailable(s.resolve());
    s.save(&login()).unwrap();
    s.save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert_eq!(seal_after_login(&s, false), AfterLogin::Moved);
    assert!(
        !p.move_note_file().exists(),
        "the note of the first move is not owed about this store"
    );
    clean(&p, &s, &old_key, "a login on another Mac");

    // (3) back to the file, and into the enclave again by the command
    let (p, old_key) = moved_device("back-and-forth");
    let s = default_store(&p);
    assert_eq!(move_to_file(&s, false).unwrap(), ToFile::Moved);
    let document = bytes(&p.secrets_file());
    let key = pick_key(&p, &FakeSealer::new("mac", None)).unwrap();
    assert!(!key.from_trial, "an ended trial has no key to lend");
    move_to_enclave(&s, &document, &key.blob, &key.public, MoveBy::Command).unwrap();
    clean(&p, &s, &old_key, "use file, use enclave");

    // A trial that is RUNNING and has evidence, ended by a sealing to another key, keeps
    // its warning: that is the one case it was made for.
    let p = paths(&tmp.path().join("running"));
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    passed_trial(&p, "mac");
    let s = default_store(&p);
    let document = bytes(&p.secrets_file());
    let (blob, public) = new_key("mac");
    move_to_enclave(&s, &document, &blob, &public, MoveBy::Command).unwrap();
    let r = report_with(&p, &s);
    assert!(r.trial_evidence_is_for_another_key());
    assert_eq!(r.warnings().len(), 1, "{:?}", r.warnings());
}

/// The secrets.json of an older gclone's login beside the store of an earlier sealing: gclone
/// 0.4.0 says "not connected" on a sealed device, its owner signs in with it, and it writes
/// a keyed `secrets.json`. Testing and moving again removed that file three days later, and
/// the older gclone was broken a second time — and so on. Nothing is tested and nothing is
/// moved while the two lie side by side; the owner's command settles it.
#[test]
fn an_older_logins_plain_file_beside_the_sealed_store_is_never_moved_again() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    passed_trial(&p, "mac");
    let live = || {
        LayeredStore::with_sealer(&p, Ok(Arc::new(FakeSealer::new("mac", None))), true)
            .sealed_by_default(true)
    };
    assert_eq!(automatic_move(&default_store(&p)), AutoMove::Moved);
    let sealed = bytes(&p.sealed_file());
    let ended = bytes(&p.trial_file());
    // gclone 0.4.0: "not connected" → its login writes secrets.json
    std::fs::write(p.secrets_file(), &document).unwrap();
    std::fs::set_permissions(p.secrets_file(), std::fs::Permissions::from_mode(0o600)).unwrap();
    let s = default_store(&p);
    assert!(s.sealed_beside_is_foreign());
    assert_eq!(source(&s), Some(Source::Plain));

    // Loads — with everything a load does besides answering — start no trial …
    for _ in 0..3 {
        assert!(same_keys(&live().load().unwrap().unwrap(), &full()));
    }
    assert_eq!(bytes(&p.trial_file()), ended, "no new trial");
    assert_eq!(bytes(&p.secrets_file()), document);
    assert_eq!(bytes(&p.sealed_file()), sealed);
    // … and even with a trial that has passed beside them (one that an earlier 0.5.1 began,
    // say) nothing moves: the sealed file is not that trial's unfinished work.
    std::fs::remove_file(p.trial_file()).unwrap();
    passed_trial(&p, "mac");
    assert!(s.sealed_beside_is_foreign());
    match automatic_move(&s) {
        AutoMove::Kept(why) => assert!(why.contains("sealed to another key"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(same_keys(&live().load().unwrap().unwrap(), &full()));
    assert_eq!(bytes(&p.secrets_file()), document);
    assert_eq!(bytes(&p.sealed_file()), sealed);
    assert!(!p.move_note_file().exists() || bytes(&p.move_note_file()).is_empty());
    let r = report_with(&p, &s);
    assert!(r.blocked_by_sealed && r.sealed_differs.is_none());
    assert!(
        r.line().contains("kept: nothing is tested or moved"),
        "{}",
        r.line()
    );
    assert!(
        r.warnings().iter().any(|w| w.contains("update it first")),
        "{:?}",
        r.warnings()
    );

    // `keystore use file` keeps the plain file for good; `keystore use enclave` seals again.
    assert_eq!(move_to_file(&s, false).unwrap(), ToFile::SealedCopyRemoved);
    assert_eq!(bytes(&p.secrets_file()), document);
    assert!(!s.sealed_beside_is_foreign());
}

/// The note about the move is part of the move: where it can be neither shown nor recorded
/// as owed, nothing moves — the owner would never be told that the device depends on this
/// Mac's enclave and on the passphrase from now on.
#[test]
fn the_automatic_move_does_not_happen_without_its_note() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    passed_trial(&p, "mac");
    let record = bytes(&p.trial_file());
    let s = default_store(&p);
    // Something that is not a file a later run could take away lies where the marker goes.
    std::fs::create_dir(p.move_note_file()).unwrap();
    match automatic_move(&s) {
        AutoMove::Kept(why) => assert!(why.contains("cannot be recorded"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(bytes(&p.secrets_file()), document);
    assert!(
        !p.sealed_file().exists(),
        "the sealed file of this run is taken away again"
    );
    assert_eq!(bytes(&p.trial_file()), record, "the trial is not ended");
    assert!(files(&p).iter().all(|name| !name.contains(".tmp-")));
    // The same for a move that an earlier run left unfinished.
    let passed = trial::load_or_new(&p);
    let (blob, public) = passed.key_for_secrets().unwrap();
    let envelope = s
        .envelope_for(
            &FakeSealer::new("mac", None),
            &blob,
            &public,
            &document,
            true,
        )
        .unwrap();
    s.write_sealed(&envelope, "t").unwrap();
    assert!(matches!(automatic_move(&s), AutoMove::Kept(_)));
    assert_eq!(bytes(&p.secrets_file()), document);
    // A later run, when the marker can be made, moves.
    std::fs::remove_dir(p.move_note_file()).unwrap();
    assert_eq!(automatic_move(&s), AutoMove::Moved);
    assert!(p.move_note_file().is_file() && !p.secrets_file().exists());
    // An owed marker that is there already (the run before was killed) is as good.
    assert_eq!(move_to_file(&s, false).unwrap(), ToFile::Moved);
    std::fs::remove_file(p.keystore_file()).unwrap();
    std::fs::remove_file(p.trial_file()).unwrap();
    passed_trial(&p, "mac");
    std::fs::write(p.move_note_file(), b"").unwrap();
    assert_eq!(automatic_move(&s), AutoMove::Moved);
    assert!(p.move_note_file().is_file());
}

/// The marker of an owed note about a move goes with the store it is about: a login that
/// begins a new store, the end of a login, and the owner's command each say themselves what
/// they did. (gclone 0.5.0 and older do not know the marker: their `logout` leaves it, and
/// the next terminal run after a new login then said "gclone tested it over several days and
/// a restart first" about a store that the login had just begun.)
#[test]
fn an_owed_move_note_does_not_outlive_the_store_it_is_about() {
    let tmp = tempfile::tempdir().unwrap();
    let owed = |p: &Paths| {
        std::fs::write(p.move_note_file(), b"").unwrap();
    };

    // A login on a signed-out device — sealed from the start,
    let p = paths(&tmp.path().join("sealed"));
    attach(&p, VAULT);
    owed(&p);
    default_store(&p).save_proven(&full()).unwrap();
    assert!(p.sealed_file().exists() && !p.move_note_file().exists());
    // or to the plain file.
    let p = paths(&tmp.path().join("plain"));
    attach(&p, VAULT);
    owed(&p);
    store(&p).save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.move_note_file().exists());
    // A save on a device that IS signed in leaves a note that is owed alone.
    let p = paths(&tmp.path().join("kept"));
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    passed_trial(&p, "mac");
    let s = default_store(&p);
    assert_eq!(automatic_move(&s), AutoMove::Moved);
    assert!(p.move_note_file().exists());
    let mut renewed = full();
    renewed.refresh_token = Some("1//renewed".into());
    s.save(&renewed).unwrap();
    assert!(
        p.move_note_file().exists(),
        "still owed: the store is the same"
    );

    // The owner's command and the end of a login.
    for by in [MoveBy::Command, MoveBy::Login] {
        let p = paths(&tmp.path().join(format!("{by:?}")));
        attach(&p, VAULT);
        plain(&p).save(&full()).unwrap();
        owed(&p);
        let (blob, public) = new_key("mac");
        let document = bytes(&p.secrets_file());
        move_to_enclave(&default_store(&p), &document, &blob, &public, by).unwrap();
        assert!(
            p.sealed_file().exists() && !p.move_note_file().exists(),
            "{by:?}"
        );
    }
}

/// The opt-outs are looked at again under the lock, by the move itself: `gclone keystore use
/// file` writes its choice under that lock, and a move that had looked before would
/// otherwise undo it a moment later.
#[test]
fn a_move_nobody_asked_for_looks_at_the_opt_outs_under_the_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    let record = passed_trial(&p, "mac");
    let (blob, public) = record.key_for_secrets().unwrap();
    let s = default_store(&p);
    let refused = |by: MoveBy, what: &str| {
        match move_to_enclave(&s, &document, &blob, &public, by) {
            Err(MoveError::Refused(why)) => assert!(why.contains("not wanted"), "{what}: {why}"),
            other => panic!("{what}, {by:?}: {other:?}"),
        }
        assert_eq!(bytes(&p.secrets_file()), document, "{what}");
        assert!(
            !p.sealed_file().exists() && !p.move_note_file().exists(),
            "{what}"
        );
    };
    // The caller looked, found no choice — and `use file` came in between.
    write_choice(&p, STORE_FILE, "t").unwrap();
    refused(MoveBy::Trial, "the choice `file`");
    refused(MoveBy::Login, "the choice `file`");
    std::fs::remove_file(p.keystore_file()).unwrap();
    // A run with GCLONE_KEYSTORE_TRIAL=0 left its marker in between.
    mark_trial_off(&p);
    refused(MoveBy::Trial, "the marker of GCLONE_KEYSTORE_TRIAL=0");
    refused(MoveBy::Login, "the marker of GCLONE_KEYSTORE_TRIAL=0");
    // The owner's command is not asked whether it is wanted — and takes the marker away.
    move_to_enclave(&s, &document, &blob, &public, MoveBy::Command).unwrap();
    assert!(p.sealed_file().exists() && !p.secrets_file().exists());
    assert!(!trial_off_marked(&p));
    assert_eq!(read_choice(&p), Choice::Enclave);
}

/// `GCLONE_KEYSTORE_TRIAL=0`, for the whole device: the marker that a run with the variable
/// leaves stops the trial, the move and the sealing login in every run, and `status` says
/// so. (That a run with the variable leaves it is shown through the binary, `tests/keystore.rs`.)
#[test]
fn the_marker_of_a_run_without_the_trial_keeps_the_plain_file_for_every_run() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    plain(&p).save(&full()).unwrap();
    let document = bytes(&p.secrets_file());
    passed_trial(&p, "mac");
    let record = bytes(&p.trial_file());
    assert!(!trial_off_marked(&p));
    mark_trial_off(&p);
    mark_trial_off(&p);
    assert!(trial_off_marked(&p));
    assert_eq!(mode(&p.trial_off_file()), 0o600);
    assert!(bytes(&p.trial_off_file()).is_empty());

    let live = LayeredStore::with_sealer(&p, Ok(Arc::new(FakeSealer::new("mac", None))), true)
        .sealed_by_default(true);
    assert!(same_keys(&live.load().unwrap().unwrap(), &full()));
    assert_eq!(automatic_move(&default_store(&p)), AutoMove::NotDue);
    assert_eq!(bytes(&p.secrets_file()), document);
    assert!(!p.sealed_file().exists());
    assert_eq!(
        bytes(&p.trial_file()),
        record,
        "no step of the trial either"
    );
    let r = report_with(&p, &default_store(&p));
    assert!(r.trial_off_marked);
    assert_eq!(
        r.line(),
        "plain file secrets.json (0600) — kept: a run with GCLONE_KEYSTORE_TRIAL=0 uses this \
         device (no Secure Enclave trial, nothing is moved; `gclone keystore use enclave` moves \
         the secrets)"
    );
    assert_eq!(r.json(&p)["key_store"]["trial_off_marker"], true);

    // A login after a logout stays plain as well; the marker is not a secret and stays.
    let s = default_store(&p);
    s.delete().unwrap();
    assert!(trial_off_marked(&p));
    std::fs::remove_file(p.trial_file()).unwrap();
    s.save_proven(&full()).unwrap();
    assert!(p.secrets_file().exists() && !p.sealed_file().exists());
    assert_eq!(seal_after_login(&s, false), AfterLogin::Plain(None));
    assert!(
        !p.trial_file().exists(),
        "a fallback that is wanted is not recorded as a failure"
    );

    // The owner's choice `enclave` is not held back by it; `keystore use enclave` on a
    // sealed device and `--new-trial` take it away.
    clear_trial_off(&p);
    assert!(!trial_off_marked(&p));
    clear_trial_off(&p);
    mark_trial_off(&p);
    let document = bytes(&p.secrets_file());
    let (blob, public) = new_key("mac");
    move_to_enclave(&s, &document, &blob, &public, MoveBy::Command).unwrap();
    assert!(!trial_off_marked(&p));
    mark_trial_off(&p);
    assert!(settle_sealed(&s).unwrap());
    assert!(!trial_off_marked(&p));
}

/// A sealed device in a session where the call into the Secure Enclave does not return: the
/// load answers after the bounded wait with the text for "this session cannot use the
/// enclave" — it never names `gclone login` — and `gclone keystore use file` gives the lock
/// back. (Every sealer of the binary is bounded: `sealer()`.)
#[test]
fn a_sealed_store_whose_enclave_does_not_answer_is_an_error_not_a_standstill() {
    let tmp = tempfile::tempdir().unwrap();
    let p = paths(tmp.path());
    attach(&p, VAULT);
    seal_on(&p, "mac", &full());
    let sealed = bytes(&p.sealed_file());
    let hangs = || -> SealerChoice {
        Ok(Arc::new(seal::Bounded::new(
            Arc::new(FakeSealer::new("mac", Some(FakeFail::Hang))),
            Duration::from_millis(200),
        )))
    };
    let s = LayeredStore::with_sealer(&p, hangs(), false).sealed_by_default(true);
    let before = Instant::now();
    let text = unavailable(s.resolve());
    let waited = before.elapsed();
    assert!(
        waited >= Duration::from_millis(200) && waited < Duration::from_secs(5),
        "{waited:?}"
    );
    assert!(
        text.starts_with("The Secure Enclave cannot be used in this session (the Secure Enclave did not answer within 200 ms)"),
        "{text}"
    );
    assert!(
        text.contains("Do not sign in again") && !text.contains("Run `gclone login`"),
        "{text}"
    );
    assert!(
        text.contains("`gclone keystore use file` — from a session where it works"),
        "{text}"
    );

    // `status` and `keystore` report instead of standing still,
    let s = LayeredStore::with_sealer(&p, hangs(), false);
    let before = Instant::now();
    let r = report_with(&p, &s);
    assert!(before.elapsed() < Duration::from_secs(5));
    assert_eq!(r.line(), "secrets.sealed — cannot be opened here");
    assert!(matches!(&r.store, Where::SealedUnusable(text) if text.contains("did not answer")));
    // and a command that holds the secrets lock gives it back: `keystore use file`, a save.
    let s = LayeredStore::with_sealer(&p, hangs(), false);
    let before = Instant::now();
    assert!(
        matches!(move_to_file(&s, false), Err(MoveError::Refused(text)) if text.contains("did not answer"))
    );
    let s = LayeredStore::with_sealer(&p, hangs(), false);
    s.save(&login()).unwrap();
    assert!(before.elapsed() < Duration::from_secs(5));
    drop(lock_exclusive(&p, Duration::ZERO).expect("the lock is free again"));
    assert_eq!(
        bytes(&p.sealed_file()),
        sealed,
        "the sealed file is not touched"
    );
    // From a session that works, the device is as it was (the keyless login beside the
    // sealed keys is the merged view).
    assert!(same_keys(&store(&p).load().unwrap().unwrap(), &full()));
}

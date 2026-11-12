//! Paths, `config.json`, `secrets.json` (SPEC §8.1, §8.2, §9.10) — owned by WP7.

use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::auth::{AuthClient, AuthEndpoints};
use crate::backend::Handle;
use crate::crypto::{Keyring, MasterKey};
use crate::error::ConfigError;
use crate::index::VaultHandles;
use crate::util;

const FILE_VERSION: u32 = 1;
/// Neither file comes near this; anything bigger is not ours.
const FILE_MAX: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub state_root: PathBuf,
}

impl Paths {
    /// `GCLONE_CONFIG_DIR` / `GCLONE_STATE_DIR`, else `~/.config/gclone` and
    /// `~/.local/state/gclone` (XDG on macOS and Linux alike, §8.1).
    pub fn resolve() -> Result<Paths, ConfigError> {
        use etcetera::BaseStrategy as _;
        let from_env = |name: &str| -> Result<Option<PathBuf>, ConfigError> {
            match std::env::var_os(name).filter(|v| !v.is_empty()) {
                Some(dir) => Ok(Some(std::path::absolute(PathBuf::from(dir))?)),
                None => Ok(None),
            }
        };
        let base = || {
            etcetera::choose_base_strategy().map_err(|e| {
                ConfigError::Io(std::io::Error::other(format!(
                    "cannot find the home directory ({e}); set GCLONE_CONFIG_DIR and GCLONE_STATE_DIR"
                )))
            })
        };
        let config_dir = match from_env("GCLONE_CONFIG_DIR")? {
            Some(dir) => dir,
            None => base()?.config_dir().join("gclone"),
        };
        let state_root = match from_env("GCLONE_STATE_DIR")? {
            Some(dir) => dir,
            None => {
                let base = base()?;
                base.state_dir()
                    .unwrap_or_else(|| base.home_dir().join(".local").join("state"))
                    .join("gclone")
            }
        };
        Ok(Paths {
            config_dir,
            state_root,
        })
    }

    /// `<config>/config.json`
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.json")
    }

    /// `<state root>/secrets.json` (§8.1: NOT under `<config>`).
    pub fn secrets_file(&self) -> PathBuf {
        self.state_root.join("secrets.json")
    }

    /// `<state root>/token.json` — per login, not per vault.
    pub fn token_file(&self) -> PathBuf {
        self.state_root.join("token.json")
    }

    pub fn state_dir(&self, vault_id_hex: &str) -> PathBuf {
        self.state_root.join(vault_id_hex)
    }

    pub fn db_file(&self, v: &str) -> PathBuf {
        self.state_dir(v).join("state.db")
    }

    pub fn index_cache_dir(&self, v: &str) -> PathBuf {
        self.state_dir(v).join("index-cache")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum BackendCfg {
    Drive,
    Dir { path: PathBuf },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    pub version: u32,
    pub vault_id: String,
    pub vault_name: String,
    pub backend: BackendCfg,
    /// Drive vaults: the Worker URL (not a secret; survives `logout`, §2.2). `None` for
    /// directory vaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    pub root_id: String,
    pub index_id: String,
    pub data_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyEntry {
    pub epoch: u32,
    pub key: String,
}

/// The four login fields are `None` for directory vaults (never empty strings).
/// `Debug` is NOT derived; no OAuth client id/secret exists on a device.
#[derive(Serialize, Deserialize, Clone)]
pub struct Secrets {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_ms: Option<u64>,
    /// §2.4 expiring-grant check.
    #[serde(default)]
    pub refresh_expires_at_ms: Option<u64>,
    /// Which OAuth client of the Worker issued `refresh_token` (sent with every `/refresh`).
    /// `"device"` for every login since 0.2.0; a file without the field holds a login from
    /// before, made through the legacy client, and is written back without it.
    #[serde(default, skip_serializing_if = "AuthClient::is_legacy")]
    pub client: AuthClient,
    /// `[]` = signed in but not unlocked yet; then the cached master key.
    #[serde(default)]
    pub keys: Vec<KeyEntry>,
    #[serde(default)]
    pub min_epoch: u32,
}

impl Secrets {
    /// Secrets without a login and without keys: what a directory vault starts from.
    pub fn empty() -> Secrets {
        Secrets {
            version: FILE_VERSION,
            auth_url: None,
            refresh_token: None,
            email: None,
            consent_ms: None,
            refresh_expires_at_ms: None,
            client: AuthClient::Legacy,
            keys: Vec::new(),
            min_epoch: 0,
        }
    }

    /// `refresh_token` is `Some` and non-empty.
    pub fn has_login(&self) -> bool {
        self.refresh_token.as_deref().is_some_and(|t| !t.is_empty())
    }

    /// The ONLY place a stored `auth_url` is validated (never at load, §8.2): `auth_url` None →
    /// `NotLoggedIn`; else `AuthEndpoints::new`. Callers invoke it only when `has_login()`.
    pub fn endpoints(&self) -> Result<AuthEndpoints, ConfigError> {
        let url = self.auth_url.as_deref().ok_or(ConfigError::NotLoggedIn)?;
        Ok(AuthEndpoints::new(url)?)
    }

    /// keys empty → `Locked`; a `CryptoError` becomes `ConfigError::Crypto`.
    pub fn keyring(&self, vault_id: [u8; 16]) -> Result<Keyring, ConfigError> {
        if self.keys.is_empty() {
            return Err(ConfigError::Locked);
        }
        let bad_key = || ConfigError::Json("secrets.json holds a key that is not 32 bytes".into());
        let mut keys = Vec::with_capacity(self.keys.len());
        for entry in &self.keys {
            let raw = Zeroizing::new(util::unb64url(&entry.key).ok_or_else(bad_key)?);
            let key = Zeroizing::new(<[u8; 32]>::try_from(raw.as_slice()).map_err(|_| bad_key())?);
            keys.push((entry.epoch, MasterKey::from_bytes(*key)));
        }
        Ok(Keyring::new(vault_id, keys, self.min_epoch)?)
    }

    /// Caches `keys` (the unlocked master keys of the vault) in place of whatever was held.
    pub fn set_keys(&mut self, keys: &Keyring) {
        self.keys = keys
            .export()
            .iter()
            .map(|(epoch, key)| KeyEntry {
                epoch: *epoch,
                key: util::b64url(key.as_slice()),
            })
            .collect();
        self.min_epoch = keys.min_epoch();
    }
}

fn parse_json<T: serde::de::DeserializeOwned>(what: &str, bytes: &[u8]) -> Result<T, ConfigError> {
    #[derive(Deserialize)]
    struct Version {
        version: u32,
    }
    // serde_json's message never quotes the document: it names a position and what it expected.
    let bad = |e: serde_json::Error| ConfigError::Json(format!("{what}: {e}"));
    let version: Version = serde_json::from_slice(bytes).map_err(bad)?;
    if version.version != FILE_VERSION {
        return Err(ConfigError::Version(version.version));
    }
    serde_json::from_slice(bytes).map_err(bad)
}

fn to_json<T: Serialize>(what: &str, value: &T) -> Result<Zeroizing<Vec<u8>>, ConfigError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| ConfigError::Json(format!("cannot encode {what}: {e}")))?;
    bytes.push(b'\n');
    Ok(Zeroizing::new(bytes))
}

fn remove_if_present(path: &Path) -> Result<(), ConfigError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

impl Config {
    /// `NotConfigured` if absent.
    pub fn load(p: &Paths) -> Result<Config, ConfigError> {
        let bytes = match std::fs::read(p.config_file()) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ConfigError::NotConfigured);
            }
            Err(e) => return Err(e.into()),
        };
        let config: Config = parse_json("config.json", &bytes)?;
        config.vault_id_bytes()?;
        Ok(config)
    }

    pub fn save(&self, p: &Paths) -> Result<(), ConfigError> {
        util::create_dir_private(&p.config_dir)?;
        let bytes = to_json("config.json", self)?;
        Ok(util::write_atomic(&p.config_file(), &bytes, 0o600)?)
    }

    /// `logout --forget`; absent = Ok.
    pub fn delete(p: &Paths) -> Result<(), ConfigError> {
        remove_if_present(&p.config_file())
    }

    pub fn vault_id_bytes(&self) -> Result<[u8; 16], ConfigError> {
        util::unhex(&self.vault_id)
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .ok_or_else(|| ConfigError::Json("config.json: vault_id is not 32 hex digits".into()))
    }

    pub fn handles(&self) -> VaultHandles {
        VaultHandles {
            root: Handle(self.root_id.clone()),
            index: Handle(self.index_id.clone()),
            data: Handle(self.data_id.clone()),
        }
    }
}

pub trait SecretStore: Send + Sync {
    /// `None` = no secrets file (never logged in, or logged out).
    fn load(&self) -> Result<Option<Secrets>, ConfigError>;
    fn save(&self, s: &Secrets) -> Result<(), ConfigError>;
    /// logout; absent = Ok. Also removes what an interrupted `save` left behind (temp copies).
    fn delete(&self) -> Result<(), ConfigError>;
}

/// 0600 JSON via `util::write_atomic` in a 0700 directory (`util::create_dir_private`). `load`
/// is strict (§8.1): directory and file must pass `util::is_private`, the file is opened
/// `O_NOFOLLOW` — else `ConfigError::InsecurePermissions(path)`. It checks JSON and `version`,
/// and does NOT validate `auth_url` (§8.2).
pub struct FileSecretStore {
    pub path: PathBuf,
}

impl FileSecretStore {
    fn dir(&self) -> &Path {
        self.path.parent().unwrap_or(Path::new("."))
    }

    fn insecure(path: &Path) -> ConfigError {
        ConfigError::InsecurePermissions(path.display().to_string())
    }

    /// The directory itself (`lstat`: a symlink in its place is not accepted) must be private.
    fn check_dir(&self) -> Result<(), ConfigError> {
        let md = std::fs::symlink_metadata(self.dir())?;
        if md.is_dir() && util::is_private(&md) {
            Ok(())
        } else {
            Err(Self::insecure(self.dir()))
        }
    }
}

impl SecretStore for FileSecretStore {
    fn load(&self) -> Result<Option<Secrets>, ConfigError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path);
        let file = match file {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            // O_NOFOLLOW on a symlink: whatever it points to is not this device's secrets file.
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                return Err(Self::insecure(&self.path));
            }
            Err(e) => return Err(e.into()),
        };
        // Nothing is read before both checks passed, and nothing is repaired silently.
        self.check_dir()?;
        let md = file.metadata()?;
        if !md.is_file() || !util::is_private(&md) {
            return Err(Self::insecure(&self.path));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(FILE_MAX + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > FILE_MAX {
            return Err(ConfigError::Json("secrets.json is too large".into()));
        }
        Ok(Some(parse_json("secrets.json", &bytes)?))
    }

    fn save(&self, s: &Secrets) -> Result<(), ConfigError> {
        util::create_dir_private(self.dir())?;
        // An existing directory that others can read would make every later load fail.
        self.check_dir()?;
        let bytes = to_json("secrets.json", s)?;
        Ok(util::write_atomic(&self.path, &bytes, 0o600)?)
    }

    fn delete(&self) -> Result<(), ConfigError> {
        remove_if_present(&self.path)?;
        // A save that was killed before its rename left a full copy — refresh token and cached
        // key — in a temp file beside it: "deleted" has to cover those as well.
        util::remove_atomic_leftovers(&self.path)?;
        Ok(())
    }
}

/// MVP: always `FileSecretStore`.
pub fn secret_store(p: &Paths) -> Box<dyn SecretStore> {
    Box::new(FileSecretStore {
        path: p.secrets_file(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn paths(root: &Path) -> Paths {
        Paths {
            config_dir: root.join("config"),
            state_root: root.join("state"),
        }
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn dir_secrets() -> Secrets {
        let keys = Keyring::new([7; 16], vec![(1, MasterKey::from_bytes([9; 32]))], 1).unwrap();
        let mut s = Secrets::empty();
        s.set_keys(&keys);
        s
    }

    #[test]
    fn paths_are_laid_out_as_specified() {
        let p = paths(Path::new("/x"));
        assert_eq!(p.config_file(), Path::new("/x/config/config.json"));
        assert_eq!(p.secrets_file(), Path::new("/x/state/secrets.json"));
        assert_eq!(p.token_file(), Path::new("/x/state/token.json"));
        assert_eq!(p.state_dir("ab"), Path::new("/x/state/ab"));
        assert_eq!(p.db_file("ab"), Path::new("/x/state/ab/state.db"));
        assert_eq!(
            p.index_cache_dir("ab"),
            Path::new("/x/state/ab/index-cache")
        );
    }

    #[test]
    fn config_round_trip_and_absence() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        assert!(matches!(Config::load(&p), Err(ConfigError::NotConfigured)));
        let dir = Config {
            version: 1,
            vault_id: util::hex(&[7; 16]),
            vault_name: "gclone".into(),
            backend: BackendCfg::Dir {
                path: "/abs/path".into(),
            },
            auth_url: None,
            root_id: "r".into(),
            index_id: "i".into(),
            data_id: "d".into(),
        };
        dir.save(&p).unwrap();
        assert_eq!(mode(&p.config_file()), 0o600);
        assert_eq!(mode(&p.config_dir), 0o700);
        let text = std::fs::read_to_string(p.config_file()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["backend"]["kind"], "dir");
        assert_eq!(json["backend"]["path"], "/abs/path");
        assert!(
            json.get("auth_url").is_none(),
            "absent for directory vaults"
        );
        let back = Config::load(&p).unwrap();
        assert_eq!(back.vault_id_bytes().unwrap(), [7; 16]);
        assert_eq!(back.handles().index, Handle("i".into()));

        let drive = Config {
            backend: BackendCfg::Drive,
            auth_url: Some("https://auth.example".into()),
            ..dir
        };
        drive.save(&p).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p.config_file()).unwrap()).unwrap();
        assert_eq!(json["backend"], serde_json::json!({ "kind": "drive" }));
        assert_eq!(json["auth_url"], "https://auth.example");

        Config::delete(&p).unwrap();
        Config::delete(&p).unwrap();
        assert!(matches!(Config::load(&p), Err(ConfigError::NotConfigured)));
    }

    #[test]
    fn config_rejects_other_versions_and_garbage() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        std::fs::create_dir_all(&p.config_dir).unwrap();
        std::fs::write(p.config_file(), br#"{"version":2}"#).unwrap();
        assert!(matches!(Config::load(&p), Err(ConfigError::Version(2))));
        std::fs::write(p.config_file(), b"not json").unwrap();
        assert!(matches!(Config::load(&p), Err(ConfigError::Json(_))));
    }

    #[test]
    fn the_spec_literal_of_secrets_deserializes() {
        let s: Secrets = parse_json(
            "secrets.json",
            br#"{ "version": 1, "auth_url": "https://gclone-auth.example.workers.dev", "refresh_token": "1//x", "email": "me@example.com",
                 "consent_ms": 1794400000000, "refresh_expires_at_ms": null, "client": "device",
                 "keys": [ { "epoch": 1, "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } ], "min_epoch": 1 }"#,
        )
        .unwrap();
        assert!(s.has_login());
        assert_eq!(
            s.endpoints().unwrap().base,
            "https://gclone-auth.example.workers.dev"
        );
        let keys = s.keyring([1; 16]).unwrap();
        assert_eq!((keys.current_epoch(), keys.min_epoch()), (1, 1));
        assert_eq!(s.client, AuthClient::Device);
    }

    /// `secrets.json` as gclone wrote it before 0.2.0 has no `client`: that login belongs to
    /// the Worker's legacy client, and the file is written back without the field.
    #[test]
    fn secrets_without_a_client_field_are_a_legacy_login() {
        let old = br#"{ "version": 1, "auth_url": "https://auth.example", "refresh_token": "1//x", "email": "me@example.com",
                        "consent_ms": 1794400000000, "refresh_expires_at_ms": null, "keys": [], "min_epoch": 0 }"#;
        let mut s: Secrets = parse_json("secrets.json", old).unwrap();
        assert!(s.has_login());
        assert_eq!(s.client, AuthClient::Legacy);
        let text = serde_json::to_string(&s).unwrap();
        assert!(!text.contains("client"), "{text}");

        s.client = AuthClient::Device;
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["client"], "device");
        let back: Secrets = serde_json::from_value(json).unwrap();
        assert_eq!(back.client, AuthClient::Device);
        // a value this build does not know is not guessed at
        let unknown = br#"{ "version": 1, "refresh_token": "1//x", "client": "tv" }"#;
        assert!(parse_json::<Secrets>("secrets.json", unknown).is_err());
    }

    #[test]
    fn directory_vault_secrets_have_no_login_fields_and_load() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        let store = secret_store(&p);
        assert!(store.load().unwrap().is_none());
        store.save(&dir_secrets()).unwrap();
        assert_eq!(mode(&p.secrets_file()), 0o600);
        assert_eq!(mode(&p.state_root), 0o700);
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p.secrets_file()).unwrap()).unwrap();
        for absent in ["auth_url", "refresh_token", "email", "consent_ms", "client"] {
            assert!(json.get(absent).is_none(), "{absent} must be absent");
        }
        let back = store.load().unwrap().unwrap();
        assert!(!back.has_login());
        assert!(matches!(back.endpoints(), Err(ConfigError::NotLoggedIn)));
        let keys = back.keyring([7; 16]).unwrap();
        assert_eq!(keys.export()[0].1.as_slice(), &[9; 32]);
        store.delete().unwrap();
        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
    }

    /// A `save` killed before its rename leaves a full copy of the secrets in a temp file;
    /// `delete` (logout) must not leave it behind.
    #[test]
    fn delete_removes_temp_copies_of_an_interrupted_save() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        let store = secret_store(&p);
        store.save(&dir_secrets()).unwrap();
        let copy = p.state_root.join(".secrets.json.tmp-0011223344556677");
        std::fs::copy(p.secrets_file(), &copy).unwrap();
        let other = p.state_root.join(".token.json.tmp-0011223344556677");
        std::fs::write(&other, b"{}").unwrap();
        store.delete().unwrap();
        assert!(!p.secrets_file().exists());
        assert!(!copy.exists(), "the temp copy holds the cached key");
        assert!(other.exists(), "only the secrets file's own temp files");

        // also when secrets.json itself is already gone
        std::fs::write(&copy, b"{}").unwrap();
        store.delete().unwrap();
        assert!(!copy.exists());
    }

    #[test]
    fn loading_never_validates_the_auth_url() {
        let tmp = tempfile::tempdir().unwrap();
        let store = secret_store(&paths(tmp.path()));
        let mut s = dir_secrets();
        s.auth_url = Some("http://example.com".into());
        s.refresh_token = Some("rt".into());
        store.save(&s).unwrap();
        let back = store.load().unwrap().unwrap();
        assert!(matches!(
            back.endpoints(),
            Err(ConfigError::Auth(crate::error::AuthError::BadAuthUrl(_)))
        ));
    }

    #[test]
    fn keyring_states() {
        let mut s = Secrets::empty();
        assert!(matches!(s.keyring([0; 16]), Err(ConfigError::Locked)));
        s.keys = vec![KeyEntry {
            epoch: 1,
            key: "short".into(),
        }];
        assert!(matches!(s.keyring([0; 16]), Err(ConfigError::Json(_))));
        s = dir_secrets();
        s.min_epoch = 5;
        assert!(matches!(s.keyring([0; 16]), Err(ConfigError::Crypto(_))));
        s.refresh_token = Some(String::new());
        assert!(!s.has_login(), "an empty token is no login");
    }

    #[test]
    fn strict_loading_refuses_open_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        let store = secret_store(&p);
        store.save(&dir_secrets()).unwrap();

        for file_mode in [0o644, 0o640, 0o604] {
            chmod(&p.secrets_file(), file_mode);
            match store.load() {
                Err(ConfigError::InsecurePermissions(path)) => {
                    assert_eq!(path, p.secrets_file().display().to_string())
                }
                _ => panic!("mode {file_mode:o} must be refused"),
            }
        }
        chmod(&p.secrets_file(), 0o600);
        assert!(store.load().unwrap().is_some());

        chmod(&p.state_root, 0o755);
        match store.load() {
            Err(ConfigError::InsecurePermissions(path)) => {
                assert_eq!(path, p.state_root.display().to_string())
            }
            _ => panic!("a 0755 state root must be refused"),
        }
        assert!(
            matches!(
                store.save(&dir_secrets()),
                Err(ConfigError::InsecurePermissions(_))
            ),
            "nothing is written into a directory others can read"
        );
        chmod(&p.state_root, 0o700);
        assert!(store.load().unwrap().is_some());
    }

    #[test]
    fn a_symlink_in_place_of_the_secrets_file_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        let store = secret_store(&p);
        store.save(&dir_secrets()).unwrap();
        let elsewhere = tmp.path().join("elsewhere.json");
        std::fs::rename(p.secrets_file(), &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, p.secrets_file()).unwrap();
        assert!(matches!(
            store.load(),
            Err(ConfigError::InsecurePermissions(_))
        ));
    }

    #[test]
    fn secrets_reject_other_versions() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        let store = secret_store(&p);
        let mut s = dir_secrets();
        s.version = 3;
        store.save(&s).unwrap();
        assert!(matches!(store.load(), Err(ConfigError::Version(3))));
    }
}

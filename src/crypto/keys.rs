//! Key hierarchy (SPEC §4.1, §9.4).
//!
//! ```text
//! MK_e          32 random bytes per key epoch e
//! K_{e,label} = HKDF-SHA-256(salt = vault_id, ikm = MK_e, info = "gclone/v1/key/" ‖ label, L = 32)
//! ```

use std::collections::BTreeMap;
use zeroize::Zeroizing;

use super::hkdf_sha256;
use super::stream::{self, Header, Opener, Sealer, StreamType};
use crate::consts::CHUNK_LOG2;
use crate::error::CryptoError;
use crate::types::Loc;
use crate::util;

const KEY_INFO_PREFIX: &[u8] = b"gclone/v1/key/";

/// One master key `MK_e`. `Clone`: keys are moved into `spawn_blocking` closures. No `Debug`.
#[derive(Clone)]
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    pub fn generate() -> Self {
        MasterKey(Zeroizing::new(util::random()))
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        MasterKey(Zeroizing::new(b))
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Purpose {
    Data,
    Index,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Purpose::Data => b"data",
            Purpose::Index => b"index",
        }
    }
}

/// A purpose key `K_{e,label}` (or `K_pass`). No `Debug`.
#[derive(Clone)]
pub struct PurposeKey(Zeroizing<[u8; 32]>);

impl PurposeKey {
    /// Only for `K_pass` (keyfile, §2.6).
    pub fn from_raw(b: [u8; 32]) -> Self {
        PurposeKey(Zeroizing::new(b))
    }

    pub(super) fn from_zeroizing(b: Zeroizing<[u8; 32]>) -> Self {
        PurposeKey(b)
    }

    pub(super) fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `{epoch → MK}`, the vault id and the local, monotonic `min_epoch`. No `Debug`.
///
/// The newest key is held outside the map so that "the current epoch" exists by construction.
#[derive(Clone)]
pub struct Keyring {
    vault_id: [u8; 16],
    current: (u32, MasterKey),
    older: BTreeMap<u32, MasterKey>,
    min_epoch: u32,
}

impl Keyring {
    /// At least one key, all epochs ≥ `min_epoch`, no epoch twice — else `Misuse`.
    pub fn new(
        vault_id: [u8; 16],
        keys: Vec<(u32, MasterKey)>,
        min_epoch: u32,
    ) -> Result<Self, CryptoError> {
        let mut older = BTreeMap::new();
        for (epoch, key) in keys {
            if epoch < min_epoch {
                return Err(CryptoError::Misuse(
                    "keyring: a key epoch is below min_epoch",
                ));
            }
            if older.insert(epoch, key).is_some() {
                return Err(CryptoError::Misuse("keyring: the same key epoch twice"));
            }
        }
        let Some(current) = older.pop_last() else {
            return Err(CryptoError::Misuse("keyring: no key"));
        };
        Ok(Keyring {
            vault_id,
            current,
            older,
            min_epoch,
        })
    }

    pub fn vault_id(&self) -> [u8; 16] {
        self.vault_id
    }

    /// The greatest epoch held: the one new streams are sealed under.
    pub fn current_epoch(&self) -> u32 {
        self.current.0
    }

    pub fn min_epoch(&self) -> u32 {
        self.min_epoch
    }

    /// `EpochTooOld` for an epoch below `min_epoch`, `UnknownEpoch` for any other epoch not held.
    /// (Every held epoch is ≥ `min_epoch`, so the too-old check has to come first to be reachable.)
    pub fn purpose(&self, epoch: u32, p: Purpose) -> Result<PurposeKey, CryptoError> {
        if epoch < self.min_epoch {
            return Err(CryptoError::EpochTooOld {
                epoch,
                min: self.min_epoch,
            });
        }
        let master = if epoch == self.current.0 {
            &self.current.1
        } else {
            self.older
                .get(&epoch)
                .ok_or(CryptoError::UnknownEpoch(epoch))?
        };
        Ok(self.derive(master, p))
    }

    /// All `(epoch, MK)` pairs, ascending by epoch.
    pub fn export(&self) -> Vec<(u32, Zeroizing<[u8; 32]>)> {
        self.older
            .iter()
            .chain(std::iter::once((&self.current.0, &self.current.1)))
            .map(|(epoch, key)| (*epoch, Zeroizing::new(*key.expose())))
            .collect()
    }

    /// Whole container under the current epoch. `ty` must have a purpose key: Bundle → `Err(Misuse)`.
    pub fn seal(&self, ty: StreamType, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let purpose = ty.purpose().ok_or(NO_PURPOSE)?;
        let key = self.derive(&self.current.1, purpose);
        Ok(stream::seal_all(
            &key,
            ty,
            self.current.0,
            CHUNK_LOG2,
            plaintext,
        ))
    }

    /// Error precedence of §4.2: header (`Truncated`, `BadMagic`, `Unsupported`), then the epoch
    /// (`UnknownEpoch` / `EpochTooOld`), then type and commit (`WrongKey`), then the chunks.
    pub fn open(
        &self,
        ty: StreamType,
        container: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let purpose = ty.purpose().ok_or(NO_PURPOSE)?;
        let header = Header::decode(container)?;
        let key = self.purpose(header.epoch, purpose)?;
        stream::open_all(&key, ty, container)
    }

    /// Sealer for one Data stream under the current epoch (suite 1, flags 0, `CHUNK_LOG2`, fresh salt).
    pub fn data_sealer(&self) -> Sealer {
        let key = self.derive(&self.current.1, Purpose::Data);
        Sealer::new(&key, StreamType::Data, self.current.0, CHUNK_LOG2)
    }

    /// Opener for a Data stream described by an index entry. Order: `loc.suite != 1` or
    /// `loc.flags != 0` → `Unsupported` (no key is derived); `chunk_log2` outside 12..=24 →
    /// `Unsupported`; then `UnknownEpoch` / `EpochTooOld`; then the stream key from the `Loc`.
    pub fn data_opener(&self, loc: &Loc) -> Result<Opener, CryptoError> {
        stream::check_loc(loc)?;
        let key = self.purpose(loc.epoch, Purpose::Data)?;
        Opener::for_data(&key, loc)
    }

    fn derive(&self, master: &MasterKey, p: Purpose) -> PurposeKey {
        let info = [KEY_INFO_PREFIX, p.label()].concat();
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf_sha256(&self.vault_id, master.expose(), &info, key.as_mut());
        PurposeKey::from_zeroizing(key)
    }
}

const NO_PURPOSE: CryptoError =
    CryptoError::Misuse("Bundle streams are keyed by the passphrase, not by the keyring");

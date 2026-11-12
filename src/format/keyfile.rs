//! Keyfile: the master key wrapped under the passphrase (SPEC §2.6, §9.4).
//! `KeyfileKey` and `KeyfilePayload` hold secrets: NO `Debug` derive.
//!
//! ```text
//! keyfile   = KdfPreamble(36) ‖ Stream(type = 0x05 Bundle, key_epoch = 0, chunk_log2 = 16, key = K_pass)
//! plaintext = UTF-8 JSON KeyfilePayload
//! name      = "gclone-key-" ‖ gen (8 lowercase hex digits) ‖ "-" ‖ h8
//! ```

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::index::SealedObject;
use super::unhex_array;
use crate::consts::{CHUNK_LOG2, KEYFILE_MAX};
use crate::crypto::{
    HEADER_LEN, KdfParams, KdfPreamble, Keyring, MasterKey, PREAMBLE_LEN, Passphrase, StreamType,
    TAG_LEN, ciphertext_len, derive_pass_key, open_all, seal_all,
};
use crate::error::FormatError;
use crate::util;

pub const KEYFILE_PREFIX: &str = "gclone-key-";

const PAYLOAD_VERSION: u32 = 1;
/// The shortest keyfile: preamble, stream header, one empty chunk (36 + 76).
const KEYFILE_MIN: usize = PREAMBLE_LEN + HEADER_LEN + TAG_LEN;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KeyfileKey {
    pub epoch: u32,
    pub key: String,
}

/// `gen` is a reserved keyword in edition 2024: the Rust identifier is `generation`
/// everywhere; only the JSON key and the object name keep the wire spelling "gen".
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KeyfilePayload {
    pub v: u32,
    pub vault_id: String,
    #[serde(rename = "gen")]
    pub generation: u32,
    pub keys: Vec<KeyfileKey>,
    pub min_epoch: u32,
    pub created_ms: u64,
    pub by: String,
}

impl KeyfilePayload {
    pub fn from_keyring(keys: &Keyring, generation: u32, by: &str, now_ms: u64) -> Self {
        KeyfilePayload {
            v: PAYLOAD_VERSION,
            vault_id: util::hex(&keys.vault_id()),
            generation,
            keys: keys
                .export()
                .iter()
                .map(|(epoch, key)| KeyfileKey {
                    epoch: *epoch,
                    key: util::b64url(key.as_slice()),
                })
                .collect(),
            min_epoch: keys.min_epoch(),
            created_ms: now_ms,
            by: by.to_owned(),
        }
    }

    /// The keyring this payload carries, for the vault `self.vault_id`. `KeyfileDamaged` unless
    /// there is at least one key, every key is 32 bytes, every epoch is ≥ `min_epoch` and
    /// distinct, and the vault id is well-formed.
    pub fn keyring(&self) -> Result<Keyring, FormatError> {
        let vault_id = self.vault_id_bytes()?;
        let mut keys = Vec::with_capacity(self.keys.len());
        for k in &self.keys {
            let raw = Zeroizing::new(util::unb64url(&k.key).ok_or(FormatError::KeyfileDamaged)?);
            let key = Zeroizing::new(
                <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| FormatError::KeyfileDamaged)?,
            );
            keys.push((k.epoch, MasterKey::from_bytes(*key)));
        }
        Keyring::new(vault_id, keys, self.min_epoch).map_err(|_| FormatError::KeyfileDamaged)
    }

    /// `KeyfileDamaged` unless `vault_id` is 32 lowercase hex digits.
    pub fn vault_id_bytes(&self) -> Result<[u8; 16], FormatError> {
        unhex_array(&self.vault_id).ok_or(FormatError::KeyfileDamaged)
    }

    /// What every reader requires of an opened payload besides the generation in the name.
    fn check(&self) -> Result<(), FormatError> {
        if self.v != PAYLOAD_VERSION {
            return Err(FormatError::KeyfileVersion(self.v));
        }
        self.keyring().map(drop)
    }
}

/// `gclone-key-<generation:08x>-<h8>`
pub fn keyfile_name(generation: u32, hash: &[u8; 32]) -> String {
    format!("{KEYFILE_PREFIX}{generation:08x}-{}", util::hex(&hash[..4]))
}

/// `(generation, h8)`. The generation is an unauthenticated number until the keyfile opens.
pub fn parse_keyfile_name(name: &str) -> Option<(u32, [u8; 4])> {
    let (generation, h8) = name.strip_prefix(KEYFILE_PREFIX)?.split_once('-')?;
    Some((
        u32::from_be_bytes(unhex_array(generation)?),
        unhex_array(h8)?,
    ))
}

/// `KdfPreamble::generate(params)` → `derive_pass_key` → Stream(type Bundle, epoch 0) over the
/// JSON payload. Blocking (Argon2id). `params` is `KdfParams::default()` everywhere outside tests.
///
/// Nothing is written that `open_keyfile` would refuse: out-of-bounds `params` (`KdfParams`), a
/// payload with `v != 1` (`KeyfileVersion`) or unusable keys (`KeyfileDamaged`), or one that
/// would exceed `KEYFILE_MAX` (`BadEntry`) fail before any key derivation.
pub fn seal_keyfile(
    p: &KeyfilePayload,
    pass: &Passphrase,
    params: KdfParams,
) -> Result<SealedObject, FormatError> {
    params.validate()?;
    p.check()?;
    let json = Zeroizing::new(
        serde_json::to_vec(p)
            .map_err(|e| FormatError::Decode(format!("cannot encode the keyfile payload: {e}")))?,
    );
    let len = PREAMBLE_LEN as u64 + ciphertext_len(json.len() as u64, CHUNK_LOG2);
    if len > KEYFILE_MAX {
        return Err(FormatError::BadEntry(format!(
            "the keyfile would be {len} bytes, more than the {KEYFILE_MAX} allowed"
        )));
    }
    let preamble = KdfPreamble::generate(params);
    let key = derive_pass_key(pass, &preamble)?;
    let mut bytes = Vec::with_capacity(len as usize);
    bytes.extend_from_slice(&preamble.encode());
    bytes.extend_from_slice(&seal_all(&key, StreamType::Bundle, 0, CHUNK_LOG2, &json));
    let hash = *blake3::hash(&bytes).as_bytes();
    Ok(SealedObject {
        name: keyfile_name(p.generation, &hash),
        hash,
        bytes,
    })
}

/// Open order and errors of §2.6 (size, name, h8, KDF bounds — before any Argon2 allocation —,
/// Argon2id, commit → `Crypto(WrongKey)`, chunks, JSON, generation/keys). Blocking.
///
/// The caller still has to compare `payload.vault_id` with the vault it is attaching to.
pub fn open_keyfile(
    name: &str,
    bytes: &[u8],
    pass: &Passphrase,
) -> Result<KeyfilePayload, FormatError> {
    let (generation, h8) = parse_keyfile_name(name).ok_or(FormatError::KeyfileDamaged)?;
    if bytes.len() < KEYFILE_MIN || bytes.len() as u64 > KEYFILE_MAX {
        return Err(FormatError::KeyfileDamaged);
    }
    // An accidental-corruption check, not an authentication: the name is as unauthenticated as
    // the bytes.
    if blake3::hash(bytes).as_bytes()[..4] != h8 {
        return Err(FormatError::KeyfileDamaged);
    }
    let (preamble, stream) = bytes.split_at(PREAMBLE_LEN);
    let preamble = KdfPreamble::decode(preamble)?;
    let key = derive_pass_key(pass, &preamble)?;
    let json = open_all(&key, StreamType::Bundle, stream)?;
    let payload = parse_payload(&json)?;
    if payload.generation != generation {
        return Err(FormatError::KeyfileDamaged);
    }
    Ok(payload)
}

/// The version is read on its own first, so that a future payload shape is reported as
/// "needs a newer gclone" and not as damage.
fn parse_payload(json: &[u8]) -> Result<KeyfilePayload, FormatError> {
    #[derive(Deserialize)]
    struct Version {
        v: u32,
    }
    let version: Version = serde_json::from_slice(json).map_err(|_| FormatError::KeyfileDamaged)?;
    if version.v != PAYLOAD_VERSION {
        return Err(FormatError::KeyfileVersion(version.v));
    }
    // serde_json's message could quote payload text: it is dropped.
    let payload: KeyfilePayload =
        serde_json::from_slice(json).map_err(|_| FormatError::KeyfileDamaged)?;
    payload.check()?;
    Ok(payload)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::kdf::tests::{SMALL, argon2_runs};
    use crate::crypto::stream::tests::{frozen, frozen_bytes, kat_keyring};

    const KAT_PASSPHRASE: &str = "correct horse battery staple";

    fn kat_payload() -> KeyfilePayload {
        KeyfilePayload::from_keyring(&kat_keyring(), 3, "kat", 1_794_400_000_000)
    }

    /// The `keyfile` section of the frozen vector file (called by `stream::tests::gen_vectors`).
    pub(crate) fn gen_frozen() -> serde_json::Value {
        let sealed = seal_keyfile(
            &kat_payload(),
            &Passphrase::from_input(KAT_PASSPHRASE),
            SMALL,
        )
        .unwrap();
        serde_json::json!({
            "passphrase": KAT_PASSPHRASE,
            "name": sealed.name,
            "bytes": util::hex(&sealed.bytes),
        })
    }

    #[test]
    fn frozen_keyfile_still_opens() {
        let frozen = frozen();
        let kf = &frozen["keyfile"];
        let name = kf["name"].as_str().expect("regenerate the vectors");
        let pass = Passphrase::from_input(kf["passphrase"].as_str().unwrap());
        let payload = open_keyfile(name, &frozen_bytes(&kf["bytes"]), &pass).unwrap();
        assert!(payload == kat_payload());
        assert_eq!(payload.keyring().unwrap().export(), kat_keyring().export());
    }

    /// A keyfile whose preamble was overwritten, renamed to match its new hash.
    fn with_preamble(sealed: &SealedObject, at: usize, value: &[u8]) -> (String, Vec<u8>) {
        let mut bytes = sealed.bytes.clone();
        bytes[at..at + value.len()].copy_from_slice(value);
        let name = keyfile_name(3, blake3::hash(&bytes).as_bytes());
        (name, bytes)
    }

    #[test]
    fn out_of_bounds_kdf_parameters_are_rejected_without_running_argon2() {
        let pass = Passphrase::from_input(KAT_PASSPHRASE);
        let sealed = seal_keyfile(&kat_payload(), &pass, SMALL).unwrap();
        let before = argon2_runs();
        let cases: [(usize, &[u8]); 8] = [
            (8, &4096u32.to_be_bytes()),
            (8, &524_289u32.to_be_bytes()),
            (8, &1_048_576u32.to_be_bytes()),
            (12, &0u32.to_be_bytes()),
            (12, &5u32.to_be_bytes()),
            (16, &2u32.to_be_bytes()),
            (4, &[2]),
            (5, &[0x10]),
        ];
        for (at, value) in cases {
            let (name, bytes) = with_preamble(&sealed, at, value);
            assert!(
                matches!(
                    open_keyfile(&name, &bytes, &pass),
                    Err(FormatError::KdfParams)
                ),
                "preamble byte {at}"
            );
        }
        // Neither does a damaged or oversized object get as far as the KDF.
        let mut flipped = sealed.bytes.clone();
        flipped[40] ^= 1;
        assert!(matches!(
            open_keyfile(&sealed.name, &flipped, &pass),
            Err(FormatError::KeyfileDamaged)
        ));
        assert_eq!(argon2_runs(), before);

        // The largest accepted parameters pass the bounds (decoding only: no 512 MiB derivation).
        let (_, bytes) = with_preamble(&sealed, 8, &524_288u32.to_be_bytes());
        let (_, bytes) = with_preamble(
            &SealedObject {
                bytes,
                ..sealed.clone()
            },
            12,
            &[0, 0, 0, 4],
        );
        let preamble = KdfPreamble::decode(&bytes).unwrap();
        assert_eq!(
            preamble.params,
            KdfParams {
                m_kib: 524_288,
                t: 4,
                p: 1
            }
        );
        assert_eq!(argon2_runs(), before);

        // One derivation per attempt on a well-formed keyfile, also with the wrong passphrase.
        open_keyfile(&sealed.name, &sealed.bytes, &pass).unwrap();
        assert!(matches!(
            open_keyfile(
                &sealed.name,
                &sealed.bytes,
                &Passphrase::from_input("wrong")
            ),
            Err(FormatError::Crypto(crate::error::CryptoError::WrongKey))
        ));
        assert_eq!(argon2_runs(), before + 2);
    }

    #[test]
    fn seal_refuses_what_open_would_refuse_before_deriving() {
        let pass = Passphrase::from_input(KAT_PASSPHRASE);
        let before = argon2_runs();
        let too_cheap = KdfParams {
            m_kib: 4096,
            t: 1,
            p: 1,
        };
        assert!(matches!(
            seal_keyfile(&kat_payload(), &pass, too_cheap),
            Err(FormatError::KdfParams)
        ));
        let mut v2 = kat_payload();
        v2.v = 2;
        assert!(matches!(
            seal_keyfile(&v2, &pass, SMALL),
            Err(FormatError::KeyfileVersion(2))
        ));
        let mut no_keys = kat_payload();
        no_keys.keys.clear();
        assert!(matches!(
            seal_keyfile(&no_keys, &pass, SMALL),
            Err(FormatError::KeyfileDamaged)
        ));
        let mut huge = kat_payload();
        huge.by = "x".repeat(KEYFILE_MAX as usize);
        assert!(matches!(
            seal_keyfile(&huge, &pass, SMALL),
            Err(FormatError::BadEntry(_))
        ));
        assert_eq!(argon2_runs(), before);
    }
}

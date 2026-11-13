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
use crate::error::{CryptoError, FormatError};
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

/// The base64 text of a master key is wiped when its holder goes (best effort, §4: what was
/// copied out of it by a move or a clone is the copy's to wipe).
impl Drop for KeyfileKey {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.key.zeroize();
    }
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

/// What `open_keyfile` checks before it derives a key, in its order (§2.6): the name parses,
/// `36 + 76 ≤ len ≤ KEYFILE_MAX`, `BLAKE3(bytes)` matches the name's `h8`, and the KDF preamble
/// is within bounds. An object that passes is a **well-formed** keyfile: it can be tried, at
/// the cost its preamble names — returned with the generation of its name. Anything else can
/// never open, whatever the passphrase, and is refused without any work; whoever picks the
/// keyfiles to try (ATTACH, the hosted viewer) uses this so that a planted object under a
/// keyfile's name takes no place among the candidates.
///
/// Nothing here is authenticated: the generation is a number from a name, and the hash is an
/// accidental-corruption check — the name is as unauthenticated as the bytes.
pub fn check_keyfile(name: &str, bytes: &[u8]) -> Result<(u32, KdfPreamble), FormatError> {
    let (generation, h8) = parse_keyfile_name(name).ok_or(FormatError::KeyfileDamaged)?;
    if bytes.len() < KEYFILE_MIN || bytes.len() as u64 > KEYFILE_MAX {
        return Err(FormatError::KeyfileDamaged);
    }
    if blake3::hash(bytes).as_bytes()[..4] != h8 {
        return Err(FormatError::KeyfileDamaged);
    }
    Ok((generation, KdfPreamble::decode(&bytes[..PREAMBLE_LEN])?))
}

/// Open order and errors of §2.6 (size, name, h8, KDF bounds — before any Argon2 allocation —,
/// Argon2id, commit → `Crypto(WrongKey)`, chunks, JSON, generation/keys). Blocking.
///
/// A passphrase that gclone before 0.5.0 normalised differently (`Passphrase::legacy`: an
/// input of the 26-symbol generated shape that is not in its canonical form) is tried a
/// second time as those versions used it, after the first try answered "wrong key".
///
/// The caller still has to compare `payload.vault_id` with the vault it is attaching to.
pub fn open_keyfile(
    name: &str,
    bytes: &[u8],
    pass: &Passphrase,
) -> Result<KeyfilePayload, FormatError> {
    let (generation, preamble) = check_keyfile(name, bytes)?;
    let stream = &bytes[PREAMBLE_LEN..];
    let open = |pass: &Passphrase| {
        let key = derive_pass_key(pass, &preamble)?;
        Ok::<_, FormatError>(open_all(&key, StreamType::Bundle, stream)?)
    };
    let json = match (open(pass), pass.legacy()) {
        (Err(FormatError::Crypto(CryptoError::WrongKey)), Some(legacy)) => open(&legacy)?,
        (opened, _) => opened?,
    };
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

    /// §2.6: a second derivation is spent only on an input of the 26-symbol shape that is not
    /// in its canonical form — the one input that gclone before 0.5.0 normalised differently
    /// — and only after the first answered "wrong key".
    #[test]
    fn the_older_normalisation_is_tried_second_and_only_where_it_differs() {
        let typed = "maple tiger candle stone wharf";
        let now = Passphrase::from_input(typed);
        let then = now
            .legacy()
            .expect("gclone before 0.5.0 used this text as typed");
        assert_eq!(then.display().as_str(), typed);
        assert!(then.legacy().is_none());
        let payload = kat_payload();

        // Sealed as 0.4.0 sealed it: the canonical form fails, the typed text opens.
        let old = seal_keyfile(&payload, &then, SMALL).unwrap();
        let before = argon2_runs();
        assert!(open_keyfile(&old.name, &old.bytes, &now).unwrap() == payload);
        assert_eq!(argon2_runs(), before + 2);
        // Sealed as it is sealed now: the first derivation opens it.
        let new = seal_keyfile(&payload, &now, SMALL).unwrap();
        let before = argon2_runs();
        assert!(open_keyfile(&new.name, &new.bytes, &now).unwrap() == payload);
        assert_eq!(argon2_runs(), before + 1);

        // One derivation for every other input, right or wrong.
        for other in [
            "correct horse battery staple",
            "MAP1E-T1GER-CAND1-EST0N-EWHARF", // canonical already: nothing to try second
            "7K2M9-QXA41-TBZR8-D0HNW",        // the 20-symbol shape never had two forms
            "7k2m9 qxa41 tbzr8 d0hnw",
        ] {
            let pass = Passphrase::from_input(other);
            assert!(pass.legacy().is_none(), "{other}");
            let before = argon2_runs();
            assert!(matches!(
                open_keyfile(&old.name, &old.bytes, &pass),
                Err(FormatError::Crypto(CryptoError::WrongKey))
            ));
            assert_eq!(argon2_runs(), before + 1, "{other}");
        }
        // A wrong passphrase of the 26-symbol shape costs two — and no more.
        let wrong = Passphrase::from_input("maple tiger candle stone whart");
        let before = argon2_runs();
        assert!(matches!(
            open_keyfile(&old.name, &old.bytes, &wrong),
            Err(FormatError::Crypto(CryptoError::WrongKey))
        ));
        assert_eq!(argon2_runs(), before + 2);
    }

    /// `check_keyfile` is every check `open_keyfile` makes before it derives a key.
    #[test]
    fn a_well_formed_keyfile_is_recognised_without_any_derivation() {
        let sealed = seal_keyfile(
            &kat_payload(),
            &Passphrase::from_input(KAT_PASSPHRASE),
            SMALL,
        )
        .unwrap();
        let before = argon2_runs();
        let (generation, preamble) = check_keyfile(&sealed.name, &sealed.bytes).unwrap();
        assert_eq!((generation, preamble.params), (3, SMALL));
        let renamed = keyfile_name(4, &sealed.hash);
        assert_eq!(check_keyfile(&renamed, &sealed.bytes).unwrap().0, 4);
        for (name, bytes) in [
            ("gclone-key-00000003", &sealed.bytes[..]),
            ("gclone-key-00000003-00000000", &sealed.bytes[..]), // the name's hash
            (sealed.name.as_str(), &sealed.bytes[..40]),
            (sealed.name.as_str(), b"junk"),
        ] {
            assert!(matches!(
                check_keyfile(name, bytes),
                Err(FormatError::KeyfileDamaged)
            ));
        }
        let mut costly = sealed.bytes.clone();
        costly[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        let name = keyfile_name(3, blake3::hash(&costly).as_bytes());
        assert!(matches!(
            check_keyfile(&name, &costly),
            Err(FormatError::KdfParams)
        ));
        assert_eq!(argon2_runs(), before);
    }
}

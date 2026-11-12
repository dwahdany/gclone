//! Passphrase → `K_pass` for the keyfile (SPEC §2.6, §4.3, §9.4). Nothing else uses Argon2.
//!
//! ```text
//! KdfPreamble(36) = "GCK1" ‖ alg = 0x01 (Argon2id) ‖ version = 0x13 ‖ 0x00 0x00 ‖ m_kib u32 BE ‖ t u32 BE ‖ p u32 BE ‖ salt(16)
//! K_pass          = HKDF-SHA-256(salt = the 36 preamble bytes, ikm = Argon2id(P, preamble.salt, m_kib, t, p, 32 bytes),
//!                                info = "gclone/v1/passphrase/keyfile", L = 32)
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use super::hkdf_sha256;
use super::keys::PurposeKey;
use crate::consts::{
    KDF_M_KIB_MAX, KDF_M_KIB_MIN, KDF_T_MAX, KDF_T_MIN, PASSPHRASE_GENERATED_SYMBOLS,
    PASSPHRASE_MIN_CHARS,
};
use crate::error::{CryptoError, FormatError};
use crate::util::{self, CROCKFORD};

pub const PREAMBLE_LEN: usize = 36;

const PREAMBLE_MAGIC: [u8; 4] = *b"GCK1";
const ALG_ARGON2ID: u8 = 0x01;
const ARGON2_V13: u8 = 0x13;
const PASS_KEY_INFO: &[u8] = b"gclone/v1/passphrase/keyfile";
/// A generated passphrase is shown in groups of this many symbols.
const GROUP: usize = 5;
const GENERATED_TEXT_LEN: usize =
    PASSPHRASE_GENERATED_SYMBOLS + PASSPHRASE_GENERATED_SYMBOLS / GROUP - 1;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    /// 262144, 3, 1 — what production code writes.
    fn default() -> Self {
        KdfParams {
            m_kib: crate::consts::KDF_M_KIB,
            t: crate::consts::KDF_T,
            p: crate::consts::KDF_P,
        }
    }
}

impl KdfParams {
    /// Accepted bounds of §2.6: `m_kib` 8192..=524288, `t` 1..=4, `p == 1`. The upper bounds cap
    /// the work a planted keyfile can demand: the parameters are read before anything is
    /// authenticated.
    pub fn validate(&self) -> Result<(), FormatError> {
        let ok = (KDF_M_KIB_MIN..=KDF_M_KIB_MAX).contains(&self.m_kib)
            && (KDF_T_MIN..=KDF_T_MAX).contains(&self.t)
            && self.p == 1;
        if ok {
            Ok(())
        } else {
            Err(FormatError::KdfParams)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdfPreamble {
    pub params: KdfParams,
    pub salt: [u8; 16],
}

impl KdfPreamble {
    /// Fresh random salt.
    pub fn generate(params: KdfParams) -> Self {
        KdfPreamble {
            params,
            salt: util::random(),
        }
    }

    pub fn encode(&self) -> [u8; PREAMBLE_LEN] {
        let mut b = [0u8; PREAMBLE_LEN];
        b[..4].copy_from_slice(&PREAMBLE_MAGIC);
        b[4] = ALG_ARGON2ID;
        b[5] = ARGON2_V13;
        b[8..12].copy_from_slice(&self.params.m_kib.to_be_bytes());
        b[12..16].copy_from_slice(&self.params.t.to_be_bytes());
        b[16..20].copy_from_slice(&self.params.p.to_be_bytes());
        b[20..].copy_from_slice(&self.salt);
        b
    }

    /// Reads the first 36 bytes of `b` and validates the bounds — no Argon2 work or memory is
    /// spent on a preamble this rejects. Fewer than 36 bytes or a foreign magic →
    /// `KeyfileDamaged`; `GCK<other digit>` → `KeyfileVersion`; any other algorithm, version,
    /// reserved byte or out-of-bounds parameter → `KdfParams`.
    pub fn decode(b: &[u8]) -> Result<Self, FormatError> {
        let Some(b) = b.first_chunk::<PREAMBLE_LEN>() else {
            return Err(FormatError::KeyfileDamaged);
        };
        if b[..4] != PREAMBLE_MAGIC {
            return Err(match b[3] {
                d @ b'0'..=b'9' if b[..3] == PREAMBLE_MAGIC[..3] => {
                    FormatError::KeyfileVersion(u32::from(d - b'0'))
                }
                _ => FormatError::KeyfileDamaged,
            });
        }
        if b[4] != ALG_ARGON2ID || b[5] != ARGON2_V13 || b[6..8] != [0, 0] {
            return Err(FormatError::KdfParams);
        }
        let word = |at: usize| u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let params = KdfParams {
            m_kib: word(8),
            t: word(12),
            p: word(16),
        };
        params.validate()?;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&b[20..]);
        Ok(KdfPreamble { params, salt })
    }
}

/// The normalised passphrase text. No `Debug`, no `Display`.
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    /// Normalisation of §2.6; used when entering AND when setting: one trailing `\n` or `\r\n`
    /// is dropped, the text is put into NFC, and a text of the generated shape (20 Crockford
    /// symbols in any case, `I`/`L`/`O` tolerated, any grouping) becomes the canonical
    /// `XXXXX-XXXXX-XXXXX-XXXXX`. Anything else is used as is.
    pub fn from_input(input: &str) -> Self {
        let line = match input.strip_suffix('\n') {
            Some(line) => line.strip_suffix('\r').unwrap_or(line),
            None => input,
        };
        // NFC never grows a string past three times its UTF-8 length: no reallocation, so no
        // copy of the text is left behind un-zeroed.
        let mut text = Zeroizing::new(String::with_capacity(3 * line.len()));
        text.extend(line.nfc());
        Passphrase(canonical_generated(&text).unwrap_or(text))
    }

    /// `from_input` + `PASSPHRASE_MIN_CHARS` → `WeakPassphrase`.
    pub fn set_checked(input: &str) -> Result<Self, FormatError> {
        let pass = Passphrase::from_input(input);
        if pass.char_count() < PASSPHRASE_MIN_CHARS {
            return Err(FormatError::WeakPassphrase);
        }
        Ok(pass)
    }

    /// 20 Crockford symbols drawn uniformly with the OS CSPRNG (100 bits), in the canonical form.
    pub fn generate() -> Self {
        let raw = Zeroizing::new(util::random::<PASSPHRASE_GENERATED_SYMBOLS>());
        let mut text = Zeroizing::new(String::with_capacity(GENERATED_TEXT_LEN));
        for (i, byte) in raw.iter().enumerate() {
            if i > 0 && i % GROUP == 0 {
                text.push('-');
            }
            // 256 is a multiple of 32: the low five bits are uniform.
            text.push(CROCKFORD[usize::from(byte & 31)] as char);
        }
        Passphrase(text)
    }

    /// The text to show once after `generate()`.
    pub fn display(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.as_str().to_owned())
    }

    /// Unicode scalar values (for the < 20 warning).
    pub fn char_count(&self) -> usize {
        self.0.chars().count()
    }
}

/// The canonical generated form of `text`, if it has the generated shape (§2.6): with ASCII
/// whitespace and `-` removed, exactly 20 characters, each a Crockford symbol in either case or
/// one of `I L O i l o`.
fn canonical_generated(text: &str) -> Option<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(GENERATED_TEXT_LEN));
    let mut symbols = 0;
    for c in text
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '-')
    {
        let symbol = match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            u if u.is_ascii() && CROCKFORD.contains(&(u as u8)) => u,
            _ => return None,
        };
        if symbols == PASSPHRASE_GENERATED_SYMBOLS {
            return None;
        }
        if symbols > 0 && symbols % GROUP == 0 {
            out.push('-');
        }
        out.push(symbol);
        symbols += 1;
    }
    (symbols == PASSPHRASE_GENERATED_SYMBOLS).then_some(out)
}

/// `K_pass` (§2.6). Blocking (≈ 1 s, 256 MiB with the default parameters): call it from
/// `spawn_blocking`. Parameters outside the accepted bounds are refused (`Kdf`) before any
/// memory is allocated, whatever the caller checked before.
pub fn derive_pass_key(pass: &Passphrase, pre: &KdfPreamble) -> Result<PurposeKey, CryptoError> {
    if pre.params.validate().is_err() {
        return Err(CryptoError::Kdf("parameters out of bounds".into()));
    }
    let mut ikm = Zeroizing::new([0u8; 32]);
    argon2id(pass.0.as_bytes(), pre, &mut ikm)?;
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf_sha256(&pre.encode(), ikm.as_ref(), PASS_KEY_INFO, key.as_mut());
    Ok(PurposeKey::from_zeroizing(key))
}

/// The only call into the `argon2` crate; it allocates the `m_kib` working memory itself.
fn argon2id(pwd: &[u8], pre: &KdfPreamble, out: &mut [u8; 32]) -> Result<(), CryptoError> {
    let kdf_err = |e: argon2::Error| CryptoError::Kdf(e.to_string());
    let KdfParams { m_kib, t, p } = pre.params;
    let params = Params::new(m_kib, t, p, Some(out.len())).map_err(kdf_err)?;
    #[cfg(test)]
    tests::ARGON2_RUNS.with(|runs| runs.set(runs.get() + 1));
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pwd, &pre.salt, out)
        .map_err(kdf_err)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::stream::tests::{frozen, frozen_bytes};
    use std::cell::Cell;

    thread_local! {
        /// Argon2 runs on the calling thread, and every test has its own thread: this counts
        /// exactly the derivations the current test caused.
        pub(crate) static ARGON2_RUNS: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn argon2_runs() -> u64 {
        ARGON2_RUNS.with(Cell::get)
    }

    pub(crate) const SMALL: KdfParams = KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
    };
    const KAT_PASSPHRASE: &str = "correct horse battery staple";

    fn kat_preamble() -> KdfPreamble {
        KdfPreamble {
            params: SMALL,
            salt: std::array::from_fn(|i| 0xc0 + i as u8),
        }
    }

    /// Raw `argon2` + `hkdf`, nothing from this module.
    fn reference_pass_key(passphrase: &str, preamble: &[u8; PREAMBLE_LEN]) -> [u8; 32] {
        let word = |at: usize| u32::from_be_bytes(preamble[at..at + 4].try_into().unwrap());
        let mut ikm = [0u8; 32];
        Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(word(8), word(12), word(16), Some(32)).unwrap(),
        )
        .hash_password_into(passphrase.as_bytes(), &preamble[20..], &mut ikm)
        .unwrap();
        let mut key = [0u8; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(preamble), &ikm)
            .expand(b"gclone/v1/passphrase/keyfile", &mut key)
            .unwrap();
        key
    }

    /// The `kdf` section of the frozen vector file (called by `stream::tests::gen_vectors`).
    pub(crate) fn gen_frozen() -> serde_json::Value {
        let preamble = kat_preamble().encode();
        serde_json::json!({
            "passphrase": KAT_PASSPHRASE,
            "preamble": util::hex(&preamble),
            "k_pass": util::hex(&reference_pass_key(KAT_PASSPHRASE, &preamble)),
        })
    }

    #[test]
    fn preamble_layout() {
        let pre = kat_preamble();
        let b = pre.encode();
        assert_eq!(&b[..8], b"GCK1\x01\x13\x00\x00");
        assert_eq!(b[8..20], [0, 0, 0x20, 0, 0, 0, 0, 1, 0, 0, 0, 1]);
        assert_eq!(b[20..], pre.salt);
        assert_eq!(KdfPreamble::decode(&b).unwrap(), pre);
        assert_eq!(
            KdfPreamble {
                params: KdfParams::default(),
                salt: [0; 16]
            }
            .encode()[8..20],
            [0, 4, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1]
        );
    }

    #[test]
    fn pass_key_matches_independent_computation_and_frozen_vector() {
        let pre = kat_preamble();
        let key = derive_pass_key(&Passphrase::from_input(KAT_PASSPHRASE), &pre).unwrap();
        assert_eq!(
            key.expose(),
            &reference_pass_key(KAT_PASSPHRASE, &pre.encode())
        );
        let frozen = frozen();
        let kdf = &frozen["kdf"];
        assert_eq!(kdf["passphrase"], KAT_PASSPHRASE);
        assert_eq!(frozen_bytes(&kdf["preamble"]), pre.encode());
        assert_eq!(frozen_bytes(&kdf["k_pass"]), key.expose());
    }

    #[test]
    fn pass_key_depends_on_every_preamble_field() {
        let pass = Passphrase::from_input(KAT_PASSPHRASE);
        let base = kat_preamble();
        let key = |pre: &KdfPreamble| *derive_pass_key(&pass, pre).unwrap().expose();
        let mut salt = base.clone();
        salt.salt[0] ^= 1;
        let mut mem = base.clone();
        mem.params.m_kib += 1;
        let mut time = base.clone();
        time.params.t = 2;
        let keys = [key(&base), key(&salt), key(&mem), key(&time)];
        for i in 0..keys.len() {
            for j in 0..i {
                assert_ne!(keys[i], keys[j]);
            }
        }
        assert_ne!(
            keys[0],
            *derive_pass_key(&Passphrase::from_input("another passphrase"), &base)
                .unwrap()
                .expose()
        );
    }

    #[test]
    fn out_of_bounds_parameters_never_reach_argon2() {
        let pass = Passphrase::from_input(KAT_PASSPHRASE);
        let before = argon2_runs();
        for (m_kib, t, p) in [
            (4096, 1, 1),
            (8191, 1, 1),
            (524_289, 1, 1),
            (1_048_576, 1, 1),
            (u32::MAX, 1, 1),
            (8192, 0, 1),
            (8192, 5, 1),
            (8192, 1, 0),
            (8192, 1, 2),
        ] {
            let pre = KdfPreamble {
                params: KdfParams { m_kib, t, p },
                salt: [7; 16],
            };
            assert!(matches!(pre.params.validate(), Err(FormatError::KdfParams)));
            assert!(matches!(
                KdfPreamble::decode(&pre.encode()),
                Err(FormatError::KdfParams)
            ));
            assert!(matches!(
                derive_pass_key(&pass, &pre),
                Err(CryptoError::Kdf(_))
            ));
        }
        assert_eq!(argon2_runs(), before);
        derive_pass_key(&pass, &kat_preamble()).unwrap();
        assert_eq!(argon2_runs(), before + 1);
    }

    #[test]
    fn bounds_are_inclusive() {
        for (m_kib, t) in [
            (8192, 1),
            (8192, 4),
            (524_288, 1),
            (524_288, 4),
            (262_144, 3),
        ] {
            let pre = KdfPreamble {
                params: KdfParams { m_kib, t, p: 1 },
                salt: [7; 16],
            };
            pre.params.validate().unwrap();
            assert_eq!(KdfPreamble::decode(&pre.encode()).unwrap(), pre);
        }
        KdfParams::default().validate().unwrap();
    }

    #[test]
    fn preamble_decode_rejects() {
        let good = kat_preamble().encode();
        assert!(matches!(
            KdfPreamble::decode(&good[..35]),
            Err(FormatError::KeyfileDamaged)
        ));
        let with = |at: usize, v: u8| {
            let mut b = good;
            b[at] = v;
            KdfPreamble::decode(&b)
        };
        assert!(matches!(with(0, b'X'), Err(FormatError::KeyfileDamaged)));
        assert!(matches!(with(3, b'2'), Err(FormatError::KeyfileVersion(2))));
        assert!(matches!(with(3, b'x'), Err(FormatError::KeyfileDamaged)));
        assert!(matches!(with(4, 2), Err(FormatError::KdfParams)));
        assert!(matches!(with(5, 0x10), Err(FormatError::KdfParams)));
        assert!(matches!(with(6, 1), Err(FormatError::KdfParams)));
        assert!(matches!(with(7, 1), Err(FormatError::KdfParams)));
        // a longer input is fine: only the first 36 bytes are the preamble
        let mut longer = good.to_vec();
        longer.extend_from_slice(b"stream");
        assert_eq!(KdfPreamble::decode(&longer).unwrap(), kat_preamble());
    }
}

//! The calls of the API that need no index (design §5): the vault descriptor, the keyfiles
//! and the unlock, the key bundle, and what the Service Worker asks about a request.

use serde::Serialize;
use zeroize::Zeroizing;

use crate::consts::{KEYFILE_MAX, KEYFILE_TRY_MAX};
use crate::crypto::{
    HEADER_LEN, KdfPreamble, Keyring, MasterKey, PREAMBLE_LEN, Passphrase, TAG_LEN,
};
use crate::error::{CryptoError, FormatError};
use crate::format::{VaultDescriptor, open_keyfile, parse_keyfile_name};
use crate::web::{mime, rules};
use crate::{Code, Error, Result, util};

pub fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// ---------------------------------------------------------------------------------------------
// Descriptor
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct DescriptorJson {
    pub vault_id: String,
    pub min_reader: u32,
    pub created_ms: u64,
    /// `VaultDescriptor::readable()`: whether this build may open the vault at all.
    pub readable: bool,
}

/// A `gclone-vault.json`: an unauthenticated hint. `damaged`: not a descriptor.
pub fn parse_descriptor(bytes: &[u8]) -> Result<DescriptorJson> {
    let d = VaultDescriptor::parse(bytes).map_err(|e| Error::new(Code::Damaged, e.to_string()))?;
    Ok(DescriptorJson {
        readable: d.readable(),
        vault_id: d.vault_id,
        min_reader: d.min_reader,
        created_ms: d.created_ms,
    })
}

// ---------------------------------------------------------------------------------------------
// Keyfiles
// ---------------------------------------------------------------------------------------------

/// The keyfiles to look at among the names of a vault root: the `KEYFILE_TRY_MAX` highest
/// generations, highest first (ties: the greater name first) — the CLI's rule. Generations
/// are unauthenticated numbers until a keyfile opens. A name listed twice comes back twice.
pub fn keyfile_candidates(names: &[String]) -> Vec<String> {
    let mut found: Vec<(u32, &String)> = names
        .iter()
        .filter_map(|name| Some((parse_keyfile_name(name)?.0, name)))
        .collect();
    found.sort_by(|a, b| b.cmp(a));
    found
        .into_iter()
        .take(KEYFILE_TRY_MAX)
        .map(|(_, name)| name.clone())
        .collect()
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct CostJson {
    #[serde(rename = "gen")]
    pub generation: u32,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

fn keyfile_error(e: FormatError) -> Error {
    match e {
        FormatError::Crypto(CryptoError::WrongKey) => Error::new(
            Code::WrongPassphrase,
            "the passphrase does not open this keyfile",
        ),
        // The CLI's rule (`cli::login::unlock`): a keyfile version is "newer"; anything else
        // that keeps a keyfile from opening is damage.
        FormatError::KeyfileVersion(_) => Error::new(Code::NeedsNewer, e.to_string()),
        e => Error::new(Code::Damaged, e.to_string()),
    }
}

/// What unlocking with this keyfile will cost, read before any work is done and checked
/// against the format's bounds (a planted keyfile cannot ask for more than 512 MiB and four
/// passes — it can ask for that). The checks `open_keyfile` makes before it derives a key, in
/// its order: name, size, the name's hash, the KDF preamble.
pub fn keyfile_cost(name: &str, bytes: &[u8]) -> Result<CostJson> {
    let damaged = || keyfile_error(FormatError::KeyfileDamaged);
    let (generation, h8) = parse_keyfile_name(name)
        .ok_or_else(|| Error::new(Code::BadInput, "not the name of a keyfile"))?;
    if bytes.len() < PREAMBLE_LEN + HEADER_LEN + TAG_LEN || bytes.len() as u64 > KEYFILE_MAX {
        return Err(damaged());
    }
    if blake3::hash(bytes).as_bytes()[..4] != h8 {
        return Err(damaged());
    }
    let pre = KdfPreamble::decode(bytes).map_err(keyfile_error)?;
    Ok(CostJson {
        generation,
        m_kib: pre.params.m_kib,
        t: pre.params.t,
        p: pre.params.p,
    })
}

fn vault_id_of(hex: &str) -> Result<[u8; 16]> {
    util::unhex(hex)
        .and_then(|v| <[u8; 16]>::try_from(v).ok())
        .ok_or_else(|| Error::new(Code::BadInput, "vault_id is not 32 lowercase hex digits"))
}

/// Argon2id and the keyfile (§2.6): the key bundle of the vault `vault_id` (32 hex digits —
/// the chosen descriptor's). Blocking and memory-hungry (the keyfile's `m_kib`).
///
/// `wrong-passphrase`: the keyfile is intact and this is not its passphrase. `needs-newer`: a
/// keyfile version this build does not read. `other-vault`: it opened, and it belongs to
/// another vault. `damaged`: anything else.
pub fn unlock(
    keyfile_name: &str,
    keyfile: &[u8],
    passphrase: &str,
    vault_id: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let vault_id = vault_id_of(vault_id)?;
    let pass = Passphrase::from_input(passphrase);
    let payload = open_keyfile(keyfile_name, keyfile, &pass).map_err(keyfile_error)?;
    if payload.vault_id_bytes().map_err(keyfile_error)? != vault_id {
        return Err(Error::new(
            Code::OtherVault,
            "this keyfile belongs to another vault",
        ));
    }
    let keys = payload.keyring().map_err(keyfile_error)?;
    Ok(bundle_of(&keys))
}

// ---------------------------------------------------------------------------------------------
// The key bundle: what crosses from the KDF worker to the vault worker
// ---------------------------------------------------------------------------------------------

const BUNDLE_VERSION: u8 = 1;
const BUNDLE_HEAD: usize = 1 + 16 + 4 + 4;
const BUNDLE_KEY: usize = 4 + 32;

/// `0x01 ‖ vault_id(16) ‖ min_epoch u32 ‖ n u32 ‖ n × (epoch u32 ‖ key(32))`, integers big-endian.
pub fn bundle_of(keys: &Keyring) -> Zeroizing<Vec<u8>> {
    let exported = keys.export();
    let mut out = Zeroizing::new(Vec::with_capacity(
        BUNDLE_HEAD + BUNDLE_KEY * exported.len(),
    ));
    out.push(BUNDLE_VERSION);
    out.extend_from_slice(&keys.vault_id());
    out.extend_from_slice(&keys.min_epoch().to_be_bytes());
    out.extend_from_slice(&(exported.len() as u32).to_be_bytes());
    for (epoch, key) in &exported {
        out.extend_from_slice(&epoch.to_be_bytes());
        out.extend_from_slice(key.as_slice());
    }
    out
}

/// The keyring of a bundle. `bad-input` for anything that is not exactly a bundle.
pub fn keys_of(bundle: &[u8]) -> Result<Keyring> {
    let malformed = || Error::new(Code::BadInput, "not a key bundle of this viewer");
    let Some((head, body)) = bundle.split_first_chunk::<BUNDLE_HEAD>() else {
        return Err(malformed());
    };
    let word = |at: usize| u32::from_be_bytes([head[at], head[at + 1], head[at + 2], head[at + 3]]);
    let (entries, rest) = body.as_chunks::<BUNDLE_KEY>();
    if head[0] != BUNDLE_VERSION || !rest.is_empty() || entries.len() != word(21) as usize {
        return Err(malformed());
    }
    let mut vault_id = [0u8; 16];
    vault_id.copy_from_slice(&head[1..17]);
    let mut keys = Vec::with_capacity(entries.len());
    for entry in entries {
        let epoch = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&entry[4..]);
        keys.push((epoch, MasterKey::from_bytes(*key)));
    }
    Keyring::new(vault_id, keys, word(17)).map_err(|_| malformed())
}

// ---------------------------------------------------------------------------------------------
// For the Service Worker
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct ServedJson {
    /// How the viewer shows the file (`mime::Kind`), whatever it is served as.
    pub kind: &'static str,
    /// `Content-Type`.
    pub mime: &'static str,
    /// `Content-Security-Policy` of the answer that carries the file's bytes.
    pub csp: &'static str,
    /// `Content-Disposition`.
    pub disposition: String,
}

/// The headers of an answer that carries the bytes of a vault file called `name`: the local
/// viewer's (`mime::of_name`, `Served::csp`, `content_disposition`). `download`: the file is
/// to be saved, not shown — `application/octet-stream` and `attachment` whatever its kind
/// (iOS Safari opens a "download" that carries a type it can display in the tab).
pub fn served(name: &str, download: bool) -> ServedJson {
    let real = mime::of_name(name);
    let as_file = mime::Served {
        kind: mime::Kind::Other,
        mime: "application/octet-stream",
    };
    let served = if download { as_file } else { real };
    ServedJson {
        kind: real.kind.as_str(),
        mime: served.mime,
        csp: served.csp(),
        disposition: rules::content_disposition(served.inline() && !download, name),
    }
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct RangeJson {
    /// `"whole"` (answer `200`), `"range"` (`206`) or `"unsatisfiable"` (`416`).
    pub kind: &'static str,
    /// The plaintext bytes to send: `start..end` (both 0 for `unsatisfiable`).
    pub start: u64,
    pub end: u64,
}

/// One `Range` header against a file of `size` bytes, by the local viewer's rule.
pub fn parse_range(header: Option<&str>, size: u64) -> RangeJson {
    match rules::parse_range(header, size) {
        rules::ByteRange::Whole => RangeJson {
            kind: "whole",
            start: 0,
            end: size,
        },
        rules::ByteRange::Part(range) => RangeJson {
            kind: "range",
            start: range.start,
            end: range.end,
        },
        rules::ByteRange::Unsatisfiable => RangeJson {
            kind: "unsatisfiable",
            start: 0,
            end: 0,
        },
    }
}

/// Drive's `createdTime` (RFC 3339) in milliseconds, as the CLI parses it.
pub fn parse_rfc3339_ms(s: &str) -> Option<u64> {
    util::parse_rfc3339_ms(s)
}

/// One Argon2id derivation with the given cost and a fixed salt — for measuring a device
/// (the `bench` feature only; the caller takes the time).
#[cfg(feature = "bench")]
pub fn kdf_bench(m_kib: u32, t: u32) -> Result<()> {
    let pre = KdfPreamble {
        params: crate::crypto::KdfParams { m_kib, t, p: 1 },
        salt: [7; 16],
    };
    crate::crypto::derive_pass_key(&Passphrase::from_input("benchmark passphrase"), &pre)
        .map(drop)
        .map_err(|e| Error::new(Code::BadInput, e.to_string()))
}

//! Stream container (SPEC §4.2, §9.4). The only ciphertext format.
//!
//! ```text
//! header(60) = "GCS1" ‖ suite ‖ chunk_log2 ‖ type ‖ flags ‖ key_epoch(u32 BE) ‖ salt(16) ‖ commit(32)
//! OKM(64)    = HKDF-SHA-256(salt = header.salt, ikm = K_purpose, info = "gclone/v1/stream" ‖ 0x00 ‖ header[0..12])
//! stream_key = OKM[0..32]      commit = OKM[32..64]
//! chunk i    = ChaCha20-Poly1305(stream_key, nonce = 0x000000 ‖ u64_be(i) ‖ final, aad = "", pt_i) → ct_i ‖ tag(16)
//! ```
//! All length functions take a `chunk_log2` that the caller has already checked to be in
//! 12..=24 (`Header::decode`, `Keyring::data_opener` and index acceptance do).

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};
use zeroize::Zeroizing;

use super::hkdf_sha256;
use super::keys::{Purpose, PurposeKey};
use crate::consts::{CHUNK_LOG2_MAX, CHUNK_LOG2_MIN};
use crate::error::CryptoError;
use crate::types::Loc;
use crate::util;

pub const HEADER_LEN: usize = crate::consts::HEADER_LEN;
pub const TAG_LEN: usize = crate::consts::TAG_LEN;
pub const MAGIC: [u8; 4] = *b"GCS1";
pub const SUITE_V1: u8 = 1;

/// `header[0..12]`: everything before the salt. It is bound into the stream key through the HKDF
/// `info`, which authenticates suite, chunk size, type, flags and epoch.
const PREFIX_LEN: usize = 12;
const SALT_END: usize = PREFIX_LEN + 16;
const STREAM_INFO: &[u8; 17] = b"gclone/v1/stream\0";

/// 4 is reserved (blob manifest) and rejected as `Unsupported`.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum StreamType {
    Data = 1,
    Segment = 2,
    Snapshot = 3,
    Bundle = 5,
}

impl StreamType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(StreamType::Data),
            2 => Some(StreamType::Segment),
            3 => Some(StreamType::Snapshot),
            5 => Some(StreamType::Bundle),
            _ => None,
        }
    }

    /// Bundle → `None` (its key is `K_pass`, §2.6).
    pub fn purpose(self) -> Option<Purpose> {
        match self {
            StreamType::Data => Some(Purpose::Data),
            StreamType::Segment | StreamType::Snapshot => Some(Purpose::Index),
            StreamType::Bundle => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub suite: u8,
    pub chunk_log2: u8,
    pub ty: StreamType,
    pub flags: u8,
    pub epoch: u32,
    pub salt: [u8; 16],
    pub commit: [u8; 32],
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[..PREFIX_LEN].copy_from_slice(&prefix(
            self.suite,
            self.chunk_log2,
            self.ty,
            self.flags,
            self.epoch,
        ));
        b[PREFIX_LEN..SALT_END].copy_from_slice(&self.salt);
        b[SALT_END..].copy_from_slice(&self.commit);
        b
    }

    /// Steps 1–2 of the §4.2 precedence: `Truncated`, `BadMagic`, then `Unsupported` for suite,
    /// `chunk_log2` range, type, flags (in that order). Reads the first 60 bytes of `b`.
    pub fn decode(b: &[u8]) -> Result<Header, CryptoError> {
        let Some(b) = b.first_chunk::<HEADER_LEN>() else {
            return Err(CryptoError::Truncated);
        };
        if b[..4] != MAGIC {
            return Err(CryptoError::BadMagic);
        }
        let (suite, chunk_log2, flags) = (b[4], b[5], b[7]);
        if suite != SUITE_V1 {
            return Err(CryptoError::Unsupported("stream suite"));
        }
        if !chunk_log2_ok(chunk_log2) {
            return Err(CryptoError::Unsupported("stream chunk size"));
        }
        let Some(ty) = StreamType::from_u8(b[6]) else {
            return Err(CryptoError::Unsupported("stream type"));
        };
        if flags != 0 {
            return Err(CryptoError::Unsupported("stream flags"));
        }
        let mut epoch = [0u8; 4];
        epoch.copy_from_slice(&b[8..PREFIX_LEN]);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&b[PREFIX_LEN..SALT_END]);
        let mut commit = [0u8; 32];
        commit.copy_from_slice(&b[SALT_END..]);
        Ok(Header {
            suite,
            chunk_log2,
            ty,
            flags,
            epoch: u32::from_be_bytes(epoch),
            salt,
            commit,
        })
    }
}

fn prefix(suite: u8, chunk_log2: u8, ty: StreamType, flags: u8, epoch: u32) -> [u8; PREFIX_LEN] {
    let mut p = [0u8; PREFIX_LEN];
    p[..4].copy_from_slice(&MAGIC);
    p[4] = suite;
    p[5] = chunk_log2;
    p[6] = ty as u8;
    p[7] = flags;
    p[8..].copy_from_slice(&epoch.to_be_bytes());
    p
}

fn chunk_log2_ok(chunk_log2: u8) -> bool {
    (CHUNK_LOG2_MIN..=CHUNK_LOG2_MAX).contains(&chunk_log2)
}

/// What a v1 reader can open at all, checked before any key is derived (§4.2 "Data streams and
/// the index"): an unknown suite, non-zero flags or an out-of-range chunk size is `Unsupported`.
pub(super) fn check_loc(loc: &Loc) -> Result<(), CryptoError> {
    if loc.suite != SUITE_V1 {
        return Err(CryptoError::Unsupported("stream suite"));
    }
    if loc.flags != 0 {
        return Err(CryptoError::Unsupported("stream flags"));
    }
    if !chunk_log2_ok(loc.chunk_log2) {
        return Err(CryptoError::Unsupported("stream chunk size"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// lengths and offsets
// ---------------------------------------------------------------------------------------------

fn chunk_size(chunk_log2: u8) -> u64 {
    1u64 << chunk_log2
}

/// `max(1, ceil(n / C))`
pub fn chunk_count(plain_len: u64, chunk_log2: u8) -> u64 {
    plain_len.div_ceil(chunk_size(chunk_log2)).max(1)
}

/// `60 + n + 16 * chunks(n)`; `None` where that does not fit in a `u64`.
pub(crate) fn checked_ciphertext_len(plain_len: u64, chunk_log2: u8) -> Option<u64> {
    chunk_count(plain_len, chunk_log2)
        .checked_mul(TAG_LEN as u64)?
        .checked_add(plain_len)?
        .checked_add(HEADER_LEN as u64)
}

/// `60 + n + 16 * chunks(n)`, saturating at `u64::MAX` (reached only by lengths no object has).
pub fn ciphertext_len(plain_len: u64, chunk_log2: u8) -> u64 {
    checked_ciphertext_len(plain_len, chunk_log2).unwrap_or(u64::MAX)
}

/// Inverse of [`ciphertext_len`]; `None` for a length no container has (§4.2).
pub fn plaintext_len(cipher_len: u64, chunk_log2: u8) -> Option<u64> {
    let tag = TAG_LEN as u64;
    let body = cipher_len.checked_sub(HEADER_LEN as u64)?;
    if body < tag {
        return None;
    }
    let c = chunk_size(chunk_log2);
    let (q, r) = (body / (c + tag), body % (c + tag));
    match r {
        // the last chunk is full
        0 => Some(q * c),
        // shorter than a tag
        r if r < tag => None,
        // an empty chunk is legal only as the single chunk of an empty plaintext
        r if r == tag => (q == 0).then_some(0),
        r => Some(q * c + r - tag),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkSpan {
    pub first: u64,
    /// Inclusive.
    pub last: u64,
    /// Relative to the container start.
    pub cipher: std::ops::Range<u64>,
    /// Plaintext bytes to drop from chunk `first`.
    pub skip: usize,
}

/// The chunks that hold `plain` of a stream with `plain_len` plaintext bytes.
/// `None` if the range is empty or out of bounds.
pub fn chunk_range(
    plain: std::ops::Range<u64>,
    plain_len: u64,
    chunk_log2: u8,
) -> Option<ChunkSpan> {
    if plain.start >= plain.end || plain.end > plain_len {
        return None;
    }
    let c = chunk_size(chunk_log2);
    let full = c + TAG_LEN as u64;
    let first = plain.start / c;
    let last = (plain.end - 1) / c;
    let start = first.checked_mul(full)?.checked_add(HEADER_LEN as u64)?;
    let end = last
        .checked_mul(full)?
        .checked_add(HEADER_LEN as u64)?
        .checked_add(chunk_cipher_len(last, plain_len, chunk_log2) as u64)?;
    Some(ChunkSpan {
        first,
        last,
        cipher: start..end,
        skip: (plain.start - first * c) as usize,
    })
}

/// ct+tag length of chunk `idx` of a stream with `plain_len` plaintext bytes; 0 if the stream
/// has no such chunk.
pub fn chunk_cipher_len(idx: u64, plain_len: u64, chunk_log2: u8) -> usize {
    let c = chunk_size(chunk_log2);
    let chunks = chunk_count(plain_len, chunk_log2);
    if idx >= chunks {
        0
    } else if idx + 1 < chunks {
        c as usize + TAG_LEN
    } else {
        (plain_len - idx * c) as usize + TAG_LEN
    }
}

// ---------------------------------------------------------------------------------------------
// key derivation and the AEAD (the only calls into `hkdf` / `chacha20poly1305` for streams)
// ---------------------------------------------------------------------------------------------

/// `(stream_key, commit)` of §4.2.
fn derive(
    key: &PurposeKey,
    prefix: &[u8; PREFIX_LEN],
    salt: &[u8; 16],
) -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let mut info = [0u8; STREAM_INFO.len() + PREFIX_LEN];
    info[..STREAM_INFO.len()].copy_from_slice(STREAM_INFO);
    info[STREAM_INFO.len()..].copy_from_slice(prefix);
    let mut okm = Zeroizing::new([0u8; 64]);
    hkdf_sha256(salt, key.expose(), &info, okm.as_mut());
    let mut stream_key = Zeroizing::new([0u8; 32]);
    stream_key.copy_from_slice(&okm[..32]);
    let mut commit = [0u8; 32];
    commit.copy_from_slice(&okm[32..]);
    (stream_key, commit)
}

/// 11-byte big-endian counter ‖ final flag, as in age: the three leading bytes stay zero.
fn nonce(idx: u64, last: bool) -> Nonce {
    let mut n = [0u8; 12];
    n[3..11].copy_from_slice(&idx.to_be_bytes());
    n[11] = last as u8;
    Nonce::from(n)
}

/// Appends `ct ‖ tag` to `out`.
fn aead_seal(
    key: &[u8; 32],
    idx: u64,
    last: bool,
    pt: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), CryptoError> {
    let start = out.len();
    out.reserve(pt.len() + TAG_LEN);
    out.extend_from_slice(pt);
    let sealed = ChaCha20Poly1305::new(key.into()).encrypt_inout_detached(
        &nonce(idx, last),
        b"",
        (&mut out[start..]).into(),
    );
    match sealed {
        Ok(tag) => {
            out.extend_from_slice(&tag);
            Ok(())
        }
        Err(_) => {
            // Never leave unencrypted plaintext in an output buffer.
            out[start..].fill(0);
            out.truncate(start);
            Err(CryptoError::Misuse("chunk too large for the AEAD"))
        }
    }
}

/// Appends the plaintext of `ct ‖ tag` to `out`; on a tag failure `out` is left as it was.
fn aead_open(
    key: &[u8; 32],
    idx: u64,
    last: bool,
    ct: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), CryptoError> {
    let Some((body, tag)) = ct.split_last_chunk::<TAG_LEN>() else {
        return Err(CryptoError::Corrupt);
    };
    let start = out.len();
    out.extend_from_slice(body);
    // The cipher verifies the tag before it touches the buffer: after a failure `out[start..]`
    // still holds ciphertext, which is then cut off again.
    let opened = ChaCha20Poly1305::new(key.into()).decrypt_inout_detached(
        &nonce(idx, last),
        b"",
        (&mut out[start..]).into(),
        &Tag::from(*tag),
    );
    if opened.is_err() {
        out.truncate(start);
        return Err(CryptoError::Corrupt);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Sealer
// ---------------------------------------------------------------------------------------------

/// Seals chunks strictly in order, exactly once each. No public constructor takes a salt or nonce.
pub struct Sealer {
    key: Zeroizing<[u8; 32]>,
    header: [u8; HEADER_LEN],
    chunk: usize,
    next: u64,
    finished: bool,
}

impl Sealer {
    /// Fresh random salt; NO salt/nonce parameter.
    ///
    /// # Panics
    /// If `chunk_log2` is outside 12..=24: such a stream could not be opened by any reader.
    pub fn new(key: &PurposeKey, ty: StreamType, epoch: u32, chunk_log2: u8) -> Sealer {
        Sealer::with_salt(key, ty, epoch, chunk_log2, util::random())
    }

    fn with_salt(
        key: &PurposeKey,
        ty: StreamType,
        epoch: u32,
        chunk_log2: u8,
        salt: [u8; 16],
    ) -> Sealer {
        assert!(
            chunk_log2_ok(chunk_log2),
            "Sealer: chunk_log2 {chunk_log2} is outside 12..=24"
        );
        let prefix = prefix(SUITE_V1, chunk_log2, ty, 0, epoch);
        let (key, commit) = derive(key, &prefix, &salt);
        let mut header = [0u8; HEADER_LEN];
        header[..PREFIX_LEN].copy_from_slice(&prefix);
        header[PREFIX_LEN..SALT_END].copy_from_slice(&salt);
        header[SALT_END..].copy_from_slice(&commit);
        Sealer {
            key,
            header,
            chunk: 1 << chunk_log2,
            next: 0,
            finished: false,
        }
    }

    /// The fixed-salt constructor of the known-answer tests (§4.7); unit tests of this file only.
    #[cfg(test)]
    fn with_salt_for_tests(
        key: &PurposeKey,
        ty: StreamType,
        epoch: u32,
        chunk_log2: u8,
        salt: [u8; 16],
    ) -> Sealer {
        Sealer::with_salt(key, ty, epoch, chunk_log2, salt)
    }

    pub fn header(&self) -> [u8; HEADER_LEN] {
        self.header
    }

    pub fn salt(&self) -> [u8; 16] {
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&self.header[PREFIX_LEN..SALT_END]);
        salt
    }

    /// Appends ct‖tag to `out`. Errors (`Misuse`): called after the final chunk; `pt.len() > C`;
    /// `pt.len() < C` and `!last`; empty `pt` unless it is the first and final chunk.
    pub fn seal_chunk(
        &mut self,
        pt: &[u8],
        last: bool,
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        if self.finished {
            return Err(CryptoError::Misuse("chunk after the final chunk"));
        }
        if pt.len() > self.chunk {
            return Err(CryptoError::Misuse("chunk longer than the chunk size"));
        }
        if pt.len() < self.chunk && !last {
            return Err(CryptoError::Misuse("short chunk that is not the final one"));
        }
        if pt.is_empty() && self.next != 0 {
            return Err(CryptoError::Misuse(
                "empty final chunk after a non-empty stream",
            ));
        }
        if self.next == u64::MAX {
            return Err(CryptoError::Misuse("too many chunks"));
        }
        aead_seal(&self.key, self.next, last, pt, out)?;
        self.next += 1;
        self.finished = last;
        Ok(())
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

// ---------------------------------------------------------------------------------------------
// Opener
// ---------------------------------------------------------------------------------------------

pub struct Opener {
    key: Zeroizing<[u8; 32]>,
    header: [u8; HEADER_LEN],
    chunk_log2: u8,
}

impl Opener {
    /// For self-describing streams (index objects, keyfile): `Header::decode`, then
    /// type != expect → `WrongKey`, then commit → `WrongKey`. Reads the first 60 bytes of `header`.
    pub fn from_header(
        key: &PurposeKey,
        header: &[u8],
        expect: StreamType,
    ) -> Result<Opener, CryptoError> {
        let h = Header::decode(header)?;
        if h.ty != expect {
            return Err(CryptoError::WrongKey);
        }
        let header = h.encode();
        let (key, commit) = derive(key, &prefix_of(&header), &h.salt);
        if !util::ct_eq(&commit, &h.commit) {
            return Err(CryptoError::WrongKey);
        }
        Ok(Opener {
            key,
            header,
            chunk_log2: h.chunk_log2,
        })
    }

    /// For Data streams: everything comes from the index entry; the stored header is never
    /// trusted. Callers normally use `Keyring::data_opener`, which performs the
    /// suite/flags/epoch checks first (suite, flags and chunk size are checked here as well).
    pub fn for_data(key: &PurposeKey, loc: &Loc) -> Result<Opener, CryptoError> {
        check_loc(loc)?;
        let prefix = prefix(
            loc.suite,
            loc.chunk_log2,
            StreamType::Data,
            loc.flags,
            loc.epoch,
        );
        let (key, commit) = derive(key, &prefix, &loc.salt);
        let mut header = [0u8; HEADER_LEN];
        header[..PREFIX_LEN].copy_from_slice(&prefix);
        header[PREFIX_LEN..SALT_END].copy_from_slice(&loc.salt);
        header[SALT_END..].copy_from_slice(&commit);
        Ok(Opener {
            key,
            header,
            chunk_log2: loc.chunk_log2,
        })
    }

    /// The 60 header bytes this opener belongs to. For a Data stream they are recomputed from
    /// the index entry: a full read compares them with the stored header (mismatch = `Corrupt`).
    pub fn expected_header(&self) -> [u8; HEADER_LEN] {
        self.header
    }

    pub fn chunk_log2(&self) -> u8 {
        self.chunk_log2
    }

    /// A **ticket**: what opens the chunks of this one stream and nothing else — its stream
    /// key and the 60 header bytes it belongs to. For a reader that must hold neither a
    /// purpose key nor a master key (the hosted viewer's Service Worker gets one ticket per
    /// opened file). The stream key is `HKDF(K_purpose, salt, …)[0..32]` of this stream: no
    /// other stream's key, no purpose key and no master key can be derived from it.
    pub fn export_ticket(&self) -> (Zeroizing<[u8; 32]>, [u8; HEADER_LEN]) {
        (self.key.clone(), self.header)
    }

    /// The opener of the Data stream a ticket was exported from ([`Opener::export_ticket`]).
    /// `header` must be exactly the 60 header bytes of a Data stream this build can read
    /// (`Truncated`, `TrailingData`, `BadMagic`, `Unsupported` as in [`Header::decode`]; another
    /// stream type is `WrongKey`). The commitment in the header cannot be checked here — it is
    /// derived from the purpose key, which a ticket deliberately does not carry — so the key is
    /// taken on trust from whoever issued the ticket; every chunk is still authenticated under
    /// it, so a wrong key opens nothing.
    pub fn from_ticket(key: Zeroizing<[u8; 32]>, header: &[u8]) -> Result<Opener, CryptoError> {
        if header.len() > HEADER_LEN {
            return Err(CryptoError::TrailingData);
        }
        let h = Header::decode(header)?;
        if h.ty != StreamType::Data {
            return Err(CryptoError::WrongKey);
        }
        Ok(Opener {
            key,
            header: h.encode(),
            chunk_log2: h.chunk_log2,
        })
    }

    /// `ct` = exactly one chunk's ct‖tag; appends plaintext to `out` only after the tag
    /// verified. `Corrupt` on failure — also for a chunk whose length no stream can contain: a
    /// non-final chunk that is not full, a chunk longer than `C + 16`, or an empty chunk other
    /// than the single chunk of an empty stream.
    pub fn open_chunk(
        &self,
        idx: u64,
        last: bool,
        ct: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let full = (1usize << self.chunk_log2) + TAG_LEN;
        let well_formed = if last {
            ct.len() <= full && (ct.len() > TAG_LEN || (ct.len() == TAG_LEN && idx == 0))
        } else {
            ct.len() == full
        };
        if !well_formed || idx == u64::MAX {
            return Err(CryptoError::Corrupt);
        }
        aead_open(&self.key, idx, last, ct, out)
    }

    /// Opens everything after the header. A verified final chunk must end the input.
    fn open_body(&self, body: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let full = (1usize << self.chunk_log2) + TAG_LEN;
        // Reserved up front so that plaintext is never copied to a second allocation.
        let mut out = Zeroizing::new(Vec::with_capacity(body.len()));
        let mut rest = body;
        let mut idx = 0u64;
        loop {
            if rest.len() < TAG_LEN {
                // End of input (or a cut inside a tag) without a verified final chunk.
                return Err(CryptoError::Truncated);
            }
            if rest.len() > full {
                let (chunk, tail) = rest.split_at(full);
                if self.open_chunk(idx, false, chunk, &mut out).is_err() {
                    // A verified final chunk with bytes after it is trailing data; anything
                    // else is damage.
                    return Err(match self.open_chunk(idx, true, chunk, &mut out) {
                        Ok(()) => CryptoError::TrailingData,
                        Err(_) => CryptoError::Corrupt,
                    });
                }
                rest = tail;
                idx += 1;
            } else {
                return match self.open_chunk(idx, true, rest, &mut out) {
                    Ok(()) => Ok(out),
                    // A verified non-final chunk at the end of the input: cut at a chunk boundary.
                    Err(_)
                        if rest.len() == full
                            && self.open_chunk(idx, false, rest, &mut out).is_ok() =>
                    {
                        Err(CryptoError::Truncated)
                    }
                    Err(e) => Err(e),
                };
            }
        }
    }
}

fn prefix_of(header: &[u8; HEADER_LEN]) -> [u8; PREFIX_LEN] {
    let mut p = [0u8; PREFIX_LEN];
    p.copy_from_slice(&header[..PREFIX_LEN]);
    p
}

/// A whole container in memory (index objects, the keyfile body).
///
/// # Panics
/// If `chunk_log2` is outside 12..=24 (see [`Sealer::new`]).
pub fn seal_all(
    key: &PurposeKey,
    ty: StreamType,
    epoch: u32,
    chunk_log2: u8,
    pt: &[u8],
) -> Vec<u8> {
    let mut sealer = Sealer::new(key, ty, epoch, chunk_log2);
    seal_with(&mut sealer, pt)
}

fn seal_with(sealer: &mut Sealer, pt: &[u8]) -> Vec<u8> {
    let chunk_log2 = sealer.header[5];
    let mut out = Vec::with_capacity(ciphertext_len(pt.len() as u64, chunk_log2) as usize);
    out.extend_from_slice(&sealer.header);
    let mut rest = pt;
    loop {
        let (chunk, tail) = rest.split_at(rest.len().min(sealer.chunk));
        // Full chunks followed by one final chunk, empty only for an empty plaintext: none of
        // the misuse cases of `seal_chunk` can occur.
        sealer
            .seal_chunk(chunk, tail.is_empty(), &mut out)
            .expect("seal_all splits its input by the chunk rules");
        if tail.is_empty() {
            return out;
        }
        rest = tail;
    }
}

/// `Truncated` / `TrailingData` / `Corrupt` / `WrongKey` (and the header errors of
/// [`Header::decode`]). No plaintext is returned unless every chunk verified.
///
/// The container does not record its length, so the last `≤ C + 16` bytes are taken as the
/// final chunk. Bytes after a *full* final chunk are `TrailingData`; bytes appended to a
/// shorter one cannot be told from damage to it and are `Corrupt`. A stream cut at a chunk
/// boundary is `Truncated`.
pub fn open_all(
    key: &PurposeKey,
    ty: StreamType,
    container: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let opener = Opener::from_header(key, container, ty)?;
    opener.open_body(&container[HEADER_LEN..])
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::{Keyring, MasterKey};
    use chacha20poly1305::aead::Aead;
    use hkdf::Hkdf;
    use sha2::Sha256;

    // ---- fixed inputs of §4.7 ----

    pub(crate) const KAT_MK: [u8; 32] = seq::<32>(0x00);
    pub(crate) const KAT_VAULT_ID: [u8; 16] = seq::<16>(0xa0);
    const KAT_SALT: [u8; 16] = seq::<16>(0xc0);
    const KAT_EPOCH: u32 = 1;
    /// Stands in for `K_pass` in the Bundle vector.
    const KAT_BUNDLE_KEY: [u8; 32] = seq::<32>(0x40);

    const fn seq<const N: usize>(start: u8) -> [u8; N] {
        let mut a = [0u8; N];
        let mut i = 0;
        while i < N {
            a[i] = start + i as u8;
            i += 1;
        }
        a
    }

    pub(crate) fn kat_plaintext(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 7 + 3) % 256) as u8).collect()
    }

    pub(crate) fn kat_keyring() -> Keyring {
        Keyring::new(
            KAT_VAULT_ID,
            vec![(KAT_EPOCH, MasterKey::from_bytes(KAT_MK))],
            KAT_EPOCH,
        )
        .unwrap()
    }

    /// The frozen vector file (generated once by `gen_vectors`, then committed).
    pub(crate) fn frozen() -> serde_json::Value {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/stream_v1.json"
        )))
        .expect("tests/vectors/stream_v1.json is valid JSON")
    }

    pub(crate) fn frozen_bytes(v: &serde_json::Value) -> Vec<u8> {
        util::unhex(v.as_str().expect("a hex string")).expect("lowercase hex")
    }

    /// `(type, chunk_log2, plaintext length, full container stored in the file)`. The lengths of
    /// §4.7 at chunk_log2 12, the production chunk size, and one stream per non-Data type.
    const CASES: &[(StreamType, u8, usize, bool)] = &[
        (StreamType::Data, 12, 0, true),
        (StreamType::Data, 12, 1, true),
        (StreamType::Data, 12, 4095, true),
        (StreamType::Data, 12, 4096, true),
        (StreamType::Data, 12, 4097, true),
        (StreamType::Data, 16, 0, true),
        (StreamType::Data, 16, 1, true),
        (StreamType::Data, 16, 65535, false),
        (StreamType::Data, 16, 65536, false),
        (StreamType::Data, 16, 65537, false),
        (StreamType::Data, 16, 200_000, false),
        (StreamType::Segment, 12, 4097, true),
        (StreamType::Snapshot, 16, 1, true),
        (StreamType::Bundle, 16, 1, true),
    ];

    fn type_name(ty: StreamType) -> &'static str {
        match ty {
            StreamType::Data => "data",
            StreamType::Segment => "segment",
            StreamType::Snapshot => "snapshot",
            StreamType::Bundle => "bundle",
        }
    }

    // ---- the independent computation: raw hkdf + chacha20poly1305, nothing from this module ----

    fn reference_purpose_key(label: &str) -> [u8; 32] {
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&KAT_VAULT_ID), &KAT_MK)
            .expand(format!("gclone/v1/key/{label}").as_bytes(), &mut key)
            .unwrap();
        key
    }

    fn reference_key(ty: StreamType) -> ([u8; 32], u32) {
        match ty {
            StreamType::Data => (reference_purpose_key("data"), KAT_EPOCH),
            StreamType::Segment | StreamType::Snapshot => {
                (reference_purpose_key("index"), KAT_EPOCH)
            }
            StreamType::Bundle => (KAT_BUNDLE_KEY, 0),
        }
    }

    fn reference_container(ty: StreamType, chunk_log2: u8, pt: &[u8]) -> Vec<u8> {
        let (purpose_key, epoch) = reference_key(ty);
        let mut out = b"GCS1".to_vec();
        out.extend_from_slice(&[0x01, chunk_log2, ty as u8, 0x00]);
        out.extend_from_slice(&epoch.to_be_bytes());
        let mut info = b"gclone/v1/stream".to_vec();
        info.push(0x00);
        info.extend_from_slice(&out);
        let (prk, _) = Hkdf::<Sha256>::extract(Some(&KAT_SALT), &purpose_key);
        let mut okm = [0u8; 64];
        Hkdf::<Sha256>::from_prk(&prk)
            .unwrap()
            .expand(&info, &mut okm)
            .unwrap();
        out.extend_from_slice(&KAT_SALT);
        out.extend_from_slice(&okm[32..]);
        let cipher = ChaCha20Poly1305::new_from_slice(&okm[..32]).unwrap();
        let chunks: Vec<&[u8]> = if pt.is_empty() {
            vec![pt]
        } else {
            pt.chunks(1 << chunk_log2).collect()
        };
        for (i, chunk) in chunks.iter().enumerate() {
            let mut nonce = [0u8; 12];
            nonce[3..11].copy_from_slice(&(i as u64).to_be_bytes());
            nonce[11] = u8::from(i + 1 == chunks.len());
            out.extend_from_slice(&cipher.encrypt(&Nonce::from(nonce), *chunk).unwrap());
        }
        out
    }

    // ---- the implementation under test, with the fixed salt ----

    fn kat_key(ty: StreamType) -> (PurposeKey, u32) {
        match ty.purpose() {
            Some(p) => (kat_keyring().purpose(KAT_EPOCH, p).unwrap(), KAT_EPOCH),
            None => (PurposeKey::from_raw(KAT_BUNDLE_KEY), 0),
        }
    }

    fn sealed_container(ty: StreamType, chunk_log2: u8, pt: &[u8]) -> Vec<u8> {
        let (key, epoch) = kat_key(ty);
        let mut sealer = Sealer::with_salt_for_tests(&key, ty, epoch, chunk_log2, KAT_SALT);
        assert_eq!(sealer.salt(), KAT_SALT);
        let out = seal_with(&mut sealer, pt);
        assert!(sealer.is_finished());
        out
    }

    #[test]
    fn purpose_keys_match_raw_hkdf() {
        let keys = kat_keyring();
        for (purpose, label) in [(Purpose::Data, "data"), (Purpose::Index, "index")] {
            assert_eq!(
                keys.purpose(KAT_EPOCH, purpose).unwrap().expose(),
                &reference_purpose_key(label)
            );
        }
        assert_ne!(
            reference_purpose_key("data"),
            reference_purpose_key("index")
        );
    }

    #[test]
    fn kat_matches_independent_computation() {
        for &(ty, chunk_log2, len, _) in CASES {
            let pt = kat_plaintext(len);
            let sealed = sealed_container(ty, chunk_log2, &pt);
            assert_eq!(
                sealed,
                reference_container(ty, chunk_log2, &pt),
                "{ty:?} chunk_log2 {chunk_log2} len {len}"
            );
            assert_eq!(sealed.len() as u64, ciphertext_len(len as u64, chunk_log2));
            let (key, _) = kat_key(ty);
            assert_eq!(*open_all(&key, ty, &sealed).unwrap(), pt);
        }
    }

    #[test]
    fn kat_matches_frozen_vectors() {
        let frozen = frozen();
        assert_eq!(frozen_bytes(&frozen["inputs"]["mk"]), KAT_MK);
        assert_eq!(frozen_bytes(&frozen["inputs"]["vault_id"]), KAT_VAULT_ID);
        assert_eq!(frozen_bytes(&frozen["inputs"]["salt"]), KAT_SALT);
        let vectors = frozen["stream"]
            .as_array()
            .expect("the vector file has no `stream` array: regenerate it (see gen_vectors)");
        assert_eq!(vectors.len(), CASES.len());
        for (v, &(ty, chunk_log2, len, full)) in vectors.iter().zip(CASES) {
            let what = format!("{ty:?} chunk_log2 {chunk_log2} len {len}");
            assert_eq!(v["type"], type_name(ty), "{what}");
            assert_eq!(v["chunk_log2"], chunk_log2, "{what}");
            assert_eq!(v["plain_len"], len, "{what}");
            let sealed = sealed_container(ty, chunk_log2, &kat_plaintext(len));
            assert_eq!(v["container_len"], sealed.len(), "{what}");
            assert_eq!(
                v["container_blake3"],
                blake3::hash(&sealed).to_hex().as_str(),
                "{what}"
            );
            assert_eq!(v.get("container").is_some(), full, "{what}");
            if full {
                assert_eq!(frozen_bytes(&v["container"]), sealed, "{what}");
            }
        }
    }

    /// Writes `tests/vectors/stream_v1.json`. Run once, then commit the file:
    /// `GCLONE_GEN_VECTORS=1 cargo test --lib -- --ignored gen_vectors`.
    /// Without that variable it returns at once, so a plain `--ignored` run (the live run of
    /// §13 item 10) never rewrites the frozen file.
    #[test]
    #[ignore = "generator: rewrites the frozen vector file when GCLONE_GEN_VECTORS=1"]
    fn gen_vectors() {
        if std::env::var("GCLONE_GEN_VECTORS").as_deref() != Ok("1") {
            return;
        }
        let stream: Vec<serde_json::Value> = CASES
            .iter()
            .map(|&(ty, chunk_log2, len, full)| {
                let container = reference_container(ty, chunk_log2, &kat_plaintext(len));
                let mut v = serde_json::json!({
                    "type": type_name(ty),
                    "chunk_log2": chunk_log2,
                    "plain_len": len,
                    "container_len": container.len(),
                    "container_blake3": blake3::hash(&container).to_hex().as_str(),
                });
                if full {
                    v["container"] = util::hex(&container).into();
                }
                v
            })
            .collect();
        let doc = serde_json::json!({
            "about": "gclone format v1 — frozen known-answer vectors (SPEC §4.7). Generated once by \
                      `GCLONE_GEN_VECTORS=1 cargo test --lib -- --ignored gen_vectors`; never edit by hand.",
            "inputs": {
                "mk": util::hex(&KAT_MK),
                "vault_id": util::hex(&KAT_VAULT_ID),
                "salt": util::hex(&KAT_SALT),
                "epoch": KAT_EPOCH,
                "bundle_key": util::hex(&KAT_BUNDLE_KEY),
                "plaintext": "pt[i] = (i * 7 + 3) mod 256",
            },
            "purpose_keys": {
                "data": util::hex(&reference_purpose_key("data")),
                "index": util::hex(&reference_purpose_key("index")),
            },
            "stream": stream,
            "kdf": crate::crypto::kdf::tests::gen_frozen(),
            "keyfile": crate::format::keyfile::tests::gen_frozen(),
            "segment": crate::format::index::tests::gen_frozen_segment(),
            "snapshot": crate::format::index::tests::gen_frozen_snapshot(),
        });
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/stream_v1.json");
        let mut text = serde_json::to_string_pretty(&doc).unwrap();
        text.push('\n');
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn frozen_purpose_keys() {
        let frozen = frozen();
        for (purpose, label) in [(Purpose::Data, "data"), (Purpose::Index, "index")] {
            assert_eq!(
                kat_keyring()
                    .purpose(KAT_EPOCH, purpose)
                    .unwrap()
                    .expose()
                    .as_slice(),
                frozen_bytes(&frozen["purpose_keys"][label])
            );
        }
    }

    #[test]
    fn header_layout() {
        let sealed = sealed_container(StreamType::Segment, 12, b"x");
        let h = Header::decode(&sealed).unwrap();
        assert_eq!(
            (h.suite, h.chunk_log2, h.ty, h.flags, h.epoch, h.salt),
            (1, 12, StreamType::Segment, 0, 1, KAT_SALT)
        );
        assert_eq!(h.encode(), sealed[..HEADER_LEN]);
        assert_eq!(&sealed[..8], b"GCS1\x01\x0c\x02\x00");
        assert_eq!(sealed[8..12], [0, 0, 0, 1]);
    }

    #[test]
    fn nonce_layout() {
        let n = nonce(0x0102_0304_0506_0708, true);
        assert_eq!(n.as_slice(), [0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1]);
        assert_eq!(nonce(0, false).as_slice(), [0u8; 12]);
    }

    #[test]
    fn failed_open_leaves_the_output_untouched() {
        let (key, _) = kat_key(StreamType::Data);
        let sealed = sealed_container(StreamType::Data, 12, &kat_plaintext(100));
        let opener = Opener::from_header(&key, &sealed, StreamType::Data).unwrap();
        let mut out = b"kept".to_vec();
        let mut bad = sealed[HEADER_LEN..].to_vec();
        bad[5] ^= 0x10;
        assert!(matches!(
            opener.open_chunk(0, true, &bad, &mut out),
            Err(CryptoError::Corrupt)
        ));
        assert_eq!(out, b"kept");
        opener
            .open_chunk(0, true, &sealed[HEADER_LEN..], &mut out)
            .unwrap();
        assert_eq!(out[..4], *b"kept");
        assert_eq!(out[4..], kat_plaintext(100));
    }

    #[test]
    fn counter_limit_is_misuse() {
        let (key, _) = kat_key(StreamType::Data);
        let mut sealer = Sealer::new(&key, StreamType::Data, 1, 12);
        sealer.next = u64::MAX;
        let mut out = Vec::new();
        assert!(matches!(
            sealer.seal_chunk(&[0u8; 4096], false, &mut out),
            Err(CryptoError::Misuse(_))
        ));
        assert!(out.is_empty());
    }

    /// A Data stream of the KAT keyring with its own salt, as an index entry describes it.
    fn data_stream(salt: [u8; 16], chunk_log2: u8, pt: &[u8]) -> (Loc, Vec<u8>) {
        let (key, epoch) = kat_key(StreamType::Data);
        let mut sealer =
            Sealer::with_salt_for_tests(&key, StreamType::Data, epoch, chunk_log2, salt);
        let sealed = seal_with(&mut sealer, pt);
        let loc = Loc {
            blob: crate::types::BlobId([7; 16]),
            off: 0,
            clen: sealed.len() as u64,
            salt,
            chunk_log2,
            epoch,
            suite: SUITE_V1,
            flags: 0,
        };
        (loc, sealed)
    }

    /// Every chunk of `sealed` through `opener`, the final one decided by the plaintext length.
    fn open_chunks(opener: &Opener, sealed: &[u8], plain_len: u64) -> Result<Vec<u8>, CryptoError> {
        let chunk_log2 = opener.chunk_log2();
        let (mut out, mut at) = (Vec::new(), HEADER_LEN);
        let chunks = chunk_count(plain_len, chunk_log2);
        for idx in 0..chunks {
            let len = chunk_cipher_len(idx, plain_len, chunk_log2);
            opener.open_chunk(idx, idx + 1 == chunks, &sealed[at..at + len], &mut out)?;
            at += len;
        }
        assert_eq!(at, sealed.len());
        Ok(out)
    }

    #[test]
    fn a_ticket_opens_its_stream_and_no_other() {
        let keys = kat_keyring();
        let pt = kat_plaintext(3 * 4096 + 17);
        let (loc_a, sealed_a) = data_stream(KAT_SALT, 12, &pt);
        let (loc_b, sealed_b) = data_stream(seq::<16>(0x10), 12, &pt);
        let opener_a = keys.data_opener(&loc_a).unwrap();
        let (key_a, header_a) = opener_a.export_ticket();
        // The ticket's header is the stream's own: what a full read compares with.
        assert_eq!(header_a, sealed_a[..HEADER_LEN]);
        assert_eq!(header_a, opener_a.expected_header());

        // From the ticket alone — no keyring, no purpose key — every chunk opens.
        let ticket_a = Opener::from_ticket(key_a.clone(), &header_a).unwrap();
        assert_eq!(ticket_a.chunk_log2(), 12);
        assert_eq!(ticket_a.expected_header(), header_a);
        assert_eq!(
            open_chunks(&ticket_a, &sealed_a, pt.len() as u64).unwrap(),
            pt
        );
        // A single chunk in the middle, as a ranged read asks for it.
        let full = 4096 + TAG_LEN;
        let mut one = Vec::new();
        ticket_a
            .open_chunk(
                2,
                false,
                &sealed_a[HEADER_LEN + 2 * full..HEADER_LEN + 3 * full],
                &mut one,
            )
            .unwrap();
        assert_eq!(one, pt[2 * 4096..3 * 4096]);

        // Another stream of the same file content, the same purpose key and the same epoch
        // has another stream key: the ticket opens none of its chunks.
        assert!(matches!(
            open_chunks(&ticket_a, &sealed_b, pt.len() as u64),
            Err(CryptoError::Corrupt)
        ));
        let (key_b, header_b) = keys.data_opener(&loc_b).unwrap().export_ticket();
        assert_ne!(key_a.as_slice(), key_b.as_slice());
        // Neither does a ticket put together from one stream's key and the other's header.
        let mixed = Opener::from_ticket(key_a.clone(), &header_b).unwrap();
        assert!(matches!(
            open_chunks(&mixed, &sealed_b, pt.len() as u64),
            Err(CryptoError::Corrupt)
        ));
        // The chunk rules hold for a ticket as for any opener: position and final flag.
        let mut out = Vec::new();
        assert!(matches!(
            ticket_a.open_chunk(1, false, &sealed_a[HEADER_LEN..HEADER_LEN + full], &mut out),
            Err(CryptoError::Corrupt)
        ));
        assert!(matches!(
            ticket_a.open_chunk(0, true, &sealed_a[HEADER_LEN..HEADER_LEN + full], &mut out),
            Err(CryptoError::Corrupt)
        ));
        assert!(out.is_empty());

        // The stream key is not a key of the hierarchy: neither the purpose key it came from
        // nor the master key.
        let (purpose, _) = kat_key(StreamType::Data);
        assert_ne!(key_a.as_slice(), purpose.expose());
        assert_ne!(key_a.as_slice(), KAT_MK);
    }

    #[test]
    fn a_ticket_needs_the_header_of_a_readable_data_stream() {
        let (loc, sealed) = data_stream(KAT_SALT, 12, b"x");
        let (key, header) = kat_keyring().data_opener(&loc).unwrap().export_ticket();
        let ticket = |header: &[u8]| Opener::from_ticket(key.clone(), header).map(drop);
        assert!(ticket(&header).is_ok());
        assert!(matches!(ticket(&header[..59]), Err(CryptoError::Truncated)));
        assert!(matches!(ticket(&[]), Err(CryptoError::Truncated)));
        assert!(matches!(ticket(&sealed), Err(CryptoError::TrailingData)));
        let with = |at: usize, byte: u8| {
            let mut h = header;
            h[at] = byte;
            ticket(&h)
        };
        assert!(matches!(with(0, b'X'), Err(CryptoError::BadMagic)));
        assert!(matches!(with(4, 2), Err(CryptoError::Unsupported(_))));
        assert!(matches!(with(5, 11), Err(CryptoError::Unsupported(_))));
        assert!(matches!(with(5, 25), Err(CryptoError::Unsupported(_))));
        assert!(matches!(with(6, 4), Err(CryptoError::Unsupported(_))));
        assert!(matches!(with(7, 1), Err(CryptoError::Unsupported(_))));
        // An index or keyfile stream is never opened from a ticket.
        for ty in [
            StreamType::Segment,
            StreamType::Snapshot,
            StreamType::Bundle,
        ] {
            assert!(matches!(with(6, ty as u8), Err(CryptoError::WrongKey)));
        }
    }
}

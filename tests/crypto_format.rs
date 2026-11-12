//! Acceptance tests of the crypto and format layer (SPEC §4.7, §12.1 WP1). Everything here
//! uses the public API only; the fixed-salt known-answer tests are unit tests in
//! `src/crypto/stream.rs`.

mod support;

use std::ops::Range;

use gclone::consts::{CHUNK_LOG2, KEYFILE_MAX};
use gclone::crypto::{
    HEADER_LEN, Header, KdfParams, KdfPreamble, Keyring, MAGIC, MasterKey, Opener, PREAMBLE_LEN,
    Passphrase, Purpose, PurposeKey, SUITE_V1, Sealer, StreamType, TAG_LEN, chunk_cipher_len,
    chunk_count, chunk_range, ciphertext_len, derive_pass_key, open_all, plaintext_len, seal_all,
};
use gclone::error::{CryptoError, FormatError, PathError};
use gclone::format::{
    DeviceRec, HeadRec, IndexName, KEYFILE_PREFIX, KeyfileKey, KeyfilePayload, Op, RemovedRec,
    SegmentBody, SegmentV1, SnapshotBody, SnapshotV1, VaultDescriptor, blob_len, blob_name,
    keyfile_name, op_from_draft, open_keyfile, open_segment, open_snapshot, parse_blob_name,
    parse_index_name, parse_keyfile_name, seal_keyfile, seal_segment, seal_snapshot, segment_name,
    snapshot_name,
};
use gclone::types::{BlobId, BlobRec, DeviceId, Entry, EntryKind, Loc, OpDraft, SegRef, Stamp};
use gclone::util;
use support::prng::for_each_seed;

// ---------------------------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------------------------

const VAULT: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];
const DEV_A: DeviceId = DeviceId([0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7]);
const DEV_B: DeviceId = DeviceId([0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7]);
/// Small KDF parameters for the keyfile tests (the lower accepted bound).
const SMALL: KdfParams = KdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};

fn master(fill: u8) -> MasterKey {
    MasterKey::from_bytes(std::array::from_fn(|i| fill.wrapping_add(i as u8)))
}

/// `MK = 00 01 … 1f`, vault `a0 … af`, epoch 1.
fn keyring() -> Keyring {
    Keyring::new(VAULT, vec![(1, master(0))], 1).unwrap()
}

/// `pt[i] = (i * 7 + 3) mod 256`
fn pt(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 7 + 3) % 256) as u8).collect()
}

/// Expects `Err(<pattern>)`; prints the actual error otherwise. Optional trailing format
/// arguments say which case failed.
macro_rules! assert_err {
    ($result:expr, $pattern:pat $(if $guard:expr)?) => {
        assert_err!($result, $pattern $(if $guard)?, "")
    };
    ($result:expr, $pattern:pat $(if $guard:expr)?, $($context:tt)+) => {
        match $result {
            Err($pattern) $(if $guard)? => {}
            Err(other) => panic!(
                "expected Err({}), got Err({other:?}) [{}]",
                stringify!($pattern),
                format_args!($($context)+)
            ),
            Ok(_) => panic!(
                "expected Err({}), got Ok [{}]",
                stringify!($pattern),
                format_args!($($context)+)
            ),
        }
    };
}

/// Fails to compile if the type implements one of the traits.
macro_rules! assert_not_impl {
    ($ty:ty: $($tr:path),+) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            $({
                #[allow(dead_code)]
                struct Implemented;
                impl<T: ?Sized + $tr> AmbiguousIfImpl<Implemented> for T {}
            })+
            let _ = <$ty as AmbiguousIfImpl<_>>::check;
        };
    };
}

/// One Data stream as the upload pipeline produces it, with the index entry that describes it.
struct Sealed {
    bytes: Vec<u8>,
    loc: Loc,
    size: u64,
}

/// Seals `plain` chunk by chunk under the keyring's current epoch.
fn seal_data(keys: &Keyring, chunk_log2: u8, plain: &[u8]) -> Sealed {
    let epoch = keys.current_epoch();
    let mut sealer = if chunk_log2 == CHUNK_LOG2 {
        keys.data_sealer()
    } else {
        let key = keys.purpose(epoch, Purpose::Data).unwrap();
        Sealer::new(&key, StreamType::Data, epoch, chunk_log2)
    };
    let c = 1usize << chunk_log2;
    let size = plain.len() as u64;
    let chunks = chunk_count(size, chunk_log2) as usize;
    let mut bytes = sealer.header().to_vec();
    for i in 0..chunks {
        assert!(!sealer.is_finished());
        let chunk = &plain[i * c..plain.len().min((i + 1) * c)];
        sealer
            .seal_chunk(chunk, i + 1 == chunks, &mut bytes)
            .unwrap();
    }
    assert!(sealer.is_finished());
    assert_eq!(bytes.len() as u64, ciphertext_len(size, chunk_log2));
    let loc = Loc {
        blob: BlobId([0xb0; 16]),
        off: 0,
        clen: bytes.len() as u64,
        salt: sealer.salt(),
        chunk_log2,
        epoch,
        suite: 1,
        flags: 0,
    };
    Sealed { bytes, loc, size }
}

/// A full read of a Data stream the way the transfer layer does it (§4.2): the opener comes
/// from the index entry, the stored header is only compared, and `size` decides which chunk is
/// final.
fn open_data(keys: &Keyring, loc: &Loc, size: u64, stored: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let opener = keys.data_opener(loc)?;
    if stored.get(..HEADER_LEN) != Some(&opener.expected_header()[..]) {
        return Err(CryptoError::Corrupt);
    }
    let chunks = chunk_count(size, loc.chunk_log2);
    let mut out = Vec::new();
    let mut at = HEADER_LEN;
    for i in 0..chunks {
        let len = chunk_cipher_len(i, size, loc.chunk_log2);
        let ct = stored.get(at..at + len).ok_or(CryptoError::Truncated)?;
        opener.open_chunk(i, i + 1 == chunks, ct, &mut out)?;
        at += len;
    }
    if at != stored.len() {
        return Err(CryptoError::TrailingData);
    }
    Ok(out)
}

/// Byte ranges of the chunks (ct‖tag) inside a container of `size` plaintext bytes.
fn chunk_spans(size: u64, chunk_log2: u8) -> Vec<Range<usize>> {
    let mut at = HEADER_LEN;
    (0..chunk_count(size, chunk_log2))
        .map(|i| {
            let len = chunk_cipher_len(i, size, chunk_log2);
            at += len;
            at - len..at
        })
        .collect()
}

/// `header ‖ chunks[order[0]] ‖ chunks[order[1]] ‖ …`
fn rebuild(container: &[u8], spans: &[Range<usize>], order: &[usize]) -> Vec<u8> {
    let mut out = container[..HEADER_LEN].to_vec();
    for &i in order {
        out.extend_from_slice(&container[spans[i].clone()]);
    }
    out
}

fn flipped(bytes: &[u8], at: usize, mask: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at] ^= mask;
    out
}

// ---------------------------------------------------------------------------------------------
// stream container: round trips and lengths
// ---------------------------------------------------------------------------------------------

#[test]
fn round_trip_lengths() {
    let keys = keyring();
    let index_key = keys.purpose(1, Purpose::Index).unwrap();
    for chunk_log2 in [12u8, 16] {
        let c = 1usize << chunk_log2;
        for len in [0, 1, c - 1, c, c + 1, 2 * c, 2 * c + 5, 3 * c] {
            let plain = pt(len);
            let n = len as u64;

            // whole-container API
            let sealed = seal_all(&index_key, StreamType::Segment, 1, chunk_log2, &plain);
            assert_eq!(sealed.len() as u64, ciphertext_len(n, chunk_log2));
            assert_eq!(
                *open_all(&index_key, StreamType::Segment, &sealed).unwrap(),
                plain
            );
            assert_eq!(plaintext_len(sealed.len() as u64, chunk_log2), Some(n));

            // chunk-by-chunk Sealer, opened from the index entry
            let data = seal_data(&keys, chunk_log2, &plain);
            assert_eq!(data.bytes.len() as u64, ciphertext_len(n, chunk_log2));
            assert_eq!(open_data(&keys, &data.loc, n, &data.bytes).unwrap(), plain);
            // a Data stream is self-describing too
            assert_eq!(*keys.open(StreamType::Data, &data.bytes).unwrap(), plain);
        }
    }
    // Keyring::seal writes the production chunk size under the current epoch
    for len in [0, 1, 65535, 65536, 65537, 200_000] {
        let plain = pt(len);
        for ty in [StreamType::Data, StreamType::Segment, StreamType::Snapshot] {
            let sealed = keys.seal(ty, &plain).unwrap();
            let header = Header::decode(&sealed).unwrap();
            assert_eq!(
                (
                    header.suite,
                    header.chunk_log2,
                    header.ty,
                    header.flags,
                    header.epoch
                ),
                (SUITE_V1, CHUNK_LOG2, ty, 0, 1)
            );
            assert_eq!(sealed.len() as u64, ciphertext_len(len as u64, CHUNK_LOG2));
            assert_eq!(*keys.open(ty, &sealed).unwrap(), plain);
        }
    }
}

#[test]
fn every_seal_draws_a_fresh_salt() {
    let keys = keyring();
    let a = keys.seal(StreamType::Segment, b"same plaintext").unwrap();
    let b = keys.seal(StreamType::Segment, b"same plaintext").unwrap();
    assert_ne!(
        Header::decode(&a).unwrap().salt,
        Header::decode(&b).unwrap().salt
    );
    assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..]);
    let (s1, s2) = (keys.data_sealer(), keys.data_sealer());
    assert_ne!(s1.salt(), s2.salt());
    assert_ne!(s1.header(), s2.header());
    let header = Header::decode(&s1.header()).unwrap();
    assert_eq!(s1.header()[..4], MAGIC);
    assert_eq!(header.salt, s1.salt());
    assert_eq!(
        (
            header.suite,
            header.chunk_log2,
            header.ty,
            header.flags,
            header.epoch
        ),
        (1, CHUNK_LOG2, StreamType::Data, 0, 1)
    );
}

#[test]
fn length_functions() {
    assert_eq!((HEADER_LEN, TAG_LEN), (60, 16));
    for chunk_log2 in [12u8, 16, 24] {
        let c = 1u64 << chunk_log2;
        let full = c + 16;

        for l in [0, 59, 60, 75] {
            assert_eq!(plaintext_len(l, chunk_log2), None, "L = {l}");
        }
        assert_eq!(plaintext_len(76, chunk_log2), Some(0));
        for q in 0..3 {
            // a last chunk of 1..15 bytes is shorter than a tag
            for r in 1..16 {
                assert_eq!(plaintext_len(60 + q * full + r, chunk_log2), None);
            }
            // an empty chunk is legal only as the single chunk of an empty plaintext
            assert_eq!(
                plaintext_len(60 + q * full + 16, chunk_log2),
                (q == 0).then_some(0)
            );
            assert_eq!(
                plaintext_len(60 + q * full + 17, chunk_log2),
                Some(q * c + 1)
            );
            assert_eq!(
                plaintext_len(60 + (q + 1) * full, chunk_log2),
                Some((q + 1) * c)
            );
        }

        for n in [
            0,
            1,
            c - 1,
            c,
            c + 1,
            2 * c,
            2 * c + 5,
            3 * c,
            1000 * c + 77,
        ] {
            let chunks = chunk_count(n, chunk_log2);
            assert_eq!(chunks, n.div_ceil(c).max(1));
            let l = ciphertext_len(n, chunk_log2);
            assert_eq!(l, 60 + n + 16 * chunks);
            assert_eq!(plaintext_len(l, chunk_log2), Some(n));
            // the chunks tile the container exactly
            if chunks <= 4 {
                let total: u64 = (0..chunks)
                    .map(|i| chunk_cipher_len(i, n, chunk_log2) as u64)
                    .sum();
                assert_eq!(60 + total, l);
            }
            assert_eq!(chunk_cipher_len(chunks, n, chunk_log2), 0);
            if chunks > 1 {
                assert_eq!(chunk_cipher_len(0, n, chunk_log2) as u64, full);
            }
        }
    }

    // exhaustive inverse over three chunks at the smallest chunk size
    let c = 4096u64;
    let mut expect_n = 0;
    for l in 0..=ciphertext_len(3 * c, 12) {
        if let Some(n) = plaintext_len(l, 12) {
            assert_eq!(
                n, expect_n,
                "plaintext_len is strictly increasing where defined"
            );
            assert_eq!(ciphertext_len(n, 12), l);
            expect_n += 1;
        }
    }
    assert_eq!(expect_n, 3 * c + 1);

    // absurd lengths saturate instead of wrapping
    assert_eq!(ciphertext_len(u64::MAX, 16), u64::MAX);
    assert_eq!(ciphertext_len(u64::MAX - 100, 16), u64::MAX);
}

#[test]
fn chunk_range_bounds() {
    let c = 4096u64;
    let n = 2 * c + 5;
    assert_eq!(chunk_range(0..0, n, 12), None);
    assert_eq!(chunk_range(5..5, n, 12), None);
    #[allow(clippy::reversed_empty_ranges)]
    let reversed = 7..3;
    assert_eq!(chunk_range(reversed, n, 12), None);
    assert_eq!(chunk_range(0..n + 1, n, 12), None);
    assert_eq!(chunk_range(n..n + 1, n, 12), None);
    assert_eq!(chunk_range(0..1, 0, 12), None);

    let whole = chunk_range(0..n, n, 12).unwrap();
    assert_eq!((whole.first, whole.last, whole.skip), (0, 2, 0));
    assert_eq!(whole.cipher, 60..ciphertext_len(n, 12));

    let last_byte = chunk_range(n - 1..n, n, 12).unwrap();
    assert_eq!((last_byte.first, last_byte.last, last_byte.skip), (2, 2, 4));
    assert_eq!(
        last_byte.cipher,
        60 + 2 * (c + 16)..60 + 2 * (c + 16) + 5 + 16
    );

    let middle = chunk_range(c - 1..c + 1, n, 12).unwrap();
    assert_eq!((middle.first, middle.last, middle.skip), (0, 1, 4095));
    assert_eq!(middle.cipher, 60..60 + 2 * (c + 16));

    let exact = chunk_range(c..2 * c, n, 12).unwrap();
    assert_eq!((exact.first, exact.last, exact.skip), (1, 1, 0));
    assert_eq!(exact.cipher, 60 + (c + 16)..60 + 2 * (c + 16));
}

#[test]
fn random_access() {
    let keys = keyring();
    for (chunk_log2, len) in [
        (12u8, 5 * 4096 + 123),
        (12, 3 * 4096),
        (16, 3 * 65536 + 4567),
    ] {
        let plain = pt(len);
        let data = seal_data(&keys, chunk_log2, &plain);
        let opener = keys.data_opener(&data.loc).unwrap();
        assert_eq!(opener.chunk_log2(), chunk_log2);
        let chunks = chunk_count(data.size, chunk_log2);
        for_each_seed("random_access", 60, |rng| {
            let off = rng.below(data.size);
            let max = (data.size - off).min(3 << chunk_log2);
            let n = 1 + rng.below(max);
            let span = chunk_range(off..off + n, data.size, chunk_log2).unwrap();
            // a ranged read fetches exactly `span.cipher` and never sees the header
            let fetched = &data.bytes[span.cipher.start as usize..span.cipher.end as usize];
            let mut out = Vec::new();
            let mut at = 0;
            for i in span.first..=span.last {
                let clen = chunk_cipher_len(i, data.size, chunk_log2);
                opener
                    .open_chunk(i, i + 1 == chunks, &fetched[at..at + clen], &mut out)
                    .unwrap();
                at += clen;
            }
            assert_eq!(at, fetched.len());
            assert_eq!(
                out[span.skip..span.skip + n as usize],
                plain[off as usize..(off + n) as usize]
            );
        });
    }
}

// ---------------------------------------------------------------------------------------------
// stream container: tampering
// ---------------------------------------------------------------------------------------------

/// The §4.7 tamper table for one flipped header bit.
fn assert_header_flip(err: &CryptoError, at: usize, tampered: &[u8], via_keyring: bool) {
    let epoch = u32::from_be_bytes(tampered[8..12].try_into().unwrap());
    let ok = match at {
        0..=3 => matches!(err, CryptoError::BadMagic),
        4 | 7 => matches!(err, CryptoError::Unsupported(_)),
        5 if (12..=24).contains(&tampered[5]) => matches!(err, CryptoError::WrongKey),
        6 if StreamType::from_u8(tampered[6]).is_some() => matches!(err, CryptoError::WrongKey),
        5 | 6 => matches!(err, CryptoError::Unsupported(_)),
        // the test keyring holds epoch 1 with min_epoch 1
        8..=11 if via_keyring && epoch == 0 => {
            matches!(err, CryptoError::EpochTooOld { epoch: 0, min: 1 })
        }
        8..=11 if via_keyring => matches!(err, CryptoError::UnknownEpoch(e) if *e == epoch),
        // raw; salt; commit
        _ => matches!(err, CryptoError::WrongKey),
    };
    assert!(
        ok,
        "header byte {at} (keyring: {via_keyring}): unexpected {err:?}"
    );
}

#[test]
fn tamper_header_table() {
    let keys = keyring();
    for ty in [StreamType::Data, StreamType::Segment, StreamType::Snapshot] {
        let key = keys.purpose(1, ty.purpose().unwrap()).unwrap();
        let sealed = keys.seal(ty, &pt(100)).unwrap();
        for at in 0..HEADER_LEN {
            for bit in 0..8 {
                let bad = flipped(&sealed, at, 1 << bit);
                assert_header_flip(&keys.open(ty, &bad).unwrap_err(), at, &bad, true);
                assert_header_flip(&open_all(&key, ty, &bad).unwrap_err(), at, &bad, false);
                let raw = Opener::from_header(&key, &bad, ty).err().unwrap();
                assert_header_flip(&raw, at, &bad, false);
                // Header::decode alone performs steps 1–2: it rejects exactly the Unsupported
                // and BadMagic rows and passes everything else through unchanged
                match Header::decode(&bad) {
                    Err(e) => {
                        assert!(at <= 7, "header byte {at}: {e:?}");
                        assert_header_flip(&e, at, &bad, false);
                    }
                    Ok(header) => {
                        assert!(at >= 5, "header byte {at} was accepted");
                        assert_eq!(header.encode(), bad[..HEADER_LEN]);
                    }
                }
            }
        }
    }
}

#[test]
fn header_error_precedence() {
    let keys = keyring();
    let key = keys.purpose(1, Purpose::Index).unwrap();
    let sealed = keys.seal(StreamType::Segment, b"index object").unwrap();

    // 1. length, then magic
    for cut in [0, 1, 59] {
        assert_err!(Header::decode(&sealed[..cut]), CryptoError::Truncated);
        assert_err!(
            keys.open(StreamType::Segment, &sealed[..cut]),
            CryptoError::Truncated
        );
        assert_err!(
            open_all(&key, StreamType::Segment, &sealed[..cut]),
            CryptoError::Truncated
        );
    }
    let mut bad = sealed.clone();
    bad[0] = b'X';
    bad[4] = 9;
    assert_err!(keys.open(StreamType::Segment, &bad), CryptoError::BadMagic);

    // 2. Unsupported in the order suite, chunk size, type, flags — each before any key work
    let mut bad = sealed.clone();
    (bad[4], bad[5], bad[6], bad[7]) = (2, 11, 4, 1);
    assert_err!(Header::decode(&bad), CryptoError::Unsupported(what) if what.contains("suite"));
    bad[4] = 1;
    assert_err!(Header::decode(&bad), CryptoError::Unsupported(what) if what.contains("chunk"));
    bad[5] = 16;
    assert_err!(Header::decode(&bad), CryptoError::Unsupported(what) if what.contains("type"));
    bad[6] = 2;
    assert_err!(Header::decode(&bad), CryptoError::Unsupported(what) if what.contains("flags"));
    for (chunk_log2, ok) in [(11, false), (12, true), (24, true), (25, false)] {
        let mut h = sealed.clone();
        h[5] = chunk_log2;
        assert_eq!(Header::decode(&h).is_ok(), ok, "chunk_log2 {chunk_log2}");
    }
    // the reserved blob-manifest type and unknown types
    for ty in [0u8, 4, 6, 255] {
        let mut h = sealed.clone();
        h[6] = ty;
        assert_err!(
            keys.open(StreamType::Segment, &h),
            CryptoError::Unsupported(_)
        );
        assert_eq!(StreamType::from_u8(ty), None);
    }
    // Unsupported wins over an unknown epoch
    let mut bad = sealed.clone();
    bad[7] = 1;
    bad[11] = 9;
    assert_err!(
        keys.open(StreamType::Segment, &bad),
        CryptoError::Unsupported(_)
    );

    // 3. the epoch, before 4. the expected type
    let mut bad = sealed.clone();
    bad[11] = 9;
    assert_err!(
        keys.open(StreamType::Snapshot, &bad),
        CryptoError::UnknownEpoch(9)
    );
    // 4. the expected type, also when both types share a purpose key
    assert_err!(
        keys.open(StreamType::Snapshot, &sealed),
        CryptoError::WrongKey
    );
    // 5. commit, before 6. the chunks: a damaged body behind a wrong key reads as WrongKey
    let other = Keyring::new(VAULT, vec![(1, master(0x80))], 1).unwrap();
    let truncated = &sealed[..HEADER_LEN + 3];
    assert_err!(
        other.open(StreamType::Segment, truncated),
        CryptoError::WrongKey
    );
    assert_err!(
        keys.open(StreamType::Segment, truncated),
        CryptoError::Truncated
    );
}

#[test]
fn tamper_chunks_and_tags() {
    let keys = keyring();
    let index_key = keys.purpose(1, Purpose::Index).unwrap();

    // every bit of a single-chunk stream's body, tag included
    let sealed = keys.seal(StreamType::Segment, &pt(100)).unwrap();
    for at in HEADER_LEN..sealed.len() {
        for bit in 0..8 {
            let bad = flipped(&sealed, at, 1 << bit);
            assert_err!(
                keys.open(StreamType::Segment, &bad),
                CryptoError::Corrupt,
                "byte {at}"
            );
        }
    }
    // the single empty chunk of an empty stream is just a tag
    let empty = keys.seal(StreamType::Snapshot, b"").unwrap();
    assert_eq!(empty.len(), HEADER_LEN + TAG_LEN);
    for at in HEADER_LEN..empty.len() {
        let bad = flipped(&empty, at, 0x04);
        assert_err!(keys.open(StreamType::Snapshot, &bad), CryptoError::Corrupt);
    }

    // a multi-chunk stream: bytes spread over every chunk and each chunk's tag
    for len in [3 * 4096, 3 * 4096 + 100] {
        let plain = pt(len);
        let sealed = seal_all(&index_key, StreamType::Segment, 1, 12, &plain);
        let data = seal_data(&keys, 12, &plain);
        let spans = chunk_spans(len as u64, 12);
        let mut positions: Vec<usize> = (HEADER_LEN..sealed.len()).step_by(97).collect();
        for span in &spans {
            positions.extend([
                span.start,
                span.end - TAG_LEN - 1,
                span.end - TAG_LEN,
                span.end - 1,
            ]);
        }
        for at in positions {
            let bad = flipped(&sealed, at, 0x20);
            assert_err!(
                open_all(&index_key, StreamType::Segment, &bad),
                CryptoError::Corrupt,
                "byte {at}"
            );
            let bad = flipped(&data.bytes, at, 0x20);
            assert_err!(
                open_data(&keys, &data.loc, data.size, &bad),
                CryptoError::Corrupt,
                "byte {at}"
            );
        }
    }
}

#[test]
fn truncation_and_trailing_data() {
    let keys = keyring();
    let key = keys.purpose(1, Purpose::Index).unwrap();
    let c = 4096usize;
    let open = |bytes: &[u8]| open_all(&key, StreamType::Segment, bytes);

    for len in [0, 1, c - 1, c, c + 1, 2 * c + 5, 3 * c] {
        let plain = pt(len);
        let sealed = seal_all(&key, StreamType::Segment, 1, 12, &plain);
        let spans = chunk_spans(len as u64, 12);
        assert_eq!(*open(&sealed).unwrap(), plain);

        // inside the header, and the header alone
        for cut in [0, 1, 30, 59, HEADER_LEN] {
            assert_err!(
                open(&sealed[..cut]),
                CryptoError::Truncated,
                "len {len} cut {cut}"
            );
        }
        // at every chunk boundary: a verified chunk, then the input ends without a final one
        for span in &spans[..spans.len() - 1] {
            assert_err!(
                open(&sealed[..span.end]),
                CryptoError::Truncated,
                "len {len}"
            );
        }
        // inside a chunk, inside a tag: never a short result
        for span in &spans {
            let cuts = [
                span.start + 1,
                span.start + 15,
                span.start + 16,
                span.end - 17,
                span.end - 1,
            ];
            for cut in cuts
                .into_iter()
                .filter(|cut| (span.start + 1..span.end).contains(cut))
            {
                assert_err!(
                    open(&sealed[..cut]),
                    CryptoError::Truncated | CryptoError::Corrupt,
                    "len {len} cut {cut}"
                );
            }
        }

        // one byte after the stream
        let mut longer = sealed.clone();
        longer.push(0);
        if len > 0 && len % c == 0 {
            // the final chunk is full: it verifies, and the extra byte is trailing data
            assert_err!(open(&longer), CryptoError::TrailingData, "len {len}");
        } else {
            // A final chunk shorter than C has no length of its own, so an appended byte reads
            // as part of it: the same failure as a damaged chunk.
            assert_err!(
                open(&longer),
                CryptoError::Corrupt | CryptoError::TrailingData,
                "len {len}"
            );
        }
        // a reader that knows the size from the index entry always tells the two apart
        let data = seal_data(&keys, 12, &plain);
        let mut longer = data.bytes.clone();
        longer.push(0);
        assert_err!(
            open_data(&keys, &data.loc, data.size, &longer),
            CryptoError::TrailingData
        );
        assert_err!(
            open_data(
                &keys,
                &data.loc,
                data.size,
                &data.bytes[..data.bytes.len() - 1]
            ),
            CryptoError::Truncated
        );
    }

    // every possible cut of a small two-chunk stream
    let sealed = seal_all(&key, StreamType::Segment, 1, 12, &pt(c + 40));
    for cut in 0..sealed.len() {
        assert_err!(
            open(&sealed[..cut]),
            CryptoError::Truncated | CryptoError::Corrupt,
            "cut {cut}"
        );
    }
    // a whole second copy of the final chunk after a full final chunk
    let sealed = seal_all(&key, StreamType::Segment, 1, 12, &pt(2 * c));
    let spans = chunk_spans(2 * c as u64, 12);
    assert_err!(
        open(&rebuild(&sealed, &spans, &[0, 1, 1])),
        CryptoError::TrailingData
    );
}

#[test]
fn swap_reorder_duplicate_drop() {
    let keys = keyring();
    let key = keys.purpose(1, Purpose::Index).unwrap();
    let c = 4096usize;
    let open = |bytes: &[u8]| open_all(&key, StreamType::Segment, bytes);

    // four chunks, once with a short and once with a full final chunk
    for len in [3 * c + 100, 4 * c] {
        let plain = pt(len);
        let sealed = seal_all(&key, StreamType::Segment, 1, 12, &plain);
        let spans = chunk_spans(len as u64, 12);
        assert_eq!(spans.len(), 4);
        assert_eq!(rebuild(&sealed, &spans, &[0, 1, 2, 3]), sealed);

        for order in [
            &[1, 0, 2, 3][..], // swap
            &[0, 2, 1, 3],
            &[3, 1, 2, 0],
            &[0, 1, 3, 2],
            &[0, 1, 1, 2, 3], // duplicate
            &[0, 0, 1, 2, 3],
            &[0, 2, 3], // drop a middle chunk
            &[0, 1, 3],
            &[1, 2, 3], // drop the first
            &[3],       // the final chunk alone
            &[2, 3],
        ] {
            assert_err!(
                open(&rebuild(&sealed, &spans, order)),
                CryptoError::Corrupt,
                "len {len} order {order:?}"
            );
        }

        // a non-final chunk presented as final and vice versa, at the chunk level
        let opener = Opener::from_header(&key, &sealed, StreamType::Segment).unwrap();
        let mut out = Vec::new();
        for i in 0..4u64 {
            let ct = &sealed[spans[i as usize].clone()];
            let last = i == 3;
            assert_err!(
                opener.open_chunk(i, !last, ct, &mut out),
                CryptoError::Corrupt,
                "chunk {i}"
            );
            assert_err!(
                opener.open_chunk(i + 1, last, ct, &mut out),
                CryptoError::Corrupt,
                "chunk {i}"
            );
            assert!(
                out.is_empty(),
                "no plaintext is released before the tag verified"
            );
        }
        for i in 0..4u64 {
            opener
                .open_chunk(i, i == 3, &sealed[spans[i as usize].clone()], &mut out)
                .unwrap();
        }
        assert_eq!(out, plain);
        // …and at the stream level: ending the stream on a non-final chunk
        assert_err!(
            open(&rebuild(&sealed, &spans, &[0, 1, 2])),
            CryptoError::Truncated,
            "len {len}"
        );

        // chunk lengths no stream can contain
        let full = &sealed[spans[0].clone()];
        assert_err!(
            opener.open_chunk(0, false, &full[..full.len() - 1], &mut out),
            CryptoError::Corrupt
        );
        assert_err!(
            opener.open_chunk(0, true, &[full, &[0u8][..]].concat(), &mut out),
            CryptoError::Corrupt
        );
        assert_err!(
            opener.open_chunk(0, true, &full[..15], &mut out),
            CryptoError::Corrupt
        );
        assert_err!(
            opener.open_chunk(1, true, &full[..16], &mut out),
            CryptoError::Corrupt
        );
        assert_err!(
            opener.open_chunk(0, true, &[], &mut out),
            CryptoError::Corrupt
        );
    }
}

#[test]
fn cross_stream_swap() {
    let keys = keyring();
    let c = 4096usize;
    let plain = pt(3 * c + 9);
    let a = seal_data(&keys, 12, &plain);
    // the same path sealed again (an "old version"): same key and content, another salt
    let b = seal_data(&keys, 12, &plain);
    assert_ne!(a.loc.salt, b.loc.salt);
    assert_eq!(open_data(&keys, &a.loc, a.size, &a.bytes).unwrap(), plain);

    // A's bytes read through an entry carrying B's salt: the header comparison fails for a
    // full read, and a ranged read (no header) fails on the first chunk it touches
    assert_err!(
        open_data(&keys, &b.loc, b.size, &a.bytes),
        CryptoError::Corrupt
    );
    let opener_b = keys.data_opener(&b.loc).unwrap();
    let spans = chunk_spans(a.size, 12);
    let mut out = Vec::new();
    for (i, span) in spans.iter().enumerate() {
        let last = i + 1 == spans.len();
        assert_err!(
            opener_b.open_chunk(i as u64, last, &a.bytes[span.clone()], &mut out),
            CryptoError::Corrupt
        );
    }
    assert!(out.is_empty());
    // even with A's stored header swapped for the expected one
    let mut spliced = opener_b.expected_header().to_vec();
    spliced.extend_from_slice(&a.bytes[HEADER_LEN..]);
    assert_err!(
        open_data(&keys, &b.loc, b.size, &spliced),
        CryptoError::Corrupt
    );

    // a chunk-aligned slice of A presented as a whole stream
    let slice = rebuild(&a.bytes, &spans, &[1, 2, 3]);
    let slice_size = a.size - c as u64;
    let mut slice_loc = a.loc.clone();
    slice_loc.clen = slice.len() as u64;
    assert_eq!(slice_loc.clen, ciphertext_len(slice_size, 12));
    assert_err!(
        open_data(&keys, &slice_loc, slice_size, &slice),
        CryptoError::Corrupt
    );
    assert_err!(keys.open(StreamType::Data, &slice), CryptoError::Corrupt);
    // a prefix of A with a smaller size in the entry: the last chunk read is not A's final one
    let prefix = rebuild(&a.bytes, &spans, &[0, 1]);
    assert_err!(
        open_data(&keys, &a.loc, 2 * c as u64, &prefix),
        CryptoError::Corrupt
    );

    // an entry that disagrees with the stream in any authenticated field
    for edit in [(|l: &mut Loc| l.salt[15] ^= 1) as fn(&mut Loc), |l| {
        l.chunk_log2 = 13
    }] {
        let mut loc = a.loc.clone();
        edit(&mut loc);
        assert_err!(
            open_data(&keys, &loc, a.size, &a.bytes),
            CryptoError::Corrupt
        );
        let opener = keys.data_opener(&loc).unwrap();
        assert_ne!(opener.expected_header(), a.bytes[..HEADER_LEN]);
    }
    // blob, off and clen say where the stream is, not what it is
    let mut moved = a.loc.clone();
    (moved.blob, moved.off) = (BlobId([1; 16]), 1 << 40);
    assert_eq!(open_data(&keys, &moved, a.size, &a.bytes).unwrap(), plain);
    assert_eq!(
        keys.data_opener(&a.loc).unwrap().expected_header(),
        a.bytes[..HEADER_LEN]
    );
}

#[test]
fn wrong_context() {
    let keys = keyring();
    let data_key = keys.purpose(1, Purpose::Data).unwrap();
    let index_key = keys.purpose(1, Purpose::Index).unwrap();
    let segment = keys.seal(StreamType::Segment, &pt(300)).unwrap();
    let data = keys.seal(StreamType::Data, &pt(300)).unwrap();

    // right bytes, wrong expected type
    assert_err!(
        keys.open(StreamType::Snapshot, &segment),
        CryptoError::WrongKey
    );
    assert_err!(keys.open(StreamType::Data, &segment), CryptoError::WrongKey);
    assert_err!(keys.open(StreamType::Segment, &data), CryptoError::WrongKey);
    assert_err!(
        open_all(&index_key, StreamType::Snapshot, &segment),
        CryptoError::WrongKey
    );
    assert_err!(
        Opener::from_header(&index_key, &segment, StreamType::Snapshot),
        CryptoError::WrongKey
    );
    assert_err!(
        Opener::from_header(&index_key, &segment, StreamType::Bundle),
        CryptoError::WrongKey
    );
    // right type, wrong purpose key
    assert_err!(
        open_all(&data_key, StreamType::Segment, &segment),
        CryptoError::WrongKey
    );
    assert_err!(
        open_all(&index_key, StreamType::Data, &data),
        CryptoError::WrongKey
    );
    // relabelling the type byte does not help: the type is bound into the stream key
    let mut relabelled = segment.clone();
    relabelled[6] = StreamType::Snapshot as u8;
    assert_err!(
        keys.open(StreamType::Snapshot, &relabelled),
        CryptoError::WrongKey
    );

    // wrong epoch key
    let two = Keyring::new(VAULT, vec![(1, master(0)), (2, master(0x40))], 1).unwrap();
    let under_two = two.seal(StreamType::Segment, b"epoch two").unwrap();
    assert_eq!(Header::decode(&under_two).unwrap().epoch, 2);
    assert_eq!(
        *two.open(StreamType::Segment, &under_two).unwrap(),
        *b"epoch two"
    );
    assert_eq!(*two.open(StreamType::Segment, &segment).unwrap(), pt(300));
    assert_err!(
        keys.open(StreamType::Segment, &under_two),
        CryptoError::UnknownEpoch(2)
    );
    let other_two = Keyring::new(VAULT, vec![(2, master(0x41))], 1).unwrap();
    assert_err!(
        other_two.open(StreamType::Segment, &under_two),
        CryptoError::WrongKey
    );
    // the same master key in another vault is another key
    let other_vault = Keyring::new([7; 16], vec![(1, master(0))], 1).unwrap();
    assert_err!(
        other_vault.open(StreamType::Segment, &segment),
        CryptoError::WrongKey
    );

    // data_opener: suite and flags are refused before any key is looked up or derived — with
    // an epoch nobody holds the answer is still Unsupported, not UnknownEpoch
    let sealed = seal_data(&keys, CHUNK_LOG2, &pt(10));
    for edit in [
        (|l: &mut Loc| l.suite = 2) as fn(&mut Loc),
        |l| l.suite = 0,
        |l| l.flags = 1,
        |l| l.flags = 0x80,
        |l| l.chunk_log2 = 11,
        |l| l.chunk_log2 = 25,
    ] {
        for epoch in [1, 99] {
            let mut loc = sealed.loc.clone();
            edit(&mut loc);
            loc.epoch = epoch;
            assert_err!(keys.data_opener(&loc), CryptoError::Unsupported(_));
            assert_err!(
                Opener::for_data(&data_key, &loc),
                CryptoError::Unsupported(_)
            );
        }
    }
    let mut loc = sealed.loc.clone();
    loc.epoch = 99;
    assert_err!(keys.data_opener(&loc), CryptoError::UnknownEpoch(99));
    loc.epoch = 0;
    assert_err!(
        keys.data_opener(&loc),
        CryptoError::EpochTooOld { epoch: 0, min: 1 }
    );

    // Bundle streams have no purpose key in a keyring
    assert_eq!(StreamType::Bundle.purpose(), None);
    assert_err!(keys.seal(StreamType::Bundle, b"x"), CryptoError::Misuse(_));
    assert_err!(
        keys.open(StreamType::Bundle, &segment),
        CryptoError::Misuse(_)
    );
    let k_pass = PurposeKey::from_raw([9; 32]);
    let bundle = seal_all(&k_pass, StreamType::Bundle, 0, CHUNK_LOG2, b"payload");
    assert_eq!(
        *open_all(&k_pass, StreamType::Bundle, &bundle).unwrap(),
        *b"payload"
    );
    assert_err!(
        open_all(&PurposeKey::from_raw([8; 32]), StreamType::Bundle, &bundle),
        CryptoError::WrongKey
    );
    assert_err!(
        keys.open(StreamType::Segment, &bundle),
        CryptoError::EpochTooOld { epoch: 0, min: 1 }
    );
}

// ---------------------------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------------------------

#[test]
fn keyring_epochs() {
    assert_err!(Keyring::new(VAULT, vec![], 1), CryptoError::Misuse(_));
    assert_err!(
        Keyring::new(VAULT, vec![(1, master(0))], 2),
        CryptoError::Misuse(_)
    );
    assert_err!(
        Keyring::new(VAULT, vec![(3, master(0)), (1, master(1))], 2),
        CryptoError::Misuse(_)
    );
    assert_err!(
        Keyring::new(VAULT, vec![(2, master(0)), (2, master(1))], 1),
        CryptoError::Misuse(_)
    );

    let keys = Keyring::new(VAULT, vec![(5, master(0x50)), (3, master(0x30))], 2).unwrap();
    assert_eq!(keys.vault_id(), VAULT);
    assert_eq!(keys.current_epoch(), 5);
    assert_eq!(keys.min_epoch(), 2);
    let exported = keys.export();
    assert_eq!(exported.len(), 2);
    assert_eq!((exported[0].0, *exported[0].1), (3, *master(0x30).expose()));
    assert_eq!((exported[1].0, *exported[1].1), (5, *master(0x50).expose()));

    for purpose in [Purpose::Data, Purpose::Index] {
        assert!(keys.purpose(3, purpose).is_ok());
        assert!(keys.purpose(5, purpose).is_ok());
        // not held
        assert_err!(keys.purpose(4, purpose), CryptoError::UnknownEpoch(4));
        assert_err!(keys.purpose(6, purpose), CryptoError::UnknownEpoch(6));
        assert_err!(keys.purpose(2, purpose), CryptoError::UnknownEpoch(2));
        assert_err!(
            keys.purpose(u32::MAX, purpose),
            CryptoError::UnknownEpoch(u32::MAX)
        );
        // below min_epoch
        assert_err!(
            keys.purpose(1, purpose),
            CryptoError::EpochTooOld { epoch: 1, min: 2 }
        );
        assert_err!(
            keys.purpose(0, purpose),
            CryptoError::EpochTooOld { epoch: 0, min: 2 }
        );
    }

    // new streams use the current epoch; older epochs stay readable
    let old = Keyring::new(VAULT, vec![(3, master(0x30))], 2).unwrap();
    let from_old = old
        .seal(StreamType::Segment, b"written before rotation")
        .unwrap();
    assert_eq!(Header::decode(&from_old).unwrap().epoch, 3);
    assert_eq!(
        *keys.open(StreamType::Segment, &from_old).unwrap(),
        *b"written before rotation"
    );
    let from_new = keys.seal(StreamType::Segment, b"after").unwrap();
    assert_eq!(Header::decode(&from_new).unwrap().epoch, 5);
    assert_err!(
        old.open(StreamType::Segment, &from_new),
        CryptoError::UnknownEpoch(5)
    );
    let data = seal_data(&keys, CHUNK_LOG2, b"data");
    assert_eq!(data.loc.epoch, 5);
    // a raised min_epoch refuses the old epoch even though the stream is intact
    let raised = Keyring::new(VAULT, vec![(5, master(0x50))], 5).unwrap();
    assert_err!(
        raised.open(StreamType::Segment, &from_old),
        CryptoError::EpochTooOld { epoch: 3, min: 5 }
    );

    // the two purposes, and two epochs, are different keys
    let seg = keys.seal(StreamType::Segment, b"x").unwrap();
    assert_err!(
        open_all(
            &keys.purpose(5, Purpose::Data).unwrap(),
            StreamType::Segment,
            &seg
        ),
        CryptoError::WrongKey
    );
    assert_err!(
        open_all(
            &keys.purpose(3, Purpose::Index).unwrap(),
            StreamType::Segment,
            &seg
        ),
        CryptoError::WrongKey
    );
    assert!(
        open_all(
            &keys.purpose(5, Purpose::Index).unwrap(),
            StreamType::Segment,
            &seg
        )
        .is_ok()
    );

    // generated master keys are random
    assert_ne!(
        MasterKey::generate().expose(),
        MasterKey::generate().expose()
    );
    assert_eq!(MasterKey::from_bytes([3; 32]).expose(), &[3; 32]);
}

#[test]
fn key_types_are_clone_send_static() {
    fn check<T: Clone + Send + 'static>() {}
    check::<Keyring>();
    check::<MasterKey>();
    check::<PurposeKey>();
    fn send_static<T: Send + 'static>() {}
    send_static::<Sealer>();
    send_static::<Passphrase>();
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Opener>();
    send_sync::<Keyring>();

    // a clone is the same keyring
    let keys = keyring();
    let clone = keys.clone();
    let sealed = std::thread::spawn(move || clone.seal(StreamType::Segment, b"moved").unwrap())
        .join()
        .unwrap();
    assert_eq!(*keys.open(StreamType::Segment, &sealed).unwrap(), *b"moved");
}

// Secrets never reach a log line or a panic message through a formatter.
assert_not_impl!(Passphrase: std::fmt::Debug, std::fmt::Display);
assert_not_impl!(MasterKey: std::fmt::Debug, std::fmt::Display);
assert_not_impl!(PurposeKey: std::fmt::Debug, std::fmt::Display);
assert_not_impl!(Keyring: std::fmt::Debug, std::fmt::Display);
assert_not_impl!(Sealer: std::fmt::Debug);
assert_not_impl!(Opener: std::fmt::Debug);
assert_not_impl!(KeyfilePayload: std::fmt::Debug, std::fmt::Display);
assert_not_impl!(KeyfileKey: std::fmt::Debug, std::fmt::Display);

#[test]
fn sealer_misuse() {
    let keys = keyring();
    let key = keys.purpose(1, Purpose::Data).unwrap();
    let c = 4096usize;
    let new = || Sealer::new(&key, StreamType::Data, 1, 12);
    let mut out = Vec::new();

    // a short chunk that is not the final one (an empty one included)
    let mut s = new();
    assert_err!(
        s.seal_chunk(&pt(c - 1), false, &mut out),
        CryptoError::Misuse(_)
    );
    assert_err!(s.seal_chunk(&[], false, &mut out), CryptoError::Misuse(_));
    // an oversize chunk, final or not
    assert_err!(
        s.seal_chunk(&pt(c + 1), false, &mut out),
        CryptoError::Misuse(_)
    );
    assert_err!(
        s.seal_chunk(&pt(c + 1), true, &mut out),
        CryptoError::Misuse(_)
    );
    // a refused call consumed nothing: the sealer still seals chunk 0
    assert!(out.is_empty() && !s.is_finished());
    s.seal_chunk(&pt(c), false, &mut out).unwrap();
    assert_eq!(out.len(), c + TAG_LEN);
    // an empty final chunk after a non-empty stream
    assert_err!(s.seal_chunk(&[], true, &mut out), CryptoError::Misuse(_));
    s.seal_chunk(&pt(5), true, &mut out).unwrap();
    assert!(s.is_finished());
    // any chunk after the final one
    let len = out.len();
    assert_err!(
        s.seal_chunk(&pt(c), false, &mut out),
        CryptoError::Misuse(_)
    );
    assert_err!(s.seal_chunk(&pt(1), true, &mut out), CryptoError::Misuse(_));
    assert_err!(s.seal_chunk(&[], true, &mut out), CryptoError::Misuse(_));
    assert_eq!(out.len(), len);
    // what was sealed in between is a valid stream
    let stream = [&s.header()[..], &out[..]].concat();
    assert_eq!(
        *open_all(&key, StreamType::Data, &stream).unwrap(),
        [pt(c), pt(5)].concat()
    );

    // the single empty chunk of an empty stream is fine; a full final chunk is fine
    let mut s = new();
    let mut out = s.header().to_vec();
    s.seal_chunk(&[], true, &mut out).unwrap();
    assert!(s.is_finished());
    assert_eq!(out.len(), HEADER_LEN + TAG_LEN);
    assert!(open_all(&key, StreamType::Data, &out).unwrap().is_empty());
    let mut s = new();
    let mut out = s.header().to_vec();
    s.seal_chunk(&pt(c), true, &mut out).unwrap();
    assert_eq!(*open_all(&key, StreamType::Data, &out).unwrap(), pt(c));
}

#[test]
#[should_panic(expected = "chunk_log2")]
fn sealer_refuses_a_chunk_size_no_reader_accepts() {
    let key = keyring().purpose(1, Purpose::Data).unwrap();
    let _ = Sealer::new(&key, StreamType::Data, 1, 11);
}

// ---------------------------------------------------------------------------------------------
// passphrase
// ---------------------------------------------------------------------------------------------

fn shown(input: &str) -> String {
    Passphrase::from_input(input).display().to_string()
}

#[test]
fn passphrase_from_input_table() {
    // one trailing newline is dropped, nothing else is trimmed
    assert_eq!(shown("hunter2 hunter2\n"), "hunter2 hunter2");
    assert_eq!(shown("hunter2 hunter2\r\n"), "hunter2 hunter2");
    assert_eq!(shown("hunter2 hunter2"), "hunter2 hunter2");
    assert_eq!(shown("two newlines\n\n"), "two newlines\n");
    assert_eq!(shown("bare return\r"), "bare return\r");
    assert_eq!(shown("  Inner  Spaces Kept  \n"), "  Inner  Spaces Kept  ");
    assert_eq!(shown(""), "");
    assert_eq!(shown("\n"), "");

    // NFC
    assert_eq!(
        shown("e\u{301}cole polytechnique"),
        "\u{e9}cole polytechnique"
    );
    assert_eq!(
        shown("e\u{301}cole polytechnique"),
        shown("\u{e9}cole polytechnique")
    );
    assert_eq!(shown("\u{41}\u{30a}ngstro\u{308}m"), "\u{c5}ngstr\u{f6}m");
    // case and other characters are significant in a typed passphrase
    assert_ne!(shown("Correct Horse"), shown("correct horse"));

    // the generated shape is canonicalised, however it was typed
    let canonical = "ABCDE-FGHJK-MNPQR-STVWX";
    for typed in [
        "abcde-fghjk-mnpqr-stvwx",
        "ABCDE FGHJK MNPQR STVWX",
        "ABCDE-FGHJK-MNPQR-STVWX",
        "abcdefghjkmnpqrstvwx",
        " AbCdE\tfghjk - mnpqr--stvwx \n",
        "abcde-fghjk-mnpqr-stvwx\r\n",
        "abcd-efgh-jkmn-pqrs-tvwx",
    ] {
        assert_eq!(shown(typed), canonical, "{typed:?}");
    }
    // look-alikes: I and L read as 1, O as 0
    assert_eq!(shown("ilo23-45678-9abcd-efghj"), "11023-45678-9ABCD-EFGHJ");
    assert_eq!(shown("ILO23 45678 9ABCD EFGHJ"), "11023-45678-9ABCD-EFGHJ");
    assert_eq!(shown("oooooiiiiilllll00000"), "00000-11111-11111-00000");
    assert_eq!(shown("0123456789abcdefghjk"), "01234-56789-ABCDE-FGHJK");
    assert_eq!(shown("mnpqrstvwxyz01234567"), "MNPQR-STVWX-YZ012-34567");

    // anything else is left untouched
    for typed in [
        "abcde-fghjk-mnpqr-stvw",   // 19 symbols
        "abcde-fghjk-mnpqr-stvwxy", // 21 symbols
        "abcde-fghjk-mnpqr-stvwu",  // U is not a Crockford symbol
        "abcde_fghjk-mnpqr-stvwx",  // another separator
        "abcde-fghjk-mnpqr-stvw\u{e9}",
        "abcde.fghjk.mnpqr.stvwx",
        "abcde\u{a0}fghjk mnpqr stvwx", // a no-break space is not ASCII whitespace
        "correct horse battery staple",
    ] {
        assert_eq!(shown(typed), typed, "{typed:?}");
    }
}

#[test]
fn passphrase_generate() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..200 {
        let pass = Passphrase::generate();
        let text = pass.display().to_string();
        assert_eq!(text.len(), 23);
        assert_eq!(pass.char_count(), 23);
        let groups: Vec<&str> = text.split('-').collect();
        assert_eq!(groups.len(), 4);
        for group in &groups {
            assert_eq!(group.len(), 5);
            assert!(
                group.bytes().all(|b| util::CROCKFORD.contains(&b)),
                "{text}"
            );
        }
        // the canonical form is a fixed point of the normalisation
        assert_eq!(shown(&text), text);
        assert_eq!(shown(&text.to_lowercase().replace('-', " ")), text);
        assert!(Passphrase::set_checked(&text).is_ok());
        seen.insert(text);
    }
    assert_eq!(seen.len(), 200);
    // every symbol of the alphabet is drawn
    let all: String = seen.into_iter().collect();
    for symbol in util::CROCKFORD {
        assert!(all.contains(*symbol as char));
    }
}

#[test]
fn passphrase_set_checked() {
    assert_err!(Passphrase::set_checked(""), FormatError::WeakPassphrase);
    assert_err!(Passphrase::set_checked("\n"), FormatError::WeakPassphrase);
    assert_err!(
        Passphrase::set_checked("elevenchars"),
        FormatError::WeakPassphrase
    );
    assert_err!(
        Passphrase::set_checked("elevenchars\n"),
        FormatError::WeakPassphrase
    );
    assert_eq!(
        Passphrase::set_checked("twelve chars")
            .unwrap()
            .char_count(),
        12
    );
    assert_eq!(
        Passphrase::set_checked("twelve chars\r\n")
            .unwrap()
            .char_count(),
        12
    );
    // counted in Unicode scalar values, not bytes: 11 × "é" is 22 bytes
    assert_err!(
        Passphrase::set_checked(&"\u{e9}".repeat(11)),
        FormatError::WeakPassphrase
    );
    assert_eq!(
        Passphrase::set_checked(&"\u{e9}".repeat(12))
            .unwrap()
            .char_count(),
        12
    );
    // …and counted after normalisation: 6 × "e + combining acute" is 12 scalars typed, 6 in NFC
    assert_err!(
        Passphrase::set_checked(&"e\u{301}".repeat(6)),
        FormatError::WeakPassphrase
    );
    assert_eq!(Passphrase::from_input("\u{1f511}\u{1f511}").char_count(), 2);
    // set_checked normalises like from_input
    let set = Passphrase::set_checked("abcde fghjk mnpqr stvwx\n").unwrap();
    assert_eq!(*set.display(), "ABCDE-FGHJK-MNPQR-STVWX");
}

// ---------------------------------------------------------------------------------------------
// keyfile
// ---------------------------------------------------------------------------------------------

fn payload(generation: u32) -> KeyfilePayload {
    KeyfilePayload::from_keyring(&keyring(), generation, "mbp", 1_794_400_000_000)
}

fn pass() -> Passphrase {
    Passphrase::from_input("correct horse battery staple")
}

/// A keyfile written by hand around arbitrary payload bytes, named by its real hash.
fn craft_keyfile(json: &[u8], pass: &Passphrase, name_generation: u32) -> (String, Vec<u8>) {
    let preamble = KdfPreamble::generate(SMALL);
    let key = derive_pass_key(pass, &preamble).unwrap();
    let mut bytes = preamble.encode().to_vec();
    bytes.extend_from_slice(&seal_all(&key, StreamType::Bundle, 0, CHUNK_LOG2, json));
    (rename(name_generation, &bytes), bytes)
}

/// The name an attacker (or `passwd`) would give these bytes.
fn rename(generation: u32, bytes: &[u8]) -> String {
    keyfile_name(generation, blake3::hash(bytes).as_bytes())
}

#[test]
fn keyfile_round_trip() {
    let p = payload(1);
    let sealed = seal_keyfile(&p, &pass(), SMALL).unwrap();

    // the name carries the generation and the h8 of the bytes
    assert_eq!(sealed.hash, *blake3::hash(&sealed.bytes).as_bytes());
    assert_eq!(
        sealed.name,
        format!("gclone-key-00000001-{}", util::hex(&sealed.hash[..4]))
    );
    assert_eq!(
        parse_keyfile_name(&sealed.name),
        Some((1, sealed.hash[..4].try_into().unwrap()))
    );

    // layout: preamble, then one Bundle stream of epoch 0 with the production chunk size
    let preamble = KdfPreamble::decode(&sealed.bytes).unwrap();
    assert_eq!(preamble.params, SMALL);
    assert_eq!(sealed.bytes[..PREAMBLE_LEN], preamble.encode());
    let header = Header::decode(&sealed.bytes[PREAMBLE_LEN..]).unwrap();
    assert_eq!(
        (
            header.ty,
            header.epoch,
            header.chunk_log2,
            header.suite,
            header.flags
        ),
        (StreamType::Bundle, 0, CHUNK_LOG2, 1, 0)
    );
    assert!(sealed.bytes.len() as u64 <= KEYFILE_MAX);

    let opened = open_keyfile(&sealed.name, &sealed.bytes, &pass()).unwrap();
    assert!(opened == p);
    assert_eq!(opened.keyring().unwrap().export(), keyring().export());
    // the passphrase is normalised the same way when set and when entered
    let opened = open_keyfile(
        &sealed.name,
        &sealed.bytes,
        &Passphrase::from_input("correct horse battery staple\r\n"),
    );
    assert!(opened.is_ok());

    // fresh KDF salt and stream salt for every keyfile
    let again = seal_keyfile(&p, &pass(), SMALL).unwrap();
    assert_ne!(
        again.bytes[20..PREAMBLE_LEN],
        sealed.bytes[20..PREAMBLE_LEN]
    );
    assert_ne!(again.name, sealed.name);
}

#[test]
fn keyfile_round_trip_at_default_parameters() {
    let params = KdfParams::default();
    assert_eq!((params.m_kib, params.t, params.p), (262_144, 3, 1));
    let generated = Passphrase::generate();
    let p = payload(7);
    let sealed = seal_keyfile(&p, &generated, params).unwrap();
    assert_eq!(KdfPreamble::decode(&sealed.bytes).unwrap().params, params);
    let typed = Passphrase::from_input(&generated.display().to_lowercase());
    assert!(open_keyfile(&sealed.name, &sealed.bytes, &typed).unwrap() == p);
}

#[test]
fn keyfile_wrong_passphrase_and_damage() {
    let sealed = seal_keyfile(&payload(1), &pass(), SMALL).unwrap();
    let body = PREAMBLE_LEN + HEADER_LEN;

    // wrong passphrase: the commit check, distinguishable from damage
    for wrong in [
        "correct horse battery stapl",
        "Correct horse battery staple",
        "",
    ] {
        assert_err!(
            open_keyfile(&sealed.name, &sealed.bytes, &Passphrase::from_input(wrong)),
            FormatError::Crypto(CryptoError::WrongKey)
        );
    }

    // a flipped byte with the name unchanged: the h8 check
    for at in [
        0,
        9,
        25,
        PREAMBLE_LEN + 2,
        PREAMBLE_LEN + 40,
        body,
        sealed.bytes.len() - 1,
    ] {
        let bad = flipped(&sealed.bytes, at, 0x01);
        assert_err!(
            open_keyfile(&sealed.name, &bad, &pass()),
            FormatError::KeyfileDamaged,
            "byte {at}"
        );
    }

    // a flipped byte in the stream body under a recomputed name: chunk authentication
    for at in [
        body,
        body + 7,
        sealed.bytes.len() - TAG_LEN,
        sealed.bytes.len() - 1,
    ] {
        let bad = flipped(&sealed.bytes, at, 0x01);
        assert_err!(
            open_keyfile(&rename(1, &bad), &bad, &pass()),
            FormatError::Crypto(CryptoError::Corrupt),
            "byte {at}"
        );
    }
    // …in the stream header's salt or commit: the commit check
    for at in [
        PREAMBLE_LEN + 12,
        PREAMBLE_LEN + 27,
        PREAMBLE_LEN + 28,
        PREAMBLE_LEN + 59,
    ] {
        let bad = flipped(&sealed.bytes, at, 0x01);
        assert_err!(
            open_keyfile(&rename(1, &bad), &bad, &pass()),
            FormatError::Crypto(CryptoError::WrongKey),
            "byte {at}"
        );
    }
    // …in the stream header's fixed fields
    let bad = flipped(&sealed.bytes, PREAMBLE_LEN, 0x01);
    assert_err!(
        open_keyfile(&rename(1, &bad), &bad, &pass()),
        FormatError::Crypto(CryptoError::BadMagic)
    );
    let bad = flipped(&sealed.bytes, PREAMBLE_LEN + 4, 0x02);
    assert_err!(
        open_keyfile(&rename(1, &bad), &bad, &pass()),
        FormatError::Crypto(CryptoError::Unsupported(_))
    );
    // a Segment stream is not a keyfile body
    let bad = flipped(&sealed.bytes, PREAMBLE_LEN + 6, 0x07);
    assert_eq!(bad[PREAMBLE_LEN + 6], StreamType::Segment as u8);
    assert_err!(
        open_keyfile(&rename(1, &bad), &bad, &pass()),
        FormatError::Crypto(CryptoError::WrongKey)
    );

    // a flipped preamble byte under a recomputed name: the preamble is the HKDF salt of K_pass
    // (WrongKey), unless the parameters leave the accepted bounds first (KdfParams)
    for at in 0..PREAMBLE_LEN {
        let bad = flipped(&sealed.bytes, at, 0x01);
        let result = open_keyfile(&rename(1, &bad), &bad, &pass());
        match at {
            // magic
            0..=3 => assert_err!(
                result,
                FormatError::KeyfileDamaged | FormatError::KeyfileVersion(_),
                "byte {at}"
            ),
            // alg, version, reserved; 8192 ^ (1 << 24) is above the memory bound; t = 0; p = 0
            4..=8 | 15 | 19 => assert_err!(result, FormatError::KdfParams, "byte {at}"),
            // t and p high bytes
            12..=14 | 16..=18 => assert_err!(result, FormatError::KdfParams, "byte {at}"),
            // 9, 10, 11: another memory size within the bounds; 20..: the salt
            _ => assert_err!(
                result,
                FormatError::Crypto(CryptoError::WrongKey),
                "byte {at}"
            ),
        }
    }
}

#[test]
fn keyfile_kdf_bounds() {
    let sealed = seal_keyfile(&payload(1), &pass(), SMALL).unwrap();
    let with_params = |m_kib: u32, t: u32, p: u32| {
        let mut bytes = sealed.bytes.clone();
        bytes[8..12].copy_from_slice(&m_kib.to_be_bytes());
        bytes[12..16].copy_from_slice(&t.to_be_bytes());
        bytes[16..20].copy_from_slice(&p.to_be_bytes());
        bytes
    };

    // Rejected by the bounds — before Argon2 runs or allocates (the unit tests of the keyfile
    // module count the derivations; here a 1 GiB request simply returns at once).
    for (m_kib, t, p) in [
        (4096, 1, 1),
        (8191, 1, 1),
        (524_289, 1, 1),
        (1_048_576, 1, 1),
        (u32::MAX, 1, 1),
        (8192, 0, 1),
        (8192, 5, 1),
        (8192, 1, 2),
        (8192, 1, 0),
    ] {
        let params = KdfParams { m_kib, t, p };
        assert_err!(params.validate(), FormatError::KdfParams, "{params:?}");
        let bytes = with_params(m_kib, t, p);
        assert_err!(
            KdfPreamble::decode(&bytes),
            FormatError::KdfParams,
            "{params:?}"
        );
        assert_err!(
            open_keyfile(&rename(1, &bytes), &bytes, &pass()),
            FormatError::KdfParams,
            "{params:?}"
        );
        assert_err!(
            seal_keyfile(&payload(1), &pass(), params),
            FormatError::KdfParams,
            "{params:?}"
        );
        let preamble = KdfPreamble {
            params,
            salt: [1; 16],
        };
        assert_err!(
            derive_pass_key(&pass(), &preamble),
            CryptoError::Kdf(_),
            "{params:?}"
        );
    }
    // alg = 2 (Argon2i), another Argon2 version, a set reserved byte
    for (at, value) in [(4, 2), (4, 0), (5, 0x10), (6, 1), (7, 1)] {
        let mut bytes = sealed.bytes.clone();
        bytes[at] = value;
        assert_err!(
            KdfPreamble::decode(&bytes),
            FormatError::KdfParams,
            "byte {at}"
        );
        assert_err!(
            open_keyfile(&rename(1, &bytes), &bytes, &pass()),
            FormatError::KdfParams,
            "byte {at}"
        );
    }

    // the upper bounds themselves are accepted
    for (m_kib, t) in [(524_288, 4), (524_288, 1), (8192, 4), (262_144, 3)] {
        let params = KdfParams { m_kib, t, p: 1 };
        params.validate().unwrap();
        let preamble = KdfPreamble::decode(&with_params(m_kib, t, 1)).unwrap();
        assert_eq!(preamble.params, params);
        assert_eq!(preamble.salt, sealed.bytes[20..PREAMBLE_LEN]);
    }
    // …and a keyfile with accepted but different parameters derives another key
    let bytes = with_params(8192, 2, 1);
    assert_err!(
        open_keyfile(&rename(1, &bytes), &bytes, &pass()),
        FormatError::Crypto(CryptoError::WrongKey)
    );
}

#[test]
fn keyfile_payload_checks() {
    let good = serde_json::to_value(payload(4)).unwrap();
    let craft = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut v = good.clone();
        edit(&mut v);
        let (name, bytes) = craft_keyfile(&serde_json::to_vec(&v).unwrap(), &pass(), 4);
        open_keyfile(&name, &bytes, &pass())
    };
    assert!(craft(&|_| {}).unwrap() == payload(4));
    // unknown fields are ignored
    assert!(craft(&|v| v["future"] = serde_json::json!({ "x": [1, 2] })).unwrap() == payload(4));

    // payload version
    assert_err!(
        craft(&|v| v["v"] = 2.into()),
        FormatError::KeyfileVersion(2)
    );
    assert_err!(
        craft(&|v| v["v"] = 0.into()),
        FormatError::KeyfileVersion(0)
    );
    // a future version is reported as such even if the rest of the payload changed shape
    assert_err!(
        craft(&|v| *v = serde_json::json!({ "v": 3, "wrapped": "…" })),
        FormatError::KeyfileVersion(3)
    );

    // the generation in the name must be the authenticated one
    let sealed = seal_keyfile(&payload(4), &pass(), SMALL).unwrap();
    assert!(open_keyfile(&sealed.name, &sealed.bytes, &pass()).is_ok());
    for generation in [0, 3, 5, u32::MAX] {
        assert_err!(
            open_keyfile(&rename(generation, &sealed.bytes), &sealed.bytes, &pass()),
            FormatError::KeyfileDamaged
        );
    }
    assert_err!(craft(&|v| v["gen"] = 5.into()), FormatError::KeyfileDamaged);

    // keys: at least one, 32 bytes each, epochs ≥ min_epoch and distinct
    assert_err!(
        craft(&|v| v["keys"] = serde_json::json!([])),
        FormatError::KeyfileDamaged
    );
    assert_err!(
        craft(&|v| v["keys"][0]["key"] = util::b64url(&[1; 31]).into()),
        FormatError::KeyfileDamaged
    );
    assert_err!(
        craft(&|v| v["keys"][0]["key"] = util::b64url(&[1; 33]).into()),
        FormatError::KeyfileDamaged
    );
    assert_err!(
        craft(&|v| v["keys"][0]["key"] = "not base64url!".into()),
        FormatError::KeyfileDamaged
    );
    assert_err!(
        craft(&|v| v["min_epoch"] = 2.into()),
        FormatError::KeyfileDamaged
    );
    assert_err!(
        craft(&|v| v["keys"][0]["epoch"] = 0.into()),
        FormatError::KeyfileDamaged
    );
    assert_err!(
        craft(&|v| {
            let first = v["keys"][0].clone();
            v["keys"].as_array_mut().unwrap().push(first);
        }),
        FormatError::KeyfileDamaged
    );
    // vault id
    assert_err!(
        craft(&|v| v["vault_id"] = "a0a1".into()),
        FormatError::KeyfileDamaged
    );
    assert_err!(
        craft(&|v| v["vault_id"] = util::hex(&VAULT).to_uppercase().into()),
        FormatError::KeyfileDamaged
    );
    // shape
    assert_err!(
        craft(&|v| {
            v.as_object_mut().unwrap().remove("keys");
        }),
        FormatError::KeyfileDamaged
    );
    assert_err!(
        craft(&|v| {
            v.as_object_mut().unwrap().remove("v");
        }),
        FormatError::KeyfileDamaged
    );
    assert_err!(
        craft(&|v| v["gen"] = "1".into()),
        FormatError::KeyfileDamaged
    );
    for not_a_payload in [&b""[..], b"not json", b"[1]", b"{\"v\":1}"] {
        let (name, bytes) = craft_keyfile(not_a_payload, &pass(), 4);
        assert_err!(
            open_keyfile(&name, &bytes, &pass()),
            FormatError::KeyfileDamaged
        );
    }

    // size limits and names
    let sealed = seal_keyfile(&payload(4), &pass(), SMALL).unwrap();
    let oversize = vec![0u8; KEYFILE_MAX as usize + 1];
    assert_err!(
        open_keyfile(&rename(4, &oversize), &oversize, &pass()),
        FormatError::KeyfileDamaged
    );
    for len in [0, 1, PREAMBLE_LEN, PREAMBLE_LEN + 75] {
        let short = &sealed.bytes[..len];
        assert_err!(
            open_keyfile(&rename(4, short), short, &pass()),
            FormatError::KeyfileDamaged,
            "{len} bytes"
        );
    }
    for name in [
        "",
        "gclone-key-",
        "gclone-vault.json",
        &sealed.name[1..],
        &sealed.name.to_uppercase(),
    ] {
        assert_err!(
            open_keyfile(name, &sealed.bytes, &pass()),
            FormatError::KeyfileDamaged,
            "{name:?}"
        );
    }
    // a keyfile of exactly KEYFILE_MAX bytes is still read (and then fails on its content)
    let mut largest = sealed.bytes.clone();
    largest.resize(KEYFILE_MAX as usize, 0);
    assert_err!(
        open_keyfile(&rename(4, &largest), &largest, &pass()),
        FormatError::Crypto(CryptoError::Corrupt | CryptoError::TrailingData)
    );
}

#[test]
fn keyfile_names() {
    let hash: [u8; 32] =
        std::array::from_fn(|i| 0xab_u8.wrapping_add((i as u8).wrapping_mul(0x22)));
    assert_eq!(KEYFILE_PREFIX, "gclone-key-");
    assert_eq!(keyfile_name(1, &hash), "gclone-key-00000001-abcdef11");
    for generation in [0, 1, 0x10, 0x1234_abcd, 0xffff_fffe, 0xffff_ffff] {
        let name = keyfile_name(generation, &hash);
        assert_eq!(name.len(), KEYFILE_PREFIX.len() + 8 + 1 + 8);
        assert_eq!(
            parse_keyfile_name(&name),
            Some((generation, [0xab, 0xcd, 0xef, 0x11]))
        );
    }
    assert_eq!(
        keyfile_name(u32::MAX, &hash),
        "gclone-key-ffffffff-abcdef11"
    );
    for bad in [
        "",
        "gclone-key-",
        "gclone-kex-00000001-abcdef11", // wrong prefix
        "Gclone-key-00000001-abcdef11",
        "xgclone-key-00000001-abcdef11",
        "gclone-key-0000001-abcdef11",   // 7-digit gen
        "gclone-key-000000001-abcdef11", // 9-digit gen
        "gclone-key-0000000A-abcdef11",  // upper-case hex
        "gclone-key-00000001-ABCDEF11",
        "gclone-key-00000001-abcdef1",
        "gclone-key-00000001-abcdef111",
        "gclone-key-00000001",
        "gclone-key-00000001-",
        "gclone-key-00000001-abcdef11-",
        "gclone-key-00000001-abcdef11.bak",
        "gclone-key-0000000g-abcdef11",
        "gclone-key-+0000001-abcdef11",
        "gclone-key-00000001_abcdef11",
        "gclone-key-00000001-abcdef11 ",
    ] {
        assert_eq!(parse_keyfile_name(bad), None, "{bad:?}");
    }
}

#[test]
fn keyfile_payload_and_keyring() {
    // from_keyring(..).keyring() reproduces the keyring: epochs, keys, min_epoch, vault id
    let keys = Keyring::new(VAULT, vec![(5, master(0x50)), (3, master(0x30))], 2).unwrap();
    let p = KeyfilePayload::from_keyring(&keys, 9, "pi", 123);
    assert_eq!(
        (p.v, p.generation, p.min_epoch, p.created_ms),
        (1, 9, 2, 123)
    );
    assert_eq!(p.by, "pi");
    assert_eq!(p.vault_id, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    assert_eq!(p.vault_id_bytes().unwrap(), VAULT);
    assert_eq!(p.keys.iter().map(|k| k.epoch).collect::<Vec<_>>(), [3, 5]);
    assert_eq!(
        util::unb64url(&p.keys[1].key).unwrap(),
        master(0x50).expose()
    );
    let back = p.keyring().unwrap();
    assert_eq!(back.vault_id(), VAULT);
    assert_eq!((back.current_epoch(), back.min_epoch()), (5, 2));
    assert_eq!(back.export(), keys.export());
    // the reproduced keyring is the same keyring
    let sealed = keys
        .seal(StreamType::Snapshot, b"from the original")
        .unwrap();
    assert_eq!(
        *back.open(StreamType::Snapshot, &sealed).unwrap(),
        *b"from the original"
    );

    // the wire spelling of `generation` is "gen"
    let json = serde_json::to_value(&p).unwrap();
    assert_eq!(json["gen"], 9);
    assert!(json.get("generation").is_none());
    let mut fields: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "by",
            "created_ms",
            "gen",
            "keys",
            "min_epoch",
            "v",
            "vault_id"
        ]
    );
    assert!(serde_json::from_value::<KeyfilePayload>(json).unwrap() == p);

    // the literal JSON of §2.6 deserializes…
    let literal = r#"{ "v": 1, "vault_id": "<32 hex>", "gen": 1,
      "keys": [ { "epoch": 1, "key": "<base64url-nopad 32 bytes>" } ], "min_epoch": 1,
      "created_ms": 1794400000000, "by": "mbp" }"#;
    let parsed: KeyfilePayload = serde_json::from_str(literal).unwrap();
    assert_eq!((parsed.v, parsed.generation, parsed.min_epoch), (1, 1, 1));
    assert_eq!(parsed.created_ms, 1_794_400_000_000);
    assert_eq!(parsed.vault_id, "<32 hex>");
    assert!(
        parsed.keys
            == [KeyfileKey {
                epoch: 1,
                key: "<base64url-nopad 32 bytes>".into()
            }]
    );
    // …and its placeholders are, of course, no keys
    assert_err!(parsed.vault_id_bytes(), FormatError::KeyfileDamaged);
    assert_err!(parsed.keyring(), FormatError::KeyfileDamaged);
    // with real values filled in it is exactly what from_keyring writes
    let filled = literal.replace("<32 hex>", &util::hex(&VAULT)).replace(
        "<base64url-nopad 32 bytes>",
        &util::b64url(master(0).expose()),
    );
    let parsed: KeyfilePayload = serde_json::from_str(&filled).unwrap();
    assert!(parsed == payload(1));
    assert_eq!(parsed.keyring().unwrap().export(), keyring().export());
    // `generation` is not an accepted spelling
    assert!(
        serde_json::from_str::<KeyfilePayload>(&filled.replace("\"gen\"", "\"generation\""))
            .is_err()
    );
}

// ---------------------------------------------------------------------------------------------
// index objects
// ---------------------------------------------------------------------------------------------

fn stamp(lamport: u64, device: DeviceId, idx: u32) -> Stamp {
    Stamp {
        lamport,
        device,
        idx,
    }
}

fn seg_ref(device: DeviceId, seq: u64, fill: u8) -> SegRef {
    SegRef {
        device,
        seq,
        hash: [fill; 32],
        file_id: format!("id-{fill:02x}"),
    }
}

fn file_entry(size: u64) -> Entry {
    Entry {
        kind: EntryKind::File,
        size,
        mtime_ns: 1_794_400_000_000_000_000,
        exec: false,
        hash: [0x77; 32],
        loc: Some(Loc {
            blob: BlobId([0xb0; 16]),
            off: 60,
            clen: ciphertext_len(size, CHUNK_LOG2),
            salt: [0x5a; 16],
            chunk_log2: CHUNK_LOG2,
            epoch: 1,
            suite: 1,
            flags: 0,
        }),
    }
}

fn put(path: &str, entry: Entry) -> Op {
    Op::Put {
        path: path.into(),
        entry,
        base: None,
        origin: None,
    }
}

fn segment() -> SegmentV1 {
    SegmentV1 {
        vault_id: VAULT,
        device: DEV_A,
        seq: 2,
        lamport: 17,
        prev: Some(seg_ref(DEV_A, 1, 0x11)),
        seen: vec![seg_ref(DEV_B, 9, 0x22)],
        created_ms: 1_794_400_000_000,
        host: "mbp".into(),
        ops: vec![
            Op::VaultInit {
                format: 1,
                name: "gclone".into(),
            },
            Op::Device {
                id: DEV_A,
                name: "mbp".into(),
            },
            Op::Blob(BlobRec {
                id: BlobId([0xb0; 16]),
                file_id: "drive-file-id".into(),
                clen: 1 << 20,
                md5: [0x5d; 16],
                created_ms: 1_794_400_000_001,
            }),
            Op::Put {
                path: "Photos/2026/\u{e9}t\u{e9}.jpg".into(),
                entry: file_entry(100_000),
                base: Some(stamp(16, DEV_B, 3)),
                origin: Some(stamp(2, DEV_A, 0)),
            },
            put("Photos/empty", Entry::empty_file(5, true)),
            put("Photos/dir", Entry::dir()),
            Op::Del {
                path: "old.txt".into(),
                base: stamp(16, DEV_B, 4),
            },
        ],
    }
}

fn snapshot() -> SnapshotV1 {
    let tip_a = seg_ref(DEV_A, 2, 0x33);
    let tip_b = seg_ref(DEV_B, 9, 0x22);
    SnapshotV1 {
        vault_id: VAULT,
        device: DEV_B,
        lamport: 18,
        created_ms: 1_794_400_000_500,
        vault_format: 1,
        vault_name: "gclone".into(),
        covered: vec![
            seg_ref(DEV_A, 1, 0x11).covered(),
            tip_a.covered(),
            // a fork: two segments with the same (device, seq)
            seg_ref(DEV_B, 9, 0x21).covered(),
            tip_b.covered(),
        ],
        covers: vec![tip_a, tip_b],
        devices: vec![DeviceRec {
            id: DEV_A,
            name: "mbp".into(),
            first_ms: 1,
        }],
        blobs: vec![],
        heads: vec![
            HeadRec {
                path: "Photos/2026/\u{e9}t\u{e9}.jpg".into(),
                stamp: stamp(17, DEV_A, 3),
                entry: file_entry(100_000),
                origin: None,
            },
            HeadRec {
                path: "Photos/dir".into(),
                stamp: stamp(17, DEV_A, 5),
                entry: Entry::dir(),
                origin: None,
            },
        ],
        removed: vec![RemovedRec {
            path: "old.txt".into(),
            stamp: stamp(3, DEV_B, 0),
            entry: file_entry(7),
            removed_ms: 1_794_400_000_400,
            by: stamp(17, DEV_A, 6),
        }],
    }
}

/// `codec ‖ postcard(body) ‖ extra`, sealed and named by hand: what a device holding the keys
/// could write without going through `seal_segment`'s checks.
fn craft_segment(keys: &Keyring, seg: &SegmentV1, codec: u8, extra: &[u8]) -> (String, Vec<u8>) {
    let mut plain = vec![codec];
    plain.extend(postcard::to_stdvec(&SegmentBody::V1(seg.clone())).unwrap());
    plain.extend_from_slice(extra);
    let bytes = keys.seal(StreamType::Segment, &plain).unwrap();
    (
        segment_name(seg.device, seg.seq, blake3::hash(&bytes).as_bytes()),
        bytes,
    )
}

fn craft_snapshot(keys: &Keyring, snap: &SnapshotV1, codec: u8, extra: &[u8]) -> (String, Vec<u8>) {
    let mut plain = vec![codec];
    plain.extend(postcard::to_stdvec(&SnapshotBody::V1(snap.clone())).unwrap());
    plain.extend_from_slice(extra);
    let bytes = keys.seal(StreamType::Snapshot, &plain).unwrap();
    (
        snapshot_name(snap.lamport, snap.device, blake3::hash(&bytes).as_bytes()),
        bytes,
    )
}

fn open_crafted_segment(seg: &SegmentV1) -> Result<(SegmentV1, [u8; 32]), FormatError> {
    let keys = keyring();
    let (name, bytes) = craft_segment(&keys, seg, 0, &[]);
    open_segment(&keys, &name, &bytes)
}

fn open_crafted_snapshot(snap: &SnapshotV1) -> Result<(SnapshotV1, [u8; 32]), FormatError> {
    let keys = keyring();
    let (name, bytes) = craft_snapshot(&keys, snap, 0, &[]);
    open_snapshot(&keys, &name, &bytes)
}

#[test]
fn index_names() {
    let hash: [u8; 32] =
        std::array::from_fn(|i| 0xab_u8.wrapping_add((i as u8).wrapping_mul(0x22)));
    let h8 = [0xab, 0xcd, 0xef, 0x11];

    let name = segment_name(DEV_A, 0x1_0002, &hash);
    assert_eq!(name, "s-d0d1d2d3d4d5d6d7-0000000000010002-abcdef11");
    assert_eq!(
        parse_index_name(&name),
        Some(IndexName::Segment {
            device: DEV_A,
            seq: 0x1_0002,
            h8
        })
    );
    let name = snapshot_name(0xfedc_ba98_7654_3210, DEV_B, &hash);
    assert_eq!(name, "c-fedcba9876543210-e0e1e2e3e4e5e6e7-abcdef11");
    assert_eq!(
        parse_index_name(&name),
        Some(IndexName::Snapshot {
            lamport: 0xfedc_ba98_7654_3210,
            device: DEV_B,
            h8
        })
    );
    for n in [0, 1, u64::MAX] {
        assert_eq!(
            parse_index_name(&segment_name(DEV_B, n, &hash)),
            Some(IndexName::Segment {
                device: DEV_B,
                seq: n,
                h8
            })
        );
        assert_eq!(
            parse_index_name(&snapshot_name(n, DEV_A, &hash)),
            Some(IndexName::Snapshot {
                lamport: n,
                device: DEV_A,
                h8
            })
        );
    }

    for bad in [
        "",
        "s",
        "s-",
        "s-zzd1d2d3d4d5d6d7-0000000000010002-abcdef11", // not hex
        "s-d0d1d2d3d4d5d6d7-000000000001000z-abcdef11",
        "s-d0d1d2d3d4d5d6d7-0000000000010002-abcdefzz",
        "s-d0d1d2d3d4d5d6-0000000000010002-abcdef11", // wrong lengths
        "s-d0d1d2d3d4d5d6d7d8-0000000000010002-abcdef11",
        "s-d0d1d2d3d4d5d6d7-000000000010002-abcdef11",
        "s-d0d1d2d3d4d5d6d7-00000000000010002-abcdef11",
        "s-d0d1d2d3d4d5d6d7-0000000000010002-abcdef1",
        "s-d0d1d2d3d4d5d6d7-0000000000010002-abcdef111",
        "s-d0d1d2d3d4d5d6d7-0000000000010002", // missing parts
        "s-d0d1d2d3d4d5d6d7-0000000000010002-",
        "s-d0d1d2d3d4d5d6d7-0000000000010002-abcdef11-", // extra parts
        "s-d0d1d2d3d4d5d6d7-0000000000010002-abcdef11-00",
        "s-D0D1D2D3D4D5D6D7-0000000000010002-abcdef11", // upper case
        "s-d0d1d2d3d4d5d6d7-0000000000010002-ABCDEF11",
        "S-d0d1d2d3d4d5d6d7-0000000000010002-abcdef11",
        "x-d0d1d2d3d4d5d6d7-0000000000010002-abcdef11", // unknown kind
        "ss-d0d1d2d3d4d5d6d7-0000000000010002-abcdef11",
        " s-d0d1d2d3d4d5d6d7-0000000000010002-abcdef11",
        "s-d0d1d2d3d4d5d6d7-0000000000010002-abcdef11.tmp",
        "c-fedcba9876543210-e0e1e2e3e4e5e6-abcdef11",
        "c-fedcba987654321-e0e1e2e3e4e5e6e7-abcdef11",
        "gclone-vault.json",
        "gclone-key-00000001-abcdef11",
    ] {
        assert_eq!(parse_index_name(bad), None, "{bad:?}");
    }
}

#[test]
fn segment_and_snapshot_round_trip() {
    let keys = keyring();

    let seg = segment();
    let sealed = seal_segment(&keys, &seg).unwrap();
    assert_eq!(sealed.hash, *blake3::hash(&sealed.bytes).as_bytes());
    assert_eq!(sealed.name, segment_name(DEV_A, 2, &sealed.hash));
    assert_eq!(
        parse_index_name(&sealed.name),
        Some(IndexName::Segment {
            device: DEV_A,
            seq: 2,
            h8: sealed.hash[..4].try_into().unwrap()
        })
    );
    assert_eq!(
        Header::decode(&sealed.bytes).unwrap().ty,
        StreamType::Segment
    );
    let (opened, hash) = open_segment(&keys, &sealed.name, &sealed.bytes).unwrap();
    assert_eq!(opened, seg);
    assert_eq!(hash, sealed.hash);
    // plaintext = codec 0x00 ‖ postcard(SegmentBody::V1)
    let plain = keys.open(StreamType::Segment, &sealed.bytes).unwrap();
    assert_eq!(plain[0], 0x00);
    assert_eq!(
        plain[1..],
        postcard::to_stdvec(&SegmentBody::V1(seg.clone())).unwrap()
    );

    let snap = snapshot();
    let sealed_snap = seal_snapshot(&keys, &snap).unwrap();
    assert_eq!(
        sealed_snap.name,
        snapshot_name(18, DEV_B, &sealed_snap.hash)
    );
    assert_eq!(
        Header::decode(&sealed_snap.bytes).unwrap().ty,
        StreamType::Snapshot
    );
    let (opened, hash) = open_snapshot(&keys, &sealed_snap.name, &sealed_snap.bytes).unwrap();
    assert_eq!(opened, snap);
    assert_eq!(hash, *blake3::hash(&sealed_snap.bytes).as_bytes());
    let plain = keys.open(StreamType::Snapshot, &sealed_snap.bytes).unwrap();
    assert_eq!(plain[0], 0x00);
    assert_eq!(
        plain[1..],
        postcard::to_stdvec(&SnapshotBody::V1(snap.clone())).unwrap()
    );

    // minimal objects
    let first = SegmentV1 {
        seq: 1,
        prev: None,
        seen: vec![],
        ops: vec![],
        ..segment()
    };
    let sealed_first = seal_segment(&keys, &first).unwrap();
    assert_eq!(
        open_segment(&keys, &sealed_first.name, &sealed_first.bytes)
            .unwrap()
            .0,
        first
    );
    let empty = SnapshotV1 {
        covers: vec![],
        covered: vec![],
        devices: vec![],
        heads: vec![],
        removed: vec![],
        ..snapshot()
    };
    let sealed_empty = seal_snapshot(&keys, &empty).unwrap();
    assert_eq!(
        open_snapshot(&keys, &sealed_empty.name, &sealed_empty.bytes)
            .unwrap()
            .0,
        empty
    );

    // the hand-written objects of the negative tests below are accepted when nothing is wrong
    assert_eq!(open_crafted_segment(&seg).unwrap().0, seg);
    assert_eq!(open_crafted_snapshot(&snap).unwrap().0, snap);

    // the two kinds are not interchangeable
    assert_err!(
        open_snapshot(&keys, &sealed.name, &sealed.bytes),
        FormatError::BadName(_)
    );
    assert_err!(
        open_segment(&keys, &sealed_snap.name, &sealed_snap.bytes),
        FormatError::BadName(_)
    );
}

#[test]
fn op_from_draft_keeps_the_op() {
    let draft = OpDraft::Put {
        path: "a/b".into(),
        entry: file_entry(10),
        base: Some(stamp(1, DEV_A, 2)),
        origin: None,
        effect: None,
    };
    assert_eq!(
        op_from_draft(&draft),
        Op::Put {
            path: "a/b".into(),
            entry: file_entry(10),
            base: Some(stamp(1, DEV_A, 2)),
            origin: None
        }
    );
    let draft = OpDraft::Del {
        path: "a/b".into(),
        base: stamp(1, DEV_A, 2),
        effect: None,
    };
    assert_eq!(
        op_from_draft(&draft),
        Op::Del {
            path: "a/b".into(),
            base: stamp(1, DEV_A, 2)
        }
    );
}

#[test]
fn index_rule_1_name_hash() {
    let keys = keyring();
    let sealed = seal_segment(&keys, &segment()).unwrap();

    // renamed: another h8
    let other_h8 = segment_name(DEV_A, 2, &[0; 32]);
    assert_err!(
        open_segment(&keys, &other_h8, &sealed.bytes),
        FormatError::IdentityMismatch(_)
    );
    // damaged: the bytes no longer match the name
    for at in [0, 30, HEADER_LEN + 1, sealed.bytes.len() - 1] {
        let bad = flipped(&sealed.bytes, at, 0x01);
        assert_err!(
            open_segment(&keys, &sealed.name, &bad),
            FormatError::IdentityMismatch(_),
            "byte {at}"
        );
    }
    assert_err!(
        open_segment(&keys, &sealed.name, &[]),
        FormatError::IdentityMismatch(_)
    );
    // not an index object name at all
    for name in [
        "",
        "gclone-vault.json",
        &sealed.name[1..],
        &sealed.name.to_uppercase(),
    ] {
        assert_err!(
            open_segment(&keys, name, &sealed.bytes),
            FormatError::BadName(_),
            "{name:?}"
        );
    }

    let sealed = seal_snapshot(&keys, &snapshot()).unwrap();
    let other_h8 = snapshot_name(18, DEV_B, &[0; 32]);
    assert_err!(
        open_snapshot(&keys, &other_h8, &sealed.bytes),
        FormatError::IdentityMismatch(_)
    );
    let bad = flipped(&sealed.bytes, 70, 0x80);
    assert_err!(
        open_snapshot(&keys, &sealed.name, &bad),
        FormatError::IdentityMismatch(_)
    );
}

#[test]
fn index_rule_2_type_commit_and_every_chunk() {
    let keys = keyring();

    // a segment long enough for several chunks
    let mut big = segment();
    big.ops = (0..3000)
        .map(|i| {
            put(
                &format!("dir-{:03}/a-rather-long-file-name-{i:06}.bin", i % 50),
                file_entry(1 + i),
            )
        })
        .collect();
    let sealed = seal_segment(&keys, &big).unwrap();
    let plain_len = plaintext_len(sealed.bytes.len() as u64, CHUNK_LOG2).unwrap();
    let spans = chunk_spans(plain_len, CHUNK_LOG2);
    assert!(spans.len() >= 3, "{} chunks", spans.len());
    assert_eq!(
        open_segment(&keys, &sealed.name, &sealed.bytes).unwrap().0,
        big
    );
    let rehashed = |bytes: &[u8]| segment_name(DEV_A, 2, blake3::hash(bytes).as_bytes());

    // truncated at a chunk boundary (and renamed to match): no partial parse
    for span in &spans[..spans.len() - 1] {
        let cut = &sealed.bytes[..span.end];
        assert_err!(
            open_segment(&keys, &rehashed(cut), cut),
            FormatError::Crypto(CryptoError::Truncated)
        );
    }
    let header_only = &sealed.bytes[..HEADER_LEN];
    assert_err!(
        open_segment(&keys, &rehashed(header_only), header_only),
        FormatError::Crypto(CryptoError::Truncated)
    );
    // a damaged chunk anywhere, the last one included
    for span in &spans {
        let bad = flipped(&sealed.bytes, span.start + 5, 0x01);
        assert_err!(
            open_segment(&keys, &rehashed(&bad), &bad),
            FormatError::Crypto(CryptoError::Corrupt)
        );
    }
    // a dropped middle chunk, a trailing chunk
    let dropped = rebuild(&sealed.bytes, &spans, &[0, 2]);
    assert_err!(
        open_segment(&keys, &rehashed(&dropped), &dropped),
        FormatError::Crypto(CryptoError::Corrupt)
    );

    // the header type must match the name prefix: a snapshot stream under a segment name
    let (_, snap_bytes) = craft_snapshot(&keys, &snapshot(), 0, &[]);
    assert_err!(
        open_segment(&keys, &rehashed(&snap_bytes), &snap_bytes),
        FormatError::Crypto(CryptoError::WrongKey)
    );
    let (_, seg_bytes) = craft_segment(&keys, &segment(), 0, &[]);
    let as_snapshot = snapshot_name(18, DEV_B, blake3::hash(&seg_bytes).as_bytes());
    assert_err!(
        open_snapshot(&keys, &as_snapshot, &seg_bytes),
        FormatError::Crypto(CryptoError::WrongKey)
    );
    // a Data stream is no index object
    let data = keys.seal(StreamType::Data, &pt(500)).unwrap();
    assert_err!(
        open_segment(&keys, &rehashed(&data), &data),
        FormatError::Crypto(CryptoError::WrongKey)
    );

    // commit: another master key, another vault's keyring, an epoch this device does not hold
    let other_key = Keyring::new(VAULT, vec![(1, master(0x80))], 1).unwrap();
    assert_err!(
        open_segment(&other_key, &sealed.name, &sealed.bytes),
        FormatError::Crypto(CryptoError::WrongKey)
    );
    let other_vault = Keyring::new([9; 16], vec![(1, master(0))], 1).unwrap();
    assert_err!(
        open_segment(&other_vault, &sealed.name, &sealed.bytes),
        FormatError::Crypto(CryptoError::WrongKey)
    );
    let newer = Keyring::new(VAULT, vec![(1, master(0)), (2, master(0x40))], 1).unwrap();
    let from_newer = seal_segment(&newer, &segment()).unwrap();
    assert_err!(
        open_segment(&keys, &from_newer.name, &from_newer.bytes),
        FormatError::Crypto(CryptoError::UnknownEpoch(2))
    );
    assert_eq!(
        open_segment(&newer, &sealed.name, &sealed.bytes).unwrap().0,
        big
    );
}

#[test]
fn index_rule_3_codec_and_postcard() {
    let keys = keyring();
    let seg = segment();
    let snap = snapshot();

    // unknown codec (0x01 is reserved for zstd + postcard)
    for codec in [1u8, 2, 0xff] {
        let (name, bytes) = craft_segment(&keys, &seg, codec, &[]);
        assert_err!(open_segment(&keys, &name, &bytes), FormatError::Codec(c) if c == codec);
        let (name, bytes) = craft_snapshot(&keys, &snap, codec, &[]);
        assert_err!(open_snapshot(&keys, &name, &bytes), FormatError::Codec(c) if c == codec);
    }
    // trailing postcard bytes
    for extra in [&[0u8][..], &[0, 0, 0], b"more"] {
        let (name, bytes) = craft_segment(&keys, &seg, 0, extra);
        assert_err!(open_segment(&keys, &name, &bytes), FormatError::Decode(_));
        let (name, bytes) = craft_snapshot(&keys, &snap, 0, extra);
        assert_err!(open_snapshot(&keys, &name, &bytes), FormatError::Decode(_));
    }

    // arbitrary plaintexts sealed with the right key and named correctly
    let body = postcard::to_stdvec(&SegmentBody::V1(seg.clone())).unwrap();
    let mut future_version = [&[0u8][..], &body].concat();
    future_version[1] = 1;
    let truncated = [&[0u8][..], &body[..body.len() - 1]].concat();
    let snapshot_body = [
        &[0u8][..],
        &postcard::to_stdvec(&SnapshotBody::V1(snap)).unwrap(),
    ]
    .concat();
    for plain in [&[][..], &[0], &truncated, &snapshot_body, b"\0\0garbage"] {
        let bytes = keys.seal(StreamType::Segment, plain).unwrap();
        let name = segment_name(DEV_A, 2, blake3::hash(&bytes).as_bytes());
        assert_err!(
            open_segment(&keys, &name, &bytes),
            FormatError::Decode(_),
            "{} bytes",
            plain.len()
        );
    }
    // A body whose version tag is not V1 is not "undecodable": it has its own error, and it
    // is one of the refusals that mean "written by a newer gclone" (§4.6).
    for (plain, tag) in [(&future_version[..], 1u8), (&b"\0garbage"[..], b'g')] {
        let bytes = keys.seal(StreamType::Segment, plain).unwrap();
        let name = segment_name(DEV_A, 2, blake3::hash(&bytes).as_bytes());
        let err = open_segment(&keys, &name, &bytes).unwrap_err();
        assert!(
            matches!(err, FormatError::BodyVersion(v) if v == tag),
            "{err:?}"
        );
        assert!(err.newer_format().is_some());
        assert!(err.to_string().contains("needs a newer gclone"));
    }
    let (name, bytes) = craft_segment(&keys, &seg, 1, &[]);
    assert!(
        open_segment(&keys, &name, &bytes)
            .unwrap_err()
            .newer_format()
            .is_some()
    );
    let (name, bytes) = craft_segment(&keys, &seg, 0, b"more");
    assert!(
        open_segment(&keys, &name, &bytes)
            .unwrap_err()
            .newer_format()
            .is_none()
    );
}

#[test]
fn index_rule_4_identity() {
    let keys = keyring();

    // wrong vault: the inner vault id is not the local one (sealed with the right keys)
    let foreign = SegmentV1 {
        vault_id: [9; 16],
        ..segment()
    };
    assert_err!(
        open_crafted_segment(&foreign),
        FormatError::IdentityMismatch(_)
    );
    assert_err!(
        seal_segment(&keys, &foreign),
        FormatError::IdentityMismatch(_)
    );
    let foreign = SnapshotV1 {
        vault_id: [9; 16],
        ..snapshot()
    };
    assert_err!(
        open_crafted_snapshot(&foreign),
        FormatError::IdentityMismatch(_)
    );
    assert_err!(
        seal_snapshot(&keys, &foreign),
        FormatError::IdentityMismatch(_)
    );

    // renamed: the name's device / seq (or lamport / device) with the right h8
    let sealed = seal_segment(&keys, &segment()).unwrap();
    for name in [
        segment_name(DEV_B, 2, &sealed.hash),
        segment_name(DEV_A, 3, &sealed.hash),
        segment_name(DEV_A, 1, &sealed.hash),
    ] {
        assert_err!(
            open_segment(&keys, &name, &sealed.bytes),
            FormatError::IdentityMismatch(_),
            "{name}"
        );
    }
    let sealed = seal_snapshot(&keys, &snapshot()).unwrap();
    for name in [
        snapshot_name(18, DEV_A, &sealed.hash),
        snapshot_name(19, DEV_B, &sealed.hash),
        snapshot_name(0, DEV_B, &sealed.hash),
    ] {
        assert_err!(
            open_snapshot(&keys, &name, &sealed.bytes),
            FormatError::IdentityMismatch(_),
            "{name}"
        );
    }
}

#[test]
fn index_rule_5_paths() {
    let keys = keyring();
    let cases: [(&str, PathError); 8] = [
        ("../x", PathError::DotComponent),
        ("a/../b", PathError::DotComponent),
        ("a/./b", PathError::DotComponent),
        ("", PathError::Empty),
        ("/etc/passwd", PathError::Absolute),
        ("a//b", PathError::EmptyComponent),
        ("a/b/", PathError::EmptyComponent),
        ("a\0b", PathError::Nul),
    ];
    for (path, expected) in cases {
        // one invalid path rejects the object as a whole
        let mut seg = segment();
        seg.ops.push(put(path, Entry::dir()));
        assert_err!(open_crafted_segment(&seg), FormatError::Path(e) if e == expected, "{path:?}");
        assert_err!(seal_segment(&keys, &seg), FormatError::Path(e) if e == expected, "{path:?}");

        let mut seg = segment();
        seg.ops.insert(
            0,
            Op::Del {
                path: path.into(),
                base: stamp(1, DEV_A, 0),
            },
        );
        assert_err!(open_crafted_segment(&seg), FormatError::Path(e) if e == expected, "{path:?}");
        assert_err!(seal_segment(&keys, &seg), FormatError::Path(e) if e == expected, "{path:?}");

        let mut snap = snapshot();
        snap.heads[1].path = path.into();
        assert_err!(open_crafted_snapshot(&snap), FormatError::Path(e) if e == expected, "{path:?}");
        assert_err!(seal_snapshot(&keys, &snap), FormatError::Path(e) if e == expected, "{path:?}");

        let mut snap = snapshot();
        snap.removed[0].path = path.into();
        assert_err!(open_crafted_snapshot(&snap), FormatError::Path(e) if e == expected, "{path:?}");
        assert_err!(seal_snapshot(&keys, &snap), FormatError::Path(e) if e == expected, "{path:?}");
    }
    let long = "x".repeat(256);
    let mut seg = segment();
    seg.ops.push(put(&long, Entry::dir()));
    assert_err!(
        open_crafted_segment(&seg),
        FormatError::Path(PathError::ComponentTooLong)
    );
}

/// A named way to break a value.
type Edit<T> = (&'static str, fn(&mut T));

#[test]
fn index_rule_6_entries() {
    let keys = keyring();
    let edits: [Edit<Entry>; 12] = [
        ("clen one too small", |e| e.loc.as_mut().unwrap().clen -= 1),
        ("clen one too large", |e| e.loc.as_mut().unwrap().clen += 1),
        ("size one too large", |e| e.size += 1),
        ("chunk_log2 = 11", |e| {
            let loc = e.loc.as_mut().unwrap();
            loc.chunk_log2 = 11;
            loc.clen = 60 + e.size + 16 * e.size.div_ceil(1 << 11);
        }),
        ("chunk_log2 = 25", |e| {
            e.loc.as_mut().unwrap().chunk_log2 = 25
        }),
        ("chunk_log2 = 0", |e| e.loc.as_mut().unwrap().chunk_log2 = 0),
        ("chunk_log2 = 255", |e| {
            e.loc.as_mut().unwrap().chunk_log2 = 255
        }),
        ("chunk size and clen disagree", |e| {
            e.loc.as_mut().unwrap().chunk_log2 = 12
        }),
        ("directory with a data location", |e| {
            e.kind = EntryKind::Dir
        }),
        ("empty file with a data location", |e| {
            e.size = 0;
            e.loc.as_mut().unwrap().clen = 76;
        }),
        ("file without a data location", |e| e.loc = None),
        ("absurd size", |e| {
            e.size = u64::MAX;
            e.loc.as_mut().unwrap().clen = u64::MAX;
        }),
    ];
    for (what, edit) in edits {
        let mut entry = file_entry(100_000);
        edit(&mut entry);

        let mut seg = segment();
        seg.ops.push(put("bad/entry", entry.clone()));
        assert_err!(open_crafted_segment(&seg), FormatError::BadEntry(m) if m.contains("bad/entry"), "{what}");
        assert_err!(
            seal_segment(&keys, &seg),
            FormatError::BadEntry(_),
            "{what}"
        );

        let mut snap = snapshot();
        snap.heads[0].entry = entry.clone();
        assert_err!(
            open_crafted_snapshot(&snap),
            FormatError::BadEntry(_),
            "{what}"
        );
        assert_err!(
            seal_snapshot(&keys, &snap),
            FormatError::BadEntry(_),
            "{what}"
        );

        let mut snap = snapshot();
        snap.removed[0].entry = entry;
        assert_err!(
            open_crafted_snapshot(&snap),
            FormatError::BadEntry(_),
            "{what}"
        );
        assert_err!(
            seal_snapshot(&keys, &snap),
            FormatError::BadEntry(_),
            "{what}"
        );
    }

    // well-formed shapes: every accepted chunk size, a directory, an empty file
    for chunk_log2 in [12u8, 16, 24] {
        let mut entry = file_entry(100_000);
        let loc = entry.loc.as_mut().unwrap();
        loc.chunk_log2 = chunk_log2;
        loc.clen = ciphertext_len(100_000, chunk_log2);
        let mut seg = segment();
        seg.ops.push(put("ok", entry));
        assert!(
            open_crafted_segment(&seg).is_ok(),
            "chunk_log2 {chunk_log2}"
        );
    }

    // An unknown suite or non-zero flags is NOT a rejection: the entry is kept, and reading it
    // fails with Unsupported ("needs a newer gclone").
    for edit in [(|l: &mut Loc| l.suite = 2) as fn(&mut Loc), |l| l.flags = 1] {
        let mut entry = file_entry(100_000);
        edit(entry.loc.as_mut().unwrap());
        let mut seg = segment();
        seg.ops.push(put("from/the/future", entry.clone()));
        let (opened, _) = open_crafted_segment(&seg).unwrap();
        assert_eq!(opened, seg);
        assert!(seal_segment(&keys, &seg).is_ok());
        assert_err!(
            keys.data_opener(entry.loc.as_ref().unwrap()),
            CryptoError::Unsupported(_)
        );
    }
}

#[test]
fn index_rule_7_snapshot_coverage() {
    let keys = keyring();
    let edits: [Edit<SnapshotV1>; 8] = [
        ("unsorted covered", |s| s.covered.swap(0, 1)),
        ("unsorted covered (devices)", |s| s.covered.reverse()),
        ("duplicate in covered", |s| {
            let first = s.covered[0];
            s.covered.insert(0, first);
        }),
        ("a tip missing from covered", |s| {
            s.covered.remove(1);
        }),
        ("a tip whose hash is not the covered one", |s| {
            s.covers[1].hash = [0x23; 32]
        }),
        ("unsorted tips", |s| s.covers.swap(0, 1)),
        ("two tips for one device", |s| {
            let tip = seg_ref(DEV_A, 1, 0x11);
            s.covers.insert(0, tip);
        }),
        ("tips without any covered segment", |s| s.covered.clear()),
    ];
    for (what, edit) in edits {
        let mut snap = snapshot();
        edit(&mut snap);
        assert_err!(
            open_crafted_snapshot(&snap),
            FormatError::BadEntry(_),
            "{what}"
        );
        assert_err!(
            seal_snapshot(&keys, &snap),
            FormatError::BadEntry(_),
            "{what}"
        );
    }
    // covered may hold more than the tips (older segments, fork branches); the reverse is an error
    let mut snap = snapshot();
    snap.covers.remove(0);
    assert_eq!(open_crafted_snapshot(&snap).unwrap().0, snap);
}

// ---------------------------------------------------------------------------------------------
// blobs and the descriptor
// ---------------------------------------------------------------------------------------------

#[test]
fn blob_len_matches_the_bytes_produced() {
    let keys = keyring();
    let c = 1u64 << CHUNK_LOG2;
    for_each_seed("blob_len", 1, |rng| {
        for members in [1usize, 2, 500] {
            let mut sizes: Vec<u64> = (0..members).map(|_| 1 + rng.below(40_000)).collect();
            // chunk-size edges and a multi-chunk member
            for (slot, edge) in sizes.iter_mut().rev().zip([c, c - 1, c + 1, 2 * c + 5, 1]) {
                *slot = edge;
            }
            let mut blob = Vec::new();
            let mut locs = Vec::new();
            for &size in &sizes {
                let plain = rng.bytes(size as usize);
                let mut member = seal_data(&keys, CHUNK_LOG2, &plain);
                member.loc.off = blob.len() as u64;
                blob.extend_from_slice(&member.bytes);
                locs.push((member.loc, plain));
            }
            assert_eq!(blob_len(&sizes), blob.len() as u64, "{members} members");
            assert_eq!(
                blob_len(&sizes),
                sizes
                    .iter()
                    .map(|&s| ciphertext_len(s, CHUNK_LOG2))
                    .sum::<u64>()
            );

            // every member is found again by its (off, clen) and by nothing else
            for (loc, plain) in &locs {
                assert!(loc.off + loc.clen <= blob.len() as u64);
                let stored = &blob[loc.off as usize..(loc.off + loc.clen) as usize];
                assert_eq!(
                    &open_data(&keys, loc, plain.len() as u64, stored).unwrap(),
                    plain
                );
            }
            if members > 1 {
                let (first, _) = &locs[0];
                let (second, plain) = &locs[1];
                let wrong = &blob
                    [first.off as usize..first.off as usize + second.clen.min(first.clen) as usize];
                assert!(open_data(&keys, second, plain.len() as u64, wrong).is_err());
            }
        }
    });
    assert_eq!(blob_len(&[]), 0);
    assert_eq!(blob_len(&[1]), 77);
}

#[test]
fn blob_names_and_descriptor() {
    let id = BlobId([0x1f; 16]);
    assert_eq!(blob_name(&id), "1f".repeat(16));
    assert_eq!(parse_blob_name(&blob_name(&id)), Some(id));
    assert_eq!(parse_blob_name("1F1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f"), None);
    assert_eq!(parse_blob_name("gclone-vault.json"), None);

    let d = VaultDescriptor::new(VAULT);
    assert_eq!((d.gclone_vault, d.min_reader), (1, 1));
    let parsed = VaultDescriptor::parse(&d.to_bytes()).unwrap();
    assert_eq!(parsed.vault_id, util::hex(&VAULT));
    assert_eq!(parsed.created_ms, d.created_ms);
    let literal = br#"{ "gclone_vault": 1, "min_reader": 1, "vault_id": "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "created_ms": 1794400000000 }"#;
    assert_eq!(
        VaultDescriptor::parse(literal).unwrap().created_ms,
        1_794_400_000_000
    );
    assert_err!(VaultDescriptor::parse(b"<html>"), FormatError::Decode(_));
    assert_err!(
        VaultDescriptor::parse(
            br#"{"gclone_vault":1,"min_reader":1,"vault_id":"xyz","created_ms":1}"#
        ),
        FormatError::Decode(_)
    );
}

//! Index objects: segments and snapshots (SPEC §4.6, §9.4).
//!
//! Both kinds are one stream whose plaintext is `codec u8 (0x00 = postcard)` ‖ postcard(body).
//! The types below are the wire format: field order is frozen and enums are append-only.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::unhex_array;
use crate::consts::{CHUNK_LOG2_MAX, CHUNK_LOG2_MIN, INDEX_OBJECT_MAX};
use crate::crypto::stream::checked_ciphertext_len;
use crate::crypto::{Keyring, StreamType};
use crate::error::FormatError;
use crate::path;
use crate::types::{BlobRec, CoveredSeg, DeviceId, Entry, EntryKind, OpDraft, SegRef, Stamp};
use crate::util;

/// `0x01` is reserved for zstd + postcard.
const CODEC_POSTCARD: u8 = 0x00;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentBody {
    V1(SegmentV1),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotBody {
    V1(SnapshotV1),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentV1 {
    pub vault_id: [u8; 16],
    pub device: DeviceId,
    /// Starts at 1 per device.
    pub seq: u64,
    /// All ops of this segment share it; op `i` has `Stamp { lamport, device, idx: i }`.
    pub lamport: u64,
    /// This device's previous segment (`None` iff `seq == 1` after a device-id birth).
    pub prev: Option<SegRef>,
    /// Per OTHER device: the greatest `(seq, hash)` known when writing (sorted by device).
    pub seen: Vec<SegRef>,
    pub created_ms: u64,
    pub host: String,
    pub ops: Vec<Op>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    VaultInit {
        format: u16,
        name: String,
    },
    Device {
        id: DeviceId,
        name: String,
    },
    Blob(BlobRec),
    Put {
        path: String,
        entry: Entry,
        base: Option<Stamp>,
        origin: Option<Stamp>,
    },
    Del {
        path: String,
        base: Stamp,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadRec {
    pub path: String,
    pub stamp: Stamp,
    pub entry: Entry,
    pub origin: Option<Stamp>,
}

/// `by` = the superseding op (§5.2.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovedRec {
    pub path: String,
    pub stamp: Stamp,
    pub entry: Entry,
    pub removed_ms: u64,
    pub by: Stamp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRec {
    pub id: DeviceId,
    pub name: String,
    pub first_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotV1 {
    pub vault_id: [u8; 16],
    pub device: DeviceId,
    pub lamport: u64,
    pub created_ms: u64,
    pub vault_format: u16,
    pub vault_name: String,
    /// Tips: per device the covered segment with the greatest `(seq, hash)`, with its file id
    /// (sorted by device).
    pub covers: Vec<SegRef>,
    /// EVERY segment folded into this snapshot — exact identities, fork branches included
    /// (sorted, unique).
    pub covered: Vec<CoveredSeg>,
    pub devices: Vec<DeviceRec>,
    /// Every blob referenced by `heads` or `removed`.
    pub blobs: Vec<BlobRec>,
    /// ALL heads (winners and conflict losers), sorted by `(path, stamp, entry.hash)`.
    pub heads: Vec<HeadRec>,
    /// Versions removed within `HISTORY_KEEP` (35 days), sorted by `(path, stamp, entry.hash)`.
    pub removed: Vec<RemovedRec>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexName {
    Segment {
        device: DeviceId,
        seq: u64,
        h8: [u8; 4],
    },
    Snapshot {
        lamport: u64,
        device: DeviceId,
        h8: [u8; 4],
    },
}

/// `s-<dev16>-<seq:016x>-<h8>` or `c-<lamport:016x>-<dev16>-<h8>`, lowercase hex only.
pub fn parse_index_name(name: &str) -> Option<IndexName> {
    let mut parts = name.split('-');
    let (kind, a, b, h8) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let h8 = unhex_array::<4>(h8)?;
    let number = |s: &str| unhex_array::<8>(s).map(u64::from_be_bytes);
    match kind {
        "s" => Some(IndexName::Segment {
            device: DeviceId::from_hex(a)?,
            seq: number(b)?,
            h8,
        }),
        "c" => Some(IndexName::Snapshot {
            lamport: number(a)?,
            device: DeviceId::from_hex(b)?,
            h8,
        }),
        _ => None,
    }
}

/// `s-<dev16>-<seq:016x>-<h8>`
pub fn segment_name(device: DeviceId, seq: u64, hash: &[u8; 32]) -> String {
    format!("s-{}-{seq:016x}-{}", device.hex(), util::hex(&hash[..4]))
}

/// `c-<lamport:016x>-<dev16>-<h8>`
pub fn snapshot_name(lamport: u64, device: DeviceId, hash: &[u8; 32]) -> String {
    format!(
        "c-{lamport:016x}-{}-{}",
        device.hex(),
        util::hex(&hash[..4])
    )
}

/// A sealed put-once object: its name, `BLAKE3(bytes)` and the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedObject {
    pub name: String,
    pub hash: [u8; 32],
    pub bytes: Vec<u8>,
}

// Borrowing twins of the body enums: the same postcard bytes without cloning the body.
#[derive(Serialize)]
enum SegmentBodyRef<'a> {
    V1(&'a SegmentV1),
}

#[derive(Serialize)]
enum SnapshotBodyRef<'a> {
    V1(&'a SnapshotV1),
}

/// Refuses to write what `open_segment` would reject: a foreign vault id, an invalid path, a
/// malformed entry, an object above `INDEX_OBJECT_MAX` (§4.6 rules 1, 4–6).
pub fn seal_segment(keys: &Keyring, seg: &SegmentV1) -> Result<SealedObject, FormatError> {
    check_vault(keys, &seg.vault_id)?;
    check_segment(seg)?;
    let bytes = keys.seal(StreamType::Segment, &encode(&SegmentBodyRef::V1(seg))?)?;
    check_size(bytes.len())?;
    let hash = *blake3::hash(&bytes).as_bytes();
    Ok(SealedObject {
        name: segment_name(seg.device, seg.seq, &hash),
        hash,
        bytes,
    })
}

/// Like [`seal_segment`], for rules 1 and 4–7.
pub fn seal_snapshot(keys: &Keyring, snap: &SnapshotV1) -> Result<SealedObject, FormatError> {
    check_vault(keys, &snap.vault_id)?;
    check_snapshot(snap)?;
    let bytes = keys.seal(StreamType::Snapshot, &encode(&SnapshotBodyRef::V1(snap))?)?;
    check_size(bytes.len())?;
    let hash = *blake3::hash(&bytes).as_bytes();
    Ok(SealedObject {
        name: snapshot_name(snap.lamport, snap.device, &hash),
        hash,
        bytes,
    })
}

/// Acceptance rules of §4.6 over the whole object; returns the segment and `BLAKE3(bytes)`.
/// Errors: `BadName` (not a segment name), `BadEntry` (rule 1: larger than `INDEX_OBJECT_MAX`;
/// rule 6), `IdentityMismatch` (rules 1 and 4), `Crypto` (rule 2), `Codec` / `BodyVersion` /
/// `Decode` (rule 3), `Path` (rule 5). [`FormatError::newer_format`] tells the errors that mean
/// "written by a newer gclone" from the ones that mean "damaged".
pub fn open_segment(
    keys: &Keyring,
    name: &str,
    bytes: &[u8],
) -> Result<(SegmentV1, [u8; 32]), FormatError> {
    let Some(IndexName::Segment { device, seq, h8 }) = parse_index_name(name) else {
        return Err(FormatError::BadName(name.to_owned()));
    };
    let hash = check_hash(name, bytes, h8)?;
    let SegmentBody::V1(seg) = decode(&keys.open(StreamType::Segment, bytes)?)?;
    check_vault(keys, &seg.vault_id)?;
    if (seg.device, seg.seq) != (device, seq) {
        return Err(FormatError::IdentityMismatch(format!(
            "{name} holds segment {}/{}",
            seg.device, seg.seq
        )));
    }
    check_segment(&seg)?;
    Ok((seg, hash))
}

/// Acceptance rules of §4.6 over the whole object; returns the snapshot and `BLAKE3(bytes)`.
/// Errors as for [`open_segment`], plus `BadEntry` for rule 7.
pub fn open_snapshot(
    keys: &Keyring,
    name: &str,
    bytes: &[u8],
) -> Result<(SnapshotV1, [u8; 32]), FormatError> {
    let Some(IndexName::Snapshot {
        lamport,
        device,
        h8,
    }) = parse_index_name(name)
    else {
        return Err(FormatError::BadName(name.to_owned()));
    };
    let hash = check_hash(name, bytes, h8)?;
    let SnapshotBody::V1(snap) = decode(&keys.open(StreamType::Snapshot, bytes)?)?;
    check_vault(keys, &snap.vault_id)?;
    if (snap.lamport, snap.device) != (lamport, device) {
        return Err(FormatError::IdentityMismatch(format!(
            "{name} holds snapshot {}/{}",
            snap.lamport, snap.device
        )));
    }
    check_snapshot(&snap)?;
    Ok((snap, hash))
}

/// Drops the `BaseEffect`.
pub fn op_from_draft(d: &OpDraft) -> Op {
    match d {
        OpDraft::VaultInit { format, name } => Op::VaultInit {
            format: *format,
            name: name.clone(),
        },
        OpDraft::Device { id, name } => Op::Device {
            id: *id,
            name: name.clone(),
        },
        OpDraft::Blob(rec) => Op::Blob(rec.clone()),
        OpDraft::Put {
            path,
            entry,
            base,
            origin,
            effect: _,
        } => Op::Put {
            path: path.clone(),
            entry: entry.clone(),
            base: *base,
            origin: *origin,
        },
        OpDraft::Del {
            path,
            base,
            effect: _,
        } => Op::Del {
            path: path.clone(),
            base: *base,
        },
    }
}

fn encode<T: Serialize>(body: &T) -> Result<Vec<u8>, FormatError> {
    postcard::to_extend(body, vec![CODEC_POSTCARD])
        .map_err(|e| FormatError::Decode(format!("cannot encode an index object: {e}")))
}

/// Rule 3: a known codec, a known body version, and postcard with no trailing bytes.
fn decode<T: DeserializeOwned>(plain: &[u8]) -> Result<T, FormatError> {
    let Some((&codec, body)) = plain.split_first() else {
        return Err(FormatError::Decode("empty index object".into()));
    };
    if codec != CODEC_POSTCARD {
        return Err(FormatError::Codec(codec));
    }
    // The body is a versioned enum whose postcard tag is its first byte; only V1 = 0 exists.
    if let Some(&version) = body.first().filter(|&&tag| tag != 0) {
        return Err(FormatError::BodyVersion(version));
    }
    let (value, rest) =
        postcard::take_from_bytes::<T>(body).map_err(|e| FormatError::Decode(e.to_string()))?;
    if !rest.is_empty() {
        return Err(FormatError::Decode(format!(
            "{} trailing bytes after the index object body",
            rest.len()
        )));
    }
    Ok(value)
}

/// Rule 1, first half: no index object is larger than `INDEX_OBJECT_MAX`.
fn check_size(len: usize) -> Result<(), FormatError> {
    if len as u64 > INDEX_OBJECT_MAX {
        return Err(FormatError::BadEntry(format!(
            "an index object of {len} bytes, more than the {INDEX_OBJECT_MAX} allowed"
        )));
    }
    Ok(())
}

/// Rule 1: at most `INDEX_OBJECT_MAX` bytes, and `BLAKE3(bytes)[0..4]` equals the name's `h8`.
fn check_hash(name: &str, bytes: &[u8], h8: [u8; 4]) -> Result<[u8; 32], FormatError> {
    check_size(bytes.len())?;
    let hash = *blake3::hash(bytes).as_bytes();
    if hash[..4] != h8 {
        return Err(FormatError::IdentityMismatch(format!(
            "the content of {name} does not match its name"
        )));
    }
    Ok(hash)
}

/// Rule 4, first half: the inner vault id is the local one.
fn check_vault(keys: &Keyring, vault_id: &[u8; 16]) -> Result<(), FormatError> {
    if *vault_id != keys.vault_id() {
        return Err(FormatError::IdentityMismatch(format!(
            "index object of vault {}, not of this vault",
            util::hex(vault_id)
        )));
    }
    Ok(())
}

/// Rules 5–6 for a segment.
fn check_segment(seg: &SegmentV1) -> Result<(), FormatError> {
    for op in &seg.ops {
        match op {
            Op::Put { path, entry, .. } => check_version(path, entry)?,
            Op::Del { path, .. } => path::validate(path)?,
            Op::VaultInit { .. } | Op::Device { .. } | Op::Blob(_) => {}
        }
    }
    Ok(())
}

/// Rules 5–7 for a snapshot.
fn check_snapshot(snap: &SnapshotV1) -> Result<(), FormatError> {
    for head in &snap.heads {
        check_version(&head.path, &head.entry)?;
    }
    for removed in &snap.removed {
        check_version(&removed.path, &removed.entry)?;
    }
    if !snap.covers.is_sorted_by(|a, b| a.device < b.device) {
        return Err(FormatError::BadEntry(
            "snapshot tips are not sorted with one entry per device".into(),
        ));
    }
    if !snap.covered.is_sorted_by(|a, b| a < b) {
        return Err(FormatError::BadEntry(
            "the snapshot's covered set is not sorted and unique".into(),
        ));
    }
    for tip in &snap.covers {
        if snap.covered.binary_search(&tip.covered()).is_err() {
            return Err(FormatError::BadEntry(format!(
                "snapshot tip {}/{} is missing from its covered set",
                tip.device, tip.seq
            )));
        }
    }
    Ok(())
}

/// Rule 5 (the path) and rule 6 (the entry) for one version of a path.
fn check_version(path: &str, entry: &Entry) -> Result<(), FormatError> {
    path::validate(path)?;
    let problem = match &entry.loc {
        Some(_) if entry.kind != EntryKind::File => "a directory with a data location",
        Some(_) if entry.size == 0 => "an empty file with a data location",
        Some(loc) if !(CHUNK_LOG2_MIN..=CHUNK_LOG2_MAX).contains(&loc.chunk_log2) => {
            "chunk size out of range"
        }
        Some(loc) if checked_ciphertext_len(entry.size, loc.chunk_log2) != Some(loc.clen) => {
            "stored length does not match the file size"
        }
        None if entry.kind == EntryKind::File && entry.size != 0 => {
            "a non-empty file without a data location"
        }
        _ => return Ok(()),
    };
    Err(FormatError::BadEntry(format!("{path}: {problem}")))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::ciphertext_len;
    use crate::crypto::stream::tests::{KAT_VAULT_ID, frozen, frozen_bytes, kat_keyring};
    use crate::types::{BlobId, Loc};

    const DEV_A: DeviceId = DeviceId([0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7]);
    const DEV_B: DeviceId = DeviceId([0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7]);

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
            file_id: format!("file-{fill:02x}"),
        }
    }

    fn blob_rec() -> BlobRec {
        BlobRec {
            id: BlobId([0xb0; 16]),
            file_id: "1AbC_dEf-drive-id".into(),
            clen: 300_000,
            md5: [0x5d; 16],
            created_ms: 1_794_400_000_123,
        }
    }

    fn file_entry() -> Entry {
        Entry {
            kind: EntryKind::File,
            size: 100_000,
            mtime_ns: -1_234_567_890_123,
            exec: true,
            hash: [0x77; 32],
            loc: Some(Loc {
                blob: BlobId([0xb0; 16]),
                off: 4242,
                clen: ciphertext_len(100_000, 16),
                salt: [0x5a; 16],
                chunk_log2: 16,
                epoch: 1,
                suite: 1,
                flags: 0,
            }),
        }
    }

    /// One op of every kind and one entry of every shape: the frozen copy pins the postcard
    /// layout of every index type.
    pub(crate) fn sample_segment() -> SegmentV1 {
        SegmentV1 {
            vault_id: KAT_VAULT_ID,
            device: DEV_A,
            seq: 2,
            lamport: 300,
            prev: Some(seg_ref(DEV_A, 1, 0x11)),
            seen: vec![seg_ref(DEV_B, 70_000, 0x22)],
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
                Op::Blob(blob_rec()),
                Op::Put {
                    path: "Photos/2026/été.jpg".into(),
                    entry: file_entry(),
                    base: Some(stamp(299, DEV_B, 5)),
                    origin: Some(stamp(12, DEV_A, 0)),
                },
                Op::Put {
                    path: "Photos/empty".into(),
                    entry: Entry::empty_file(1_794_400_000_000_000_000, false),
                    base: None,
                    origin: None,
                },
                Op::Put {
                    path: "Photos/dir".into(),
                    entry: Entry::dir(),
                    base: None,
                    origin: None,
                },
                Op::Del {
                    path: "old.txt".into(),
                    base: stamp(u64::MAX, DEV_B, u32::MAX),
                },
            ],
        }
    }

    pub(crate) fn sample_snapshot() -> SnapshotV1 {
        let tip_a = seg_ref(DEV_A, 2, 0x33);
        let tip_b = seg_ref(DEV_B, 70_000, 0x22);
        SnapshotV1 {
            vault_id: KAT_VAULT_ID,
            device: DEV_B,
            lamport: 301,
            created_ms: 1_794_400_000_500,
            vault_format: 1,
            vault_name: "gclone".into(),
            covered: vec![
                CoveredSeg {
                    device: DEV_A,
                    seq: 1,
                    h4: [0x11; 4],
                },
                tip_a.covered(),
                CoveredSeg {
                    device: DEV_B,
                    seq: 70_000,
                    h4: [0x21; 4],
                },
                tip_b.covered(),
            ],
            covers: vec![tip_a, tip_b],
            devices: vec![DeviceRec {
                id: DEV_A,
                name: "mbp".into(),
                first_ms: 1_794_300_000_000,
            }],
            blobs: vec![blob_rec()],
            heads: vec![
                HeadRec {
                    path: "Photos/2026/été.jpg".into(),
                    stamp: stamp(300, DEV_A, 3),
                    entry: file_entry(),
                    origin: Some(stamp(12, DEV_A, 0)),
                },
                HeadRec {
                    path: "Photos/dir".into(),
                    stamp: stamp(300, DEV_A, 5),
                    entry: Entry::dir(),
                    origin: None,
                },
            ],
            removed: vec![RemovedRec {
                path: "old.txt".into(),
                stamp: stamp(7, DEV_B, 1),
                entry: Entry::empty_file(5, true),
                removed_ms: 1_794_400_000_400,
                by: stamp(300, DEV_A, 6),
            }],
        }
    }

    fn frozen_object(obj: &SealedObject) -> serde_json::Value {
        serde_json::json!({ "name": obj.name, "bytes": util::hex(&obj.bytes) })
    }

    /// The `segment` section of the frozen vector file (called by `stream::tests::gen_vectors`).
    pub(crate) fn gen_frozen_segment() -> serde_json::Value {
        frozen_object(&seal_segment(&kat_keyring(), &sample_segment()).unwrap())
    }

    pub(crate) fn gen_frozen_snapshot() -> serde_json::Value {
        frozen_object(&seal_snapshot(&kat_keyring(), &sample_snapshot()).unwrap())
    }

    #[test]
    fn frozen_segment_still_opens() {
        let frozen = frozen();
        let name = frozen["segment"]["name"]
            .as_str()
            .expect("regenerate the vectors");
        let bytes = frozen_bytes(&frozen["segment"]["bytes"]);
        let (seg, hash) = open_segment(&kat_keyring(), name, &bytes).unwrap();
        assert_eq!(seg, sample_segment());
        assert_eq!(hash, *blake3::hash(&bytes).as_bytes());
        assert_eq!(name, segment_name(seg.device, seg.seq, &hash));
    }

    #[test]
    fn frozen_snapshot_still_opens() {
        let frozen = frozen();
        let name = frozen["snapshot"]["name"]
            .as_str()
            .expect("regenerate the vectors");
        let bytes = frozen_bytes(&frozen["snapshot"]["bytes"]);
        let (snap, hash) = open_snapshot(&kat_keyring(), name, &bytes).unwrap();
        assert_eq!(snap, sample_snapshot());
        assert_eq!(name, snapshot_name(snap.lamport, snap.device, &hash));
    }

    #[test]
    fn borrowed_bodies_encode_like_the_owned_ones() {
        let seg = sample_segment();
        let mut owned = vec![CODEC_POSTCARD];
        owned.extend(postcard::to_stdvec(&SegmentBody::V1(seg.clone())).unwrap());
        assert_eq!(encode(&SegmentBodyRef::V1(&seg)).unwrap(), owned);
        assert_eq!(decode::<SegmentBody>(&owned).unwrap(), SegmentBody::V1(seg));

        let snap = sample_snapshot();
        let mut owned = vec![CODEC_POSTCARD];
        owned.extend(postcard::to_stdvec(&SnapshotBody::V1(snap.clone())).unwrap());
        assert_eq!(encode(&SnapshotBodyRef::V1(&snap)).unwrap(), owned);
        assert_eq!(
            decode::<SnapshotBody>(&owned).unwrap(),
            SnapshotBody::V1(snap)
        );
    }

    #[test]
    fn decode_fails_closed() {
        let good = encode(&SegmentBodyRef::V1(&sample_segment())).unwrap();
        assert!(matches!(
            decode::<SegmentBody>(&[]),
            Err(FormatError::Decode(_))
        ));
        let mut zstd = good.clone();
        zstd[0] = 0x01;
        assert!(matches!(
            decode::<SegmentBody>(&zstd),
            Err(FormatError::Codec(1))
        ));
        let mut v2 = good.clone();
        v2[1] = 0x01;
        assert!(matches!(
            decode::<SegmentBody>(&v2),
            Err(FormatError::BodyVersion(1))
        ));
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(
            matches!(decode::<SegmentBody>(&trailing), Err(FormatError::Decode(m)) if m.contains("trailing"))
        );
        assert!(matches!(
            decode::<SegmentBody>(&good[..good.len() - 1]),
            Err(FormatError::Decode(_))
        ));
    }

    /// Rule 1: the cap is checked first. (The buffer is never read — untouched zero pages — so
    /// the test does not cost a gibibyte of memory.)
    #[test]
    fn an_index_object_above_the_cap_is_refused_unread() {
        assert!(check_size(INDEX_OBJECT_MAX as usize).is_ok());
        assert!(matches!(
            check_size(INDEX_OBJECT_MAX as usize + 1),
            Err(FormatError::BadEntry(m)) if m.contains("more than")
        ));
        let keys = kat_keyring();
        let huge = vec![0u8; INDEX_OBJECT_MAX as usize + 1];
        let segment = segment_name(DEV_A, 1, &[0; 32]);
        let snapshot = snapshot_name(1, DEV_A, &[0; 32]);
        assert!(matches!(
            open_segment(&keys, &segment, &huge),
            Err(FormatError::BadEntry(_))
        ));
        assert!(matches!(
            open_snapshot(&keys, &snapshot, &huge),
            Err(FormatError::BadEntry(_))
        ));
    }

    /// What says "written by a newer gclone" and what says "damaged" (§4.6).
    #[test]
    fn newer_format_classifies_version_errors_only() {
        use crate::error::CryptoError;
        for newer in [
            FormatError::Codec(1),
            FormatError::BodyVersion(1),
            FormatError::Crypto(CryptoError::Unsupported("stream suite")),
            FormatError::Crypto(CryptoError::UnknownEpoch(2)),
        ] {
            assert!(newer.newer_format().is_some(), "{newer}");
        }
        for damaged in [
            FormatError::Decode("x".into()),
            FormatError::BadName("x".into()),
            FormatError::IdentityMismatch("x".into()),
            FormatError::BadEntry("x".into()),
            FormatError::KeyfileVersion(2),
            FormatError::Crypto(CryptoError::BadMagic),
            FormatError::Crypto(CryptoError::WrongKey),
            FormatError::Crypto(CryptoError::Corrupt),
            FormatError::Crypto(CryptoError::Truncated),
            FormatError::Crypto(CryptoError::TrailingData),
            FormatError::Crypto(CryptoError::EpochTooOld { epoch: 1, min: 2 }),
        ] {
            assert!(damaged.newer_format().is_none(), "{damaged}");
        }
    }

    #[test]
    fn op_from_draft_drops_the_effect() {
        use crate::types::{BaseEffect, BaseEffectKind};
        let effect = Some(BaseEffect {
            pair: 1,
            key: "k".into(),
            rel: "r".into(),
            kind: BaseEffectKind::Forget,
        });
        let cases = [
            (
                OpDraft::VaultInit {
                    format: 1,
                    name: "v".into(),
                },
                Op::VaultInit {
                    format: 1,
                    name: "v".into(),
                },
            ),
            (
                OpDraft::Device {
                    id: DEV_A,
                    name: "d".into(),
                },
                Op::Device {
                    id: DEV_A,
                    name: "d".into(),
                },
            ),
            (OpDraft::Blob(blob_rec()), Op::Blob(blob_rec())),
            (
                OpDraft::Put {
                    path: "a/b".into(),
                    entry: file_entry(),
                    base: Some(stamp(1, DEV_A, 2)),
                    origin: Some(stamp(3, DEV_B, 4)),
                    effect: effect.clone(),
                },
                Op::Put {
                    path: "a/b".into(),
                    entry: file_entry(),
                    base: Some(stamp(1, DEV_A, 2)),
                    origin: Some(stamp(3, DEV_B, 4)),
                },
            ),
            (
                OpDraft::Del {
                    path: "a/b".into(),
                    base: stamp(1, DEV_A, 2),
                    effect,
                },
                Op::Del {
                    path: "a/b".into(),
                    base: stamp(1, DEV_A, 2),
                },
            ),
        ];
        for (draft, op) in cases {
            assert_eq!(op_from_draft(&draft), op);
        }
    }
}

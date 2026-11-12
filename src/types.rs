//! Shared plain types (SPEC §4.4, §9.3).
//!
//! The types marked "S" in the spec derive serde's `Serialize`/`Deserialize`; they are stored
//! with postcard inside index objects and in `state.db`. **Field order is frozen and enums are
//! append-only** — reordering anything here is a format break.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::consts::RACY_WINDOW_NS;
use crate::util;

/// 8-byte device id (`dev16` = its 16 lowercase hex characters).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 8]);

/// 16-byte blob id; a blob's object name is its 32 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlobId(pub [u8; 16]);

/// Identity of one op: op `idx` of the segment `(lamport, device)`.
/// `Ord` is lexicographic `(lamport, device, idx)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Stamp {
    pub lamport: u64,
    pub device: DeviceId,
    pub idx: u32,
}

/// Where a file's Data stream lives. `off` is the byte offset of the member's 60-byte header
/// inside the blob; `clen = ciphertext_len(size, chunk_log2)`. `suite` and `flags` are the
/// stream header's bytes 4 and 7 (v1 writers emit 1 and 0).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Loc {
    pub blob: BlobId,
    pub off: u64,
    pub clen: u64,
    pub salt: [u8; 16],
    pub chunk_log2: u8,
    pub epoch: u32,
    pub suite: u8,
    pub flags: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    File,
    Dir,
}

/// One version of a path. `hash` = BLAKE3(plaintext), all-zero for `Dir`;
/// `loc` is `None` for `Dir` and for zero-length files.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub kind: EntryKind,
    pub size: u64,
    pub mtime_ns: i64,
    pub exec: bool,
    pub hash: [u8; 32],
    pub loc: Option<Loc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRec {
    pub id: BlobId,
    pub file_id: String,
    pub clen: u64,
    pub md5: [u8; 16],
    pub created_ms: u64,
}

/// Full reference to one segment: identity `(device, seq, hash)` plus where to fetch it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegRef {
    pub device: DeviceId,
    pub seq: u64,
    pub hash: [u8; 32],
    pub file_id: String,
}

/// Compact segment identity used in a snapshot's coverage set: `h4 = hash[0..4]` (the name's
/// `h8`). `Ord` is `(device, seq, h4)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CoveredSeg {
    pub device: DeviceId,
    pub seq: u64,
    pub h4: [u8; 4],
}

/// Stat signature of a local file (§5.4). ctime is part of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatSig {
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub ino: u64,
    pub mode: u32,
}

/// One head of a path in the local replica (§5.2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub path: String,
    pub stamp: Stamp,
    pub entry: Entry,
    pub origin: Option<Stamp>,
    pub winner: bool,
}

/// A version that stopped being a head; `by` = the (smallest) superseding op (§5.2.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovedVersion {
    pub path: String,
    pub stamp: Stamp,
    pub entry: Entry,
    pub removed_ms: u64,
    pub by: Stamp,
}

/// Per-pair base row: what this device last saw in sync at one comparison key (§5.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseRow {
    pub key: String,
    pub rel: String,
    pub kind: EntryKind,
    pub sig: StatSig,
    pub hash: [u8; 32],
    pub remote_stamp: Stamp,
    pub observed_ns: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BaseEffectKind {
    Set {
        sig: StatSig,
        hash: [u8; 32],
        observed_ns: i64,
        kind: EntryKind,
    },
    Forget,
}

/// What happens to the `base` table when the op carrying this effect is committed (§5.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseEffect {
    pub pair: i64,
    pub key: String,
    pub rel: String,
    pub kind: BaseEffectKind,
}

/// An op as staged in `pending` (postcard): the index op plus its local base effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpDraft {
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
        effect: Option<BaseEffect>,
    },
    Del {
        path: String,
        base: Stamp,
        effect: Option<BaseEffect>,
    },
}

impl DeviceId {
    pub fn random() -> Self {
        DeviceId(util::random())
    }

    /// 16 lowercase hex characters.
    pub fn hex(&self) -> String {
        util::hex(&self.0)
    }

    /// The first 8 hex characters (`dev8` of conflict names, §5.1).
    pub fn short(&self) -> String {
        util::hex(&self.0[..4])
    }

    /// Exactly 16 lowercase hex characters; anything else is `None`.
    pub fn from_hex(s: &str) -> Option<Self> {
        let v = util::unhex(s)?;
        Some(DeviceId(v.try_into().ok()?))
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", self.hex())
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

impl BlobId {
    pub fn random() -> Self {
        BlobId(util::random())
    }

    /// 32 lowercase hex characters — the blob's object name.
    pub fn hex(&self) -> String {
        util::hex(&self.0)
    }

    /// Exactly 32 lowercase hex characters; anything else is `None`.
    pub fn from_hex(s: &str) -> Option<Self> {
        let v = util::unhex(s)?;
        Some(BlobId(v.try_into().ok()?))
    }
}

impl fmt::Debug for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobId({})", self.hex())
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

impl Entry {
    /// A directory entry: size 0, mtime 0, all-zero hash, no `loc`.
    pub fn dir() -> Self {
        Entry {
            kind: EntryKind::Dir,
            size: 0,
            mtime_ns: 0,
            exec: false,
            hash: [0; 32],
            loc: None,
        }
    }

    /// A zero-length file: `hash = BLAKE3("")`, no `loc` (§6.2).
    pub fn empty_file(mtime_ns: i64, exec: bool) -> Self {
        Entry {
            kind: EntryKind::File,
            size: 0,
            mtime_ns,
            exec,
            hash: *blake3::hash(b"").as_bytes(),
            loc: None,
        }
    }

    /// Equal `kind`, `size` and `hash`; `loc`, mtime and exec are ignored (§5.2.3).
    pub fn same_content(&self, o: &Entry) -> bool {
        self.kind == o.kind && self.size == o.size && self.hash == o.hash
    }
}

impl SegRef {
    /// `(device, seq, hash[0..4])`.
    pub fn covered(&self) -> CoveredSeg {
        CoveredSeg {
            device: self.device,
            seq: self.seq,
            h4: [self.hash[0], self.hash[1], self.hash[2], self.hash[3]],
        }
    }
}

impl StatSig {
    pub fn from_metadata(md: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        StatSig {
            size: md.size(),
            mtime_ns: md
                .mtime()
                .saturating_mul(1_000_000_000)
                .saturating_add(md.mtime_nsec()),
            ctime_ns: md
                .ctime()
                .saturating_mul(1_000_000_000)
                .saturating_add(md.ctime_nsec()),
            ino: md.ino(),
            mode: md.mode(),
        }
    }

    /// The owner-execute bit (`0o100`) — what decides between 0755 and 0644 on download (§5.7).
    pub fn is_exec(&self) -> bool {
        self.mode & 0o100 != 0
    }
}

impl BaseRow {
    /// Racy-timestamp rule (§5.4): trusted iff `max(mtime, ctime) + RACY_WINDOW < observed`.
    /// Untrusted rows never short-cut hashing.
    pub fn trusted(&self) -> bool {
        self.sig
            .mtime_ns
            .max(self.sig.ctime_ns)
            .saturating_add(RACY_WINDOW_NS)
            < self.observed_ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(l: u64, d: u8, i: u32) -> Stamp {
        Stamp {
            lamport: l,
            device: DeviceId([d; 8]),
            idx: i,
        }
    }

    #[test]
    fn ids_hex_round_trip() {
        let d = DeviceId([0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18]);
        assert_eq!(d.hex(), "a1b2c3d4e5f60718");
        assert_eq!(d.short(), "a1b2c3d4");
        assert_eq!(DeviceId::from_hex("a1b2c3d4e5f60718"), Some(d));
        assert_eq!(DeviceId::from_hex("A1B2C3D4E5F60718"), None);
        assert_eq!(DeviceId::from_hex("a1b2c3d4e5f6071"), None);
        assert_eq!(DeviceId::from_hex("a1b2c3d4e5f607180"), None);
        assert_eq!(format!("{d}"), "a1b2c3d4e5f60718");
        assert_eq!(format!("{d:?}"), "DeviceId(a1b2c3d4e5f60718)");

        let b = BlobId::random();
        assert_eq!(b.hex().len(), 32);
        assert_eq!(BlobId::from_hex(&b.hex()), Some(b));
        assert_eq!(BlobId::from_hex("zz"), None);
        assert_ne!(BlobId::random(), BlobId::random());
        assert_ne!(DeviceId::random(), DeviceId::random());
    }

    #[test]
    fn stamp_order_is_lamport_device_idx() {
        assert!(stamp(1, 9, 9) < stamp(2, 0, 0));
        assert!(stamp(2, 1, 9) < stamp(2, 2, 0));
        assert!(stamp(2, 2, 0) < stamp(2, 2, 1));
        let c = |d: u8, s: u64, h: u8| CoveredSeg {
            device: DeviceId([d; 8]),
            seq: s,
            h4: [h; 4],
        };
        assert!(c(1, 9, 9) < c(2, 0, 0));
        assert!(c(1, 1, 9) < c(1, 2, 0));
        assert!(c(1, 1, 1) < c(1, 1, 2));
    }

    #[test]
    fn entry_helpers() {
        let d = Entry::dir();
        assert_eq!(d.kind, EntryKind::Dir);
        assert_eq!(d.hash, [0; 32]);
        assert!(d.loc.is_none());

        let e = Entry::empty_file(5, true);
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(e.size, 0);
        assert!(e.exec);
        assert_eq!(
            util::hex(&e.hash),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );

        let loc = Loc {
            blob: BlobId([1; 16]),
            off: 0,
            clen: 77,
            salt: [2; 16],
            chunk_log2: 16,
            epoch: 1,
            suite: 1,
            flags: 0,
        };
        let a = Entry {
            kind: EntryKind::File,
            size: 1,
            mtime_ns: 1,
            exec: false,
            hash: [7; 32],
            loc: Some(loc.clone()),
        };
        let mut b = a.clone();
        b.mtime_ns = 99;
        b.exec = true;
        b.loc = Some(Loc {
            blob: BlobId([9; 16]),
            ..loc
        });
        assert!(a.same_content(&b));
        b.size = 2;
        assert!(!a.same_content(&b));
        b.size = 1;
        b.hash = [8; 32];
        assert!(!a.same_content(&b));
        assert!(!d.same_content(&Entry {
            kind: EntryKind::File,
            ..Entry::dir()
        }));
    }

    #[test]
    fn segref_covered() {
        let mut hash = [0u8; 32];
        hash[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        let r = SegRef {
            device: DeviceId([3; 8]),
            seq: 12,
            hash,
            file_id: "f".into(),
        };
        assert_eq!(
            r.covered(),
            CoveredSeg {
                device: DeviceId([3; 8]),
                seq: 12,
                h4: [1, 2, 3, 4]
            }
        );
    }

    #[test]
    fn base_row_trusted_racy_window() {
        let row = |mtime: i64, ctime: i64, observed: i64| BaseRow {
            key: "k".into(),
            rel: "k".into(),
            kind: EntryKind::File,
            sig: StatSig {
                size: 1,
                mtime_ns: mtime,
                ctime_ns: ctime,
                ino: 1,
                mode: 0o100644,
            },
            hash: [0; 32],
            remote_stamp: stamp(1, 1, 0),
            observed_ns: observed,
        };
        let s = 1_000_000_000i64;
        // observed well after both timestamps
        assert!(row(10 * s, 10 * s, 13 * s).trusted());
        // exactly at the window edge: not trusted (strict <)
        assert!(!row(10 * s, 10 * s, 12 * s).trusted());
        assert!(row(10 * s, 10 * s, 12 * s + 1).trusted());
        // inside the window
        assert!(!row(10 * s, 10 * s, 11 * s).trusted());
        // ctime decides when it is newer than mtime (chmod, rename)
        assert!(!row(s, 12 * s, 13 * s).trusted());
        assert!(row(s, 12 * s, 15 * s).trusted());
        // mtime in the future
        assert!(!row(100 * s, s, 13 * s).trusted());
        // no overflow
        assert!(!row(i64::MAX, 0, i64::MAX).trusted());
    }

    #[test]
    fn stat_sig_from_metadata() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"hello").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sig = StatSig::from_metadata(&std::fs::symlink_metadata(&p).unwrap());
        assert_eq!(sig.size, 5);
        assert!(sig.is_exec());
        assert!(sig.mtime_ns > 1_600_000_000 * 1_000_000_000);
        assert!(sig.ctime_ns >= sig.mtime_ns - 5_000_000_000);
        assert_ne!(sig.ino, 0);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let sig2 = StatSig::from_metadata(&std::fs::symlink_metadata(&p).unwrap());
        assert!(!sig2.is_exec());
        assert_eq!(sig2.ino, sig.ino);
    }

    #[test]
    fn postcard_layout_is_stable() {
        // Field order and enum order are frozen (§4.4): a change here is a format break.
        let s = stamp(1, 0xaa, 2);
        assert_eq!(
            postcard::to_stdvec(&s).unwrap(),
            [1, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 2]
        );
        assert_eq!(postcard::to_stdvec(&EntryKind::File).unwrap(), [0]);
        assert_eq!(postcard::to_stdvec(&EntryKind::Dir).unwrap(), [1]);
        let d = Entry::dir();
        let bytes = postcard::to_stdvec(&d).unwrap();
        // kind(1) size(1) mtime(1) exec(1) hash(32) loc(1)
        assert_eq!(bytes.len(), 37);
        assert_eq!(postcard::from_bytes::<Entry>(&bytes).unwrap(), d);

        let draft = OpDraft::Put {
            path: "a/b".into(),
            entry: Entry::empty_file(-5, false),
            base: Some(s),
            origin: None,
            effect: Some(BaseEffect {
                pair: 3,
                key: "a/b".into(),
                rel: "a/b".into(),
                kind: BaseEffectKind::Set {
                    sig: StatSig {
                        size: 0,
                        mtime_ns: -5,
                        ctime_ns: 7,
                        ino: u64::MAX,
                        mode: 0o100644,
                    },
                    hash: [1; 32],
                    observed_ns: 9,
                    kind: EntryKind::File,
                },
            }),
        };
        let bytes = postcard::to_stdvec(&draft).unwrap();
        assert_eq!(bytes[0], 3, "OpDraft::Put is variant 3");
        assert_eq!(postcard::from_bytes::<OpDraft>(&bytes).unwrap(), draft);
        assert_eq!(
            postcard::to_stdvec(&OpDraft::VaultInit {
                format: 1,
                name: String::new()
            })
            .unwrap()[0],
            0
        );
        assert_eq!(
            postcard::to_stdvec(&OpDraft::Device {
                id: DeviceId([0; 8]),
                name: String::new()
            })
            .unwrap()[0],
            1
        );
        assert_eq!(
            postcard::to_stdvec(&OpDraft::Del {
                path: "p".into(),
                base: s,
                effect: None
            })
            .unwrap()[0],
            4
        );
    }
}

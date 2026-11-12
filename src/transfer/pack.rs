//! Packing small files into one blob (SPEC §4.5, §6.2, §9.8) — owned by WP5.

use std::fs::File;

use md5::{Digest, Md5};

use super::source::{changed, open_failed, open_source, read_full, unchanged_at_eof, unreadable};
use super::{UploadSource, Uploaded};
use crate::consts::{CHUNK_LOG2, HEADER_LEN, MIB, PACK_MEMBER_MAX, PACK_TARGET};
use crate::crypto::{Keyring, SUITE_V1, ciphertext_len};
use crate::error::TransferError;
use crate::types::{BlobId, DeviceId, Entry, EntryKind, Loc, StatSig};
use crate::util;

/// A pack is also closed before its sealed bytes would pass this: the per-member overhead of
/// very small files must not let the buffer outgrow the §6.1 estimate ("≤ 17 MiB").
const PACK_BYTES_MAX: u64 = PACK_TARGET + MIB;

pub struct SealedPack {
    pub blob_id: BlobId,
    pub bytes: bytes::Bytes,
    pub md5: [u8; 16],
    /// `loc.blob = blob_id`.
    pub files: Vec<Uploaded>,
}

/// Owned `Keyring` clone, device, buffer, members — `'static`, so it can be moved into
/// `spawn_blocking` and returned.
pub struct PackBuilder {
    keys: Keyring,
    device: DeviceId,
    blob_id: BlobId,
    /// The sealed members so far.
    buf: Vec<u8>,
    files: Vec<Uploaded>,
    /// Plaintext bytes in `buf`.
    plain: u64,
    /// One member's plaintext and its sealed form, reused from file to file.
    scratch: Vec<u8>,
    sealed: Vec<u8>,
}

impl PackBuilder {
    pub fn new(keys: Keyring, device: DeviceId) -> Self {
        PackBuilder {
            keys,
            device,
            blob_id: BlobId::random(),
            buf: Vec::new(),
            files: Vec::new(),
            plain: 0,
            scratch: Vec::new(),
            sealed: Vec::new(),
        }
    }

    /// Reads, hashes and seals one small file into the current pack. Returns a finished pack
    /// when `PACK_TARGET` is reached: the pack that was closed because this member would have
    /// pushed it past the target — the member itself is then the first of the next pack.
    /// Blocking. `Err(SourceChanged/SourceUnreadable)` leaves the builder unchanged; so does a
    /// file that is no pack member (empty, or `PACK_MEMBER_MAX` and larger), which is refused
    /// with `Io(InvalidInput)`.
    pub fn add(&mut self, src: &UploadSource) -> Result<Option<SealedPack>, TransferError> {
        let observed_ns = util::now_ns();
        let (file, sig) = open_source(&src.abs).map_err(|e| open_failed(&src.abs, e))?;
        if sig.size == 0 || sig.size >= PACK_MEMBER_MAX {
            return Err(TransferError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{}: a file of {} bytes is not packed",
                    src.abs.display(),
                    sig.size
                ),
            )));
        }
        self.add_opened(src, file, sig, observed_ns)
    }

    /// [`add`](Self::add) for a descriptor the caller opened and classified
    /// (`0 < sig.size < PACK_MEMBER_MAX`); `observed_ns` is from before its `fstat`.
    pub(crate) fn add_opened(
        &mut self,
        src: &UploadSource,
        mut file: File,
        sig: StatSig,
        observed_ns: i64,
    ) -> Result<Option<SealedPack>, TransferError> {
        debug_assert!(sig.size > 0 && sig.size < PACK_MEMBER_MAX);
        self.scratch.resize(sig.size as usize, 0);
        let got = read_full(&mut file, &mut self.scratch).map_err(|e| unreadable(&src.abs, e))?;
        if got != self.scratch.len()
            || !unchanged_at_eof(&mut file, &sig).map_err(|e| unreadable(&src.abs, e))?
        {
            return Err(changed(&src.abs));
        }

        // Sealed aside first, so that an error cannot leave half a member in the pack.
        let mut sealer = self.keys.data_sealer();
        self.sealed.clear();
        self.sealed.extend_from_slice(&sealer.header());
        let mut chunks = self.scratch.chunks(1 << CHUNK_LOG2).peekable();
        while let Some(chunk) = chunks.next() {
            sealer.seal_chunk(chunk, chunks.peek().is_none(), &mut self.sealed)?;
        }
        let clen = ciphertext_len(sig.size, CHUNK_LOG2);
        debug_assert_eq!(clen, self.sealed.len() as u64);

        let full =
            self.plain + sig.size > PACK_TARGET || self.buf.len() as u64 + clen > PACK_BYTES_MAX;
        let closed = if full { self.take_pack() } else { None };

        self.files.push(Uploaded {
            remote_path: src.remote_path.clone(),
            entry: Entry {
                kind: EntryKind::File,
                size: sig.size,
                mtime_ns: sig.mtime_ns,
                exec: sig.is_exec(),
                hash: *blake3::hash(&self.scratch).as_bytes(),
                loc: Some(Loc {
                    blob: self.blob_id,
                    off: self.buf.len() as u64,
                    clen,
                    salt: sealer.salt(),
                    chunk_log2: CHUNK_LOG2,
                    epoch: self.keys.current_epoch(),
                    suite: SUITE_V1,
                    flags: 0,
                }),
            },
            sig,
            observed_ns,
        });
        // Grown by doubling, but never past what a pack can hold.
        let need = self.buf.len() + self.sealed.len();
        if need > self.buf.capacity() {
            let cap = need.max((2 * self.buf.capacity()).min(PACK_BYTES_MAX as usize));
            self.buf.reserve_exact(cap - self.buf.len());
        }
        self.buf.extend_from_slice(&self.sealed);
        self.plain += sig.size;
        Ok(closed)
    }

    pub fn finish(mut self) -> Result<Option<SealedPack>, TransferError> {
        Ok(self.take_pack())
    }

    /// Closes the pack under construction (`None` if it has no member) and starts a new one
    /// under a fresh blob id.
    pub(crate) fn take_pack(&mut self) -> Option<SealedPack> {
        if self.files.is_empty() {
            return None;
        }
        let mut buf = std::mem::take(&mut self.buf);
        buf.shrink_to_fit();
        let bytes = bytes::Bytes::from(buf);
        let files = std::mem::take(&mut self.files);
        let blob_id = std::mem::replace(&mut self.blob_id, BlobId::random());
        tracing::debug!(
            device = %self.device, blob = %blob_id, members = files.len(), plain = self.plain,
            bytes = bytes.len(), "pack sealed"
        );
        self.plain = 0;
        Some(SealedPack {
            blob_id,
            md5: Md5::digest(&bytes).into(),
            bytes,
            files,
        })
    }

    /// Drops the members sealed so far (their sources are reported as failed by the caller).
    pub(crate) fn discard(&mut self) {
        self.buf = Vec::new();
        self.files.clear();
        self.plain = 0;
    }

    /// Bytes held for the pack under construction.
    pub(crate) fn buffered(&self) -> u64 {
        self.buf.capacity() as u64
    }
}

const _: () = assert!(PACK_MEMBER_MAX + (HEADER_LEN as u64) < PACK_BYTES_MAX);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MasterKey;
    use crate::format::blob_len;

    fn keys() -> Keyring {
        Keyring::new([7; 16], vec![(1, MasterKey::from_bytes([9; 32]))], 1).unwrap()
    }

    fn source(dir: &std::path::Path, name: &str, data: &[u8]) -> UploadSource {
        let abs = dir.join(name);
        std::fs::write(&abs, data).unwrap();
        UploadSource {
            abs,
            remote_path: format!("remote/{name}"),
        }
    }

    #[test]
    fn members_are_contiguous_streams_and_the_length_is_blob_len() {
        let dir = tempfile::tempdir().unwrap();
        let keys = keys();
        for count in [1usize, 2, 500] {
            let mut builder = PackBuilder::new(keys.clone(), DeviceId([1; 8]));
            let mut plain = Vec::new();
            for i in 0..count {
                let data: Vec<u8> = (0..1 + (i * 37) % 300).map(|j| (i + j) as u8).collect();
                let src = source(dir.path(), &format!("f{i}"), &data);
                assert!(builder.add(&src).unwrap().is_none());
                plain.push(data);
            }
            let pack = builder.finish().unwrap().unwrap();
            let sizes: Vec<u64> = plain.iter().map(|d| d.len() as u64).collect();
            assert_eq!(pack.bytes.len() as u64, blob_len(&sizes), "{count} members");
            assert_eq!(pack.md5, <[u8; 16]>::from(Md5::digest(&pack.bytes)));
            assert_eq!(pack.files.len(), count);

            let mut off = 0;
            for (up, data) in pack.files.iter().zip(&plain) {
                let loc = up.entry.loc.as_ref().unwrap();
                assert_eq!((loc.blob, loc.off), (pack.blob_id, off));
                assert_eq!(up.entry.hash, *blake3::hash(data).as_bytes());
                assert_eq!(up.entry.size, data.len() as u64);
                let opener = keys.data_opener(loc).unwrap();
                let member = &pack.bytes[off as usize..(off + loc.clen) as usize];
                assert_eq!(member[..HEADER_LEN], opener.expected_header());
                let mut out = Vec::new();
                opener
                    .open_chunk(0, true, &member[HEADER_LEN..], &mut out)
                    .unwrap();
                assert_eq!(&out, data);
                off += loc.clen;
            }
            assert_eq!(off, pack.bytes.len() as u64);
        }
    }

    #[test]
    fn a_pack_closes_before_it_passes_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = PackBuilder::new(keys(), DeviceId([1; 8]));
        let member = vec![0x5a; (PACK_MEMBER_MAX - 1) as usize];
        let mut closed = Vec::new();
        for i in 0..40 {
            let src = source(dir.path(), &format!("f{i}"), &member);
            closed.extend(builder.add(&src).unwrap());
        }
        closed.extend(builder.finish().unwrap());
        assert_eq!(closed.len(), 3);
        let total: usize = closed.iter().map(|p| p.files.len()).sum();
        assert_eq!(total, 40);
        let mut ids: Vec<BlobId> = closed.iter().map(|p| p.blob_id).collect();
        ids.dedup();
        assert_eq!(ids.len(), 3, "every pack has its own blob id");
        for pack in &closed {
            let plain: u64 = pack.files.iter().map(|f| f.entry.size).sum();
            assert!(plain <= PACK_TARGET);
            assert!(pack.files.iter().all(|f| {
                let loc = f.entry.loc.as_ref().unwrap();
                loc.blob == pack.blob_id && loc.off + loc.clen <= pack.bytes.len() as u64
            }));
        }
        // In path order: the first pack holds the first sixteen files.
        assert_eq!(closed[0].files.len(), 16);
        assert_eq!(closed[0].files[0].remote_path, "remote/f0");
        assert_eq!(closed[1].files[0].remote_path, "remote/f16");
    }

    #[test]
    fn failures_leave_the_builder_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = PackBuilder::new(keys(), DeviceId([1; 8]));
        let first = source(dir.path(), "a", b"first");
        builder.add(&first).unwrap();

        let missing = UploadSource {
            abs: dir.path().join("missing"),
            remote_path: "missing".into(),
        };
        // Gone since it was scanned: changed, not unreadable.
        assert!(matches!(
            builder.add(&missing),
            Err(TransferError::SourceChanged(_))
        ));
        for (name, data) in [
            ("empty", vec![]),
            ("big", vec![1u8; PACK_MEMBER_MAX as usize]),
        ] {
            let src = source(dir.path(), name, &data);
            assert!(
                matches!(builder.add(&src), Err(TransferError::Io(_))),
                "{name}"
            );
        }
        // A descriptor whose file was shortened after the fstat: the read comes up short.
        let shrunk = source(dir.path(), "shrunk", &[3u8; 4096]);
        let (file, sig) = open_source(&shrunk.abs).unwrap();
        std::fs::write(&shrunk.abs, b"short").unwrap();
        assert!(matches!(
            builder.add_opened(&shrunk, file, sig, 0),
            Err(TransferError::SourceChanged(_))
        ));

        let pack = builder.finish().unwrap().unwrap();
        assert_eq!(pack.files.len(), 1);
        assert_eq!(pack.bytes.len() as u64, blob_len(&[5]));
    }

    #[test]
    fn an_empty_builder_finishes_with_nothing() {
        let builder = PackBuilder::new(keys(), DeviceId([1; 8]));
        assert!(builder.finish().unwrap().is_none());
    }
}

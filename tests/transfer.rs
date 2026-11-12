//! WP5 acceptance (SPEC §12.1): the transfer layer on `MemBackend` / `Flaky` with temp
//! directories and no `Vault` — `upload_batch`, packs, downloads, ranged reads, target rules.
//!
//! Every test talks to the backend through a [`Recorder`], which logs each `put` (name, id,
//! md5 and header of the bytes the pipeline sent) and each `get` (range): "never the same blob
//! id with different bytes" and "resumes from the first unverified chunk" are asserted on that
//! log, not inferred from what happens to be stored.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::ops::Range;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gclone::backend::{
    Backend, ByteStream, Flaky, Handle, MemBackend, ObjMeta, OpKind, PutBody, Quota,
};
use gclone::consts::{
    CHUNK_LOG2, DOWNLOAD_RETRIES, HEADER_LEN, MIB, PACK_MEMBER_MAX, PART_SIZE, PARTIAL_PREFIX,
    UPLOAD_ATTEMPTS,
};
use gclone::crypto::{Keyring, MasterKey, chunk_range, ciphertext_len};
use gclone::error::{BackendError, CryptoError, QuotaKind, TransferError};
use gclone::format::{blob_len, blob_name};
use gclone::transfer::{
    BlobUpload, DownloadItem, Downloaded, LocalExpect, TransferCtx, UploadEvent, UploadSource,
    Uploaded, check_target_safe, download_group, drafts_for, hash_file, locate_blob, lstat_sig,
    materialize_empties, materialize_empty, move_aside, read_range, upload_batch, verify_remote,
};
use gclone::types::{
    BaseEffect, BaseEffectKind, BlobId, BlobRec, DeviceId, Entry, EntryKind, Head, OpDraft, Stamp,
    StatSig,
};
use gclone::ui::Progress;
use md5::{Digest, Md5};
use support::prng::Prng;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const CHUNK: u64 = 1 << CHUNK_LOG2;
/// One sealed chunk: ciphertext and tag.
const SEALED_CHUNK: u64 = CHUNK + 16;

// ---------------------------------------------------------------------------------------------
// The recording backend
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct PutRecord {
    id: Handle,
    name: String,
    /// Bytes the caller sent before the put ended, their md5, and the first 60 of them.
    len: u64,
    md5: [u8; 16],
    header: Vec<u8>,
    ok: bool,
}

impl PutRecord {
    fn salt(&self) -> &[u8] {
        &self.header[12..28]
    }
}

struct Tee {
    hasher: Md5,
    len: u64,
    header: Vec<u8>,
}

impl Tee {
    fn take(&mut self, data: &[u8]) {
        let want = HEADER_LEN - self.header.len();
        self.header.extend_from_slice(&data[..want.min(data.len())]);
        self.hasher.update(data);
        self.len += data.len() as u64;
    }
}

struct Recorder {
    inner: Flaky<MemBackend>,
    puts: Mutex<Vec<PutRecord>>,
    gets: Mutex<Vec<Range<u64>>>,
}

impl Recorder {
    fn puts(&self) -> Vec<PutRecord> {
        self.puts.lock().unwrap().clone()
    }

    fn gets(&self) -> Vec<Range<u64>> {
        self.gets.lock().unwrap().clone()
    }

    /// The range of the one request made since `forget`.
    fn only_get(&self) -> Range<u64> {
        let gets = self.gets();
        assert_eq!(gets.len(), 1, "requests: {gets:?}");
        gets[0].clone()
    }

    fn forget(&self) {
        self.puts.lock().unwrap().clear();
        self.gets.lock().unwrap().clear();
    }
}

impl Backend for Recorder {
    async fn new_ids(&self, n: usize) -> Result<Vec<Handle>, BackendError> {
        self.inner.new_ids(n).await
    }

    async fn create_folder(&self, id: &Handle, p: &Handle, n: &str) -> Result<(), BackendError> {
        self.inner.create_folder(id, p, n).await
    }

    async fn put(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
        body: PutBody,
    ) -> Result<ObjMeta, BackendError> {
        let tee = Mutex::new(Tee {
            hasher: Md5::new(),
            len: 0,
            header: Vec::new(),
        });
        let result = match body {
            PutBody::Small(data) => {
                tee.lock().unwrap().take(&data);
                self.inner.put(id, parent, name, PutBody::Small(data)).await
            }
            PutBody::Stream { total, mut parts } => {
                // Relayed part by part, so that Flaky's hooks fire where they would without
                // the recorder.
                let (tx, relayed) = mpsc::channel(1);
                let relay = async {
                    while let Some(item) = parts.recv().await {
                        if let Ok(part) = &item {
                            tee.lock().unwrap().take(part);
                        }
                        if tx.send(item).await.is_err() {
                            break;
                        }
                    }
                    drop(tx);
                };
                let body = PutBody::Stream {
                    total,
                    parts: relayed,
                };
                let put = self.inner.put(id, parent, name, body);
                tokio::pin!(put, relay);
                tokio::select! {
                    biased;
                    result = &mut put => result,
                    () = &mut relay => put.await,
                }
            }
        };
        let tee = tee.into_inner().unwrap();
        self.puts.lock().unwrap().push(PutRecord {
            id: id.clone(),
            name: name.to_string(),
            len: tee.len,
            md5: tee.hasher.finalize().into(),
            header: tee.header,
            ok: result.is_ok(),
        });
        result
    }

    async fn get(&self, h: &Handle, range: Option<Range<u64>>) -> Result<ByteStream, BackendError> {
        self.gets
            .lock()
            .unwrap()
            .push(range.clone().unwrap_or(0..u64::MAX));
        self.inner.get(h, range).await
    }

    async fn stat(&self, h: &Handle) -> Result<Option<ObjMeta>, BackendError> {
        self.inner.stat(h).await
    }

    async fn list(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        self.inner.list(parent).await
    }

    async fn find_by_name(&self, name: &str) -> Result<Vec<ObjMeta>, BackendError> {
        self.inner.find_by_name(name).await
    }

    async fn trash(&self, h: &Handle) -> Result<(), BackendError> {
        self.inner.trash(h).await
    }

    async fn untrash(&self, h: &Handle) -> Result<(), BackendError> {
        self.inner.untrash(h).await
    }

    async fn delete(&self, h: &Handle) -> Result<(), BackendError> {
        self.inner.delete(h).await
    }

    async fn about(&self) -> Result<Quota, BackendError> {
        self.inner.about().await
    }

    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
}

/// §4.2 misuse resistance, on the put log: one blob name never carries two different byte
/// strings. Attempts that broke off are compared by their header (salt and commitment).
fn assert_no_reseal(puts: &[PutRecord]) {
    let mut by_name: BTreeMap<&str, Vec<&PutRecord>> = BTreeMap::new();
    for put in puts {
        by_name.entry(&put.name).or_default().push(put);
    }
    for (name, puts) in by_name {
        for pair in puts.windows(2) {
            if pair[0].header.len() == HEADER_LEN && pair[1].header.len() == HEADER_LEN {
                assert_eq!(
                    pair[0].header, pair[1].header,
                    "blob {name} was sealed twice"
                );
            }
            if pair[0].len == pair[1].len {
                assert_eq!(
                    pair[0].md5, pair[1].md5,
                    "blob {name} went up with different bytes"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Test environment
// ---------------------------------------------------------------------------------------------

struct Env {
    _tmp: tempfile::TempDir,
    src: PathBuf,
    dst: PathBuf,
    mem: MemBackend,
    flaky: Flaky<MemBackend>,
    cx: TransferCtx<Recorder>,
    folder: Handle,
}

/// What a batch reported, after checking that every source is in exactly one event.
struct Uploads {
    blobs: Vec<BlobUpload>,
    failed: Vec<(UploadSource, TransferError)>,
}

impl Uploads {
    fn find(&self, remote: &str) -> (&Uploaded, Option<&BlobRec>) {
        self.blobs
            .iter()
            .find_map(|b| {
                let file = b.files.iter().find(|f| f.remote_path == remote)?;
                Some((file, b.blob.as_ref()))
            })
            .unwrap_or_else(|| panic!("{remote} was not uploaded"))
    }

    fn blob(&self, remote: &str) -> &BlobRec {
        self.find(remote).1.expect("the file has a blob")
    }

    fn error(&self, remote: &str) -> &TransferError {
        let failed = self.failed.iter().find(|(s, _)| s.remote_path == remote);
        &failed.unwrap_or_else(|| panic!("{remote} did not fail")).1
    }

    fn assert_all_ok(&self) {
        let failed: Vec<String> = self
            .failed
            .iter()
            .map(|(s, e)| format!("{}: {e}", s.remote_path))
            .collect();
        assert!(failed.is_empty(), "failed uploads: {failed:?}");
    }
}

fn keys() -> Keyring {
    Keyring::new([0xa0; 16], vec![(1, MasterKey::from_bytes([0x42; 32]))], 1).unwrap()
}

fn bytes(seed: u64, len: usize) -> Vec<u8> {
    Prng::new(seed).bytes(len)
}

fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

fn head(up: &Uploaded) -> Head {
    Head {
        path: up.remote_path.clone(),
        stamp: Stamp {
            lamport: 1,
            device: DeviceId([1; 8]),
            idx: 0,
        },
        entry: up.entry.clone(),
        origin: None,
        winner: true,
    }
}

fn transient() -> BackendError {
    BackendError::Transient("injected".into())
}

async fn collect(mut events: mpsc::Receiver<UploadEvent>, mut expected: Vec<String>) -> Uploads {
    let mut ups = Uploads {
        blobs: Vec::new(),
        failed: Vec::new(),
    };
    while let Some(event) = events.recv().await {
        match event {
            UploadEvent::Blob(up) => {
                assert!(!up.files.is_empty(), "an event without files");
                ups.blobs.push(up);
            }
            UploadEvent::Failed(src, e) => ups.failed.push((src, e)),
        }
    }
    let mut seen: Vec<String> = ups
        .blobs
        .iter()
        .flat_map(|b| b.files.iter().map(|f| f.remote_path.clone()))
        .chain(ups.failed.iter().map(|(s, _)| s.remote_path.clone()))
        .collect();
    seen.sort();
    expected.sort();
    assert_eq!(seen, expected, "every source appears in exactly one event");
    ups
}

impl Env {
    async fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let (src, dst) = (tmp.path().join("src"), tmp.path().join("dst"));
        fs::create_dir(&src).unwrap();
        fs::create_dir(&dst).unwrap();
        let mem = MemBackend::new();
        let flaky = Flaky::new(mem.clone());
        let folder = mem.new_ids(1).await.unwrap().remove(0);
        mem.create_folder(&folder, &Handle::top(), "data")
            .await
            .unwrap();
        mem.reset_counters();
        let cx = TransferCtx {
            backend: Arc::new(Recorder {
                inner: flaky.clone(),
                puts: Mutex::default(),
                gets: Mutex::default(),
            }),
            keys: keys(),
            device: DeviceId([1; 8]),
            progress: Progress::hidden(),
            cancel: CancellationToken::new(),
        };
        Env {
            _tmp: tmp,
            src,
            dst,
            mem,
            flaky,
            cx,
            folder,
        }
    }

    fn rec(&self) -> &Recorder {
        &self.cx.backend
    }

    /// Creates `src/<rel>`; the remote path is `rel`.
    fn write(&self, rel: &str, data: &[u8]) -> UploadSource {
        let abs = self.src.join(rel);
        fs::create_dir_all(abs.parent().unwrap()).unwrap();
        fs::write(&abs, data).unwrap();
        UploadSource {
            abs,
            remote_path: rel.to_string(),
        }
    }

    fn start(&self, sources: &[UploadSource], transfers: usize) -> mpsc::Receiver<UploadEvent> {
        upload_batch(
            self.cx.clone(),
            self.folder.clone(),
            sources.to_vec(),
            transfers,
        )
    }

    async fn upload(&self, sources: &[UploadSource], transfers: usize) -> Uploads {
        let expected = sources.iter().map(|s| s.remote_path.clone()).collect();
        collect(self.start(sources, transfers), expected).await
    }

    fn item(&self, up: &Uploaded, rel: &str, expect: LocalExpect) -> DownloadItem {
        DownloadItem {
            head: head(up),
            root: self.dst.clone(),
            rel: rel.to_string(),
            expect_local: expect,
        }
    }

    /// Downloads one uploaded file to `dst/<rel>`.
    async fn fetch(
        &self,
        ups: &Uploads,
        remote: &str,
        rel: &str,
        expect: LocalExpect,
    ) -> Result<Downloaded, TransferError> {
        let (up, blob) = ups.find(remote);
        let item = self.item(up, rel, expect);
        let mut done = download_group(&self.cx, blob.unwrap(), vec![item]).await;
        assert_eq!(done.len(), 1);
        done.remove(0).1
    }

    /// Uploads one file and returns the batch.
    async fn one(&self, rel: &str, data: &[u8]) -> Uploads {
        let ups = self.upload(&[self.write(rel, data)], 2).await;
        ups.assert_all_ok();
        ups
    }

    fn stored(&self, blob: &BlobRec) -> bytes::Bytes {
        self.mem
            .read(&Handle(blob.file_id.clone()))
            .expect("the blob is stored")
    }

    /// Files stored in the data folder and not trashed.
    async fn live_blobs(&self) -> Vec<ObjMeta> {
        self.mem.list(&self.folder).await.unwrap()
    }

    /// Every path below `dst`, relative, sorted.
    fn dst_tree(&self) -> Vec<String> {
        fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                out.push(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string(),
                );
                if path.symlink_metadata().unwrap().is_dir() {
                    walk(&path, root, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.dst, &self.dst, &mut out);
        out.sort();
        out
    }

    fn assert_no_partials(&self) {
        let partials: Vec<String> = self
            .dst_tree()
            .into_iter()
            .filter(|p| p.rsplit('/').next().unwrap().starts_with(PARTIAL_PREFIX))
            .collect();
        assert!(
            partials.is_empty(),
            "partial files left behind: {partials:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Upload → download round trip
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn round_trip_of_every_size_class() {
    let env = Env::new().await;
    let m = MIB as usize;
    let sizes = [0, 1, 65_535, 65_536, 65_537, m - 1, m, 5 * m, 40 * m];
    let mut plain = BTreeMap::new();
    let mut sources = Vec::new();
    for (i, size) in sizes.iter().enumerate() {
        let name = format!("dir/f{i}-{size}");
        let data = bytes(i as u64, *size);
        sources.push(env.write(&name, &data));
        plain.insert(name, data);
    }
    // One executable among them: the bit travels in the entry.
    let exec = sources[3].remote_path.clone();
    fs::set_permissions(&sources[3].abs, fs::Permissions::from_mode(0o755)).unwrap();

    let ups = env.upload(&sources, 4).await;
    ups.assert_all_ok();

    // Zero length: no blob, no location, the hash of the empty string.
    let (empty, none) = ups.find("dir/f0-0");
    assert!(none.is_none());
    let empty_sig = lstat_sig(&sources[0].abs).unwrap().unwrap();
    assert_eq!(empty.entry, Entry::empty_file(empty_sig.mtime_ns, false));
    assert_eq!(empty.sig, empty_sig);

    // 0 < n < 1 MiB: one pack, members in path order; the rest: one blob each.
    assert_eq!(
        ups.blobs.len(),
        5,
        "one event for the empties, one pack, three large files"
    );
    assert_eq!(env.mem.counters().put, 4);
    let pack = ups
        .blobs
        .iter()
        .find(|b| b.files.len() == 5)
        .expect("a pack of five");
    let packed: Vec<&str> = pack.files.iter().map(|f| f.remote_path.as_str()).collect();
    let small: Vec<&str> = sources[1..6]
        .iter()
        .map(|s| s.remote_path.as_str())
        .collect();
    assert_eq!(packed, small);

    for event in &ups.blobs {
        let Some(blob) = &event.blob else { continue };
        let member_sizes: Vec<u64> = event.files.iter().map(|f| f.entry.size).collect();
        let stored = env.stored(blob);
        assert_eq!(blob.clen, blob_len(&member_sizes));
        assert_eq!(stored.len() as u64, blob.clen);
        assert_eq!(blob.md5, md5(&stored));
        let meta = env
            .mem
            .stat(&Handle(blob.file_id.clone()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (meta.name, meta.parent),
            (blob_name(&blob.id), env.folder.clone())
        );
        assert_eq!(blob.created_ms, meta.created_ms);

        let mut off = 0;
        for file in &event.files {
            let data = &plain[&file.remote_path];
            let loc = file
                .entry
                .loc
                .as_ref()
                .expect("a non-empty file has a location");
            assert_eq!((loc.blob, loc.off), (blob.id, off));
            assert_eq!(loc.clen, ciphertext_len(data.len() as u64, CHUNK_LOG2));
            assert_eq!(
                (loc.chunk_log2, loc.epoch, loc.suite, loc.flags),
                (CHUNK_LOG2, 1, 1, 0)
            );
            assert_eq!(file.entry.kind, EntryKind::File);
            assert_eq!(file.entry.size, data.len() as u64);
            assert_eq!(file.entry.hash, *blake3::hash(data).as_bytes());
            assert_eq!(file.entry.exec, file.remote_path == exec);
            off += loc.clen;
        }
        assert_eq!(off, blob.clen, "members are contiguous and fill the blob");
    }
    // Salts are fresh for every stream.
    let salts: BTreeSet<[u8; 16]> = ups
        .blobs
        .iter()
        .flat_map(|b| {
            b.files
                .iter()
                .filter_map(|f| Some(f.entry.loc.as_ref()?.salt))
        })
        .collect();
    assert_eq!(salts.len(), 8);

    // Down again.
    for event in &ups.blobs {
        let items: Vec<DownloadItem> = event
            .files
            .iter()
            .map(|f| env.item(f, &f.remote_path, LocalExpect::Absent))
            .collect();
        let done = match &event.blob {
            Some(blob) => download_group(&env.cx, blob, items).await,
            None => {
                let mut done = Vec::new();
                for item in items {
                    let result = materialize_empty(&item).await;
                    done.push((item, result));
                }
                done
            }
        };
        assert_eq!(done.len(), event.files.len());
        for ((item, result), up) in done.into_iter().zip(&event.files) {
            let got = result.unwrap_or_else(|e| panic!("{}: {e}", item.rel));
            let target = env.dst.join(&item.rel);
            assert_eq!(item.rel, up.remote_path, "results come in input order");
            assert_eq!(got.rel, item.rel);
            assert_eq!(got.moved_aside, None);
            assert_eq!(Some(got.sig), lstat_sig(&target).unwrap());
            assert_eq!(fs::read(&target).unwrap(), plain[&item.rel], "{}", item.rel);
            let (sig, _, hash) = hash_file(&target).unwrap();
            assert_eq!(hash, up.entry.hash);
            assert_eq!(sig.mtime_ns, up.sig.mtime_ns, "the mtime is restored");
            assert_eq!(sig.is_exec(), item.rel == exec);
            assert_eq!(
                sig.mode & 0o7022,
                0,
                "never setuid, never group- or world-writable"
            );
        }
    }
    env.assert_no_partials();
    assert_eq!(env.dst_tree().len(), sizes.len() + 1);

    let total: u64 = sizes.iter().map(|s| *s as u64).sum();
    assert_eq!(env.cx.progress.bytes(), 2 * total);
    assert_eq!(env.cx.progress.files(), 2 * sizes.len() as u64 - 1);
    assert_eq!(env.cx.progress.blobs(), 8);
}

#[tokio::test]
async fn a_pack_of_500_tiny_files_is_one_put_and_one_get() {
    let env = Env::new().await;
    let mut plain = Vec::new();
    let mut sources = Vec::new();
    for i in 0..500 {
        let data = bytes(1000 + i, 1 + (i as usize * 13) % 200);
        sources.push(env.write(&format!("tiny/{i:03}"), &data));
        plain.push(data);
    }
    let ups = env.upload(&sources, 4).await;
    ups.assert_all_ok();
    let counters = env.mem.counters();
    assert_eq!(
        (counters.put, counters.new_ids),
        (1, 1),
        "one put, none per file"
    );
    assert_eq!(ups.blobs.len(), 1);
    let blob = ups.blobs[0].blob.as_ref().unwrap();
    let files = &ups.blobs[0].files;
    assert_eq!(files.len(), 500);
    assert_eq!(
        blob.clen,
        blob_len(&plain.iter().map(|p| p.len() as u64).collect::<Vec<_>>())
    );

    // All members with one coalesced request.
    env.mem.reset_counters();
    let items = files
        .iter()
        .map(|f| env.item(f, &f.remote_path, LocalExpect::Absent))
        .collect();
    let done = download_group(&env.cx, blob, items).await;
    assert_eq!(env.rec().only_get(), 0..blob.clen);
    assert_eq!(env.mem.counters().get_bytes, blob.clen);
    for ((item, result), data) in done.iter().zip(&plain) {
        result
            .as_ref()
            .unwrap_or_else(|e| panic!("{}: {e}", item.rel));
        assert_eq!(&fs::read(env.dst.join(&item.rel)).unwrap(), data);
    }

    // Each member alone: exactly its own bytes are requested.
    for i in [0usize, 137, 499] {
        env.rec().forget();
        let rel = format!("alone/{i}");
        let item = env.item(&files[i], &rel, LocalExpect::Absent);
        let loc = files[i].entry.loc.clone().unwrap();
        let done = download_group(&env.cx, blob, vec![item]).await;
        done[0].1.as_ref().unwrap();
        assert_eq!(env.rec().only_get(), loc.off..loc.off + loc.clen);
        assert_eq!(fs::read(env.dst.join(&rel)).unwrap(), plain[i]);
    }
    env.assert_no_partials();
}

#[tokio::test]
async fn members_are_coalesced_up_to_the_gap_limit() {
    let env = Env::new().await;
    let size = 200 * 1024;
    let sources: Vec<UploadSource> = (0..10)
        .map(|i| env.write(&format!("m{i}"), &bytes(i, size)))
        .collect();
    let ups = env.upload(&sources, 1).await;
    ups.assert_all_ok();
    assert_eq!(ups.blobs.len(), 1);
    let blob = ups.blobs[0].blob.as_ref().unwrap();
    let files = &ups.blobs[0].files;
    let clen = ciphertext_len(size as u64, CHUNK_LOG2);
    let span = |a: u64, b: u64| a * clen..(b + 1) * clen;

    // (members asked for — deliberately not in blob order, expected requests)
    let cases: [(&[usize], Vec<Range<u64>>); 4] = [
        // One member between them: the gap (≈ 200 KiB) is read and thrown away.
        (&[2, 0], vec![span(0, 2)]),
        // Two members between them (≈ 400 KiB): two requests.
        (&[3, 0], vec![span(0, 0), span(3, 3)]),
        (&[9, 0, 5, 1], vec![span(0, 1), span(5, 5), span(9, 9)]),
        (&[4, 5, 6, 7], vec![span(4, 7)]),
    ];
    for (round, (members, requests)) in cases.into_iter().enumerate() {
        env.rec().forget();
        let items: Vec<DownloadItem> = members
            .iter()
            .map(|&i| env.item(&files[i], &format!("r{round}/m{i}"), LocalExpect::Absent))
            .collect();
        let done = download_group(&env.cx, blob, items).await;
        assert_eq!(env.rec().gets(), requests, "members {members:?}");
        for ((item, result), &i) in done.iter().zip(members) {
            result.as_ref().unwrap();
            assert_eq!(
                item.rel,
                format!("r{round}/m{i}"),
                "results come in input order"
            );
            assert_eq!(
                fs::read(env.dst.join(&item.rel)).unwrap(),
                bytes(i as u64, size)
            );
        }
    }
}

#[tokio::test]
async fn a_file_that_outgrew_the_pack_limit_goes_up_alone() {
    let env = Env::new().await;
    let a = env.write("a", &bytes(1, 100));
    // What the scan saw …
    let b = env.write("b", &bytes(2, 500 * 1024));
    let c = env.write("c", &bytes(3, 100));
    // … and what is there when the upload opens it.
    let grown = bytes(4, PACK_MEMBER_MAX as usize + 5);
    fs::write(&b.abs, &grown).unwrap();

    let ups = env.upload(&[a, b, c], 2).await;
    ups.assert_all_ok();
    assert_eq!(env.mem.counters().put, 2);
    let (up, blob) = ups.find("b");
    let loc = up.entry.loc.as_ref().unwrap();
    assert_eq!(up.entry.size, grown.len() as u64);
    assert_eq!((loc.off, loc.clen), (0, blob.unwrap().clen));
    assert_eq!(blob.unwrap().clen, blob_len(&[grown.len() as u64]));
    assert_eq!(
        ups.blob("a").id,
        ups.blob("c").id,
        "the small files share a pack"
    );
    assert_ne!(ups.blob("a").id, ups.blob("b").id);

    env.fetch(&ups, "b", "b", LocalExpect::Absent)
        .await
        .unwrap();
    assert_eq!(fs::read(env.dst.join("b")).unwrap(), grown);
}

// ---------------------------------------------------------------------------------------------
// Retries: sealed bytes are replayed, never regenerated
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_pack_is_replayed_byte_for_byte() {
    // (fault, puts expected, the retry keeps the Drive id)
    type Arm = fn(&Flaky<MemBackend>);
    let cases: [(&str, Arm, usize, bool); 4] = [
        ("lost ack", |f| f.lose_ack_next_put(), 2, true),
        (
            "transient",
            |f| f.fail_next(OpKind::Put, 2, transient),
            3,
            true,
        ),
        (
            "session lost",
            |f| f.fail_next(OpKind::Put, 1, || BackendError::SessionLost),
            2,
            false,
        ),
        ("wrong md5", |f| f.corrupt_md5_next_put(), 2, false),
    ];
    for (what, arm, attempts, same_id) in cases {
        let env = Env::new().await;
        let sources: Vec<UploadSource> = (0..20)
            .map(|i| env.write(&format!("p{i:02}"), &bytes(i, 3000 + i as usize)))
            .collect();
        arm(&env.flaky);
        let ups = env.upload(&sources, 2).await;
        ups.assert_all_ok();
        assert_eq!(ups.blobs.len(), 1, "{what}");
        let blob = ups.blobs[0].blob.as_ref().unwrap();

        let puts = env.rec().puts();
        assert_eq!(puts.len(), attempts, "{what}");
        assert_no_reseal(&puts);
        for put in &puts {
            assert_eq!(
                put.name,
                blob_name(&blob.id),
                "{what}: a pack keeps its blob id"
            );
            assert_eq!((put.len, put.md5), (blob.clen, blob.md5), "{what}");
        }
        let ids: BTreeSet<&str> = puts.iter().map(|p| p.id.0.as_str()).collect();
        // Same Drive id while the first put may have stored the object; a new one otherwise.
        assert_eq!(ids.len(), if same_id { 1 } else { attempts }, "{what}");
        // What is stored under the accepted id is what was sealed first.
        assert_eq!(blob.file_id, puts.last().unwrap().id.0, "{what}");
        assert_eq!(md5(&env.stored(blob)), puts[0].md5, "{what}");
        let live = env.live_blobs().await;
        assert_eq!(live.len(), 1, "{what}: one live object carries the name");
        assert_eq!(live[0].handle.0, blob.file_id);

        let got = env.fetch(&ups, "p07", "p07", LocalExpect::Absent).await;
        got.unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(fs::read(env.dst.join("p07")).unwrap(), bytes(7, 3007));
    }
}

#[tokio::test]
async fn a_rejected_upload_is_trashed_and_retried_under_a_new_id() {
    let env = Env::new().await;
    let small: Vec<UploadSource> = (0..5)
        .map(|i| env.write(&format!("s{i}"), &bytes(i, 900)))
        .collect();
    env.flaky.corrupt_md5_next_put();
    let ups = env.upload(&small, 1).await;
    ups.assert_all_ok();
    let puts = env.rec().puts();
    assert_eq!(puts.len(), 2);
    assert_ne!(puts[0].id, puts[1].id);
    let first = env.mem.stat(&puts[0].id).await.unwrap().unwrap();
    let second = env.mem.stat(&puts[1].id).await.unwrap().unwrap();
    assert!(first.trashed && !second.trashed);
    assert_eq!(env.mem.counters().trash, 1);
    assert_eq!(ups.blob("s0").file_id, puts[1].id.0);

    // A large file cannot be replayed: the retry is a new stream under a new blob id.
    env.rec().forget();
    let data = bytes(77, 5 * MIB as usize);
    let large = env.write("large", &data);
    env.flaky.corrupt_md5_next_put();
    let ups = env.upload(&[large], 1).await;
    ups.assert_all_ok();
    let puts = env.rec().puts();
    assert_eq!(puts.len(), 2);
    assert_no_reseal(&puts);
    assert_ne!(puts[0].name, puts[1].name, "a new blob id");
    assert_ne!(puts[0].id, puts[1].id, "a new Drive id");
    assert_ne!(puts[0].salt(), puts[1].salt(), "a new salt");
    assert!(env.mem.stat(&puts[0].id).await.unwrap().unwrap().trashed);
    let (up, blob) = ups.find("large");
    assert_eq!(blob.unwrap().file_id, puts[1].id.0);
    assert_eq!(blob_name(&blob.unwrap().id), puts[1].name);
    assert_eq!(up.entry.loc.as_ref().unwrap().salt, puts[1].salt());
    env.fetch(&ups, "large", "large", LocalExpect::Absent)
        .await
        .unwrap();
    assert_eq!(fs::read(env.dst.join("large")).unwrap(), data);
}

#[tokio::test]
async fn a_pack_that_never_gets_through_fails_every_member() {
    let env = Env::new().await;
    let sources: Vec<UploadSource> = (0..6)
        .map(|i| env.write(&format!("p{i}"), &bytes(i, 500)))
        .collect();
    env.flaky.fail_next(OpKind::Put, u32::MAX, transient);
    let ups = env.upload(&sources, 2).await;
    assert!(ups.blobs.is_empty());
    assert_eq!(ups.failed.len(), 6);
    for (_, e) in &ups.failed {
        assert!(
            matches!(e, TransferError::Backend(BackendError::Transient(_))),
            "{e}"
        );
    }
    assert_eq!(env.rec().puts().len(), UPLOAD_ATTEMPTS as usize);
    assert_no_reseal(&env.rec().puts());
    assert!(env.live_blobs().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_file_is_never_sealed_twice_under_one_blob_id() {
    let size = 17 * MIB as usize;
    // (fault, puts expected)
    type Arm = fn(&Flaky<MemBackend>);
    let cases: [(&str, Arm, usize); 4] = [
        // The object is there and intact: found by id, no second upload.
        ("lost ack", |f| f.lose_ack_next_put(), 1),
        ("transient", |f| f.fail_next(OpKind::Put, 1, transient), 2),
        ("session cut", |f| f.cut_next_stream_put(PART_SIZE), 2),
        (
            "session lost",
            |f| f.fail_next(OpKind::Put, 2, || BackendError::SessionLost),
            3,
        ),
    ];
    for (what, arm, attempts) in cases {
        let env = Env::new().await;
        let data = bytes(5, size);
        let src = env.write("big", &data);
        arm(&env.flaky);
        let ups = env.upload(&[src], 2).await;
        ups.assert_all_ok();
        let (up, blob) = ups.find("big");
        let blob = blob.unwrap();

        let puts = env.rec().puts();
        assert_eq!(puts.len(), attempts, "{what}");
        assert_no_reseal(&puts);
        let names: BTreeSet<&str> = puts.iter().map(|p| p.name.as_str()).collect();
        let ids: BTreeSet<&str> = puts.iter().map(|p| p.id.0.as_str()).collect();
        assert_eq!(
            (names.len(), ids.len()),
            (attempts, attempts),
            "{what}: new blob id and Drive id per attempt"
        );
        let salts: BTreeSet<&[u8]> = puts
            .iter()
            .filter(|p| p.len > 0)
            .map(|p| p.salt())
            .collect();
        assert_eq!(
            salts.len(),
            puts.iter().filter(|p| p.len > 0).count(),
            "{what}: new salt per attempt"
        );

        let accepted = puts.last().unwrap();
        assert_eq!(
            (blob_name(&blob.id), blob.file_id.as_str()),
            (accepted.name.clone(), accepted.id.0.as_str())
        );
        assert_eq!(
            (blob.clen, blob.md5),
            (accepted.len, accepted.md5),
            "{what}"
        );
        assert_eq!(
            md5(&env.stored(blob)),
            accepted.md5,
            "{what}: stored = sent"
        );
        assert_eq!(up.entry.loc.as_ref().unwrap().salt, accepted.salt());
        assert_eq!(up.entry.hash, *blake3::hash(&data).as_bytes());
        assert_eq!(env.live_blobs().await.len(), 1, "{what}");
        verify_remote(env.rec(), &env.cx.keys, blob, &head(up))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn a_small_single_blob_with_a_lost_ack_is_found_by_id() {
    let env = Env::new().await;
    let data = bytes(9, MIB as usize);
    let src = env.write("one-mib", &data);
    env.flaky.lose_ack_next_put();
    let ups = env.upload(&[src], 1).await;
    ups.assert_all_ok();
    assert_eq!(env.rec().puts().len(), 1);
    assert_eq!(env.live_blobs().await.len(), 1);
    env.fetch(&ups, "one-mib", "x", LocalExpect::Absent)
        .await
        .unwrap();
    assert_eq!(fs::read(env.dst.join("x")).unwrap(), data);
}

// ---------------------------------------------------------------------------------------------
// Sources that change or cannot be read
// ---------------------------------------------------------------------------------------------

fn append(path: &Path, byte: u8) {
    use std::io::Write;
    let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&[byte]).unwrap();
}

/// Appends to `path` at the start of the next `times` stream puts.
fn keep_changing(flaky: &Flaky<MemBackend>, path: PathBuf, times: u32) {
    if times == 0 {
        return;
    }
    let again = flaky.clone();
    flaky.on_put_progress(
        0,
        Box::new(move || {
            append(&path, 0xcc);
            keep_changing(&again, path, times - 1);
        }),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_that_changes_mid_upload_is_read_again_with_everything_new() {
    let env = Env::new().await;
    // Two parts: the second — and with it the final fstat — is sealed after the hook ran.
    let src = env.write("moving", &bytes(6, 17 * MIB as usize));
    keep_changing(&env.flaky, src.abs.clone(), 1);

    let ups = env.upload(std::slice::from_ref(&src), 2).await;
    ups.assert_all_ok();
    let now = fs::read(&src.abs).unwrap();
    assert_eq!(now.len(), 17 * MIB as usize + 1);
    let (up, blob) = ups.find("moving");
    assert_eq!(up.entry.size, now.len() as u64);
    assert_eq!(up.entry.hash, *blake3::hash(&now).as_bytes());
    assert_eq!(
        Some(up.sig),
        lstat_sig(&src.abs).unwrap(),
        "the signature is of the bytes sent"
    );

    let puts = env.rec().puts();
    assert_eq!(puts.len(), 2);
    assert!(!puts[0].ok && puts[1].ok);
    assert_ne!(puts[0].name, puts[1].name, "a new blob id");
    assert_ne!(puts[0].id, puts[1].id, "a new Drive id");
    assert_ne!(puts[0].salt(), puts[1].salt(), "a new salt");
    assert_no_reseal(&puts);
    assert_eq!(
        env.live_blobs().await.len(),
        1,
        "the abandoned attempt stored nothing"
    );
    assert_eq!(md5(&env.stored(blob.unwrap())), puts[1].md5);

    env.fetch(&ups, "moving", "moving", LocalExpect::Absent)
        .await
        .unwrap();
    assert_eq!(fs::read(env.dst.join("moving")).unwrap(), now);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_that_keeps_changing_fails_after_the_attempts() {
    let env = Env::new().await;
    let moving = env.write("moving", &bytes(6, 17 * MIB as usize));
    let still = env.write("still", &bytes(7, 2000));
    keep_changing(&env.flaky, moving.abs.clone(), UPLOAD_ATTEMPTS + 2);

    let ups = env.upload(&[moving.clone(), still], 1).await;
    match ups.error("moving") {
        TransferError::SourceChanged(path) => assert_eq!(path, moving.abs.to_str().unwrap()),
        e => panic!("{e}"),
    }
    ups.find("still");

    let large: Vec<PutRecord> = env.rec().puts().into_iter().filter(|p| !p.ok).collect();
    assert_eq!(large.len(), UPLOAD_ATTEMPTS as usize);
    let names: BTreeSet<&str> = large.iter().map(|p| p.name.as_str()).collect();
    let salts: BTreeSet<&[u8]> = large.iter().map(|p| p.salt()).collect();
    assert_eq!((names.len(), salts.len()), (large.len(), large.len()));
    assert_eq!(
        env.live_blobs().await.len(),
        1,
        "only the pack of the other file is stored"
    );
    assert_eq!(
        fs::read(&moving.abs).unwrap().len(),
        17 * MIB as usize + UPLOAD_ATTEMPTS as usize
    );
}

/// Sources are files a scan saw as regular files. One that is gone when the upload gets to it,
/// or has become something else, changed since — `SourceChanged`, which the sync engine reports
/// as a skip and which does not hold back the deletes of the run. Only a file that is still
/// there and cannot be read is `SourceUnreadable`.
#[tokio::test]
async fn fifos_symlinks_and_directories_are_refused_without_blocking() {
    let env = Env::new().await;
    let regular = env.write("a-regular", b"fine");
    let fifo = env.src.join("b-fifo");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: `c` is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    std::os::unix::fs::symlink(&regular.abs, env.src.join("c-link")).unwrap();
    std::os::unix::fs::symlink(env.src.join("nowhere"), env.src.join("d-dangling")).unwrap();
    fs::create_dir(env.src.join("e-dir")).unwrap();
    let odd = ["b-fifo", "c-link", "d-dangling", "e-dir", "f-missing"];
    let mut sources = vec![regular];
    sources.extend(odd.iter().map(|name| UploadSource {
        abs: env.src.join(name),
        remote_path: name.to_string(),
    }));
    sources.push(env.write("g-regular", b"also fine"));
    // A file that exists and may not be opened (unless the tests run as root).
    let locked = env.write("h-locked", b"private");
    fs::set_permissions(&locked.abs, fs::Permissions::from_mode(0o000)).unwrap();
    let binds = fs::File::open(&locked.abs).is_err();
    sources.push(locked);
    // A large file that is gone: the same answer from the path that would have streamed it.
    let large = env.write("i-large-gone", &bytes(3, 2 * MIB as usize));
    fs::remove_file(&large.abs).unwrap();
    sources.push(large);

    // Opening a FIFO for reading blocks until there is a writer — unless O_NONBLOCK is set.
    let ups = tokio::time::timeout(Duration::from_secs(30), env.upload(&sources, 2))
        .await
        .expect("the upload must not block on a FIFO");
    for name in odd.into_iter().chain(["i-large-gone"]) {
        match ups.error(name) {
            TransferError::SourceChanged(path) => assert!(path.ends_with(name)),
            e => panic!("{name}: {e}"),
        }
    }
    if binds {
        match ups.error("h-locked") {
            TransferError::SourceUnreadable { path, err } => {
                assert!(path.ends_with("h-locked"));
                assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
            }
            e => panic!("h-locked: {e}"),
        }
    }
    assert_eq!(ups.blob("a-regular").id, ups.blob("g-regular").id);
    assert_eq!(env.mem.counters().put, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_source_that_vanishes_before_a_new_attempt_has_changed() {
    let env = Env::new().await;
    let src = env.write("moving", &bytes(4, 17 * MIB as usize));
    // The first attempt sees the file change; it is gone when the second one opens it again.
    let path = src.abs.clone();
    env.flaky.on_put_progress(
        0,
        Box::new(move || {
            use std::io::Write;
            let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(b"!").unwrap();
            fs::remove_file(&path).unwrap();
        }),
    );
    let ups = env.upload(&[src], 1).await;
    assert!(
        matches!(ups.error("moving"), TransferError::SourceChanged(_)),
        "{}",
        ups.error("moving")
    );
    assert_eq!(env.flaky.calls(OpKind::Put), 1, "nothing to send again");
    assert!(env.live_blobs().await.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Stop conditions
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_quota_or_rate_limit_answer_stops_the_batch() {
    type Make = fn() -> BackendError;
    type IsThat = fn(&TransferError) -> bool;
    let cases: [(Make, IsThat); 2] = [
        (
            || BackendError::QuotaExceeded(QuotaKind::StorageFull),
            |e| {
                matches!(
                    e,
                    TransferError::Backend(BackendError::QuotaExceeded(QuotaKind::StorageFull))
                )
            },
        ),
        (
            || BackendError::RateLimited,
            |e| matches!(e, TransferError::Backend(BackendError::RateLimited)),
        ),
    ];
    for (make, is_that_error) in cases {
        let env = Env::new().await;
        let mut sources = vec![env.write("a-empty", b"")];
        for i in 0..4 {
            sources.push(env.write(&format!("b-large{i}"), &bytes(i, MIB as usize)));
        }
        for i in 0..30 {
            sources.push(env.write(&format!("c-small{i:02}"), &bytes(i, 4000)));
        }
        sources.push(env.write("d-empty", b""));
        env.flaky.fail_next(OpKind::Put, 1, make);

        let ups = env.upload(&sources, 1).await;
        // The empty file before the failing put needed no put; everything else — the failed
        // blob, the large files behind it, the pack, the later empty file — carries the error.
        assert_eq!(ups.blobs.len(), 1);
        assert!(ups.blobs[0].blob.is_none());
        assert_eq!(ups.blobs[0].files[0].remote_path, "a-empty");
        assert_eq!(ups.failed.len(), sources.len() - 1);
        for (src, e) in &ups.failed {
            assert!(is_that_error(e), "{}: {e}", src.remote_path);
        }
        assert_eq!(env.flaky.calls(OpKind::Put), 1, "no further put is started");
        assert!(env.live_blobs().await.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_receiver_stops_the_pipeline() {
    let env = Env::new().await;
    let sources: Vec<UploadSource> = (0..40)
        .map(|i| env.write(&format!("f{i:02}"), &bytes(i, MIB as usize)))
        .collect();
    let mut events = env.start(&sources, 1);
    assert!(matches!(events.recv().await, Some(UploadEvent::Blob(_))));
    drop(events);

    // The puts come to rest far from the end.
    let mut puts = env.flaky.calls(OpKind::Put);
    loop {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let now = env.flaky.calls(OpKind::Put);
        if now == puts {
            break;
        }
        puts = now;
    }
    assert!(puts <= 4, "{puts} puts after the receiver was dropped");
}

#[tokio::test]
async fn a_cancelled_batch_starts_nothing() {
    let env = Env::new().await;
    let mut sources = vec![env.write("a-empty", b"")];
    sources.extend((0..10).map(|i| env.write(&format!("b{i}"), &bytes(i, 3000))));
    sources.push(env.write("c-large", &bytes(1, MIB as usize)));
    env.cx.cancel.cancel();
    let ups = env.upload(&sources, 2).await;
    assert!(ups.blobs.is_empty());
    assert_eq!(ups.failed.len(), sources.len());
    assert!(
        ups.failed
            .iter()
            .all(|(_, e)| matches!(e, TransferError::Cancelled))
    );
    assert_eq!(env.flaky.calls(OpKind::Put), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_mid_batch_accounts_for_every_source() {
    let env = Env::new().await;
    let sources: Vec<UploadSource> = (0..30)
        .map(|i| env.write(&format!("f{i:02}"), &bytes(i, MIB as usize)))
        .collect();
    let mut events = env.start(&sources, 1);
    let first = events.recv().await.expect("a first event");
    env.cx.cancel.cancel();
    let mut done = usize::from(matches!(first, UploadEvent::Blob(_)));
    let mut cancelled = 0;
    while let Some(event) = events.recv().await {
        match event {
            UploadEvent::Blob(_) => done += 1,
            UploadEvent::Failed(_, TransferError::Cancelled) => cancelled += 1,
            UploadEvent::Failed(src, e) => panic!("{}: {e}", src.remote_path),
        }
    }
    assert_eq!(done + cancelled, sources.len());
    assert!(
        cancelled >= sources.len() - 4,
        "{done} uploads finished after the cancellation"
    );
    assert_eq!(env.flaky.calls(OpKind::Put) as usize, done);
}

/// §5.7: after a cancellation every wait for the backend — not only the put — ends within
/// five seconds (`CANCEL_GRACE`). `Flaky::hang` is a network that went away: the call never
/// returns. Time is paused, so the five seconds are exact and cost nothing.
#[tokio::test(start_paused = true)]
async fn a_cancelled_upload_waits_five_seconds_for_no_backend_call() {
    // The id before the put; the put itself; the `stat` after a put whose answer was lost.
    let cases = [
        (OpKind::NewIds, false, 0),
        (OpKind::Put, false, 1),
        (OpKind::Stat, true, 1),
    ];
    for (hangs, lose_ack, puts) in cases {
        let env = Env::new().await;
        let src = env.write("f", &bytes(1, 5 * MIB as usize));
        env.flaky.hang(hangs);
        if lose_ack {
            env.flaky.lose_ack_next_put();
        }
        let mut events = env.start(&[src], 1);
        while env.flaky.calls(hangs) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let cancelled = tokio::time::Instant::now();
        env.cx.cancel.cancel();
        let event = tokio::time::timeout(Duration::from_secs(3600), events.recv())
            .await
            .unwrap_or_else(|_| panic!("{hangs:?}: the batch never ended"));
        let waited = cancelled.elapsed();
        match event {
            Some(UploadEvent::Failed(src, TransferError::Cancelled)) => {
                assert_eq!(src.remote_path, "f")
            }
            Some(UploadEvent::Failed(_, e)) => panic!("{hangs:?}: {e}"),
            Some(UploadEvent::Blob(_)) => panic!("{hangs:?}: uploaded after the cancellation"),
            None => panic!("{hangs:?}: no event"),
        }
        assert!(
            waited >= Duration::from_secs(5) && waited < Duration::from_secs(6),
            "{hangs:?}: waited {waited:?}"
        );
        assert!(events.recv().await.is_none());
        assert_eq!(env.flaky.calls(OpKind::Put), puts, "{hangs:?}");
        assert_eq!(env.flaky.calls(hangs), 1, "{hangs:?}: not asked again");
    }
}

/// The download side has no grace: a cancelled download stops at once, also while it looks a
/// blob up by name or asks how long a blob is whose download ended early.
#[tokio::test(start_paused = true)]
async fn a_cancelled_download_waits_for_no_backend_call() {
    for hangs in [OpKind::FindByName, OpKind::Stat] {
        let env = Env::new().await;
        let ups = env.one("f", &bytes(1, 300_000)).await;
        let (up, blob) = ups.find("f");
        let mut rec = blob.unwrap().clone();
        match hangs {
            // The recorded id is gone: the blob is looked up by its name.
            OpKind::FindByName => rec.file_id = "an-id-from-another-account".into(),
            // The object is shorter than recorded: the download ends early and `stat` is asked.
            _ => env
                .mem
                .tamper(&Handle(rec.file_id.clone()), |v| v.truncate(100_000)),
        }
        env.flaky.hang(hangs);
        let item = env.item(up, "f", LocalExpect::Absent);
        let download = download_group(&env.cx, &rec, vec![item]);
        let cancel = async {
            while env.flaky.calls(hangs) == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let at = tokio::time::Instant::now();
            env.cx.cancel.cancel();
            at
        };
        let both = async { tokio::join!(download, cancel) };
        let (done, cancelled) = tokio::time::timeout(Duration::from_secs(3600), both)
            .await
            .unwrap_or_else(|_| panic!("{hangs:?}: the download never ended"));
        assert!(
            matches!(done[0].1, Err(TransferError::Cancelled)),
            "{hangs:?}: {:?}",
            done[0].1
        );
        assert!(cancelled.elapsed() < Duration::from_secs(1), "{hangs:?}");
        assert!(env.dst_tree().is_empty(), "{hangs:?}");
    }
}

#[tokio::test]
async fn zero_length_files_are_not_written_after_a_cancellation() {
    let env = Env::new().await;
    let ups = env
        .upload(&[env.write("empty", b""), env.write("full", b"content")], 1)
        .await;
    ups.assert_all_ok();
    let (up, _) = ups.find("empty");
    let items: Vec<DownloadItem> = (0..40)
        .map(|i| env.item(up, &format!("d/e{i:02}"), LocalExpect::Absent))
        .collect();

    env.cx.cancel.cancel();
    for done in [
        materialize_empties(items.clone(), &env.cx.cancel).await,
        download_group(&env.cx, ups.blob("full"), items.clone()).await,
    ] {
        assert_eq!(done.len(), items.len());
        for (item, result) in &done {
            assert!(
                matches!(result, Err(TransferError::Cancelled)),
                "{}: {result:?}",
                item.rel
            );
        }
    }
    assert!(env.dst_tree().is_empty(), "nothing was created");

    // Without a cancellation: every file, in input order.
    let done = materialize_empties(items.clone(), &CancellationToken::new()).await;
    assert_eq!(done.len(), items.len());
    for ((item, result), wanted) in done.iter().zip(&items) {
        assert_eq!(item.rel, wanted.rel);
        assert_eq!(result.as_ref().unwrap().rel, wanted.rel);
        assert_eq!(fs::read(env.dst.join(&item.rel)).unwrap(), b"");
    }
}

#[tokio::test]
async fn an_empty_batch_closes_the_channel() {
    let env = Env::new().await;
    let ups = env.upload(&[], 4).await;
    assert!(ups.blobs.is_empty() && ups.failed.is_empty());
    // transfers = 0 is taken as 1.
    let ups = env.upload(&[env.write("x", b"x")], 0).await;
    ups.assert_all_ok();
}

// ---------------------------------------------------------------------------------------------
// drafts_for
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn drafts_carry_the_base_effect_of_the_uploaded_record() {
    let env = Env::new().await;
    let sources = [
        env.write("a/one", b"first"),
        env.write("a/two", b"second"),
        env.write("zero", b""),
    ];
    let ups = env.upload(&sources, 1).await;
    ups.assert_all_ok();
    let base = Stamp {
        lamport: 41,
        device: DeviceId([9; 8]),
        idx: 3,
    };
    // Planner-side facts only: `a/one` replaces a known version and gets a base row, `a/two`
    // is new and gets a base row, `zero` gets neither.
    let facts = |path: &str| match path {
        "a/one" => (
            Some(base),
            Some((7, "A/ONE".to_string(), "a/one".to_string())),
        ),
        "a/two" => (None, Some((7, "A/TWO".to_string(), "a/two".to_string()))),
        _ => (None, None),
    };

    let pack = ups.blobs.iter().find(|b| b.blob.is_some()).unwrap();
    let drafts = drafts_for(pack, &facts);
    assert_eq!(drafts.len(), 3);
    assert_eq!(drafts[0], OpDraft::Blob(pack.blob.clone().unwrap()));
    for (draft, (up, (key, stamp))) in drafts[1..].iter().zip(
        pack.files
            .iter()
            .zip([("A/ONE", Some(base)), ("A/TWO", None)]),
    ) {
        let expected = OpDraft::Put {
            path: up.remote_path.clone(),
            entry: up.entry.clone(),
            base: stamp,
            origin: None,
            effect: Some(BaseEffect {
                pair: 7,
                key: key.to_string(),
                rel: up.remote_path.clone(),
                kind: BaseEffectKind::Set {
                    sig: up.sig,
                    hash: up.entry.hash,
                    observed_ns: up.observed_ns,
                    kind: EntryKind::File,
                },
            }),
        };
        assert_eq!(draft, &expected);
    }

    // No blob: no Blob op.
    let empty = ups.blobs.iter().find(|b| b.blob.is_none()).unwrap();
    let drafts = drafts_for(empty, &facts);
    let expected = OpDraft::Put {
        path: "zero".into(),
        entry: empty.files[0].entry.clone(),
        base: None,
        origin: None,
        effect: None,
    };
    assert_eq!(drafts, [expected]);

    // The record is what was observed: the fstat before reading, and a time not after it.
    for up in pack.files.iter().chain(&empty.files) {
        let abs = env.src.join(&up.remote_path);
        assert_eq!(Some(up.sig), lstat_sig(&abs).unwrap());
        assert!(up.observed_ns > up.sig.mtime_ns.min(up.sig.ctime_ns));
        assert!(up.observed_ns <= gclone::util::now_ns());
    }
}

// ---------------------------------------------------------------------------------------------
// Downloads: resume, damage, misplaced blobs
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_cut_download_resumes_from_the_first_unverified_chunk() {
    let env = Env::new().await;
    let data = bytes(3, 5 * MIB as usize);
    let ups = env.one("big", &data).await;
    let blob = ups.blob("big").clone();
    env.rec().forget();

    env.flaky.cut_next_get(1_000_000);
    env.fetch(&ups, "big", "big", LocalExpect::Absent)
        .await
        .unwrap();
    assert_eq!(fs::read(env.dst.join("big")).unwrap(), data);
    // 1,000,000 bytes hold the header and 15 whole chunks; the 16th was not verified.
    let verified = HEADER_LEN as u64 + 15 * SEALED_CHUNK;
    assert_eq!(env.rec().gets(), [0..blob.clen, verified..blob.clen]);

    // A cut between two chunks of another download.
    env.rec().forget();
    env.flaky.cut_next_get(3 * SEALED_CHUNK + 100);
    let (up, _) = ups.find("big");
    let item = env.item(up, "again", LocalExpect::Absent);
    let done = download_group(&env.cx, &blob, vec![item]).await;
    done[0].1.as_ref().unwrap();
    assert_eq!(env.rec().gets().len(), 2);
    assert_eq!(
        env.rec().gets()[1].start,
        HEADER_LEN as u64 + 3 * SEALED_CHUNK
    );
    assert_eq!(fs::read(env.dst.join("again")).unwrap(), data);
    env.assert_no_partials();
}

#[tokio::test(start_paused = true)]
async fn a_download_gives_up_after_the_retries() {
    let env = Env::new().await;
    let data = bytes(3, 300_000);
    let ups = env.one("f", &data).await;

    // DOWNLOAD_RETRIES failures are survived …
    env.flaky
        .fail_next(OpKind::Get, DOWNLOAD_RETRIES, transient);
    env.fetch(&ups, "f", "ok", LocalExpect::Absent)
        .await
        .unwrap();
    assert_eq!(env.rec().gets().len(), DOWNLOAD_RETRIES as usize + 1);
    assert_eq!(fs::read(env.dst.join("ok")).unwrap(), data);

    // … one more is not.
    env.rec().forget();
    env.flaky
        .fail_next(OpKind::Get, DOWNLOAD_RETRIES + 1, transient);
    let err = env
        .fetch(&ups, "f", "bad", LocalExpect::Absent)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TransferError::Backend(BackendError::Transient(_))),
        "{err}"
    );
    assert_eq!(env.rec().gets().len(), DOWNLOAD_RETRIES as usize + 1);
    assert!(!env.dst.join("bad").exists());
    env.assert_no_partials();

    // A quota answer is not retried at all, and fails the whole group.
    env.flaky.clear();
    env.rec().forget();
    env.flaky.fail_next(OpKind::Get, 1, || {
        BackendError::QuotaExceeded(QuotaKind::DailyDownload)
    });
    let err = env
        .fetch(&ups, "f", "quota", LocalExpect::Absent)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        TransferError::Backend(BackendError::QuotaExceeded(QuotaKind::DailyDownload))
    ));
    assert_eq!(env.rec().gets().len(), 1);
}

#[tokio::test]
async fn a_tampered_blob_fails_with_corrupt_and_leaves_nothing() {
    let env = Env::new().await;
    let data = bytes(3, 5 * MIB as usize);
    let ups = env.one("big", &data).await;
    let blob = ups.blob("big").clone();
    let (up, _) = ups.find("big");
    let handle = Handle(blob.file_id.clone());

    // In the header, in the first chunk, in the middle, in the very last tag byte.
    for at in [5, HEADER_LEN as u64 + 1, blob.clen / 2, blob.clen - 1] {
        let checkpoint = env.mem.checkpoint();
        env.mem.tamper(&handle, |v| v[at as usize] ^= 0x01);
        let err = env
            .fetch(&ups, "big", "sub/big", LocalExpect::Absent)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TransferError::Crypto(CryptoError::Corrupt)),
            "byte {at}: {err}"
        );
        assert!(
            !env.dst.join("sub/big").exists(),
            "byte {at}: no target file"
        );
        env.assert_no_partials();
        let err = verify_remote(env.rec(), &env.cx.keys, &blob, &head(up))
            .await
            .unwrap_err();
        assert!(
            matches!(err, TransferError::Crypto(CryptoError::Corrupt)),
            "byte {at}: {err}"
        );
        env.mem.restore(&checkpoint);
    }
    // Untouched again: fine.
    verify_remote(env.rec(), &env.cx.keys, &blob, &head(up))
        .await
        .unwrap();
    env.fetch(&ups, "big", "sub/big", LocalExpect::Absent)
        .await
        .unwrap();

    // The index entry is the authority for the content as well.
    let mut wrong = head(up);
    wrong.entry.hash[0] ^= 1;
    let err = verify_remote(env.rec(), &env.cx.keys, &blob, &wrong)
        .await
        .unwrap_err();
    assert!(matches!(err, TransferError::Verify(_)), "{err}");
    let item = DownloadItem {
        head: wrong,
        root: env.dst.clone(),
        rel: "wrong-hash".into(),
        expect_local: LocalExpect::Absent,
    };
    let done = download_group(&env.cx, &blob, vec![item]).await;
    assert!(matches!(done[0].1, Err(TransferError::Verify(_))));
    assert!(!env.dst.join("wrong-hash").exists());
    env.assert_no_partials();
}

#[tokio::test]
async fn damage_in_a_pack_fails_only_the_member_it_hits() {
    let env = Env::new().await;
    let sources: Vec<UploadSource> = (0..5)
        .map(|i| env.write(&format!("m{i}"), &bytes(i, 100_000)))
        .collect();
    let ups = env.upload(&sources, 1).await;
    ups.assert_all_ok();
    let blob = ups.blob("m0").clone();
    let hit = ups.find("m2").0.entry.loc.clone().unwrap();
    env.mem.tamper(&Handle(blob.file_id.clone()), |v| {
        v[(hit.off + hit.clen / 2) as usize] ^= 0x80
    });

    let items = ups.blobs[0]
        .files
        .iter()
        .map(|f| env.item(f, &f.remote_path, LocalExpect::Absent))
        .collect();
    let done = download_group(&env.cx, &blob, items).await;
    for (i, (item, result)) in done.iter().enumerate() {
        if i == 2 {
            assert!(matches!(
                result,
                Err(TransferError::Crypto(CryptoError::Corrupt))
            ));
            assert!(!env.dst.join(&item.rel).exists());
        } else {
            result.as_ref().unwrap();
            assert_eq!(
                fs::read(env.dst.join(&item.rel)).unwrap(),
                bytes(i as u64, 100_000)
            );
        }
    }
    env.assert_no_partials();
    assert_eq!(env.rec().gets().len(), 1, "one request, damage or not");
}

#[tokio::test]
async fn swapped_and_truncated_blobs_fail() {
    let env = Env::new().await;
    let ups = env
        .upload(
            &[
                env.write("a", &bytes(1, MIB as usize)),
                env.write("b", &bytes(2, MIB as usize)),
            ],
            2,
        )
        .await;
    ups.assert_all_ok();
    let (a, b) = (ups.blob("a").clone(), ups.blob("b").clone());
    assert_eq!(a.clen, b.clen);
    let (up_a, _) = ups.find("a");
    let (ha, hb) = (Handle(a.file_id.clone()), Handle(b.file_id.clone()));

    // Swap: A's object now serves B's bytes — a valid stream of the right length, of this
    // very vault, under the wrong entry.
    let checkpoint = env.mem.checkpoint();
    assert!(env.mem.replace_content(&ha, &hb));
    let err = env
        .fetch(&ups, "a", "a", LocalExpect::Absent)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TransferError::Crypto(CryptoError::Corrupt)),
        "{err}"
    );
    let err = verify_remote(env.rec(), &env.cx.keys, &a, &head(up_a))
        .await
        .unwrap_err();
    assert!(
        matches!(err, TransferError::Crypto(CryptoError::Corrupt)),
        "{err}"
    );
    // A ranged read does not look at the header: it fails on the first chunk it touches.
    let mut sink = Vec::new();
    let err = read_range(
        env.rec(),
        &env.cx.keys,
        &a,
        &head(up_a),
        500_000..500_010,
        &mut sink,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, TransferError::Crypto(CryptoError::Corrupt)),
        "{err}"
    );
    assert!(sink.is_empty(), "no plaintext of an unverified chunk");
    assert!(!env.dst.join("a").exists());
    env.assert_no_partials();
    env.mem.restore(&checkpoint);

    // Truncated: mid-chunk, at a chunk boundary, to the header only, to nothing.
    for keep in [
        a.clen / 2,
        HEADER_LEN as u64 + 4 * SEALED_CHUNK,
        HEADER_LEN as u64,
        0,
    ] {
        env.mem.tamper(&ha, |v| v.truncate(keep as usize));
        let err = env
            .fetch(&ups, "a", "a", LocalExpect::Absent)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TransferError::Verify(_)),
            "kept {keep}: {err}"
        );
        let err = verify_remote(env.rec(), &env.cx.keys, &a, &head(up_a))
            .await
            .unwrap_err();
        assert!(
            matches!(err, TransferError::Verify(_)),
            "kept {keep}: {err}"
        );
        assert!(!env.dst.join("a").exists());
        env.assert_no_partials();
        env.mem.restore(&checkpoint);
    }

    // A longer object (bytes appended) changes nothing: only what the entry names is read.
    env.mem.tamper(&ha, |v| v.extend_from_slice(&[0u8; 100]));
    env.fetch(&ups, "a", "a", LocalExpect::Absent)
        .await
        .unwrap();
    assert_eq!(fs::read(env.dst.join("a")).unwrap(), bytes(1, MIB as usize));
}

#[tokio::test]
async fn entries_that_cannot_be_right_fail_without_a_request() {
    let env = Env::new().await;
    let ups = env.one("f", &bytes(1, 200_000)).await;
    let (up, blob) = ups.find("f");
    let blob = blob.unwrap().clone();
    env.rec().forget();
    let keys = &env.cx.keys;

    let try_all = async |head: Head, blob: &BlobRec| {
        let item = DownloadItem {
            head: head.clone(),
            root: env.dst.clone(),
            rel: "f".into(),
            expect_local: LocalExpect::Absent,
        };
        let mut sink = Vec::new();
        let errors = [
            download_group(&env.cx, blob, vec![item])
                .await
                .remove(0)
                .1
                .unwrap_err(),
            read_range(env.rec(), keys, blob, &head, 0..10, &mut sink)
                .await
                .unwrap_err(),
            verify_remote(env.rec(), keys, blob, &head)
                .await
                .unwrap_err(),
        ];
        assert!(sink.is_empty());
        errors
    };

    // loc.off + loc.clen > blob.clen
    let mut short = blob.clone();
    short.clen -= 1;
    for e in try_all(head(up), &short).await {
        assert!(matches!(e, TransferError::Verify(_)), "{e}");
    }
    let mut beyond = head(up);
    beyond.entry.loc.as_mut().unwrap().off = u64::MAX - 10;
    for e in try_all(beyond, &blob).await {
        assert!(matches!(e, TransferError::Verify(_)), "{e}");
    }
    // A location in another blob.
    let mut other = blob.clone();
    other.id = BlobId([0xee; 16]);
    for e in try_all(head(up), &other).await {
        assert!(matches!(e, TransferError::Verify(_)), "{e}");
    }
    // clen and size disagree.
    let mut odd = head(up);
    odd.entry.size += 1;
    for e in try_all(odd, &blob).await {
        assert!(matches!(e, TransferError::Verify(_)), "{e}");
    }
    // A future writer's stream: "needs a newer gclone", not tampering.
    for (suite, flags) in [(2, 0), (1, 1)] {
        let mut future = head(up);
        let loc = future.entry.loc.as_mut().unwrap();
        (loc.suite, loc.flags) = (suite, flags);
        for e in try_all(future, &blob).await {
            assert!(
                matches!(e, TransferError::Crypto(CryptoError::Unsupported(_))),
                "{e}"
            );
        }
    }
    // A key epoch this device does not hold.
    let mut epoch = head(up);
    epoch.entry.loc.as_mut().unwrap().epoch = 9;
    for e in try_all(epoch, &blob).await {
        assert!(
            matches!(e, TransferError::Crypto(CryptoError::UnknownEpoch(9))),
            "{e}"
        );
    }

    assert!(env.rec().gets().is_empty(), "no request was made");
    assert_eq!(env.mem.counters().get, 0);
    assert!(env.dst_tree().is_empty());
}

#[tokio::test]
async fn a_blob_whose_file_id_is_gone_is_found_by_name() {
    let env = Env::new().await;
    let data = bytes(1, 300_000);
    let ups = env.one("f", &data).await;
    let (up, blob) = ups.find("f");
    let real = blob.unwrap().clone();
    let mut stale = real.clone();
    stale.file_id = "an-id-from-another-account".into();

    // Download, ranged read, verification and locate_blob all take the name.
    let item = env.item(up, "f", LocalExpect::Absent);
    let done = download_group(&env.cx, &stale, vec![item]).await;
    done[0].1.as_ref().unwrap();
    assert_eq!(fs::read(env.dst.join("f")).unwrap(), data);
    let mut out = Vec::new();
    let n = read_range(env.rec(), &env.cx.keys, &stale, &head(up), 10..20, &mut out)
        .await
        .unwrap();
    assert_eq!((n, &out[..]), (10, &data[10..20]));
    verify_remote(env.rec(), &env.cx.keys, &stale, &head(up))
        .await
        .unwrap();
    assert_eq!(
        locate_blob(env.rec(), &stale).await.unwrap().handle.0,
        real.file_id
    );
    assert_eq!(
        locate_blob(env.rec(), &real).await.unwrap().handle.0,
        real.file_id
    );

    // A trashed object is still returned through its id (the caller un-trashes) …
    env.mem.trash(&Handle(real.file_id.clone())).await.unwrap();
    assert!(locate_blob(env.rec(), &real).await.unwrap().trashed);
    // … but a name lookup does not see trashed objects.
    let err = locate_blob(env.rec(), &stale).await.unwrap_err();
    assert!(
        matches!(&err, TransferError::BlobMissing(id) if *id == real.id.hex()),
        "{err}"
    );
    env.mem
        .untrash(&Handle(real.file_id.clone()))
        .await
        .unwrap();

    // Two objects with the name: not "exactly one hit".
    let twin = env.mem.new_ids(1).await.unwrap().remove(0);
    let body = PutBody::Small(env.stored(&real));
    env.mem
        .put(&twin, &env.folder, &blob_name(&real.id), body)
        .await
        .unwrap();
    let err = locate_blob(env.rec(), &stale).await.unwrap_err();
    assert!(matches!(err, TransferError::BlobMissing(_)), "{err}");
    let item = env.item(up, "twin", LocalExpect::Absent);
    let done = download_group(&env.cx, &stale, vec![item]).await;
    assert!(matches!(done[0].1, Err(TransferError::BlobMissing(_))));
    // The recorded id still works.
    env.fetch(&ups, "f", "by-id", LocalExpect::Absent)
        .await
        .unwrap();

    // Nothing left at all.
    assert!(env.mem.hard_delete(&twin));
    assert!(env.mem.hard_delete(&Handle(real.file_id.clone())));
    for rec in [&real, &stale] {
        let err = locate_blob(env.rec(), rec).await.unwrap_err();
        assert!(matches!(err, TransferError::BlobMissing(_)), "{err}");
        let err = verify_remote(env.rec(), &env.cx.keys, rec, &head(up))
            .await
            .unwrap_err();
        assert!(matches!(err, TransferError::BlobMissing(_)), "{err}");
    }
    let err = env
        .fetch(&ups, "f", "gone", LocalExpect::Absent)
        .await
        .unwrap_err();
    assert!(matches!(err, TransferError::BlobMissing(_)), "{err}");
    assert!(!env.dst.join("gone").exists());
    env.assert_no_partials();
}

#[tokio::test]
async fn a_missing_blob_fails_every_item_of_the_group() {
    let env = Env::new().await;
    // Far enough apart for separate requests.
    let sources: Vec<UploadSource> = (0..4)
        .map(|i| env.write(&format!("m{i}"), &bytes(i, 600_000)))
        .collect();
    let ups = env.upload(&sources, 1).await;
    ups.assert_all_ok();
    let blob = ups.blob("m0").clone();
    assert!(env.mem.hard_delete(&Handle(blob.file_id.clone())));
    env.rec().forget();
    let items = [0usize, 2]
        .iter()
        .map(|&i| {
            env.item(
                &ups.blobs[0].files[i],
                &format!("m{i}"),
                LocalExpect::Absent,
            )
        })
        .collect();
    let done = download_group(&env.cx, &blob, items).await;
    assert_eq!(done.len(), 2);
    for (_, result) in &done {
        assert!(matches!(result, Err(TransferError::BlobMissing(_))));
    }
    assert_eq!(
        env.rec().gets().len(),
        1,
        "the second range is not even requested"
    );
    assert!(env.dst_tree().is_empty());
}

#[tokio::test]
async fn a_cancelled_download_leaves_nothing() {
    let env = Env::new().await;
    let ups = env.one("f", &bytes(1, 300_000)).await;
    env.rec().forget();
    env.cx.cancel.cancel();
    let err = env
        .fetch(&ups, "f", "f", LocalExpect::Absent)
        .await
        .unwrap_err();
    assert!(matches!(err, TransferError::Cancelled), "{err}");
    assert!(env.dst_tree().is_empty());
}

// ---------------------------------------------------------------------------------------------
// Ranged reads
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn read_range_equals_the_plaintext_slice() {
    let env = Env::new().await;
    let sizes = [
        ("a-first", 50_000),
        ("b-packed", 300_000),
        ("c-last", 70_000),
        ("d-large", 5 * MIB as usize),
    ];
    let mut plain = BTreeMap::new();
    let mut sources = Vec::new();
    for (i, (name, size)) in sizes.iter().enumerate() {
        let data = bytes(i as u64, *size);
        sources.push(env.write(name, &data));
        plain.insert(*name, data);
    }
    let ups = env.upload(&sources, 2).await;
    ups.assert_all_ok();
    assert_ne!(ups.find("b-packed").0.entry.loc.as_ref().unwrap().off, 0);

    let mut rng = Prng::from_env();
    for name in ["b-packed", "d-large"] {
        let (up, blob) = ups.find(name);
        let (blob, data, loc) = (blob.unwrap(), &plain[name], up.entry.loc.clone().unwrap());
        let size = data.len() as u64;
        let mut ranges = vec![
            0..size,
            0..1,
            size - 1..size,
            CHUNK - 1..CHUNK + 1,
            0..CHUNK,
            CHUNK..2 * CHUNK,
        ];
        for _ in 0..40 {
            let start = rng.below(size);
            let most = if rng.bool() { 200 } else { size - start };
            let len = 1 + rng.below(most);
            ranges.push(start..start + len);
        }
        for range in ranges {
            env.rec().forget();
            let mut out = Vec::new();
            let n = read_range(
                env.rec(),
                &env.cx.keys,
                blob,
                &head(up),
                range.clone(),
                &mut out,
            )
            .await
            .unwrap_or_else(|e| panic!("{name} {range:?}: {e}"));
            let end = range.end.min(size);
            assert_eq!(n, end - range.start, "{name} {range:?}");
            assert_eq!(
                out,
                data[range.start as usize..end as usize],
                "{name} {range:?}"
            );
            // One request for exactly the chunks that hold the range.
            let span = chunk_range(range.start..end, size, CHUNK_LOG2).unwrap();
            assert_eq!(
                env.rec().only_get(),
                loc.off + span.cipher.start..loc.off + span.cipher.end
            );
        }

        // Clamped to the file; nothing to read is no request.
        env.rec().forget();
        let mut out = Vec::new();
        let n = read_range(
            env.rec(),
            &env.cx.keys,
            blob,
            &head(up),
            size - 5..size + 100,
            &mut out,
        )
        .await
        .unwrap();
        assert_eq!((n, &out[..]), (5, &data[data.len() - 5..]));
        env.rec().forget();
        for nothing in [0..0, 7..7, size..size + 10, size + 1..size + 2] {
            let mut out = Vec::new();
            let n = read_range(env.rec(), &env.cx.keys, blob, &head(up), nothing, &mut out)
                .await
                .unwrap();
            assert_eq!((n, out.len()), (0, 0));
        }
        assert!(env.rec().gets().is_empty());
    }

    // A cut in the middle of a ranged read is resumed like any download.
    let (up, blob) = ups.find("d-large");
    env.rec().forget();
    env.flaky.cut_next_get(2 * SEALED_CHUNK + 5);
    let mut out = Vec::new();
    let range = CHUNK + 10..6 * CHUNK;
    read_range(
        env.rec(),
        &env.cx.keys,
        blob.unwrap(),
        &head(up),
        range.clone(),
        &mut out,
    )
    .await
    .unwrap();
    assert_eq!(
        out,
        plain["d-large"][range.start as usize..range.end as usize]
    );
    let gets = env.rec().gets();
    assert_eq!(gets.len(), 2);
    assert_eq!(gets[1].start, gets[0].start + 2 * SEALED_CHUNK);

    // A zero-length file has nothing to read and nothing to fetch.
    let empty = env.one("empty", b"").await;
    let (up, none) = empty.find("empty");
    assert!(none.is_none());
    env.rec().forget();
    let no_blob = ups.blob("a-first");
    let mut out = Vec::new();
    assert_eq!(
        read_range(
            env.rec(),
            &env.cx.keys,
            no_blob,
            &head(up),
            0..100,
            &mut out
        )
        .await
        .unwrap(),
        0
    );
    verify_remote(env.rec(), &env.cx.keys, no_blob, &head(up))
        .await
        .unwrap();
    assert!(env.rec().gets().is_empty());
}

// ---------------------------------------------------------------------------------------------
// Target rules (§5.7 steps 1–3)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_symlinked_ancestor_is_an_unsafe_target() {
    let env = Env::new().await;
    let ups = env.one("f", b"remote content").await;
    let outside = env.dst.parent().unwrap().join("outside");
    fs::create_dir_all(outside.join("deep")).unwrap();
    std::os::unix::fs::symlink(&outside, env.dst.join("link")).unwrap();
    fs::create_dir(env.dst.join("real")).unwrap();
    std::os::unix::fs::symlink(&outside, env.dst.join("real/link")).unwrap();
    fs::write(env.dst.join("file"), b"a file, not a directory").unwrap();
    env.rec().forget();

    for rel in [
        "link/f",
        "link/deep/f",
        "real/link/f",
        "file/f",
        "link/new/dirs/f",
    ] {
        let err = env
            .fetch(&ups, "f", rel, LocalExpect::Absent)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TransferError::UnsafeTarget(_)),
            "{rel}: {err}"
        );
        assert!(matches!(
            check_target_safe(&env.dst, rel),
            Err(TransferError::UnsafeTarget(_))
        ));
    }
    // Paths that are no paths.
    for rel in ["../escape", "a/../../escape", "/abs", "a//b", "", "a/./b"] {
        assert!(
            matches!(
                check_target_safe(&env.dst, rel),
                Err(TransferError::UnsafeTarget(_))
            ),
            "{rel:?}"
        );
        let err = env
            .fetch(&ups, "f", rel, LocalExpect::Absent)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TransferError::UnsafeTarget(_)),
            "{rel:?}: {err}"
        );
    }
    assert!(
        env.rec().gets().is_empty(),
        "nothing is downloaded for an unsafe target"
    );
    assert_eq!(
        fs::read_dir(&outside).unwrap().count(),
        1,
        "nothing was written through the link"
    );
    assert_eq!(fs::read_dir(outside.join("deep")).unwrap().count(), 0);
    assert!(!env.dst.parent().unwrap().join("escape").exists());

    // Real directories — existing or not yet — are fine; a symlink as the target itself is
    // not an ancestor (it is handled by the target rules, below).
    for rel in ["real/f", "real/new/deeper/f", "f"] {
        check_target_safe(&env.dst, rel).unwrap();
    }
    assert!(
        !env.dst.join("real/new").exists(),
        "the check creates nothing"
    );
    env.fetch(&ups, "f", "real/new/deeper/f", LocalExpect::Absent)
        .await
        .unwrap();
    assert_eq!(
        fs::read(env.dst.join("real/new/deeper/f")).unwrap(),
        b"remote content"
    );
}

#[tokio::test]
async fn an_unexpected_directory_is_never_moved_or_replaced() {
    let env = Env::new().await;
    let ups = env.one("f", b"remote content").await;
    fs::create_dir_all(env.dst.join("t/inner")).unwrap();
    fs::write(env.dst.join("t/inner/keep"), b"local").unwrap();
    fs::create_dir(env.dst.join("empty")).unwrap();
    let before = env.dst_tree();

    // A directory nobody expected — full or empty, and whatever the plan expected instead.
    let sig = lstat_sig(&env.dst.join("t/inner/keep")).unwrap().unwrap();
    for (rel, expect) in [
        ("t", LocalExpect::Absent),
        ("t", LocalExpect::File(sig)),
        ("empty", LocalExpect::Absent),
        ("empty", LocalExpect::File(sig)),
        // Expected to be empty, but it is not: rmdir refuses.
        ("t", LocalExpect::EmptyDir),
    ] {
        let err = env.fetch(&ups, "f", rel, expect).await.unwrap_err();
        assert!(
            matches!(err, TransferError::UnsafeTarget(_)),
            "{rel} {expect:?}: {err}"
        );
        assert_eq!(env.dst_tree(), before, "{rel} {expect:?}");
    }
    assert_eq!(fs::read(env.dst.join("t/inner/keep")).unwrap(), b"local");

    // The expected empty directory: rmdir, then the file.
    let got = env
        .fetch(&ups, "f", "empty", LocalExpect::EmptyDir)
        .await
        .unwrap();
    assert_eq!(got.moved_aside, None);
    assert_eq!(fs::read(env.dst.join("empty")).unwrap(), b"remote content");
    // Expected, but gone meanwhile: nothing is in the way.
    env.fetch(&ups, "f", "was-a-dir", LocalExpect::EmptyDir)
        .await
        .unwrap();
    env.assert_no_partials();
}

#[tokio::test]
async fn an_unexpected_file_is_moved_aside_not_overwritten() {
    let env = Env::new().await;
    let ups = env.one("f", b"remote content").await;

    // Nothing was expected, a file is there.
    fs::write(env.dst.join("notes.txt"), b"local work").unwrap();
    let got = env
        .fetch(&ups, "f", "notes.txt", LocalExpect::Absent)
        .await
        .unwrap();
    let aside = got.moved_aside.clone().expect("the local file is kept");
    assert_eq!(fs::read(&aside).unwrap(), b"local work");
    assert_eq!(
        fs::read(env.dst.join("notes.txt")).unwrap(),
        b"remote content"
    );
    assert_eq!(aside.parent(), Some(env.dst.as_path()));
    let name = aside.file_name().unwrap().to_str().unwrap();
    assert!(
        name.starts_with("notes.conflict-local-") && name.ends_with("Z.txt"),
        "{name}"
    );
    assert_eq!(
        Some(got.sig),
        lstat_sig(&env.dst.join("notes.txt")).unwrap()
    );

    // The expected file, unchanged: replaced, nothing kept.
    let sig = lstat_sig(&env.dst.join("notes.txt")).unwrap().unwrap();
    fs::write(env.src.join("f"), b"remote content, second version").unwrap();
    let ups2 = env
        .upload(
            &[UploadSource {
                abs: env.src.join("f"),
                remote_path: "f".into(),
            }],
            1,
        )
        .await;
    let got = env
        .fetch(&ups2, "f", "notes.txt", LocalExpect::File(sig))
        .await
        .unwrap();
    assert_eq!(got.moved_aside, None);
    assert_eq!(
        fs::read(env.dst.join("notes.txt")).unwrap(),
        b"remote content, second version"
    );
    assert_eq!(
        env.dst_tree().len(),
        2,
        "the replaced file is gone, the earlier conflict copy stays"
    );

    // The expected file, edited since the plan was made: a different signature → kept.
    let planned = lstat_sig(&env.dst.join("notes.txt")).unwrap().unwrap();
    fs::write(env.dst.join("notes.txt"), b"edited after the scan").unwrap();
    assert_ne!(
        Some(planned),
        lstat_sig(&env.dst.join("notes.txt")).unwrap()
    );
    let got = env
        .fetch(&ups, "f", "notes.txt", LocalExpect::File(planned))
        .await
        .unwrap();
    let second = got.moved_aside.expect("the edited file is kept");
    assert_ne!(second, aside);
    assert_eq!(fs::read(&second).unwrap(), b"edited after the scan");
    assert_eq!(
        fs::read(&aside).unwrap(),
        b"local work",
        "an earlier conflict copy is not replaced"
    );
    assert_eq!(
        fs::read(env.dst.join("notes.txt")).unwrap(),
        b"remote content"
    );

    // Same content, same size, but only the mode differs: still not the expected file.
    let mut other = lstat_sig(&env.dst.join("notes.txt")).unwrap().unwrap();
    other.mode ^= 0o100;
    let got = env
        .fetch(&ups, "f", "notes.txt", LocalExpect::File(other))
        .await
        .unwrap();
    assert!(got.moved_aside.is_some());

    // An empty directory was expected, a file is there: unexpected, kept.
    let got = env
        .fetch(&ups, "f", "notes.txt", LocalExpect::EmptyDir)
        .await
        .unwrap();
    assert!(got.moved_aside.is_some());

    // A symlink at the target is moved aside as a link; its destination is not touched.
    let victim = env.dst.parent().unwrap().join("victim");
    fs::write(&victim, b"do not touch").unwrap();
    std::os::unix::fs::symlink(&victim, env.dst.join("ln")).unwrap();
    let got = env
        .fetch(&ups, "f", "ln", LocalExpect::Absent)
        .await
        .unwrap();
    let kept = got.moved_aside.unwrap();
    assert!(kept.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(fs::read(&victim).unwrap(), b"do not touch");
    assert!(env.dst.join("ln").symlink_metadata().unwrap().is_file());
    assert_eq!(fs::read(env.dst.join("ln")).unwrap(), b"remote content");
    env.assert_no_partials();
}

#[tokio::test]
async fn zero_length_files_follow_the_same_target_rules() {
    let env = Env::new().await;
    let ups = env.one("empty", b"").await;
    let (up, none) = ups.find("empty");
    assert!(none.is_none());
    let item = |rel: &str, expect| env.item(up, rel, expect);

    let got = materialize_empty(&item("new/dir/empty", LocalExpect::Absent))
        .await
        .unwrap();
    let target = env.dst.join("new/dir/empty");
    assert_eq!(fs::read(&target).unwrap(), b"");
    assert_eq!(Some(got.sig), lstat_sig(&target).unwrap());
    assert_eq!(got.sig.mtime_ns, up.sig.mtime_ns);
    assert_eq!(
        (got.rel.as_str(), &got.moved_aside),
        ("new/dir/empty", &None)
    );

    fs::write(env.dst.join("taken"), b"local").unwrap();
    let got = materialize_empty(&item("taken", LocalExpect::Absent))
        .await
        .unwrap();
    assert_eq!(fs::read(got.moved_aside.unwrap()).unwrap(), b"local");
    assert_eq!(fs::read(env.dst.join("taken")).unwrap(), b"");

    fs::create_dir(env.dst.join("d")).unwrap();
    let err = materialize_empty(&item("d", LocalExpect::Absent))
        .await
        .unwrap_err();
    assert!(matches!(err, TransferError::UnsafeTarget(_)), "{err}");
    materialize_empty(&item("d", LocalExpect::EmptyDir))
        .await
        .unwrap();
    assert!(env.dst.join("d").symlink_metadata().unwrap().is_file());

    std::os::unix::fs::symlink(env.dst.join("new"), env.dst.join("link")).unwrap();
    let err = materialize_empty(&item("link/dir/x", LocalExpect::Absent))
        .await
        .unwrap_err();
    assert!(matches!(err, TransferError::UnsafeTarget(_)), "{err}");

    // Only a zero-length file entry is materialized this way.
    let full = env.one("full", b"not empty").await;
    let wrong = env.item(full.find("full").0, "full", LocalExpect::Absent);
    let err = materialize_empty(&wrong).await.unwrap_err();
    assert!(matches!(err, TransferError::Verify(_)), "{err}");

    // In a group they need no request; the blob record is not even looked at.
    env.rec().forget();
    let done = download_group(
        &env.cx,
        full.blob("full"),
        vec![item("in-group", LocalExpect::Absent)],
    )
    .await;
    done[0].1.as_ref().unwrap();
    assert!(env.rec().gets().is_empty());
    assert_eq!(fs::read(env.dst.join("in-group")).unwrap(), b"");
    env.assert_no_partials();
}

#[tokio::test]
async fn a_differently_spelled_entry_is_a_collision_where_the_file_system_folds() {
    let env = Env::new().await;
    fs::write(env.dst.join("CaseProbe"), b"").unwrap();
    let folds = env.dst.join("caseprobe").exists();
    fs::remove_file(env.dst.join("CaseProbe")).unwrap();
    let ups = env.one("f", b"remote content").await;
    fs::write(env.dst.join("Readme.TXT"), b"local spelling").unwrap();

    let result = env
        .fetch(&ups, "f", "readme.txt", LocalExpect::Absent)
        .await;
    if folds {
        // The entry in the way has other name bytes: never alternate between two spellings.
        let err = result.unwrap_err();
        assert!(
            matches!(&err, TransferError::TargetCollision(rel) if rel == "readme.txt"),
            "{err}"
        );
        assert_eq!(
            env.dst_tree(),
            ["Readme.TXT"],
            "nothing moved, nothing written"
        );
        assert_eq!(
            fs::read(env.dst.join("Readme.TXT")).unwrap(),
            b"local spelling"
        );
    } else {
        // Two names, two files.
        assert_eq!(result.unwrap().moved_aside, None);
        assert_eq!(env.dst_tree(), ["Readme.TXT", "readme.txt"]);
    }
    env.assert_no_partials();
}

#[tokio::test]
async fn several_paths_with_one_content_are_fetched_once() {
    let env = Env::new().await;
    let data = bytes(1, 250_000);
    let ups = env
        .upload(&[env.write("a", &bytes(0, 1000)), env.write("b", &data)], 1)
        .await;
    ups.assert_all_ok();
    let (up, blob) = ups.find("b");
    let loc = up.entry.loc.clone().unwrap();
    fs::create_dir_all(env.dst.join("blocked")).unwrap();
    env.rec().forget();

    // Three index entries that share the location (the planner's Reuse), with their own
    // mtime and mode; one of them cannot be written.
    let mut exec = up.clone();
    exec.entry.exec = true;
    exec.entry.mtime_ns = 1_500_000_000_123_456_789;
    let items = vec![
        env.item(up, "copy1", LocalExpect::Absent),
        env.item(up, "blocked", LocalExpect::Absent),
        env.item(&exec, "sub/copy2", LocalExpect::Absent),
    ];
    let done = download_group(&env.cx, blob.unwrap(), items).await;
    assert_eq!(env.rec().only_get(), loc.off..loc.off + loc.clen);
    done[0].1.as_ref().unwrap();
    assert!(matches!(done[1].1, Err(TransferError::UnsafeTarget(_))));
    let second = done[2].1.as_ref().unwrap();
    assert_eq!(fs::read(env.dst.join("copy1")).unwrap(), data);
    assert_eq!(fs::read(env.dst.join("sub/copy2")).unwrap(), data);
    assert_eq!(second.sig.mtime_ns, 1_500_000_000_123_456_789);
    assert!(second.sig.is_exec());
    assert!(!done[0].1.as_ref().unwrap().sig.is_exec());
    env.assert_no_partials();
}

/// Descriptors this process has open right now (`/dev/fd` exists on macOS and Linux).
fn open_descriptors() -> usize {
    fs::read_dir("/dev/fd").map_or(0, |entries| entries.count())
}

/// The planner's `Reuse` gives every path with known content the same location, so a tree
/// with a few hundred identical files (licence files, `INSTALLER`, templates) is one member
/// with as many targets. They are written one after another: the number of files open at a
/// time must not grow with them (the soft limit is 256 on macOS, 1024 on most Linux systems).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn many_paths_with_one_content_do_not_exhaust_the_descriptors() {
    let env = Env::new().await;
    let small = bytes(1, 100);
    // A blob of its own, too large to wait in memory: streamed to one file, copied from it.
    let large = bytes(2, PACK_MEMBER_MAX as usize + 4097);
    let ups = env
        .upload(&[env.write("large", &large), env.write("small", &small)], 1)
        .await;
    ups.assert_all_ok();

    let baseline = open_descriptors();
    let stop = Arc::new(AtomicBool::new(false));
    let watcher = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut peak = 0;
            while !stop.load(Ordering::Relaxed) {
                peak = peak.max(open_descriptors());
                std::thread::sleep(Duration::from_micros(200));
            }
            peak
        })
    };
    for (name, data, paths) in [("small", &small, 320), ("large", &large, 24)] {
        let (up, blob) = ups.find(name);
        let items: Vec<DownloadItem> = (0..paths)
            .map(|i| {
                let rel = format!("{name}/d{}/f{i:03}", i % 5);
                env.item(up, &rel, LocalExpect::Absent)
            })
            .collect();
        env.rec().forget();
        let done = download_group(&env.cx, blob.unwrap(), items).await;
        assert_eq!(done.len(), paths);
        assert_eq!(env.rec().gets().len(), 1, "{name}: fetched once");
        for (item, result) in &done {
            let got = result
                .as_ref()
                .unwrap_or_else(|e| panic!("{}: {e}", item.rel));
            assert_eq!(got.rel, item.rel);
            assert_eq!(&fs::read(env.dst.join(&item.rel)).unwrap(), data);
            assert_eq!(Some(got.sig), lstat_sig(&env.dst.join(&item.rel)).unwrap());
        }
    }
    stop.store(true, Ordering::Relaxed);
    let peak = watcher.join().unwrap();
    // Other tests of this binary open files at the same time; 320 partial files open at once
    // are far beyond that noise.
    assert!(
        peak < baseline + 200,
        "up to {peak} descriptors were open ({baseline} before)"
    );
    env.assert_no_partials();
}

#[tokio::test]
async fn the_downloaded_signature_is_fresh_and_private_until_renamed() {
    let env = Env::new().await;
    let ups = env.one("f", &bytes(1, 100_000)).await;
    let before = gclone::util::now_ns();
    let got = env
        .fetch(&ups, "f", "f", LocalExpect::Absent)
        .await
        .unwrap();
    assert!(got.observed_ns >= before && got.observed_ns <= gclone::util::now_ns());
    assert_eq!(got.sig.size, 100_000);
    // 0644 under the usual umasks; in any case nothing beyond it.
    assert_eq!(got.sig.mode & 0o777 & !0o644, 0);
    assert_eq!(got.sig.mode & 0o600, 0o600);

    // move_aside on its own: the conflict name of §5.1, never an existing name.
    let target = env.dst.join("f");
    let now_ms = 1_794_000_000_000;
    let stamp = gclone::util::format_utc_compact(now_ms);
    let aside = move_aside(&target, now_ms).unwrap();
    assert!(!target.exists());
    assert_eq!(aside, env.dst.join(format!("f.conflict-local-{stamp}")));
    fs::write(&target, b"again").unwrap();
    let second = move_aside(&target, now_ms).unwrap();
    assert_eq!(second, env.dst.join(format!("f.conflict-local-{stamp}-2")));
    assert_eq!(fs::read(&aside).unwrap().len(), 100_000);
    assert!(move_aside(&target, 0).is_err(), "nothing to move");
}

#[tokio::test]
async fn a_download_keeps_the_permission_bits_of_the_file_it_replaces() {
    let env = Env::new().await;
    let ups = env.one("f", &bytes(3, 50_000)).await;
    let empty = env.one("empty", b"").await;
    let (up, blob) = ups.find("f");
    let mut exec = up.clone();
    exec.entry.exec = true;
    let mode = |rel: &str| {
        fs::metadata(env.dst.join(rel))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    let chmod = |rel: &str, mode: u32| {
        fs::set_permissions(env.dst.join(rel), fs::Permissions::from_mode(mode)).unwrap();
    };
    let expected = |rel: &str| LocalExpect::File(lstat_sig(&env.dst.join(rel)).unwrap().unwrap());

    // The expected file is replaced: a private file stays private, whatever the umask.
    fs::write(env.dst.join("secret"), b"old").unwrap();
    chmod("secret", 0o600);
    let got = env
        .fetch(&ups, "f", "secret", expected("secret"))
        .await
        .unwrap();
    assert_eq!(got.moved_aside, None);
    assert_eq!(fs::read(env.dst.join("secret")).unwrap().len(), 50_000);
    assert_eq!(mode("secret"), 0o600);
    assert_eq!(got.sig.mode & 0o7777, 0o600);

    // The exec flag is applied on top of the kept bits: x follows r, nothing else widens.
    for (before, exec_flag, after) in [
        (0o600, true, 0o700),
        (0o640, true, 0o750),
        (0o755, false, 0o644),
        (0o700, false, 0o600),
        (0o664, false, 0o664),
        (0o4750, true, 0o750),
    ] {
        chmod("secret", before);
        let item = env.item(
            if exec_flag { &exec } else { up },
            "secret",
            expected("secret"),
        );
        let done = download_group(&env.cx, blob.unwrap(), vec![item]).await;
        done[0].1.as_ref().unwrap();
        assert_eq!(mode("secret"), after, "{before:o} exec={exec_flag}");
    }

    // A file that is moved aside (row 7, or a concurrent change) keeps its bits under the
    // conflict name, and the download at its path is as private as it was.
    fs::write(env.dst.join("mine"), b"unsynced").unwrap();
    chmod("mine", 0o600);
    let got = env
        .fetch(&ups, "f", "mine", LocalExpect::Absent)
        .await
        .unwrap();
    let aside = got.moved_aside.expect("moved aside");
    assert_eq!(fs::read(&aside).unwrap(), b"unsynced");
    assert_eq!(
        fs::metadata(&aside).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(mode("mine"), 0o600);

    // Zero-length files go the same way.
    fs::write(env.dst.join("empty"), b"x").unwrap();
    chmod("empty", 0o600);
    materialize_empty(&env.item(empty.find("empty").0, "empty", expected("empty")))
        .await
        .unwrap();
    assert_eq!(fs::read(env.dst.join("empty")).unwrap(), b"");
    assert_eq!(mode("empty"), 0o600);

    // A new file: 0644 / 0755 under the umask, as before.
    env.fetch(&ups, "f", "new", LocalExpect::Absent)
        .await
        .unwrap();
    assert_eq!(mode("new") & !0o644, 0);
    assert_eq!(mode("new") & 0o600, 0o600);
    env.assert_no_partials();
}

#[test]
fn stat_signatures_distinguish_what_the_rules_need() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f");
    fs::write(&path, b"one").unwrap();
    let a: StatSig = lstat_sig(&path).unwrap().unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let b = lstat_sig(&path).unwrap().unwrap();
    assert_ne!(a, b);
    assert!(b.is_exec() && !a.is_exec());
    assert_eq!(lstat_sig(&dir.path().join("missing")).unwrap(), None);
}

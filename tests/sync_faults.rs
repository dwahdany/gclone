//! Fault injection for the sync engine (SPEC §12.1 WP6, §13 item 6): a run killed between
//! the blob put and the commit, failing and skipped transfers, quotas, a stuck outbox,
//! cancellation, list lag.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use gclone::backend::{
    Backend, ByteStream, Flaky, Handle, MemBackend, ObjMeta, OpKind, PutBody, Quota,
};
use gclone::consts::{LEDGER_WARN, MIB};
use gclone::crypto::{KdfParams, Keyring, MasterKey, Passphrase};
use gclone::error::{BackendError, IndexError, QuotaKind, SyncError, exit_code};
use gclone::format::{KeyfilePayload, seal_keyfile};
use gclone::index::{CreateParams, OpenParams, Vault, VaultHandles};
use gclone::state::{Db, LedgerDir};
use gclone::sync::{self, Direction, Mode, SkipReason, Summary, SyncOpts, SyncRequest};
use gclone::ui::Ui;
use tokio_util::sync::CancellationToken;

use Direction::{Down, Up};

const VAULT: [u8; 16] = [0x52; 16];

fn pattern(seed: u32, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    blake3::Hasher::new()
        .update(&seed.to_le_bytes())
        .finalize_xof()
        .fill(&mut buf);
    buf
}

/// One "Drive"; every device wraps it in its own fault injector.
struct Net {
    mem: MemBackend,
    keys: Keyring,
    handles: VaultHandles,
    tmp: tempfile::TempDir,
    devices: std::sync::atomic::AtomicU8,
}

struct Dev<B: Backend> {
    vault: Vault<B>,
    db: Db,
    root: PathBuf,
    n: u8,
}

impl Net {
    async fn new() -> Net {
        let mem = MemBackend::new();
        let tmp = tempfile::tempdir().unwrap();
        let keys = Keyring::new(VAULT, vec![(1, MasterKey::generate())], 1).unwrap();
        let keyfile = seal_keyfile(
            &KeyfilePayload::from_keyring(&keys, 1, "creator", mem.now_ms()),
            &Passphrase::from_input("correct horse battery staple"),
            KdfParams {
                m_kib: 8192,
                t: 1,
                p: 1,
            },
        )
        .unwrap();
        let (_creator, found) = Vault::create(
            Arc::new(mem.clone()),
            Db::open_in_memory().unwrap(),
            keys.clone(),
            CreateParams {
                vault_id: VAULT,
                vault_name: "gclone".into(),
                device_name: "creator".into(),
                cache_dir: tmp.path().join("cache-creator"),
                machine_fp: Some([0xff; 32]),
                keyfile,
            },
        )
        .await
        .unwrap();
        Net {
            mem,
            keys,
            handles: found.handles,
            tmp,
            devices: 0.into(),
        }
    }

    /// A new device on `backend` with an empty sync root.
    async fn device<B: Backend>(&self, backend: B) -> Dev<B> {
        let n = self.devices.fetch_add(1, Ordering::Relaxed);
        let root = self.tmp.path().join(format!("root{n}"));
        std::fs::create_dir(&root).unwrap();
        self.open(backend, Db::open_in_memory().unwrap(), n, root)
            .await
    }

    /// (Re-)opens a device on its state: what a new process does.
    async fn open<B: Backend>(&self, backend: B, db: Db, n: u8, root: PathBuf) -> Dev<B> {
        let vault = Vault::open(
            Arc::new(backend),
            db.clone(),
            self.keys.clone(),
            OpenParams {
                vault_id: VAULT,
                handles: self.handles.clone(),
                device_name: format!("dev{n}"),
                cache_dir: self.tmp.path().join(format!("cache{n}")),
                machine_fp: Some([n; 32]),
            },
        )
        .await
        .unwrap();
        Dev { vault, db, root, n }
    }

    async fn flaky(&self) -> (Dev<Flaky<MemBackend>>, Flaky<MemBackend>) {
        let flaky = Flaky::new(self.mem.clone());
        let dev = self.device(flaky.clone()).await;
        dev.vault.refresh().await.unwrap();
        (dev, flaky)
    }

    async fn plain(&self) -> Dev<MemBackend> {
        let dev = self.device(self.mem.clone()).await;
        dev.vault.refresh().await.unwrap();
        dev
    }

    /// Objects in the vault's data folders (blobs), trashed ones included.
    fn blobs(&self) -> Vec<ObjMeta> {
        let folders: Vec<Handle> = self
            .mem
            .all_objects()
            .into_iter()
            .filter(|m| m.is_folder && m.parent == self.handles.data)
            .map(|m| m.handle)
            .collect();
        self.mem
            .all_objects()
            .into_iter()
            .filter(|m| !m.is_folder && folders.contains(&m.parent))
            .collect()
    }
}

impl<B: Backend> Dev<B> {
    fn req(&self, direction: Direction) -> SyncRequest {
        SyncRequest {
            direction,
            mode: Mode::Sync,
            local_root: self.root.clone(),
            remote_prefix: String::new(),
            own_dirs: Vec::new(),
            opts: SyncOpts {
                dry_run: false,
                checksum: false,
                force: false,
                excludes: Vec::new(),
                max_delete: None,
                assume_yes: false,
                // One blob at a time: the order of puts is the order of paths.
                transfers: 1,
                reset_pair: false,
                keep_pair: false,
            },
        }
    }

    /// The settle sequence of §5.8: refresh → commit → resolve_conflicts.
    async fn settle(&self) {
        self.vault.refresh().await.unwrap();
        self.vault.commit().await.unwrap();
        self.vault.resolve_conflicts().await.unwrap();
    }

    async fn run(&self, direction: Direction) -> Result<Summary, SyncError> {
        let req = self.req(direction);
        sync::run(&self.vault, &req, &Ui::silent(), CancellationToken::new()).await
    }

    /// settle → run → finish_mutation.
    async fn cmd(&self, direction: Direction) -> Result<Summary, SyncError> {
        self.settle().await;
        let summary = self.run(direction).await?;
        self.vault.finish_mutation().await.unwrap();
        Ok(summary)
    }

    fn write(&self, rel: &str, data: &[u8]) {
        let p = self.root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    fn tree(&self) -> BTreeMap<String, Vec<u8>> {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string();
                    out.insert(rel, std::fs::read(&path).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.root, &self.root, &mut out);
        out
    }

    fn remote_paths(&self) -> Vec<String> {
        self.vault
            .walk("")
            .unwrap()
            .into_iter()
            .map(|h| h.path)
            .collect()
    }
}

fn quota() -> BackendError {
    BackendError::QuotaExceeded(QuotaKind::StorageFull)
}

fn rate_limited() -> BackendError {
    BackendError::RateLimited
}

fn fatal() -> BackendError {
    BackendError::Fatal {
        status: 400,
        reason: "badRequest".into(),
        message: "injected".into(),
    }
}

fn code(e: SyncError) -> i32 {
    exit_code(&e.into())
}

// ---------------------------------------------------------------------------------------------
// A backend whose blob puts can be made to hang: a process killed mid-run
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Gate {
    inner: MemBackend,
    /// Blob puts let through before the gate closes; negative = open.
    allowed: Arc<AtomicI64>,
    blob_puts: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
}

impl Gate {
    fn new(inner: MemBackend, allowed: i64) -> Gate {
        Gate {
            inner,
            allowed: Arc::new(AtomicI64::new(allowed)),
            blob_puts: Arc::default(),
            closed: Arc::default(),
        }
    }
}

fn is_blob_name(name: &str) -> bool {
    name.len() == 32 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Backend for Gate {
    async fn new_ids(&self, n: usize) -> Result<Vec<Handle>, BackendError> {
        self.inner.new_ids(n).await
    }
    async fn create_folder(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
    ) -> Result<(), BackendError> {
        self.inner.create_folder(id, parent, name).await
    }
    async fn put(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
        body: PutBody,
    ) -> Result<ObjMeta, BackendError> {
        if is_blob_name(name) {
            let n = self.blob_puts.fetch_add(1, Ordering::SeqCst) as i64;
            let allowed = self.allowed.load(Ordering::SeqCst);
            if allowed >= 0 && n >= allowed {
                self.closed.store(true, Ordering::SeqCst);
                std::future::pending::<()>().await;
            }
        }
        self.inner.put(id, parent, name, body).await
    }
    async fn get(
        &self,
        h: &Handle,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<ByteStream, BackendError> {
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

/// Runs an upload on a device whose second blob put hangs, and drops the run once the first
/// blob's ops are staged: the state a killed process leaves behind. Returns the device's
/// state for the "next process".
async fn killed_after_first_blob(net: &Net) -> (Db, u8, PathBuf, Gate) {
    let gate = Gate::new(net.mem.clone(), 1);
    let dev = net.device(gate.clone()).await;
    dev.write("a.bin", &pattern(1, (MIB + 100) as usize));
    dev.write("b.bin", &pattern(2, (MIB + 200) as usize));
    dev.write("c.bin", &pattern(3, (MIB + 300) as usize));
    dev.settle().await;
    {
        let run = dev.run(Up);
        tokio::pin!(run);
        let staged = async {
            loop {
                let pending = dev.db.pending_count().unwrap();
                if gate.closed.load(Ordering::SeqCst) && pending > 0 {
                    return pending;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        };
        tokio::select! {
            result = &mut run => panic!("the run finished: {result:?}"),
            pending = staged => assert_eq!(pending, 2, "the first blob and its Put are staged"),
        }
        // Dropped here: nothing after the staging ran — no commit, no segment.
    }
    assert!(dev.remote_paths().is_empty(), "nothing was published");
    assert_eq!(
        net.blobs().len(),
        1,
        "one blob is stored, referenced by nothing published"
    );
    gate.allowed.store(-1, Ordering::SeqCst);
    let Dev { db, n, root, vault } = dev;
    drop(vault);
    (db, n, root, gate)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_killed_between_blob_put_and_commit_uploads_nothing_twice() {
    let net = Net::new().await;
    let (db, n, root, gate) = killed_after_first_blob(&net).await;

    // The next process: settle publishes the leftover ops before anything is planned.
    let dev = net.open(gate.clone(), db, n, root).await;
    dev.settle().await;
    assert_eq!(dev.db.pending_count().unwrap(), 0);
    assert_eq!(dev.remote_paths(), ["a.bin"]);
    let summary = dev.run(Up).await.unwrap();
    dev.vault.finish_mutation().await.unwrap();
    assert!(summary.failed.is_empty() && summary.skipped.is_empty());
    assert_eq!(summary.uploaded, 2, "a.bin is not uploaded again");
    assert_eq!(net.blobs().len(), 3, "one blob per file, none twice");
    assert_eq!(dev.remote_paths(), ["a.bin", "b.bin", "c.bin"]);
    assert!(dev.vault.conflicts().unwrap().is_empty());

    // Converged: another device gets exactly the three files, no conflict copy.
    let other = net.plain().await;
    let down = other.cmd(Down).await.unwrap();
    assert_eq!(down.downloaded, 3);
    assert_eq!(other.tree(), dev.tree());
    let again = dev.cmd(Up).await.unwrap();
    assert_eq!(
        (again.uploaded, again.reused, again.deleted_remote),
        (0, 0, 0)
    );
    assert!(
        other
            .remote_paths()
            .iter()
            .all(|p| !p.contains(".conflict-"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_leftover_put_followed_by_a_planned_delete_deletes_the_file() {
    let net = Net::new().await;
    let (db, n, root, gate) = killed_after_first_blob(&net).await;
    // Before the next run the user deletes the file whose Put is still staged.
    std::fs::remove_file(root.join("a.bin")).unwrap();

    let dev = net.open(gate, db, n, root).await;
    dev.settle().await;
    // The leftover Put is published first (with its base row) …
    assert_eq!(dev.remote_paths(), ["a.bin"]);
    let summary = dev.run(Up).await.unwrap();
    dev.vault.finish_mutation().await.unwrap();
    // … so the planner sees "deleted locally" and deletes it, instead of resurrecting it.
    assert_eq!((summary.uploaded, summary.deleted_remote), (2, 1));
    assert_eq!(dev.remote_paths(), ["b.bin", "c.bin"]);
    assert_eq!(dev.vault.removed_versions("a.bin").unwrap().len(), 1);
    let other = net.plain().await;
    other.cmd(Down).await.unwrap();
    assert_eq!(other.tree(), dev.tree());
}

// ---------------------------------------------------------------------------------------------
// Failures and skips
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_upload_suppresses_deletes() {
    let net = Net::new().await;
    let (dev, flaky) = net.flaky().await;
    dev.write("keep", b"k");
    dev.write("gone", b"g");
    dev.cmd(Up).await.unwrap();

    std::fs::remove_file(dev.root.join("gone")).unwrap();
    dev.write("new.bin", &pattern(1, (MIB + 1) as usize));
    dev.write("ok.txt", b"small and fine");
    dev.settle().await;
    // The first put of the run is new.bin's blob; a fatal error is not retried.
    flaky.fail_nth(OpKind::Put, 1, fatal);
    let summary = dev.run(Up).await.unwrap();
    dev.vault.finish_mutation().await.unwrap();
    assert_eq!(summary.failed.len(), 1, "{:?}", summary.failed);
    assert_eq!(summary.failed[0].0, "new.bin");
    assert!(summary.deletes_suppressed);
    assert_eq!((summary.uploaded, summary.deleted_remote), (1, 0));
    assert_eq!(summary.exit_code(), 6);
    // What completed is committed; the delete did not happen.
    assert_eq!(dev.remote_paths(), ["gone", "keep", "ok.txt"]);
    assert_eq!(dev.db.pending_count().unwrap(), 0);

    // The next run finishes the job.
    let summary = dev.cmd(Up).await.unwrap();
    assert!(summary.failed.is_empty() && !summary.deletes_suppressed);
    assert_eq!((summary.uploaded, summary.deleted_remote), (1, 1));
    assert_eq!(dev.remote_paths(), ["keep", "new.bin", "ok.txt"]);
}

/// §5.7: a file that is gone when the upload gets to it changed during the run like one that
/// was rewritten — a skip, which does not hold back the deletes of the run. (A build or an
/// editor removing its temporary files is the everyday case.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_that_vanished_after_the_scan_is_skipped_and_deletes_go_ahead() {
    let net = Net::new().await;
    let (dev, flaky) = net.flaky().await;
    dev.write("keep", b"k");
    dev.write("gone", b"g");
    dev.cmd(Up).await.unwrap();

    std::fs::remove_file(dev.root.join("gone")).unwrap();
    dev.write("a.bin", &pattern(1, (5 * MIB) as usize));
    dev.write("b.bin", &pattern(2, (MIB + 2) as usize));
    dev.write("c.tmp", &pattern(3, (MIB + 3) as usize));
    dev.settle().await;
    // One transfer at a time, in path order, and the pipeline opens at most one source beyond
    // the one in flight: while `a.bin` goes up, `c.tmp` was scanned and planned but not opened.
    let vanishing = dev.root.join("c.tmp");
    flaky.on_put_progress(
        0,
        Box::new(move || std::fs::remove_file(&vanishing).unwrap()),
    );
    let summary = dev.run(Up).await.unwrap();
    dev.vault.finish_mutation().await.unwrap();
    assert_eq!(
        summary.skipped,
        [("c.tmp".to_string(), SkipReason::ChangedDuringUpload)]
    );
    assert!(summary.failed.is_empty(), "{:?}", summary.failed);
    assert!(!summary.deletes_suppressed);
    assert_eq!((summary.uploaded, summary.deleted_remote), (2, 1));
    assert_eq!(dev.remote_paths(), ["a.bin", "b.bin", "keep"]);
    assert_eq!(summary.exit_code(), 6);

    // The next run has nothing left to do.
    let summary = dev.cmd(Up).await.unwrap();
    assert_eq!((summary.uploaded, summary.deleted_remote), (0, 0));
    assert_eq!(summary.exit_code(), 0);
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
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            file.write_all(&[0xcc]).unwrap();
            keep_changing(&again, path, times - 1);
        }),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_time_skip_does_not_suppress_deletes() {
    let net = Net::new().await;
    let (dev, flaky) = net.flaky().await;
    dev.write("keep", b"k");
    dev.write("gone", b"g");
    dev.cmd(Up).await.unwrap();

    std::fs::remove_file(dev.root.join("gone")).unwrap();
    // A file that changes during every attempt to read it (two parts, so that the final
    // fstat comes after the hook).
    dev.write("moving.bin", &pattern(2, (17 * MIB) as usize));
    dev.settle().await;
    keep_changing(&flaky, dev.root.join("moving.bin"), 3);
    let summary = dev.run(Up).await.unwrap();
    dev.vault.finish_mutation().await.unwrap();
    assert_eq!(
        summary.skipped,
        [("moving.bin".to_string(), SkipReason::ChangedDuringUpload)]
    );
    assert!(summary.failed.is_empty(), "a skip is not a failure");
    assert!(!summary.deletes_suppressed);
    assert_eq!((summary.uploaded, summary.deleted_remote), (0, 1));
    assert_eq!(dev.remote_paths(), ["keep"]);
    assert_eq!(summary.exit_code(), 6);

    // Left alone, the file goes up with the next run.
    let summary = dev.cmd(Up).await.unwrap();
    assert_eq!(summary.uploaded, 1);
    assert_eq!(dev.remote_paths(), ["keep", "moving.bin"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_download_suppresses_local_deletes_and_keeps_what_finished() {
    let net = Net::new().await;
    let a = net.plain().await;
    a.write("stays", b"s");
    a.write("gone", b"g");
    a.cmd(Up).await.unwrap();
    let b = net.plain().await;
    b.cmd(Down).await.unwrap();

    a.write("damaged.bin", &pattern(1, (MIB + 1) as usize));
    a.write("fine.bin", &pattern(2, (MIB + 2) as usize));
    std::fs::remove_file(a.root.join("gone")).unwrap();
    a.cmd(Up).await.unwrap();
    let head = a.vault.head("damaged.bin").unwrap().unwrap();
    let blob = a
        .vault
        .blob(&head.entry.loc.unwrap().blob)
        .unwrap()
        .unwrap();
    net.mem
        .tamper(&Handle(blob.file_id), |data| data[5000] ^= 0x80);

    let summary = b.cmd(Down).await.unwrap();
    assert_eq!(summary.failed.len(), 1);
    assert_eq!(summary.failed[0].0, "damaged.bin");
    assert!(summary.deletes_suppressed);
    assert_eq!((summary.downloaded, summary.deleted_local), (1, 0));
    let tree = b.tree();
    assert_eq!(
        tree.keys().collect::<Vec<_>>(),
        ["fine.bin", "gone", "stays"]
    );
    assert_eq!(tree["fine.bin"], pattern(2, (MIB + 2) as usize));
    // No partial file is left behind.
    assert!(std::fs::read_dir(&b.root).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".gclone-partial-")
    }));
}

// ---------------------------------------------------------------------------------------------
// Quotas
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quota_exceeded_stops_cleanly_with_staged_work_committed() {
    let net = Net::new().await;
    let (dev, flaky) = net.flaky().await;
    for (i, name) in ["a.bin", "b.bin", "c.bin", "d.bin"].into_iter().enumerate() {
        dev.write(name, &pattern(i as u32, (MIB + 10 * i as u64) as usize));
    }
    dev.write("old", b"synced before");
    dev.settle().await;
    // Blob puts go in path order, one at a time: the second one hits the quota.
    flaky.fail_nth(OpKind::Put, 2, quota);
    let err = dev.run(Up).await.unwrap_err();
    assert!(
        matches!(
            err,
            SyncError::Backend(BackendError::QuotaExceeded(QuotaKind::StorageFull))
        ),
        "{err}"
    );
    assert_eq!(code(err), 75);
    // No further put was started; what completed is committed.
    assert_eq!(net.blobs().len(), 1);
    assert_eq!(dev.db.pending_count().unwrap(), 0);
    assert_eq!(dev.remote_paths(), ["a.bin"]);
    assert_eq!(dev.vault.outbox_stuck(), None);

    // Tomorrow: the rest goes up, nothing twice.
    let summary = dev.cmd(Up).await.unwrap();
    assert_eq!(summary.uploaded, 4);
    assert_eq!(
        dev.remote_paths(),
        ["a.bin", "b.bin", "c.bin", "d.bin", "old"]
    );
    assert_eq!(net.blobs().len(), 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limited_with_a_full_ledger_is_the_daily_upload_limit() {
    let net = Net::new().await;
    let (dev, flaky) = net.flaky().await;
    dev.write("a.bin", &pattern(1, (MIB + 1) as usize));
    dev.settle().await;

    // Without the ledger evidence it is just a rate limit.
    flaky.fail_next(OpKind::Put, 1, rate_limited);
    let err = dev.run(Up).await.unwrap_err();
    assert!(
        matches!(err, SyncError::Backend(BackendError::RateLimited)),
        "{err}"
    );
    assert_eq!(code(err), 75);

    // ≥ LEDGER_WARN uploaded in the trailing 24 h: it is Google's 750 GB/day cap.
    dev.db
        .ledger_add(gclone::util::now_ms(), LedgerDir::Up, LEDGER_WARN)
        .unwrap();
    flaky.fail_next(OpKind::Put, 1, rate_limited);
    let err = dev.run(Up).await.unwrap_err();
    assert!(
        matches!(
            err,
            SyncError::Backend(BackendError::QuotaExceeded(QuotaKind::DailyUpload))
        ),
        "{err}"
    );
    assert_eq!(code(err), 75);
    assert!(dev.remote_paths().is_empty());

    flaky.clear();
    assert_eq!(dev.cmd(Up).await.unwrap().uploaded, 1);
    // The upload itself went into the ledger.
    let sum = dev
        .db
        .ledger_sum_24h(gclone::util::now_ms(), LedgerDir::Up)
        .unwrap();
    assert!(sum > LEDGER_WARN + MIB);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_download_quota_stops_the_run_and_keeps_finished_files() {
    let net = Net::new().await;
    let a = net.plain().await;
    for (i, name) in ["a.bin", "b.bin", "c.bin"].into_iter().enumerate() {
        a.write(name, &pattern(i as u32, (MIB + 10 * i as u64) as usize));
    }
    a.cmd(Up).await.unwrap();

    let (b, flaky) = net.flaky().await;
    b.settle().await;
    fn daily() -> BackendError {
        BackendError::QuotaExceeded(QuotaKind::DailyDownload)
    }
    // One stream (transfers = 1 would give two): fail everything after the first blob.
    flaky.fail_nth(OpKind::Get, 2, daily);
    flaky.fail_nth(OpKind::Get, 3, daily);
    let err = b.run(Down).await.unwrap_err();
    assert!(
        matches!(
            err,
            SyncError::Backend(BackendError::QuotaExceeded(QuotaKind::DailyDownload))
        ),
        "{err}"
    );
    let kept = b.tree();
    assert!(!kept.is_empty() && kept.len() < 3, "{:?}", kept.keys());
    for (name, data) in &kept {
        assert_eq!(*data, a.tree()[name]);
    }
    // The next run fetches only what is missing.
    flaky.clear();
    let summary = b.cmd(Down).await.unwrap();
    assert_eq!(summary.downloaded as usize, 3 - kept.len());
    assert_eq!(b.tree(), a.tree());
}

/// §5.7, §6.5: `RateLimited` is what the backend answers once its own retries are spent. The
/// run must stop launching downloads and end with exit 75 — not walk through every remaining
/// blob, each one spending the backend's whole retry budget against an API that said "stop".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rate_limited_download_stops_the_run_and_keeps_finished_files() {
    let net = Net::new().await;
    let a = net.plain().await;
    let names = ["a.bin", "b.bin", "c.bin", "d.bin", "e.bin", "f.bin"];
    for (i, name) in names.into_iter().enumerate() {
        a.write(name, &pattern(i as u32, (MIB + 10 * i as u64) as usize));
    }
    a.cmd(Up).await.unwrap();

    let (b, flaky) = net.flaky().await;
    b.settle().await;

    // Every request is refused: the two streams of `transfers = 1` each get their answer, and
    // no third request is made.
    let before = flaky.calls(OpKind::Get);
    flaky.fail_next(OpKind::Get, u32::MAX, rate_limited);
    let err = b.run(Down).await.unwrap_err();
    assert!(
        matches!(err, SyncError::Backend(BackendError::RateLimited)),
        "{err}"
    );
    assert_eq!(code(err), 75);
    assert_eq!(flaky.calls(OpKind::Get) - before, 2);
    assert!(b.tree().is_empty());

    // The first blob arrives, then the limit: what completed is kept, the rest is not asked
    // for (one more group may have been started before the answer came).
    flaky.clear();
    let before = flaky.calls(OpKind::Get);
    for nth in 2..=names.len() as u64 {
        flaky.fail_nth(OpKind::Get, nth, rate_limited);
    }
    let err = b.run(Down).await.unwrap_err();
    assert!(
        matches!(err, SyncError::Backend(BackendError::RateLimited)),
        "{err}"
    );
    let gets = flaky.calls(OpKind::Get) - before;
    assert!((2..=3).contains(&gets), "{gets} requests");
    let kept = b.tree();
    assert_eq!(kept.len(), 1, "{:?}", kept.keys());
    for (name, data) in &kept {
        assert_eq!(*data, a.tree()[name]);
    }

    // Later: only what is missing is fetched.
    flaky.clear();
    let summary = b.cmd(Down).await.unwrap();
    assert_eq!(summary.downloaded as usize, names.len() - 1);
    assert_eq!(b.tree(), a.tree());
}

// ---------------------------------------------------------------------------------------------
// Stuck outbox, cancellation, list lag
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stuck_outbox_blocks_uploads_but_not_downloads() {
    let net = Net::new().await;
    let other = net.plain().await;
    other.write("from-other", b"o");
    other.cmd(Up).await.unwrap();

    let (dev, flaky) = net.flaky().await;
    dev.write("mine.bin", &pattern(1, (MIB + 1) as usize));
    dev.settle().await;
    // Every segment put fails: the blob goes up, its segment stays in the outbox.
    flaky.fail_put_named("s-", u32::MAX, quota);
    let err = dev.run(Up).await.unwrap_err();
    assert!(
        matches!(err, SyncError::Index(IndexError::OutboxStuck(_))),
        "{err}"
    );
    assert_eq!(code(err), 75);
    assert!(dev.vault.outbox_stuck().is_some());
    assert_eq!(
        net.blobs().len(),
        2,
        "the other device's blob and mine.bin's"
    );

    // Up: refused before any work.
    dev.write("second.bin", &pattern(2, (MIB + 2) as usize));
    let report = dev.vault.refresh().await.unwrap();
    assert!(report.outbox_stuck);
    let puts = flaky.calls(OpKind::Put);
    let err = dev.run(Up).await.unwrap_err();
    assert!(
        matches!(err, SyncError::Index(IndexError::OutboxStuck(_))),
        "{err}"
    );
    assert_eq!(flaky.calls(OpKind::Put), puts, "no put was attempted");
    assert_eq!(net.blobs().len(), 2);

    // Down: completes.
    let summary = dev.run(Down).await.unwrap();
    assert_eq!(summary.downloaded, 1);
    assert_eq!(std::fs::read(dev.root.join("from-other")).unwrap(), b"o");
    assert!(dev.vault.outbox_stuck().is_some());

    // Once the backend accepts segments again, the outbox drains and uploads work.
    flaky.clear();
    let summary = dev.cmd(Up).await.unwrap();
    assert_eq!(
        summary.uploaded, 1,
        "mine.bin was published by the outbox, not uploaded again"
    );
    assert_eq!(dev.remote_paths(), ["from-other", "mine.bin", "second.bin"]);
    assert_eq!(net.blobs().len(), 3);
}

const DAY_MS: u64 = 86_400_000;

/// §5.8, end to end: a device whose segment stayed in the outbox while it was away for more
/// than `ORPHAN_GRACE`. Another device's `gc --orphans` trashes the blob it cannot know.
/// Regression: the returning device published the sealed segment as it was — a head on a
/// trashed blob and a base row saying "in sync", so the file was never uploaded again and the
/// only remote copy went with Drive's trash purge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_segment_that_waited_too_long_is_withdrawn_and_the_file_uploaded_again() {
    let net = Net::new().await;
    let other = net.plain().await;
    let (dev, flaky) = net.flaky().await;
    let data = pattern(1, (MIB + 1) as usize);
    dev.write("mine.bin", &data);
    dev.settle().await;
    flaky.fail_put_named("s-", u32::MAX, quota);
    let err = dev.run(Up).await.unwrap_err();
    assert!(
        matches!(err, SyncError::Index(IndexError::OutboxStuck(_))),
        "{err}"
    );
    let first = net.blobs();
    assert_eq!(first.len(), 1);
    let (db, n, root) = (dev.db.clone(), dev.n, dev.root.clone());
    drop(dev);

    net.mem.advance_ms(15 * DAY_MS);
    let report = other.vault.refresh().await.unwrap();
    assert_eq!(report.blocked_young, 0);
    let swept = sync::gc(&other.vault, false, true, false).await.unwrap();
    assert_eq!(swept.orphans, 1);

    // The device comes back with a working backend.
    let dev = net.open(net.mem.clone(), db, n, root).await;
    let summary = dev.cmd(Up).await.unwrap();
    assert_eq!(summary.uploaded, 1, "mine.bin is uploaded again");
    assert_eq!(dev.remote_paths(), ["mine.bin"]);
    let head = dev.vault.head("mine.bin").unwrap().unwrap();
    let rec = dev
        .vault
        .blob(&head.entry.loc.unwrap().blob)
        .unwrap()
        .unwrap();
    assert_ne!(rec.file_id, first[0].handle.0);
    let stored = net
        .mem
        .stat(&Handle(rec.file_id))
        .await
        .unwrap()
        .expect("the head's blob exists");
    assert!(!stored.trashed, "and is not in the trash");

    // The other device gets the file.
    other.cmd(Down).await.unwrap();
    assert_eq!(other.tree().get("mine.bin"), Some(&data));
    assert_eq!(dev.cmd(Up).await.unwrap().uploaded, 0);
}

/// §5.9, end to end with the real `restore`: its segment is stuck on a full Drive — the very
/// situation `gc --purge` is recommended for. Regression: gc looked at heads only, trashed the
/// restored version's blob once its removal was 30 days old and deleted it for good in the
/// same run; the outbox then published a head for a blob that existed nowhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gc_purge_spares_the_blob_of_a_restore_that_is_stuck_in_the_outbox() {
    use gclone::sync::remote_ops;
    let net = Net::new().await;
    let (dev, flaky) = net.flaky().await;
    let data = pattern(7, (MIB + 1) as usize);
    dev.write("f", &data);
    dev.cmd(Up).await.unwrap();
    let blob = dev
        .vault
        .head("f")
        .unwrap()
        .unwrap()
        .entry
        .loc
        .unwrap()
        .blob;
    let handle = Handle(dev.vault.blob(&blob).unwrap().unwrap().file_id);
    remote_ops::rm(&dev.vault, &["f".to_string()], false)
        .await
        .unwrap();
    assert!(dev.vault.head("f").unwrap().is_none());

    net.mem.advance_ms(24 * DAY_MS);
    dev.settle().await;
    let offered = remote_ops::restore_candidates(&dev.vault, "f", net.mem.now_ms())
        .await
        .unwrap();
    assert_eq!(offered.len(), 1);
    flaky.fail_put_named("s-", u32::MAX, quota);
    let err = remote_ops::restore(&dev.vault, "f", &offered[0])
        .await
        .unwrap_err();
    assert!(
        matches!(err, SyncError::Index(IndexError::OutboxStuck(_))),
        "{err}"
    );

    // Day 31: gc is allowed with a stuck outbox — and must leave that blob alone.
    net.mem.advance_ms(7 * DAY_MS);
    let report = dev.vault.refresh().await.unwrap();
    assert!(report.outbox_stuck);
    assert_eq!(report.blocked_young, 0);
    for dry_run in [true, false] {
        let gc = sync::gc(&dev.vault, dry_run, true, true).await.unwrap();
        assert_eq!((gc.dead_blobs, gc.orphans, gc.purged), (0, 0, 0));
        assert!(gc.purge_skipped.is_empty());
    }
    let stored = net.mem.stat(&handle).await.unwrap().expect("not deleted");
    assert!(!stored.trashed);

    // The Drive has room again: the restore is published and the file can be read back.
    flaky.clear();
    assert!(!dev.vault.refresh().await.unwrap().outbox_stuck);
    assert!(dev.vault.head("f").unwrap().is_some());
    std::fs::remove_file(dev.root.join("f")).unwrap();
    let other = net.plain().await;
    other.cmd(Down).await.unwrap();
    assert_eq!(other.tree().get("f"), Some(&data));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ctrl_c_commits_what_completed_and_reports_interrupted() {
    let net = Net::new().await;
    let (dev, flaky) = net.flaky().await;
    dev.write("a.bin", &pattern(1, (MIB + 1) as usize));
    dev.write("b.bin", &pattern(2, (6 * MIB) as usize));
    dev.write("c.bin", &pattern(3, (MIB + 3) as usize));
    dev.settle().await;
    let cancel = CancellationToken::new();
    // The first Ctrl-C arrives while b.bin (the first stream put) is on its way.
    let token = cancel.clone();
    flaky.on_put_progress(0, Box::new(move || token.cancel()));
    let req = dev.req(Up);
    let err = sync::run(&dev.vault, &req, &Ui::silent(), cancel)
        .await
        .unwrap_err();
    assert!(matches!(err, SyncError::Interrupted), "{err}");
    assert_eq!(code(err), 130);
    // Staged ops were committed before returning.
    assert_eq!(dev.db.pending_count().unwrap(), 0);
    let published = dev.remote_paths();
    assert!(published.contains(&"a.bin".to_string()), "{published:?}");
    assert!(
        !published.contains(&"c.bin".to_string()),
        "nothing new was launched"
    );

    // A token that is cancelled from the start does no work at all.
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let blobs = net.blobs().len();
    let err = sync::run(&dev.vault, &req, &Ui::silent(), cancelled)
        .await
        .unwrap_err();
    assert!(matches!(err, SyncError::Interrupted));
    assert_eq!(net.blobs().len(), blobs);

    let summary = dev.cmd(Up).await.unwrap();
    assert_eq!(summary.uploaded as usize, 3 - published.len());
    assert_eq!(dev.remote_paths(), ["a.bin", "b.bin", "c.bin"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_lag_makes_check_blobs_confirm_by_id() {
    let net = Net::new().await;
    let (dev, flaky) = net.flaky().await;
    dev.write("one.bin", &pattern(1, (MIB + 1) as usize));
    dev.write("two.bin", &pattern(2, (MIB + 2) as usize));
    dev.write("small", b"s");
    dev.cmd(Up).await.unwrap();

    // The listing does not show the young blobs yet (nor their folder).
    flaky.set_list_lag_ms(3_600_000);
    let report = sync::check_blobs(&dev.vault).await.unwrap();
    assert!(report.ok(), "{:?}", report.missing);
    assert!(report.missing.is_empty() && report.mismatched.is_empty());
    assert_eq!(report.checked, 3);
    assert_eq!(report.listed_late, 3);
    assert!(report.untrashed.is_empty());

    // A blob that is really gone is still found.
    let head = dev.vault.head("one.bin").unwrap().unwrap();
    let blob = dev
        .vault
        .blob(&head.entry.loc.unwrap().blob)
        .unwrap()
        .unwrap();
    net.mem.hard_delete(&Handle(blob.file_id));
    let report = sync::check_blobs(&dev.vault).await.unwrap();
    assert_eq!((report.missing.len(), report.listed_late), (1, 2));
    assert!(!report.ok());
    flaky.set_list_lag_ms(0);
    let report = sync::check_blobs(&dev.vault).await.unwrap();
    assert_eq!((report.missing.len(), report.listed_late), (1, 0));
}

/// The CLI may spawn a sync: its future must be `Send` for every backend.
#[tokio::test]
async fn the_sync_futures_are_send() {
    fn assert_send<T: Send>(_: &T) {}
    let net = Net::new().await;
    let dev = net.plain().await;
    let req = dev.req(Up);
    let ui = Ui::silent();
    let run = sync::run(&dev.vault, &req, &ui, CancellationToken::new());
    assert_send(&run);
    drop(run);
    assert_send(&sync::gc(&dev.vault, true, true, true));
    assert_send(&sync::check_blobs(&dev.vault));
    assert_send(&sync::check_local(&dev.vault, &dev.root, ""));
    assert_send(&sync::check_download(
        &dev.vault,
        "",
        gclone::ui::Progress::hidden(),
    ));
    assert_send(&sync::remote_ops::mkdir(&dev.vault, "d"));
    assert_send(&sync::remote_ops::rm(&dev.vault, &[], true));
    assert_send(&sync::remote_ops::mv(&dev.vault, "a", "b", false));
    assert_send(&sync::remote_ops::restore_candidates(&dev.vault, "a", 0));
    assert_send(&sync::remote_ops::restorable_under(&dev.vault, "a", 0));
    assert_send(&sync::remote_ops::restore_many(&dev.vault, &[]));
    assert_eq!(dev.n, 0);
}

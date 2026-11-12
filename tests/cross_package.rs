//! Cross-package checks added by integration wave 2 (SPEC §17.3; owned by the integrator, not
//! by a work package): `Vault` (WP4) and the transfer layer (WP5) working together on every
//! backend — `DriveBackend` over `FakeDrive` (WP3), `DirBackend`, `MemBackend` and `AnyBackend`
//! (WP2) — with a real keyfile (WP1). Each package's own tests use `MemBackend` / `Flaky` only.
//!
//! Covered: create → upload → stage → commit → discover → keyfile → attach → refresh →
//! download on a second and a third device; edits and deletes; snapshot, cleanup, keyfile
//! replacement and repair; the recovery drill on a copied directory vault in both layouts;
//! ops staged by a run that died before its commit; Drive faults (5xx, 429, 401, lost answers, list lag, paging, a revoked login, a foreign
//! account) seen through `Vault` and `transfer`.
//!
//! Integration wave 3 (SPEC §17.4) added the sync engine (WP6) on the same backends: the whole
//! command flow `settle → sync::run → finish_mutation` in both directions between two devices,
//! `remote_ops`, `check_*`, `gc` and `restore`; Drive faults under a running sync.

#[path = "support/fake_drive.rs"]
mod fake_drive;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use fake_drive::FakeDrive;
use gclone::backend::{AnyBackend, Backend, DirBackend, MemBackend, get_all};
use gclone::consts::{MIB, PART_SIZE};
use gclone::crypto::{KdfParams, Keyring, MasterKey, Passphrase};
use gclone::error::{GuardKind, SyncError};
use gclone::format::{KeyfilePayload, open_keyfile, seal_keyfile};
use gclone::index::{CreateParams, OpenParams, Vault, creation_winner};
use gclone::state::Db;
use gclone::sync::{self, Direction, Mode, Summary, SyncOpts, SyncRequest, remote_ops};
use gclone::transfer::{
    DownloadItem, LocalExpect, TransferCtx, UploadEvent, UploadSource, download_group, drafts_for,
    locate_blob, materialize_empty, read_range, upload_batch, verify_remote,
};
use gclone::types::{EntryKind, OpDraft};
use gclone::ui::{Progress, Ui};
use tokio_util::sync::CancellationToken;

const VAULT: [u8; 16] = [0x42; 16];
const PASS: &str = "correct horse battery staple";

fn pattern(seed: u8, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    blake3::Hasher::new()
        .update(&[0x77, seed])
        .finalize_xof()
        .fill(&mut buf);
    buf
}

fn cx<B: Backend>(v: &Vault<B>) -> TransferCtx<B> {
    TransferCtx {
        backend: v.backend().clone(),
        keys: v.keys().clone(),
        device: v.device_id(),
        progress: Progress::hidden(),
        cancel: CancellationToken::new(),
    }
}

/// Uploads `files` (relative path → content) from `root`, stages and commits them.
async fn push<B: Backend>(v: &Vault<B>, root: &Path, files: &BTreeMap<String, Vec<u8>>) {
    stage_uploads(v, root, files).await;
    let rep = v.commit().await.unwrap();
    assert!(rep.segment.is_some());
    assert_eq!(rep.dropped_ops, 0);
    v.finish_mutation().await.unwrap();
}

/// The part of `push` before the commit: blobs uploaded, ops staged durably.
async fn stage_uploads<B: Backend>(v: &Vault<B>, root: &Path, files: &BTreeMap<String, Vec<u8>>) {
    let mut sources = Vec::new();
    for (rel, data) in files {
        let abs = root.join(rel);
        std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::fs::write(&abs, data).unwrap();
        sources.push(UploadSource {
            abs,
            remote_path: rel.clone(),
        });
    }
    let folder = v.data_folder().await.unwrap();
    let mut rx = upload_batch(cx(v), folder, sources, 2);
    let mut seen = 0;
    while let Some(ev) = rx.recv().await {
        match ev {
            UploadEvent::Blob(up) => {
                seen += up.files.len();
                let bases: BTreeMap<String, _> = up
                    .files
                    .iter()
                    .map(|f| {
                        (
                            f.remote_path.clone(),
                            v.head(&f.remote_path).unwrap().map(|h| h.stamp),
                        )
                    })
                    .collect();
                let drafts = drafts_for(&up, &|p| (bases[p], None));
                if up.blob.is_some() {
                    v.note_blob_created().unwrap();
                }
                v.stage(drafts).unwrap();
            }
            UploadEvent::Failed(src, e) => panic!("upload of {} failed: {e}", src.remote_path),
        }
    }
    assert_eq!(seen, files.len());
}

/// Downloads every winner into `root` and compares with `want`.
async fn pull_and_compare<B: Backend>(v: &Vault<B>, root: &Path, want: &BTreeMap<String, Vec<u8>>) {
    let c = cx(v);
    let heads = v.walk("").unwrap();
    let files: Vec<_> = heads
        .iter()
        .filter(|h| h.entry.kind == EntryKind::File)
        .collect();
    assert_eq!(
        files.iter().map(|h| h.path.clone()).collect::<Vec<_>>(),
        want.keys().cloned().collect::<Vec<_>>()
    );
    let mut groups: BTreeMap<_, Vec<DownloadItem>> = BTreeMap::new();
    for h in files {
        let item = DownloadItem {
            head: h.clone(),
            root: root.to_path_buf(),
            rel: h.path.clone(),
            expect_local: LocalExpect::Absent,
        };
        match &h.entry.loc {
            None => {
                materialize_empty(&item).await.unwrap();
            }
            Some(loc) => groups.entry(loc.blob).or_default().push(item),
        }
    }
    for (blob, items) in groups {
        let rec = v.blob(&blob).unwrap().expect("blob record");
        let meta = locate_blob(&**v.backend(), &rec).await.unwrap();
        assert_eq!(meta.size, rec.clen);
        assert_eq!(meta.md5, Some(rec.md5));
        // verify_remote and read_range on the first member
        let first = items[0].head.clone();
        verify_remote(&**v.backend(), v.keys(), &rec, &first)
            .await
            .unwrap();
        let data = &want[&first.path];
        let (s, e) = (data.len() as u64 / 3, data.len() as u64 * 2 / 3 + 1);
        let e = e.min(data.len() as u64);
        let mut out = Vec::new();
        let n = read_range(&**v.backend(), v.keys(), &rec, &first, s..e, &mut out)
            .await
            .unwrap();
        assert_eq!(n, e - s);
        assert_eq!(out, data[s as usize..e as usize]);
        for (item, res) in download_group(&c, &rec, items).await {
            res.unwrap_or_else(|e| panic!("download of {} failed: {e}", item.rel));
        }
    }
    for (rel, data) in want {
        let got = std::fs::read(root.join(rel)).unwrap();
        assert!(got == *data, "{rel} differs");
    }
}

async fn scenario<B: Backend>(a_net: Arc<B>, b_net: Arc<B>, c_net: Arc<B>) {
    let tmp = tempfile::tempdir().unwrap();
    let keys = Keyring::new(VAULT, vec![(1, MasterKey::generate())], 1).unwrap();
    let pass = Passphrase::from_input(PASS);
    let params = KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
    };
    let keyfile = seal_keyfile(
        &KeyfilePayload::from_keyring(&keys, 1, "a", a_net.now_ms()),
        &pass,
        params,
    )
    .unwrap();

    assert!(Vault::discover(&*a_net).await.unwrap().is_empty());

    // --- device A creates
    let (a, found_a) = Vault::create(
        a_net.clone(),
        Db::open(&tmp.path().join("a.db")).unwrap(),
        keys.clone(),
        CreateParams {
            vault_id: VAULT,
            vault_name: "gclone".into(),
            device_name: "a".into(),
            cache_dir: tmp.path().join("cache-a"),
            machine_fp: Some([1; 32]),
            keyfile,
        },
    )
    .await
    .unwrap();
    a.refresh().await.unwrap();
    assert_eq!(a.vault_name(), "gclone");

    let mut files = BTreeMap::new();
    files.insert("empty".to_string(), Vec::new());
    for i in 0..40u8 {
        files.insert(
            format!("small/f{i:02}.txt"),
            pattern(i, 100 + 997 * i as usize),
        );
    }
    files.insert(
        "mid/one.bin".to_string(),
        pattern(200, (MIB + 12_345) as usize),
    );
    files.insert(
        "big/two parts.bin".to_string(),
        pattern(201, (PART_SIZE + 3 * MIB + 17) as usize),
    );
    push(&a, &tmp.path().join("src-a"), &files).await;

    // --- device B discovers, opens the keyfile, attaches
    let found = Vault::discover(&*b_net).await.unwrap();
    assert_eq!(found.len(), 1);
    let fv = creation_winner(&found).unwrap().clone();
    assert_eq!(fv.vault_id, VAULT);
    assert_eq!(fv.root_name, "gclone");
    assert_eq!(fv.descriptor_created_ms, found_a.descriptor_created_ms);
    assert_eq!(fv.handles.root, found_a.handles.root);
    assert_eq!(fv.handles.index, found_a.handles.index);
    assert_eq!(fv.handles.data, found_a.handles.data);
    assert_eq!(fv.keyfiles.len(), 1);
    let kf = &fv.keyfiles[0];
    let kf_bytes = get_all(&*b_net, &kf.handle, None).await.unwrap();
    let payload = open_keyfile(&kf.name, &kf_bytes, &pass).unwrap();
    assert_eq!(payload.vault_id_bytes().unwrap(), VAULT);
    let keys_b = payload.keyring().unwrap();
    Vault::verify_visible(&*b_net, &fv.handles).await.unwrap();

    let b = Vault::open(
        b_net.clone(),
        Db::open(&tmp.path().join("b.db")).unwrap(),
        keys_b,
        OpenParams {
            vault_id: VAULT,
            handles: fv.handles.clone(),
            device_name: "b".into(),
            cache_dir: tmp.path().join("cache-b"),
            machine_fp: Some([2; 32]),
        },
    )
    .await
    .unwrap();
    let rep = b.refresh().await.unwrap();
    assert!(rep.corrupt_objects.is_empty(), "{rep:?}");
    assert!(!rep.outbox_stuck);
    b.commit_ops(vec![OpDraft::Device {
        id: b.device_id(),
        name: "b".into(),
    }])
    .await
    .unwrap();
    b.finish_mutation().await.unwrap();
    pull_and_compare(&b, &tmp.path().join("dst-b"), &files).await;

    let rep = a.refresh().await.unwrap();
    assert!(rep.corrupt_objects.is_empty(), "{rep:?}");
    assert_eq!(a.head_fingerprint().unwrap(), b.head_fingerprint().unwrap());
    assert_eq!(a.devices().unwrap().len(), 2);

    // --- B edits one file, deletes another; A sees it
    let mut edit = BTreeMap::new();
    edit.insert("small/f03.txt".to_string(), pattern(99, 4321));
    push(&b, &tmp.path().join("src-b"), &edit).await;
    let del = b.head("small/f04.txt").unwrap().unwrap();
    b.commit_ops(vec![OpDraft::Del {
        path: del.path.clone(),
        base: del.stamp,
        effect: None,
    }])
    .await
    .unwrap();
    b.finish_mutation().await.unwrap();
    files.insert("small/f03.txt".to_string(), pattern(99, 4321));
    files.remove("small/f04.txt");

    a.refresh().await.unwrap();
    assert!(a.conflicts().unwrap().is_empty());
    assert!(a.head("small/f04.txt").unwrap().is_none());
    assert_eq!(a.head_fingerprint().unwrap(), b.head_fingerprint().unwrap());
    pull_and_compare(&a, &tmp.path().join("dst-a"), &files).await;

    // --- snapshot, keyfile replacement, repair, and a late joiner from the snapshot
    let snap = a.write_snapshot().await.unwrap();
    assert!(snap.starts_with("c-"), "{snap}");
    a.cleanup_index().await.unwrap();
    let kf2 = seal_keyfile(
        &KeyfilePayload::from_keyring(&keys, 2, "a", a_net.now_ms()),
        &Passphrase::from_input("another long passphrase"),
        params,
    )
    .unwrap();
    assert_eq!(a.replace_keyfile(&kf2).await.unwrap(), 1);
    let listed = b.keyfiles().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, kf2.name);
    let rr = a.repair(false).await.unwrap();
    assert!(rr.still_missing.is_empty(), "{rr:?}");

    let found = Vault::discover(&*c_net).await.unwrap();
    assert_eq!(found.len(), 1);
    let c = Vault::open(
        c_net.clone(),
        Db::open(&tmp.path().join("c.db")).unwrap(),
        keys.clone(),
        OpenParams {
            vault_id: VAULT,
            handles: found[0].handles.clone(),
            device_name: "c".into(),
            cache_dir: tmp.path().join("cache-c"),
            machine_fp: Some([3; 32]),
        },
    )
    .await
    .unwrap();
    let rep = c.refresh().await.unwrap();
    assert!(rep.corrupt_objects.is_empty(), "{rep:?}");
    pull_and_compare(&c, &tmp.path().join("dst-c"), &files).await;
    b.refresh().await.unwrap();
    assert_eq!(c.head_fingerprint().unwrap(), b.head_fingerprint().unwrap());
    let st = c.stats(c_net.now_ms()).unwrap();
    assert_eq!(st.files, files.len() as u64);
    assert_eq!(st.conflicts, 0);

    // --- killed between staging and commit (§5.8): the staged ops survive a re-open, their
    //     blobs pass verify_pending_blobs on this backend, and the next commit publishes them
    c.commit_ops(vec![OpDraft::Device {
        id: c.device_id(),
        name: "c".into(),
    }])
    .await
    .unwrap();
    let mut late = BTreeMap::new();
    late.insert("late/small".to_string(), pattern(210, 2222));
    late.insert("late/large".to_string(), pattern(211, (2 * MIB) as usize));
    late.insert("late/empty".to_string(), Vec::new());
    stage_uploads(&c, &tmp.path().join("src-c"), &late).await;
    assert!(c.db().pending_count().unwrap() > 0);
    let c_id = c.device_id();
    drop(c);
    let c = Vault::open(
        c_net.clone(),
        Db::open(&tmp.path().join("c.db")).unwrap(),
        keys.clone(),
        OpenParams {
            vault_id: VAULT,
            handles: found[0].handles.clone(),
            device_name: "c".into(),
            cache_dir: tmp.path().join("cache-c"),
            machine_fp: Some([3; 32]),
        },
    )
    .await
    .unwrap();
    assert_eq!(c.device_id(), c_id);
    let rep = c.refresh().await.unwrap();
    assert!(!rep.rotated_device);
    let rep = c.commit().await.unwrap();
    assert!(rep.segment.is_some());
    assert_eq!(rep.dropped_ops, 0);
    assert_eq!(c.resolve_conflicts().await.unwrap(), 0);
    c.finish_mutation().await.unwrap();
    assert_eq!(c.db().pending_count().unwrap(), 0);
    files.extend(late);
    b.refresh().await.unwrap();
    assert!(b.conflicts().unwrap().is_empty());
    pull_and_compare(&b, &tmp.path().join("dst-b2"), &files).await;
    assert_eq!(c.head_fingerprint().unwrap(), b.head_fingerprint().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_mem() {
    let mem = Arc::new(MemBackend::new());
    scenario(mem.clone(), mem.clone(), mem).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let open = || Arc::new(DirBackend::open(tmp.path()).unwrap());
    scenario(open(), open(), open()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_any_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let open = || Arc::new(AnyBackend::Dir(DirBackend::open(tmp.path()).unwrap()));
    scenario(open(), open(), open()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_fake_drive() {
    let fake = FakeDrive::start().await;
    scenario(
        Arc::new(fake.backend()),
        Arc::new(fake.backend()),
        Arc::new(fake.backend()),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_any_fake_drive() {
    let fake = FakeDrive::start().await;
    let open = || Arc::new(AnyBackend::Drive(fake.backend()));
    scenario(open(), open(), open()).await;
}

/// Drive mode with paging and list lag (what real Drive does to a fresh listing).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_fake_drive_paged() {
    let fake = FakeDrive::start().await;
    fake.set_page_cap(3);
    scenario(
        Arc::new(fake.backend()),
        Arc::new(fake.backend()),
        Arc::new(fake.backend()),
    )
    .await;
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let name = e.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        let dst = to.join(&name);
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &dst);
        } else {
            std::fs::copy(e.path(), &dst).unwrap();
        }
    }
}

async fn make_dir_vault(tmp: &Path) -> (Keyring, BTreeMap<String, Vec<u8>>) {
    let net = Arc::new(DirBackend::open(&tmp.join("vault")).unwrap());
    let keys = Keyring::new(VAULT, vec![(1, MasterKey::generate())], 1).unwrap();
    let keyfile = seal_keyfile(
        &KeyfilePayload::from_keyring(&keys, 1, "a", 1),
        &Passphrase::from_input(PASS),
        KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
        },
    )
    .unwrap();
    let (a, _) = Vault::create(
        net.clone(),
        Db::open(&tmp.join("a.db")).unwrap(),
        keys.clone(),
        CreateParams {
            vault_id: VAULT,
            vault_name: "gclone".into(),
            device_name: "a".into(),
            cache_dir: tmp.join("cache-a"),
            machine_fp: Some([1; 32]),
            keyfile,
        },
    )
    .await
    .unwrap();
    a.refresh().await.unwrap();
    let mut files = BTreeMap::new();
    files.insert("empty".to_string(), Vec::new());
    for i in 0..10u8 {
        files.insert(format!("d/f{i}"), pattern(i, 3000 * (i as usize + 1)));
    }
    files.insert("big".to_string(), pattern(50, (5 * MIB) as usize));
    push(&a, &tmp.join("src"), &files).await;
    // a few more segments + one edit so that `seen` references exist
    for i in 0..3u8 {
        let mut m = BTreeMap::new();
        m.insert(format!("d/f{i}"), pattern(100 + i, 777));
        files.extend(m.clone());
        push(&a, &tmp.join("src"), &m).await;
    }
    (keys, files)
}

async fn attach_fresh(
    root: &Path,
    tmp: &Path,
    tag: &str,
    keys: &Keyring,
    want_root_name: &str,
) -> Vault<DirBackend> {
    let net = Arc::new(DirBackend::open(root).unwrap());
    let found = Vault::discover(&*net).await.unwrap();
    assert_eq!(found.len(), 1, "{tag}");
    assert_eq!(found[0].root_name, want_root_name);
    assert_eq!(found[0].keyfiles.len(), 1);
    let kf = &found[0].keyfiles[0];
    let bytes = get_all(&*net, &kf.handle, None).await.unwrap();
    let payload = open_keyfile(&kf.name, &bytes, &Passphrase::from_input(PASS)).unwrap();
    assert_eq!(payload.vault_id_bytes().unwrap(), VAULT);
    Vault::verify_visible(&*net, &found[0].handles)
        .await
        .unwrap();
    let v = Vault::open(
        net,
        Db::open(&tmp.join(format!("{tag}.db"))).unwrap(),
        keys.clone(),
        OpenParams {
            vault_id: VAULT,
            handles: found[0].handles.clone(),
            device_name: tag.into(),
            cache_dir: tmp.join(format!("cache-{tag}")),
            machine_fp: Some([9; 32]),
        },
    )
    .await
    .unwrap();
    let rep = v.refresh().await.unwrap();
    assert!(rep.corrupt_objects.is_empty(), "{tag}: {rep:?}");
    v
}

/// §12.1 WP7 recovery drill, library level: (a) outer directory copied without the id map,
/// (b) only the inner vault folder.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_drill_both_layouts() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("vault")).unwrap();
    let (keys, files) = make_dir_vault(tmp.path()).await;

    let outer = tmp.path().join("copy-outer");
    copy_tree(&tmp.path().join("vault"), &outer);
    assert!(!outer.join(".gclone-dir-ids.json").exists());
    let v = attach_fresh(&outer, tmp.path(), "outer", &keys, "gclone").await;
    pull_and_compare(&v, &tmp.path().join("dst-outer"), &files).await;
    // the recovered copy must also be writable: attach op + a new file
    v.commit_ops(vec![OpDraft::Device {
        id: v.device_id(),
        name: "outer".into(),
    }])
    .await
    .unwrap();
    let mut m = BTreeMap::new();
    m.insert("new-after-recovery".to_string(), pattern(7, 9999));
    push(&v, &tmp.path().join("src-outer"), &m).await;
    let mut files2 = files.clone();
    files2.extend(m);
    let w = attach_fresh(&outer, tmp.path(), "outer2", &keys, "gclone").await;
    pull_and_compare(&w, &tmp.path().join("dst-outer2"), &files2).await;
    v.refresh().await.unwrap();
    assert_eq!(v.head_fingerprint().unwrap(), w.head_fingerprint().unwrap());

    let inner = tmp.path().join("copy-inner");
    copy_tree(&tmp.path().join("vault").join("gclone"), &inner);
    let v = attach_fresh(&inner, tmp.path(), "inner", &keys, "").await;
    pull_and_compare(&v, &tmp.path().join("dst-inner"), &files).await;
    v.commit_ops(vec![OpDraft::Device {
        id: v.device_id(),
        name: "inner".into(),
    }])
    .await
    .unwrap();
    v.finish_mutation().await.unwrap();
    let rr = v.repair(false).await.unwrap();
    assert!(rr.still_missing.is_empty(), "{rr:?}");
}

/// Drive faults seen through Vault + transfer: transient errors and a 401 are absorbed, list
/// lag does not produce Gap/Rollback, a revoked login is Auth(Expired) with exit code 4, a
/// foreign account is VaultNotVisible.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drive_faults_through_vault_and_transfer() {
    use fake_drive::Route;
    use gclone::error::{AuthError, BackendError, IndexError, exit_code};

    let fake = FakeDrive::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let net = Arc::new(fake.backend());
    let keys = Keyring::new(VAULT, vec![(1, MasterKey::generate())], 1).unwrap();
    let keyfile = seal_keyfile(
        &KeyfilePayload::from_keyring(&keys, 1, "a", 1),
        &Passphrase::from_input(PASS),
        KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
        },
    )
    .unwrap();
    fake.fail_next(Route::Multipart, 1, 503, "backendError");
    fake.unauthorized_once(Route::CreateFolder);
    let (a, found) = Vault::create(
        net.clone(),
        Db::open(&tmp.path().join("a.db")).unwrap(),
        keys.clone(),
        CreateParams {
            vault_id: VAULT,
            vault_name: "gclone".into(),
            device_name: "a".into(),
            cache_dir: tmp.path().join("cache-a"),
            machine_fp: Some([1; 32]),
            keyfile,
        },
    )
    .await
    .unwrap();
    a.refresh().await.unwrap();

    let mut files = BTreeMap::new();
    for i in 0..6u8 {
        files.insert(format!("f{i}"), pattern(i, 50_000));
    }
    files.insert("big".to_string(), pattern(60, (PART_SIZE + MIB) as usize));
    fake.fail_next(Route::Multipart, 2, 429, "rateLimitExceeded");
    fake.lose_response_once(Route::SessionPut);
    fake.fail_next(Route::ResumableInit, 1, 500, "internalError");
    push(&a, &tmp.path().join("src"), &files).await;

    // second device under list lag
    fake.set_list_lag(2);
    let net_b = Arc::new(fake.backend());
    let b = Vault::open(
        net_b.clone(),
        Db::open(&tmp.path().join("b.db")).unwrap(),
        keys.clone(),
        OpenParams {
            vault_id: VAULT,
            handles: found.handles.clone(),
            device_name: "b".into(),
            cache_dir: tmp.path().join("cache-b"),
            machine_fp: Some([2; 32]),
        },
    )
    .await
    .unwrap();
    let mut m = BTreeMap::new();
    m.insert("late".to_string(), pattern(61, 1234));
    push(&a, &tmp.path().join("src"), &m).await;
    files.extend(m);
    for _ in 0..4 {
        let rep = b.refresh().await.unwrap();
        assert!(rep.corrupt_objects.is_empty(), "{rep:?}");
    }
    fake.set_list_lag(0);
    b.refresh().await.unwrap();
    fake.fail_next(Route::Media, 1, 503, "backendError");
    pull_and_compare(&b, &tmp.path().join("dst-b"), &files).await;

    // foreign account
    fake.fail_next(Route::Stat, 1, 403, "appNotAuthorizedToFile");
    let e = Vault::verify_visible(&*net_b, &found.handles)
        .await
        .unwrap_err();
    assert!(matches!(e, IndexError::VaultNotVisible), "{e:?}");
    assert_eq!(exit_code(&anyhow::Error::new(e)), 4);
    Vault::verify_visible(&*net_b, &found.handles)
        .await
        .unwrap();

    // revoked login
    fake.revoke_refresh_token();
    let e = b.refresh().await.unwrap_err();
    assert!(
        matches!(
            e,
            IndexError::Backend(BackendError::Auth(AuthError::Expired))
        ),
        "{e:?}"
    );
    assert_eq!(exit_code(&anyhow::Error::new(e)), 4);
}

// ---------------------------------------------------------------------------------------------
// Integration wave 3: the sync engine (WP6) on every backend
// ---------------------------------------------------------------------------------------------

fn sync_req(root: &Path, direction: Direction, mode: Mode, prefix: &str) -> SyncRequest {
    SyncRequest {
        direction,
        mode,
        local_root: root.to_path_buf(),
        remote_prefix: prefix.to_string(),
        own_dirs: Vec::new(),
        opts: SyncOpts {
            dry_run: false,
            checksum: false,
            force: false,
            excludes: Vec::new(),
            max_delete: None,
            assume_yes: false,
            transfers: 2,
            reset_pair: false,
            keep_pair: false,
        },
    }
}

/// The same request with `--yes`.
fn confirmed(mut req: SyncRequest) -> SyncRequest {
    req.opts.assume_yes = true;
    req
}

/// One command as the CLI runs it (§10): settle → `sync::run` → `finish_mutation`.
async fn sync_cmd<B: Backend>(v: &Vault<B>, req: &SyncRequest) -> Summary {
    v.refresh().await.unwrap();
    v.commit().await.unwrap();
    v.resolve_conflicts().await.unwrap();
    let summary = sync::run(v, req, &Ui::silent(), CancellationToken::new())
        .await
        .unwrap_or_else(|e| panic!("sync failed: {e}"));
    v.finish_mutation().await.unwrap();
    summary
}

fn assert_clean(summary: &Summary, what: &str) {
    assert!(summary.failed.is_empty(), "{what}: {:?}", summary.failed);
    assert!(summary.skipped.is_empty(), "{what}: {:?}", summary.skipped);
    assert!(!summary.deletes_suppressed, "{what}");
    assert_eq!(summary.exit_code(), 0, "{what}");
}

/// Every regular file under `root`: relative path → content.
fn read_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let md = std::fs::symlink_metadata(&p).unwrap();
            if md.is_dir() {
                walk(root, &p, out);
            } else if md.is_file() {
                let rel = p.strip_prefix(root).unwrap().to_str().unwrap().to_string();
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn write_file(root: &Path, rel: &str, data: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

async fn new_vault<B: Backend>(net: Arc<B>, tmp: &Path) -> (Vault<B>, Keyring) {
    let keys = Keyring::new(VAULT, vec![(1, MasterKey::generate())], 1).unwrap();
    let keyfile = seal_keyfile(
        &KeyfilePayload::from_keyring(&keys, 1, "a", net.now_ms()),
        &Passphrase::from_input(PASS),
        KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
        },
    )
    .unwrap();
    let (a, _) = Vault::create(
        net,
        Db::open(&tmp.join("a.db")).unwrap(),
        keys.clone(),
        CreateParams {
            vault_id: VAULT,
            vault_name: "gclone".into(),
            device_name: "a".into(),
            cache_dir: tmp.join("cache-a"),
            machine_fp: Some([1; 32]),
            keyfile,
        },
    )
    .await
    .unwrap();
    a.refresh().await.unwrap();
    (a, keys)
}

async fn attach<B: Backend>(net: Arc<B>, tmp: &Path, keys: &Keyring) -> Vault<B> {
    let found = Vault::discover(&*net).await.unwrap();
    assert_eq!(found.len(), 1);
    Vault::verify_visible(&*net, &found[0].handles)
        .await
        .unwrap();
    let b = Vault::open(
        net,
        Db::open(&tmp.join("b.db")).unwrap(),
        keys.clone(),
        OpenParams {
            vault_id: VAULT,
            handles: found[0].handles.clone(),
            device_name: "b".into(),
            cache_dir: tmp.join("cache-b"),
            machine_fp: Some([2; 32]),
        },
    )
    .await
    .unwrap();
    b.refresh().await.unwrap();
    b.commit_ops(vec![OpDraft::Device {
        id: b.device_id(),
        name: "b".into(),
    }])
    .await
    .unwrap();
    b.finish_mutation().await.unwrap();
    b
}

/// Two devices, one vault, the real command flow. `fault` is called once, right before device
/// A's second upload run (Drive mode arms request failures there).
async fn sync_scenario<B: Backend>(a_net: Arc<B>, b_net: Arc<B>, fault: impl FnOnce()) {
    use Direction::{Down, Up};
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let (a, keys) = new_vault(a_net, tmp.path()).await;
    let (ra, rb) = (tmp.path().join("root-a"), tmp.path().join("root-b"));
    std::fs::create_dir(&ra).unwrap();

    // --- A pushes a tree: an empty file, a pack of small files, a blob of its own, a
    //     two-part resumable blob, an executable, an empty directory
    write_file(&ra, "empty", b"");
    for i in 0..40u8 {
        write_file(
            &ra,
            &format!("small/f{i:02}.txt"),
            &pattern(i, 100 + 997 * i as usize),
        );
    }
    write_file(&ra, "mid/one.bin", &pattern(200, (MIB + 12_345) as usize));
    write_file(
        &ra,
        "big/two parts.bin",
        &pattern(201, (PART_SIZE + 3 * MIB + 17) as usize),
    );
    write_file(&ra, "bin/tool", b"#!/bin/sh\n");
    std::fs::set_permissions(ra.join("bin/tool"), PermissionsExt::from_mode(0o755)).unwrap();
    std::fs::create_dir_all(ra.join("hollow/inner")).unwrap();

    let up = sync_cmd(&a, &sync_req(&ra, Up, Mode::Sync, "")).await;
    assert_clean(&up, "first push");
    assert_eq!(up.uploaded, 44);
    assert_eq!((up.deleted_remote, up.reused), (0, 0));
    // a second run has nothing to do and hashes nothing new
    let again = sync_cmd(&a, &sync_req(&ra, Up, Mode::Sync, "")).await;
    assert_clean(&again, "no-change push");
    assert_eq!(
        (again.uploaded, again.reused, again.meta_updates),
        (0, 0, 0)
    );

    // --- B attaches and pulls (the root does not exist yet)
    let b = attach(b_net, tmp.path(), &keys).await;
    let down = sync_cmd(&b, &sync_req(&rb, Down, Mode::Sync, "")).await;
    assert_clean(&down, "first pull");
    assert_eq!(down.downloaded, 44);
    assert_eq!(down.bytes_down, up.bytes_up);
    assert!(read_tree(&ra) == read_tree(&rb), "trees differ after pull");
    assert!(rb.join("hollow/inner").is_dir());
    let mode = std::fs::metadata(rb.join("bin/tool"))
        .unwrap()
        .permissions()
        .mode();
    assert_ne!(mode & 0o100, 0);
    let again = sync_cmd(&b, &sync_req(&rb, Down, Mode::Sync, "")).await;
    assert_clean(&again, "no-change pull");
    assert_eq!((again.downloaded, again.hashed), (0, 0));

    // --- B edits, deletes, renames a directory, adds; pushes with `sync`
    write_file(&rb, "small/f03.txt", &pattern(99, 4321));
    std::fs::remove_file(rb.join("small/f04.txt")).unwrap();
    std::fs::rename(rb.join("mid"), rb.join("middle")).unwrap();
    write_file(&rb, "new/from-b.txt", b"from b");
    let up_b = sync_cmd(&b, &sync_req(&rb, Up, Mode::Sync, "")).await;
    assert_clean(&up_b, "push from b");
    assert_eq!(up_b.reused, 1, "the renamed file is an index-only put");
    assert_eq!(up_b.uploaded, 2);
    assert_eq!(up_b.deleted_remote, 2);

    // --- A pulls B's changes, then adds files and pushes them through injected faults
    let down_a = sync_cmd(&a, &sync_req(&ra, Down, Mode::Sync, "")).await;
    assert_clean(&down_a, "pull on a");
    assert_eq!((down_a.downloaded, down_a.deleted_local), (3, 2));
    write_file(&ra, "new/from-a.txt", &pattern(77, 300_000));
    write_file(
        &ra,
        "big/second.bin",
        &pattern(78, (PART_SIZE + 5) as usize),
    );
    fault();
    let up_a = sync_cmd(&a, &sync_req(&ra, Up, Mode::Copy, "")).await;
    assert_clean(&up_a, "copy from a");
    assert_eq!(up_a.uploaded, 2);
    let down_b = sync_cmd(&b, &sync_req(&rb, Down, Mode::Sync, "")).await;
    assert_clean(&down_b, "pull on b");
    assert_eq!(down_b.downloaded, 2);
    let tree = read_tree(&ra);
    assert!(tree == read_tree(&rb), "trees differ after the exchange");
    assert_eq!(tree["small/f03.txt"], pattern(99, 4321));
    assert!(!tree.contains_key("small/f04.txt"));
    assert!(tree.contains_key("middle/one.bin") && !tree.contains_key("mid/one.bin"));
    assert!(!ra.join("mid").exists());
    assert!(a.conflicts().unwrap().is_empty());
    assert_eq!(a.head_fingerprint().unwrap(), b.head_fingerprint().unwrap());

    // --- index-only commands on A reach B's tree
    remote_ops::mkdir(&a, "made/here").await.unwrap();
    let moved = remote_ops::mv(&a, "small", "tiny", false).await.unwrap();
    assert_eq!(
        (moved.to.as_str(), moved.entries, moved.replaced),
        ("tiny", 39, 0)
    );
    assert_eq!(
        remote_ops::rm(&a, &["new/from-b.txt".to_string()], false)
            .await
            .unwrap(),
        1
    );
    a.finish_mutation().await.unwrap();
    // 40 of B's 47 entries go: the delete guard (G4) stops the run unless it is confirmed
    b.refresh().await.unwrap();
    let guarded = sync::run(
        &b,
        &sync_req(&rb, Down, Mode::Sync, ""),
        &Ui::silent(),
        CancellationToken::new(),
    )
    .await;
    assert!(
        matches!(
            guarded,
            Err(SyncError::Guard(GuardKind::DeleteLimit { deletes: 40, .. }))
        ),
        "{guarded:?}"
    );
    assert!(
        rb.join("small/f00.txt").is_file(),
        "a refused run changes nothing"
    );
    let down_b = sync_cmd(&b, &confirmed(sync_req(&rb, Down, Mode::Sync, ""))).await;
    assert_clean(&down_b, "pull after remote ops");
    assert_eq!((down_b.downloaded, down_b.deleted_local), (39, 40));
    assert!(rb.join("made/here").is_dir());
    assert!(rb.join("tiny/f00.txt").is_file() && !rb.join("small").exists());
    assert!(!rb.join("new/from-b.txt").exists());

    // --- a sub-tree pair: `copy :tiny DIR`
    let sub = tmp.path().join("sub");
    let s = sync_cmd(&b, &sync_req(&sub, Down, Mode::Copy, "tiny")).await;
    assert_clean(&s, "copy of a prefix");
    assert_eq!(s.downloaded, 39);
    assert_eq!(read_tree(&sub).len(), 39);
    assert_eq!(read_tree(&sub)["f03.txt"], pattern(99, 4321));

    // --- restore the version B overwrote, check and gc
    let now = a.backend().now_ms();
    let offered = remote_ops::restore_candidates(&a, "small/f03.txt", now)
        .await
        .unwrap();
    assert!(!offered.is_empty(), "the overwritten version is offered");
    let old = offered
        .iter()
        .find(|v| v.entry.hash == *blake3::hash(&pattern(3, 100 + 997 * 3)).as_bytes())
        .expect("the first version of small/f03.txt");
    remote_ops::restore(&a, "restored.txt", old).await.unwrap();
    a.finish_mutation().await.unwrap();
    let down_b = sync_cmd(&b, &sync_req(&rb, Down, Mode::Sync, "")).await;
    assert_clean(&down_b, "pull after restore");
    assert_eq!(
        std::fs::read(rb.join("restored.txt")).unwrap(),
        pattern(3, 100 + 997 * 3)
    );

    for v in [&a, &b] {
        v.refresh().await.unwrap();
        let rep = sync::check_blobs(v).await.unwrap();
        assert!(rep.ok() && rep.checked > 0, "{rep:?}");
        assert!(rep.untrashed.is_empty(), "{rep:?}");
        assert_eq!(rep.orphans, 0, "{rep:?}");
        let rep = sync::check_download(v, "", Progress::hidden())
            .await
            .unwrap();
        assert!(rep.ok() && rep.checked > 0, "{rep:?}");
        // nothing is old enough to collect: gc and purge leave everything in place
        let gc = sync::gc(v, false, true, true).await.unwrap();
        assert_eq!((gc.dead_blobs, gc.orphans, gc.purged), (0, 0, 0), "{gc:?}");
        assert!(gc.purge_skipped.is_empty(), "{gc:?}");
    }
    // A's tree is behind (it has not pulled its own remote ops): check_local on B, which is
    let rep = sync::check_local(&b, &rb, "").await.unwrap();
    assert!(rep.ok() && rep.checked > 0, "{rep:?}");
    let down_a = sync_cmd(&a, &confirmed(sync_req(&ra, Down, Mode::Sync, ""))).await;
    assert_clean(&down_a, "final pull on a");
    assert!(read_tree(&ra) == read_tree(&rb), "trees differ at the end");
    let rep = sync::check_local(&a, &ra, "").await.unwrap();
    assert!(rep.ok(), "{rep:?}");
    assert_eq!(a.head_fingerprint().unwrap(), b.head_fingerprint().unwrap());
    assert_eq!(a.db().pending_count().unwrap(), 0);
    assert_eq!(b.db().pending_count().unwrap(), 0);

    // --- a new process on A: the device id, the pair and its base rows come from state.db
    let (net, handles, device) = (a.backend().clone(), a.handles().clone(), a.device_id());
    drop(a);
    let a = Vault::open(
        net,
        Db::open(&tmp.path().join("a.db")).unwrap(),
        keys.clone(),
        OpenParams {
            vault_id: VAULT,
            handles,
            device_name: "a".into(),
            cache_dir: tmp.path().join("cache-a"),
            machine_fp: Some([1; 32]),
        },
    )
    .await
    .unwrap();
    assert_eq!(a.device_id(), device);
    let s = sync_cmd(&a, &sync_req(&ra, Up, Mode::Sync, "")).await;
    assert_clean(&s, "no-change push after a restart");
    assert_eq!(
        (
            s.uploaded,
            s.reused,
            s.meta_updates,
            s.deleted_remote,
            s.hashed
        ),
        (0, 0, 0, 0, 0)
    );
    let s = sync_cmd(&a, &sync_req(&ra, Down, Mode::Sync, "")).await;
    assert_clean(&s, "no-change pull after a restart");
    assert_eq!((s.downloaded, s.deleted_local, s.hashed), (0, 0, 0));
    assert_eq!(a.head_fingerprint().unwrap(), b.head_fingerprint().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_on_mem() {
    let mem = Arc::new(MemBackend::new());
    sync_scenario(mem.clone(), mem, || {}).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_on_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let open = || Arc::new(DirBackend::open(tmp.path()).unwrap());
    sync_scenario(open(), open(), || {}).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_on_any_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let open = || Arc::new(AnyBackend::Dir(DirBackend::open(tmp.path()).unwrap()));
    sync_scenario(open(), open(), || {}).await;
}

/// Drive mode, with request failures armed for one upload run: they are absorbed by the
/// backend and the run stays clean.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_on_fake_drive_with_faults() {
    use fake_drive::Route;
    let fake = FakeDrive::start().await;
    let arm = fake.clone();
    sync_scenario(
        Arc::new(fake.backend()),
        Arc::new(fake.backend()),
        move || {
            arm.fail_next(Route::Multipart, 2, 503, "backendError");
            arm.fail_next(Route::ResumableInit, 1, 429, "rateLimitExceeded");
            arm.lose_response_once(Route::SessionPut);
        },
    )
    .await;
}

/// Drive mode behind `AnyBackend` (what the CLI holds), with paging.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_on_any_fake_drive_paged() {
    let fake = FakeDrive::start().await;
    fake.set_page_cap(3);
    let open = || Arc::new(AnyBackend::Drive(fake.backend()));
    sync_scenario(open(), open(), || {}).await;
}

/// A remote prefix that is a file (or lies under one) is not a directory to sync with: an
/// upload below it would make the index move the file to a conflict name (§5.2.3 rule 2), and
/// a download would silently find nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prefix_that_is_a_file_is_refused() {
    use Direction::{Down, Up};
    let tmp = tempfile::tempdir().unwrap();
    let (a, _) = new_vault(Arc::new(MemBackend::new()), tmp.path()).await;
    let root = tmp.path().join("root");
    write_file(&root, "notes.txt", b"a file");
    write_file(&root, "dir/inner.txt", b"inner");
    let up = sync_cmd(&a, &sync_req(&root, Up, Mode::Sync, "")).await;
    assert_clean(&up, "push");
    let before = a.head_fingerprint().unwrap();

    let other = tmp.path().join("other");
    write_file(&other, "x", b"x");
    for (direction, prefix) in [
        (Up, "notes.txt"),
        (Up, "notes.txt/below"),
        (Down, "notes.txt"),
        (Down, "dir/inner.txt/deeper"),
    ] {
        for mode in [Mode::Copy, Mode::Sync] {
            let res = sync::run(
                &a,
                &sync_req(&other, direction, mode, prefix),
                &Ui::silent(),
                CancellationToken::new(),
            )
            .await;
            assert!(
                matches!(res, Err(SyncError::Usage(_))),
                "{direction:?} {mode:?} :{prefix}: {res:?}"
            );
        }
    }
    a.finish_mutation().await.unwrap();
    assert_eq!(a.head_fingerprint().unwrap(), before);
    assert_eq!(a.db().pending_count().unwrap(), 0);
    assert_eq!(read_tree(&other).len(), 1);
    // a directory prefix, existing or new, is fine
    let s = sync_cmd(&a, &sync_req(&other, Up, Mode::Copy, "dir")).await;
    assert_clean(&s, "copy into :dir");
    let s = sync_cmd(&a, &sync_req(&other, Up, Mode::Copy, "fresh/place")).await;
    assert_clean(&s, "copy into a new prefix");
    assert!(a.head("dir/x").unwrap().is_some() && a.head("fresh/place/x").unwrap().is_some());
    assert!(a.conflicts().unwrap().is_empty());
}

//! WP2 acceptance (SPEC §12.1): the generic backend contract on every fake, and what each fake
//! promises beyond it — `MemBackend`'s hooks, `DirBackend`'s id map and `p:` handles, `Flaky`'s
//! injectors.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use bytes::Bytes;
use futures_util::StreamExt;
use gclone::backend::{
    AnyBackend, Backend, Counters, DirBackend, Flaky, Handle, MemBackend, ObjMeta, OpKind, PutBody,
    conformance, get_all, stream_body,
};
use gclone::consts::{MULTIPART_MAX, PART_SIZE};
use gclone::error::{BackendError, QuotaKind};
use tokio::sync::mpsc;

const IDS_FILE: &str = ".gclone-dir-ids.json";
const PART: usize = PART_SIZE as usize;

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

fn pattern(seed: u8, len: usize) -> Bytes {
    let mut buf = vec![0u8; len];
    blake3::Hasher::new()
        .update(&[0xA5, seed])
        .finalize_xof()
        .fill(&mut buf);
    buf.into()
}

fn md5(data: &[u8]) -> [u8; 16] {
    use md5::Digest;
    md5::Md5::digest(data).into()
}

fn top() -> Handle {
    Handle::top()
}

async fn id<B: Backend>(b: &B) -> Handle {
    b.new_ids(1).await.unwrap().remove(0)
}

async fn folder<B: Backend>(b: &B, parent: &Handle, name: &str) -> Handle {
    let h = id(b).await;
    b.create_folder(&h, parent, name).await.unwrap();
    h
}

async fn put<B: Backend>(b: &B, parent: &Handle, name: &str, data: &Bytes) -> Handle {
    let h = id(b).await;
    let meta = b
        .put(&h, parent, name, stream_body(data.clone()))
        .await
        .unwrap();
    assert_eq!(meta.md5, Some(md5(data)));
    h
}

fn names(metas: &[ObjMeta]) -> Vec<String> {
    let mut names: Vec<String> = metas.iter().map(|m| m.name.clone()).collect();
    names.sort();
    names
}

fn is_fatal(e: &BackendError, want: u16) -> bool {
    matches!(e, BackendError::Fatal { status, .. } if *status == want)
}

/// A `Stream` body whose parts arrive through a channel of capacity 1; `sent` counts the parts
/// the feeding task has handed over.
fn fed_body(parts: Vec<std::io::Result<Bytes>>, total: u64) -> (PutBody, Arc<AtomicU32>) {
    let (tx, rx) = mpsc::channel(1);
    let sent = Arc::new(AtomicU32::new(0));
    let counter = sent.clone();
    tokio::spawn(async move {
        for part in parts {
            if tx.send(part).await.is_err() {
                return;
            }
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    (PutBody::Stream { total, parts: rx }, sent)
}

fn parts_of(data: &Bytes) -> Vec<std::io::Result<Bytes>> {
    data.chunks(PART).map(|c| Ok(data.slice_ref(c))).collect()
}

/// Recursive copy; `skip` names entries of the top level to leave out.
fn copy_tree(from: &Path, to: &Path, skip: &[&str]) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if skip.iter().any(|s| name == *s) {
            continue;
        }
        let dest = to.join(&name);
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest, &[]);
        } else {
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}

fn transient() -> BackendError {
    BackendError::Transient("planned".into())
}

fn quota() -> BackendError {
    BackendError::QuotaExceeded(QuotaKind::StorageFull)
}

// ---------------------------------------------------------------------------------------------
// the generic contract
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn conformance_mem() {
    conformance::run(MemBackend::new()).await;
}

#[tokio::test]
async fn conformance_dir() {
    let dir = tempfile::tempdir().unwrap();
    conformance::run(DirBackend::open(dir.path()).unwrap()).await;
}

#[tokio::test]
async fn conformance_flaky_mem() {
    conformance::run(Flaky::new(MemBackend::new())).await;
}

#[tokio::test]
async fn conformance_flaky_dir() {
    let dir = tempfile::tempdir().unwrap();
    conformance::run(Flaky::new(DirBackend::open(dir.path()).unwrap())).await;
}

#[tokio::test]
async fn conformance_any() {
    conformance::run(AnyBackend::Mem(MemBackend::new())).await;
    let dir = tempfile::tempdir().unwrap();
    conformance::run(AnyBackend::Dir(DirBackend::open(dir.path()).unwrap())).await;
}

/// The suite also holds on a multi-threaded runtime (the engine spawns tasks).
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn conformance_on_worker_threads() {
    let dir = tempfile::tempdir().unwrap();
    let dir_backend = DirBackend::open(dir.path()).unwrap();
    let a = tokio::spawn(conformance::run(MemBackend::new()));
    let b = tokio::spawn(conformance::run(dir_backend));
    a.await.unwrap();
    b.await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// get_all / stream_body
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn stream_body_splits_at_multipart_max() {
    let at_limit = pattern(1, MULTIPART_MAX as usize);
    assert!(matches!(stream_body(at_limit), PutBody::Small(_)));
    assert!(matches!(stream_body(Bytes::new()), PutBody::Small(b) if b.is_empty()));

    let data = pattern(2, 2 * PART + 5);
    let PutBody::Stream { total, mut parts } = stream_body(data.clone()) else {
        panic!("a body above MULTIPART_MAX must be a Stream");
    };
    assert_eq!(total, data.len() as u64);
    let mut sizes = Vec::new();
    let mut joined = Vec::new();
    while let Some(part) = parts.recv().await {
        let part = part.unwrap();
        sizes.push(part.len());
        joined.extend_from_slice(&part);
    }
    assert_eq!(sizes, [PART, PART, 5]);
    assert!(joined == data);

    let just_over = pattern(3, MULTIPART_MAX as usize + 1);
    let PutBody::Stream { total, mut parts } = stream_body(just_over) else {
        panic!("MULTIPART_MAX + 1 must be a Stream");
    };
    assert_eq!(total, MULTIPART_MAX + 1);
    assert_eq!(parts.recv().await.unwrap().unwrap().len() as u64, total);
    assert!(parts.recv().await.is_none());
}

#[tokio::test]
async fn get_all_joins_chunks_and_passes_errors() {
    let b = MemBackend::new();
    let data = pattern(4, 1_000_000);
    let h = put(&b, &top(), "x", &data).await;
    assert!(get_all(&b, &h, None).await.unwrap() == data);
    assert!(get_all(&b, &h, Some(5..7)).await.unwrap() == data[5..7]);
    assert!(get_all(&b, &h, Some(7..7)).await.unwrap().is_empty());
    assert!(matches!(
        get_all(&b, &Handle("nope".into()), None).await,
        Err(BackendError::NotFound)
    ));
    let flaky = Flaky::new(b);
    flaky.cut_next_get(600_000);
    assert!(matches!(
        get_all(&flaky, &h, None).await,
        Err(BackendError::Transient(_))
    ));
}

// ---------------------------------------------------------------------------------------------
// MemBackend
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn mem_clones_share_one_store_and_clock() {
    let a = MemBackend::new();
    let b = a.clone();
    a.set_now_ms(1_000_000);
    assert_eq!(b.now_ms(), 1_000_000);
    let data = pattern(1, 10);
    let h = put(&a, &top(), "x", &data).await;
    assert_eq!(b.stat(&h).await.unwrap().unwrap().created_ms, 1_000_000);
    assert!(get_all(&b, &h, None).await.unwrap() == data);
    b.advance_ms(500);
    assert_eq!(a.now_ms(), 1_000_500);
    let f = folder(&b, &top(), "f").await;
    assert_eq!(a.stat(&f).await.unwrap().unwrap().created_ms, 1_000_500);
    // Ids never repeat across clones.
    let ids: HashSet<Handle> = [a.new_ids(3).await.unwrap(), b.new_ids(3).await.unwrap()]
        .concat()
        .into_iter()
        .collect();
    assert_eq!(ids.len(), 6);
}

#[tokio::test]
async fn mem_counters() {
    let b = MemBackend::new();
    assert_eq!(b.counters(), Counters::default());
    let f = folder(&b, &top(), "f").await; // new_ids + create_folder
    let data = pattern(1, 300_000);
    let h = put(&b, &f, "x", &data).await; // new_ids + put
    b.put(&h, &f, "x", PutBody::Small(pattern(2, 5)))
        .await
        .unwrap(); // answered from the existing id: counted, no bytes
    b.stat(&h).await.unwrap();
    b.list(&f).await.unwrap();
    b.list(&top()).await.unwrap();
    b.find_by_name("x").await.unwrap();
    b.trash(&h).await.unwrap();
    b.untrash(&h).await.unwrap();
    b.about().await.unwrap();
    get_all(&b, &h, Some(0..1000)).await.unwrap();
    let c = b.counters();
    assert_eq!(
        c,
        Counters {
            new_ids: 2,
            create_folder: 1,
            put: 2,
            put_bytes: 300_000,
            get: 1,
            get_bytes: 1000,
            stat: 1,
            list: 2,
            find_by_name: 1,
            trash: 1,
            untrash: 1,
            delete: 0,
            about: 1,
        }
    );

    // get_bytes counts what was actually handed out.
    b.reset_counters();
    let mut stream = b.get(&h, None).await.unwrap();
    let first = stream.next().await.unwrap().unwrap();
    drop(stream);
    assert!(
        first.len() < data.len(),
        "a get stream comes in several chunks"
    );
    assert_eq!(b.counters().get_bytes, first.len() as u64);
    assert_eq!(b.counters().get, 1);
    b.delete(&h).await.unwrap();
    assert_eq!(b.counters().delete, 1);
    b.reset_counters();
    assert_eq!(b.counters(), Counters::default());
}

#[tokio::test]
async fn mem_adversary_hooks() {
    let b = MemBackend::new();
    let f = folder(&b, &top(), "f").await;
    let one = pattern(1, 1000);
    let two = pattern(2, 2000);
    let h1 = put(&b, &f, "one", &one).await;
    let h2 = put(&b, &f, "two", &two).await;
    assert_eq!(b.all_objects().len(), 3);
    assert!(b.read(&h1).unwrap() == one);
    assert!(b.read(&f).is_none());
    assert!(b.read(&Handle("nope".into())).is_none());

    // tamper: the bytes change and the md5 follows (a server-consistent lie)
    b.tamper(&h1, |v| v[10] ^= 0xff);
    let tampered = b.read(&h1).unwrap();
    assert!(tampered != one);
    assert_eq!(tampered.len(), one.len());
    assert_eq!(
        b.stat(&h1).await.unwrap().unwrap().md5,
        Some(md5(&tampered))
    );
    b.tamper(&h1, |v| v.truncate(10));
    assert_eq!(b.stat(&h1).await.unwrap().unwrap().size, 10);

    // rename
    assert!(b.rename(&h2, "renamed"));
    assert!(!b.rename(&Handle("nope".into()), "x"));
    assert!(b.find_by_name("two").await.unwrap().is_empty());
    assert_eq!(b.find_by_name("renamed").await.unwrap()[0].handle, h2);

    // swap: h1 serves h2's bytes under its own id and name
    assert!(b.replace_content(&h1, &h2));
    assert!(!b.replace_content(&h1, &Handle("nope".into())));
    assert!(!b.replace_content(&Handle("nope".into()), &h2));
    assert!(!b.replace_content(&h1, &f));
    let swapped = b.stat(&h1).await.unwrap().unwrap();
    assert_eq!(swapped.name, "one");
    assert_eq!((swapped.size, swapped.md5), (2000, Some(md5(&two))));
    assert!(get_all(&b, &h1, None).await.unwrap() == two);

    // rollback: content goes back, the clock does not
    b.set_now_ms(5_000);
    let checkpoint = b.checkpoint();
    b.advance_ms(1_000);
    let h3 = put(&b, &f, "three", &pattern(3, 30)).await;
    b.trash(&h2).await.unwrap();
    assert!(b.hard_delete(&h1));
    assert!(!b.hard_delete(&h1));
    b.restore(&checkpoint);
    assert!(b.stat(&h3).await.unwrap().is_none());
    assert!(!b.stat(&h2).await.unwrap().unwrap().trashed);
    assert!(get_all(&b, &h1, None).await.unwrap() == two);
    assert_eq!(b.now_ms(), 6_000);
    // …and it can be replayed.
    b.restore(&checkpoint);
    assert_eq!(b.all_objects().len(), 3);
    // Ids handed out after the checkpoint are not handed out again.
    assert_ne!(id(&b).await, h3);

    // hard delete of a folder takes its content along
    assert!(b.hard_delete(&f));
    assert!(b.all_objects().is_empty());
    assert!(matches!(
        b.get(&h1, None).await,
        Err(BackendError::NotFound)
    ));
}

#[tokio::test]
#[should_panic(expected = "MemBackend::tamper")]
async fn mem_tamper_of_nothing_panics() {
    MemBackend::new().tamper(&Handle("nope".into()), |v| v.clear());
}

#[tokio::test]
async fn mem_behaves_like_drive() {
    let b = MemBackend::new();
    let f = folder(&b, &top(), "f").await;
    let sub = folder(&b, &f, "sub").await;
    let data = pattern(1, 100);
    let h = put(&b, &sub, "x", &data).await;

    // Two objects of one name in one folder.
    let twin = put(&b, &sub, "x", &pattern(2, 50)).await;
    assert_eq!(b.list(&sub).await.unwrap().len(), 2);
    assert_eq!(b.find_by_name("x").await.unwrap().len(), 2);
    b.delete(&twin).await.unwrap();

    // The top level is a folder.
    let t = b.stat(&top()).await.unwrap().unwrap();
    assert!(t.is_folder && t.handle.is_top() && !t.trashed);
    assert!(is_fatal(&b.get(&top(), None).await.err().unwrap(), 403));
    assert!(is_fatal(&b.get(&f, None).await.err().unwrap(), 403));
    assert!(is_fatal(&b.trash(&top()).await.unwrap_err(), 400));
    assert!(is_fatal(&b.delete(&top()).await.unwrap_err(), 400));

    // A trashed folder hides everything below it; the content stays readable.
    b.trash(&f).await.unwrap();
    assert!(b.stat(&h).await.unwrap().unwrap().trashed);
    assert!(b.stat(&sub).await.unwrap().unwrap().trashed);
    assert!(b.list(&sub).await.unwrap().is_empty());
    assert!(b.list(&f).await.unwrap().is_empty());
    assert!(b.list(&top()).await.unwrap().is_empty());
    assert!(b.find_by_name("x").await.unwrap().is_empty());
    assert!(get_all(&b, &h, None).await.unwrap() == data);
    let about = b.about().await.unwrap();
    assert_eq!((about.usage, about.usage_in_trash), (100, 100));
    b.untrash(&f).await.unwrap();
    assert!(!b.stat(&h).await.unwrap().unwrap().trashed);
    assert_eq!(b.list(&sub).await.unwrap().len(), 1);
    assert_eq!(b.about().await.unwrap().usage_in_trash, 0);

    // Unknown parents: nothing to list, nothing to create in.
    let nowhere = Handle("nowhere".into());
    assert!(b.list(&nowhere).await.unwrap().is_empty());
    let new = id(&b).await;
    let err = b
        .put(&new, &nowhere, "y", PutBody::Small(data.clone()))
        .await
        .unwrap_err();
    assert!(is_fatal(&err, 404), "{err}");
    assert!(is_fatal(
        &b.create_folder(&new, &nowhere, "y").await.unwrap_err(),
        404
    ));
    assert!(is_fatal(
        &b.create_folder(&new, &h, "y").await.unwrap_err(),
        404
    ));
    assert!(b.stat(&new).await.unwrap().is_none());
    // A file's id is not a folder.
    assert!(matches!(
        b.create_folder(&h, &top(), "f2").await,
        Err(BackendError::AlreadyExists)
    ));
    // A folder's id answers a put with the folder (the caller's size/md5 check then fails).
    let meta = b.put(&f, &top(), "z", PutBody::Small(data)).await.unwrap();
    assert!(meta.is_folder && meta.md5.is_none());

    // Deleting a folder deletes its content.
    b.delete(&f).await.unwrap();
    assert!(b.stat(&h).await.unwrap().is_none());
    assert!(b.all_objects().is_empty());
}

#[tokio::test]
async fn mem_enforces_the_put_body_contract() {
    let b = MemBackend::new();
    let h = id(&b).await;

    let too_big = PutBody::Small(pattern(1, MULTIPART_MAX as usize + 1));
    assert!(is_fatal(
        &b.put(&h, &top(), "x", too_big).await.unwrap_err(),
        400
    ));

    // A part that is neither PART_SIZE nor the last one.
    let (body, _) = fed_body(vec![Ok(pattern(2, 1000)), Ok(pattern(3, 1000))], 2000);
    assert!(is_fatal(
        &b.put(&h, &top(), "x", body).await.unwrap_err(),
        400
    ));

    // More bytes than announced.
    let (body, _) = fed_body(vec![Ok(pattern(4, 1000))], 999);
    assert!(is_fatal(
        &b.put(&h, &top(), "x", body).await.unwrap_err(),
        400
    ));

    // The channel closes early.
    let (body, _) = fed_body(vec![Ok(pattern(5, PART))], PART as u64 + 10);
    let err = b.put(&h, &top(), "x", body).await.unwrap_err();
    assert!(matches!(&err, BackendError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof));

    assert!(b.stat(&h).await.unwrap().is_none());
    assert!(b.all_objects().is_empty());
    assert_eq!(b.counters().put_bytes, 0);

    // A Stream may be small, and empty.
    let (body, _) = fed_body(vec![Ok(pattern(6, 1000))], 1000);
    assert_eq!(b.put(&h, &top(), "x", body).await.unwrap().size, 1000);
    let empty = id(&b).await;
    let (body, _) = fed_body(vec![], 0);
    let meta = b.put(&empty, &top(), "e", body).await.unwrap();
    assert_eq!((meta.size, meta.md5), (0, Some(md5(b""))));
    assert!(get_all(&b, &empty, None).await.unwrap().is_empty());

    // Ranges that start past the end are empty.
    assert!(get_all(&b, &h, Some(1000..2000)).await.unwrap().is_empty());
    assert!(get_all(&b, &h, Some(5000..6000)).await.unwrap().is_empty());
}

// ---------------------------------------------------------------------------------------------
// DirBackend
// ---------------------------------------------------------------------------------------------

/// A small vault-shaped tree: `gclone/{gclone-vault.json, index/s-1, data/dev-0000/blob}`.
struct Tree {
    root: Handle,
    index: Handle,
    data: Handle,
    dev: Handle,
    descriptor: Handle,
    segment: Handle,
    blob: Handle,
    descriptor_bytes: Bytes,
    segment_bytes: Bytes,
    blob_bytes: Bytes,
}

async fn build_tree<B: Backend>(b: &B) -> Tree {
    let root = folder(b, &top(), "gclone").await;
    let index = folder(b, &root, "index").await;
    let data = folder(b, &root, "data").await;
    let dev = folder(b, &data, "dev-0000").await;
    let descriptor_bytes = Bytes::from_static(br#"{"gclone_vault":1}"#);
    let segment_bytes = pattern(11, 40_000);
    let blob_bytes = pattern(12, MULTIPART_MAX as usize + 4321);
    Tree {
        descriptor: put(b, &root, "gclone-vault.json", &descriptor_bytes).await,
        segment: put(b, &index, "s-1", &segment_bytes).await,
        blob: put(b, &dev, "blob", &blob_bytes).await,
        root,
        index,
        data,
        dev,
        descriptor_bytes,
        segment_bytes,
        blob_bytes,
    }
}

#[tokio::test]
async fn dir_layout_is_plain_files() {
    let dir = tempfile::tempdir().unwrap();
    let b = DirBackend::open(dir.path()).unwrap();
    assert_eq!(b.root(), dir.path());
    let t = build_tree(&b).await;
    let on_disk = |rel: &str| fs::read(dir.path().join(rel)).unwrap();
    assert!(on_disk("gclone/gclone-vault.json") == t.descriptor_bytes);
    assert!(on_disk("gclone/index/s-1") == t.segment_bytes);
    assert!(on_disk("gclone/data/dev-0000/blob") == t.blob_bytes);
    assert!(dir.path().join(IDS_FILE).is_file());
    // No spool file is left behind.
    assert_eq!(
        fs::read_dir(dir.path().join(".gclone-tmp"))
            .unwrap()
            .count(),
        0
    );

    b.trash(&t.segment).await.unwrap();
    assert!(!dir.path().join("gclone/index/s-1").exists());
    assert!(dir.path().join(".trash").is_dir());
    b.delete(&t.segment).await.unwrap();
    assert_eq!(fs::read_dir(dir.path().join(".trash")).unwrap().count(), 0);

    // created_ms is the file's mtime: just now.
    let meta = b.stat(&t.blob).await.unwrap().unwrap();
    assert!(b.now_ms().abs_diff(meta.created_ms) < 60_000);
}

#[tokio::test]
async fn dir_open_needs_an_existing_directory_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        DirBackend::open(&dir.path().join("missing")),
        Err(BackendError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound
    ));
    let file = dir.path().join("file");
    fs::write(&file, b"x").unwrap();
    assert!(matches!(DirBackend::open(&file), Err(BackendError::Io(_))));
    fs::remove_file(&file).unwrap();

    let b = DirBackend::open(dir.path()).unwrap();
    assert!(b.list(&top()).await.unwrap().is_empty());
    assert!(b.find_by_name("x").await.unwrap().is_empty());
    assert!(b.stat(&Handle("abc".into())).await.unwrap().is_none());
    assert_eq!(b.new_ids(2).await.unwrap().len(), 2);
    let about = b.about().await.unwrap();
    assert_eq!((about.usage, about.usage_in_trash), (0, 0));
    assert_eq!(
        fs::read_dir(dir.path()).unwrap().count(),
        0,
        "reads must not write"
    );
}

#[tokio::test]
async fn dir_reopen_sees_everything() {
    let dir = tempfile::tempdir().unwrap();
    let t;
    let trashed;
    let before;
    {
        let b = DirBackend::open(dir.path()).unwrap();
        t = build_tree(&b).await;
        trashed = put(&b, &t.index, "s-old", &pattern(20, 500)).await;
        b.trash(&trashed).await.unwrap();
        before = b.stat(&t.blob).await.unwrap().unwrap();
    }
    let b = DirBackend::open(dir.path()).unwrap();
    for (h, name, parent, bytes) in [
        (
            &t.descriptor,
            "gclone-vault.json",
            &t.root,
            &t.descriptor_bytes,
        ),
        (&t.segment, "s-1", &t.index, &t.segment_bytes),
        (&t.blob, "blob", &t.dev, &t.blob_bytes),
    ] {
        let meta = b.stat(h).await.unwrap().expect("ids survive a reopen");
        assert_eq!(meta.handle, *h);
        assert_eq!(meta.name, name);
        assert_eq!(meta.parent, *parent);
        assert_eq!(
            (meta.size, meta.md5),
            (bytes.len() as u64, Some(md5(bytes)))
        );
        assert!(!meta.is_folder && !meta.trashed);
        assert!(get_all(&b, h, None).await.unwrap() == *bytes);
    }
    assert_eq!(
        b.stat(&t.blob).await.unwrap().unwrap().created_ms,
        before.created_ms
    );
    for (h, name, parent) in [
        (&t.root, "gclone", &top()),
        (&t.index, "index", &t.root),
        (&t.data, "data", &t.root),
        (&t.dev, "dev-0000", &t.data),
    ] {
        let meta = b
            .stat(h)
            .await
            .unwrap()
            .expect("folder ids survive a reopen");
        assert!(meta.is_folder);
        assert_eq!((meta.name.as_str(), &meta.parent), (name, parent));
    }
    // Listings answer with the same ids.
    let listed = b.list(&t.root).await.unwrap();
    assert_eq!(names(&listed), ["data", "gclone-vault.json", "index"]);
    let handles: HashSet<Handle> = listed.into_iter().map(|m| m.handle).collect();
    assert_eq!(
        handles,
        HashSet::from([t.data.clone(), t.descriptor.clone(), t.index.clone()])
    );
    assert_eq!(b.list(&top()).await.unwrap()[0].handle, t.root);
    assert_eq!(b.find_by_name("blob").await.unwrap()[0].handle, t.blob);
    // The trash survives too.
    assert_eq!(names(&b.list(&t.index).await.unwrap()), ["s-1"]);
    let meta = b.stat(&trashed).await.unwrap().unwrap();
    assert!(meta.trashed);
    assert_eq!(meta.parent, t.index);
    assert!(get_all(&b, &trashed, None).await.unwrap() == pattern(20, 500));
    b.untrash(&trashed).await.unwrap();
    assert_eq!(names(&b.list(&t.index).await.unwrap()), ["s-1", "s-old"]);
    // Put-once holds across the reopen.
    let again = b
        .put(&t.segment, &t.index, "s-1", PutBody::Small(pattern(21, 9)))
        .await
        .unwrap();
    assert_eq!(again.size, t.segment_bytes.len() as u64);
}

#[tokio::test]
async fn dir_copy_without_the_id_map_serves_path_handles() {
    let dir = tempfile::tempdir().unwrap();
    let t = build_tree(&DirBackend::open(dir.path()).unwrap()).await;
    let copy = tempfile::tempdir().unwrap();
    copy_tree(dir.path(), copy.path(), &[IDS_FILE]);
    assert!(!copy.path().join(IDS_FILE).exists());
    let b = DirBackend::open(copy.path()).unwrap();

    // Ids recorded elsewhere are gone; names still resolve.
    assert!(b.stat(&t.blob).await.unwrap().is_none());
    assert!(matches!(
        b.get(&t.blob, None).await,
        Err(BackendError::NotFound)
    ));
    assert!(b.list(&t.index).await.unwrap().is_empty());

    let found = b.find_by_name("gclone-vault.json").await.unwrap();
    assert_eq!(found.len(), 1);
    let descriptor = &found[0];
    assert_eq!(
        descriptor.handle,
        Handle("p:gclone/gclone-vault.json".into())
    );
    assert_eq!(descriptor.parent, Handle("p:gclone".into()));
    assert_eq!(
        (descriptor.size, descriptor.md5),
        (
            t.descriptor_bytes.len() as u64,
            Some(md5(&t.descriptor_bytes))
        )
    );
    assert!(get_all(&b, &descriptor.handle, None).await.unwrap() == t.descriptor_bytes);

    let in_top = b.list(&top()).await.unwrap();
    assert_eq!(names(&in_top), ["gclone"]);
    assert_eq!(in_top[0].handle, descriptor.parent);
    assert_eq!(in_top[0].parent, top());
    assert!(in_top[0].is_folder);

    let in_root = b.list(&descriptor.parent).await.unwrap();
    assert_eq!(names(&in_root), ["data", "gclone-vault.json", "index"]);
    assert!(in_root.iter().all(|m| m.parent == descriptor.parent));
    let index = in_root.iter().find(|m| m.name == "index").unwrap();
    let segments = b.list(&index.handle).await.unwrap();
    assert_eq!(names(&segments), ["s-1"]);
    assert_eq!(segments[0].md5, Some(md5(&t.segment_bytes)));
    assert!(get_all(&b, &segments[0].handle, None).await.unwrap() == t.segment_bytes);

    let blob = &b.find_by_name("blob").await.unwrap()[0];
    assert_eq!(blob.handle, Handle("p:gclone/data/dev-0000/blob".into()));
    assert_eq!(blob.md5, Some(md5(&t.blob_bytes)));
    assert!(get_all(&b, &blob.handle, Some(100..5000)).await.unwrap() == t.blob_bytes[100..5000]);
    let stat = b.stat(&blob.handle).await.unwrap().unwrap();
    assert_eq!(stat.handle, blob.handle);
    assert_eq!(stat.parent, Handle("p:gclone/data/dev-0000".into()));
    assert!(!stat.trashed);

    // Path handles cannot leave the directory or name its private files.
    for bad in [
        "p:../x",
        "p:gclone/../gclone",
        "p:/etc/passwd",
        "p:",
        "p:.gclone-dir-ids.json",
    ] {
        assert!(
            b.stat(&Handle(bad.into())).await.unwrap().is_none(),
            "{bad}"
        );
    }

    // The copy is a working vault: new objects get ids, old ones keep their path handles…
    let new_bytes = pattern(30, 2000);
    let new = put(&b, &index.handle, "s-2", &new_bytes).await;
    assert!(!new.0.starts_with("p:"));
    assert_eq!(b.stat(&new).await.unwrap().unwrap().parent, index.handle);
    assert_eq!(names(&b.list(&index.handle).await.unwrap()), ["s-1", "s-2"]);
    assert!(fs::read(copy.path().join("gclone/index/s-2")).unwrap() == new_bytes);
    // …also through trash and untrash.
    let seg = segments[0].handle.clone();
    b.trash(&seg).await.unwrap();
    b.trash(&seg).await.unwrap();
    let stat = b.stat(&seg).await.unwrap().unwrap();
    assert!(stat.trashed);
    assert_eq!(
        (stat.handle.clone(), stat.parent.clone()),
        (seg.clone(), index.handle.clone())
    );
    assert!(get_all(&b, &seg, None).await.unwrap() == t.segment_bytes);
    assert_eq!(names(&b.list(&index.handle).await.unwrap()), ["s-2"]);
    assert!(b.find_by_name("s-1").await.unwrap().is_empty());
    b.untrash(&seg).await.unwrap();
    b.untrash(&seg).await.unwrap();
    assert!(!b.stat(&seg).await.unwrap().unwrap().trashed);
    assert_eq!(names(&b.list(&index.handle).await.unwrap()), ["s-1", "s-2"]);
    b.delete(&seg).await.unwrap();
    assert!(b.stat(&seg).await.unwrap().is_none());
    assert!(matches!(b.delete(&seg).await, Err(BackendError::NotFound)));

    // A put whose name is already there (same object, new id) adopts the file instead of
    // overwriting it; the caller sees the existing size and md5.
    let adopt = id(&b).await;
    let meta = b
        .put(
            &adopt,
            &descriptor.parent,
            "gclone-vault.json",
            PutBody::Small(pattern(31, 7)),
        )
        .await
        .unwrap();
    assert_eq!(meta.handle, adopt);
    assert_eq!(meta.md5, Some(md5(&t.descriptor_bytes)));
    assert!(get_all(&b, &adopt, None).await.unwrap() == t.descriptor_bytes);
    assert_eq!(
        b.find_by_name("gclone-vault.json").await.unwrap()[0].handle,
        adopt
    );
    // The same for a folder.
    let data_id = id(&b).await;
    b.create_folder(&data_id, &descriptor.parent, "data")
        .await
        .unwrap();
    assert_eq!(names(&b.list(&data_id).await.unwrap()), ["dev-0000"]);
}

#[tokio::test]
async fn dir_inner_vault_folder_as_root() {
    let dir = tempfile::tempdir().unwrap();
    let t = build_tree(&DirBackend::open(dir.path()).unwrap()).await;
    // What a web download of the vault folder yields: its content, no id map.
    let copy = tempfile::tempdir().unwrap();
    copy_tree(&dir.path().join("gclone"), copy.path(), &[]);
    let b = DirBackend::open(copy.path()).unwrap();

    let found = b.find_by_name("gclone-vault.json").await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].parent, top(), "the vault root is the top level");
    assert_eq!(found[0].handle, Handle("p:gclone-vault.json".into()));
    assert!(get_all(&b, &found[0].handle, None).await.unwrap() == t.descriptor_bytes);

    let in_top = b.list(&top()).await.unwrap();
    assert_eq!(names(&in_top), ["data", "gclone-vault.json", "index"]);
    assert!(in_top.iter().all(|m| m.parent == top()));
    let index = in_top.iter().find(|m| m.name == "index").unwrap();
    let segments = b.list(&index.handle).await.unwrap();
    assert_eq!(names(&segments), ["s-1"]);
    assert_eq!(segments[0].parent, index.handle);
    assert!(get_all(&b, &segments[0].handle, None).await.unwrap() == t.segment_bytes);

    // The vault root itself can be stat-ed (it is never "missing" or "trashed").
    let root = b.stat(&top()).await.unwrap().unwrap();
    assert!(root.is_folder && root.handle.is_top() && root.parent.is_top() && !root.trashed);
    assert!(is_fatal(&b.trash(&top()).await.unwrap_err(), 400));
    assert!(is_fatal(&b.delete(&top()).await.unwrap_err(), 400));
    assert!(is_fatal(&b.get(&top(), None).await.err().unwrap(), 403));

    // Writing at the top level works.
    let h = put(&b, &top(), "gclone-key-00000002-abcdef01", &pattern(1, 300)).await;
    assert_eq!(b.stat(&h).await.unwrap().unwrap().parent, top());
    assert!(copy.path().join("gclone-key-00000002-abcdef01").is_file());
}

#[tokio::test]
async fn dir_ignores_dot_names_and_refuses_unstorable_ones() {
    let dir = tempfile::tempdir().unwrap();
    let b = DirBackend::open(dir.path()).unwrap();
    let f = folder(&b, &top(), "f").await;
    let h = put(&b, &f, "x", &pattern(1, 10)).await;
    b.trash(&h).await.unwrap();
    b.untrash(&h).await.unwrap();
    fs::write(dir.path().join(".DS_Store"), b"junk").unwrap();
    fs::write(dir.path().join("f/.DS_Store"), b"junk").unwrap();
    fs::write(dir.path().join("f/._x"), b"junk").unwrap();
    std::os::unix::fs::symlink(dir.path().join("f/x"), dir.path().join("f/link")).unwrap();

    assert_eq!(names(&b.list(&top()).await.unwrap()), ["f"]);
    assert_eq!(names(&b.list(&f).await.unwrap()), ["x"]);
    assert!(b.find_by_name(".DS_Store").await.unwrap().is_empty());
    assert!(b.find_by_name("link").await.unwrap().is_empty());
    assert!(b.find_by_name(IDS_FILE).await.unwrap().is_empty());
    assert!(b.stat(&Handle("p:f/link".into())).await.unwrap().is_none());
    assert_eq!(b.about().await.unwrap().usage, 10);

    for name in [".hidden", "", "a/b", ".", "..", ".trash", IDS_FILE] {
        let new = id(&b).await;
        let err = b
            .put(&new, &f, name, PutBody::Small(pattern(2, 5)))
            .await
            .unwrap_err();
        assert!(is_fatal(&err, 400), "{name:?}: {err}");
        assert!(is_fatal(
            &b.create_folder(&new, &f, name).await.unwrap_err(),
            400
        ));
    }
    // Ids must not look like path handles or the top level.
    for bad in ["p:f/y", ""] {
        let err = b
            .put(&Handle(bad.into()), &f, "y", PutBody::Small(pattern(3, 5)))
            .await
            .unwrap_err();
        assert!(is_fatal(&err, 400));
    }
    assert!(!dir.path().join("f/y").exists());
}

#[tokio::test]
async fn dir_one_name_one_object() {
    let dir = tempfile::tempdir().unwrap();
    let b = DirBackend::open(dir.path()).unwrap();
    let f = folder(&b, &top(), "f").await;
    let original = pattern(1, 1000);
    let h = put(&b, &f, "x", &original).await;

    // Another id for a name that is taken: refused, nothing overwritten.
    let other = id(&b).await;
    let err = b
        .put(&other, &f, "x", PutBody::Small(pattern(2, 10)))
        .await
        .unwrap_err();
    assert!(is_fatal(&err, 409), "{err}");
    assert!(b.stat(&other).await.unwrap().is_none());
    assert!(get_all(&b, &h, None).await.unwrap() == original);
    assert!(is_fatal(
        &b.create_folder(&other, &f, "x").await.unwrap_err(),
        409
    ));
    // A folder with content that another id owns: refused.
    assert!(is_fatal(
        &b.create_folder(&other, &top(), "f").await.unwrap_err(),
        409
    ));
    assert!(is_fatal(
        &b.put(&other, &top(), "f", PutBody::Small(pattern(3, 10)))
            .await
            .unwrap_err(),
        409
    ));

    // An empty folder is adopted by a second id (a device that lost the first one).
    let empty = folder(&b, &f, "empty").await;
    let second = id(&b).await;
    b.create_folder(&second, &f, "empty").await.unwrap();
    for h in [&empty, &second] {
        let meta = b.stat(h).await.unwrap().unwrap();
        assert!(meta.is_folder);
        assert_eq!((&meta.handle, meta.name.as_str()), (h, "empty"));
    }
    let inside = put(&b, &second, "y", &pattern(4, 20)).await;
    assert_eq!(names(&b.list(&empty).await.unwrap()), ["y"]);
    assert_eq!(names(&b.list(&second).await.unwrap()), ["y"]);
    assert_eq!(b.list(&second).await.unwrap()[0].parent, second);
    // Both ids follow the folder into the trash and back, also across a reopen.
    b.trash(&second).await.unwrap();
    let b = DirBackend::open(dir.path()).unwrap();
    assert!(b.stat(&empty).await.unwrap().unwrap().trashed);
    assert!(b.stat(&inside).await.unwrap().unwrap().trashed);
    b.untrash(&empty).await.unwrap();
    assert!(!b.stat(&second).await.unwrap().unwrap().trashed);
    assert!(!b.stat(&inside).await.unwrap().unwrap().trashed);

    // Once the name is free again it can be reused; the old id stays gone.
    b.delete(&h).await.unwrap();
    let reused = pattern(5, 30);
    let h2 = put(&b, &f, "x", &reused).await;
    assert!(b.stat(&h).await.unwrap().is_none());
    assert!(get_all(&b, &h2, None).await.unwrap() == reused);
    // The same after the file was removed behind the backend's back.
    fs::remove_file(dir.path().join("f/x")).unwrap();
    assert!(b.stat(&h2).await.unwrap().is_none());
    let h3 = put(&b, &f, "x", &original).await;
    assert!(
        b.stat(&h2).await.unwrap().is_none(),
        "a stale id must not name the new object"
    );
    assert!(get_all(&b, &h3, None).await.unwrap() == original);
}

#[tokio::test]
async fn dir_trashed_folders_and_untrash_targets() {
    let dir = tempfile::tempdir().unwrap();
    let b = DirBackend::open(dir.path()).unwrap();
    let t = build_tree(&b).await;

    // A trashed folder takes its content along; everything stays readable by id.
    b.trash(&t.data).await.unwrap();
    for h in [&t.data, &t.dev, &t.blob] {
        assert!(b.stat(h).await.unwrap().unwrap().trashed);
    }
    assert_eq!(b.stat(&t.data).await.unwrap().unwrap().parent, t.root);
    assert_eq!(b.stat(&t.blob).await.unwrap().unwrap().parent, t.dev);
    assert!(b.list(&t.data).await.unwrap().is_empty());
    assert!(b.list(&t.dev).await.unwrap().is_empty());
    assert_eq!(
        names(&b.list(&t.root).await.unwrap()),
        ["gclone-vault.json", "index"]
    );
    assert!(b.find_by_name("blob").await.unwrap().is_empty());
    assert!(get_all(&b, &t.blob, None).await.unwrap() == t.blob_bytes);
    let about = b.about().await.unwrap();
    assert_eq!(about.usage_in_trash, t.blob_bytes.len() as u64);
    assert_eq!(
        about.usage,
        (t.blob_bytes.len() + t.segment_bytes.len() + t.descriptor_bytes.len()) as u64
    );
    // Trashing or untrashing what is only trashed through its folder changes nothing.
    b.trash(&t.blob).await.unwrap();
    b.untrash(&t.blob).await.unwrap();
    assert!(b.stat(&t.blob).await.unwrap().unwrap().trashed);

    // The name can be taken while the original is in the trash; then untrash is refused.
    let data2 = folder(&b, &t.root, "data").await;
    assert_ne!(data2, t.data);
    assert!(is_fatal(&b.untrash(&t.data).await.unwrap_err(), 409));
    assert!(b.stat(&t.data).await.unwrap().unwrap().trashed);
    b.delete(&data2).await.unwrap();
    b.untrash(&t.data).await.unwrap();
    for h in [&t.data, &t.dev, &t.blob] {
        assert!(!b.stat(h).await.unwrap().unwrap().trashed);
    }
    assert_eq!(b.find_by_name("blob").await.unwrap()[0].handle, t.blob);
    assert_eq!(b.about().await.unwrap().usage_in_trash, 0);

    // An object trashed before its folder comes back into the trashed folder.
    b.trash(&t.segment).await.unwrap();
    b.trash(&t.index).await.unwrap();
    b.untrash(&t.segment).await.unwrap();
    assert!(
        b.stat(&t.segment).await.unwrap().unwrap().trashed,
        "its folder is still trashed"
    );
    b.untrash(&t.index).await.unwrap();
    assert!(!b.stat(&t.segment).await.unwrap().unwrap().trashed);
    assert_eq!(names(&b.list(&t.index).await.unwrap()), ["s-1"]);

    // …and has nowhere to go once the folder is deleted.
    b.trash(&t.segment).await.unwrap();
    b.delete(&t.index).await.unwrap();
    assert!(is_fatal(&b.untrash(&t.segment).await.unwrap_err(), 404));
    assert!(get_all(&b, &t.segment, None).await.unwrap() == t.segment_bytes);

    // Deleting a folder deletes its content.
    b.delete(&t.root).await.unwrap();
    for h in [&t.root, &t.data, &t.dev, &t.blob, &t.descriptor] {
        assert!(b.stat(h).await.unwrap().is_none());
    }
    assert!(b.list(&top()).await.unwrap().is_empty());
    assert!(!dir.path().join("gclone").exists());
}

#[tokio::test]
async fn dir_two_openers_see_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let a = DirBackend::open(dir.path()).unwrap();
    let b = DirBackend::open(dir.path()).unwrap();
    assert!(b.find_by_name("x").await.unwrap().is_empty());

    let f = folder(&a, &top(), "f").await;
    let data = pattern(1, 5000);
    let h = put(&a, &f, "x", &data).await;
    let meta = b
        .stat(&h)
        .await
        .unwrap()
        .expect("the other opener's id resolves");
    assert_eq!(
        (meta.parent.clone(), meta.md5),
        (f.clone(), Some(md5(&data)))
    );
    assert_eq!(b.list(&f).await.unwrap()[0].handle, h);
    assert_eq!(b.find_by_name("x").await.unwrap()[0].handle, h);
    // Put-once across openers.
    let again = b
        .put(&h, &f, "x", PutBody::Small(pattern(2, 9)))
        .await
        .unwrap();
    assert_eq!(again.size, 5000);

    b.trash(&h).await.unwrap();
    assert!(a.stat(&h).await.unwrap().unwrap().trashed);
    assert!(a.list(&f).await.unwrap().is_empty());
    assert!(a.find_by_name("x").await.unwrap().is_empty());
    a.untrash(&h).await.unwrap();
    assert!(!b.stat(&h).await.unwrap().unwrap().trashed);
    b.delete(&h).await.unwrap();
    assert!(a.stat(&h).await.unwrap().is_none());
    assert!(matches!(a.get(&h, None).await, Err(BackendError::NotFound)));

    // Concurrent puts from both openers all land, each under its id.
    let mut tasks = Vec::new();
    for i in 0..16u8 {
        let backend = if i % 2 == 0 { a.clone() } else { b.clone() };
        let f = f.clone();
        tasks.push(tokio::spawn(async move {
            let data = pattern(100 + i, 3000 + i as usize);
            (put(&backend, &f, &format!("obj-{i:02}"), &data).await, data)
        }));
    }
    for task in tasks {
        let (h, data) = task.await.unwrap();
        assert!(get_all(&a, &h, None).await.unwrap() == data);
        assert_eq!(b.stat(&h).await.unwrap().unwrap().md5, Some(md5(&data)));
    }
    assert_eq!(a.list(&f).await.unwrap().len(), 16);
    let c = DirBackend::open(dir.path()).unwrap();
    assert_eq!(c.list(&f).await.unwrap().len(), 16);
    assert!(
        c.list(&f)
            .await
            .unwrap()
            .iter()
            .all(|m| !m.handle.0.starts_with("p:"))
    );
}

#[tokio::test]
async fn dir_journal_is_compacted_and_survives_damage() {
    let dir = tempfile::tempdir().unwrap();
    let journal = dir.path().join(IDS_FILE);
    let lines = || fs::read_to_string(&journal).unwrap().lines().count();
    let b = DirBackend::open(dir.path()).unwrap();
    let f = folder(&b, &top(), "f").await;
    let data = pattern(1, 100);
    let h = put(&b, &f, "x", &data).await;
    let kept_in_trash = put(&b, &f, "old", &pattern(2, 50)).await;
    b.trash(&kept_in_trash).await.unwrap();
    for _ in 0..40 {
        b.trash(&h).await.unwrap();
        b.untrash(&h).await.unwrap();
    }
    let before = lines();
    assert!(
        before > 150,
        "every change is one or two appended records ({before})"
    );

    // Reopening rewrites a journal that is mostly history; nothing is forgotten.
    let b = DirBackend::open(dir.path()).unwrap();
    assert!(
        lines() <= 4,
        "compacted to one record per binding and trash slot ({})",
        lines()
    );
    let meta = b.stat(&h).await.unwrap().unwrap();
    assert_eq!(
        (meta.parent.clone(), meta.md5, meta.trashed),
        (f.clone(), Some(md5(&data)), false)
    );
    assert!(b.stat(&f).await.unwrap().unwrap().is_folder);
    assert!(b.stat(&kept_in_trash).await.unwrap().unwrap().trashed);
    b.untrash(&kept_in_trash).await.unwrap();
    assert_eq!(names(&b.list(&f).await.unwrap()), ["old", "x"]);

    // An opener that read the old journal notices the replacement.
    let stale = DirBackend::open(dir.path()).unwrap();
    for _ in 0..40 {
        b.trash(&h).await.unwrap();
        b.untrash(&h).await.unwrap();
    }
    let _compacting = DirBackend::open(dir.path()).unwrap();
    assert!(lines() <= 4);
    let late = put(&b, &f, "late", &pattern(3, 10)).await;
    assert!(stale.stat(&late).await.unwrap().is_some());
    assert!(stale.stat(&h).await.unwrap().is_some());

    // A torn last record (crash in the middle of an append) and foreign lines are skipped.
    let mut raw = fs::read(&journal).unwrap();
    raw.extend_from_slice(
        b"{\"op\":\"future-thing\",\"x\":1}\nnot json at all\n{\"op\":\"bind\",\"id\":\"tor",
    );
    fs::write(&journal, raw).unwrap();
    let b = DirBackend::open(dir.path()).unwrap();
    assert!(b.stat(&h).await.unwrap().is_some());
    let after = put(&b, &f, "after", &pattern(4, 10)).await;
    let b = DirBackend::open(dir.path()).unwrap();
    for h in [&h, &late, &after, &kept_in_trash, &f] {
        assert!(b.stat(h).await.unwrap().is_some());
    }

    // Without the journal the objects are still there, by name.
    fs::remove_file(&journal).unwrap();
    assert!(b.stat(&h).await.unwrap().is_none());
    assert_eq!(
        b.find_by_name("x").await.unwrap()[0].handle,
        Handle("p:f/x".into())
    );
}

#[tokio::test]
async fn dir_md5_follows_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let b = DirBackend::open(dir.path()).unwrap();
    let h = put(&b, &top(), "x", &pattern(1, 1000)).await;
    // Changed behind the backend's back (other size): the recorded md5 is not trusted.
    let changed = pattern(2, 1234);
    fs::write(dir.path().join("x"), &changed).unwrap();
    let meta = b.stat(&h).await.unwrap().unwrap();
    assert_eq!((meta.size, meta.md5), (1234, Some(md5(&changed))));
    assert_eq!(b.list(&top()).await.unwrap()[0].md5, Some(md5(&changed)));
    assert!(get_all(&b, &h, None).await.unwrap() == changed);
    // Ranges are clamped to the file as it is.
    assert!(get_all(&b, &h, Some(1200..9999)).await.unwrap() == changed[1200..]);
    assert!(get_all(&b, &h, Some(5000..9999)).await.unwrap().is_empty());
}

#[tokio::test]
async fn dir_failed_puts_leave_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let b = DirBackend::open(dir.path()).unwrap();
    let f = folder(&b, &top(), "f").await;
    let spool_is_empty = || {
        fs::read_dir(dir.path().join(".gclone-tmp"))
            .map_or(true, |mut entries| entries.next().is_none())
    };

    let h = id(&b).await;
    let (body, _) = fed_body(
        vec![Ok(pattern(1, PART)), Err(std::io::Error::other("changed"))],
        2 * PART_SIZE,
    );
    assert!(matches!(
        b.put(&h, &f, "x", body).await,
        Err(BackendError::Io(_))
    ));
    let (body, _) = fed_body(vec![Ok(pattern(2, PART))], PART_SIZE + 200); // closes early
    assert!(matches!(
        b.put(&h, &f, "x", body).await,
        Err(BackendError::Io(_))
    ));
    let (body, _) = fed_body(vec![Ok(pattern(3, 100)), Ok(pattern(4, 100))], 200); // bad part size
    assert!(is_fatal(&b.put(&h, &f, "x", body).await.unwrap_err(), 400));
    let too_big = PutBody::Small(pattern(5, MULTIPART_MAX as usize + 1));
    assert!(is_fatal(
        &b.put(&h, &f, "x", too_big).await.unwrap_err(),
        400
    ));
    let nowhere = Handle("nowhere".into());
    let err = b
        .put(&h, &nowhere, "x", PutBody::Small(pattern(6, 5)))
        .await
        .unwrap_err();
    assert!(is_fatal(&err, 404));
    assert!(is_fatal(
        &b.create_folder(&h, &nowhere, "x").await.unwrap_err(),
        404
    ));

    assert!(b.stat(&h).await.unwrap().is_none());
    assert!(b.list(&f).await.unwrap().is_empty());
    assert!(!dir.path().join("f/x").exists());
    assert!(spool_is_empty());

    // A put that is dropped half-way leaves nothing either.
    let (tx, rx) = mpsc::channel(1);
    tx.send(Ok(pattern(7, PART))).await.unwrap();
    let body = PutBody::Stream {
        total: 2 * PART_SIZE,
        parts: rx,
    };
    let pending = b.put(&h, &f, "x", body);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(300), pending)
            .await
            .is_err()
    );
    // The blocking write that was under way may still be finishing.
    for _ in 0..100 {
        if spool_is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(spool_is_empty());
    assert!(b.stat(&h).await.unwrap().is_none());

    // The id is still usable.
    let data = pattern(8, 100);
    let meta = b
        .put(&h, &f, "x", PutBody::Small(data.clone()))
        .await
        .unwrap();
    assert_eq!(meta.md5, Some(md5(&data)));
}

// ---------------------------------------------------------------------------------------------
// Flaky
// ---------------------------------------------------------------------------------------------

/// A flaky Mem backend with one folder and one stored object.
async fn flaky_with_object() -> (Flaky<MemBackend>, Handle, Handle, Bytes) {
    let b = Flaky::new(MemBackend::new());
    let f = folder(&b, &top(), "f").await;
    let data = pattern(1, 700_000);
    let h = put(&b, &f, "obj", &data).await;
    (b, f, h, data)
}

#[tokio::test]
async fn flaky_fail_next_fails_exactly_that_many_calls() {
    let (b, f, h, _) = flaky_with_object().await;
    let inner_before = b.inner().counters();

    b.fail_next(OpKind::Stat, 2, transient);
    assert!(matches!(b.stat(&h).await, Err(BackendError::Transient(_))));
    b.list(&f).await.unwrap(); // other operations are untouched
    assert!(matches!(b.stat(&h).await, Err(BackendError::Transient(_))));
    assert!(b.stat(&h).await.unwrap().is_some());
    // The failed calls never reached the inner backend.
    assert_eq!(b.inner().counters().stat, inner_before.stat + 1);

    // Every operation kind can fail, and the failure is the one that was made.
    let new = id(&b).await;
    b.fail_next(OpKind::NewIds, 1, quota);
    b.fail_next(OpKind::CreateFolder, 1, quota);
    b.fail_next(OpKind::Put, 1, quota);
    b.fail_next(OpKind::Get, 1, quota);
    b.fail_next(OpKind::List, 1, quota);
    b.fail_next(OpKind::FindByName, 1, quota);
    b.fail_next(OpKind::Trash, 1, quota);
    b.fail_next(OpKind::Untrash, 1, quota);
    b.fail_next(OpKind::Delete, 1, quota);
    b.fail_next(OpKind::About, 1, quota);
    let is_quota =
        |e: BackendError| matches!(e, BackendError::QuotaExceeded(QuotaKind::StorageFull));
    assert!(is_quota(b.new_ids(1).await.unwrap_err()));
    assert!(is_quota(b.create_folder(&new, &f, "g").await.unwrap_err()));
    assert!(is_quota(
        b.put(&new, &f, "p", PutBody::Small(pattern(2, 5)))
            .await
            .unwrap_err()
    ));
    assert!(is_quota(b.get(&h, None).await.err().unwrap()));
    assert!(is_quota(b.list(&f).await.unwrap_err()));
    assert!(is_quota(b.find_by_name("obj").await.unwrap_err()));
    assert!(is_quota(b.trash(&h).await.unwrap_err()));
    assert!(is_quota(b.untrash(&h).await.unwrap_err()));
    assert!(is_quota(b.delete(&h).await.unwrap_err()));
    assert!(is_quota(b.about().await.unwrap_err()));
    // Nothing happened, and everything works again.
    assert!(b.stat(&new).await.unwrap().is_none());
    assert!(!b.stat(&h).await.unwrap().unwrap().trashed);
    b.new_ids(1).await.unwrap();
    b.create_folder(&new, &f, "g").await.unwrap();
    drop(b.get(&h, None).await.unwrap());
    b.list(&f).await.unwrap();
    b.find_by_name("obj").await.unwrap();
    b.trash(&h).await.unwrap();
    b.untrash(&h).await.unwrap();
    b.about().await.unwrap();

    // u32::MAX = until cleared.
    b.fail_next(OpKind::Delete, u32::MAX, transient);
    for _ in 0..5 {
        assert!(b.delete(&h).await.is_err());
    }
    b.clear();
    b.delete(&h).await.unwrap();
}

#[tokio::test]
async fn flaky_fail_nth_counts_from_now() {
    let (b, _, h, _) = flaky_with_object().await;
    b.stat(&h).await.unwrap();
    b.stat(&h).await.unwrap();
    b.fail_nth(OpKind::Stat, 3, transient);
    b.fail_nth(OpKind::Stat, 5, quota);
    b.stat(&h).await.unwrap();
    b.list(&top()).await.unwrap(); // another kind does not count
    b.stat(&h).await.unwrap();
    assert!(matches!(b.stat(&h).await, Err(BackendError::Transient(_))));
    b.stat(&h).await.unwrap();
    assert!(matches!(
        b.stat(&h).await,
        Err(BackendError::QuotaExceeded(_))
    ));
    for _ in 0..4 {
        b.stat(&h).await.unwrap();
    }
    b.fail_nth(OpKind::Get, 1, transient);
    assert!(b.get(&h, None).await.is_err());
    assert!(b.get(&h, None).await.is_ok());
}

#[tokio::test]
async fn flaky_fail_put_named() {
    let (b, f, _, _) = flaky_with_object().await;
    let body = || PutBody::Small(pattern(2, 100));
    let seg = id(&b).await;
    b.fail_put_named("s-", 2, quota);
    assert!(matches!(
        b.put(&seg, &f, "s-0001", body()).await,
        Err(BackendError::QuotaExceeded(QuotaKind::StorageFull))
    ));
    // Other names pass and do not use up the failures.
    let blob = id(&b).await;
    b.put(&blob, &f, "c-0001", body()).await.unwrap();
    b.put(&id(&b).await, &f, "xs-0001", body()).await.unwrap();
    assert!(b.put(&seg, &f, "s-0001", body()).await.is_err());
    assert!(b.stat(&seg).await.unwrap().is_none());
    b.put(&seg, &f, "s-0001", body()).await.unwrap();

    // u32::MAX: every such put fails until `clear`.
    b.fail_put_named("s-", u32::MAX, quota);
    let seg2 = id(&b).await;
    for _ in 0..10 {
        assert!(b.put(&seg2, &f, "s-0002", body()).await.is_err());
        let (stream, _) = fed_body(parts_of(&pattern(3, PART + 1)), PART as u64 + 1);
        assert!(b.put(&seg2, &f, "s-0002", stream).await.is_err());
    }
    b.put(&id(&b).await, &f, "c-0002", body()).await.unwrap();
    b.clear();
    b.put(&seg2, &f, "s-0002", body()).await.unwrap();
    assert_eq!(b.calls(OpKind::Put), 1 + 5 + 20 + 2);
}

#[tokio::test]
async fn flaky_lose_ack_stores_the_object() {
    let (b, f, _, _) = flaky_with_object().await;
    let data = pattern(2, 1000);
    let h = id(&b).await;
    b.lose_ack_next_put();
    let err = b
        .put(&h, &f, "x", PutBody::Small(data.clone()))
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::Transient(_)));
    assert!(err.is_temporary());
    assert!(b.inner().read(&h).unwrap() == data, "the object IS stored");
    // The retry takes the idempotent path — once, the injector is spent.
    let meta = b
        .put(&h, &f, "x", PutBody::Small(data.clone()))
        .await
        .unwrap();
    assert_eq!((meta.size, meta.md5), (1000, Some(md5(&data))));
    assert_eq!(b.inner().counters().put_bytes, 700_000 + 1000);

    // The same with a Stream body.
    let big = pattern(3, PART + 10);
    let h = id(&b).await;
    b.lose_ack_next_put();
    let (body, _) = fed_body(parts_of(&big), big.len() as u64);
    assert!(matches!(
        b.put(&h, &f, "y", body).await,
        Err(BackendError::Transient(_))
    ));
    assert!(b.inner().read(&h).unwrap() == big);
    b.put(&id(&b).await, &f, "z", PutBody::Small(data))
        .await
        .unwrap();
}

#[tokio::test]
async fn flaky_cut_next_stream_put() {
    let (b, f, _, _) = flaky_with_object().await;
    b.cut_next_stream_put(PART_SIZE + 1);
    // Small puts pass and leave the injector armed.
    b.put(&id(&b).await, &f, "small", PutBody::Small(pattern(2, 10)))
        .await
        .unwrap();

    let big = pattern(3, 4 * PART + 9);
    let h = id(&b).await;
    let puts_before = b.inner().counters().put;
    let (body, sent) = fed_body(parts_of(&big), big.len() as u64);
    assert!(matches!(
        b.put(&h, &f, "big", body).await,
        Err(BackendError::SessionLost)
    ));
    // Two parts were consumed (the second crosses the offset); a third may sit in the channel.
    let sent = sent.load(Ordering::SeqCst);
    assert!((2..=3).contains(&sent), "{sent} parts were taken");
    assert!(b.stat(&h).await.unwrap().is_none(), "nothing is stored");
    assert_eq!(
        b.inner().counters().put,
        puts_before,
        "nothing reached the backend"
    );
    assert!(b.find_by_name("big").await.unwrap().is_empty());

    // Once: the retry goes through.
    let (body, _) = fed_body(parts_of(&big), big.len() as u64);
    let meta = b.put(&h, &f, "big", body).await.unwrap();
    assert_eq!(meta.md5, Some(md5(&big)));

    // An offset beyond the body: everything is consumed, still nothing stored.
    b.cut_next_stream_put(u64::MAX);
    let h = id(&b).await;
    let (body, sent) = fed_body(parts_of(&big), big.len() as u64);
    assert!(matches!(
        b.put(&h, &f, "big2", body).await,
        Err(BackendError::SessionLost)
    ));
    assert_eq!(sent.load(Ordering::SeqCst), 5);
    assert!(b.stat(&h).await.unwrap().is_none());
}

#[tokio::test]
async fn flaky_on_put_progress_fires_once_at_the_offset() {
    let (b, f, _, _) = flaky_with_object().await;
    let big = pattern(2, 5 * PART + 77);
    let fired = Arc::new(AtomicU32::new(0));
    let sent_when_fired = Arc::new(AtomicU64::new(u64::MAX));

    // Armed by a Stream put only.
    let hook = {
        let fired = fired.clone();
        Box::new(move || {
            fired.fetch_add(1, Ordering::SeqCst);
        })
    };
    b.on_put_progress(0, hook);
    b.put(&id(&b).await, &f, "small", PutBody::Small(pattern(3, 10)))
        .await
        .unwrap();
    assert_eq!(fired.load(Ordering::SeqCst), 0);
    let (body, _) = fed_body(parts_of(&big), big.len() as u64);
    let h0 = id(&b).await;
    b.put(&h0, &f, "big0", body).await.unwrap();
    assert_eq!(fired.load(Ordering::SeqCst), 1);

    // At the stated offset: after the part that crosses it, before the rest.
    fired.store(0, Ordering::SeqCst);
    let (body, sent) = fed_body(parts_of(&big), big.len() as u64);
    let hook = {
        let (fired, sent, seen) = (fired.clone(), sent.clone(), sent_when_fired.clone());
        Box::new(move || {
            fired.fetch_add(1, Ordering::SeqCst);
            seen.store(sent.load(Ordering::SeqCst) as u64, Ordering::SeqCst);
        })
    };
    b.on_put_progress(2 * PART_SIZE + 1, hook);
    let h = id(&b).await;
    let meta = b.put(&h, &f, "big", body).await.unwrap();
    assert_eq!(fired.load(Ordering::SeqCst), 1);
    // Three parts had been received (≥ 2·PART + 1 bytes); at most one more was in the channel.
    let seen = sent_when_fired.load(Ordering::SeqCst);
    assert!(
        (3..=4).contains(&seen),
        "fired after {seen} parts were sent"
    );
    assert_eq!(meta.md5, Some(md5(&big)), "the put itself is untouched");
    assert!(b.inner().read(&h).unwrap() == big);

    // Once: the next Stream put does not fire it again.
    let (body, _) = fed_body(parts_of(&big), big.len() as u64);
    b.put(&id(&b).await, &f, "big2", body).await.unwrap();
    assert_eq!(fired.load(Ordering::SeqCst), 1);

    // The use it exists for: the source changes mid-upload, the feeder reports it.
    let changed = Arc::new(AtomicBool::new(false));
    let hook = {
        let changed = changed.clone();
        Box::new(move || changed.store(true, Ordering::SeqCst))
    };
    b.on_put_progress(PART_SIZE, hook);
    let (tx, rx) = mpsc::channel(1);
    let feeder = {
        let (changed, big) = (changed.clone(), big.clone());
        tokio::spawn(async move {
            for part in big.chunks(PART) {
                let item = if changed.load(Ordering::SeqCst) {
                    Err(std::io::Error::other("source changed"))
                } else {
                    Ok(big.slice_ref(part))
                };
                let failed = item.is_err();
                if tx.send(item).await.is_err() || failed {
                    return;
                }
            }
        })
    };
    let h = id(&b).await;
    let body = PutBody::Stream {
        total: big.len() as u64,
        parts: rx,
    };
    assert!(matches!(
        b.put(&h, &f, "racy", body).await,
        Err(BackendError::Io(_))
    ));
    feeder.await.unwrap();
    assert!(changed.load(Ordering::SeqCst));
    assert!(b.stat(&h).await.unwrap().is_none());

    // With a cut in the same put the hook still fires at its offset.
    fired.store(0, Ordering::SeqCst);
    let hook = {
        let fired = fired.clone();
        Box::new(move || {
            fired.fetch_add(1, Ordering::SeqCst);
        })
    };
    b.on_put_progress(PART_SIZE, hook);
    b.cut_next_stream_put(3 * PART_SIZE);
    let (body, _) = fed_body(parts_of(&big), big.len() as u64);
    assert!(matches!(
        b.put(&id(&b).await, &f, "cut", body).await,
        Err(BackendError::SessionLost)
    ));
    assert_eq!(fired.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn flaky_corrupt_md5_once() {
    let (b, f, _, _) = flaky_with_object().await;
    let data = pattern(2, 1000);
    let h = id(&b).await;
    b.corrupt_md5_next_put();
    let meta = b
        .put(&h, &f, "x", PutBody::Small(data.clone()))
        .await
        .unwrap();
    assert_eq!(meta.size, 1000);
    assert!(meta.md5.is_some());
    assert_ne!(meta.md5, Some(md5(&data)), "the returned md5 is wrong");
    // The stored object is fine; only the answer lied.
    assert_eq!(b.stat(&h).await.unwrap().unwrap().md5, Some(md5(&data)));
    let h2 = id(&b).await;
    let meta = b
        .put(&h2, &f, "y", PutBody::Small(data.clone()))
        .await
        .unwrap();
    assert_eq!(meta.md5, Some(md5(&data)));

    // A lost acknowledgement comes first; the lie waits for the next answer.
    b.corrupt_md5_next_put();
    b.lose_ack_next_put();
    let h3 = id(&b).await;
    assert!(
        b.put(&h3, &f, "z", PutBody::Small(data.clone()))
            .await
            .is_err()
    );
    let retry = b
        .put(&h3, &f, "z", PutBody::Small(data.clone()))
        .await
        .unwrap();
    assert_ne!(retry.md5, Some(md5(&data)));
    let retry = b
        .put(&h3, &f, "z", PutBody::Small(data.clone()))
        .await
        .unwrap();
    assert_eq!(retry.md5, Some(md5(&data)));
}

#[tokio::test]
async fn flaky_cut_next_get() {
    let (b, _, h, data) = flaky_with_object().await;

    async fn drain(mut s: gclone::backend::ByteStream) -> (Vec<u8>, Option<BackendError>) {
        let mut got = Vec::new();
        while let Some(item) = s.next().await {
            match item {
                Ok(chunk) => got.extend_from_slice(&chunk),
                Err(e) => {
                    assert!(s.next().await.is_none(), "nothing follows the error");
                    return (got, Some(e));
                }
            }
        }
        (got, None)
    }

    b.cut_next_get(300_001);
    let (got, err) = drain(b.get(&h, None).await.unwrap()).await;
    assert_eq!(got.len(), 300_001);
    assert!(got[..] == data[..300_001]);
    assert!(matches!(err, Some(BackendError::Transient(_))));
    // Once.
    let (got, err) = drain(b.get(&h, None).await.unwrap()).await;
    assert!(err.is_none());
    assert!(got[..] == data[..]);

    // Within a range, offsets count from the range start.
    b.cut_next_get(10);
    let (got, err) = drain(b.get(&h, Some(1000..2000)).await.unwrap()).await;
    assert!(got[..] == data[1000..1010]);
    assert!(err.is_some());

    // At 0: the error comes first.
    b.cut_next_get(0);
    let (got, err) = drain(b.get(&h, None).await.unwrap()).await;
    assert!(got.is_empty());
    assert!(matches!(err, Some(BackendError::Transient(_))));

    // Beyond the end: everything, then the error.
    b.cut_next_get(u64::MAX);
    let (got, err) = drain(b.get(&h, Some(0..5000)).await.unwrap()).await;
    assert!(got[..] == data[..5000]);
    assert!(matches!(err, Some(BackendError::Transient(_))));

    // A get that fails outright leaves the injector spent, not pending forever.
    b.cut_next_get(5);
    assert!(matches!(
        b.get(&Handle("nope".into()), None).await,
        Err(BackendError::NotFound)
    ));
    let (got, err) = drain(b.get(&h, None).await.unwrap()).await;
    assert!(err.is_none());
    assert_eq!(got.len(), data.len());
}

#[tokio::test]
async fn flaky_list_lag_hides_young_objects() {
    let b = Flaky::new(MemBackend::new());
    b.inner().set_now_ms(1_000_000);
    let f = folder(&b, &top(), "f").await;
    let old = put(&b, &f, "old", &pattern(1, 10)).await;
    b.inner().advance_ms(10_000);
    let young = put(&b, &f, "young", &pattern(2, 10)).await;

    b.set_list_lag_ms(5_000);
    assert_eq!(names(&b.list(&f).await.unwrap()), ["old"]);
    assert!(b.find_by_name("young").await.unwrap().is_empty());
    assert_eq!(b.find_by_name("old").await.unwrap()[0].handle, old);
    // Only listings lag: the object is there by id.
    assert!(b.stat(&young).await.unwrap().is_some());
    assert!(b.get(&young, None).await.is_ok());

    b.inner().advance_ms(4_999);
    assert_eq!(names(&b.list(&f).await.unwrap()), ["old"]);
    b.inner().advance_ms(1);
    assert_eq!(names(&b.list(&f).await.unwrap()), ["old", "young"]);
    assert_eq!(b.find_by_name("young").await.unwrap()[0].handle, young);

    // The lag stays until it is taken away.
    let newer = put(&b, &f, "newer", &pattern(3, 10)).await;
    assert_eq!(names(&b.list(&f).await.unwrap()), ["old", "young"]);
    b.set_list_lag_ms(0);
    assert_eq!(names(&b.list(&f).await.unwrap()), ["newer", "old", "young"]);
    b.set_list_lag_ms(1);
    assert_eq!(b.list(&f).await.unwrap().len(), 2);
    b.clear();
    assert_eq!(b.find_by_name("newer").await.unwrap()[0].handle, newer);

    // On a directory the age comes from the file's mtime and the wall clock.
    let dir = tempfile::tempdir().unwrap();
    let d = Flaky::new(DirBackend::open(dir.path()).unwrap());
    let h = put(&d, &top(), "x", &pattern(4, 10)).await;
    d.set_list_lag_ms(3_600_000);
    assert!(d.list(&top()).await.unwrap().is_empty());
    assert!(d.find_by_name("x").await.unwrap().is_empty());
    assert!(d.stat(&h).await.unwrap().is_some());
    d.set_list_lag_ms(0);
    assert_eq!(d.list(&top()).await.unwrap().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn flaky_hang_never_answers_until_cleared() {
    let (b, f, h, data) = flaky_with_object().await;
    let inner_before = b.inner().counters();
    b.hang(OpKind::Stat);
    b.hang(OpKind::Put);
    // An hour (of paused time) passes without an answer; the calls count, the inner backend
    // sees none of them, and dropping the future is the only way out.
    let hour = std::time::Duration::from_secs(3600);
    assert!(tokio::time::timeout(hour, b.stat(&h)).await.is_err());
    let new = id(&b).await;
    let small = PutBody::Small(pattern(2, 5));
    assert!(
        tokio::time::timeout(hour, b.put(&new, &f, "p", small))
            .await
            .is_err()
    );
    assert_eq!((b.calls(OpKind::Stat), b.calls(OpKind::Put)), (1, 2));
    assert_eq!(b.inner().counters().stat, inner_before.stat);
    assert_eq!(b.inner().counters().put, inner_before.put);
    // Other operations answer as usual, and so does a hanging one once the plan is cleared.
    assert!(get_all(&b, &h, None).await.unwrap() == data);
    b.clear();
    assert!(b.stat(&h).await.unwrap().is_some());
    assert!(b.stat(&new).await.unwrap().is_none());
}

#[tokio::test]
async fn flaky_counts_calls_and_shares_its_plan() {
    let b = Flaky::new(MemBackend::new());
    for op in [OpKind::NewIds, OpKind::Put, OpKind::About] {
        assert_eq!(b.calls(op), 0);
    }
    let f = folder(&b, &top(), "f").await;
    let data = pattern(1, 10);
    let h = put(&b, &f, "x", &data).await;
    b.stat(&h).await.unwrap();
    b.stat(&h).await.unwrap();
    b.list(&f).await.unwrap();
    b.find_by_name("x").await.unwrap();
    drop(b.get(&h, None).await.unwrap());
    b.trash(&h).await.unwrap();
    b.untrash(&h).await.unwrap();
    b.about().await.unwrap();
    b.fail_next(OpKind::Delete, 1, transient);
    assert!(b.delete(&h).await.is_err()); // an injected failure is a call too
    b.delete(&h).await.unwrap();
    let counts = |b: &Flaky<MemBackend>| {
        [
            OpKind::NewIds,
            OpKind::CreateFolder,
            OpKind::Put,
            OpKind::Get,
            OpKind::Stat,
            OpKind::List,
            OpKind::FindByName,
            OpKind::Trash,
            OpKind::Untrash,
            OpKind::Delete,
            OpKind::About,
        ]
        .map(|op| b.calls(op))
    };
    assert_eq!(counts(&b), [2, 1, 1, 1, 2, 1, 1, 1, 1, 2, 1]);
    assert_eq!(b.inner().counters().delete, 1);
    assert_eq!(b.now_ms(), b.inner().now_ms());

    // `clear` drops the planned faults, not the counts.
    b.fail_next(OpKind::Stat, 3, transient);
    b.fail_nth(OpKind::List, 1, transient);
    b.fail_put_named("", u32::MAX, transient);
    b.lose_ack_next_put();
    b.corrupt_md5_next_put();
    b.cut_next_stream_put(0);
    b.cut_next_get(0);
    b.on_put_progress(0, Box::new(|| panic!("cleared hooks never run")));
    b.set_list_lag_ms(u64::MAX);
    b.hang(OpKind::Stat);
    b.clear();
    assert_eq!(counts(&b), [2, 1, 1, 1, 2, 1, 1, 1, 1, 2, 1]);
    let big = pattern(2, PART + 3);
    let h = id(&b).await;
    let (body, _) = fed_body(parts_of(&big), big.len() as u64);
    assert_eq!(b.put(&h, &f, "y", body).await.unwrap().md5, Some(md5(&big)));
    assert!(b.stat(&h).await.unwrap().is_some());
    assert_eq!(b.list(&f).await.unwrap().len(), 1);
    assert!(get_all(&b, &h, None).await.unwrap() == big);

    // A clone (one per "device" task) shares plan and counts.
    let other = b.clone();
    other.fail_next(OpKind::About, 1, quota);
    assert!(b.about().await.is_err());
    assert_eq!(other.calls(OpKind::About), 2);
    let shared = Arc::new(b);
    shared.fail_next(OpKind::About, 1, quota);
    assert!(other.about().await.is_err());
}

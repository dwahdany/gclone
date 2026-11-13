//! `gclone serve restic` at the HTTP level, without restic (SPEC §13 "restic", H1–H11): the
//! library's server over an in-memory pipe (HTTP/2, as `--stdio`) and over a loopback socket
//! (HTTP/1.1, as `--port`), on the in-memory backend.

#[path = "support/h2.rs"]
mod h2;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use gclone::backend::{
    Backend, ByteStream, Flaky, Handle, MemBackend, ObjMeta, OpKind, PutBody, Quota,
};
use gclone::error::{AuthError, BackendError, QuotaKind};
use gclone::restic::{self, App, Options, RepoName};
use h2::{H2, Out, full, sha};
use hyper::{Method, Request};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{Semaphore, mpsc};

// ---------------------------------------------------------------------------------------------
// A backend whose puts can be held
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Gate {
    arrived: Arc<Semaphore>,
    open: Arc<Semaphore>,
}

impl Gate {
    async fn reached(&self) {
        self.arrived.acquire().await.unwrap().forget();
    }

    fn release(&self) {
        self.open.add_permits(1);
    }
}

/// The next put of a held name waits at its gate before it reaches the store.
struct Gated<B: Backend> {
    inner: B,
    gates: Mutex<Vec<(String, Gate)>>,
}

impl<B: Backend> Gated<B> {
    fn hold_put(&self, name: &str) -> Gate {
        let gate = Gate {
            arrived: Arc::new(Semaphore::new(0)),
            open: Arc::new(Semaphore::new(0)),
        };
        let held = (name.to_string(), gate.clone());
        self.gates.lock().unwrap().push(held);
        gate
    }
}

impl<B: Backend> Backend for Gated<B> {
    async fn new_ids(&self, n: usize) -> Result<Vec<Handle>, BackendError> {
        self.inner.new_ids(n).await
    }
    async fn create_folder(&self, id: &Handle, p: &Handle, name: &str) -> Result<(), BackendError> {
        self.inner.create_folder(id, p, name).await
    }
    async fn put(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
        body: PutBody,
    ) -> Result<ObjMeta, BackendError> {
        let gate = {
            let mut gates = self.gates.lock().unwrap();
            let at = gates.iter().position(|(n, _)| n == name);
            at.map(|at| gates.remove(at).1)
        };
        if let Some(gate) = gate {
            gate.arrived.add_permits(1);
            gate.open.acquire().await.unwrap().forget();
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
    async fn list_strict(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        self.inner.list_strict(parent).await
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

type Be = Gated<Flaky<MemBackend>>;

struct Store {
    mem: MemBackend,
    flaky: Flaky<MemBackend>,
    be: Arc<Be>,
}

impl Store {
    fn new() -> Store {
        let mem = MemBackend::new();
        let flaky = Flaky::new(mem.clone());
        let be = Arc::new(Gated {
            inner: flaky.clone(),
            gates: Mutex::default(),
        });
        Store { mem, flaky, be }
    }

    /// The untrashed files of that name, anywhere.
    fn live(&self, name: &str) -> Vec<ObjMeta> {
        let all = self.mem.all_objects().into_iter();
        all.filter(|m| m.name == name && !m.trashed && !m.is_folder)
            .collect()
    }

    fn folder(&self, name: &str) -> Handle {
        let all = self.mem.all_objects().into_iter();
        let mut found = all.filter(|m| m.name == name && m.is_folder && !m.trashed);
        found
            .next()
            .unwrap_or_else(|| panic!("no folder {name}"))
            .handle
    }
}

fn repo(name: &str) -> RepoName {
    RepoName::parse(name).unwrap()
}

fn data(seed: u8, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    blake3::Hasher::new()
        .update(&[seed])
        .finalize_xof()
        .fill(&mut buf);
    buf
}

impl H2 {
    /// A client connected to `app` the way restic is in `--stdio` mode.
    async fn connect(app: Arc<App<Be>>) -> H2 {
        let (client, server) = tokio::io::duplex(256 * 1024);
        tokio::spawn(async move {
            let _ = restic::http::serve_h2(app, server).await;
        });
        H2::over(client).await
    }

    async fn stdio(store: &Store, opts: Options) -> H2 {
        H2::connect(App::single(store.be.clone(), repo("r"), opts)).await
    }
}

// ---------------------------------------------------------------------------------------------
// H1–H3, H8: statuses and headers
// ---------------------------------------------------------------------------------------------

/// H1: every row of the status table, over HTTP/2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_status_table() {
    let store = Store::new();
    let h = H2::stdio(&store, Options::default()).await;
    let x = "a".repeat(64);

    // Outside the grammar: 404 without a look at Drive — restic's readiness probe among them.
    for path in [
        "/file-2026821414756312606".to_string(),
        "/data".into(),
        "/config/".into(),
        format!("/locks/{}", "A".repeat(64)),
        format!("/locks/{}", &x[1..]),
        "/locks/..".into(),
        "/%2e%2e/config".into(),
        format!("/data/aa/{x}"),
        format!("//locks/{x}"),
    ] {
        assert_eq!(h.get(&path).await.status, 404, "{path}");
        assert_eq!(h.post(&path, b"x").await.status, 404, "{path}");
    }
    assert_eq!(
        store.mem.counters(),
        Default::default(),
        "nothing was asked of Drive"
    );

    // A known path with another method.
    for (method, path, allow) in [
        (
            Method::PUT,
            "/config".to_string(),
            "HEAD, GET, POST, DELETE",
        ),
        (
            Method::PATCH,
            format!("/keys/{x}"),
            "HEAD, GET, POST, DELETE",
        ),
        (Method::POST, "/locks/".into(), "GET"),
        (Method::DELETE, "/snapshots/".into(), "GET"),
        (Method::HEAD, "/data/".into(), "GET"),
        (Method::GET, "/".into(), "POST"),
        (Method::DELETE, "/".into(), "POST"),
    ] {
        let res = h.send(method.clone(), &path, &[], full(b"")).await;
        assert_eq!(res.status, 405, "{method} {path}");
        assert_eq!(res.header("allow"), Some(allow));
        assert!(res.header("server").is_none());
    }

    // No repository yet: 404 for files, and 403 — never 404 — for a listing.
    assert_eq!(h.head("/config").await.status, 404);
    assert_eq!(h.get("/config").await.status, 404);
    assert_eq!(h.get(&format!("/keys/{x}")).await.status, 404);
    assert_eq!(
        h.post(&format!("/keys/{}", sha(b"k")), b"k").await.status,
        404
    );
    assert_eq!(h.delete(&format!("/keys/{x}")).await.status, 404);
    for ty in ["data", "keys", "locks", "snapshots", "index"] {
        assert_eq!(h.get(&format!("/{ty}/")).await.status, 403, "{ty}");
    }

    // Create: only with ?create=true; twice is fine.
    assert_eq!(h.post("/", b"").await.status, 400);
    assert_eq!(h.post("/?create=false", b"").await.status, 400);
    h.create().await;
    let folders = store.mem.counters().create_folder;
    assert_eq!(folders, 263);
    assert_eq!(h.post("/?x=1&create=true", b"").await.status, 200);
    assert_eq!(store.mem.counters().create_folder, folders);

    // A tree without a config: `HEAD config` 404, everything else serves.
    assert_eq!(h.head("/config").await.status, 404);
    for ty in ["data", "keys", "locks", "snapshots", "index"] {
        let res = h.get(&format!("/{ty}/")).await;
        assert_eq!((res.status, res.bytes()), (200, &b"[]"[..]), "{ty}");
    }

    // Uploads.
    let key = data(1, 454);
    let key_path = h.save("keys", &key).await;
    assert_eq!(h.post("/config", b"the config").await.status, 200);
    assert_eq!(
        h.post(&key_path, &key).await.status,
        200,
        "an identical file again"
    );
    assert_eq!(h.post("/config", b"the config").await.status, 200);
    assert_eq!(h.post("/config", b"another one").await.status, 403);
    // What restic sends after an upload that failed — `DELETE config` — is refused as well:
    // the config is the first init's (one refusal covers one delete).
    assert_eq!(h.delete("/config").await.status, 403);
    assert_eq!(h.get("/config").await.bytes(), b"the config");
    assert_eq!(
        h.post(&key_path, b"not the key").await.status,
        403,
        "another size"
    );
    let mut wrong = key.clone();
    wrong[0] ^= 1;
    assert_eq!(
        h.post(&key_path, &wrong).await.status,
        400,
        "same size, other bytes"
    );
    assert_eq!(h.post(&format!("/keys/{x}"), b"abc").await.status, 400);
    let big_wrong = data(2, 5 << 20);
    assert_eq!(h.post(&format!("/data/{x}"), &big_wrong).await.status, 400);
    assert!(store.live(&x).is_empty());
    // No Content-Length.
    let (tx, rx) = mpsc::channel(1);
    tx.send(Ok(Bytes::from_static(b"abc"))).await.unwrap();
    drop(tx);
    let path = format!("/keys/{}", sha(b"abc"));
    let res = h.send(Method::POST, &path, &[], Out::Stream(rx)).await;
    assert_eq!(res.status, 411);

    // Reads.
    let res = h.head("/config").await;
    assert_eq!(
        (res.status, res.header("content-length")),
        (200, Some("10"))
    );
    assert!(res.bytes().is_empty());
    let res = h.head(&key_path).await;
    assert_eq!(
        (res.status, res.header("content-length")),
        (200, Some("454"))
    );
    assert_eq!(h.head(&format!("/keys/{x}")).await.status, 404);
    let res = h.get(&key_path).await;
    assert_eq!((res.status, res.bytes()), (200, &key[..]));
    assert_eq!(h.range("/config", "bytes=0-").await.bytes(), b"the config");
    assert_eq!(h.range(&key_path, "bytes=454-").await.status, 416);

    // Deletes: idempotent.
    let lock = h.save("locks", &data(3, 155)).await;
    assert_eq!(h.delete(&lock).await.status, 200);
    assert_eq!(h.delete(&lock).await.status, 200);
    assert_eq!(h.get(&lock).await.status, 404);
    assert_eq!(h.delete(&format!("/data/{x}")).await.status, 200);

    // Drive's failures by class.
    let lock = data(4, 155);
    let lock_path = format!("/locks/{}", sha(&lock));
    let failures: [(fn() -> BackendError, u16); 7] = [
        (|| BackendError::RateLimited, 503),
        (|| BackendError::Transient("x".into()), 503),
        (|| BackendError::QuotaExceeded(QuotaKind::StorageFull), 507),
        (|| BackendError::QuotaExceeded(QuotaKind::DailyUpload), 507),
        (|| BackendError::Auth(AuthError::Expired), 401),
        (
            || BackendError::QuotaExceeded(QuotaKind::ProjectApiQuota),
            403,
        ),
        (|| BackendError::AppNotAuthorized, 403),
    ];
    for (make, status) in failures {
        store.flaky.fail_next(OpKind::Put, 1, make);
        assert_eq!(h.post(&lock_path, &lock).await.status, status);
        store.flaky.fail_next(OpKind::List, 1, make);
        // 507 has no meaning for a listing; the class is the same.
        assert_eq!(h.get("/snapshots/").await.status, status);
    }
    store.flaky.corrupt_md5_next_put();
    assert_eq!(h.post(&lock_path, &lock).await.status, 500);
    assert!(store.live(&sha(&lock)).is_empty());
    assert_eq!(h.post(&lock_path, &lock).await.status, 200);

    // A duplicate folder: 403 on `HEAD config` and on a listing; a missing one likewise.
    let stray = store.mem.new_ids(1).await.unwrap().remove(0);
    let parent = store.folder("r");
    store
        .mem
        .create_folder(&stray, &parent, "locks")
        .await
        .unwrap();
    assert_eq!(h.head("/config").await.status, 403);
    assert_eq!(h.get("/locks/").await.status, 403);
    assert_eq!(h.get("/snapshots/").await.status, 403);
    assert_eq!(h.post(&lock_path, &lock).await.status, 403);
    store.mem.trash(&stray).await.unwrap();
    assert_eq!(h.head("/config").await.status, 200);
    store.mem.trash(&store.folder("snapshots")).await.unwrap();
    assert_eq!(h.get("/snapshots/").await.status, 403);
    assert_eq!(h.head("/config").await.status, 403);

    // The whole repository in the trash: files 404, listings 403.
    store.mem.trash(&parent).await.unwrap();
    assert_eq!(h.head("/config").await.status, 404);
    assert_eq!(h.get("/keys/").await.status, 403);
    assert_eq!(h.get("/data/").await.status, 403);

    // Append-only: every delete but a lock's is refused; the rest is unchanged.
    let store = Store::new();
    let h = H2::stdio(
        &store,
        Options {
            append_only: true,
            ..Options::default()
        },
    )
    .await;
    h.create().await;
    assert_eq!(h.post("/config", b"cfg").await.status, 200);
    let lock = h.save("locks", &data(5, 155)).await;
    let snap = h.save("snapshots", &data(6, 450)).await;
    for path in [
        &snap,
        "/config",
        &format!("/data/{x}"),
        &format!("/index/{x}"),
    ] {
        assert_eq!(h.delete(path).await.status, 403, "{path}");
    }
    assert_eq!(h.delete(&lock).await.status, 200);
    assert_eq!(h.get(&snap).await.status, 200);
}

/// H2, H3: the headers restic depends on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_and_range_headers() {
    let store = Store::new();
    let h = H2::stdio(&store, Options::default()).await;
    h.create().await;
    let res = h.get("/index/").await;
    assert_eq!(
        res.header("content-type"),
        Some("application/vnd.x.restic.rest.v2")
    );
    assert_eq!(res.header("content-length"), Some("2"));
    assert_eq!(res.bytes(), b"[]");

    let pack = data(7, 100_000);
    let path = h.save("data", &pack).await;
    let small = h.save("data", &data(8, 10)).await;
    let res = h.get("/data/").await;
    let json = String::from_utf8(res.bytes().to_vec()).unwrap();
    assert_eq!(
        res.header("content-length"),
        Some(json.len().to_string().as_str())
    );
    let listed: Vec<HashMap<String, serde_json::Value>> = serde_json::from_str(&json).unwrap();
    let mut expected = vec![
        (path[6..].to_string(), 100_000u64),
        (small[6..].to_string(), 10),
    ];
    expected.sort();
    let got: Vec<(String, u64)> = listed
        .iter()
        .map(|e| {
            (
                e["name"].as_str().unwrap().to_string(),
                e["size"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(got, expected, "sorted by name, with sizes");

    // restic's two forms of Range, and no Range at all.
    for (range, status, from, to) in [
        (None, 200, 0usize, 100_000usize),
        (Some("bytes=0-"), 206, 0, 100_000),
        (Some("bytes=500-"), 206, 500, 100_000),
        (Some("bytes=500-999"), 206, 500, 1000),
        (Some("bytes=99999-99999"), 206, 99_999, 100_000),
        (Some("bytes=99000-200000"), 206, 99_000, 100_000),
    ] {
        let res = match range {
            Some(range) => h.range(&path, range).await,
            None => h.get(&path).await,
        };
        assert_eq!(res.status, status, "{range:?}");
        assert_eq!(res.bytes(), &pack[from..to], "{range:?}");
        let len = (to - from).to_string();
        assert_eq!(
            res.header("content-length"),
            Some(len.as_str()),
            "{range:?}"
        );
        let content_range = (status == 206).then(|| format!("bytes {from}-{}/100000", to - 1));
        assert_eq!(
            res.header("content-range"),
            content_range.as_deref(),
            "{range:?}"
        );
        assert!(res.header("content-encoding").is_none());
    }
    let res = h.range(&path, "bytes=100000-100010").await;
    assert_eq!(res.status, 416);
    assert_eq!(res.header("content-range"), Some("bytes */100000"));

    let res = h.head(&path).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.header("content-length"), Some("100000"));
    assert!(res.bytes().is_empty());
    // An empty file: 200 and nothing, whatever the range.
    let empty = h.save("keys", b"").await;
    let res = h.range(&empty, "bytes=0-").await;
    assert_eq!((res.status, res.header("content-length")), (200, Some("0")));
}

// ---------------------------------------------------------------------------------------------
// H4–H7: streams
// ---------------------------------------------------------------------------------------------

/// H4: a download that fails resets its stream and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_download_resets_one_stream() {
    let store = Store::new();
    let h = H2::stdio(&store, Options::default()).await;
    h.create().await;
    let pack = data(9, 3 << 20);
    let path = h.save("data", &pack).await;
    store.flaky.cut_next_get(1 << 20);
    let res = h.get(&path).await;
    assert_eq!(res.status, 200, "the headers had left already");
    assert!(res.body.is_err(), "a short body must not look complete");
    // The same connection, the next request.
    let res = h.get(&path).await;
    assert_eq!(res.bytes(), &pack[..]);
    // A failure before the first byte is a status.
    store
        .flaky
        .fail_next(OpKind::Get, 1, || BackendError::RateLimited);
    assert_eq!(h.get(&path).await.status, 503);
}

/// H5: many streams at once, both directions, several MiB each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_streams() {
    let store = Store::new();
    let h = H2::stdio(&store, Options::default()).await;
    h.create().await;
    let packs: Vec<Vec<u8>> = (0..10u8)
        .map(|i| data(20 + i, (3 << 20) + usize::from(i) * 777_777))
        .collect();
    let mut first = Vec::new();
    for pack in &packs[..5] {
        first.push(h.save("data", pack).await);
    }
    // Ten uploads (five of them of files that are there) and ten downloads, all at once.
    let mut tasks = tokio::task::JoinSet::new();
    for (i, pack) in packs.iter().enumerate() {
        let (up, pack) = (h.clone(), pack.clone());
        tasks.spawn(async move {
            let h = up;
            h.save("data", &pack).await;
            let range = h
                .range(&format!("/data/{}", sha(&pack)), "bytes=1000-")
                .await;
            assert_eq!(range.bytes(), &pack[1000..], "pack {i}");
        });
        let (h, path, pack) = (h.clone(), first[i % 5].clone(), packs[i % 5].clone());
        tasks.spawn(async move {
            assert_eq!(h.get(&path).await.bytes(), &pack[..]);
        });
    }
    while let Some(done) = tasks.join_next().await {
        done.unwrap();
    }
    for pack in &packs {
        let [stored] = store.live(&sha(pack)).try_into().unwrap();
        assert_eq!(store.mem.read(&stored.handle).unwrap(), pack);
    }
}

/// H6: an upload that restic gave up on leaves no object — whether its body was cut or
/// complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoned_uploads_leave_nothing() {
    let store = Store::new();
    let h = H2::stdio(&store, Options::default()).await;
    h.create().await;
    let objects = store.mem.all_objects().len();

    // Reset in the middle of the body.
    let pack = data(40, 6 << 20);
    let path = format!("/data/{}", sha(&pack));
    let (tx, rx) = mpsc::channel(1);
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost{path}"))
        .header("content-length", pack.len())
        .body(Out::Stream(rx))
        .unwrap();
    let pending = tokio::spawn(h.send.clone().send_request(req));
    tx.send(Ok(Bytes::copy_from_slice(&pack[..2 << 20])))
        .await
        .unwrap();
    tx.send(Err(std::io::Error::other("the client gave up")))
        .await
        .unwrap();
    assert!(pending.await.unwrap().is_err());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        store.mem.all_objects().len(),
        objects,
        "not even in the trash"
    );

    // The body complete, the put on its way to Drive, and restic resets the stream — Ctrl-C
    // while it creates its lock. Nobody will ever delete that lock: the server has to.
    let lock = data(41, 155);
    let name = sha(&lock);
    let gate = store.be.hold_put(&name);
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost/locks/{name}"))
        .body(full(&lock))
        .unwrap();
    let pending = tokio::spawn(h.send.clone().send_request(req));
    gate.reached().await;
    pending.abort();
    let _ = pending.await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    gate.release();
    for _ in 0..100 {
        if store.mem.counters().trash > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        store.mem.all_objects().len(),
        objects + 1,
        "the put was not cut"
    );
    assert!(
        store.live(&name).is_empty(),
        "and its object is in the trash"
    );
    let res = h.get("/locks/").await;
    assert_eq!((res.status, res.bytes()), (200, &b"[]"[..]));

    // The server serves on.
    assert_eq!(h.post(&path, &pack).await.status, 200);
    assert_eq!(h.get(&path).await.bytes(), &pack[..]);
}

/// The connection ends while an upload has not been answered: `App::close` — what the process
/// does before it exits — returns when the upload has taken back what it stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_end_of_the_connection_takes_back_an_unanswered_upload() {
    let store = Store::new();
    let app = App::single(store.be.clone(), repo("r"), Options::default());
    let h = H2::connect(app.clone()).await;
    h.create().await;
    let lock = data(42, 155);
    let name = sha(&lock);
    let gate = store.be.hold_put(&name);
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost/locks/{name}"))
        .body(full(&lock))
        .unwrap();
    let pending = tokio::spawn(h.send.clone().send_request(req));
    gate.reached().await;
    // restic goes away.
    pending.abort();
    h.close().await;
    let closing = tokio::spawn({
        let app = app.clone();
        async move { app.close().await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!closing.is_finished(), "the put is on its way to Drive");
    gate.release();
    tokio::time::timeout(Duration::from_secs(10), closing)
        .await
        .expect("close ends with the upload")
        .unwrap();
    assert_eq!(store.mem.counters().put, 1, "the put was not cut");
    assert!(store.live(&name).is_empty(), "its object is in the trash");
}

/// H7: an upload that waits for Drive holds its own stream's window, not the connection's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_upload_does_not_stall_the_others() {
    let store = Store::new();
    let h = H2::stdio(&store, Options::default()).await;
    h.create().await;
    let big = data(50, 40 << 20);
    let gate = store.be.hold_put(&sha(&big));
    let stalled = tokio::spawn({
        let (h, big) = (h.clone(), big.clone());
        async move { h.save("data", &big).await }
    });
    gate.reached().await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let others = async {
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..8u8 {
            let h = h.clone();
            tasks.spawn(async move { h.save("data", &data(60 + i, 2 << 20)).await });
        }
        let lock = h.save("locks", &data(70, 155)).await;
        while let Some(done) = tasks.join_next().await {
            done.unwrap();
        }
        assert_eq!(h.delete(&lock).await.status, 200);
    };
    tokio::time::timeout(Duration::from_secs(60), others)
        .await
        .expect("the other streams move while one upload waits for Drive");
    assert!(!stalled.is_finished());
    gate.release();
    let path = stalled.await.unwrap();
    assert_eq!(
        h.range(&path, "bytes=41943000-").await.bytes(),
        &big[41_943_000..]
    );
}

// ---------------------------------------------------------------------------------------------
// H8–H11: the listener
// ---------------------------------------------------------------------------------------------

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

struct Listener {
    port: u16,
    http: reqwest::Client,
    _stop: tokio_util::sync::DropGuard,
}

impl Listener {
    async fn start(store: &Store, opts: Options) -> Listener {
        let (listeners, port) = gclone::web::bind_v6(0, gclone::web::V6::Required)
            .await
            .expect("bind");
        let hosts: Vec<String> = ["127.0.0.1", "localhost", "[::1]"]
            .iter()
            .map(|h| format!("{h}:{port}"))
            .collect();
        let app = App::listener(store.be.clone(), TOKEN.to_string(), hosts, opts);
        let stop = tokio_util::sync::CancellationToken::new();
        let handler = move |req| app.clone().handle(req);
        tokio::spawn(gclone::web::serve(listeners, handler, 64, stop.clone()));
        Listener {
            port,
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
            _stop: stop.drop_guard(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn req(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, self.url(path))
            .basic_auth("gclone", Some(TOKEN))
    }

    async fn status(&self, method: Method, path: &str) -> u16 {
        self.req(method, path)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    async fn post(&self, path: &str, data: &[u8]) -> u16 {
        let req = self.req(Method::POST, path).body(data.to_vec());
        req.send().await.unwrap().status().as_u16()
    }

    /// One raw exchange: what was sent, and everything the server answered until it closed.
    async fn raw(&self, request: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", self.port))
            .await
            .unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer))
            .await
            .expect("the server answers and closes")
            .unwrap();
        String::from_utf8_lossy(&answer).into_owned()
    }
}

fn basic(password: &str) -> String {
    use base64::Engine as _;
    let raw = format!("gclone:{password}");
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

/// H8, H9: the three checks of the listener, and its prefixes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listener_is_guarded() {
    let store = Store::new();
    let l = Listener::start(&store, Options::default()).await;
    let port = l.port;

    // The token.
    let bare = |path: &str| l.http.get(l.url(path));
    let res = bare("/r/config").send().await.unwrap();
    assert_eq!(res.status(), 401);
    assert_eq!(res.headers()["www-authenticate"], "Basic realm=\"gclone\"");
    assert_eq!(res.headers()["connection"], "close");
    for wrong in [
        "Basic Og==".to_string(),
        basic("nope"),
        basic(""),
        format!("Bearer {TOKEN}"),
    ] {
        let res = bare("/r/config")
            .header("authorization", &wrong)
            .send()
            .await;
        assert_eq!(res.unwrap().status(), 401, "{wrong}");
    }
    // Twice is not once.
    let twice = format!(
        "GET /r/config HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: {a}\r\n\
         Authorization: {a}\r\n\r\n",
        a = basic(TOKEN)
    );
    assert!(l.raw(&twice).await.starts_with("HTTP/1.1 401"));
    // Any user name goes with the right password; the probe path is still nothing.
    let res = bare("/r/config")
        .basic_auth("someone", Some(TOKEN))
        .send()
        .await;
    assert_eq!(res.unwrap().status(), 404);
    assert_eq!(l.status(Method::GET, "/file-1").await, 404);
    assert_eq!(l.status(Method::GET, "/r").await, 404);
    assert_eq!(l.status(Method::GET, "/Bad/config").await, 404);
    assert_eq!(
        store.mem.counters().list,
        1,
        "one look at Drive, for the one real request"
    );

    // Host: only the names the listener has, checked before the token.
    for (host, status) in [
        (format!("127.0.0.1:{port}"), 404),
        (format!("localhost:{port}"), 404),
        (format!("LocalHost:{port}"), 404),
        (format!("[::1]:{port}"), 404),
        ("127.0.0.1".to_string(), 403),
        (format!("127.0.0.1:{}", port.wrapping_add(1)), 403),
        (format!("evil.example:{port}"), 403),
        (format!("127.0.0.1:{port}.evil.example"), 403),
    ] {
        let res = l
            .req(Method::HEAD, "/r/config")
            .header("host", &host)
            .send()
            .await;
        assert_eq!(res.unwrap().status(), status, "{host}");
    }
    let no_host = format!(
        "GET /r/config HTTP/1.0\r\nAuthorization: {}\r\n\r\n",
        basic(TOKEN)
    );
    assert_eq!(l.raw(&no_host).await.split(' ').nth(1), Some("403"));

    // Origin: a browser sends it on cross-site writes; restic never does.
    for origin in [
        "https://evil.example",
        "null",
        &format!("http://127.0.0.1:{port}"),
    ] {
        let res = l
            .req(Method::POST, "/r/?create=true")
            .header("origin", origin);
        assert_eq!(res.send().await.unwrap().status(), 403, "{origin}");
    }
    assert_eq!(store.mem.counters().create_folder, 0);

    // H8: restic's create over HTTP/1.1 is a chunked POST without a body.
    let create = format!(
        "POST /r/?create=true HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: {}\r\n\
         Content-Type: binary/octet-stream\r\nTransfer-Encoding: chunked\r\n\
         Connection: close\r\n\r\n0\r\n\r\n",
        basic(TOKEN)
    );
    assert!(l.raw(&create).await.starts_with("HTTP/1.1 200"));
    assert_eq!(store.mem.counters().create_folder, 263);

    // Two repositories under two prefixes.
    assert_eq!(l.post("/s/?create=true", b"").await, 200);
    assert_eq!(l.post("/r/config", b"config of r").await, 200);
    assert_eq!(l.post("/s/config", b"s").await, 200);
    let key = data(80, 454);
    assert_eq!(l.post(&format!("/r/keys/{}", sha(&key)), &key).await, 200);
    let get = |path: &'static str| async { l.req(Method::GET, path).send().await.unwrap() };
    assert_eq!(
        get("/r/config").await.bytes().await.unwrap(),
        &b"config of r"[..]
    );
    assert_eq!(get("/s/config").await.bytes().await.unwrap(), &b"s"[..]);
    assert_eq!(get("/s/keys/").await.bytes().await.unwrap(), &b"[]"[..]);
    let res = get("/r/keys/").await;
    assert_eq!(
        res.headers()["content-type"],
        "application/vnd.x.restic.rest.v2"
    );
    assert!(res.text().await.unwrap().contains(&sha(&key)));
    assert_eq!(
        l.status(Method::GET, "/t/keys/").await,
        403,
        "no such repository"
    );
    // Append-only is the listener's as a whole.
    let l = Listener::start(
        &store,
        Options {
            append_only: true,
            ..Options::default()
        },
    )
    .await;
    assert_eq!(l.status(Method::DELETE, "/r/config").await, 403);
    assert_eq!(l.status(Method::HEAD, "/r/config").await, 200);
}

/// H10: request bodies. Nothing of an unauthenticated one is read; an authenticated one is
/// read to its end before an error is answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_bodies() {
    let store = Store::new();
    let l = Listener::start(&store, Options::default()).await;
    let x = "a".repeat(64);

    // Headers that announce 1 GiB, and not one byte of it: the answer comes all the same, and
    // the connection is closed.
    let announce = format!(
        "POST /r/data/{x} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: 1073741824\r\n\r\n",
        l.port
    );
    let answer = l.raw(&announce).await;
    assert!(answer.starts_with("HTTP/1.1 401"), "{answer}");
    assert!(
        answer.to_ascii_lowercase().contains("connection: close"),
        "{answer}"
    );
    let wrong_host = announce.replace("Host: 127.0.0.1", "Host: 127.0.0.2");
    assert!(l.raw(&wrong_host).await.starts_with("HTTP/1.1 403"));

    // Authenticated: each of these errors is decided before the body was read — and reaches
    // the client as a status, not as a broken connection.
    let big = data(81, 24 << 20);
    assert_eq!(
        l.post(&format!("/r/data/{}", sha(&big)), &big).await,
        404,
        "no repository"
    );
    assert_eq!(l.post("/r/?create=true", b"").await, 200);
    assert_eq!(
        l.post(&format!("/r/data/{x}"), &big).await,
        400,
        "a wrong name"
    );
    assert_eq!(l.post("/r/data/", &big).await, 405);
    assert_eq!(l.post("/r/nothing", &big).await, 404);
    store.flaky.fail_next(OpKind::Put, 1, || {
        BackendError::QuotaExceeded(QuotaKind::StorageFull)
    });
    assert_eq!(l.post(&format!("/r/data/{}", sha(&big)), &big).await, 507);
    // No Content-Length (a chunked upload): 411, after the body.
    let chunks = futures_util::stream::iter([Ok::<_, std::io::Error>(Bytes::from(big.clone()))]);
    let body = reqwest::Body::wrap_stream(chunks);
    let req = l
        .req(Method::POST, &format!("/r/data/{}", sha(&big)))
        .body(body);
    assert_eq!(req.send().await.unwrap().status(), 411);
    assert!(store.live(&sha(&big)).is_empty());

    // And it works: streamed in, streamed out.
    let path = format!("/r/data/{}", sha(&big));
    assert_eq!(l.post(&path, &big).await, 200);
    let res = l
        .req(Method::GET, &path)
        .header("range", "bytes=100-")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 206);
    assert_eq!(
        res.headers()["content-length"],
        (big.len() - 100).to_string().as_str()
    );
    assert_eq!(res.bytes().await.unwrap(), &big[100..]);
}

/// H11: a folder that was replaced under its name is noticed by the next `HEAD config`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listener_follows_a_replaced_repository() {
    let store = Store::new();
    let l = Listener::start(&store, Options::default()).await;
    assert_eq!(l.post("/r/?create=true", b"").await, 200);
    assert_eq!(l.post("/r/config", b"the old one").await, 200);
    let lock = data(82, 155);
    let lock_path = format!("/r/locks/{}", sha(&lock));
    assert_eq!(l.post(&lock_path, &lock).await, 200);

    // Renamed in the Drive UI; another machine creates the name anew.
    let old = store.folder("r");
    assert!(store.mem.rename(&old, "r-2025"));
    let other = Store {
        mem: store.mem.clone(),
        flaky: store.flaky.clone(),
        be: store.be.clone(),
    };
    let h = H2::stdio(&other, Options::default()).await;
    h.create().await;
    assert_eq!(h.post("/config", b"new").await.status, 200);

    let res = l.req(Method::HEAD, "/r/config").send().await.unwrap();
    assert_eq!(res.headers()["content-length"], "3");
    let res = l.req(Method::GET, "/r/config").send().await.unwrap();
    assert_eq!(res.bytes().await.unwrap(), &b"new"[..]);
    assert_eq!(l.status(Method::GET, &lock_path).await, 404);
    // The old one is reachable under its new name.
    assert_eq!(
        l.status(Method::GET, &lock_path.replace("/r/", "/r-2025/"))
            .await,
        200
    );
}

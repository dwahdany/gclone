//! WP3 acceptance (SPEC §12.1), Drive side: `DriveBackend` against `FakeDrive` — the generic
//! backend contract, the wire shapes of §6.4.1, the upload protocol of §6.2 and the error
//! handling of §6.5. No network beyond 127.0.0.1.

#[path = "support/fake_drive.rs"]
mod fake_drive;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use fake_drive::{FakeDrive, Route, fast_pacer};
use gclone::backend::drive::{
    DriveBackend, DriveConfig, DriveEndpoints, FIELDS, PacerConfig, ProbeOutcome, run_probes,
};
use gclone::backend::{Backend, Handle, ObjMeta, PutBody, conformance, get_all, stream_body};
use gclone::consts::{MULTIPART_MAX, PART_SIZE, UPLOAD_GRANULE};
use gclone::error::{AuthError, BackendError, QuotaKind};
use serde_json::{Value, json};
use tokio::sync::mpsc;

const PART: usize = PART_SIZE as usize;
const GRANULE: u64 = UPLOAD_GRANULE;

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

fn pattern(seed: u8, len: usize) -> Bytes {
    let mut buf = vec![0u8; len];
    blake3::Hasher::new()
        .update(&[0x3C, seed])
        .finalize_xof()
        .fill(&mut buf);
    buf.into()
}

fn md5(data: &[u8]) -> [u8; 16] {
    use md5::Digest;
    md5::Md5::digest(data).into()
}

async fn id(b: &DriveBackend) -> Handle {
    b.new_ids(1).await.unwrap().remove(0)
}

async fn folder(b: &DriveBackend, name: &str) -> Handle {
    let h = id(b).await;
    b.create_folder(&h, &Handle::top(), name).await.unwrap();
    h
}

/// A fake, a backend on it, and a folder to put things into.
async fn setup() -> (FakeDrive, DriveBackend, Handle) {
    let fake = FakeDrive::start().await;
    let b = fake.backend();
    let dir = folder(&b, "dir").await;
    (fake, b, dir)
}

async fn put(b: &DriveBackend, parent: &Handle, name: &str, data: &Bytes) -> ObjMeta {
    let h = id(b).await;
    b.put(&h, parent, name, stream_body(data.clone()))
        .await
        .unwrap()
}

async fn wait_until(what: &str, cond: impl Fn() -> bool) {
    for _ in 0..2000 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("timed out waiting until {what}");
}

/// A `Stream` put whose parts the test hands over one by one.
struct Feed {
    tx: mpsc::Sender<std::io::Result<Bytes>>,
    done: tokio::task::JoinHandle<Result<ObjMeta, BackendError>>,
}

fn start_stream(b: &DriveBackend, id: &Handle, parent: &Handle, total: u64) -> Feed {
    let (tx, parts) = mpsc::channel(1);
    let (b, id, parent) = (b.clone(), id.clone(), parent.clone());
    let done = tokio::spawn(async move {
        b.put(&id, &parent, "stream.bin", PutBody::Stream { total, parts })
            .await
    });
    Feed { tx, done }
}

impl Feed {
    async fn send(&self, part: Bytes) {
        // An aborted put has dropped its receiver; the test then looks at the put's result.
        let _ = self.tx.send(Ok(part)).await;
    }

    async fn finish(self) -> Result<ObjMeta, BackendError> {
        drop(self.tx);
        self.done.await.expect("the put task panicked")
    }
}

/// Every non-final Content-Range is a multiple of 256 KiB, the ranges are in bounds.
fn assert_granules(requests: &[(u64, u64, u64)]) {
    for &(start, len, total) in requests {
        assert!(
            len > 0 && start + len <= total,
            "range {start}+{len} of {total}"
        );
        if start + len != total {
            assert_eq!(
                len % GRANULE,
                0,
                "a non-final part of {len} bytes at {start}"
            );
        }
        assert_eq!(start % GRANULE, 0, "a part starting at {start}");
    }
}

fn is_fatal(e: &BackendError, want: u16) -> bool {
    matches!(e, BackendError::Fatal { status, .. } if *status == want)
}

/// An upload endpoint that takes request bodies at its own pace: what a slow uplink looks like
/// from the client, and what `FakeDrive` — which gets every body at loopback speed — cannot
/// show. A resumable initiation is answered `200` with a session URI on this server; every
/// other request `200` with `answer` as its JSON body, once its whole body was read.
struct SlowUpload {
    base: String,
    /// Body bytes read so far, over all requests.
    taken: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for SlowUpload {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl SlowUpload {
    /// Reads `step` body bytes, then waits `every`. `stop_at`: after that many bytes of one
    /// body nothing more is read, and the connection stays open.
    fn start(step: usize, every: Duration, stop_at: Option<u64>, answer: String) -> SlowUpload {
        // A small receive buffer, so that the pace reaches the sender instead of the kernel
        // swallowing the body.
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(64 * 1024).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(16).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let taken = Arc::new(AtomicU64::new(0));
        let (session, counter) = (format!("{base}/session/1?upload_id=slow"), taken.clone());
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let (answer, session, taken) = (answer.clone(), session.clone(), counter.clone());
                connections.spawn(async move {
                    let _ =
                        Self::serve(stream, step, every, stop_at, &answer, &session, &taken).await;
                });
            }
        });
        SlowUpload { base, taken, task }
    }

    fn taken(&self) -> u64 {
        self.taken.load(Ordering::Relaxed)
    }

    async fn serve(
        mut stream: tokio::net::TcpStream,
        step: usize,
        every: Duration,
        stop_at: Option<u64>,
        answer: &str,
        session: &str,
        taken: &AtomicU64,
    ) -> std::io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = vec![0u8; step];
        loop {
            // The head, and whatever part of the body came with it.
            let mut head = Vec::new();
            let body_at = loop {
                if let Some(at) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at + 4;
                }
                match stream.read(&mut buf).await? {
                    0 => return Ok(()),
                    n => head.extend_from_slice(&buf[..n]),
                }
            };
            let text = String::from_utf8_lossy(&head[..body_at]).to_ascii_lowercase();
            let len: u64 = text
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let mut got = (head.len() - body_at) as u64;
            taken.fetch_add(got, Ordering::Relaxed);
            while got < len {
                if stop_at.is_some_and(|stop| got >= stop) {
                    return std::future::pending().await;
                }
                tokio::time::sleep(every).await;
                let want = step.min((len - got) as usize);
                match stream.read(&mut buf[..want]).await? {
                    0 => return Ok(()),
                    n => {
                        got += n as u64;
                        taken.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
            }
            let reply = if text.contains("uploadtype=resumable") {
                format!("HTTP/1.1 200 OK\r\nLocation: {session}\r\nContent-Length: 0\r\n\r\n")
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\n\
                     Content-Length: {}\r\n\r\n{answer}",
                    answer.len()
                )
            };
            stream.write_all(reply.as_bytes()).await?;
        }
    }
}

/// A backend whose metadata and auth calls go to `fake` and whose uploads go to `slow`, with
/// `HTTP_READ_TIMEOUT` shortened to `read_timeout` and a single attempt per request.
fn slow_backend(fake: &FakeDrive, slow: &SlowUpload, read_timeout: Duration) -> DriveBackend {
    let cfg = DriveConfig {
        endpoints: DriveEndpoints {
            api: fake.endpoints().api,
            upload: format!("{}/upload", slow.base),
        },
        pacer: PacerConfig {
            max_attempts: 1,
            ..fast_pacer()
        },
        read_timeout,
        ..DriveConfig::default()
    };
    DriveBackend::new(fake.token_provider(), cfg).unwrap()
}

// ---------------------------------------------------------------------------------------------
// the generic contract
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn conformance_suite_passes_on_drive_backend() {
    let fake = FakeDrive::start().await;
    conformance::run(fake.backend()).await;
    // 3 parts + tail of the large object, one part + one byte for the refused second stream put
    assert!(fake.hits(Route::SessionPut) >= 4);
    assert_granules(&fake.session_requests());
}

#[tokio::test]
async fn conformance_suite_passes_with_short_pages_and_completion_conflicts() {
    let fake = FakeDrive::start().await;
    fake.set_page_cap(1);
    fake.conflict_at(Route::SessionPut);
    conformance::run(fake.backend()).await;
}

// ---------------------------------------------------------------------------------------------
// wire shapes (§6.4.1)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_fakes_wire_shapes_decode() {
    let (fake, b, dir) = setup().await;
    let data = pattern(1, 70_000);
    let before = b.now_ms();
    let meta = put(&b, &dir, "blob", &data).await;

    // What is on the wire: int64 as strings, RFC 3339 text, no size on folders.
    let token = fake.token_provider().access_token().await.unwrap();
    let http = reqwest::Client::new();
    let get = |path: String| {
        let (http, token) = (http.clone(), token.clone());
        async move {
            let r = http.get(path).bearer_auth(token).send().await.unwrap();
            assert_eq!(r.status(), 200);
            r.json::<Value>().await.unwrap()
        }
    };
    let api = fake.endpoints().api;
    let file = get(format!(
        "{api}/drive/v3/files/{}?fields={FIELDS}",
        meta.handle.0
    ))
    .await;
    assert_eq!(file["size"], json!("70000"), "size is a JSON string");
    assert_eq!(file["md5Checksum"].as_str().unwrap().len(), 32);
    let created = file["createdTime"].as_str().unwrap();
    assert!(
        created.ends_with('Z') && created.contains('T') && created.len() == 24,
        "{created}"
    );
    assert_eq!(file["parents"], json!([dir.0]));
    assert_eq!(file["trashed"], json!(false));
    let dir_json = get(format!("{api}/drive/v3/files/{}?fields={FIELDS}", dir.0)).await;
    assert!(dir_json.get("size").is_none() && dir_json.get("md5Checksum").is_none());
    assert_eq!(dir_json["mimeType"], "application/vnd.google-apps.folder");
    let bare = get(format!("{api}/drive/v3/files/{}", meta.handle.0)).await;
    assert_eq!(
        bare,
        json!({ "kind": "drive#file", "id": meta.handle.0, "name": "blob", "mimeType": "application/octet-stream" })
    );
    let about = get(format!(
        "{api}/drive/v3/about?fields=storageQuota,user(emailAddress)"
    ))
    .await;
    assert!(
        about["storageQuota"]["limit"].is_string() && about["storageQuota"]["usage"].is_string()
    );
    assert!(about["storageQuota"]["usageInDriveTrash"].is_string());

    // What the backend makes of it.
    assert_eq!(meta.size, 70_000);
    assert_eq!(meta.md5, Some(md5(&data)));
    assert!(meta.created_ms + 5_000 >= before && meta.created_ms <= b.now_ms() + 5_000);
    assert_eq!(
        meta.created_ms,
        gclone::util::parse_rfc3339_ms(created).unwrap()
    );
    let stat = b.stat(&dir).await.unwrap().unwrap();
    assert!(stat.is_folder && stat.parent.is_top());
    assert_eq!((stat.size, stat.md5), (0, None));
    assert!(stat.created_ms > 0);

    b.trash(&meta.handle).await.unwrap();
    let quota = b.about().await.unwrap();
    assert_eq!(quota.limit, Some(16_106_127_360));
    assert_eq!(quota.usage, 70_000);
    assert_eq!(quota.usage_in_trash, 70_000);
    assert_eq!(quota.account.as_deref(), Some("me@example.com"));
}

#[tokio::test]
async fn top_level_parents_and_the_root_folder() {
    let (fake, b, dir) = setup().await;
    let top = stat_top(&b).await;
    assert!(top.is_folder && top.handle.is_top() && top.parent.is_top() && !top.trashed);
    assert_eq!(top.name, "");

    // A second backend knows nothing yet: it has to ask for the root id — once.
    let inner = put(&b, &dir, "inner", &pattern(2, 10)).await;
    let outer = put(&b, &Handle::top(), "outer", &pattern(3, 10)).await;
    assert!(outer.parent.is_top());
    let fresh = fake.backend();
    let root_lookups = || {
        fake.requests(Route::Stat)
            .iter()
            .filter(|r| r.path.ends_with("/root"))
            .count()
    };
    let before = root_lookups();
    assert_eq!(
        fresh.stat(&inner.handle).await.unwrap().unwrap().parent,
        dir
    );
    assert!(
        fresh
            .stat(&outer.handle)
            .await
            .unwrap()
            .unwrap()
            .parent
            .is_top()
    );
    let found = fresh.find_by_name("dir").await.unwrap();
    assert!(found.len() == 1 && found[0].parent.is_top());
    assert_eq!(root_lookups() - before, 1);

    // The top level itself cannot be trashed, deleted or downloaded.
    assert!(is_fatal(&b.trash(&Handle::top()).await.unwrap_err(), 400));
    assert!(is_fatal(&b.delete(&Handle::top()).await.unwrap_err(), 400));
    assert!(is_fatal(
        &b.get(&Handle::top(), None).await.err().unwrap(),
        403
    ));
    assert!(
        is_fatal(&b.get(&dir, None).await.err().unwrap(), 403),
        "a folder has no content"
    );
}

async fn stat_top(b: &DriveBackend) -> ObjMeta {
    b.stat(&Handle::top())
        .await
        .unwrap()
        .expect("the top level always exists")
}

#[tokio::test]
async fn classification_falls_back_to_the_status_on_html() {
    let (fake, b, dir) = setup().await;
    let html = "<!DOCTYPE html><title>Error</title><p>rate limit quota userRateLimitExceeded";
    fake.fail_next_raw(Route::Stat, 1, 403, html);
    assert!(
        is_fatal(&b.stat(&dir).await.unwrap_err(), 403),
        "HTML is not searched for reasons"
    );
    fake.fail_next_raw(Route::Stat, 1, 404, html);
    assert!(b.stat(&dir).await.unwrap().is_none());
    fake.fail_next_raw(Route::Stat, 2, 503, html);
    assert!(
        b.stat(&dir).await.unwrap().is_some(),
        "a 503 page is retried"
    );
    fake.fail_next_raw(Route::Stat, 1, 429, "slow down");
    assert!(b.stat(&dir).await.unwrap().is_some());
    assert_eq!(b.pacer().stats().throttles, 1);
}

#[tokio::test]
async fn no_client_follows_redirects() {
    let (fake, b, dir) = setup().await;
    let obj = put(&b, &dir, "x", &pattern(4, 100)).await;
    // The injected 3xx points back at the same route: a client that followed it would succeed.
    for status in [301, 302, 307] {
        fake.fail_next_raw(Route::About, 1, status, "moved");
        let hits = fake.hits(Route::About);
        assert!(
            is_fatal(&b.about().await.unwrap_err(), status),
            "API client, {status}"
        );
        assert_eq!(fake.hits(Route::About), hits + 1);

        fake.fail_next_raw(Route::Media, 1, status, "moved");
        let hits = fake.hits(Route::Media);
        assert!(
            is_fatal(&b.get(&obj.handle, None).await.err().unwrap(), status),
            "transfer client, {status}"
        );
        assert_eq!(fake.hits(Route::Media), hits + 1);

        fake.fail_next_raw(Route::Multipart, 1, status, "moved");
        let hits = fake.hits(Route::Multipart);
        let body = PutBody::Small(pattern(5, 100));
        let h = id(&b).await;
        assert!(
            is_fatal(&b.put(&h, &dir, "y", body).await.unwrap_err(), status),
            "upload client, {status}"
        );
        assert_eq!(fake.hits(Route::Multipart), hits + 1);
    }
    // A 308 on a metadata route is an error too, not a redirect.
    fake.fail_next_raw(Route::About, 1, 308, "");
    assert!(is_fatal(&b.about().await.unwrap_err(), 308));
}

// ---------------------------------------------------------------------------------------------
// multipart
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn multipart_request_shape() {
    let (fake, b, dir) = setup().await;
    let data = pattern(5, 1234);
    let h = id(&b).await;
    b.put(&h, &dir, "it's \"a\" name", PutBody::Small(data.clone()))
        .await
        .unwrap();
    let top = id(&b).await;
    b.put(&top, &Handle::top(), "top", PutBody::Small(data.clone()))
        .await
        .unwrap();

    let seen = fake.requests(Route::Multipart);
    assert_eq!(seen.len(), 2);
    let first = &seen[0];
    assert_eq!(
        (first.method.as_str(), first.path.as_str()),
        ("POST", "/upload/drive/v3/files")
    );
    assert_eq!(first.param("uploadType").as_deref(), Some("multipart"));
    assert_eq!(first.param("fields").as_deref(), Some(FIELDS));
    let content_type = &first.headers["content-type"];
    let boundary = content_type
        .strip_prefix("multipart/related; boundary=")
        .expect(content_type);
    assert!(boundary.len() >= 16);
    assert_eq!(
        first.part_types,
        [
            "application/json; charset=UTF-8",
            "application/octet-stream"
        ]
    );
    assert_eq!(
        first.json,
        Some(
            json!({ "id": h.0, "name": "it's \"a\" name", "parents": [dir.0], "mimeType": "application/octet-stream" })
        )
    );
    assert!(first.headers["authorization"].starts_with("Bearer "));
    assert!(first.headers["user-agent"].starts_with("gclone/"));
    // top level: no `parents` at all
    assert_eq!(
        seen[1].json,
        Some(json!({ "id": top.0, "name": "top", "mimeType": "application/octet-stream" }))
    );
    assert_ne!(
        seen[1].headers["content-type"], *content_type,
        "the boundary is random"
    );
    assert_eq!(fake.object(&h.0).unwrap(), data);
    assert_eq!(fake.hits(Route::Stat), 0, "the answer carries everything");

    // an empty object
    let empty = put(&b, &dir, "empty", &Bytes::new()).await;
    assert_eq!((empty.size, empty.md5), (0, Some(md5(b""))));
    // a zero-length stream has no byte range to send: it goes multipart as well
    let h = id(&b).await;
    let (_tx, parts) = mpsc::channel(1);
    let meta = b
        .put(
            &h,
            &dir,
            "empty-stream",
            PutBody::Stream { total: 0, parts },
        )
        .await
        .unwrap();
    assert_eq!(meta.size, 0);
    assert_eq!(fake.hits(Route::ResumableInit), 0);

    // a Small body above MULTIPART_MAX is a caller bug, refused before any request
    let hits = fake.hits(Route::Multipart);
    let h = id(&b).await;
    let big = PutBody::Small(pattern(6, MULTIPART_MAX as usize + 1));
    assert!(is_fatal(
        &b.put(&h, &dir, "big", big).await.unwrap_err(),
        400
    ));
    assert_eq!(fake.hits(Route::Multipart), hits);
}

#[tokio::test]
async fn multipart_max_is_the_boundary_between_the_two_uploads() {
    let (fake, b, dir) = setup().await;
    let at = pattern(7, MULTIPART_MAX as usize);
    let meta = put(&b, &dir, "at", &at).await;
    assert_eq!(
        (fake.hits(Route::Multipart), fake.hits(Route::ResumableInit)),
        (1, 0)
    );
    assert_eq!((meta.size, meta.md5), (MULTIPART_MAX, Some(md5(&at))));

    let over = pattern(8, MULTIPART_MAX as usize + 1);
    let meta = put(&b, &dir, "over", &over).await;
    assert_eq!(
        (fake.hits(Route::Multipart), fake.hits(Route::ResumableInit)),
        (1, 1)
    );
    assert_eq!(
        fake.session_requests(),
        [(0, MULTIPART_MAX + 1, MULTIPART_MAX + 1)]
    );
    assert_eq!((meta.size, meta.md5), (MULTIPART_MAX + 1, Some(md5(&over))));
    assert_eq!(fake.object(&meta.handle.0).unwrap(), over);
}

// ---------------------------------------------------------------------------------------------
// resumable
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn resumable_sends_fields_at_initiation_and_uses_the_session_uri_verbatim() {
    let (fake, b, dir) = setup().await;
    let data = pattern(9, 2 * PART + 300_000);
    let h = id(&b).await;
    let meta = b
        .put(&h, &dir, "big", stream_body(data.clone()))
        .await
        .unwrap();

    let init = &fake.requests(Route::ResumableInit)[0];
    assert_eq!(
        (init.method.as_str(), init.path.as_str()),
        ("POST", "/upload/drive/v3/files")
    );
    assert_eq!(init.param("uploadType").as_deref(), Some("resumable"));
    assert_eq!(
        init.param("fields").as_deref(),
        Some(FIELDS),
        "fields= belongs on the initiation URL"
    );
    assert_eq!(
        init.headers["x-upload-content-type"],
        "application/octet-stream"
    );
    assert_eq!(
        init.headers["x-upload-content-length"],
        data.len().to_string()
    );
    assert!(init.headers["content-type"].starts_with("application/json"));
    assert_eq!(
        init.json,
        Some(
            json!({ "id": h.0, "name": "big", "parents": [dir.0], "mimeType": "application/octet-stream" })
        )
    );

    // The fake refuses a session URI that was re-encoded or extended; these are its raw escapes.
    let puts = fake.requests(Route::SessionPut);
    assert_eq!(puts.len(), 3);
    for p in &puts {
        assert!(
            p.query.contains("_x%2By%3D%3D&upload_protocol=resumable"),
            "{}",
            p.query
        );
        assert!(
            p.param("fields").is_none(),
            "nothing is appended to the session URI"
        );
        assert_eq!(p.method, "PUT");
        assert_eq!(p.headers["content-length"], p.body_len.to_string());
    }

    // The fake answers a create in the default projection unless fields= reached it: the meta
    // is complete without a follow-up stat.
    assert_eq!(fake.hits(Route::Stat), 0);
    assert_eq!((meta.size, meta.md5), (data.len() as u64, Some(md5(&data))));
    assert!(meta.created_ms > 0);
    assert_eq!(
        (&meta.handle, &meta.parent, meta.name.as_str()),
        (&h, &dir, "big")
    );
    assert_eq!(fake.object(&h.0).unwrap(), data);

    let total = data.len() as u64;
    assert_eq!(
        fake.session_requests(),
        [
            (0, PART_SIZE, total),
            (PART_SIZE, PART_SIZE, total),
            (2 * PART_SIZE, 300_000, total)
        ]
    );
    assert_eq!(fake.status_queries(), 0);
}

#[tokio::test]
async fn a_stripped_completion_body_costs_exactly_one_stat() {
    let (fake, b, dir) = setup().await;
    for (seed, len) in [(10u8, MULTIPART_MAX as usize + 77), (11, 5000)] {
        let data = pattern(seed, len);
        fake.strip_completion_body_once();
        let stats = fake.hits(Route::Stat);
        let meta = put(&b, &dir, "stripped", &data).await;
        assert_eq!(fake.hits(Route::Stat), stats + 1, "{len} bytes");
        assert_eq!((meta.size, meta.md5), (len as u64, Some(md5(&data))));
        assert!(meta.created_ms > 0);
        assert_eq!(meta.parent, dir);
    }
}

#[tokio::test]
async fn content_ranges_are_multiples_of_256_kib_whatever_the_parts_are() {
    let (fake, b, dir) = setup().await;
    // Parts that are not PART_SIZE and not granule multiples (the contract says PART_SIZE; the
    // state machine must not depend on it).
    let data = pattern(12, 9 * 700_000 + 4321);
    let h = id(&b).await;
    let feed = start_stream(&b, &h, &dir, data.len() as u64);
    for chunk in data.chunks(700_000) {
        feed.send(data.slice_ref(chunk)).await;
    }
    let meta = feed.finish().await.unwrap();
    assert_eq!(meta.md5, Some(md5(&data)));
    assert_eq!(fake.object(&h.0).unwrap(), data);
    // Parts made of several slices still go out with a Content-Length, not chunked.
    for p in fake.requests(Route::SessionPut) {
        assert_eq!(p.headers["content-length"], p.body_len.to_string());
        assert!(!p.headers.contains_key("transfer-encoding"));
    }
    let requests = fake.session_requests();
    assert!(requests.len() >= 5, "{requests:?}");
    assert_granules(&requests);
    let mut next = 0;
    for (start, len, _) in requests {
        assert_eq!(start, next, "ranges follow each other");
        next = start + len;
    }
    assert_eq!(next, data.len() as u64);
}

#[tokio::test]
async fn a_partial_ack_is_found_by_a_status_query_and_resent_from_there() {
    let (fake, b, dir) = setup().await;
    let data = pattern(13, PART + 1_000_000);
    let total = data.len() as u64;
    fake.ack_only(5 * GRANULE + 1000); // 5 granules stay, the answer is a 503
    let h = id(&b).await;
    let meta = b
        .put(&h, &dir, "acked", stream_body(data.clone()))
        .await
        .unwrap();
    assert_eq!(meta.md5, Some(md5(&data)));
    assert_eq!(
        fake.object(&h.0).unwrap(),
        data,
        "resent bytes are the same bytes"
    );
    assert_eq!(fake.status_queries(), 1);
    assert_eq!(
        fake.session_requests(),
        [
            (0, PART_SIZE, total),
            (5 * GRANULE, PART_SIZE - 5 * GRANULE, total),
            (PART_SIZE, 1_000_000, total)
        ]
    );

    // Nothing kept at all: the query answers a 308 without Range, the part goes out again.
    let data = pattern(14, PART + 5);
    fake.ack_only(1000);
    let meta = put(&b, &dir, "acked-0", &data).await;
    assert_eq!(meta.md5, Some(md5(&data)));
    assert_eq!(fake.status_queries(), 2);
}

#[tokio::test]
async fn a_session_that_advances_through_cut_parts_is_not_given_up() {
    // Three rounds are all a session without progress gets here.
    let fake = FakeDrive::start().await;
    let pacer = PacerConfig {
        max_attempts: 3,
        ..fast_pacer()
    };
    let b = fake.backend_with(fake.token_provider(), pacer);
    let dir = folder(&b, "dir").await;
    let data = pattern(70, MULTIPART_MAX as usize + 4321);
    // Twelve part PUTs in a row are cut: one granule stays each time, the answer is a 503.
    // Every one of those rounds moved the session forward — seen in the status query.
    fake.ack_only_times(GRANULE, 12);
    let h = id(&b).await;
    let meta = b
        .put(&h, &dir, "limping", stream_body(data.clone()))
        .await
        .unwrap();
    assert_eq!(meta.md5, Some(md5(&data)));
    assert_eq!(fake.object(&h.0).unwrap(), data);
    assert_eq!(fake.status_queries(), 12);
    let starts: Vec<u64> = fake.session_requests().iter().map(|r| r.0).collect();
    let expected: Vec<u64> = (0..=12).map(|k| k * GRANULE).collect();
    assert_eq!(starts, expected, "each part goes on where the last one got");

    // Rounds that keep nothing still end the put after `max_attempts` of them.
    let sent = fake.session_requests().len();
    fake.ack_only_times(0, u32::MAX);
    let h = id(&b).await;
    let body = stream_body(pattern(71, MULTIPART_MAX as usize + 1));
    let err = b.put(&h, &dir, "stuck", body).await.unwrap_err();
    assert!(matches!(err, BackendError::Transient(_)), "{err:?}");
    assert_eq!(fake.session_requests().len() - sent, 3);
    assert!(fake.object(&h.0).is_none());
}

#[tokio::test]
async fn rounds_without_progress_wait_before_the_next_one() {
    let (fake, b, dir) = setup().await;
    let unit = Duration::from_millis(200);
    b.pacer().set_backoff_unit(unit);

    // Two parts in a row are answered 308 with the old Range: nothing was kept. The part goes
    // out again — after BACKOFF(0), then BACKOFF(1), not back to back.
    let data = pattern(72, 3 * GRANULE as usize + 77);
    let total = data.len() as u64;
    fake.drop_parts(2);
    let h = id(&b).await;
    let started = Instant::now();
    let feed = start_stream(&b, &h, &dir, total);
    feed.send(data.clone()).await;
    let meta = feed.finish().await.unwrap();
    let took = started.elapsed();
    assert_eq!(meta.md5, Some(md5(&data)));
    assert_eq!(fake.session_requests(), [(0, total, total); 3]);
    assert_eq!(fake.status_queries(), 0);
    assert!(took >= 3 * unit, "three sends in {took:?}");

    // Every byte is acknowledged, but the session is not complete yet: the part's answer and
    // two status queries say 308 with the full Range. The queries are spaced the same way and
    // the part is not sent again.
    let data = pattern(73, 2 * GRANULE as usize + 5);
    let total = data.len() as u64;
    fake.hold_completion(3);
    let h = id(&b).await;
    let started = Instant::now();
    let feed = start_stream(&b, &h, &dir, total);
    feed.send(data.clone()).await;
    let meta = feed.finish().await.unwrap();
    let took = started.elapsed();
    assert_eq!(meta.md5, Some(md5(&data)));
    assert_eq!(fake.object(&h.0).unwrap(), data);
    assert_eq!(fake.session_requests().len(), 4, "one more part, sent once");
    assert_eq!(fake.status_queries(), 3);
    assert!(took >= 3 * unit, "three status queries in {took:?}");

    // A session that never completes still ends in Transient.
    b.pacer().set_backoff_unit(Duration::from_millis(1));
    fake.hold_completion(u32::MAX);
    let h = id(&b).await;
    let feed = start_stream(&b, &h, &dir, total);
    feed.send(data.clone()).await;
    let err = feed.finish().await.unwrap_err();
    assert!(
        matches!(&err, BackendError::Transient(m) if m.contains("no progress")),
        "{err:?}"
    );
    let max = u64::from(PacerConfig::default().max_attempts);
    assert_eq!(fake.status_queries(), 3 + max);
}

#[tokio::test]
async fn a_308_without_range_restarts_from_zero_while_the_part_is_retained() {
    let (fake, b, dir) = setup().await;
    let data = pattern(15, PART + 12_345);
    let total = data.len() as u64;
    fake.omit_range_header_once();
    let h = id(&b).await;
    let meta = b
        .put(&h, &dir, "restart", stream_body(data.clone()))
        .await
        .unwrap();
    assert_eq!(meta.md5, Some(md5(&data)));
    assert_eq!(fake.object(&h.0).unwrap(), data);
    assert_eq!(
        fake.session_requests(),
        [
            (0, PART_SIZE, total),
            (0, PART_SIZE, total),
            (PART_SIZE, 12_345, total)
        ]
    );
}

#[tokio::test]
async fn a_308_without_range_is_session_lost_once_the_bytes_are_gone() {
    let (fake, b, dir) = setup().await;
    let data = pattern(16, 2 * PART + 99);
    let h = id(&b).await;
    let feed = start_stream(&b, &h, &dir, data.len() as u64);
    feed.send(data.slice(..PART)).await;
    wait_until("the first part was sent", || {
        fake.session_requests().len() == 1
    })
    .await;
    // The first part is acknowledged and let go; now the server forgets everything.
    fake.omit_range_header_once();
    feed.send(data.slice(PART..2 * PART)).await;
    feed.send(data.slice(2 * PART..)).await;
    assert!(matches!(
        feed.finish().await,
        Err(BackendError::SessionLost)
    ));
    assert!(fake.object(&h.0).is_none());
    assert!(b.stat(&h).await.unwrap().is_none(), "never partial");
}

#[tokio::test]
async fn an_expired_session_is_session_lost() {
    let (fake, b, dir) = setup().await;
    fake.expire_sessions();
    let h = id(&b).await;
    let body = stream_body(pattern(17, MULTIPART_MAX as usize + 1));
    assert!(matches!(
        b.put(&h, &dir, "gone", body).await,
        Err(BackendError::SessionLost)
    ));
    assert_eq!(
        fake.hits(Route::SessionPut),
        1,
        "a 404 on the session is not retried"
    );

    // any other 4xx on the session as well; a 410 at the status query too
    let (fake, b, dir) = setup().await;
    fake.fail_next(Route::SessionPut, 1, 400, "badRequest");
    let h = id(&b).await;
    let body = stream_body(pattern(18, MULTIPART_MAX as usize + 1));
    assert!(matches!(
        b.put(&h, &dir, "bad", body).await,
        Err(BackendError::SessionLost)
    ));
    fake.fail_next(Route::SessionPut, 1, 503, "backendError");
    fake.fail_next_raw(Route::SessionPut, 1, 410, "Gone");
    let h = id(&b).await;
    let body = stream_body(pattern(19, MULTIPART_MAX as usize + 1));
    assert!(matches!(
        b.put(&h, &dir, "gone-at-query", body).await,
        Err(BackendError::SessionLost)
    ));
}

#[tokio::test]
async fn a_lost_final_response_is_settled_by_the_status_query_without_resending() {
    let (fake, b, dir) = setup().await;
    let data = pattern(20, PART + 4242);
    let h = id(&b).await;
    let feed = start_stream(&b, &h, &dir, data.len() as u64);
    feed.send(data.slice(..PART)).await;
    wait_until("the first part was sent", || {
        fake.session_requests().len() == 1
    })
    .await;
    fake.lose_response_once(Route::SessionPut); // the final part is stored, the answer is a 503
    feed.send(data.slice(PART..)).await;
    let meta = feed.finish().await.unwrap();
    assert_eq!((meta.size, meta.md5), (data.len() as u64, Some(md5(&data))));
    assert!(meta.created_ms > 0);
    assert_eq!(
        fake.session_requests().len(),
        2,
        "the final part is not sent twice"
    );
    assert_eq!(fake.status_queries(), 1);
    assert_eq!(
        fake.hits(Route::Stat),
        0,
        "the query's 200 carries the File"
    );
    assert_eq!(fake.object(&h.0).unwrap(), data);
}

#[tokio::test]
async fn a_401_on_a_part_costs_one_refresh_and_the_upload_completes() {
    let (fake, b, dir) = setup().await;
    let data = pattern(21, 2 * PART + 31_337);
    let h = id(&b).await;
    let feed = start_stream(&b, &h, &dir, data.len() as u64);
    feed.send(data.slice(..PART)).await;
    wait_until("the first part was sent", || {
        fake.session_requests().len() == 1
    })
    .await;
    let refreshes = fake.hits(Route::AuthRefresh);
    fake.unauthorized_once(Route::SessionPut); // part 2
    feed.send(data.slice(PART..2 * PART)).await;
    feed.send(data.slice(2 * PART..)).await;
    let meta = feed.finish().await.unwrap();
    assert_eq!(meta.md5, Some(md5(&data)));
    assert_eq!(fake.object(&h.0).unwrap(), data, "byte-identical");
    assert_eq!(
        fake.hits(Route::AuthRefresh),
        refreshes + 1,
        "exactly one refresh"
    );
    assert_eq!(
        fake.status_queries(),
        1,
        "the session is asked where it stands"
    );
    // part 1, part 2 (401), part 2 again, tail
    let total = data.len() as u64;
    assert_eq!(
        fake.session_requests(),
        [
            (0, PART_SIZE, total),
            (PART_SIZE, PART_SIZE, total),
            (PART_SIZE, PART_SIZE, total),
            (2 * PART_SIZE, 31_337, total)
        ]
    );
    // The retried requests carry the fresh token.
    let puts = fake.requests(Route::SessionPut);
    assert_eq!(
        puts[0].headers["authorization"],
        puts[1].headers["authorization"]
    );
    assert_ne!(
        puts[1].headers["authorization"],
        puts[2].headers["authorization"]
    );
}

#[tokio::test]
async fn two_401s_in_a_row_end_the_put_with_auth_expired() {
    let (fake, b, dir) = setup().await;
    fake.fail_next(Route::SessionPut, 2, 401, "authError"); // the part, then the status query
    let h = id(&b).await;
    let body = stream_body(pattern(22, MULTIPART_MAX as usize + 9));
    let err = b.put(&h, &dir, "401", body).await.unwrap_err();
    assert!(
        matches!(err, BackendError::Auth(AuthError::Expired)),
        "{err:?}"
    );
    assert_eq!(fake.hits(Route::SessionPut), 2);
    assert!(fake.object(&h.0).is_none());

    // A 401 with a 503 in between is not "two in a row".
    let (fake, b, dir) = setup().await;
    fake.unauthorized_once(Route::SessionPut);
    fake.fail_next(Route::SessionPut, 1, 503, "backendError");
    fake.unauthorized_once(Route::SessionPut);
    let data = pattern(23, MULTIPART_MAX as usize + 9);
    let meta = put(&b, &dir, "401-503-401", &data).await;
    assert_eq!(meta.md5, Some(md5(&data)));
}

#[tokio::test]
async fn throttled_parts_back_off_and_go_on() {
    let (fake, b, dir) = setup().await;
    fake.fail_next(Route::SessionPut, 1, 403, "userRateLimitExceeded");
    fake.fail_next(Route::SessionPut, 1, 429, "rateLimitExceeded");
    let data = pattern(24, MULTIPART_MAX as usize + 1);
    let meta = put(&b, &dir, "throttled", &data).await;
    assert_eq!(meta.md5, Some(md5(&data)));
    assert_eq!(b.pacer().stats().throttles, 2);
    assert!(
        b.pacer().stats().write_rate < fast_pacer().write_start,
        "a throttled part slows the writes"
    );

    // A session that only ever throttles ends in RateLimited; a full one in QuotaExceeded.
    fake.fail_next(Route::SessionPut, u32::MAX, 429, "rateLimitExceeded");
    let h = id(&b).await;
    let body = stream_body(pattern(25, MULTIPART_MAX as usize + 1));
    assert!(matches!(
        b.put(&h, &dir, "never", body).await,
        Err(BackendError::RateLimited)
    ));
    let (fake, b, dir) = setup().await;
    fake.fail_next(Route::SessionPut, 1, 403, "storageQuotaExceeded");
    let h = id(&b).await;
    let body = stream_body(pattern(26, MULTIPART_MAX as usize + 1));
    let err = b.put(&h, &dir, "full", body).await.unwrap_err();
    assert!(
        matches!(err, BackendError::QuotaExceeded(QuotaKind::StorageFull)),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_failing_source_aborts_with_io() {
    let (fake, b, dir) = setup().await;
    let h = id(&b).await;
    let feed = start_stream(&b, &h, &dir, 3 * PART_SIZE);
    feed.send(pattern(27, PART)).await;
    let _ = feed
        .tx
        .send(Err(std::io::Error::other("the source changed")))
        .await;
    assert!(matches!(feed.finish().await, Err(BackendError::Io(_))));
    assert!(fake.object(&h.0).is_none());

    // a channel that ends early, and a body longer than announced
    let h = id(&b).await;
    let feed = start_stream(&b, &h, &dir, 2 * PART_SIZE);
    feed.send(pattern(28, PART)).await;
    let err = feed.finish().await.unwrap_err();
    assert!(
        matches!(&err, BackendError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof),
        "{err:?}"
    );
    let h = id(&b).await;
    let feed = start_stream(&b, &h, &dir, PART_SIZE + 10);
    feed.send(pattern(29, PART)).await;
    feed.send(pattern(30, 11)).await;
    assert!(is_fatal(&feed.finish().await.unwrap_err(), 400));
}

// ---------------------------------------------------------------------------------------------
// conflict rule
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_409_for_an_existing_id_returns_the_existing_meta() {
    for at in [Route::Multipart, Route::ResumableInit, Route::SessionPut] {
        let (fake, b, dir) = setup().await;
        fake.conflict_at(at);
        let original = pattern(31, 5000);
        let h = id(&b).await;
        let first = b
            .put(&h, &dir, "original", PutBody::Small(original.clone()))
            .await
            .unwrap();

        let other = match at {
            Route::Multipart => pattern(32, 600),
            _ => pattern(33, MULTIPART_MAX as usize + 600),
        };
        let again = b
            .put(&h, &Handle::top(), "other", stream_body(other))
            .await
            .unwrap();
        assert_eq!(
            (again.size, again.md5),
            (5000, Some(md5(&original))),
            "{at:?}"
        );
        assert_eq!((again.name.as_str(), &again.parent), ("original", &dir));
        assert_eq!(again.created_ms, first.created_ms);
        assert_eq!(
            fake.object(&h.0).unwrap(),
            original,
            "nothing is overwritten"
        );
        assert_eq!(fake.hits(Route::Stat), 1, "one stat resolves the conflict");
        match at {
            Route::Multipart => assert_eq!(fake.hits(Route::Multipart), 2),
            Route::ResumableInit => assert_eq!(
                fake.hits(Route::SessionPut),
                0,
                "the 409 came at initiation"
            ),
            _ => assert_eq!(
                fake.hits(Route::SessionPut),
                1,
                "the 409 came at completion"
            ),
        }
    }
}

#[tokio::test]
async fn a_409_without_an_object_is_session_lost_after_three_stats() {
    for at in [Route::Multipart, Route::ResumableInit, Route::SessionPut] {
        let (fake, b, dir) = setup().await;
        fake.conflict_then_absent(at);
        let data = match at {
            Route::Multipart => pattern(34, 600),
            _ => pattern(35, MULTIPART_MAX as usize + 600),
        };
        let h = id(&b).await;
        let err = b
            .put(&h, &dir, "phantom", stream_body(data.clone()))
            .await
            .unwrap_err();
        assert!(matches!(err, BackendError::SessionLost), "{at:?}: {err:?}");
        assert_eq!(fake.hits(Route::Stat), 3, "{at:?}");
        assert!(fake.object(&h.0).is_none());
        // The id is burnt for the caller; a new one works.
        let meta = put(&b, &dir, "phantom", &data).await;
        assert_eq!(meta.md5, Some(md5(&data)));
    }
}

#[tokio::test]
async fn create_folder_is_idempotent_and_needs_its_parent() {
    let (fake, b, dir) = setup().await;
    let h = id(&b).await;
    b.create_folder(&h, &dir, "sub").await.unwrap();
    b.create_folder(&h, &dir, "sub").await.unwrap();
    assert_eq!(fake.hits(Route::CreateFolder), 3);
    let seen = &fake.requests(Route::CreateFolder)[1];
    assert_eq!(
        (seen.method.as_str(), seen.path.as_str()),
        ("POST", "/drive/v3/files")
    );
    assert_eq!(seen.param("fields").as_deref(), Some(FIELDS));
    assert_eq!(
        seen.json,
        Some(
            json!({ "id": h.0, "name": "sub", "mimeType": "application/vnd.google-apps.folder", "parents": [dir.0] })
        )
    );
    let top_folder = &fake.requests(Route::CreateFolder)[0];
    assert!(top_folder.json.as_ref().unwrap().get("parents").is_none());

    let missing = Handle("1NoSuchFolder".into());
    let h = id(&b).await;
    let err = b.create_folder(&h, &missing, "x").await.unwrap_err();
    assert!(
        matches!(&err, BackendError::Fatal { status: 404, reason, .. } if reason == "notFound"),
        "{err:?}"
    );
    for body in [
        stream_body(pattern(36, 10)),
        stream_body(pattern(37, MULTIPART_MAX as usize + 1)),
    ] {
        let err = b.put(&h, &missing, "x", body).await.unwrap_err();
        assert!(
            matches!(&err, BackendError::Fatal { status: 404, reason, .. } if reason == "notFound"),
            "{err:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// listing, trash, delete, download
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn listing_follows_next_page_token_and_asks_for_untrashed_objects() {
    let (fake, b, dir) = setup().await;
    for i in 0..5u8 {
        put(&b, &dir, &format!("obj-{i}"), &pattern(40 + i, 10)).await;
    }
    fake.set_page_cap(2);
    let listed = b.list(&dir).await.unwrap();
    let mut names: Vec<&str> = listed.iter().map(|m| m.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["obj-0", "obj-1", "obj-2", "obj-3", "obj-4"]);
    assert!(
        listed
            .iter()
            .all(|m| m.parent == dir && m.size == 10 && m.md5.is_some())
    );

    let pages = fake.requests(Route::List);
    assert_eq!(pages.len(), 3, "2 + 2 + 1");
    for page in &pages {
        assert_eq!(
            (page.method.as_str(), page.path.as_str()),
            ("GET", "/drive/v3/files")
        );
        assert_eq!(
            page.param("q").unwrap(),
            format!("'{}' in parents and trashed = false", dir.0)
        );
        assert_eq!(page.param("pageSize").as_deref(), Some("1000"));
        assert_eq!(page.param("spaces").as_deref(), Some("drive"));
        assert_eq!(
            page.param("fields").unwrap(),
            format!("nextPageToken,files({FIELDS})")
        );
    }
    assert!(pages[0].param("pageToken").is_none());
    assert!(pages[1].param("pageToken").is_some() && pages[2].param("pageToken").is_some());
    assert_ne!(pages[1].param("pageToken"), pages[2].param("pageToken"));

    // the top level is 'root'
    b.list(&Handle::top()).await.unwrap();
    assert_eq!(
        fake.requests(Route::List)
            .last()
            .unwrap()
            .param("q")
            .unwrap(),
        "'root' in parents and trashed = false"
    );

    // a rejected page token restarts the listing
    let before = fake.hits(Route::List);
    fake.reject_page_token_once();
    assert_eq!(b.list(&dir).await.unwrap().len(), 5);
    assert_eq!(
        fake.hits(Route::List) - before,
        2 + 3,
        "page 1, refused page 2, then all three again"
    );

    // a folder that does not exist lists as empty
    assert!(
        b.list(&Handle("1NoSuchFolder".into()))
            .await
            .unwrap()
            .is_empty()
    );

    // … and `list_strict` says so instead: its callers act on "empty" (§7.6, R2).
    let missing = b.list_strict(&Handle("1NoSuchFolder".into())).await;
    assert!(
        matches!(missing, Err(BackendError::NotFound)),
        "{missing:?}"
    );
    assert_eq!(b.list_strict(&dir).await.unwrap().len(), 5);
    // A `404` for a folder that exists is never a listing, empty or short. It is not
    // retried: the caller looks at the folder.
    let before = fake.hits(Route::List);
    fake.fail_next(Route::List, 1, 404, "notFound");
    let listed = b.list_strict(&dir).await;
    assert!(matches!(listed, Err(BackendError::NotFound)), "{listed:?}");
    assert_eq!(fake.hits(Route::List) - before, 1);
    fake.fail_next(Route::List, 1, 404, "notFound");
    assert!(
        b.list(&dir).await.unwrap().is_empty(),
        "`list` is unchanged"
    );
}

#[tokio::test]
async fn find_by_name_escapes_the_query_and_filters_exactly() {
    let (fake, b, dir) = setup().await;
    let tricky = r"it's a \ name";
    let a = put(&b, &dir, tricky, &pattern(50, 10)).await;
    put(&b, &dir, &tricky.to_uppercase(), &pattern(51, 10)).await;
    fake.set_page_cap(1);
    let found = b.find_by_name(tricky).await.unwrap();
    // Drive's `name =` ignores case (the fake does too): the backend filters byte-exactly.
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].handle, a.handle);
    assert_eq!(found[0].parent, dir);
    let seen = fake.requests(Route::List);
    assert_eq!(
        seen[0].param("q").unwrap(),
        r"name = 'it\'s a \\ name' and trashed = false"
    );
    assert_eq!(seen.len(), 2, "both pages were read");

    b.trash(&a.handle).await.unwrap();
    assert!(b.find_by_name(tricky).await.unwrap().is_empty());
}

#[tokio::test]
async fn list_lag_hides_new_objects_for_some_listings() {
    let (fake, b, dir) = setup().await;
    fake.set_list_lag(2);
    let meta = put(&b, &dir, "late", &pattern(52, 10)).await;
    assert!(b.list(&dir).await.unwrap().is_empty());
    assert!(b.find_by_name("late").await.unwrap().is_empty());
    assert!(
        b.stat(&meta.handle).await.unwrap().is_some(),
        "by id it is there at once"
    );
    assert_eq!(b.list(&dir).await.unwrap().len(), 1);
}

#[tokio::test]
async fn trash_patches_and_delete_sends_delete() {
    let (fake, b, dir) = setup().await;
    let meta = put(&b, &dir, "x", &pattern(53, 10)).await;
    b.trash(&meta.handle).await.unwrap();
    b.untrash(&meta.handle).await.unwrap();
    let patches = fake.requests(Route::Patch);
    assert_eq!(patches.len(), 2);
    for (p, want) in patches.iter().zip([true, false]) {
        assert_eq!(p.method, "PATCH");
        assert_eq!(p.path, format!("/drive/v3/files/{}", meta.handle.0));
        assert_eq!(p.param("fields").as_deref(), Some(FIELDS));
        assert_eq!(p.json, Some(json!({ "trashed": want })));
    }
    b.delete(&meta.handle).await.unwrap();
    let deletes = fake.requests(Route::Delete);
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].method, "DELETE");
    assert_eq!(
        deletes[0].path,
        format!("/drive/v3/files/{}", meta.handle.0)
    );
    assert_eq!(deletes[0].body_len, 0);
    assert!(fake.object(&meta.handle.0).is_none());
    assert!(matches!(
        b.delete(&meta.handle).await,
        Err(BackendError::NotFound)
    ));
    assert!(matches!(
        b.trash(&meta.handle).await,
        Err(BackendError::NotFound)
    ));
}

#[tokio::test]
async fn ranged_downloads() {
    let (fake, b, dir) = setup().await;
    let data = pattern(54, 100_000);
    let meta = put(&b, &dir, "x", &data).await;
    let h = &meta.handle;
    assert_eq!(get_all(&b, h, Some(10..20)).await.unwrap(), data[10..20]);
    let media = fake.requests(Route::Media);
    assert_eq!(media[0].param("alt").as_deref(), Some("media"));
    assert_eq!(
        media[0].headers["range"], "bytes=10-19",
        "end is exclusive in the API, inclusive on the wire"
    );
    assert_eq!(
        get_all(&b, h, Some(99_990..u64::MAX)).await.unwrap(),
        data[99_990..]
    );
    assert_eq!(
        fake.requests(Route::Media)[1].headers["range"],
        "bytes=99990-"
    );
    assert_eq!(get_all(&b, h, None).await.unwrap(), data);
    assert!(!fake.requests(Route::Media)[2].headers.contains_key("range"));

    // past the end → empty (the server says 416); an empty range → empty without a download
    assert!(
        get_all(&b, h, Some(100_000..100_010))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        get_all(&b, h, Some(500_000..u64::MAX))
            .await
            .unwrap()
            .is_empty()
    );
    let downloads = fake.hits(Route::Media);
    assert!(get_all(&b, h, Some(7..7)).await.unwrap().is_empty());
    assert_eq!(fake.hits(Route::Media), downloads);
    let absent = id(&b).await;
    assert!(matches!(
        b.get(&absent, Some(7..7)).await,
        Err(BackendError::NotFound)
    ));
    assert!(matches!(
        b.get(&absent, Some(0..7)).await,
        Err(BackendError::NotFound)
    ));
}

#[tokio::test]
async fn an_abuse_flag_is_acknowledged_on_the_second_request() {
    let (fake, b, dir) = setup().await;
    let data = pattern(55, 3000);
    let meta = put(&b, &dir, "flagged", &data).await;
    fake.mark_abusive(&meta.handle.0);
    assert_eq!(get_all(&b, &meta.handle, None).await.unwrap(), data);
    let media = fake.requests(Route::Media);
    assert_eq!(media.len(), 2);
    assert!(media[0].param("acknowledgeAbuse").is_none());
    assert_eq!(media[1].param("acknowledgeAbuse").as_deref(), Some("true"));
    assert_eq!(media[1].param("alt").as_deref(), Some("media"));
    // ranges survive the retry
    assert_eq!(
        get_all(&b, &meta.handle, Some(5..50)).await.unwrap(),
        data[5..50]
    );
    assert_eq!(
        fake.requests(Route::Media)[3].headers["range"],
        "bytes=5-49"
    );
}

// ---------------------------------------------------------------------------------------------
// errors, tokens, pacing (§6.5)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_401_costs_one_refresh_and_one_retry() {
    let (fake, b, dir) = setup().await;
    let refreshes = fake.hits(Route::AuthRefresh);
    assert_eq!(refreshes, 1, "the provider started without a token");
    fake.unauthorized_once(Route::Stat);
    assert!(b.stat(&dir).await.unwrap().is_some());
    assert_eq!(fake.hits(Route::AuthRefresh), 2, "one POST /auth/refresh");
    let stats = fake.requests(Route::Stat);
    assert_eq!(stats.len(), 2);
    assert_ne!(
        stats[0].headers["authorization"],
        stats[1].headers["authorization"]
    );
    let refresh = &fake.requests(Route::AuthRefresh)[1];
    assert_eq!(
        (refresh.method.as_str(), refresh.path.as_str()),
        ("POST", "/auth/refresh")
    );
    assert_eq!(
        refresh.json,
        Some(json!({ "refresh_token": "rt-ok", "client": "device" }))
    );

    // twice in a row: Auth(Expired), after exactly one more refresh
    fake.fail_next(Route::Stat, 2, 401, "authError");
    let err = b.stat(&dir).await.unwrap_err();
    assert!(
        matches!(err, BackendError::Auth(AuthError::Expired)),
        "{err:?}"
    );
    assert_eq!(fake.hits(Route::AuthRefresh), 3);
    assert_eq!(fake.requests(Route::Stat).len(), 4);
}

#[tokio::test]
async fn a_dead_login_surfaces_as_an_auth_error() {
    let (fake, b, dir) = setup().await;
    fake.revoke_refresh_token(); // the access token dies with it: 401 → refresh → invalid_grant
    let err = b.stat(&dir).await.unwrap_err();
    assert!(
        matches!(err, BackendError::Auth(AuthError::Expired)),
        "{err:?}"
    );
    let err = b
        .put(&id_free(), &dir, "x", stream_body(pattern(56, 10)))
        .await
        .unwrap_err();
    assert!(
        matches!(err, BackendError::Auth(AuthError::Expired)),
        "{err:?}"
    );

    let (fake, b, dir) = setup().await;
    fake.break_client();
    fake.unauthorized_once(Route::Stat);
    let err = b.stat(&dir).await.unwrap_err();
    assert!(
        matches!(err, BackendError::Auth(AuthError::WorkerMisconfigured(_))),
        "{err:?}"
    );
    // and for a backend that never had a token
    let fresh = fake.backend();
    let err = fresh.about().await.unwrap_err();
    assert!(
        matches!(err, BackendError::Auth(AuthError::WorkerMisconfigured(_))),
        "{err:?}"
    );
}

fn id_free() -> Handle {
    Handle("1SomeUnusedId".into())
}

#[tokio::test]
async fn terminal_errors_map_to_their_variants() {
    let (fake, b, dir) = setup().await;
    let obj = put(&b, &dir, "x", &pattern(57, 100)).await;
    let quota = |e: BackendError| match e {
        BackendError::QuotaExceeded(kind) => kind,
        other => panic!("expected QuotaExceeded, got {other:?}"),
    };

    fake.fail_next(Route::Multipart, 1, 403, "storageQuotaExceeded");
    let err = b
        .put(&id_free(), &dir, "y", stream_body(pattern(58, 10)))
        .await
        .unwrap_err();
    assert_eq!(quota(err), QuotaKind::StorageFull);
    fake.fail_next(Route::ResumableInit, 1, 403, "storageQuotaExceeded");
    let body = stream_body(pattern(59, MULTIPART_MAX as usize + 1));
    assert_eq!(
        quota(b.put(&id_free(), &dir, "y", body).await.unwrap_err()),
        QuotaKind::StorageFull
    );
    fake.fail_next(Route::Multipart, 1, 403, "uploadLimitExceeded");
    let err = b
        .put(&id_free(), &dir, "y", stream_body(pattern(60, 10)))
        .await
        .unwrap_err();
    assert_eq!(quota(err), QuotaKind::DailyUpload);
    fake.fail_next(Route::Media, 1, 403, "downloadQuotaExceeded");
    assert_eq!(
        quota(b.get(&obj.handle, None).await.err().unwrap()),
        QuotaKind::DailyDownload
    );
    fake.fail_next(Route::List, 1, 403, "dailyLimitExceeded");
    assert_eq!(
        quota(b.list(&dir).await.unwrap_err()),
        QuotaKind::ProjectApiQuota
    );
    fake.fail_next(Route::Stat, 1, 403, "appNotAuthorizedToFile");
    assert!(matches!(
        b.stat(&obj.handle).await,
        Err(BackendError::AppNotAuthorized)
    ));
    fake.fail_next(Route::Patch, 1, 403, "numChildrenInNonRootLimitExceeded");
    let err = b.trash(&obj.handle).await.unwrap_err();
    assert!(
        matches!(&err, BackendError::Fatal { status: 403, reason, .. } if reason == "numChildrenInNonRootLimitExceeded"),
        "{err:?}"
    );
    // none of these was retried
    assert_eq!(fake.hits(Route::Patch), 1);
    assert_eq!(fake.hits(Route::List), 1);
    assert_eq!(b.pacer().stats().throttles, 0);
}

#[tokio::test]
async fn throttles_and_server_errors_are_retried_up_to_the_attempt_limit() {
    let (fake, b, dir) = setup().await;
    fake.fail_next(Route::Stat, 1, 403, "userRateLimitExceeded");
    fake.fail_next(Route::Stat, 1, 429, "rateLimitExceeded");
    fake.fail_next(Route::Stat, 1, 500, "internalError");
    fake.fail_next(Route::Stat, 1, 502, "badGateway");
    assert!(b.stat(&dir).await.unwrap().is_some());
    assert_eq!(fake.hits(Route::Stat), 5);
    assert_eq!(b.pacer().stats().throttles, 2);
    assert!(
        b.pacer().stats().read_rate < fast_pacer().read_start,
        "throttling halves the class rate"
    );
    assert_eq!(b.pacer().stats().write_rate, fast_pacer().write_start);

    let max = u64::from(PacerConfig::default().max_attempts);
    fake.fail_next(Route::About, u32::MAX, 429, "rateLimitExceeded");
    assert!(matches!(b.about().await, Err(BackendError::RateLimited)));
    assert_eq!(fake.hits(Route::About), max);
    fake.fail_next(Route::Delete, u32::MAX, 503, "backendError");
    assert!(matches!(
        b.delete(&dir).await,
        Err(BackendError::Transient(_))
    ));
    assert_eq!(fake.hits(Route::Delete), max);
    assert!(b.stat(&dir).await.unwrap().is_some(), "nothing was deleted");
}

#[tokio::test]
async fn connection_failures_are_transient() {
    let fake = FakeDrive::start().await;
    // A port nothing listens on: bind one and close it again.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let cfg = DriveConfig {
        endpoints: DriveEndpoints {
            api: format!("http://127.0.0.1:{closed}"),
            upload: format!("http://127.0.0.1:{closed}/upload"),
        },
        pacer: PacerConfig {
            max_attempts: 3,
            ..fast_pacer()
        },
        ..DriveConfig::default()
    };
    let b = DriveBackend::new(fake.token_provider(), cfg).unwrap();
    b.pacer().set_backoff_unit(Duration::from_millis(1));
    assert!(matches!(b.about().await, Err(BackendError::Transient(_))));
    assert!(matches!(
        b.new_ids(1).await,
        Err(BackendError::Transient(_))
    ));
    let body = PutBody::Small(pattern(61, 10));
    assert!(matches!(
        b.put(&id_free(), &Handle::top(), "x", body).await,
        Err(BackendError::Transient(_))
    ));
    assert!(b.new_ids(0).await.unwrap().is_empty(), "no ids, no request");
}

/// The File resource a create answers with (§6.4.1), for [`SlowUpload`].
fn file_json(id: &Handle, parent: &Handle, name: &str, data: &[u8]) -> String {
    let md5: String = md5(data).iter().map(|b| format!("{b:02x}")).collect();
    json!({
        "id": id.0, "name": name, "mimeType": "application/octet-stream", "parents": [parent.0],
        "size": data.len().to_string(), "md5Checksum": md5,
        "createdTime": "2026-11-11T09:14:03.123Z", "trashed": false,
    })
    .to_string()
}

#[tokio::test]
async fn an_upload_that_flows_steadily_may_take_longer_than_the_read_timeout() {
    // reqwest's `read_timeout` is one deadline for connect + request body + response headers;
    // with it, this request was cut off after `read_timeout` although bytes kept flowing.
    let fake = FakeDrive::start().await;
    let setup_backend = fake.backend();
    let dir = folder(&setup_backend, "dir").await;
    let h = id(&setup_backend).await;
    let data = pattern(80, MULTIPART_MAX as usize);
    // 64 KiB every 50 ms: the 4 MiB body needs more than three seconds.
    let slow = SlowUpload::start(
        64 * 1024,
        Duration::from_millis(50),
        None,
        file_json(&h, &dir, "slow", &data),
    );
    let read_timeout = Duration::from_secs(2);
    let b = slow_backend(&fake, &slow, read_timeout);
    let started = Instant::now();
    let meta = b
        .put(&h, &dir, "slow", PutBody::Small(data.clone()))
        .await
        .unwrap();
    let took = started.elapsed();
    assert_eq!((meta.size, meta.md5), (data.len() as u64, Some(md5(&data))));
    assert!(slow.taken() > data.len() as u64, "the whole body arrived");
    assert!(
        took > read_timeout,
        "the request outlived the read timeout: {took:?}"
    );
}

#[tokio::test]
async fn an_upload_that_stops_moving_is_given_up_after_the_read_timeout() {
    let fake = FakeDrive::start().await;
    let setup_backend = fake.backend();
    let dir = folder(&setup_backend, "dir").await;
    let h = id(&setup_backend).await;
    // The server reads 1 MiB of the 16 MiB part and then nothing, with the connection open.
    let stop = 1024 * 1024;
    let slow = SlowUpload::start(64 * 1024, Duration::ZERO, Some(stop), String::new());
    let read_timeout = Duration::from_secs(1);
    let b = slow_backend(&fake, &slow, read_timeout);
    let started = Instant::now();
    let body = stream_body(pattern(81, PART + 1));
    // The request's total timeout (minutes for a part) is not what ends it.
    let err = tokio::time::timeout(Duration::from_secs(60), b.put(&h, &dir, "stalled", body))
        .await
        .expect("the stall is noticed")
        .unwrap_err();
    let took = started.elapsed();
    assert!(
        matches!(&err, BackendError::Transient(m) if m.contains("stalled")),
        "{err:?}"
    );
    assert!(took >= read_timeout, "{took:?}");
    assert!(slow.taken() >= stop && slow.taken() < PART_SIZE);
}

#[tokio::test]
async fn the_write_breaker_reports_the_daily_upload_limit() {
    let fake = FakeDrive::start().await;
    let pacer = PacerConfig {
        breaker: Duration::from_millis(40),
        max_attempts: 1000,
        ..fast_pacer()
    };
    let b = fake.backend_with(fake.token_provider(), pacer);
    let dir = folder(&b, "dir").await;
    // Writes are throttled without one success for longer than the breaker time.
    fake.fail_next(Route::Multipart, u32::MAX, 403, "userRateLimitExceeded");
    let err = b
        .put(&id_free(), &dir, "x", stream_body(pattern(62, 10)))
        .await
        .unwrap_err();
    assert!(
        matches!(err, BackendError::QuotaExceeded(QuotaKind::DailyUpload)),
        "{err:?}"
    );
    assert!(b.pacer().write_breaker_tripped());
    assert!(fake.hits(Route::Multipart) >= 2);
    // Reads are not affected by it: a throttled read is just retried.
    fake.fail_next(Route::Stat, 1, 429, "rateLimitExceeded");
    assert!(b.stat(&dir).await.unwrap().is_some());
}

#[tokio::test]
async fn the_id_pool_batches_and_falls_back_to_ten() {
    let fake = FakeDrive::start().await;
    let b = fake.backend();
    assert!(b.new_ids(0).await.unwrap().is_empty());
    assert_eq!(fake.hits(Route::GenerateIds), 0);
    let mut all = b.new_ids(3).await.unwrap();
    all.extend(b.new_ids(90).await.unwrap());
    assert_eq!(
        fake.hits(Route::GenerateIds),
        1,
        "one batch of 100 serves both"
    );
    let seen = &fake.requests(Route::GenerateIds)[0];
    assert_eq!(seen.path, "/drive/v3/files/generateIds");
    assert_eq!(
        (
            seen.param("count").as_deref(),
            seen.param("space").as_deref(),
            seen.param("type").as_deref()
        ),
        (Some("100"), Some("drive"), Some("files"))
    );
    all.extend(b.new_ids(250).await.unwrap());
    assert_eq!(fake.hits(Route::GenerateIds), 4);
    let unique: std::collections::HashSet<_> = all.iter().collect();
    assert_eq!(unique.len(), 343);

    // a 400 → count=10 from then on
    let b = fake.backend();
    fake.fail_next(Route::GenerateIds, 1, 400, "invalid");
    let before = fake.hits(Route::GenerateIds);
    assert_eq!(b.new_ids(15).await.unwrap().len(), 15);
    let counts: Vec<_> = fake.requests(Route::GenerateIds)[before as usize..]
        .iter()
        .map(|r| r.param("count").unwrap())
        .collect();
    assert_eq!(counts, ["100", "10", "10"]);
}

#[tokio::test]
async fn now_ms_follows_the_servers_date_header() {
    let (_fake, b, _dir) = setup().await;
    let local = gclone::util::now_ms();
    let server = b.now_ms();
    // The fake runs on this machine's clock; `Date` has one-second resolution.
    assert!(
        server.abs_diff(local) < 3_000,
        "server {server} vs local {local}"
    );
}

// ---------------------------------------------------------------------------------------------
// probes (§2.9)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_automatable_probes_run_against_the_fake() {
    let fake = FakeDrive::start().await;
    let cfg = DriveConfig {
        endpoints: fake.endpoints(),
        pacer: fast_pacer(),
        ..DriveConfig::default()
    };
    let lines = run_probes(fake.token_provider(), cfg).await;
    let ids: Vec<u8> = lines.iter().map(|l| l.id).collect();
    assert_eq!(ids, [6, 8, 9, 10, 12, 13], "{lines:#?}");
    for line in &lines {
        assert!(!line.question.is_empty());
        assert!(
            matches!(line.outcome, ProbeOutcome::Pass(_) | ProbeOutcome::Info(_)),
            "probe {}: {:?}",
            line.id,
            line.outcome
        );
    }
    let text = |id: u8| match &lines.iter().find(|l| l.id == id).unwrap().outcome {
        ProbeOutcome::Pass(t)
        | ProbeOutcome::Info(t)
        | ProbeOutcome::Fail(t)
        | ProbeOutcome::Skipped(t) => t.clone(),
    };
    assert!(
        text(6).contains("multipart: 409")
            && text(6).contains("409 at initiation")
            && text(6).contains("found")
    );
    assert!(text(10).contains("count=1000 accepted"));
    assert!(
        matches!(lines[2].outcome, ProbeOutcome::Pass(_)),
        "probe 9 on the fake"
    );
    assert!(text(13).contains("does not show it"));
    // The throwaway folder is trashed afterwards.
    let b = fake.backend();
    assert!(b.list(&Handle::top()).await.unwrap().is_empty());
    assert!(fake.object_ids().len() > 5, "the probes did create objects");

    // Without a usable login every row is skipped, none is missing.
    fake.revoke_refresh_token();
    let cfg = DriveConfig {
        endpoints: fake.endpoints(),
        pacer: fast_pacer(),
        ..DriveConfig::default()
    };
    let lines = run_probes(fake.token_provider(), cfg).await;
    assert_eq!(lines.len(), 6);
    assert!(
        lines
            .iter()
            .all(|l| matches!(l.outcome, ProbeOutcome::Skipped(_)))
    );
}

#[tokio::test]
async fn backends_share_one_drive() {
    let fake = FakeDrive::start().await;
    let (a, b) = (fake.backend(), fake.backend());
    let dir = folder(&a, "shared").await;
    let data = pattern(63, 2000);
    let meta = put(&a, &dir, "from-a", &data).await;
    assert_eq!(get_all(&b, &meta.handle, None).await.unwrap(), data);
    assert_eq!(b.list(&dir).await.unwrap().len(), 1);
    let _keep: Arc<_> = fake.token_provider();
}

//! Multipart body and the resumable-upload state machine (SPEC §6.2) — owned by WP3.
//! Private to `backend::drive`.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use reqwest::header::{CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, LOCATION, RANGE, RETRY_AFTER};
use tokio::sync::mpsc::Receiver;
use tokio::time::Instant;

use super::api::{
    BLOB_MIME, Failure, File, Outgoing, decode, error_body, header_text, metadata, terminal,
};
use super::errors::{HttpClass, classify, parse_range_header};
use super::pacer::CallKind;
use super::{FIELDS, Inner};
use crate::auth::login::describe;
use crate::backend::{Handle, ObjMeta, bad_request};
use crate::consts::{UPLOAD_GRANULE, UPLOAD_MIN_RATE, UPLOAD_SLICE};
use crate::error::{AuthError, BackendError, QuotaKind};
use crate::util;

/// The conflict rule looks for the object this often before giving the id up.
const CONFLICT_STATS: u32 = 3;
const JSON_UTF8: &str = "application/json; charset=UTF-8";

/// `multipart/related`: the JSON metadata part first, then the bytes (§6.2). One buffer, so the
/// request can be replayed as is.
pub(super) fn multipart_body(boundary: &str, metadata: &serde_json::Value, data: &[u8]) -> Bytes {
    let head = format!(
        "--{boundary}\r\nContent-Type: {JSON_UTF8}\r\n\r\n{metadata}\r\n\
         --{boundary}\r\nContent-Type: {BLOB_MIME}\r\n\r\n"
    );
    let tail = format!("\r\n--{boundary}--\r\n");
    let mut body = BytesMut::with_capacity(head.len() + data.len() + tail.len());
    body.put_slice(head.as_bytes());
    body.put_slice(data);
    body.put_slice(tail.as_bytes());
    body.freeze()
}

/// Watches an upload body leave (§6.4). reqwest's read timeout cannot do this: before the
/// answer's headers arrive it is a single deadline that sending the body does not push back, so
/// it would cap the duration of the whole request instead of catching a stall.
pub(super) struct Watch {
    /// The stall limit, `HTTP_READ_TIMEOUT`.
    limit: Duration,
    origin: Instant,
    /// Milliseconds after `origin` at which the request started or the HTTP stack last took a
    /// slice of the body; [`HANDED_OVER`] once it has taken the last one.
    moved: AtomicU64,
}

/// The whole body is with the HTTP stack and the kernel. How much of it is still unsent cannot
/// be seen from here; from now on only the request's total timeout rules.
const HANDED_OVER: u64 = u64::MAX;

impl Watch {
    fn new(limit: Duration) -> Self {
        Watch {
            limit,
            origin: Instant::now(),
            moved: AtomicU64::new(0),
        }
    }

    fn note(&self, last: bool) {
        let at = match last {
            true => HANDED_OVER,
            false => self.origin.elapsed().as_millis() as u64,
        };
        self.moved.store(at, Ordering::Relaxed);
    }

    /// The request goes out now: the stall clock starts here, not where the request was built.
    pub(super) fn start(&self) {
        if self.moved.load(Ordering::Relaxed) != HANDED_OVER {
            self.note(false);
        }
    }

    /// Completes once no slice was taken for `limit`; never, once the body is handed over.
    pub(super) async fn stalled(&self) {
        loop {
            let seen = self.moved.load(Ordering::Relaxed);
            if seen == HANDED_OVER {
                return std::future::pending().await;
            }
            tokio::time::sleep_until(self.origin + Duration::from_millis(seen) + self.limit).await;
            if self.moved.load(Ordering::Relaxed) == seen {
                return;
            }
        }
    }

    pub(super) fn complaint(&self) -> String {
        format!(
            "the upload stalled: no bytes left for {:?}, the connection was given up",
            self.limit
        )
    }
}

/// An upload body as a stream of slices of at most `UPLOAD_SLICE` bytes (cut without copying),
/// each of which reports to the [`Watch`] when the HTTP stack takes it.
struct Slices {
    rest: VecDeque<Bytes>,
    watch: Arc<Watch>,
}

impl futures_util::Stream for Slices {
    type Item = std::io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        let slice = match this.rest.front_mut() {
            Some(front) if front.len() > UPLOAD_SLICE => Some(front.split_to(UPLOAD_SLICE)),
            _ => this.rest.pop_front(),
        };
        // The stack stops asking after `Content-Length` bytes, so the last slice says "done".
        this.watch.note(this.rest.is_empty());
        Poll::Ready(slice.map(Ok))
    }
}

/// The parts of a stream body the server may still ask for: bytes `[base, end)`.
struct Window {
    base: u64,
    end: u64,
    parts: VecDeque<Bytes>,
}

impl Window {
    fn push(&mut self, part: Bytes) {
        self.end += part.len() as u64;
        self.parts.push_back(part);
    }

    /// Forgets the parts that lie entirely below `acked`.
    fn release_below(&mut self, acked: u64) {
        while let Some(first) = self.parts.front() {
            let first_end = self.base + first.len() as u64;
            if first_end > acked {
                break;
            }
            self.base = first_end;
            self.parts.pop_front();
        }
    }

    /// `[from, from + len)` as slices of the retained parts (no copy).
    fn slices(&self, from: u64, len: u64) -> Vec<Bytes> {
        let (mut at, to) = (self.base, from + len);
        let mut out = Vec::new();
        for part in &self.parts {
            let part_end = at + part.len() as u64;
            let (a, b) = (from.max(at), to.min(part_end));
            if a < b {
                out.push(part.slice((a - at) as usize..(b - at) as usize));
            }
            at = part_end;
        }
        out
    }
}

/// What one request on the session URI means for the state machine.
enum Step {
    /// `308`: the server holds this many bytes.
    Progress(u64),
    /// `200` / `201` with the File resource.
    Done(Bytes),
    Conflict,
    Unauthorized,
    /// Network error or `5xx`: ask the session where it stands.
    Retry(String),
    Throttle(Option<Duration>),
    /// `404`, `410`, any other `4xx`.
    Lost,
    Fail(BackendError),
}

impl Inner {
    /// Gives `request` — built on the upload client — the body `slices` and the two limits of
    /// §6.4: the stall watch, and a total timeout that leaves room for every byte at
    /// `UPLOAD_MIN_RATE`. `Content-Length` is explicit: the body is a stream.
    pub(super) fn upload_request(
        &self,
        request: reqwest::RequestBuilder,
        slices: Vec<Bytes>,
    ) -> Outgoing {
        let len: u64 = slices.iter().map(|s| s.len() as u64).sum();
        let watch = Arc::new(Watch::new(self.read_timeout));
        let body = Slices {
            rest: slices.into_iter().filter(|s| !s.is_empty()).collect(),
            watch: watch.clone(),
        };
        if body.rest.is_empty() {
            watch.note(true);
        }
        let allowance = self.read_timeout + Duration::from_secs(len.div_ceil(UPLOAD_MIN_RATE));
        Outgoing {
            request: request
                .header(CONTENT_LENGTH, len)
                .timeout(allowance)
                .body(reqwest::Body::wrap_stream(body)),
            watch: Some(watch),
        }
    }

    /// Small objects: one `uploadType=multipart` request.
    pub(super) async fn put_small(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
        data: Bytes,
    ) -> Result<ObjMeta, BackendError> {
        let boundary = format!("gclone-{}", util::hex(&util::random::<16>()));
        let body = multipart_body(&boundary, &metadata(id, parent, name, BLOB_MIME), &data);
        drop(data);
        let content_type = format!("multipart/related; boundary={boundary}");
        let url = self.upload_url();
        let sent = self
            .call(CallKind::Create, || {
                let request = self
                    .upload
                    .post(&url)
                    .query(&[("uploadType", "multipart"), ("fields", FIELDS)])
                    .header(CONTENT_TYPE, &content_type);
                self.upload_request(request, vec![body.clone()])
            })
            .await;
        match sent {
            Ok(reply) => self.created(id, parent, &reply.body).await,
            Err(Failure::Conflict) => self.resolve_conflict(id, parent).await,
            Err(f) => Err(f.into_create_error()),
        }
    }

    /// Conflict rule (§6.2): the id exists, or is on its way to existing. The caller of `put`
    /// compares size and md5 of what is found.
    async fn resolve_conflict(
        &self,
        id: &Handle,
        parent: &Handle,
    ) -> Result<ObjMeta, BackendError> {
        for attempt in 0..CONFLICT_STATS {
            if attempt > 0 {
                tokio::time::sleep(self.pacer.backoff_for(attempt - 1)).await;
            }
            if let Some(meta) = self.stat_expecting(id, parent).await? {
                return Ok(meta);
            }
        }
        // Reserved by an upload that never finished: the id is burnt, the caller takes a new one.
        Err(BackendError::SessionLost)
    }

    /// The answer of a finished create. Drive answers in its default projection when `fields=`
    /// did not take effect: then one `stat` supplies size, md5 and creation time.
    async fn created(
        &self,
        id: &Handle,
        parent: &Handle,
        body: &[u8],
    ) -> Result<ObjMeta, BackendError> {
        if let Ok(file) = decode::<File>(body)
            && file.id == id.0
            && file.is_complete_blob()
        {
            return self.created_meta(file, parent).await;
        }
        match self.stat_expecting(id, parent).await? {
            Some(meta) => Ok(meta),
            None => Err(BackendError::SessionLost),
        }
    }

    /// Large objects: a resumable session fed from `parts` (§6.2).
    pub(super) async fn put_stream(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
        total: u64,
        mut parts: Receiver<std::io::Result<Bytes>>,
    ) -> Result<ObjMeta, BackendError> {
        // 1. Initiate. `fields=` here decides the projection of the completing answer.
        let url = self.upload_url();
        let meta = metadata(id, parent, name, BLOB_MIME).to_string();
        let initiated = self
            .call(CallKind::Create, || {
                self.upload
                    .post(&url)
                    .query(&[("uploadType", "resumable"), ("fields", FIELDS)])
                    .header("X-Upload-Content-Type", BLOB_MIME)
                    .header("X-Upload-Content-Length", total)
                    .header(CONTENT_TYPE, JSON_UTF8)
                    .body(meta.clone())
            })
            .await;
        let reply = match initiated {
            Ok(reply) => reply,
            Err(Failure::Conflict) => return self.resolve_conflict(id, parent).await,
            Err(f) => return Err(f.into_create_error()),
        };
        // The session URI is opaque: used verbatim, nothing appended, nothing re-encoded.
        let Some(session) = header_text(&reply.headers, &LOCATION).map(str::to_owned) else {
            return Err(BackendError::Transient(
                "Drive opened an upload session without a session URI".to_string(),
            ));
        };

        // 2. Send loop.
        let max = self.pacer.max_attempts();
        let mut window = Window {
            base: 0,
            end: 0,
            parts: VecDeque::new(),
        };
        let mut acked = 0u64;
        // The most the server ever held. Progress is measured against this, not against `acked`,
        // so that a session which keeps forgetting bytes and taking them again still ends.
        let mut best = 0u64;
        // The next request is a status query, not a part.
        let mut query = false;
        // Rounds in a row without the server taking new bytes — whether a part's own answer or
        // the status query after a failed part says so.
        let mut stalled = 0u32;
        let mut unauthorized = false;
        loop {
            let asked = query;
            let step = if query {
                self.session_request(&session, total, None).await
            } else {
                if acked < window.base {
                    // The server wants bytes that were already let go.
                    return Err(BackendError::SessionLost);
                }
                window.release_below(acked);
                while window.end < total && window.end - acked < UPLOAD_GRANULE {
                    match parts.recv().await {
                        Some(Ok(part)) => {
                            if window.end + part.len() as u64 > total {
                                return Err(bad_request(format!(
                                    "the upload body is longer than the announced {total} bytes"
                                )));
                            }
                            window.push(part);
                        }
                        // The source changed: stop sending; the session expires on its own.
                        Some(Err(e)) => return Err(BackendError::Io(e)),
                        None => {
                            return Err(BackendError::Io(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                format!(
                                    "the upload body ended after {} of {total} bytes",
                                    window.end
                                ),
                            )));
                        }
                    }
                }
                let available = window.end - acked;
                // The largest multiple of the granule at hand, or everything once the end is.
                let len = if window.end == total {
                    available
                } else {
                    available - available % UPLOAD_GRANULE
                };
                if len == 0 {
                    // Every byte is acknowledged, yet the session is not complete: ask again
                    // (a round of its own — `asked` stays false, so it counts and backs off).
                    self.session_request(&session, total, None).await
                } else {
                    let slices = window.slices(acked, len);
                    self.session_request(&session, total, Some((acked, len, slices)))
                        .await
                }
            };
            if !matches!(step, Step::Unauthorized) {
                unauthorized = false;
            }
            match step {
                Step::Progress(held) => {
                    if held > window.end {
                        return Err(BackendError::SessionLost);
                    }
                    query = false;
                    if held > best {
                        // New bytes are with the server. A part cut off halfway counts too: the
                        // status query after it (`asked`) is where that shows.
                        best = held;
                        stalled = 0;
                        self.pacer.on_success(CallKind::UploadPart);
                    } else if !asked {
                        // A part went out and nothing was kept (e.g. a 308 without `Range`), or
                        // every byte is held and the session is still not complete. A round
                        // without progress like any other: counted, and not repeated at once.
                        stalled += 1;
                        if stalled >= max {
                            return Err(BackendError::Transient(
                                "the upload session makes no progress".to_string(),
                            ));
                        }
                        tokio::time::sleep(self.pacer.backoff_for(stalled - 1)).await;
                    }
                    // (A status query without news: its failed round is counted already.)
                    acked = held;
                }
                Step::Done(body) => {
                    self.pacer.on_success(CallKind::UploadPart);
                    return self.created(id, parent, &body).await;
                }
                Step::Conflict => return self.resolve_conflict(id, parent).await,
                Step::Unauthorized => {
                    // §6.2 step 5: refresh once, ask the session, go on; a second 401 in a row
                    // is final. A 401 is never a lost session.
                    stalled += 1;
                    if unauthorized || stalled >= max {
                        return Err(BackendError::Auth(AuthError::Expired));
                    }
                    unauthorized = true;
                    self.tokens.force_refresh().await?;
                    query = true;
                }
                Step::Retry(detail) => {
                    stalled += 1;
                    if stalled >= max {
                        return Err(BackendError::Transient(detail));
                    }
                    tokio::time::sleep(self.pacer.backoff_for(stalled - 1)).await;
                    query = true;
                }
                Step::Throttle(retry_after) => {
                    let sleep = self
                        .pacer
                        .on_throttle(CallKind::UploadPart, retry_after, stalled);
                    if self.pacer.write_breaker_tripped() {
                        return Err(BackendError::QuotaExceeded(QuotaKind::DailyUpload));
                    }
                    stalled += 1;
                    if stalled >= max {
                        return Err(BackendError::RateLimited);
                    }
                    tokio::time::sleep(sleep).await;
                    query = true;
                }
                Step::Lost => return Err(BackendError::SessionLost),
                Step::Fail(e) => return Err(e),
            }
        }
    }

    /// One `PUT <session>`: a part (`Some((start, len, slices))`) or a status query (`None`).
    /// Unpaced; the bearer token is taken now — uploads outlive the access token.
    async fn session_request(
        &self,
        session: &str,
        total: u64,
        part: Option<(u64, u64, Vec<Bytes>)>,
    ) -> Step {
        let token = match self.token().await {
            Ok(token) => token,
            Err(e) => return Step::Fail(e),
        };
        let request = self.upload.put(session);
        let request = match part {
            Some((start, len, slices)) => self.upload_request(
                request.header(
                    CONTENT_RANGE,
                    format!("bytes {start}-{}/{total}", start + len - 1),
                ),
                slices,
            ),
            None => request
                .header(CONTENT_LENGTH, 0)
                .header(CONTENT_RANGE, format!("bytes */{total}"))
                .into(),
        };
        let response = match request.send(&token).await {
            Ok(response) => response,
            Err(detail) => return Step::Retry(detail),
        };
        self.note_date(response.headers());
        let status = response.status().as_u16();
        match status {
            // No `Range` header = nothing stored.
            308 => Step::Progress(parse_range_header(header_text(response.headers(), &RANGE))),
            200 | 201 => match response.bytes().await {
                Ok(body) => Step::Done(body),
                Err(e) => Step::Retry(describe(&e.without_url())),
            },
            _ => {
                let retry_after = header_text(response.headers(), &RETRY_AFTER).map(str::to_owned);
                let body = error_body(response).await;
                match classify(status, retry_after.as_deref(), &body) {
                    HttpClass::Unauthorized => Step::Unauthorized,
                    HttpClass::Conflict => Step::Conflict,
                    HttpClass::Throttle { retry_after } => Step::Throttle(retry_after),
                    HttpClass::Transient => Step::Retry(format!("Drive answered {status}")),
                    class => match terminal(class) {
                        Some(e) => Step::Fail(e),
                        None => Step::Lost,
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_layout() {
        let meta = serde_json::json!({ "id": "i", "name": "n" });
        let body = multipart_body("B", &meta, b"\x00data\r\n");
        let expected = b"--B\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n\
            {\"id\":\"i\",\"name\":\"n\"}\r\n\
            --B\r\nContent-Type: application/octet-stream\r\n\r\n\x00data\r\n\r\n--B--\r\n";
        assert_eq!(&body[..], &expected[..]);
        let empty = multipart_body("B", &meta, b"");
        assert!(empty.ends_with(b"application/octet-stream\r\n\r\n\r\n--B--\r\n"));
    }

    #[test]
    fn window_slices_and_release() {
        let mut w = Window {
            base: 0,
            end: 0,
            parts: VecDeque::new(),
        };
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        w.push(Bytes::copy_from_slice(&data[..400]));
        w.push(Bytes::copy_from_slice(&data[400..800]));
        w.push(Bytes::copy_from_slice(&data[800..]));
        assert_eq!(w.end, 1000);
        let join = |slices: Vec<Bytes>| slices.concat();
        assert_eq!(join(w.slices(0, 1000)), data);
        assert_eq!(join(w.slices(390, 20)), data[390..410]);
        assert_eq!(w.slices(400, 400).len(), 1, "a whole part is one slice");
        assert_eq!(join(w.slices(799, 201)), data[799..]);

        w.release_below(399);
        assert_eq!((w.base, w.parts.len()), (0, 3));
        w.release_below(400);
        assert_eq!((w.base, w.parts.len()), (400, 2));
        w.release_below(900);
        assert_eq!((w.base, w.parts.len()), (800, 1));
        assert_eq!(join(w.slices(900, 100)), data[900..]);
        w.release_below(1000);
        assert_eq!((w.base, w.parts.len()), (1000, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn body_slices_are_small_and_the_last_one_ends_the_watch() {
        use futures_util::StreamExt;
        let data: Vec<u8> = (0..=255u8).cycle().take(2 * UPLOAD_SLICE + 100).collect();
        let watch = Arc::new(Watch::new(Duration::from_secs(60)));
        let mut body = Slices {
            rest: VecDeque::from([
                Bytes::copy_from_slice(&data[..UPLOAD_SLICE + 7]),
                Bytes::copy_from_slice(&data[UPLOAD_SLICE + 7..]),
            ]),
            watch: watch.clone(),
        };
        let mut seen = Vec::new();
        let mut sizes = Vec::new();
        while let Some(slice) = body.next().await {
            let slice = slice.unwrap();
            sizes.push(slice.len());
            seen.extend_from_slice(&slice);
            let handed_over = watch.moved.load(Ordering::Relaxed) == HANDED_OVER;
            assert_eq!(handed_over, seen.len() == data.len());
        }
        assert_eq!(seen, data, "the same bytes in the same order");
        assert_eq!(sizes, [UPLOAD_SLICE, 7, UPLOAD_SLICE, 93]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_watch_fires_when_nothing_moved_for_the_limit() {
        let limit = Duration::from_secs(60);
        let waited = |watch: Arc<Watch>, secs: u64| async move {
            tokio::time::timeout(Duration::from_secs(secs), watch.stalled())
                .await
                .is_ok()
        };

        // Slices taken every 50 s for ten minutes: never a stall, however long the body takes.
        let watch = Arc::new(Watch::new(limit));
        watch.start();
        for _ in 0..12 {
            assert!(!waited(watch.clone(), 50).await);
            watch.note(false);
        }
        // Then nothing: it fires `limit` after the last slice, not earlier.
        assert!(!waited(watch.clone(), 59).await);
        assert!(waited(watch.clone(), 2).await);

        // The clock starts when the request goes out, not when it was built.
        let watch = Arc::new(Watch::new(limit));
        tokio::time::sleep(Duration::from_secs(45)).await;
        watch.start();
        assert!(!waited(watch.clone(), 59).await);
        assert!(waited(watch.clone(), 2).await);

        // Once the whole body is handed over the total timeout rules, not the watch.
        let watch = Arc::new(Watch::new(limit));
        watch.start();
        watch.note(true);
        watch.start();
        assert!(!waited(watch.clone(), 3600).await);
    }
}

//! Storage backend trait, fakes and the conformance suite (SPEC §9.5) — owned by WP2
//! (`drive/` by WP3).
//!
//! Trait methods are written `fn f(&self, …) -> impl Future<Output = …> + Send` so that every
//! backend future is `Send` (the engine is generic over `B: Backend` and spawns tasks).
//! Implementations may write them as `async fn`.

use std::future::Future;

use crate::consts::{MULTIPART_MAX, PART_SIZE};
use crate::error::BackendError;

pub mod any;
pub mod conformance;
pub mod dir;
pub mod drive;
pub mod flaky;
pub mod mem;

pub use any::AnyBackend;
pub use dir::DirBackend;
pub use flaky::{Flaky, OpKind};
pub use mem::{Counters, MemBackend, MemCheckpoint};

/// Opaque backend object id (Drive file ID).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Handle(pub String);

impl Handle {
    /// Reserved handle of the backend's top level: `Handle("")`. Drive: My Drive root; Dir: the
    /// directory itself.
    pub fn top() -> Handle {
        Handle(String::new())
    }

    pub fn is_top(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone, Debug)]
pub struct ObjMeta {
    pub handle: Handle,
    pub name: String,
    /// `Handle::top()` for top-level objects.
    pub parent: Handle,
    /// 0 for folders.
    pub size: u64,
    /// `None` for folders.
    pub md5: Option<[u8; 16]>,
    pub created_ms: u64,
    pub is_folder: bool,
    pub trashed: bool,
}

pub enum PutBody {
    /// `len ≤ MULTIPART_MAX`.
    Small(bytes::Bytes),
    /// `total` bytes arrive as parts of exactly `PART_SIZE` (last one shorter). An `Err` item
    /// aborts the put with `BackendError::Io`.
    Stream {
        total: u64,
        parts: tokio::sync::mpsc::Receiver<std::io::Result<bytes::Bytes>>,
    },
}

#[derive(Clone, Debug, Default)]
pub struct Quota {
    pub limit: Option<u64>,
    pub usage: u64,
    pub usage_in_trash: u64,
    pub account: Option<String>,
}

pub type ByteStream =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<bytes::Bytes, BackendError>> + Send>>;

pub trait Backend: Send + Sync + 'static {
    /// Fresh object ids usable in `create_folder`/`put`. Never fails for Mem/Dir.
    fn new_ids(&self, n: usize) -> impl Future<Output = Result<Vec<Handle>, BackendError>> + Send;

    /// Idempotent: creating an existing id is Ok. `parent` may be `Handle::top()`.
    fn create_folder(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
    ) -> impl Future<Output = Result<(), BackendError>> + Send;

    /// Put-once. If an object with `id` already exists, returns ITS meta without writing (the
    /// caller compares size/md5). Never returns `AlreadyExists` or `NotFound` (an unresolvable
    /// id conflict is `SessionLost`, §6.2). On any error the object either does not exist or is
    /// complete (never partial).
    fn put(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
        body: PutBody,
    ) -> impl Future<Output = Result<ObjMeta, BackendError>> + Send;

    /// Whole object or a byte range (end exclusive, clamped to size). Trashed objects are still
    /// readable. `NotFound` if absent.
    fn get(
        &self,
        h: &Handle,
        range: Option<std::ops::Range<u64>>,
    ) -> impl Future<Output = Result<ByteStream, BackendError>> + Send;

    /// Includes trashed objects (`trashed = true`).
    fn stat(
        &self,
        h: &Handle,
    ) -> impl Future<Output = Result<Option<ObjMeta>, BackendError>> + Send;

    /// Direct, non-trashed children; all pages; `Handle::top()` allowed.
    fn list(
        &self,
        parent: &Handle,
    ) -> impl Future<Output = Result<Vec<ObjMeta>, BackendError>> + Send;

    /// As [`Backend::list`], for callers that must tell "no children" from "no such folder":
    /// a store that answers "not found" for the folder itself returns `NotFound` here and not
    /// an empty listing (Drive: a `404` on any page of the listing). The default is `list` —
    /// the fakes have no such answer; their callers `stat` the folder of an empty listing.
    fn list_strict(
        &self,
        parent: &Handle,
    ) -> impl Future<Output = Result<Vec<ObjMeta>, BackendError>> + Send {
        self.list(parent)
    }

    /// Exact name, non-trashed, anywhere visible.
    fn find_by_name(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Vec<ObjMeta>, BackendError>> + Send;

    /// Idempotent; `NotFound` if absent.
    fn trash(&self, h: &Handle) -> impl Future<Output = Result<(), BackendError>> + Send;

    fn untrash(&self, h: &Handle) -> impl Future<Output = Result<(), BackendError>> + Send;

    /// Permanent. Called only by `gc --purge` (§5.9). `NotFound` if absent.
    fn delete(&self, h: &Handle) -> impl Future<Output = Result<(), BackendError>> + Send;

    fn about(&self) -> impl Future<Output = Result<Quota, BackendError>> + Send;

    /// Server clock estimate.
    fn now_ms(&self) -> u64;
}

/// Collects `get` into one buffer.
pub async fn get_all<B: Backend>(
    b: &B,
    h: &Handle,
    range: Option<std::ops::Range<u64>>,
) -> Result<bytes::Bytes, BackendError> {
    use futures_util::StreamExt;
    let mut stream = b.get(h, range).await?;
    let Some(first) = stream.next().await.transpose()? else {
        return Ok(bytes::Bytes::new());
    };
    let Some(second) = stream.next().await.transpose()? else {
        return Ok(first);
    };
    let mut buf = Vec::with_capacity(first.len() + second.len());
    buf.extend_from_slice(&first);
    buf.extend_from_slice(&second);
    while let Some(chunk) = stream.next().await.transpose()? {
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.into())
}

/// [`get_all`] for an object whose bytes are not authenticated yet: never more than `max`
/// bytes are buffered. `Ok(None)` when the object holds more — the listed size is a claim of
/// the store, so the bound is enforced on what actually arrives: one byte more than allowed is
/// asked for, and the stream is dropped as soon as it has delivered more than `max`.
pub async fn get_bounded<B: Backend>(
    b: &B,
    h: &Handle,
    max: u64,
) -> Result<Option<bytes::Bytes>, BackendError> {
    let stream = b.get(h, Some(0..max.saturating_add(1))).await?;
    collect_bounded(stream, max).await
}

/// Collects `stream` unless it delivers more than `max` bytes (`Ok(None)`; the rest is not read).
async fn collect_bounded(
    mut stream: ByteStream,
    max: u64,
) -> Result<Option<bytes::Bytes>, BackendError> {
    use futures_util::StreamExt;
    let fits = |held: usize, more: usize| (held as u64).saturating_add(more as u64) <= max;
    let Some(first) = stream.next().await.transpose()? else {
        return Ok(Some(bytes::Bytes::new()));
    };
    if !fits(0, first.len()) {
        return Ok(None);
    }
    let Some(second) = stream.next().await.transpose()? else {
        return Ok(Some(first));
    };
    if !fits(first.len(), second.len()) {
        return Ok(None);
    }
    let mut buf = Vec::with_capacity(first.len() + second.len());
    buf.extend_from_slice(&first);
    buf.extend_from_slice(&second);
    while let Some(chunk) = stream.next().await.transpose()? {
        if !fits(buf.len(), chunk.len()) {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Some(buf.into()))
}

/// `Small` if `≤ MULTIPART_MAX`, else `Stream` fed from `PART_SIZE` slices.
pub fn stream_body(data: bytes::Bytes) -> PutBody {
    let total = data.len() as u64;
    if total <= MULTIPART_MAX {
        return PutBody::Small(data);
    }
    // Every part is queued up front (the slices share `data`), so no feeding task is needed.
    let part = PART_SIZE as usize;
    let (tx, parts) = tokio::sync::mpsc::channel(data.len().div_ceil(part));
    for start in (0..data.len()).step_by(part) {
        let end = data.len().min(start + part);
        let queued = tx.try_send(Ok(data.slice(start..end))).is_ok();
        debug_assert!(queued, "the channel holds every part");
    }
    PutBody::Stream { total, parts }
}

// ---------------------------------------------------------------------------------------------
// Shared by the fakes: the `PutBody` contract, enforced the way Drive would enforce it
// ---------------------------------------------------------------------------------------------

/// A caller bug that real Drive answers with `400`.
pub(crate) fn bad_request(message: impl Into<String>) -> BackendError {
    BackendError::Fatal {
        status: 400,
        reason: "badRequest".into(),
        message: message.into(),
    }
}

/// Drive's answer to a media download of a folder.
pub(crate) fn not_downloadable() -> BackendError {
    BackendError::Fatal {
        status: 403,
        reason: "fileNotDownloadable".into(),
        message: "a folder has no content to download".into(),
    }
}

pub(crate) fn check_small(len: usize) -> Result<(), BackendError> {
    if len as u64 > MULTIPART_MAX {
        return Err(bad_request(format!(
            "a Small body of {len} bytes exceeds MULTIPART_MAX; use PutBody::Stream"
        )));
    }
    Ok(())
}

/// Receives a `Stream` body and checks it against the contract: parts of exactly `PART_SIZE`
/// (the last one shorter), `total` bytes overall. An `Err` item, or a channel that closes
/// early, is `BackendError::Io`.
pub(crate) struct PartReader {
    total: u64,
    seen: u64,
    parts: tokio::sync::mpsc::Receiver<std::io::Result<bytes::Bytes>>,
}

impl PartReader {
    pub(crate) fn new(
        total: u64,
        parts: tokio::sync::mpsc::Receiver<std::io::Result<bytes::Bytes>>,
    ) -> Self {
        PartReader {
            total,
            seen: 0,
            parts,
        }
    }

    /// `Ok(None)` once exactly `total` bytes have arrived.
    pub(crate) async fn next(&mut self) -> Result<Option<bytes::Bytes>, BackendError> {
        if self.seen == self.total {
            return Ok(None);
        }
        let part = match self.parts.recv().await {
            Some(item) => item?,
            None => {
                return Err(BackendError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!(
                        "the upload body ended after {} of {} bytes",
                        self.seen, self.total
                    ),
                )));
            }
        };
        let len = part.len() as u64;
        let end = self.seen + len;
        if end > self.total {
            return Err(bad_request(format!(
                "the upload body is longer than the announced {} bytes",
                self.total
            )));
        }
        if len != PART_SIZE && end != self.total {
            return Err(bad_request(format!(
                "upload part of {len} bytes at offset {}: every part but the last must be PART_SIZE",
                self.seen
            )));
        }
        self.seen = end;
        Ok(Some(part))
    }
}

pub(crate) fn md5_of(data: &[u8]) -> [u8; 16] {
    use md5::Digest;
    md5::Md5::digest(data).into()
}

impl ObjMeta {
    /// What `stat(Handle::top())` answers on the fakes: the top level as a folder.
    pub(crate) fn top(created_ms: u64) -> ObjMeta {
        ObjMeta {
            handle: Handle::top(),
            name: String::new(),
            parent: Handle::top(),
            size: 0,
            md5: None,
            created_ms,
            is_folder: true,
            trashed: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// `chunks` pieces of `len` bytes; `polled` counts the pieces the reader took.
    fn pieces(chunks: usize, len: usize, polled: &Arc<AtomicUsize>) -> ByteStream {
        let polled = polled.clone();
        Box::pin(futures_util::stream::iter((0..chunks).map(move |_| {
            polled.fetch_add(1, Ordering::SeqCst);
            Ok(bytes::Bytes::from(vec![7u8; len]))
        })))
    }

    #[tokio::test]
    async fn collect_bounded_stops_reading_a_body_that_is_too_long() {
        // A server that ignores the range and keeps sending: the read stops at the bound.
        let polled = Arc::new(AtomicUsize::new(0));
        let endless = pieces(usize::MAX, 1000, &polled);
        assert!(collect_bounded(endless, 4500).await.unwrap().is_none());
        assert_eq!(
            polled.load(Ordering::SeqCst),
            5,
            "4 pieces fit, the 5th decides"
        );

        // Too long in the first or in the second piece.
        for (len, max) in [(1000, 999), (1000, 1999)] {
            let polled = Arc::new(AtomicUsize::new(0));
            let got = collect_bounded(pieces(9, len, &polled), max).await.unwrap();
            assert!(got.is_none());
            assert!(polled.load(Ordering::SeqCst) <= 2);
        }

        // Exactly the bound, and anything shorter, is returned whole.
        for (chunks, max) in [(0, 0), (1, 1000), (2, 2000), (5, 5000), (5, u64::MAX)] {
            let polled = Arc::new(AtomicUsize::new(0));
            let got = collect_bounded(pieces(chunks, 1000, &polled), max)
                .await
                .unwrap()
                .expect("fits");
            assert_eq!(got.len(), chunks * 1000);
        }

        // An error of the stream is passed on.
        let failing: ByteStream = Box::pin(futures_util::stream::iter([
            Ok(bytes::Bytes::from_static(b"abc")),
            Err(BackendError::RateLimited),
        ]));
        assert!(matches!(
            collect_bounded(failing, 100).await,
            Err(BackendError::RateLimited)
        ));
    }

    #[tokio::test]
    async fn get_bounded_asks_for_one_byte_more_than_allowed() {
        let b = MemBackend::new();
        let [h] = <[Handle; 1]>::try_from(b.new_ids(1).await.unwrap()).unwrap();
        let data = bytes::Bytes::from(vec![1u8; 3 * 1024 * 1024]);
        b.put(&h, &Handle::top(), "big", PutBody::Small(data.clone()))
            .await
            .unwrap();

        let before = b.counters().get_bytes;
        assert!(get_bounded(&b, &h, 1000).await.unwrap().is_none());
        assert_eq!(b.counters().get_bytes - before, 1001);
        assert!(
            get_bounded(&b, &h, data.len() as u64 - 1)
                .await
                .unwrap()
                .is_none()
        );
        let whole = get_bounded(&b, &h, data.len() as u64).await.unwrap();
        assert_eq!(whole, Some(data));
        assert!(matches!(
            get_bounded(&b, &Handle("nope".into()), 10).await,
            Err(BackendError::NotFound)
        ));
    }
}

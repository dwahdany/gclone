//! The upload pipeline (SPEC §6.2, §9.8) — owned by WP5.
//!
//! ```text
//! sources ──► classifier (one blocking step at a time, path order)
//!               ├─ empty file ─────────────────────────────► Blob { blob: None }
//!               ├─ small file ─► PackBuilder ─► sealed pack ─┐
//!               └─ large file ──────────────────────────────┤ wait for one of `transfers` slots
//!                                                            ▼
//!                                   put ─► acceptance (size + md5) ─► Blob / Failed
//! ```
//! Sealed bytes are replayed, never regenerated: a pack keeps its bytes (and blob id) over all
//! attempts; a large file that must be read again gets a new salt, blob id and Drive id.

use std::fs::File;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use md5::{Digest, Md5};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::pack::{PackBuilder, SealedPack};
use super::source::{
    READ_SIZE, changed, open_failed, open_source, read_full, unchanged, unchanged_at_eof,
    unreadable,
};
use super::{BlobUpload, TransferCtx, UploadEvent, UploadSource, Uploaded, blocking, replicate};
use crate::backend::{Backend, Handle, ObjMeta, PutBody, stream_body};
use crate::consts::{
    CHUNK_LOG2, HEADER_LEN, MULTIPART_MAX, PACK_MEMBER_MAX, PART_SIZE, SOURCE_RECHECK_BYTES,
    TAG_LEN, UPLOAD_ATTEMPTS,
};
use crate::crypto::{Keyring, SUITE_V1, Sealer, ciphertext_len};
use crate::error::{BackendError, CryptoError, QuotaKind, TransferError};
use crate::format::blob_name;
use crate::types::{
    BaseEffect, BaseEffectKind, BlobId, BlobRec, Entry, EntryKind, Loc, OpDraft, Stamp, StatSig,
};
use crate::ui::Progress;
use crate::util;

/// After a cancellation, backend calls in flight get this long to finish before they are
/// dropped (§5.7).
const CANCEL_GRACE: Duration = Duration::from_secs(5);
const CHUNK: usize = 1 << CHUNK_LOG2;

/// THE upload entry point (§6.2) — the only upload function other packages call. Spawns the
/// pipeline on the current runtime and returns at once. Owns: classification by the size seen
/// at open, zero-length files, packing, `transfers` concurrent puts, the memory bound,
/// attempts, acceptance (size + md5), stop on QuotaExceeded/RateLimited, cancellation (every
/// wait for the backend ends `CANCEL_GRACE` after it at the latest).
/// Events arrive in completion order; every source appears in exactly one event; the channel
/// (capacity = transfers) closes when all are accounted for. Dropping the receiver cancels the
/// batch. `sources` are in path order.
pub fn upload_batch<B: Backend>(
    cx: TransferCtx<B>,
    data_folder: Handle,
    sources: Vec<UploadSource>,
    transfers: usize,
) -> mpsc::Receiver<UploadEvent> {
    start(cx, data_folder, sources, transfers, Arc::default())
}

/// `[Blob (if any), Put…]` for one event. `facts(remote_path)` returns planner-side facts
/// only: the base stamp, and `Some((pair, key, rel))` when a base row is to be written. The
/// `BaseEffectKind::Set { sig, hash, observed_ns, kind }` is built HERE from
/// `Uploaded.{sig, entry.hash, observed_ns, entry.kind}` — the caller never supplies those.
#[allow(clippy::type_complexity)]
pub fn drafts_for(
    up: &BlobUpload,
    facts: &dyn Fn(&str) -> (Option<Stamp>, Option<(i64, String, String)>),
) -> Vec<OpDraft> {
    let blob = up.blob.iter().cloned().map(OpDraft::Blob);
    let puts = up.files.iter().map(|f| {
        let (base, row) = facts(&f.remote_path);
        OpDraft::Put {
            path: f.remote_path.clone(),
            entry: f.entry.clone(),
            base,
            origin: None,
            effect: row.map(|(pair, key, rel)| BaseEffect {
                pair,
                key,
                rel,
                kind: BaseEffectKind::Set {
                    sig: f.sig,
                    hash: f.entry.hash,
                    observed_ns: f.observed_ns,
                    kind: f.entry.kind,
                },
            }),
        }
    });
    blob.chain(puts).collect()
}

// ---------------------------------------------------------------------------------------------
// Shared state of one batch
// ---------------------------------------------------------------------------------------------

/// Buffer bytes the pipeline holds: part buffers from allocation until the backend drops them,
/// sealed packs, and the pack under construction. This is the quantity §6.1 bounds.
#[derive(Default)]
struct Meter {
    now: AtomicU64,
    peak: AtomicU64,
}

impl Meter {
    fn hold(self: &Arc<Self>, n: u64) -> Held {
        let mut held = Held {
            meter: self.clone(),
            n: 0,
        };
        held.set(n);
        held
    }

    fn peak(&self) -> u64 {
        self.peak.load(Ordering::Relaxed)
    }
}

struct Held {
    meter: Arc<Meter>,
    n: u64,
}

impl Held {
    fn set(&mut self, n: u64) {
        if n >= self.n {
            let now = self.meter.now.fetch_add(n - self.n, Ordering::Relaxed) + (n - self.n);
            self.meter.peak.fetch_max(now, Ordering::Relaxed);
        } else {
            self.meter.now.fetch_sub(self.n - n, Ordering::Relaxed);
        }
        self.n = n;
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.set(0);
    }
}

/// The owner behind a `Bytes` given to the backend: metered until its last reference is gone.
struct Metered<T> {
    data: T,
    _held: Held,
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Metered<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

fn metered<T: AsRef<[u8]> + Send + 'static>(data: T, held: Held) -> Bytes {
    Bytes::from_owner(Metered { data, _held: held })
}

#[derive(Copy, Clone)]
enum StopCause {
    Quota(QuotaKind),
    RateLimited,
    Cancelled,
}

/// Why no new put may start. The first cause stays.
struct Stop {
    cause: Mutex<Option<StopCause>>,
    cancel: CancellationToken,
}

impl Stop {
    fn set(&self, cause: StopCause) {
        self.cause
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert(cause);
    }

    /// The error every source that has not started gets, if the batch has stopped.
    fn error(&self) -> Option<TransferError> {
        let cause = *self.cause.lock().unwrap_or_else(|e| e.into_inner());
        let cause = cause.or(self.cancel.is_cancelled().then_some(StopCause::Cancelled))?;
        Some(match cause {
            StopCause::Quota(kind) => BackendError::QuotaExceeded(kind).into(),
            StopCause::RateLimited => BackendError::RateLimited.into(),
            StopCause::Cancelled => TransferError::Cancelled,
        })
    }
}

struct Batch<B: Backend> {
    cx: TransferCtx<B>,
    folder: Handle,
    stop: Stop,
    meter: Arc<Meter>,
    events: mpsc::Sender<UploadEvent>,
    /// When the grace period of a cancelled batch ends: `CANCEL_GRACE` after the cancellation
    /// was first noticed by a call in flight.
    grace_ends: OnceLock<tokio::time::Instant>,
}

/// Why an uploaded object is not accepted.
enum Refused {
    /// Not what was sent: the object is trashed and the upload attempted again.
    Damaged(String),
    /// The batch was cancelled before the backend told.
    Cancelled,
}

impl<B: Backend> Batch<B> {
    /// `None` when the receiver was dropped: the batch is cancelled and nobody listens.
    async fn unless_dropped<T>(&self, fut: impl Future<Output = T>) -> Option<T> {
        tokio::select! {
            biased;
            () = self.events.closed() => {
                self.stop.set(StopCause::Cancelled);
                None
            }
            out = fut => Some(out),
        }
    }

    async fn emit(&self, events: Vec<UploadEvent>) -> bool {
        for event in events {
            if self.events.send(event).await.is_err() {
                self.stop.set(StopCause::Cancelled);
                return false;
            }
        }
        true
    }

    /// Every wait for the backend goes through here (§5.7): the put itself, and the calls
    /// around it — the id before it, the `stat`s and the `trash` after it. A call in flight
    /// survives a cancellation until `CANCEL_GRACE` after it; then it is dropped (`None`). The
    /// deadline is one for the whole batch, not one per call: a transfer that is cancelled
    /// during its put does not get another five seconds for the `stat` behind it.
    async fn in_flight<T>(&self, fut: impl Future<Output = T>) -> Option<T> {
        tokio::pin!(fut);
        tokio::select! {
            biased;
            out = &mut fut => Some(out),
            () = self.cx.cancel.cancelled() => {
                let until = *self
                    .grace_ends
                    .get_or_init(|| tokio::time::Instant::now() + CANCEL_GRACE);
                tokio::time::timeout_at(until, fut).await.ok()
            }
        }
    }

    /// The Drive id for a put that starts now. `Err` once the batch has stopped: an id is only
    /// asked for to start a put, and no put starts after a cancellation or a quota answer —
    /// however long the backend took over the id.
    async fn new_id(&self) -> Result<Handle, Failure> {
        let Some(ids) = self.in_flight(self.cx.backend.new_ids(1)).await else {
            return Err(Failure::Fatal(TransferError::Cancelled));
        };
        if let Some(stopped) = self.stop.error() {
            return Err(Failure::Fatal(stopped));
        }
        match ids.map(|ids| ids.into_iter().next()) {
            Ok(Some(id)) => Ok(id),
            Ok(None) => Err(Failure::Fatal(
                BackendError::Transient("the backend returned no object id".into()).into(),
            )),
            Err(e) => Err(match self.verdict(&e) {
                Verdict::Fatal => Failure::Fatal(e.into()),
                Verdict::Unknown | Verdict::Lost => Failure::Retry(e.into()),
            }),
        }
    }

    /// What a failed put means for the next attempt. Quota and rate-limit answers stop the batch.
    fn verdict(&self, e: &BackendError) -> Verdict {
        match e {
            BackendError::QuotaExceeded(kind) => {
                self.stop.set(StopCause::Quota(*kind));
                Verdict::Fatal
            }
            BackendError::RateLimited => {
                self.stop.set(StopCause::RateLimited);
                Verdict::Fatal
            }
            BackendError::SessionLost => Verdict::Lost,
            BackendError::Transient(_) | BackendError::Io(_) => Verdict::Unknown,
            _ => Verdict::Fatal,
        }
    }

    /// Acceptance of a finished upload (§6.2): size and md5 as computed locally. A backend that
    /// reports no md5 is asked once more; still none → accepted on size.
    async fn accept(&self, meta: ObjMeta, len: u64, md5: &[u8; 16]) -> Result<ObjMeta, Refused> {
        if meta.is_folder || meta.size != len {
            let why = format!("stored {} bytes, sent {len}", meta.size);
            return Err(Refused::Damaged(why));
        }
        let reported = match meta.md5 {
            Some(md5) => Some(md5),
            None => match self.in_flight(self.cx.backend.stat(&meta.handle)).await {
                Some(Ok(Some(again))) => again.md5,
                Some(_) => None,
                None => return Err(Refused::Cancelled),
            },
        };
        match reported {
            Some(reported) if reported != *md5 => Err(Refused::Damaged(format!(
                "stored md5 {}, sent {}",
                util::hex(&reported),
                util::hex(md5)
            ))),
            Some(_) => Ok(meta),
            None => {
                tracing::debug!(id = %meta.handle.0, "the backend reports no md5: accepted on size");
                Ok(meta)
            }
        }
    }

    /// Accepts the object, or trashes it and asks for a new attempt.
    async fn accept_or_trash(
        &self,
        meta: ObjMeta,
        blob: BlobId,
        len: u64,
        md5: [u8; 16],
    ) -> Result<BlobRec, Failure> {
        let id = meta.handle.clone();
        match self.accept(meta, len, &md5).await {
            Ok(meta) => Ok(BlobRec {
                id: blob,
                file_id: meta.handle.0,
                clen: len,
                md5,
                created_ms: meta.created_ms,
            }),
            Err(Refused::Damaged(why)) => {
                self.trash(&id).await;
                Err(Failure::Retry(TransferError::Verify(format!(
                    "the upload of blob {blob} was not stored intact: {why}"
                ))))
            }
            // Unverified and unreferenced: an orphan for `gc --orphans` (§5.9).
            Err(Refused::Cancelled) => Err(Failure::Fatal(TransferError::Cancelled)),
        }
    }

    async fn trash(&self, id: &Handle) {
        match self.in_flight(self.cx.backend.trash(id)).await {
            Some(Ok(()) | Err(BackendError::NotFound)) => {}
            Some(Err(e)) => tracing::warn!(id = %id.0, "could not trash a rejected upload: {e}"),
            None => tracing::warn!(
                id = %id.0,
                "interrupted before a rejected upload was trashed; gc --orphans removes it"
            ),
        }
    }
}

enum Verdict {
    /// The object may have been stored: the same bytes may go up again under the same id.
    Unknown,
    /// Nothing usable is there: the next attempt takes a new Drive id.
    Lost,
    Fatal,
}

enum Failure {
    /// Worth another attempt; the error is reported if none is left.
    Retry(TransferError),
    Fatal(TransferError),
}

fn fail_all(sources: Vec<UploadSource>, err: TransferError) -> Vec<UploadEvent> {
    let mut events = Vec::with_capacity(sources.len());
    let mut sources = sources.into_iter().peekable();
    while let Some(src) = sources.next() {
        if sources.peek().is_none() {
            events.push(UploadEvent::Failed(src, err));
            break;
        }
        events.push(UploadEvent::Failed(src, replicate(&err)));
    }
    events
}

// ---------------------------------------------------------------------------------------------
// Classifier and packer: one blocking step yields the next thing that needs a transfer slot
// ---------------------------------------------------------------------------------------------

struct Classifier {
    sources: std::vec::IntoIter<UploadSource>,
    builder: PackBuilder,
    /// Sources of the pack under construction, in member order.
    members: Vec<UploadSource>,
    /// Verified zero-length files that were not reported yet.
    empties: Vec<Uploaded>,
    building: Held,
}

enum Item {
    Pack(SealedPack, Vec<UploadSource>),
    /// A large file with the descriptor that classified it and the time before its `fstat`.
    Single(UploadSource, File, StatSig, i64),
    End,
}

struct Step {
    /// Sources settled without a put: failures and zero-length files.
    events: Vec<UploadEvent>,
    item: Item,
}

enum Class {
    Empty(Uploaded),
    Packed(Option<SealedPack>),
    Single(File, StatSig, i64),
}

impl Classifier {
    fn next(&mut self, stop: &Stop) -> Step {
        let mut events = Vec::new();
        let mut item = self.next_item(stop, &mut events);
        self.building.set(self.builder.buffered());
        if let Item::Pack(pack, _) = &mut item {
            let held = self.building.meter.hold(pack.bytes.len() as u64);
            pack.bytes = metered(std::mem::take(&mut pack.bytes), held);
        }
        if !self.empties.is_empty() {
            events.push(UploadEvent::Blob(BlobUpload {
                blob: None,
                files: std::mem::take(&mut self.empties),
            }));
        }
        Step { events, item }
    }

    fn next_item(&mut self, stop: &Stop, events: &mut Vec<UploadEvent>) -> Item {
        while let Some(src) = self.sources.next() {
            if stop.error().is_some() {
                // No new put is started: what has not gone up fails with the stop error.
                self.builder.discard();
                let rest = self
                    .members
                    .drain(..)
                    .chain([src])
                    .chain(self.sources.by_ref());
                events.extend(rest.map(|s| {
                    UploadEvent::Failed(s, stop.error().unwrap_or(TransferError::Cancelled))
                }));
                return Item::End;
            }
            match self.classify(&src) {
                Ok(Class::Empty(up)) => self.empties.push(up),
                Ok(Class::Packed(closed)) => {
                    let closed = closed.map(|pack| (pack, std::mem::take(&mut self.members)));
                    self.members.push(src);
                    if let Some((pack, sources)) = closed {
                        return Item::Pack(pack, sources);
                    }
                }
                Ok(Class::Single(file, sig, observed_ns)) => {
                    return Item::Single(src, file, sig, observed_ns);
                }
                Err(e) => events.push(UploadEvent::Failed(src, e)),
            }
        }
        match self.builder.take_pack() {
            Some(pack) => Item::Pack(pack, std::mem::take(&mut self.members)),
            None => Item::End,
        }
    }

    /// Classification by the size seen at open (§6.2). A small or empty file that changes while
    /// it is read is opened and classified again, `UPLOAD_ATTEMPTS` times in all. A source that
    /// is gone, or no regular file any more, has changed since the scan: `SourceChanged` at
    /// once (there is nothing to read again).
    fn classify(&mut self, src: &UploadSource) -> Result<Class, TransferError> {
        let mut attempt = 1;
        loop {
            let observed_ns = util::now_ns();
            let (mut file, sig) = open_source(&src.abs).map_err(|e| open_failed(&src.abs, e))?;
            let read = match sig.size {
                0 => empty_upload(src, &mut file, sig, observed_ns).map(Class::Empty),
                n if n < PACK_MEMBER_MAX => self
                    .builder
                    .add_opened(src, file, sig, observed_ns)
                    .map(Class::Packed),
                _ => return Ok(Class::Single(file, sig, observed_ns)),
            };
            match read {
                Err(TransferError::SourceChanged(_)) if attempt < UPLOAD_ATTEMPTS => attempt += 1,
                read => return read,
            }
        }
    }
}

/// A zero-length file has no blob: only the fact that it is (still) empty is recorded.
fn empty_upload(
    src: &UploadSource,
    file: &mut File,
    sig: StatSig,
    observed_ns: i64,
) -> Result<Uploaded, TransferError> {
    if !unchanged_at_eof(file, &sig).map_err(|e| unreadable(&src.abs, e))? {
        return Err(changed(&src.abs));
    }
    Ok(Uploaded {
        remote_path: src.remote_path.clone(),
        entry: Entry::empty_file(sig.mtime_ns, sig.is_exec()),
        sig,
        observed_ns,
    })
}

// ---------------------------------------------------------------------------------------------
// The coordinator
// ---------------------------------------------------------------------------------------------

fn start<B: Backend>(
    cx: TransferCtx<B>,
    folder: Handle,
    sources: Vec<UploadSource>,
    transfers: usize,
    meter: Arc<Meter>,
) -> mpsc::Receiver<UploadEvent> {
    let transfers = transfers.max(1);
    let (events, receiver) = mpsc::channel(transfers);
    let batch = Arc::new(Batch {
        stop: Stop {
            cause: Mutex::new(None),
            cancel: cx.cancel.clone(),
        },
        cx,
        folder,
        meter,
        events,
        grace_ends: OnceLock::new(),
    });
    tokio::spawn(run(batch, sources, transfers));
    receiver
}

async fn run<B: Backend>(batch: Arc<Batch<B>>, sources: Vec<UploadSource>, transfers: usize) {
    let slots = Arc::new(Semaphore::new(transfers));
    // Dropped (and its tasks aborted) when this function returns early: the receiver is gone.
    let mut tasks = JoinSet::new();
    let mut classifier = Classifier {
        sources: sources.into_iter(),
        builder: PackBuilder::new(batch.cx.keys.clone(), batch.cx.device),
        members: Vec::new(),
        empties: Vec::new(),
        building: batch.meter.hold(0),
    };
    loop {
        // The next pack is built while the slots are busy; it then waits for a slot, so at
        // most one pack exists beyond those in flight.
        let step = {
            let batch = batch.clone();
            blocking(move || {
                let step = classifier.next(&batch.stop);
                (classifier, step)
            })
        };
        let Some(Ok((back, step))) = batch.unless_dropped(step).await else {
            return;
        };
        classifier = back;
        for event in &step.events {
            if let UploadEvent::Blob(up) = event {
                up.files.iter().for_each(|_| batch.cx.progress.file_done());
            }
        }
        if !batch.emit(step.events).await {
            return;
        }
        if matches!(step.item, Item::End) {
            break;
        }
        let Some(Ok(slot)) = batch.unless_dropped(slots.clone().acquire_owned()).await else {
            return;
        };
        let batch = batch.clone();
        tasks.spawn(async move {
            let events = match step.item {
                Item::Pack(pack, sources) => upload_pack(&batch, pack, sources).await,
                Item::Single(src, file, sig, observed_ns) => {
                    vec![upload_single(&batch, src, (file, sig, observed_ns)).await]
                }
                Item::End => Vec::new(),
            };
            // The slot is held until the events are taken: a slow consumer slows the puts.
            batch.emit(events).await;
            drop(slot);
        });
        while tasks.try_join_next().is_some() {}
    }
    drop(classifier);
    while let Some(Some(_)) = batch.unless_dropped(tasks.join_next()).await {}
    tracing::debug!(
        peak_buffer_bytes = batch.meter.peak(),
        "upload batch finished"
    );
}

// ---------------------------------------------------------------------------------------------
// Packs: the sealed bytes are replayed
// ---------------------------------------------------------------------------------------------

async fn upload_pack<B: Backend>(
    batch: &Batch<B>,
    pack: SealedPack,
    sources: Vec<UploadSource>,
) -> Vec<UploadEvent> {
    let SealedPack {
        blob_id,
        bytes,
        md5,
        files,
    } = pack;
    let len = bytes.len() as u64;
    let name = blob_name(&blob_id);
    // `Some` after a failure that may have stored the object: same id, same bytes (idempotent).
    let mut same_id: Option<Handle> = None;
    let mut last = None;
    for _ in 0..UPLOAD_ATTEMPTS {
        if let Some(stopped) = batch.stop.error() {
            return fail_all(sources, stopped);
        }
        let attempt = async {
            let id = match same_id.take() {
                Some(id) => id,
                None => batch.new_id().await?,
            };
            let put = batch
                .cx
                .backend
                .put(&id, &batch.folder, &name, stream_body(bytes.clone()));
            match batch.in_flight(put).await {
                None => Err(Failure::Fatal(TransferError::Cancelled)),
                Some(Ok(meta)) => batch.accept_or_trash(meta, blob_id, len, md5).await,
                Some(Err(e)) => Err(match batch.verdict(&e) {
                    Verdict::Unknown => {
                        same_id = Some(id);
                        Failure::Retry(e.into())
                    }
                    Verdict::Lost => Failure::Retry(e.into()),
                    Verdict::Fatal => Failure::Fatal(e.into()),
                }),
            }
        };
        match attempt.await {
            Ok(rec) => {
                batch
                    .cx
                    .progress
                    .add_bytes(files.iter().map(|f| f.entry.size).sum());
                files.iter().for_each(|_| batch.cx.progress.file_done());
                batch.cx.progress.blob_done();
                return vec![UploadEvent::Blob(BlobUpload {
                    blob: Some(rec),
                    files,
                })];
            }
            Err(Failure::Retry(e)) => last = Some(e),
            Err(Failure::Fatal(e)) => return fail_all(sources, e),
        }
    }
    fail_all(sources, last.unwrap_or(TransferError::Cancelled))
}

// ---------------------------------------------------------------------------------------------
// Single-member blobs: sealed while they are sent, so a new attempt reads the file again
// ---------------------------------------------------------------------------------------------

async fn upload_single<B: Backend>(
    batch: &Batch<B>,
    src: UploadSource,
    first: (File, StatSig, i64),
) -> UploadEvent {
    let mut opened = Some(first);
    let mut last = None;
    for _ in 0..UPLOAD_ATTEMPTS {
        if let Some(stopped) = batch.stop.error() {
            return UploadEvent::Failed(src, stopped);
        }
        let attempt = async {
            let (file, sig, observed_ns) = match opened.take() {
                Some(opened) => opened,
                None => {
                    let path = src.abs.clone();
                    let reopened = blocking(move || {
                        let observed_ns = util::now_ns();
                        open_source(&path).map(|(file, sig)| (file, sig, observed_ns))
                    });
                    match reopened.await {
                        Ok(Ok(opened)) => opened,
                        Ok(Err(e)) => return Err(Failure::Fatal(open_failed(&src.abs, e))),
                        Err(e) => return Err(Failure::Fatal(e)),
                    }
                }
            };
            attempt_single(batch, &src, file, sig, observed_ns).await
        };
        match attempt.await {
            Ok(up) => {
                batch.cx.progress.file_done();
                if up.blob.is_some() {
                    batch.cx.progress.blob_done();
                }
                return UploadEvent::Blob(up);
            }
            Err(Failure::Retry(e)) => last = Some(e),
            Err(Failure::Fatal(e)) => return UploadEvent::Failed(src, e),
        }
    }
    UploadEvent::Failed(src, last.unwrap_or(TransferError::Cancelled))
}

async fn attempt_single<B: Backend>(
    batch: &Batch<B>,
    src: &UploadSource,
    mut file: File,
    sig: StatSig,
    observed_ns: i64,
) -> Result<BlobUpload, Failure> {
    if sig.size == 0 {
        // Emptied since it was classified as large.
        let src = src.clone();
        let up = blocking(move || empty_upload(&src, &mut file, sig, observed_ns)).await;
        return match up {
            Ok(Ok(up)) => Ok(BlobUpload {
                blob: None,
                files: vec![up],
            }),
            Ok(Err(e @ TransferError::SourceChanged(_))) => Err(Failure::Retry(e)),
            Ok(Err(e)) | Err(e) => Err(Failure::Fatal(e)),
        };
    }

    // Everything is new in every attempt: salt (inside the sealer), blob id, Drive id.
    let blob_id = BlobId::random();
    let name = blob_name(&blob_id);
    let sealer = StreamSealer::new(&batch.cx.keys, &batch.meter, file, sig);
    let total = sealer.total;
    let id = batch.new_id().await?;
    let backend = &batch.cx.backend;

    let (sealed, put) = if total <= MULTIPART_MAX {
        let (sealer, part) = blocking(move || {
            let mut sealer = sealer;
            let part = sealer.next_part();
            (sealer, part)
        })
        .await
        .map_err(Failure::Fatal)?;
        let part = part.map_err(|e| e.failure(src))?;
        batch.cx.progress.add_bytes(sig.size);
        let put = backend.put(&id, &batch.folder, &name, PutBody::Small(part));
        match batch.in_flight(put).await {
            Some(put) => (Ok(sealer), put),
            None => return Err(Failure::Fatal(TransferError::Cancelled)),
        }
    } else {
        let (tx, parts) = mpsc::channel(1);
        let put = backend.put(&id, &batch.folder, &name, PutBody::Stream { total, parts });
        let both = async { tokio::join!(feed(sealer, tx, &batch.cx.progress), put) };
        match batch.in_flight(both).await {
            Some(both) => both,
            None => return Err(Failure::Fatal(TransferError::Cancelled)),
        }
    };

    let sealer = match sealed {
        Ok(sealer) => sealer,
        Err(aborted) => {
            // The blob is incomplete; whatever the backend made of it must not stay.
            if put.is_ok() {
                batch.trash(&id).await;
            }
            return Err(match (aborted, put) {
                (Aborted::Source(e), _) => e.failure(src),
                (Aborted::Task(e), _) => Failure::Fatal(e),
                (Aborted::Backend, Err(e)) => match batch.verdict(&e) {
                    Verdict::Unknown | Verdict::Lost => Failure::Retry(e.into()),
                    Verdict::Fatal => Failure::Fatal(e.into()),
                },
                (Aborted::Backend, Ok(_)) => Failure::Retry(TransferError::Verify(format!(
                    "the upload of blob {blob_id} was answered before it was complete"
                ))),
            });
        }
    };
    let md5: [u8; 16] = sealer.md5.finalize().into();
    let meta = match put {
        Ok(meta) => meta,
        Err(e) => match batch.verdict(&e) {
            // The whole body went out and only the answer is missing: the object may be there.
            Verdict::Unknown => match batch.in_flight(backend.stat(&id)).await {
                Some(Ok(Some(meta))) => meta,
                Some(_) => return Err(Failure::Retry(e.into())),
                None => return Err(Failure::Fatal(TransferError::Cancelled)),
            },
            Verdict::Lost => return Err(Failure::Retry(e.into())),
            Verdict::Fatal => return Err(Failure::Fatal(e.into())),
        },
    };
    let rec = batch.accept_or_trash(meta, blob_id, total, md5).await?;
    Ok(BlobUpload {
        blob: Some(rec),
        files: vec![Uploaded {
            remote_path: src.remote_path.clone(),
            entry: Entry {
                kind: EntryKind::File,
                size: sig.size,
                mtime_ns: sig.mtime_ns,
                exec: sig.is_exec(),
                hash: *sealer.plain.finalize().as_bytes(),
                loc: Some(Loc {
                    blob: blob_id,
                    off: 0,
                    clen: total,
                    salt: sealer.sealer.salt(),
                    chunk_log2: CHUNK_LOG2,
                    epoch: batch.cx.keys.current_epoch(),
                    suite: SUITE_V1,
                    flags: 0,
                }),
            },
            sig,
            observed_ns,
        }],
    })
}

enum Aborted {
    Source(SealError),
    /// The backend stopped taking parts.
    Backend,
    Task(TransferError),
}

/// Seals part after part into the put's channel. The channel slot is reserved **before** a
/// part is built: besides the part the backend is sending, only one more exists (§6.1).
async fn feed(
    mut sealer: StreamSealer,
    tx: mpsc::Sender<std::io::Result<Bytes>>,
    progress: &Progress,
) -> Result<StreamSealer, Aborted> {
    loop {
        let Ok(slot) = tx.reserve().await else {
            return Err(Aborted::Backend);
        };
        let before = sealer.read;
        let (back, part) = blocking(move || {
            let part = sealer.next_part();
            (sealer, part)
        })
        .await
        .map_err(Aborted::Task)?;
        sealer = back;
        match part {
            Ok(part) => {
                progress.add_bytes(sealer.read - before);
                slot.send(Ok(part));
                if sealer.emitted == sealer.total {
                    return Ok(sealer);
                }
            }
            Err(e) => {
                // The backend aborts the session on an `Err` item (§6.2).
                slot.send(Err(std::io::Error::other(e.to_string())));
                return Err(Aborted::Source(e));
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum SealError {
    #[error("the source file changed while it was read")]
    Changed,
    #[error("cannot read the source file: {0}")]
    Unreadable(std::io::Error),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl SealError {
    fn failure(self, src: &UploadSource) -> Failure {
        match self {
            SealError::Changed => Failure::Retry(changed(&src.abs)),
            SealError::Unreadable(e) => Failure::Fatal(unreadable(&src.abs, e)),
            SealError::Crypto(e) => Failure::Fatal(e.into()),
        }
    }
}

/// One file as one Data stream, produced in parts of `PART_SIZE` blob bytes.
struct StreamSealer {
    file: File,
    sig: StatSig,
    sealer: Sealer,
    /// BLAKE3 of the plaintext, MD5 of the blob bytes.
    plain: blake3::Hasher,
    md5: Md5,
    /// `blob_len` of the size at open.
    total: u64,
    /// Blob bytes handed out.
    emitted: u64,
    /// Plaintext bytes sealed, and that count at the last `fstat`.
    read: u64,
    checked: u64,
    /// Plaintext read from the file and not sealed yet: `rbuf[rpos..rlen]`.
    rbuf: Vec<u8>,
    rpos: usize,
    rlen: usize,
    /// Sealed bytes past the last part boundary (less than one sealed chunk; at first the
    /// header). The part buffer itself exists only while a part is built.
    carry: Vec<u8>,
    meter: Arc<Meter>,
}

impl StreamSealer {
    fn new(keys: &Keyring, meter: &Arc<Meter>, file: File, sig: StatSig) -> Self {
        let sealer = keys.data_sealer();
        let total = ciphertext_len(sig.size, CHUNK_LOG2);
        let mut md5 = Md5::new();
        md5.update(sealer.header());
        StreamSealer {
            carry: sealer.header().to_vec(),
            file,
            sig,
            sealer,
            plain: blake3::Hasher::new(),
            md5,
            total,
            emitted: 0,
            read: 0,
            checked: 0,
            rbuf: vec![0; READ_SIZE.min(sig.size as usize)],
            rpos: 0,
            rlen: 0,
            meter: meter.clone(),
        }
    }

    /// The next `PART_SIZE` bytes of the blob, or the shorter rest. Blocking. The last part is
    /// only returned after the source proved unchanged.
    fn next_part(&mut self) -> Result<Bytes, SealError> {
        let left = self.total - self.emitted;
        let want = PART_SIZE.min(left) as usize;
        let (mut out, held) = part_buffer(&self.meter, left);
        out.extend_from_slice(&self.carry);
        while out.len() < want {
            if self.rpos == self.rlen {
                self.refill()?;
            }
            let chunk = &self.rbuf[self.rpos..self.rlen.min(self.rpos + CHUNK)];
            let last = self.read + chunk.len() as u64 == self.sig.size;
            let at = out.len();
            self.sealer.seal_chunk(chunk, last, &mut out)?;
            self.md5.update(&out[at..]);
            self.plain.update(chunk);
            self.read += chunk.len() as u64;
            self.rpos += chunk.len();
            if last
                && !unchanged_at_eof(&mut self.file, &self.sig).map_err(SealError::Unreadable)?
            {
                return Err(SealError::Changed);
            }
        }
        self.emitted += want as u64;
        self.carry.clear();
        self.carry.extend_from_slice(&out[want..]);
        out.truncate(want);
        Ok(metered(out, held))
    }

    /// Reads the next piece of the file: exactly as much as the size at open promises.
    fn refill(&mut self) -> Result<(), SealError> {
        if self.read - self.checked >= SOURCE_RECHECK_BYTES {
            self.checked = self.read;
            if !unchanged(&self.file, &self.sig).map_err(SealError::Unreadable)? {
                return Err(SealError::Changed);
            }
        }
        let want = (self.sig.size - self.read).min(self.rbuf.len() as u64) as usize;
        let got =
            read_full(&mut self.file, &mut self.rbuf[..want]).map_err(SealError::Unreadable)?;
        if got < want {
            return Err(SealError::Changed);
        }
        (self.rpos, self.rlen) = (0, got);
        Ok(())
    }
}

/// A buffer for the next part of a blob with `left` bytes to go. While it is built, a full part
/// can overshoot by less than one sealed chunk (plus the header in the first part); the last
/// part is exact.
fn part_buffer(meter: &Arc<Meter>, left: u64) -> (Vec<u8>, Held) {
    let cap = if left > PART_SIZE {
        PART_SIZE as usize + HEADER_LEN + CHUNK + TAG_LEN
    } else {
        left as usize
    };
    (Vec::with_capacity(cap), meter.hold(cap as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{ByteStream, MemBackend, Quota};
    use crate::consts::{MIB, PACK_TARGET};
    use crate::crypto::MasterKey;
    use crate::types::DeviceId;
    use std::sync::atomic::AtomicUsize;

    fn keys() -> Keyring {
        Keyring::new([7; 16], vec![(1, MasterKey::from_bytes([9; 32]))], 1).unwrap()
    }

    fn ctx<B: Backend>(backend: B) -> TransferCtx<B> {
        TransferCtx {
            backend: Arc::new(backend),
            keys: keys(),
            device: DeviceId([1; 8]),
            progress: Progress::hidden(),
            cancel: CancellationToken::new(),
        }
    }

    fn write(dir: &std::path::Path, name: &str, len: usize) -> UploadSource {
        let abs = dir.join(name);
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        std::fs::write(&abs, data).unwrap();
        UploadSource {
            abs,
            remote_path: name.to_string(),
        }
    }

    /// A backend that is slower than the sealer: it sits on the first part of every stream for
    /// `HOLD`, so parts pile up behind it as far as the pipeline lets them.
    struct Slow {
        inner: MemBackend,
        puts_now: AtomicUsize,
        puts_peak: AtomicUsize,
        /// Calls of `new_ids`, each of which takes this long.
        ids: AtomicUsize,
        id_delay: Duration,
    }

    const HOLD: Duration = Duration::from_millis(2500);

    impl Backend for Slow {
        async fn new_ids(&self, n: usize) -> Result<Vec<Handle>, BackendError> {
            self.ids.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.id_delay).await;
            self.inner.new_ids(n).await
        }
        async fn create_folder(
            &self,
            id: &Handle,
            p: &Handle,
            n: &str,
        ) -> Result<(), BackendError> {
            self.inner.create_folder(id, p, n).await
        }
        async fn put(
            &self,
            id: &Handle,
            parent: &Handle,
            name: &str,
            body: PutBody,
        ) -> Result<ObjMeta, BackendError> {
            let now = self.puts_now.fetch_add(1, Ordering::SeqCst) + 1;
            self.puts_peak.fetch_max(now, Ordering::SeqCst);
            let body = match body {
                PutBody::Small(data) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    PutBody::Small(data)
                }
                PutBody::Stream { total, mut parts } => {
                    let mut all = Vec::new();
                    while let Some(part) = parts.recv().await {
                        let part = part?;
                        if all.is_empty() {
                            tokio::time::sleep(HOLD).await;
                        }
                        all.extend_from_slice(&part);
                    }
                    assert_eq!(all.len() as u64, total);
                    stream_body(all.into())
                }
            };
            let stored = self.inner.put(id, parent, name, body).await;
            self.puts_now.fetch_sub(1, Ordering::SeqCst);
            stored
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn buffers_stay_within_the_memory_bound() {
        const TRANSFERS: usize = 2;
        let dir = tempfile::tempdir().unwrap();
        let mut sources = Vec::new();
        // Two files of three parts each — both in flight, each with its first part held by the
        // backend, while the packer builds the first of three packs behind them.
        for i in 0..2 {
            sources.push(write(
                dir.path(),
                &format!("a-large-{i}"),
                40 * MIB as usize + i,
            ));
        }
        for i in 0..40 {
            sources.push(write(
                dir.path(),
                &format!("b-small-{i:02}"),
                MIB as usize - 1,
            ));
        }
        let total = sources.len();
        let cx = ctx(Slow {
            inner: MemBackend::new(),
            puts_now: AtomicUsize::new(0),
            puts_peak: AtomicUsize::new(0),
            ids: AtomicUsize::new(0),
            id_delay: Duration::ZERO,
        });
        let meter = Arc::new(Meter::default());
        let mut events = start(cx.clone(), Handle::top(), sources, TRANSFERS, meter.clone());
        let (mut files, mut blobs) = (0, 0);
        while let Some(event) = events.recv().await {
            match event {
                UploadEvent::Blob(up) => {
                    files += up.files.len();
                    blobs += 1;
                }
                UploadEvent::Failed(src, e) => panic!("{}: {e}", src.remote_path),
            }
        }
        assert_eq!((files, blobs), (total, 2 + 3));
        assert_eq!(cx.backend.puts_peak.load(Ordering::SeqCst), TRANSFERS);

        // §6.1: 2 × PART_SIZE per transfer, plus one pack under construction (≤ 17 MiB). The
        // slack covers the overshoot of a part buffer (one sealed chunk) and the first member
        // of the pack after the one that waits for a slot.
        let bound = 2 * PART_SIZE * TRANSFERS as u64 + PACK_TARGET + MIB;
        let slack = 2 * MIB;
        let peak = meter.peak();
        assert!(peak <= bound + slack, "peak {peak} exceeds {bound}");
        // The meter did measure something.
        assert!(peak >= PART_SIZE, "peak {peak} is implausibly low");
        assert_eq!(
            meter.now.load(Ordering::Relaxed),
            0,
            "every buffer was released"
        );
    }

    /// §5.7: nothing is launched after a cancellation. An id the backend hands out two
    /// seconds later — inside the grace period — must not start a put.
    #[tokio::test(start_paused = true)]
    async fn an_id_that_arrives_after_the_cancellation_starts_no_put() {
        let dir = tempfile::tempdir().unwrap();
        for len in [3000, 2 * MIB as usize, 20 * MIB as usize] {
            let cx = ctx(Slow {
                inner: MemBackend::new(),
                puts_now: AtomicUsize::new(0),
                puts_peak: AtomicUsize::new(0),
                ids: AtomicUsize::new(0),
                id_delay: Duration::from_secs(2),
            });
            let sources = vec![write(dir.path(), "f", len)];
            let mut events = start(cx.clone(), Handle::top(), sources, 1, Arc::default());
            while cx.backend.ids.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let cancelled = tokio::time::Instant::now();
            cx.cancel.cancel();
            match events.recv().await {
                Some(UploadEvent::Failed(_, TransferError::Cancelled)) => {}
                Some(UploadEvent::Failed(_, e)) => panic!("len {len}: {e}"),
                Some(UploadEvent::Blob(_)) => panic!("len {len}: uploaded after the cancellation"),
                None => panic!("len {len}: no event"),
            }
            // The id was waited for (it came within the grace period), and then not used.
            let waited = cancelled.elapsed();
            assert!(
                waited >= Duration::from_millis(1900) && waited < CANCEL_GRACE,
                "len {len}: {waited:?}"
            );
            assert!(events.recv().await.is_none());
            assert_eq!(cx.backend.puts_peak.load(Ordering::SeqCst), 0, "len {len}");
            assert_eq!(cx.backend.ids.load(Ordering::SeqCst), 1, "len {len}");
        }
    }

    #[test]
    fn stream_sealer_parts_are_exact_and_match_the_stream_format() {
        let dir = tempfile::tempdir().unwrap();
        let keys = keys();
        let meter = Arc::new(Meter::default());
        for len in [
            1usize,
            CHUNK,
            CHUNK + 1,
            PART_SIZE as usize,
            2 * PART_SIZE as usize + 12345,
        ] {
            let src = write(dir.path(), "f", len);
            let (file, sig) = open_source(&src.abs).unwrap();
            let mut sealer = StreamSealer::new(&keys, &meter, file, sig);
            let mut blob = Vec::new();
            while sealer.emitted < sealer.total {
                let part = sealer.next_part().unwrap();
                assert!(part.len() as u64 == PART_SIZE || sealer.emitted == sealer.total);
                blob.extend_from_slice(&part);
            }
            assert_eq!(blob.len() as u64, ciphertext_len(len as u64, CHUNK_LOG2));
            assert_eq!(
                <[u8; 16]>::from(sealer.md5.clone().finalize()),
                <[u8; 16]>::from(Md5::digest(&blob))
            );
            let plain = std::fs::read(&src.abs).unwrap();
            assert_eq!(sealer.plain.finalize(), blake3::hash(&plain));

            // Opened the way a reader does: from the index entry, not from the stored header.
            let loc = Loc {
                blob: BlobId([0; 16]),
                off: 0,
                clen: blob.len() as u64,
                salt: sealer.sealer.salt(),
                chunk_log2: CHUNK_LOG2,
                epoch: 1,
                suite: SUITE_V1,
                flags: 0,
            };
            let opener = keys.data_opener(&loc).unwrap();
            assert_eq!(blob[..HEADER_LEN], opener.expected_header());
            let mut out = Vec::new();
            let chunks: Vec<&[u8]> = blob[HEADER_LEN..].chunks(CHUNK + TAG_LEN).collect();
            for (i, chunk) in chunks.iter().enumerate() {
                opener
                    .open_chunk(i as u64, i + 1 == chunks.len(), chunk, &mut out)
                    .unwrap();
            }
            assert_eq!(out, plain, "len {len}");
        }
        assert_eq!(meter.now.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn stream_sealer_notices_a_source_that_changes() {
        let dir = tempfile::tempdir().unwrap();
        let keys = keys();
        let meter = Arc::new(Meter::default());

        // Grown: bytes follow the size seen at open.
        let src = write(dir.path(), "grown", 3 * CHUNK);
        let (file, sig) = open_source(&src.abs).unwrap();
        let mut sealer = StreamSealer::new(&keys, &meter, file, sig);
        std::fs::write(&src.abs, vec![1u8; 3 * CHUNK + 1]).unwrap();
        assert!(matches!(sealer.next_part(), Err(SealError::Changed)));

        // Shrunk: the read ends before the size seen at open.
        let src = write(dir.path(), "shrunk", 3 * CHUNK);
        let (file, sig) = open_source(&src.abs).unwrap();
        let mut sealer = StreamSealer::new(&keys, &meter, file, sig);
        std::fs::write(&src.abs, vec![1u8; CHUNK]).unwrap();
        assert!(matches!(sealer.next_part(), Err(SealError::Changed)));

        // Same length, rewritten in place: only the signature tells.
        let src = write(dir.path(), "touched", 3 * CHUNK);
        let (file, sig) = open_source(&src.abs).unwrap();
        let mut sealer = StreamSealer::new(&keys, &meter, file, sig);
        let later = std::time::SystemTime::now() + Duration::from_secs(5);
        std::fs::File::options()
            .write(true)
            .open(&src.abs)
            .unwrap()
            .set_modified(later)
            .unwrap();
        assert!(matches!(sealer.next_part(), Err(SealError::Changed)));
    }

    #[test]
    fn a_long_read_rechecks_the_source_before_the_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("long");
        // Sparse: 100 MiB of zeros, seven parts.
        let size = 100 * MIB;
        File::create(&path).unwrap().set_len(size).unwrap();
        let (file, sig) = open_source(&path).unwrap();
        let mut sealer = StreamSealer::new(&keys(), &Arc::new(Meter::default()), file, sig);
        assert_eq!(sealer.total.div_ceil(PART_SIZE), 7);
        sealer.next_part().unwrap();

        // Same size, same content, another mtime.
        let later = std::time::SystemTime::now() + Duration::from_secs(5);
        let touched = File::options().write(true).open(&path).unwrap();
        touched.set_modified(later).unwrap();

        let mut parts = 1;
        let err = loop {
            match sealer.next_part() {
                Ok(_) => parts += 1,
                Err(e) => break e,
            }
        };
        assert!(matches!(err, SealError::Changed), "{err}");
        // Noticed at the SOURCE_RECHECK_BYTES mark, three parts before the end of the file.
        assert_eq!(parts as u64, SOURCE_RECHECK_BYTES / PART_SIZE);
        assert_eq!(sealer.read, SOURCE_RECHECK_BYTES);
    }

    #[test]
    fn the_first_stop_cause_stays() {
        let stop = Stop {
            cause: Mutex::new(None),
            cancel: CancellationToken::new(),
        };
        assert!(stop.error().is_none());
        stop.cancel.cancel();
        assert!(matches!(stop.error(), Some(TransferError::Cancelled)));
        stop.set(StopCause::Quota(QuotaKind::StorageFull));
        stop.set(StopCause::RateLimited);
        assert!(matches!(
            stop.error(),
            Some(TransferError::Backend(BackendError::QuotaExceeded(
                QuotaKind::StorageFull
            )))
        ));
    }
}

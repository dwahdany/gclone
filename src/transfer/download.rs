//! Downloads, ranged reads and target rules (SPEC §5.7 steps 1–3, §6.3, §9.8) — owned by WP5.
//!
//! One code path reads data blobs: a [`Pump`] requests a byte range and feeds it to a
//! [`Decoder`], which cuts it into the units the index entries predict (header, chunk, chunk,
//! …, gap), authenticates each chunk and hands the plaintext to a [`Sink`] — partial files
//! (`download_group`), an output buffer (`read_range`) or a hasher (`verify_remote`). Nothing
//! about the layout is taken from the blob itself.

use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures_util::{FutureExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use super::{LocalExpect, TransferCtx, blocking, durable, replicate};
use crate::backend::{Backend, ByteStream, Handle, ObjMeta};
use crate::consts::{
    DOWNLOAD_BATCH_AGE, DOWNLOAD_BATCH_BYTES, DOWNLOAD_BATCH_FILES, DOWNLOAD_OPEN_FILES,
    DOWNLOAD_OPEN_TOTAL, DOWNLOAD_RETRIES, HEADER_LEN, MIB, PACK_MEMBER_MAX, PARTIAL_PREFIX,
    RANGE_COALESCE_GAP,
};
use crate::crypto::{
    ChunkSpan, Keyring, Opener, chunk_cipher_len, chunk_count, chunk_range, ciphertext_len,
};
use crate::error::{BackendError, CryptoError, TransferError};
use crate::format::blob_name;
use crate::types::{BlobRec, Entry, EntryKind, Head, Loc, StatSig};
use crate::ui::Progress;
use crate::{path, util};

/// Received bytes are decoded off the async threads in batches of about this size.
const FEED_BATCH: usize = MIB as usize;

/// A member of at most this many plaintext bytes — every pack member (§6.2) — waits in memory
/// until its last chunk verified and is then written to its targets one after another. A larger
/// one goes into the partial file of one target as it arrives; the other targets are copied
/// from that file. Either way a member has at most two files open, however many paths share
/// its content (§5.7 step 2).
const MEMBER_BUFFER_MAX: u64 = PACK_MEMBER_MAX;

/// Local copies of a large member are made in pieces of this size.
const COPY_PIECE: u64 = MIB;

#[derive(Clone, Debug)]
pub struct DownloadItem {
    pub head: Head,
    pub root: std::path::PathBuf,
    pub rel: String,
    pub expect_local: LocalExpect,
}

#[derive(Clone, Debug)]
pub struct Downloaded {
    pub rel: String,
    pub sig: StatSig,
    pub observed_ns: i64,
    pub moved_aside: Option<std::path::PathBuf>,
}

/// All items must reference `blob`. Coalesces ranges, verifies, writes partial files, finishes
/// per §5.7 steps 1–3. `Err(UnsafeTarget)` and `Err(TargetCollision)` are the run-time skips of
/// §5.7 (the caller reports them as Skip, not as failures). A `NotFound` for `blob.file_id` is
/// retried through `find_by_name(blob name)` (exactly one hit), else `BlobMissing`.
///
/// The result has the items in their input order. Items that share one `Loc` (reused content)
/// are fetched once and written one after another — the number of files open at a time does
/// not grow with the number of items. Zero-length entries are materialized without a request.
/// Once `cx.cancel` fires, what is not finished comes back as `Err(Cancelled)`.
///
/// **Durability** (§5.7 step 3a): the files are finished in batches (`Batch`), and an `Ok`
/// leaves this function only after the barrier behind its batch — the content was durable
/// before the rename, and the rename is durable now. The caller may record it at once.
pub async fn download_group<B: Backend>(
    cx: &TransferCtx<B>,
    blob: &BlobRec,
    items: Vec<DownloadItem>,
) -> Vec<(DownloadItem, Result<Downloaded, TransferError>)> {
    let mut results: Vec<Option<Result<Downloaded, TransferError>>> =
        items.iter().map(|_| None).collect();

    // Everything that can be decided without a request (§4.5, §5.7 step 1).
    let mut wanted = Vec::new();
    let mut empties = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let checked =
            early_target_check(item).and_then(|()| data_member(&cx.keys, blob, &item.head.entry));
        match checked {
            Ok(Some((opener, loc))) => wanted.push((i, opener, loc.clone())),
            Ok(None) => match check_empty(item) {
                Ok(()) => empties.push(Target::new(i, item)),
                Err(e) => results[i] = Some(Err(e)),
            },
            Err(e) => results[i] = Some(Err(e)),
        }
    }

    // Every file of the group goes through one sequence of batches: no outcome leaves it
    // before the barrier behind it (§5.7 step 3). `None` only if a blocking step died — the
    // files it held then come back as errors.
    let new_batch = || Batch::new(Some(cx.progress.clone()));
    let mut batch = Some(new_batch());
    if !empties.is_empty() {
        let (mut filling, cancel) = (new_batch(), cx.cancel.clone());
        let filled = blocking(move || {
            for target in empties {
                filling.add_empty(target, &cancel);
            }
            filling
        });
        batch = filled.await.ok();
    }

    // Members in blob order; neighbours closer than RANGE_COALESCE_GAP share one request.
    wanted.sort_by_key(|(_, _, loc)| (loc.off, loc.clen));
    let mut runs: Vec<Run> = Vec::new();
    for (i, opener, loc) in wanted {
        let entry = &items[i].head.entry;
        let target = Target::new(i, &items[i]);
        if let Some(run) = runs.last_mut()
            && let (Some(member), Some(file)) = (run.members.last(), run.files.last_mut())
        {
            if file.loc == loc && file.size == entry.size && file.hash == entry.hash {
                file.targets.push(target);
                continue;
            }
            if loc.off >= member.end && loc.off - member.end <= RANGE_COALESCE_GAP {
                run.members.push(Member::whole(opener, &loc, entry.size));
                run.files.push(FileMember::new(loc, entry, target));
                continue;
            }
        }
        runs.push(Run {
            members: vec![Member::whole(opener, &loc, entry.size)],
            files: vec![FileMember::new(loc, entry, target)],
        });
    }

    let mut source = BlobSource::new(blob);
    // A failure of the blob as a whole (missing, truncated, quota, cancelled, retries used up).
    let mut fatal: Option<TransferError> = None;
    let mut fetched = false;
    for run in runs {
        if let Some(e) = &fatal {
            for target in run.files.iter().flat_map(|f| &f.targets) {
                results[target.idx] = Some(Err(replicate(e)));
            }
            continue;
        }
        let sink = FileSink {
            files: run.files,
            batch: batch.take().unwrap_or_else(new_batch),
            progress: cx.progress.clone(),
            cancel: cx.cancel.clone(),
        };
        let decoder = Decoder::new(run.members, sink);
        let mut pump = Pump::new(&*cx.backend, &mut source, decoder, cx.cancel.clone());
        match pump.run().await {
            Ok(()) => fetched = true,
            Err(e) => fatal = Some(e),
        }
        // The batch goes on to the next request of this blob: files of neighbouring requests
        // share a barrier.
        batch = pump.decoder.take().map(|decoder| decoder.sink.batch);
    }
    // The last barrier of the group — nothing was reported before this point.
    if let Some(batch) = batch
        && let Ok(settled) = blocking(move || batch.finish()).await
    {
        for (i, result) in settled {
            results[i] = Some(result);
        }
    }
    if fetched {
        cx.progress.blob_done();
    }
    in_input_order(items, results)
}

/// The items with their outcomes. An item without one was in a blocking step that died.
fn in_input_order(
    items: Vec<DownloadItem>,
    results: Vec<Option<Result<Downloaded, TransferError>>>,
) -> Vec<(DownloadItem, Result<Downloaded, TransferError>)> {
    items
        .into_iter()
        .zip(results)
        .map(|(item, result)| (item, result.unwrap_or_else(|| Err(decoder_lost()))))
        .collect()
}

/// Zero-length files (same target rules).
pub async fn materialize_empty(item: &DownloadItem) -> Result<Downloaded, TransferError> {
    let done = materialize_empties(vec![item.clone()], &CancellationToken::new()).await;
    match done.into_iter().next() {
        Some((_, result)) => result,
        None => Err(decoder_lost()),
    }
}

/// [`materialize_empty`] for every item, in batches (§5.7 step 3): the files are created and
/// renamed into place, and each batch ends with the barrier that makes it durable — an `Ok`
/// is returned only behind it. Once `cancel` fires, the items not written yet come back as
/// `Err(Cancelled)` (§5.7).
pub async fn materialize_empties(
    items: Vec<DownloadItem>,
    cancel: &CancellationToken,
) -> Vec<(DownloadItem, Result<Downloaded, TransferError>)> {
    let mut results: Vec<Option<Result<Downloaded, TransferError>>> =
        items.iter().map(|_| None).collect();
    let mut targets = Vec::new();
    for (i, item) in items.iter().enumerate() {
        match check_empty(item) {
            Ok(()) => targets.push(Target::new(i, item)),
            Err(e) => results[i] = Some(Err(e)),
        }
    }
    let cancel = cancel.clone();
    let settled = blocking(move || {
        let mut batch = Batch::new(None);
        for target in targets {
            batch.add_empty(target, &cancel);
        }
        batch.finish()
    });
    for (i, result) in settled.await.unwrap_or_default() {
        results[i] = Some(result);
    }
    in_input_order(items, results)
}

/// The entry is a file without content.
fn check_empty(item: &DownloadItem) -> Result<(), TransferError> {
    let e = &item.head.entry;
    if e.kind != EntryKind::File
        || e.size != 0
        || e.loc.is_some()
        || e.hash != *blake3::hash(b"").as_bytes()
    {
        return Err(TransferError::Verify(format!(
            "{}: not a zero-length file",
            item.rel
        )));
    }
    Ok(())
}

/// Plaintext bytes `[range)` of one file to `out` (cat). Authenticates every chunk it touches.
/// `blob` = the record of `head.entry.loc.blob`. The range is clamped to the file; verified
/// chunks are written as they arrive, so a later failure can follow output (§4.2).
pub async fn read_range<B: Backend>(
    backend: &B,
    keys: &Keyring,
    blob: &BlobRec,
    head: &Head,
    range: std::ops::Range<u64>,
    out: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
) -> Result<u64, TransferError> {
    let entry = &head.entry;
    let Some((opener, loc)) = data_member(keys, blob, entry)? else {
        return Ok(0);
    };
    let end = range.end.min(entry.size);
    let Some(span) = chunk_range(range.start..end, entry.size, loc.chunk_log2) else {
        return Ok(0);
    };
    let sink = RangeSink {
        skip: span.skip,
        left: end - range.start,
        out: Vec::new(),
        err: None,
    };
    let decoder = Decoder::new(vec![Member::span(opener, loc, entry.size, &span)], sink);
    let mut source = BlobSource::new(blob);
    let mut pump = Pump::new(backend, &mut source, decoder, CancellationToken::new());
    let mut written = 0;
    loop {
        let more = pump.step().await;
        if let Some(decoder) = pump.decoder.as_mut() {
            let verified = std::mem::take(&mut decoder.sink.out);
            out.write_all(&verified).await?;
            written += verified.len() as u64;
            if let Some(e) = decoder.sink.err.take() {
                return Err(e);
            }
        }
        if !more? {
            break;
        }
    }
    out.flush().await?;
    Ok(written)
}

/// Download + authenticate + BLAKE3-compare without writing (`check --download`).
pub async fn verify_remote<B: Backend>(
    backend: &B,
    keys: &Keyring,
    blob: &BlobRec,
    head: &Head,
) -> Result<(), TransferError> {
    let entry = &head.entry;
    let mismatch = || TransferError::Verify(format!("{}: content hash mismatch", head.path));
    let Some((opener, loc)) = data_member(keys, blob, entry)? else {
        return if entry.hash == *blake3::hash(b"").as_bytes() {
            Ok(())
        } else {
            Err(mismatch())
        };
    };
    let sink = HashSink {
        hasher: blake3::Hasher::new(),
        err: None,
    };
    let decoder = Decoder::new(vec![Member::whole(opener, loc, entry.size)], sink);
    let mut source = BlobSource::new(blob);
    let mut pump = Pump::new(backend, &mut source, decoder, CancellationToken::new());
    pump.run().await?;
    let sink = pump.decoder.take().ok_or_else(decoder_lost)?.sink;
    match sink.err {
        Some(e) => Err(e),
        None if *sink.hasher.finalize().as_bytes() != entry.hash => Err(mismatch()),
        None => Ok(()),
    }
}

/// `stat(rec.file_id)`; if absent: `find_by_name(blob name)` with exactly one hit; else
/// `BlobMissing`. Returns trashed objects too (caller un-trashes).
pub async fn locate_blob<B: Backend>(backend: &B, rec: &BlobRec) -> Result<ObjMeta, TransferError> {
    match backend.stat(&Handle(rec.file_id.clone())).await? {
        Some(meta) if !meta.is_folder => Ok(meta),
        _ => find_named(backend, rec).await,
    }
}

async fn find_named<B: Backend>(backend: &B, rec: &BlobRec) -> Result<ObjMeta, TransferError> {
    let mut hits = backend.find_by_name(&blob_name(&rec.id)).await?;
    hits.retain(|m| !m.is_folder);
    match hits.pop() {
        Some(meta) if hits.is_empty() => Ok(meta),
        _ => Err(TransferError::BlobMissing(rec.id.hex())),
    }
}

/// No symlinked ancestors, `path::validate`. Every existing ancestor of the target inside
/// `root` must be a real directory; ancestors that do not exist yet are fine (the download
/// creates them).
pub fn check_target_safe(root: &std::path::Path, rel: &str) -> Result<(), TransferError> {
    parent_dir(root, rel, false).map(drop)
}

/// Rename to the local conflict name (§5.1): `stem.conflict-local-<UTC>ext`, with `-2`, `-3`, …
/// while the name is taken. Never replaces an existing entry.
pub fn move_aside(target: &std::path::Path, now_ms: u64) -> std::io::Result<std::path::PathBuf> {
    let name = target.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the target has no UTF-8 file name",
        )
    })?;
    for attempt in 1..=10_000 {
        let aside = target.with_file_name(path::local_conflict_name(name, now_ms, attempt));
        // A hard link fails if the name exists — a rename would replace it.
        match fs::hard_link(target, &aside) {
            Ok(()) => {
                if let Err(e) = fs::remove_file(target) {
                    let _ = fs::remove_file(&aside);
                    return Err(e);
                }
                return Ok(aside);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            // No hard links here (FAT, some network file systems): check, then rename.
            Err(_) => match fs::symlink_metadata(&aside) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    fs::rename(target, &aside)?;
                    return Ok(aside);
                }
                Err(e) => return Err(e),
                Ok(_) => {}
            },
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no free conflict name",
    ))
}

// ---------------------------------------------------------------------------------------------
// Checks before any request
// ---------------------------------------------------------------------------------------------

/// The opener and location of a file's Data stream, or `None` for a zero-length file. Checks,
/// in this order: readable by this version (`Unsupported`) and key epoch held; stored in
/// `blob`; `clen` consistent with the size; inside the blob (§4.5) — else `Verify`.
fn data_member<'a>(
    keys: &Keyring,
    blob: &BlobRec,
    entry: &'a Entry,
) -> Result<Option<(Opener, &'a Loc)>, TransferError> {
    let bad = |what: &str| Err(TransferError::Verify(format!("blob {}: {what}", blob.id)));
    if entry.kind != EntryKind::File {
        return bad("the entry is not a file");
    }
    let Some(loc) = &entry.loc else {
        return if entry.size == 0 {
            Ok(None)
        } else {
            bad("the entry has no content location")
        };
    };
    let opener = keys.data_opener(loc)?;
    if loc.blob != blob.id {
        return bad("the entry is stored in another blob");
    }
    if entry.size == 0 || loc.clen != ciphertext_len(entry.size, loc.chunk_log2) {
        return bad("the entry's length and location disagree");
    }
    if loc
        .off
        .checked_add(loc.clen)
        .is_none_or(|end| end > blob.clen)
    {
        return bad("the entry's location is outside the blob");
    }
    Ok(Some((opener, loc)))
}

/// §5.7 step 1, plus the one outcome of step 3 that is certain before the download: a
/// directory nobody expected is never moved aside or replaced.
fn early_target_check(item: &DownloadItem) -> Result<(), TransferError> {
    let dir = parent_dir(&item.root, &item.rel, false)?;
    let target = dir.join(path::file_name(&item.rel));
    match fs::symlink_metadata(&target) {
        Ok(md) if md.is_dir() && item.expect_local != LocalExpect::EmptyDir => {
            Err(directory_in_the_way(&item.rel))
        }
        _ => Ok(()),
    }
}

fn directory_in_the_way(rel: &str) -> TransferError {
    TransferError::UnsafeTarget(format!("{rel}: a directory is in the way"))
}

fn decoder_lost() -> TransferError {
    TransferError::Io(io::Error::other("the download worker stopped unexpectedly"))
}

// ---------------------------------------------------------------------------------------------
// Decoder: bytes of a blob range → verified plaintext
// ---------------------------------------------------------------------------------------------

/// Receives the verified plaintext of the members of one request, in member order.
trait Sink: Send + 'static {
    fn data(&mut self, member: usize, plain: &[u8]) -> Result<(), TransferError>;
    /// Every wanted chunk of the member verified.
    fn end(&mut self, member: usize) -> Result<(), TransferError>;
    /// The member cannot be completed; nothing more arrives for it.
    fn fail(&mut self, member: usize, err: TransferError);
}

/// One Data stream (or a chunk span of it) inside the requested range.
struct Member {
    opener: Opener,
    /// Plaintext length from the authenticated entry: it decides which chunk is final.
    size: u64,
    /// Blob offsets of the first unit read and of the end of the last one.
    start: u64,
    end: u64,
    /// The stored header comes first and must equal the one recomputed from the entry.
    header: bool,
    next: u64,
    last: u64,
}

impl Member {
    fn whole(opener: Opener, loc: &Loc, size: u64) -> Member {
        Member {
            last: chunk_count(size, loc.chunk_log2) - 1,
            opener,
            size,
            start: loc.off,
            end: loc.off + loc.clen,
            header: true,
            next: 0,
        }
    }

    /// A ranged read skips the header entirely (§4.2).
    fn span(opener: Opener, loc: &Loc, size: u64, span: &ChunkSpan) -> Member {
        Member {
            opener,
            size,
            start: loc.off + span.cipher.start,
            end: loc.off + span.cipher.end,
            header: false,
            next: span.first,
            last: span.last,
        }
    }

    fn unit_len(&self) -> usize {
        if self.header {
            HEADER_LEN
        } else {
            chunk_cipher_len(self.next, self.size, self.opener.chunk_log2())
        }
    }
}

struct Decoder<S> {
    /// Ascending and disjoint.
    members: Vec<Member>,
    cur: usize,
    /// Blob offset of the first byte that is neither verified nor skipped: a unit boundary, or
    /// a point in the gap before `members[cur]`.
    pos: u64,
    /// The received part of the unit at `pos`.
    unit: Vec<u8>,
    plain: Vec<u8>,
    sink: S,
}

impl<S: Sink> Decoder<S> {
    fn new(members: Vec<Member>, sink: S) -> Self {
        Decoder {
            pos: members.first().map_or(0, |m| m.start),
            members,
            cur: 0,
            unit: Vec::new(),
            plain: Vec::new(),
            sink,
        }
    }

    fn done(&self) -> bool {
        self.cur == self.members.len()
    }

    /// Blob offset after the last member.
    fn end(&self) -> u64 {
        self.members.last().map_or(0, |m| m.end)
    }

    /// Where a new request has to start: the first unverified unit (§6.3). A partly received
    /// unit is dropped, the rest of a gap is skipped.
    fn resume(&mut self) -> u64 {
        self.unit.clear();
        if let Some(m) = self.members.get(self.cur) {
            self.pos = self.pos.max(m.start);
        }
        self.pos
    }

    /// Consumes bytes that continue at `pos + unit.len()`.
    fn feed(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let Some(m) = self.members.get(self.cur) else {
                return;
            };
            if self.pos < m.start {
                // A gap, or the rest of a member that failed.
                let skip = (m.start - self.pos).min(data.len() as u64) as usize;
                self.pos += skip as u64;
                data = &data[skip..];
                continue;
            }
            let need = m.unit_len();
            if self.unit.is_empty() && data.len() >= need {
                let (unit, rest) = data.split_at(need);
                data = rest;
                self.accept(unit);
            } else {
                let take = (need - self.unit.len()).min(data.len());
                self.unit.extend_from_slice(&data[..take]);
                data = &data[take..];
                if self.unit.len() == need {
                    let unit = std::mem::take(&mut self.unit);
                    self.accept(&unit);
                    self.unit = unit;
                    self.unit.clear();
                }
            }
        }
    }

    /// One complete unit of the current member.
    fn accept(&mut self, unit: &[u8]) {
        let i = self.cur;
        let m = &mut self.members[i];
        self.pos += unit.len() as u64;
        let finished = if m.header {
            m.header = false;
            if unit == m.opener.expected_header() {
                Ok(false)
            } else {
                Err(CryptoError::Corrupt.into())
            }
        } else {
            self.plain.clear();
            let last = m.next + 1 == chunk_count(m.size, m.opener.chunk_log2());
            match m.opener.open_chunk(m.next, last, unit, &mut self.plain) {
                Ok(()) => {
                    m.next += 1;
                    let finished = m.next > m.last;
                    self.sink.data(i, &self.plain).map(|()| finished)
                }
                Err(e) => Err(e.into()),
            }
        };
        match finished {
            Ok(false) => return,
            Ok(true) => {
                if let Err(e) = self.sink.end(i) {
                    self.sink.fail(i, e);
                }
            }
            Err(e) => self.sink.fail(i, e),
        }
        self.cur += 1;
    }

    /// The blob as a whole failed: every member that is not finished fails with it.
    fn fail_rest(&mut self, err: &TransferError) {
        for i in self.cur..self.members.len() {
            self.sink.fail(i, replicate(err));
        }
        self.cur = self.members.len();
    }
}

// ---------------------------------------------------------------------------------------------
// Pump: ranged requests with resume
// ---------------------------------------------------------------------------------------------

/// Which object holds the blob: the recorded file id, or — once that id proved gone — the
/// single object carrying the blob's name (§6.3).
struct BlobSource<'a> {
    rec: &'a BlobRec,
    handle: Handle,
    by_name: bool,
}

impl<'a> BlobSource<'a> {
    fn new(rec: &'a BlobRec) -> Self {
        BlobSource {
            rec,
            handle: Handle(rec.file_id.clone()),
            by_name: false,
        }
    }
}

struct Pump<'a, 'b, B: Backend, S> {
    backend: &'a B,
    source: &'a mut BlobSource<'b>,
    /// `None` only if a decoding step died.
    decoder: Option<Decoder<S>>,
    stream: Option<ByteStream>,
    /// Failed requests since the last one that made progress, and the position at that time.
    retries: u32,
    mark: u64,
    cancel: CancellationToken,
}

async fn unless_cancelled<T>(
    cancel: &CancellationToken,
    fut: impl Future<Output = T>,
) -> Result<T, TransferError> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(TransferError::Cancelled),
        out = fut => Ok(out),
    }
}

/// Pause before the n-th retry of a broken download (n ≥ 1): 250 ms, doubling. The backend
/// paces and backs off the requests themselves (§6.5); this only keeps a dead connection from
/// being hammered.
fn retry_pause(n: u32) -> Duration {
    Duration::from_millis(250 << (n - 1).min(5))
}

impl<'a, 'b, B: Backend, S: Sink> Pump<'a, 'b, B, S> {
    fn new(
        backend: &'a B,
        source: &'a mut BlobSource<'b>,
        decoder: Decoder<S>,
        cancel: CancellationToken,
    ) -> Self {
        Pump {
            backend,
            source,
            decoder: Some(decoder),
            stream: None,
            retries: 0,
            mark: 0,
            cancel,
        }
    }

    /// Runs to the end. `Err` is a failure of the blob as a whole; the members it left
    /// unfinished have failed with it. Failures of single members are the sink's business.
    async fn run(&mut self) -> Result<(), TransferError> {
        loop {
            match self.step().await {
                Ok(true) => {}
                Ok(false) => return Ok(()),
                Err(e) => {
                    if let Some(decoder) = self.decoder.as_mut() {
                        decoder.fail_rest(&e);
                    }
                    return Err(e);
                }
            }
        }
    }

    /// Receives and decodes one batch. `Ok(false)`: every member is finished or failed.
    async fn step(&mut self) -> Result<bool, TransferError> {
        let decoder = self.decoder.as_mut().ok_or_else(decoder_lost)?;
        if decoder.done() {
            return Ok(false);
        }
        if self.stream.is_none() {
            let range = decoder.resume()..decoder.end();
            match self.open(range).await? {
                Ok(stream) => self.stream = Some(stream),
                Err(e) => {
                    self.broken(Err(e)).await?;
                    return Ok(true);
                }
            }
        }
        let Some(stream) = self.stream.as_mut() else {
            return Ok(true);
        };

        // Wait for the first buffer, then take what is ready, up to FEED_BATCH.
        let mut batch = Vec::new();
        let mut size = 0;
        // `Some` once the stream ended (`Ok`) or broke (`Err`).
        let mut ended = None;
        let mut next = Some(unless_cancelled(&self.cancel, stream.next()).await?);
        loop {
            match next {
                Some(Some(Ok(bytes))) => {
                    size += bytes.len();
                    batch.push(bytes);
                }
                Some(Some(Err(e))) => ended = Some(Err(e)),
                Some(None) => ended = Some(Ok(())),
                None => break,
            }
            if ended.is_some() || size >= FEED_BATCH {
                break;
            }
            next = stream.next().now_or_never();
        }

        if !batch.is_empty() {
            let mut decoder = self.decoder.take().ok_or_else(decoder_lost)?;
            let decoded = blocking(move || {
                batch.iter().for_each(|bytes| decoder.feed(bytes));
                decoder
            });
            self.decoder = Some(decoded.await?);
        }
        if self.decoder.as_ref().is_none_or(|d| d.done()) {
            self.stream = None;
            return Ok(false);
        }
        if let Some(end) = ended {
            self.stream = None;
            self.broken(end).await?;
        }
        Ok(true)
    }

    /// `get` with the by-name fallback for a file id that is gone. The inner error is a
    /// failed request, to be judged by [`broken`](Self::broken).
    async fn open(
        &mut self,
        range: std::ops::Range<u64>,
    ) -> Result<Result<ByteStream, BackendError>, TransferError> {
        loop {
            let get = self.backend.get(&self.source.handle, Some(range.clone()));
            match unless_cancelled(&self.cancel, get).await? {
                Err(BackendError::NotFound) if !self.source.by_name => {
                    let named = find_named(self.backend, self.source.rec);
                    let found = unless_cancelled(&self.cancel, named).await??;
                    self.source.handle = found.handle;
                    self.source.by_name = true;
                }
                Err(BackendError::NotFound) => {
                    return Err(TransferError::BlobMissing(self.source.rec.id.hex()));
                }
                other => return Ok(other),
            }
        }
    }

    /// A request failed, broke off or ended early: pause and let the next step re-request from
    /// the first unverified chunk, or give up.
    async fn broken(&mut self, end: Result<(), BackendError>) -> Result<(), TransferError> {
        let decoder = self.decoder.as_mut().ok_or_else(decoder_lost)?;
        let (pos, need) = (decoder.resume(), decoder.end());
        let err = match end {
            Err(e @ (BackendError::Transient(_) | BackendError::Io(_))) => e,
            Err(e) => return Err(e.into()),
            Ok(()) => {
                // A cut connection can look like this — and so does an object that is shorter
                // than the index says. The second never gets better.
                let stat = self.backend.stat(&self.source.handle);
                if let Ok(Some(meta)) = unless_cancelled(&self.cancel, stat).await?
                    && meta.size < need
                {
                    return Err(TransferError::Verify(format!(
                        "blob {} is truncated: {} bytes stored, {} recorded",
                        self.source.rec.id, meta.size, self.source.rec.clen
                    )));
                }
                BackendError::Transient("the download ended early".into())
            }
        };
        if pos > self.mark {
            self.retries = 0;
        }
        self.mark = pos;
        if self.retries >= DOWNLOAD_RETRIES {
            return Err(err.into());
        }
        self.retries += 1;
        tracing::debug!(blob = %self.source.rec.id, at = pos, retry = self.retries, "download broke off: {err}");
        unless_cancelled(&self.cancel, tokio::time::sleep(retry_pause(self.retries))).await
    }
}

// ---------------------------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------------------------

/// `read_range`: the bytes of the range, trimmed out of the chunks that hold it.
struct RangeSink {
    /// Plaintext bytes to drop before the range starts, and bytes of the range still to come.
    skip: usize,
    left: u64,
    out: Vec<u8>,
    err: Option<TransferError>,
}

impl Sink for RangeSink {
    fn data(&mut self, _: usize, plain: &[u8]) -> Result<(), TransferError> {
        let from = self.skip.min(plain.len());
        self.skip -= from;
        let take = ((plain.len() - from) as u64).min(self.left) as usize;
        self.out.extend_from_slice(&plain[from..from + take]);
        self.left -= take as u64;
        Ok(())
    }

    fn end(&mut self, _: usize) -> Result<(), TransferError> {
        Ok(())
    }

    fn fail(&mut self, _: usize, err: TransferError) {
        self.err = Some(err);
    }
}

/// `verify_remote`: nothing is kept but the hash.
struct HashSink {
    hasher: blake3::Hasher,
    err: Option<TransferError>,
}

impl Sink for HashSink {
    fn data(&mut self, _: usize, plain: &[u8]) -> Result<(), TransferError> {
        self.hasher.update(plain);
        Ok(())
    }

    fn end(&mut self, _: usize) -> Result<(), TransferError> {
        Ok(())
    }

    fn fail(&mut self, _: usize, err: TransferError) {
        self.err = Some(err);
    }
}

/// The members of one request and the files they become.
struct Run {
    members: Vec<Member>,
    files: Vec<FileMember>,
}

/// One member of a blob and every local file that gets its content.
struct FileMember {
    loc: Loc,
    size: u64,
    hash: [u8; 32],
    hasher: blake3::Hasher,
    targets: Vec<Target>,
    /// The verified plaintext so far, for a member of at most `MEMBER_BUFFER_MAX` bytes: no
    /// file is opened before the member is complete.
    buffer: Option<Vec<u8>>,
    /// For a larger member: the one target whose partial file takes the plaintext as it
    /// arrives. The others are copied from that file once the member is complete.
    primary: Option<usize>,
}

impl FileMember {
    fn new(loc: Loc, entry: &Entry, target: Target) -> Self {
        FileMember {
            loc,
            size: entry.size,
            hash: entry.hash,
            hasher: blake3::Hasher::new(),
            targets: vec![target],
            buffer: (entry.size <= MEMBER_BUFFER_MAX).then(Vec::new),
            primary: None,
        }
    }

    /// Fails every target that has no outcome yet with (a copy of) `err`.
    fn settle_all(&mut self, err: &TransferError, batch: &mut Batch) {
        (self.buffer, self.primary) = (None, None);
        for target in self.targets.iter_mut().filter(|t| !t.settled) {
            target.settle();
            batch.fail(target.idx, replicate(err));
        }
    }
}

/// `download_group`: partial files, finished per §5.7 once the member's hash matched.
struct FileSink {
    files: Vec<FileMember>,
    /// Takes every target that is written, and every outcome (§5.7 step 3).
    batch: Batch,
    progress: Progress,
    /// Looked at between the targets of one member, which can be many (§5.7).
    cancel: CancellationToken,
}

impl FileSink {
    /// The end of §5.7 step 2 for one target whose partial file is complete: it goes to the
    /// batch, which syncs it, closes it, and renames it once its content is durable.
    fn finish(&mut self, member: usize, at: usize) {
        let size = self.files[member].size;
        let target = &mut self.files[member].targets[at];
        match target.stage(size) {
            Ok((staged, file)) => self.batch.add(staged, file),
            Err(e) => self.batch.fail(target.idx, e),
        }
        target.settle();
    }
}

impl Sink for FileSink {
    fn data(&mut self, member: usize, plain: &[u8]) -> Result<(), TransferError> {
        let file = &mut self.files[member];
        file.hasher.update(plain);
        if let Some(buffer) = &mut file.buffer {
            if buffer.capacity() == 0 {
                buffer.reserve_exact(file.size as usize);
            }
            buffer.extend_from_slice(plain);
            return Ok(());
        }
        // The first target whose partial file can be created takes the bytes.
        while file.primary.is_none() {
            let Some(at) = file.targets.iter().position(|t| !t.settled) else {
                break;
            };
            let target = &mut file.targets[at];
            match target.open() {
                Ok(()) => file.primary = Some(at),
                Err(e) => {
                    target.settle();
                    self.batch.fail(target.idx, e);
                }
            }
        }
        // With no file left to write, the decoder is told to skip the rest of the member; every
        // target already has its own error, so this one is never reported.
        let Some(at) = file.primary else {
            return Err(TransferError::Cancelled);
        };
        match file.targets[at].write(plain) {
            Ok(()) => {
                self.progress.add_bytes(plain.len() as u64);
                Ok(())
            }
            Err(e) => {
                // A full disk or an I/O error: the other targets would be written to the same
                // tree, from a file that is now incomplete. They fail with it.
                file.settle_all(&e, &mut self.batch);
                Err(TransferError::Cancelled)
            }
        }
    }

    fn end(&mut self, member: usize) -> Result<(), TransferError> {
        let file = &mut self.files[member];
        if *file.hasher.finalize().as_bytes() != file.hash {
            return Err(TransferError::Verify(
                "content hash mismatch after decryption".into(),
            ));
        }
        let (size, hash) = (file.size, file.hash);
        let buffer = file.buffer.take();
        let primary = file.primary.take();
        // The complete, verified partial file of a streamed member. It is read for the copies
        // and goes back to its target afterwards.
        let source = primary.and_then(|at| file.targets[at].partial.take());
        let mut piece = Vec::new();
        // One target after another: each file is written, finished and closed before the next
        // one is opened.
        for at in 0..self.files[member].targets.len() {
            let target = &mut self.files[member].targets[at];
            if target.settled || Some(at) == primary {
                continue;
            }
            let filled = match (&buffer, &source) {
                _ if self.cancel.is_cancelled() => Err(TransferError::Cancelled),
                (Some(buffer), _) => target.write(buffer),
                (None, Some(source)) => {
                    target.copy_from(&source.file, size, &hash, &mut piece, &self.cancel)
                }
                (None, None) => Err(decoder_lost()),
            };
            match filled {
                Ok(()) => {
                    self.progress.add_bytes(size);
                    self.finish(member, at);
                }
                Err(e) => {
                    target.settle();
                    self.batch.fail(target.idx, e);
                }
            }
        }
        if let Some(at) = primary {
            self.files[member].targets[at].partial = source;
            self.finish(member, at);
        }
        Ok(())
    }

    fn fail(&mut self, member: usize, err: TransferError) {
        self.files[member].settle_all(&err, &mut self.batch);
    }
}

// ---------------------------------------------------------------------------------------------
// Local targets (§5.7 steps 1–3)
// ---------------------------------------------------------------------------------------------

struct Target {
    idx: usize,
    root: PathBuf,
    rel: String,
    expect: LocalExpect,
    mtime_ns: i64,
    exec: bool,
    /// Created when the first bytes are written to it — verified ones only.
    partial: Option<Partial>,
    /// The outcome is recorded; nothing more is written.
    settled: bool,
}

impl Target {
    fn new(idx: usize, item: &DownloadItem) -> Self {
        Target {
            idx,
            root: item.root.clone(),
            rel: item.rel.clone(),
            expect: item.expect_local,
            mtime_ns: item.head.entry.mtime_ns,
            exec: item.head.entry.exec,
            partial: None,
            settled: false,
        }
    }

    /// Creates the partial file, unless it exists.
    fn open(&mut self) -> Result<(), TransferError> {
        if self.partial.is_none() {
            self.partial = Some(Partial::create(&self.root, &self.rel)?);
        }
        Ok(())
    }

    fn write(&mut self, plain: &[u8]) -> Result<(), TransferError> {
        let partial = match &mut self.partial {
            Some(partial) => partial,
            None => self.partial.insert(Partial::create(&self.root, &self.rel)?),
        };
        Ok(partial.file.write_all(plain)?)
    }

    /// Fills the partial file with the `size` bytes of `source` — the complete partial file of
    /// another target of the same member. The bytes are hashed again on the way: what is
    /// renamed into place is what was verified, whatever happened to `source` meanwhile.
    fn copy_from(
        &mut self,
        source: &File,
        size: u64,
        hash: &[u8; 32],
        piece: &mut Vec<u8>,
        cancel: &CancellationToken,
    ) -> Result<(), TransferError> {
        use std::os::unix::fs::FileExt;
        piece.resize(size.min(COPY_PIECE) as usize, 0);
        let mut hasher = blake3::Hasher::new();
        let mut at = 0;
        while at < size {
            if cancel.is_cancelled() {
                return Err(TransferError::Cancelled);
            }
            let n = (size - at).min(COPY_PIECE) as usize;
            source.read_exact_at(&mut piece[..n], at)?;
            hasher.update(&piece[..n]);
            self.write(&piece[..n])?;
            at += n as u64;
        }
        if hasher.finalize().as_bytes() != hash {
            return Err(TransferError::Verify(
                "content hash mismatch in a local copy".into(),
            ));
        }
        Ok(())
    }

    /// Removes the partial file, if there still is one.
    fn settle(&mut self) {
        self.partial = None;
        self.settled = true;
    }

    /// The end of §5.7 step 2, after the last verified byte: mtime and mode are set. What
    /// comes back goes to a [`Batch`]: the file's name, which waits there for the rename, and
    /// the descriptor it was written with — the one its content is synced through.
    fn stage(&mut self, size: u64) -> Result<(Staged, File), TransferError> {
        let partial = self.partial.take().ok_or_else(decoder_lost)?;
        let target = self.root.join(&self.rel);
        let mtime = filetime::FileTime::from_unix_time(
            self.mtime_ns.div_euclid(1_000_000_000),
            self.mtime_ns.rem_euclid(1_000_000_000) as u32,
        );
        filetime::set_file_handle_times(&partial.file, None, Some(mtime))?;
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            // A regular file at the target — the one the rename replaces, or one that is
            // moved aside first — hands its permission bits to its successor.
            let replaced = match fs::symlink_metadata(&target) {
                Ok(md) if md.is_file() => Some(md.mode()),
                _ => None,
            };
            let mode = file_mode(replaced, self.exec);
            // Whatever the mode — a file that replaces a `chmod 000` file takes that over —
            // the descriptor at hand stays usable: the file is never opened a second time.
            partial
                .file
                .set_permissions(fs::Permissions::from_mode(mode))?;
        }
        let staged = Staged {
            idx: self.idx,
            root: self.root.clone(),
            rel: self.rel.clone(),
            expect: self.expect,
            name: partial.name,
            size,
        };
        Ok((staged, partial.file))
    }
}

/// A partial file that is complete — verified content, final mtime and mode. It is renamed
/// into place by its [`Batch`], after the barrier that makes its content durable.
struct Staged {
    idx: usize,
    root: PathBuf,
    rel: String,
    expect: LocalExpect,
    name: PartialName,
    size: u64,
}

impl Staged {
    /// §5.7 step 3 up to the rename and the `lstat` behind it. Returns the outcome — which
    /// must not be reported before the rename is durable — and the directory it happened in.
    /// A partial file that is gone (somebody removed it) fails here, and fails alone.
    fn rename(mut self) -> Result<(Downloaded, PathBuf), TransferError> {
        let target = self.root.join(&self.rel);
        let way = make_way(&target, &self.rel, self.expect)?;
        if let Err(e) = fs::rename(&self.name.path, &target) {
            way.undo(&target);
            return Err(e.into());
        }
        self.name.renamed = true;
        let observed_ns = util::now_ns();
        let sig = StatSig::from_metadata(&fs::symlink_metadata(&target)?);
        let done = Downloaded {
            rel: std::mem::take(&mut self.rel),
            sig,
            observed_ns,
            moved_aside: match way {
                Way::MovedAside(aside) => Some(aside),
                Way::Free | Way::RemovedDir => None,
            },
        };
        let dir = target.parent().unwrap_or(&self.root).to_path_buf();
        Ok((done, dir))
    }
}

/// Writing descriptors that wait in the batches of this process for their hand-over; kept
/// under `DOWNLOAD_OPEN_TOTAL`.
static HELD: AtomicUsize = AtomicUsize::new(0);

/// The written files of a download whose outcome is not reported yet, and the outcomes that
/// may be (§5.7 step 3a). A file is durable only after a flush of the drive's write cache, and
/// such a flush costs the same for one file as for a thousand — so the files are finished
/// together, in this order:
///
/// 1. **content barrier**, in two halves. *Hand-over*: every file is synced through the
///    descriptor it was written with, and closed ([`durable::hand_over`]) — at once where
///    that is cheap by itself (`DOWNLOAD_OPEN_FILES` = 1), in groups behind one `syncfs` on
///    Linux. A file whose sync or close fails is dropped from the batch, alone. *Flush*: the
///    drives are flushed ([`durable::Drives::flush`]), once for the whole batch;
/// 2. each file is renamed into place under the re-stat rules (`make_way`). A power loss
///    from here on finds complete files at the targets, never empty or half-written ones
///    that a later upload would take for local edits;
/// 3. **rename barrier** — the directories the renames happened in, and their ancestors up
///    to the root (they may have been created for these files), are made durable
///    ([`durable::make_durable`]);
/// 4. only now the outcomes are released, and the caller writes its base rows.
///
/// A failing barrier fails every file behind it: after a failed content barrier nothing is
/// renamed, after a failed rename barrier nothing is reported as downloaded. A directory that
/// alone cannot be made durable fails the files in and below it.
///
/// A batch is closed after `DOWNLOAD_BATCH_FILES` files or `DOWNLOAD_BATCH_BYTES` bytes, when
/// a file arrives `DOWNLOAD_BATCH_AGE` after its first one (a slow download does not keep
/// finished files waiting for a full batch), and at the end of its group. It holds names —
/// and at most `max_open` descriptors, plus one per device for the flush.
struct Batch {
    /// Counts a file when it is released; `None`: nobody watches.
    progress: Option<Progress>,
    /// Complete files that are still open: their content is not handed over yet.
    open: Vec<(Staged, File)>,
    /// `open` is handed over when it has this many files.
    max_open: usize,
    /// Handed over and closed; they wait for the flush and their rename.
    staged: Vec<Staged>,
    /// What the flush of this batch's content needs.
    drives: durable::Drives,
    bytes: u64,
    /// When the first file of the batch was added.
    opened: Option<Instant>,
    max_age: Duration,
    /// `(item index, outcome)`: failures at once, an `Ok` only behind both of its barriers.
    released: Vec<(usize, Result<Downloaded, TransferError>)>,
}

impl Batch {
    fn new(progress: Option<Progress>) -> Batch {
        Batch {
            progress,
            open: Vec::new(),
            max_open: DOWNLOAD_OPEN_FILES,
            staged: Vec::new(),
            drives: durable::Drives::default(),
            bytes: 0,
            opened: None,
            max_age: DOWNLOAD_BATCH_AGE,
            released: Vec::new(),
        }
    }

    /// A failure needs no barrier.
    fn fail(&mut self, idx: usize, err: TransferError) {
        self.released.push((idx, Err(err)));
    }

    /// Files that wait for the end of the batch.
    fn waiting(&self) -> usize {
        self.open.len() + self.staged.len()
    }

    /// `file` is the descriptor the staged file was written with.
    fn add(&mut self, staged: Staged, file: File) {
        self.bytes += staged.size;
        self.open.push((staged, file));
        let held = HELD.fetch_add(1, Ordering::Relaxed) + 1;
        let opened = *self.opened.get_or_insert_with(Instant::now);
        if self.waiting() >= DOWNLOAD_BATCH_FILES
            || self.bytes >= DOWNLOAD_BATCH_BYTES
            || (self.waiting() > 1 && opened.elapsed() >= self.max_age)
        {
            self.flush();
        } else if self.open.len() >= self.max_open || held > DOWNLOAD_OPEN_TOTAL {
            self.hand_over();
        }
    }

    /// A zero-length file: nothing to fetch, the same rules for the target.
    fn add_empty(&mut self, mut target: Target, cancel: &CancellationToken) {
        if cancel.is_cancelled() {
            return self.fail(target.idx, TransferError::Cancelled);
        }
        match target.write(&[]).and_then(|()| target.stage(0)) {
            Ok((staged, file)) => self.add(staged, file),
            Err(e) => self.fail(target.idx, e),
        }
    }

    /// First half of step 1 for the files that are still open: each is synced through its
    /// own descriptor and closed. One that fails is reported and removed; the others go on.
    fn hand_over(&mut self) {
        let open = std::mem::take(&mut self.open);
        if open.is_empty() {
            return;
        }
        HELD.fetch_sub(open.len(), Ordering::Relaxed);
        let (staged, files): (Vec<Staged>, Vec<File>) = open.into_iter().unzip();
        let named = staged.iter().map(|s| s.name.path.as_path()).zip(files);
        let mut failed: HashMap<usize, io::Error> =
            match durable::hand_over(named.collect(), &mut self.drives) {
                Ok(failed) => failed.into_iter().collect(),
                Err(e) => {
                    // Dropping the staged files removes them.
                    let e = TransferError::Io(e);
                    let all = staged.iter().map(|s| (s.idx, Err(replicate(&e))));
                    self.released.extend(all);
                    return;
                }
            };
        for (at, file) in staged.into_iter().enumerate() {
            match failed.remove(&at) {
                // Dropping the staged file removes it.
                Some(e) => self.released.push((file.idx, Err(TransferError::Io(e)))),
                None => self.staged.push(file),
            }
        }
    }

    /// Steps 1–4 for the files added so far.
    fn flush(&mut self) {
        self.hand_over();
        let staged = std::mem::take(&mut self.staged);
        let drives = std::mem::take(&mut self.drives);
        (self.bytes, self.opened) = (0, None);
        if staged.is_empty() {
            return;
        }
        let partials: Vec<&Path> = staged.iter().map(|s| s.name.path.as_path()).collect();
        if let Err(e) = drives.flush(&partials) {
            // Nothing is renamed; dropping the staged files removes them.
            let e = TransferError::Io(e);
            let failed = staged.iter().map(|s| (s.idx, Err(replicate(&e))));
            self.released.extend(failed);
            return;
        }

        let mut renamed = Vec::with_capacity(staged.len());
        let mut dirs: BTreeSet<PathBuf> = BTreeSet::new();
        for file in staged {
            let (idx, root) = (file.idx, file.root.clone());
            match file.rename() {
                Ok((done, dir)) => {
                    // A directory that is in the set has its ancestors in it too.
                    for dir in dir.ancestors() {
                        if !dir.starts_with(&root) || !dirs.insert(dir.to_path_buf()) {
                            break;
                        }
                    }
                    renamed.push((idx, done, dir));
                }
                Err(e) => self.released.push((idx, Err(e))),
            }
        }

        let dirs: Vec<&Path> = dirs.iter().map(PathBuf::as_path).collect();
        // The files are in place, but nobody is told of one whose rename is not known to be
        // durable: no base row without the barrier.
        let failed = match durable::make_durable(&dirs) {
            Ok(failed) => failed,
            Err(e) => {
                let e = TransferError::Io(e);
                let all = renamed.iter().map(|(idx, _, _)| (*idx, Err(replicate(&e))));
                self.released.extend(all);
                return;
            }
        };
        for (idx, done, dir) in renamed {
            // The directory of the rename or one above it: the file's chain is broken.
            let broken = failed.iter().find(|(at, _)| dir.starts_with(dirs[*at]));
            match broken {
                Some((_, e)) => {
                    let e = io::Error::new(e.kind(), e.to_string());
                    self.released.push((idx, Err(TransferError::Io(e))));
                }
                None => {
                    if let Some(progress) = &self.progress {
                        progress.file_done();
                    }
                    self.released.push((idx, Ok(done)));
                }
            }
        }
    }

    /// Closes the last batch; every outcome that comes back is final.
    fn finish(mut self) -> Vec<(usize, Result<Downloaded, TransferError>)> {
        self.flush();
        std::mem::take(&mut self.released)
    }
}

impl Drop for Batch {
    /// A batch that is dropped unfinished (its blocking step died) gives its descriptors back.
    fn drop(&mut self) {
        HELD.fetch_sub(self.open.len(), Ordering::Relaxed);
    }
}

/// A partial file while it is written.
struct Partial {
    name: PartialName,
    file: File,
}

/// `<dir>/.gclone-partial-<8 random hex>`; removed on drop unless it was renamed into place.
struct PartialName {
    path: PathBuf,
    renamed: bool,
}

impl Partial {
    fn create(root: &Path, rel: &str) -> Result<Partial, TransferError> {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = parent_dir(root, rel, true)?;
        let mut taken = None;
        for _ in 0..8 {
            let path = dir.join(format!(
                "{PARTIAL_PREFIX}{}",
                util::hex(&util::random::<4>())
            ));
            // Readable as well: the other targets of a large member are copied from it.
            let opened = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path);
            match opened {
                Ok(file) => {
                    let name = PartialName {
                        path,
                        renamed: false,
                    };
                    return Ok(Partial { name, file });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => taken = Some(e),
                Err(e) => return Err(e.into()),
            }
        }
        Err(taken
            .unwrap_or_else(|| io::ErrorKind::AlreadyExists.into())
            .into())
    }
}

impl Drop for PartialName {
    fn drop(&mut self) {
        if !self.renamed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// The parent directory of `root/rel`, after `path::validate` and a walk from `root` down:
/// every existing level must `lstat` as a directory — not a symlink, not a file — else
/// `UnsafeTarget`. Missing levels end the check, or are created (`create`).
fn parent_dir(root: &Path, rel: &str, create: bool) -> Result<PathBuf, TransferError> {
    path::validate(rel).map_err(|e| TransferError::UnsafeTarget(format!("{rel}: {e}")))?;
    if create {
        fs::create_dir_all(root)?;
    }
    let mut dir = root.to_path_buf();
    let mut missing = false;
    for name in path::parent(rel).into_iter().flat_map(|p| p.split('/')) {
        dir.push(name);
        while !missing {
            match fs::symlink_metadata(&dir) {
                Ok(md) if md.is_dir() => break,
                Ok(_) => {
                    return Err(TransferError::UnsafeTarget(format!(
                        "{rel}: {} is not a directory",
                        dir.display()
                    )));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound && !create => missing = true,
                Err(e) if e.kind() == io::ErrorKind::NotFound => match fs::create_dir(&dir) {
                    Ok(()) => break,
                    // Somebody else made it meanwhile: look at what it is.
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                },
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(dir)
}

/// What [`make_way`] did to the entry that was at the target.
enum Way {
    Free,
    MovedAside(PathBuf),
    RemovedDir,
}

impl Way {
    /// The rename did not happen: put back what was there, as far as possible.
    fn undo(&self, target: &Path) {
        match self {
            Way::Free => {}
            Way::MovedAside(aside) => {
                if fs::hard_link(aside, target).is_ok() {
                    let _ = fs::remove_file(aside);
                }
            }
            Way::RemovedDir => {
                let _ = fs::create_dir(target);
            }
        }
    }
}

/// §5.7 step 3: re-stat the target immediately before the rename and compare with what the
/// plan expects there.
fn make_way(target: &Path, rel: &str, expect: LocalExpect) -> Result<Way, TransferError> {
    let md = match fs::symlink_metadata(target) {
        Ok(md) => md,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Way::Free),
        Err(e) => return Err(e.into()),
    };
    if md.is_dir() {
        // The expected empty directory goes (rmdir refuses a non-empty one); any other
        // directory is never moved aside or replaced.
        return if expect == LocalExpect::EmptyDir && fs::remove_dir(target).is_ok() {
            Ok(Way::RemovedDir)
        } else {
            Err(directory_in_the_way(rel))
        };
    }
    if let LocalExpect::File(sig) = expect
        && md.is_file()
        && StatSig::from_metadata(&md) == sig
    {
        // Exactly the file the plan saw: the rename replaces it.
        return Ok(Way::Free);
    }
    // Unexpected. If the directory lists no entry with exactly these name bytes, the entry is
    // a different spelling that the file system folds onto ours.
    if !listed_exactly(target)? {
        return Err(TransferError::TargetCollision(rel.to_string()));
    }
    Ok(Way::MovedAside(move_aside(target, util::now_ms())?))
}

fn listed_exactly(target: &Path) -> io::Result<bool> {
    let (Some(dir), Some(name)) = (target.parent(), target.file_name()) else {
        return Ok(true);
    };
    for entry in fs::read_dir(dir)? {
        if entry?.file_name() == name {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The permission bits of a downloaded file (§5.7 step 2). The index records only whether a
/// file is executable. A file that takes the place of an existing regular file keeps that
/// file's permission bits — a private 0600 file is never widened by an update — with the x
/// bits following `exec` exactly as `SetLocalMeta` sets them (x follows r); set-id and sticky
/// bits are not carried over. A new file gets 0644 / 0755 under the umask.
fn file_mode(replaced: Option<u32>, exec: bool) -> u32 {
    match replaced {
        Some(mode) => {
            let mode = mode & 0o777;
            if exec {
                mode | 0o100 | ((mode & 0o044) >> 2)
            } else {
                mode & !0o111
            }
        }
        None => (if exec { 0o755 } else { 0o644 }) & !umask(),
    }
}

/// The process umask. It can only be read by setting it, so it is read once.
fn umask() -> u32 {
    static UMASK: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *UMASK.get_or_init(|| {
        // SAFETY: umask(2) has no preconditions and cannot fail. The mask in force between the
        // two calls is the strictest one, so a file another thread creates in that moment is at
        // worst more private than it asked for.
        let mask = unsafe {
            let mask = libc::umask(0o077);
            libc::umask(mask);
            mask
        };
        // `mode_t` is 16 bits wide on macOS and is `u32` itself on Linux.
        #[allow(clippy::useless_conversion)]
        u32::from(mask)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::CHUNK_LOG2;
    use crate::crypto::MasterKey;
    use crate::types::BlobId;

    fn keys() -> Keyring {
        Keyring::new([7; 16], vec![(1, MasterKey::from_bytes([9; 32]))], 1).unwrap()
    }

    /// Seals `plain` as one Data stream; returns the stream and its location at `off`.
    fn seal(keys: &Keyring, plain: &[u8], off: u64) -> (Vec<u8>, Loc) {
        let mut sealer = keys.data_sealer();
        let mut out = sealer.header().to_vec();
        let mut chunks = plain.chunks(1 << CHUNK_LOG2).peekable();
        while let Some(chunk) = chunks.next() {
            sealer
                .seal_chunk(chunk, chunks.peek().is_none(), &mut out)
                .unwrap();
        }
        let loc = Loc {
            blob: BlobId([1; 16]),
            off,
            clen: out.len() as u64,
            salt: sealer.salt(),
            chunk_log2: CHUNK_LOG2,
            epoch: 1,
            suite: 1,
            flags: 0,
        };
        (out, loc)
    }

    #[derive(Default)]
    struct Collect {
        plain: Vec<Vec<u8>>,
        ended: Vec<usize>,
        failed: Vec<(usize, String)>,
    }

    impl Sink for Collect {
        fn data(&mut self, member: usize, plain: &[u8]) -> Result<(), TransferError> {
            self.plain
                .resize(self.plain.len().max(member + 1), Vec::new());
            self.plain[member].extend_from_slice(plain);
            Ok(())
        }
        fn end(&mut self, member: usize) -> Result<(), TransferError> {
            self.ended.push(member);
            Ok(())
        }
        fn fail(&mut self, member: usize, err: TransferError) {
            self.failed.push((member, err.to_string()));
        }
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31) ^ seed)
            .collect()
    }

    /// Three members with gaps: `gap ‖ A ‖ gap ‖ B ‖ C`.
    fn blob3(keys: &Keyring) -> (Vec<u8>, Vec<Vec<u8>>, Vec<Loc>) {
        let plains = vec![pattern(100_000, 1), pattern(65_536, 2), pattern(5, 3)];
        let mut blob = vec![0xee; 10];
        let mut locs = Vec::new();
        for (i, plain) in plains.iter().enumerate() {
            let (stream, loc) = seal(keys, plain, blob.len() as u64);
            blob.extend_from_slice(&stream);
            locs.push(loc);
            if i == 0 {
                blob.extend_from_slice(&[0xee; 1000]);
            }
        }
        (blob, plains, locs)
    }

    fn decoder(keys: &Keyring, plains: &[Vec<u8>], locs: &[Loc]) -> Decoder<Collect> {
        let members = locs
            .iter()
            .zip(plains)
            .map(|(loc, p)| Member::whole(keys.data_opener(loc).unwrap(), loc, p.len() as u64))
            .collect();
        Decoder::new(members, Collect::default())
    }

    #[test]
    fn the_decoder_is_independent_of_how_the_bytes_arrive() {
        let keys = keys();
        let (blob, plains, locs) = blob3(&keys);
        for piece in [1usize, 7, 59, 60, 61, 4096, 65_552, 65_553, blob.len()] {
            let mut dec = decoder(&keys, &plains, &locs);
            let from = dec.resume() as usize;
            assert_eq!(from, 10);
            for part in blob[from..].chunks(piece) {
                dec.feed(part);
            }
            assert!(dec.done(), "piece {piece}");
            assert_eq!(dec.sink.plain, plains, "piece {piece}");
            assert_eq!(dec.sink.ended, [0, 1, 2]);
            assert!(dec.sink.failed.is_empty());
            assert_eq!(dec.pos, blob.len() as u64);
        }
    }

    #[test]
    fn the_decoder_resumes_at_the_first_unverified_unit() {
        let keys = keys();
        let (blob, plains, locs) = blob3(&keys);
        let end = blob.len();
        for cut in (10..end).step_by(977).chain([10, 69, 70, 71, end - 1]) {
            let mut dec = decoder(&keys, &plains, &locs);
            dec.feed(&blob[10..cut]);
            let at = dec.resume() as usize;
            let gap = (locs[0].off + locs[0].clen) as usize..locs[1].off as usize;
            if gap.contains(&cut) {
                // The rest of a gap is not requested again.
                assert_eq!(at, gap.end, "cut {cut}");
            } else {
                // Never past the cut, never more than one unit before it.
                assert!(
                    at <= cut && cut - at <= 65_552,
                    "cut {cut}: resumes at {at}"
                );
            }
            dec.feed(&blob[at..]);
            assert!(dec.done(), "cut {cut}");
            assert_eq!(dec.sink.plain, plains, "cut {cut}");
            assert!(dec.sink.failed.is_empty());
        }
        // A cut inside the gap resumes at the next member, not inside the gap.
        let mut dec = decoder(&keys, &plains, &locs);
        let gap = (locs[0].off + locs[0].clen) as usize;
        dec.feed(&blob[10..gap + 500]);
        assert_eq!(dec.resume(), locs[1].off);
    }

    #[test]
    fn a_damaged_member_fails_alone() {
        let keys = keys();
        let (blob, plains, locs) = blob3(&keys);
        // In the first chunk of A, in the header of B, in the last byte of C.
        for (at, failed) in [
            (locs[0].off as usize + 100, 0),
            (locs[1].off as usize + 20, 1),
            (blob.len() - 1, 2),
        ] {
            let mut bad = blob.clone();
            bad[at] ^= 0x40;
            let mut dec = decoder(&keys, &plains, &locs);
            for part in bad[10..].chunks(10_000) {
                dec.feed(part);
            }
            assert!(dec.done());
            assert_eq!(dec.sink.failed.len(), 1, "damage at {at}");
            assert_eq!(dec.sink.failed[0].0, failed);
            assert!(dec.sink.failed[0].1.contains("corrupt"));
            let ok: Vec<usize> = (0..3).filter(|i| *i != failed).collect();
            assert_eq!(dec.sink.ended, ok);
            for i in ok {
                assert_eq!(dec.sink.plain[i], plains[i]);
            }
            // No plaintext of a chunk that did not verify.
            let got = dec.sink.plain.get(failed).map_or(0, Vec::len);
            assert_eq!(got % 65_536, 0);
            assert!(got < plains[failed].len());
        }
    }

    #[test]
    fn members_cannot_be_swapped_sliced_or_cut_short() {
        let keys = keys();
        let a = pattern(200_000, 1);
        let b = pattern(200_000, 2);
        let (stream_a, loc_a) = seal(&keys, &a, 0);
        let (stream_b, _) = seal(&keys, &b, 0);
        let run = |bytes: &[u8], size: u64| {
            let member = Member::whole(keys.data_opener(&loc_a).unwrap(), &loc_a, size);
            let mut dec = Decoder::new(vec![member], Collect::default());
            dec.feed(bytes);
            dec
        };
        // Another stream of the same length under A's entry: fails at the header.
        let dec = run(&stream_b, a.len() as u64);
        assert_eq!(dec.sink.failed.len(), 1);
        assert!(dec.sink.plain.is_empty());
        // B's chunks behind A's header: fails on the first chunk.
        let mut spliced = stream_a[..HEADER_LEN].to_vec();
        spliced.extend_from_slice(&stream_b[HEADER_LEN..]);
        let dec = run(&spliced, a.len() as u64);
        assert_eq!(dec.sink.failed.len(), 1);
        assert!(dec.sink.plain.is_empty());
        // A cut short at a chunk boundary: the decoder still waits for the rest — the final
        // chunk is decided by the entry's size, not by where the bytes end.
        let dec = run(&stream_a[..HEADER_LEN + 2 * 65_552], a.len() as u64);
        assert!(!dec.done());
        assert!(dec.sink.ended.is_empty());
        // An entry that claims a shorter file: its last chunk is not final in the stream.
        let dec = run(&stream_a, 2 * 65_536);
        assert_eq!(dec.sink.failed.len(), 1);
    }

    #[test]
    fn a_span_reads_only_its_chunks() {
        let keys = keys();
        let plain = pattern(300_000, 9);
        let (stream, mut loc) = seal(&keys, &plain, 0);
        loc.off = 1234;
        for range in [
            0..1u64,
            65_535..65_537,
            70_000..200_000,
            299_999..300_000,
            0..300_000,
        ] {
            let span = chunk_range(range.clone(), plain.len() as u64, CHUNK_LOG2).unwrap();
            let member = Member::span(keys.data_opener(&loc).unwrap(), &loc, 300_000, &span);
            assert_eq!(member.start, 1234 + span.cipher.start);
            let sink = RangeSink {
                skip: span.skip,
                left: range.end - range.start,
                out: Vec::new(),
                err: None,
            };
            let mut dec = Decoder::new(vec![member], sink);
            dec.feed(&stream[span.cipher.start as usize..span.cipher.end as usize]);
            assert!(dec.done() && dec.sink.err.is_none());
            assert_eq!(
                dec.sink.out,
                plain[range.start as usize..range.end as usize]
            );
        }
    }

    /// A download item for `rel` under `root` with nothing expected at the target.
    fn item(root: &Path, rel: &str, entry: &Entry) -> DownloadItem {
        DownloadItem {
            head: Head {
                path: rel.to_string(),
                stamp: crate::types::Stamp {
                    lamport: 1,
                    device: crate::types::DeviceId([1; 8]),
                    idx: 0,
                },
                entry: entry.clone(),
                origin: None,
                winner: true,
            },
            root: root.to_path_buf(),
            rel: rel.to_string(),
            expect_local: LocalExpect::Absent,
        }
    }

    fn file_entry(data: &[u8]) -> Entry {
        Entry {
            kind: EntryKind::File,
            size: data.len() as u64,
            mtime_ns: 1_700_000_000_000_000_000,
            exec: false,
            hash: *blake3::hash(data).as_bytes(),
            loc: None,
        }
    }

    /// A sink with one member of `data` and a target for each of `rels` under `root`.
    fn file_sink(
        root: &Path,
        data: &[u8],
        rels: &[String],
        cancel: &CancellationToken,
    ) -> FileSink {
        let entry = file_entry(data);
        let (_, loc) = seal(&keys(), b"x", 0);
        let mut targets = rels
            .iter()
            .enumerate()
            .map(|(i, rel)| Target::new(i, &item(root, rel, &entry)));
        let mut file = FileMember::new(loc, &entry, targets.next().unwrap());
        file.targets.extend(targets);
        FileSink {
            files: vec![file],
            batch: Batch::new(None),
            progress: Progress::hidden(),
            cancel: cancel.clone(),
        }
    }

    fn open_partials(sink: &FileSink) -> usize {
        let targets = sink.files.iter().flat_map(|f| &f.targets);
        targets.filter(|t| t.partial.is_some()).count()
    }

    /// Entries under `dir`, recursively, whose name marks a partial file.
    fn partial_files(dir: &Path) -> usize {
        let Ok(entries) = fs::read_dir(dir) else {
            return 0;
        };
        entries
            .map(|e| e.unwrap())
            .map(|e| match e.file_type().unwrap().is_dir() {
                true => partial_files(&e.path()),
                false => usize::from(e.file_name().to_string_lossy().starts_with(PARTIAL_PREFIX)),
            })
            .sum()
    }

    #[test]
    fn a_small_member_opens_no_file_before_it_is_verified_and_then_one_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let data = pattern(5000, 4);
        // More targets than a default macOS process may have files open (256).
        let rels: Vec<String> = (0..400).map(|i| format!("d{}/f{i:03}", i % 7)).collect();
        let mut sink = file_sink(dir.path(), &data, &rels, &CancellationToken::new());
        assert!(sink.files[0].buffer.is_some());
        for piece in data.chunks(1500) {
            sink.data(0, piece).unwrap();
            assert_eq!(open_partials(&sink), 0);
        }
        assert_eq!(partial_files(dir.path()), 0, "nothing on disk yet");
        sink.end(0).unwrap();
        assert_eq!(open_partials(&sink), 0);
        assert!(sink.files[0].buffer.is_none(), "the buffer is released");
        let mut results = sink.batch.finish();
        results.sort_by_key(|(i, _)| *i);
        assert_eq!(results.len(), rels.len());
        for ((i, result), rel) in results.iter().zip(&rels) {
            let done = result.as_ref().unwrap_or_else(|e| panic!("{rel}: {e}"));
            assert_eq!((&rels[*i], &done.rel), (rel, rel));
            assert_eq!(fs::read(dir.path().join(rel)).unwrap(), data);
        }
        assert_eq!(partial_files(dir.path()), 0);
    }

    #[test]
    fn a_large_member_streams_into_one_file_and_is_copied_from_it() {
        let dir = tempfile::tempdir().unwrap();
        let data = pattern(MEMBER_BUFFER_MAX as usize + 70_001, 5);
        // The first target cannot be created: the next one takes the stream.
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), dir.path().join("link")).unwrap();
        let mut rels = vec!["link/unsafe".to_string()];
        rels.extend((0..12).map(|i| format!("d{}/f{i:02}", i % 3)));
        let mut sink = file_sink(dir.path(), &data, &rels, &CancellationToken::new());
        assert!(sink.files[0].buffer.is_none());
        for piece in data.chunks(1 << CHUNK_LOG2) {
            sink.data(0, piece).unwrap();
            assert_eq!(
                open_partials(&sink),
                1,
                "one partial file, whatever the targets"
            );
        }
        assert_eq!(sink.files[0].primary, Some(1));
        assert_eq!(partial_files(dir.path()), 1);
        sink.end(0).unwrap();
        assert_eq!(open_partials(&sink), 0);
        let mut results = sink.batch.finish();
        results.sort_by_key(|(i, _)| *i);
        assert_eq!(results.len(), rels.len());
        assert!(matches!(results[0].1, Err(TransferError::UnsafeTarget(_))));
        for (i, result) in &results[1..] {
            result
                .as_ref()
                .unwrap_or_else(|e| panic!("{}: {e}", rels[*i]));
            assert_eq!(fs::read(dir.path().join(&rels[*i])).unwrap(), data);
        }
        assert_eq!(partial_files(dir.path()), 0);
        assert!(!dir.path().join("elsewhere").exists());
    }

    #[test]
    fn a_copy_is_verified_and_a_failed_write_fails_the_member() {
        let dir = tempfile::tempdir().unwrap();
        let data = pattern(MEMBER_BUFFER_MAX as usize + 10, 6);
        let rels: Vec<String> = (0..3).map(|i| format!("f{i}")).collect();
        let cancel = CancellationToken::new();

        // The partial file is changed behind the sink's back after it was verified: the copies
        // notice (and the file itself, hashed while it arrived, is finished as it was meant).
        let mut sink = file_sink(dir.path(), &data, &rels, &cancel);
        sink.data(0, &data).unwrap();
        {
            use std::os::unix::fs::FileExt;
            let partial = sink.files[0].targets[0].partial.as_ref().unwrap();
            partial.file.write_all_at(b"tampered", 100).unwrap();
        }
        sink.end(0).unwrap();
        let mut results = sink.batch.finish();
        results.sort_by_key(|(i, _)| *i);
        assert!(results[0].1.is_ok());
        for (_, result) in &results[1..] {
            assert!(matches!(result, Err(TransferError::Verify(_))));
        }
        assert!(!dir.path().join("f1").exists() && !dir.path().join("f2").exists());
        assert_eq!(partial_files(dir.path()), 0);

        // A member that does not verify reaches no target and leaves no file.
        let dir = tempfile::tempdir().unwrap();
        for len in [5000, MEMBER_BUFFER_MAX as usize + 10] {
            let mut sink = file_sink(dir.path(), &data[..len], &rels, &cancel);
            sink.files[0].hash[0] ^= 1;
            sink.data(0, &data[..len]).unwrap();
            let err = sink.end(0).unwrap_err();
            sink.fail(0, err);
            assert_eq!(open_partials(&sink), 0);
            let results = sink.batch.finish();
            assert_eq!(results.len(), rels.len());
            for (_, result) in &results {
                assert!(matches!(result, Err(TransferError::Verify(_))));
            }
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0, "len {len}");
        }
    }

    #[test]
    fn a_cancellation_is_seen_between_the_targets_of_one_member() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let rels: Vec<String> = (0..5).map(|i| format!("f{i}")).collect();

        // Small: nothing was opened yet, nothing is.
        let dir = tempfile::tempdir().unwrap();
        let data = pattern(5000, 7);
        let mut sink = file_sink(dir.path(), &data, &rels, &cancel);
        sink.data(0, &data).unwrap();
        sink.end(0).unwrap();
        let results = sink.batch.finish();
        assert_eq!(results.len(), rels.len());
        for (_, result) in &results {
            assert!(matches!(result, Err(TransferError::Cancelled)));
        }
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);

        // Large: the file that is complete is finished, no copy is started.
        let dir = tempfile::tempdir().unwrap();
        let data = pattern(MEMBER_BUFFER_MAX as usize + 1, 8);
        let mut sink = file_sink(dir.path(), &data, &rels, &cancel);
        sink.data(0, &data).unwrap();
        sink.end(0).unwrap();
        let mut results = sink.batch.finish();
        results.sort_by_key(|(i, _)| *i);
        assert!(results[0].1.is_ok());
        for (_, result) in &results[1..] {
            assert!(matches!(result, Err(TransferError::Cancelled)));
        }
        assert_eq!(fs::read(dir.path().join("f0")).unwrap(), data);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    /// What a barrier was asked to make durable, and what the tree looked like then.
    #[derive(Debug)]
    struct Barrier {
        paths: Vec<PathBuf>,
        partials: usize,
        files: usize,
    }

    /// Regular files under `dir` that are not partial files.
    fn finished_files(dir: &Path) -> usize {
        let Ok(entries) = fs::read_dir(dir) else {
            return 0;
        };
        entries
            .map(|e| e.unwrap())
            .map(|e| match e.file_type().unwrap().is_dir() {
                true => finished_files(&e.path()),
                false => usize::from(!e.file_name().to_string_lossy().starts_with(PARTIAL_PREFIX)),
            })
            .sum()
    }

    /// Records every barrier under `root`; the `fail`-th one (counted from 1) is refused.
    fn watch(
        root: &Path,
        fail: Option<usize>,
    ) -> (
        durable::hook::Guard,
        std::sync::Arc<std::sync::Mutex<Vec<Barrier>>>,
    ) {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (log, dir) = (seen.clone(), root.to_path_buf());
        let guard = durable::hook::observe(root, move |paths| {
            let mut log = log.lock().unwrap();
            log.push(Barrier {
                paths: paths.iter().map(|p| p.to_path_buf()).collect(),
                partials: partial_files(&dir),
                files: finished_files(&dir),
            });
            match fail == Some(log.len()) {
                true => Err(io::Error::other("the drive said no")),
                false => Ok(()),
            }
        });
        (guard, seen)
    }

    fn is_partial(path: &Path) -> bool {
        let name = path.file_name().unwrap().to_string_lossy();
        name.starts_with(PARTIAL_PREFIX)
    }

    #[test]
    fn nothing_is_reported_before_the_content_and_the_renames_are_durable() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let (_guard, seen) = watch(&root, None);
        let data = pattern(5000, 11);
        let rels: Vec<String> = ["a/b/f0", "a/f1", "f2"].map(String::from).to_vec();
        let mut sink = file_sink(&root, &data, &rels, &CancellationToken::new());
        sink.data(0, &data).unwrap();
        sink.end(0).unwrap();

        // Written and complete — and not renamed, not flushed, not reported.
        assert_eq!(open_partials(&sink), 0);
        assert_eq!(sink.batch.waiting(), 3);
        assert_eq!((partial_files(&root), finished_files(&root)), (3, 0));
        assert!(seen.lock().unwrap().is_empty());
        assert!(sink.batch.released.is_empty());

        let results = sink.batch.finish();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|(_, r)| r.is_ok()));
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.len(),
            2,
            "one barrier for the content, one for the renames"
        );

        // The content barrier names the three partial files, whole and with their final
        // attributes, while no target exists yet.
        let content = &seen[0];
        assert_eq!((content.partials, content.files), (3, 0));
        assert_eq!(content.paths.len(), 3);
        assert!(content.paths.iter().all(|p| is_partial(p)));
        // The rename barrier names every directory a rename happened in and its ancestors
        // up to the root; the partial files are gone, the targets are there.
        let renames = &seen[1];
        assert_eq!((renames.partials, renames.files), (0, 3));
        let dirs: BTreeSet<PathBuf> = renames.paths.iter().cloned().collect();
        let expect = [root.clone(), root.join("a"), root.join("a/b")];
        assert_eq!(dirs, expect.into_iter().collect());
        assert_eq!(renames.paths.len(), 3, "each directory once");
        for rel in &rels {
            let md = fs::metadata(root.join(rel)).unwrap();
            assert_eq!(fs::read(root.join(rel)).unwrap(), data);
            let mtime = filetime::FileTime::from_last_modification_time(&md);
            assert_eq!(mtime.unix_seconds(), 1_700_000_000);
        }
    }

    #[test]
    fn the_content_barrier_sees_the_finished_partial_files() {
        let dir = tempfile::tempdir().unwrap();
        let data = pattern(70_000, 12);
        let expect = data.clone();
        let _guard = durable::hook::observe(dir.path(), move |paths| {
            for path in paths.iter().filter(|p| is_partial(p)) {
                use std::os::unix::fs::PermissionsExt;
                let md = fs::metadata(path)?;
                assert_eq!(fs::read(path)?, expect);
                let mtime = filetime::FileTime::from_last_modification_time(&md);
                assert_eq!(mtime.unix_seconds(), 1_700_000_000);
                // The final mode, not the 0600 the partial file was created with.
                assert_eq!(md.permissions().mode() & 0o777, 0o644 & !umask());
            }
            Ok(())
        });
        let rels = vec!["x".to_string(), "y".to_string()];
        let mut sink = file_sink(dir.path(), &data, &rels, &CancellationToken::new());
        sink.data(0, &data).unwrap();
        sink.end(0).unwrap();
        let results = sink.batch.finish();
        assert!(results.iter().all(|(_, r)| r.is_ok()));
    }

    #[test]
    fn a_file_that_takes_over_an_unreadable_mode_is_flushed_like_any_other() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        fs::write(&locked, b"old").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let (_guard, seen) = watch(dir.path(), None);
        let data = pattern(3000, 15);
        let entry = file_entry(&data);
        let mut batch = Batch::new(None);
        for (i, rel) in ["locked", "plain"].into_iter().enumerate() {
            let mut item = item(dir.path(), rel, &entry);
            if let Ok(md) = fs::symlink_metadata(dir.path().join(rel)) {
                item.expect_local = LocalExpect::File(StatSig::from_metadata(&md));
            }
            let mut target = Target::new(i, &item);
            target.write(&data).unwrap();
            let (staged, file) = target.stage(entry.size).unwrap();
            batch.add(staged, file);
        }
        let results = batch.finish();
        assert!(results.iter().all(|(_, r)| r.is_ok()), "{results:?}");
        {
            // Nobody could open the mode-000 file, and nobody has to: it is synced through
            // the descriptor it was written with, and the content barrier names it.
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 2);
            assert_eq!(seen[0].paths.len(), 2);
            assert_eq!(seen[1].files, 2);
        }
        // The new version replaced the old one and kept its mode.
        let md = fs::symlink_metadata(&locked).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o000);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(&locked).unwrap(), data);
    }

    /// The access mode a descriptor was opened with.
    fn access_mode(file: &File) -> i32 {
        use std::os::fd::AsRawFd;
        // SAFETY: `F_GETFL` reads the flags of an open descriptor.
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) & libc::O_ACCMODE }
    }

    /// §17.16: a file is synced through the descriptor it was written with — never through one
    /// that was opened after the writes — and a file whose sync fails fails alone.
    #[test]
    fn every_file_is_synced_through_the_descriptor_it_was_written_with() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let synced = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = synced.clone();
        let refuse = std::sync::Arc::new(std::sync::Mutex::new(None::<u64>));
        let refused = refuse.clone();
        let _files = durable::hook::observe_files(dir.path(), move |path, file| {
            let (on_disk, open) = (fs::symlink_metadata(path)?, file.metadata()?);
            let partial = is_partial(path) && on_disk.ino() == open.ino();
            log.lock().unwrap().push((partial, access_mode(file)));
            // The second partial file that comes by is the one that cannot be written back.
            let mut refused = refused.lock().unwrap();
            let nth = log.lock().unwrap().iter().filter(|(p, _)| *p).count();
            if partial && nth == 2 && refused.is_none() {
                *refused = Some(open.ino());
                return Err(io::Error::other("write-back failed"));
            }
            Ok(())
        });
        let (_guard, seen) = watch(dir.path(), None);

        let data = pattern(4000, 21);
        let rels: Vec<String> = (0..5).map(|i| format!("f{i}")).collect();
        let mut sink = file_sink(dir.path(), &data, &rels, &CancellationToken::new());
        // Whatever the platform's number: here three files wait for one hand-over.
        sink.batch.max_open = 3;
        sink.data(0, &data).unwrap();
        sink.end(0).unwrap();
        // Five files: three were handed over together (one of them failed), two are open.
        assert_eq!((sink.batch.staged.len(), sink.batch.open.len()), (2, 2));
        assert_eq!(sink.batch.drives.len(), 1);
        assert_eq!(sink.batch.released.len(), 1);
        assert!(
            seen.lock().unwrap().is_empty(),
            "handing over is no barrier"
        );
        assert_eq!(partial_files(dir.path()), 4, "the failed file is removed");

        let results = sink.batch.finish();
        assert_eq!(results.len(), 5);
        let failed: Vec<&TransferError> = results
            .iter()
            .filter_map(|(_, r)| r.as_ref().err())
            .collect();
        assert_eq!(failed.len(), 1, "{results:?}");
        assert!(matches!(failed[0], TransferError::Io(e) if e.to_string() == "write-back failed"));
        assert_eq!(
            (partial_files(dir.path()), finished_files(dir.path())),
            (0, 4)
        );
        {
            // Each partial file went by exactly once, on a descriptor that is open for
            // writing; the directory of the renames is the one path that was opened to sync.
            let synced = synced.lock().unwrap();
            let files: Vec<&(bool, i32)> = synced.iter().filter(|(partial, _)| *partial).collect();
            assert_eq!(files.len(), 5);
            assert!(files.iter().all(|(_, mode)| *mode == libc::O_RDWR));
            assert_eq!(synced.len(), 6);
            assert_eq!(synced[5], (false, libc::O_RDONLY));
            // The content barrier names the four files that are left.
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 2);
            assert_eq!((seen[0].paths.len(), seen[0].partials), (4, 4));
        }
    }

    /// §17.16: a staged file carries the mtime of the file it will be — years old, as a rule —
    /// and must not look abandoned to a scan of the tree for that; and should a partial file
    /// vanish all the same, its own file fails, not the batch.
    #[test]
    fn a_staged_file_is_not_swept_and_a_vanished_one_fails_alone() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let data = pattern(2000, 22);
        let rels: Vec<String> = (0..4).map(|i| format!("d/f{i}")).collect();
        let mut sink = file_sink(&root, &data, &rels, &CancellationToken::new());
        sink.data(0, &data).unwrap();
        sink.end(0).unwrap();
        assert_eq!(sink.batch.waiting(), 4);
        for entry in fs::read_dir(root.join("d")).unwrap() {
            let md = entry.unwrap().metadata().unwrap();
            let age = md.modified().unwrap().elapsed().unwrap();
            assert!(
                age > crate::consts::PARTIAL_STALE,
                "the entry's mtime: {age:?}"
            );
        }

        // What another gclone that syncs the same tree does while the batch is open.
        let filter = crate::sync::Filter::new(&[], &root).unwrap();
        let scan = crate::sync::scan(&root, &filter).unwrap();
        assert!(scan.entries.iter().all(|e| e.kind == EntryKind::Dir));
        assert_eq!(partial_files(&root), 4, "no staged file is swept");

        // One is removed by hand: the other three arrive.
        let victim = fs::read_dir(root.join("d"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        fs::remove_file(victim.path()).unwrap();
        let results = sink.batch.finish();
        assert_eq!(results.len(), 4);
        let lost: Vec<&TransferError> = results
            .iter()
            .filter_map(|(_, r)| r.as_ref().err())
            .collect();
        assert_eq!(lost.len(), 1, "{results:?}");
        assert!(
            matches!(lost[0], TransferError::Io(e) if e.kind() == io::ErrorKind::NotFound),
            "{:?}",
            lost[0]
        );
        assert_eq!((partial_files(&root), finished_files(&root)), (0, 3));
    }

    /// A directory that alone cannot be made durable fails the files in and below it.
    #[test]
    fn a_directory_that_cannot_be_synced_fails_the_files_below_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let bad = root.join("bad");
        let _files = durable::hook::observe_files(&root, move |path, _| match path == bad {
            true => Err(io::Error::other("this directory does not sync")),
            false => Ok(()),
        });
        let data = pattern(900, 23);
        let rels: Vec<String> = ["top", "good/a", "bad/b", "bad/deep/c"]
            .map(String::from)
            .to_vec();
        let mut sink = file_sink(&root, &data, &rels, &CancellationToken::new());
        sink.data(0, &data).unwrap();
        sink.end(0).unwrap();
        let mut results = sink.batch.finish();
        results.sort_by_key(|(idx, _)| *idx);
        let ok: Vec<bool> = results.iter().map(|(_, r)| r.is_ok()).collect();
        assert_eq!(ok, [true, true, false, false], "{results:?}");
        // All four are in place; two are not reported, and get no base row.
        assert_eq!(finished_files(&root), 4);
    }

    #[test]
    fn a_failed_barrier_fails_every_file_behind_it() {
        let data = pattern(5000, 13);
        let rels: Vec<String> = (0..4).map(|i| format!("d{}/f{i}", i % 2)).collect();
        let io_error = |r: &Result<Downloaded, TransferError>| match r {
            Err(TransferError::Io(e)) => e.to_string() == "the drive said no",
            _ => false,
        };

        // The content could not be made durable: nothing is renamed, nothing is left behind.
        let dir = tempfile::tempdir().unwrap();
        let (_guard, seen) = watch(dir.path(), Some(1));
        let mut sink = file_sink(dir.path(), &data, &rels, &CancellationToken::new());
        sink.data(0, &data).unwrap();
        sink.end(0).unwrap();
        let results = sink.batch.finish();
        assert_eq!(results.len(), rels.len());
        assert!(results.iter().all(|(_, r)| io_error(r)), "{results:?}");
        assert_eq!(seen.lock().unwrap().len(), 1, "no second barrier");
        assert_eq!(
            (partial_files(dir.path()), finished_files(dir.path())),
            (0, 0)
        );

        // The renames could not be made durable: the files are in place, and not one of them
        // is reported as downloaded — no base row may be written for them.
        let dir = tempfile::tempdir().unwrap();
        let (_guard, seen) = watch(dir.path(), Some(2));
        let mut sink = file_sink(dir.path(), &data, &rels, &CancellationToken::new());
        sink.data(0, &data).unwrap();
        sink.end(0).unwrap();
        let results = sink.batch.finish();
        assert_eq!(results.len(), rels.len());
        assert!(results.iter().all(|(_, r)| io_error(r)), "{results:?}");
        assert_eq!(seen.lock().unwrap().len(), 2);
        assert_eq!(
            (partial_files(dir.path()), finished_files(dir.path())),
            (0, 4)
        );
    }

    #[test]
    fn a_batch_is_closed_by_count_and_by_bytes() {
        // Count: the batch closes itself when it is full; the rest waits for `finish`.
        let dir = tempfile::tempdir().unwrap();
        let (_guard, seen) = watch(dir.path(), None);
        let data = pattern(100, 14);
        let rels: Vec<String> = (0..DOWNLOAD_BATCH_FILES + 3)
            .map(|i| format!("d{}/f{i:04}", i % 5))
            .collect();
        let mut sink = file_sink(dir.path(), &data, &rels, &CancellationToken::new());
        // However slow this machine is: only the count closes this batch.
        sink.batch.max_age = Duration::MAX;
        sink.data(0, &data).unwrap();
        sink.end(0).unwrap();
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 2, "one full batch: content, then renames");
            assert_eq!(seen[0].paths.len(), DOWNLOAD_BATCH_FILES);
            assert_eq!(seen[0].files, 0);
            assert_eq!(seen[1].files, DOWNLOAD_BATCH_FILES);
            // The three files of the next batch are written and wait.
            assert_eq!(partial_files(dir.path()), 3);
        }
        assert_eq!(sink.batch.released.len(), DOWNLOAD_BATCH_FILES);
        assert_eq!(sink.batch.waiting(), 3);
        let results = sink.batch.finish();
        assert_eq!(results.len(), rels.len());
        assert!(results.iter().all(|(_, r)| r.is_ok()));
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 4);
            assert_eq!(seen[2].paths.len(), 3);
            assert_eq!(seen[3].files, rels.len());
        }

        // Bytes: two files that together reach the limit close the batch.
        let dir = tempfile::tempdir().unwrap();
        let (_guard, seen) = watch(dir.path(), None);
        let entry = file_entry(b"x");
        let mut batch = Batch::new(None);
        for (i, rel) in ["one", "two", "three"].into_iter().enumerate() {
            let mut target = Target::new(i, &item(dir.path(), rel, &entry));
            target.write(b"x").unwrap();
            let (staged, file) = target.stage(DOWNLOAD_BATCH_BYTES / 2).unwrap();
            batch.add(staged, file);
            let barriers = seen.lock().unwrap().len();
            assert_eq!(barriers, [0, 2, 2][i], "after {rel}");
        }
        assert_eq!(batch.finish().len(), 3);
        assert_eq!(seen.lock().unwrap().len(), 4);

        // Age: a file that arrives when the batch is old enough closes it — here at once.
        let dir = tempfile::tempdir().unwrap();
        let (_guard, seen) = watch(dir.path(), None);
        let mut batch = Batch::new(None);
        batch.max_age = Duration::ZERO;
        for (i, rel) in ["one", "two", "three"].into_iter().enumerate() {
            let mut target = Target::new(i, &item(dir.path(), rel, &entry));
            target.write(b"x").unwrap();
            let (staged, file) = target.stage(1).unwrap();
            batch.add(staged, file);
            let barriers = seen.lock().unwrap().len();
            assert_eq!(barriers, [0, 2, 2][i], "after {rel}");
        }
        assert_eq!(batch.waiting(), 1);
        assert_eq!(batch.finish().len(), 3);

        // Open descriptors: a batch never holds more than `max_open` written files open,
        // and handing them over ends neither the batch nor anything a barrier is for.
        let dir = tempfile::tempdir().unwrap();
        let (_guard, seen) = watch(dir.path(), None);
        let mut batch = Batch::new(None);
        (batch.max_open, batch.max_age) = (4, Duration::MAX);
        for i in 0..10 {
            let mut target = Target::new(i, &item(dir.path(), &format!("f{i}"), &entry));
            target.write(b"x").unwrap();
            let (staged, file) = target.stage(1).unwrap();
            batch.add(staged, file);
            assert_eq!(batch.open.len(), (i + 1) % 4, "after file {i}");
            assert_eq!(batch.waiting(), i + 1);
        }
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(batch.drives.len(), 1);
        assert_eq!(batch.finish().len(), 10);
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn empty_files_wait_for_their_barriers_too() {
        let dir = tempfile::tempdir().unwrap();
        let (_guard, seen) = watch(dir.path(), None);
        let empty = file_entry(b"");
        let items = |names: &[&str]| -> Vec<DownloadItem> {
            let items = names.iter().map(|rel| item(dir.path(), rel, &empty));
            items.collect()
        };

        let live = CancellationToken::new();
        let done = materialize_empties(items(&["a", "sub/b", "sub/c"]), &live).await;
        assert_eq!(done.len(), 3);
        for (item, result) in &done {
            let done = result
                .as_ref()
                .unwrap_or_else(|e| panic!("{}: {e}", item.rel));
            assert_eq!((done.rel.as_str(), done.sig.size), (item.rel.as_str(), 0));
            assert_eq!(fs::read(dir.path().join(&item.rel)).unwrap(), b"");
        }
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 2);
            assert_eq!((seen[0].paths.len(), seen[0].files), (3, 0));
            assert_eq!((seen[1].partials, seen[1].files), (0, 3));
        }

        // One file alone goes the same way.
        materialize_empty(&item(dir.path(), "single", &empty))
            .await
            .unwrap();
        assert_eq!(seen.lock().unwrap().len(), 4);

        // An entry with content is refused; a cancelled run writes nothing and flushes nothing.
        let full = item(dir.path(), "full", &file_entry(b"content"));
        let refused = materialize_empty(&full).await.unwrap_err();
        assert!(matches!(refused, TransferError::Verify(_)));
        let cancel = CancellationToken::new();
        cancel.cancel();
        for (_, result) in materialize_empties(items(&["late", "later"]), &cancel).await {
            assert!(matches!(result, Err(TransferError::Cancelled)));
        }
        assert_eq!(seen.lock().unwrap().len(), 4);
        assert_eq!(finished_files(dir.path()), 4);

        // A refused barrier: the files are not reported.
        let other = tempfile::tempdir().unwrap();
        let (_guard, _) = watch(other.path(), Some(2));
        let items: Vec<DownloadItem> = ["p", "q"]
            .iter()
            .map(|rel| item(other.path(), rel, &empty))
            .collect();
        for (_, result) in materialize_empties(items, &CancellationToken::new()).await {
            assert!(matches!(result, Err(TransferError::Io(_))));
        }
    }

    #[test]
    fn retry_pauses_double_and_stay_bounded() {
        let pauses: Vec<u64> = (1..=DOWNLOAD_RETRIES)
            .map(|n| retry_pause(n).as_millis() as u64)
            .collect();
        assert_eq!(pauses, [250, 500, 1000, 2000, 4000]);
        assert_eq!(retry_pause(40), retry_pause(6));
    }

    #[test]
    fn move_aside_never_replaces_and_counts_up() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("notes.txt");
        let now = 1_794_000_000_000;
        let mut names = Vec::new();
        for round in 0..3 {
            fs::write(&target, format!("version {round}")).unwrap();
            let aside = move_aside(&target, now).unwrap();
            assert!(!target.exists());
            assert_eq!(
                fs::read_to_string(&aside).unwrap(),
                format!("version {round}")
            );
            names.push(aside.file_name().unwrap().to_str().unwrap().to_string());
        }
        let stamp = util::format_utc_compact(now);
        assert_eq!(
            names,
            [
                format!("notes.conflict-local-{stamp}.txt"),
                format!("notes.conflict-local-{stamp}-2.txt"),
                format!("notes.conflict-local-{stamp}-3.txt"),
            ]
        );
    }

    #[test]
    fn the_umask_is_read_without_changing_it() {
        let first = umask();
        // SAFETY: as in `umask()`.
        let now = unsafe {
            let mask = libc::umask(0o077);
            libc::umask(mask);
            mask
        };
        // `mode_t` is 16 bits wide on macOS and is `u32` itself on Linux.
        #[allow(clippy::useless_conversion)]
        let now = u32::from(now);
        assert_eq!(first, now);
        assert_eq!(first, umask());
    }
}

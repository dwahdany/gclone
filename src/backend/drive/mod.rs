//! Google Drive backend (SPEC §6.2–§6.5, §9.6) — owned by WP3.
//!
//! `api.rs` / `upload.rs` are private to this module (request builders, multipart body,
//! resumable state machine, wire structs of §6.4.1).

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;

use super::{
    Backend, ByteStream, Handle, ObjMeta, PutBody, Quota, bad_request, check_small,
    not_downloadable,
};
use crate::auth::TokenProvider;
use crate::auth::login::describe;
use crate::consts::{HTTP_CONNECT_TIMEOUT, HTTP_READ_TIMEOUT};
use crate::error::BackendError;
use crate::util;

mod api;
pub mod errors;
pub mod pacer;
pub mod probe;
mod upload;

pub use errors::{HttpClass, classify, parse_range_header};
pub use pacer::{CallKind, Class, Pacer, PacerConfig, PacerStats};
pub use probe::{ProbeLine, ProbeOutcome, run_probes};

use api::Failure;

/// Drive fields read on every metadata call (§3.2).
pub const FIELDS: &str = "id,name,size,md5Checksum,createdTime,mimeType,trashed,parents";

/// Injectable for tests. Paths `/drive/v3/...` are appended.
#[derive(Clone, Debug)]
pub struct DriveEndpoints {
    pub api: String,
    pub upload: String,
}

impl Default for DriveEndpoints {
    fn default() -> Self {
        DriveEndpoints {
            api: "https://www.googleapis.com".to_string(),
            upload: "https://www.googleapis.com/upload".to_string(),
        }
    }
}

pub struct DriveConfig {
    pub endpoints: DriveEndpoints,
    pub transfers: usize,
    pub pacer: PacerConfig,
    pub user_agent: String,
    /// `HTTP_READ_TIMEOUT` (§6.1, §6.4). Injectable for tests, which cannot wait a minute for a
    /// stalled peer.
    pub read_timeout: Duration,
}

impl Default for DriveConfig {
    fn default() -> Self {
        DriveConfig {
            endpoints: DriveEndpoints::default(),
            transfers: crate::consts::TRANSFERS_DEFAULT,
            pacer: PacerConfig::default(),
            user_agent: concat!("gclone/", env!("CARGO_PKG_VERSION")).to_string(),
            read_timeout: HTTP_READ_TIMEOUT,
        }
    }
}

/// What is known about the id of My Drive's root folder (Drive reports it, not `root`, as the
/// parent of top-level objects).
#[derive(Clone)]
enum Root {
    Unknown,
    Known(String),
    /// This login cannot read the root folder; no parent is ever taken for it.
    Unavailable,
}

struct Inner {
    /// Metadata calls: HTTP/2 via ALPN.
    api: reqwest::Client,
    /// `alt=media` downloads: HTTP/1.1, read timeout, no total timeout.
    transfer: reqwest::Client,
    /// Uploads: HTTP/1.1 and **no** read timeout — reqwest's is one deadline for connecting,
    /// sending the whole request body and receiving the answer's headers, however steadily the
    /// body flows. Every request has a total timeout instead (`read_timeout` unless
    /// `upload_request` raises it for a body) and bodies are watched for stalls (§6.4).
    upload: reqwest::Client,
    /// `HTTP_READ_TIMEOUT` unless a test shortened it.
    read_timeout: Duration,
    tokens: Arc<TokenProvider>,
    pacer: Pacer,
    ep: DriveEndpoints,
    /// Pre-generated ids not handed out yet.
    id_pool: Mutex<Vec<String>>,
    /// `generateIds` refused `count = 100` once (probe 10).
    small_id_batches: AtomicBool,
    /// Server clock minus local clock, from the most recent `Date` header.
    clock_offset_ms: AtomicI64,
    root: Mutex<Root>,
}

/// api client (h2), transfer and upload clients (h1), all with redirect `Policy::none()`;
/// tokens, pacer, id pool, clock offset.
#[derive(Clone)]
pub struct DriveBackend {
    inner: Arc<Inner>,
}

impl DriveBackend {
    pub fn new(
        tokens: std::sync::Arc<TokenProvider>,
        cfg: DriveConfig,
    ) -> Result<Self, BackendError> {
        // Every client: no redirects. `308 Resume Incomplete` is a status of the upload protocol
        // and must reach the state machine untouched (§6.4).
        let builder = || {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(HTTP_CONNECT_TIMEOUT)
                .user_agent(cfg.user_agent.clone())
        };
        let streams = |b: reqwest::ClientBuilder| {
            b.http1_only()
                .pool_max_idle_per_host(3 * cfg.transfers.max(1))
                .tcp_nodelay(true)
        };
        let failed = |e: reqwest::Error| {
            BackendError::Io(std::io::Error::other(format!(
                "cannot set up the HTTP client: {}",
                describe(&e)
            )))
        };
        let api = builder()
            .read_timeout(cfg.read_timeout)
            .build()
            .map_err(failed)?;
        let transfer = streams(builder())
            .read_timeout(cfg.read_timeout)
            .build()
            .map_err(failed)?;
        let upload = streams(builder())
            .timeout(cfg.read_timeout)
            .build()
            .map_err(failed)?;
        let trim = |s: &str| s.trim_end_matches('/').to_string();
        Ok(DriveBackend {
            inner: Arc::new(Inner {
                api,
                transfer,
                upload,
                read_timeout: cfg.read_timeout,
                tokens,
                pacer: Pacer::new(cfg.pacer),
                ep: DriveEndpoints {
                    api: trim(&cfg.endpoints.api),
                    upload: trim(&cfg.endpoints.upload),
                },
                id_pool: Mutex::new(Vec::new()),
                small_id_batches: AtomicBool::new(false),
                clock_offset_ms: AtomicI64::new(0),
                root: Mutex::new(Root::Unknown),
            }),
        })
    }

    pub fn pacer(&self) -> &Pacer {
        &self.inner.pacer
    }
}

/// The top level has no id of its own to act on.
fn refuse_top(h: &Handle, what: &str) -> Result<(), BackendError> {
    if h.is_top() {
        return Err(bad_request(format!("the top level cannot be {what}")));
    }
    Ok(())
}

/// Cuts `[start, end)` out of a whole-object stream — for a server that ignored `Range`.
fn cut(
    stream: impl futures_util::Stream<Item = Result<Bytes, BackendError>> + Send + 'static,
    start: u64,
    end: u64,
) -> ByteStream {
    let mut pos = 0u64;
    Box::pin(stream.filter_map(move |item| {
        let out = match item {
            Err(e) => Some(Err(e)),
            Ok(chunk) => {
                let lo = pos;
                pos += chunk.len() as u64;
                let (a, b) = (start.max(lo), end.min(pos));
                (a < b).then(|| Ok(chunk.slice((a - lo) as usize..(b - lo) as usize)))
            }
        };
        std::future::ready(out)
    }))
}

/// §6.2–6.5; wire shapes §6.4.1.
impl Backend for DriveBackend {
    async fn new_ids(&self, n: usize) -> Result<Vec<Handle>, BackendError> {
        let inner = &self.inner;
        loop {
            {
                let mut pool = inner.id_pool.lock().unwrap_or_else(|e| e.into_inner());
                if pool.len() >= n {
                    let at = pool.len() - n;
                    return Ok(pool.split_off(at).into_iter().map(Handle).collect());
                }
            }
            let fresh = inner.generate_ids().await?;
            if fresh.is_empty() {
                return Err(BackendError::Transient(
                    "Drive generated no object ids".to_string(),
                ));
            }
            inner
                .id_pool
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(fresh);
        }
    }

    async fn create_folder(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
    ) -> Result<(), BackendError> {
        refuse_top(id, "created")?;
        self.inner.create_folder(id, parent, name).await
    }

    async fn put(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
        body: PutBody,
    ) -> Result<ObjMeta, BackendError> {
        refuse_top(id, "written")?;
        match body {
            PutBody::Small(data) => {
                check_small(data.len())?;
                self.inner.put_small(id, parent, name, data).await
            }
            // An empty resumable upload has no byte range to send.
            PutBody::Stream { total: 0, .. } => {
                self.inner.put_small(id, parent, name, Bytes::new()).await
            }
            PutBody::Stream { total, parts } => {
                self.inner.put_stream(id, parent, name, total, parts).await
            }
        }
    }

    async fn get(
        &self,
        h: &Handle,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<ByteStream, BackendError> {
        if h.is_top() {
            return Err(not_downloadable());
        }
        let inner = &self.inner;
        let empty = || -> ByteStream { Box::pin(futures_util::stream::empty()) };
        if let Some(r) = &range
            && r.start >= r.end
        {
            // Nothing to fetch — but an absent object is NotFound all the same.
            return match inner.stat_file(&h.0).await? {
                Some(_) => Ok(empty()),
                None => Err(BackendError::NotFound),
            };
        }
        let range_header = range.as_ref().map(|r| match r.end {
            u64::MAX => format!("bytes={}-", r.start),
            end => format!("bytes={}-{}", r.start, end - 1),
        });
        let url = inner.file_url(&h.0);
        let mut acknowledge_abuse = false;
        let reply = loop {
            let asked = inner
                .call_streaming(CallKind::Download, || {
                    let mut request = inner.transfer.get(&url).query(&[("alt", "media")]);
                    if acknowledge_abuse {
                        request = request.query(&[("acknowledgeAbuse", "true")]);
                    }
                    if let Some(value) = &range_header {
                        request = request.header(reqwest::header::RANGE, value);
                    }
                    request
                })
                .await;
            match asked {
                Ok(reply) => break reply,
                // §6.3: flagged content is fetched once more, acknowledging the flag.
                Err(Failure::Abuse) if !acknowledge_abuse => acknowledge_abuse = true,
                // The range starts at or past the end: clamped to nothing.
                Err(Failure::Other(BackendError::Fatal { status: 416, .. })) if range.is_some() => {
                    return Ok(empty());
                }
                Err(f) => return Err(f.into_error()),
            }
        };
        let Some(response) = reply.stream else {
            return Ok(empty());
        };
        let stream = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(|e| BackendError::Transient(describe(&e.without_url()))));
        Ok(match range {
            Some(r) if reply.status == 200 => cut(stream, r.start, r.end),
            _ => Box::pin(stream),
        })
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

    async fn list_trashed(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        self.inner.list_trashed(parent).await
    }

    async fn find_by_name(&self, name: &str) -> Result<Vec<ObjMeta>, BackendError> {
        self.inner.find_by_name(name).await
    }

    async fn trash(&self, h: &Handle) -> Result<(), BackendError> {
        refuse_top(h, "trashed")?;
        self.inner.set_trashed(h, true).await
    }

    async fn untrash(&self, h: &Handle) -> Result<(), BackendError> {
        refuse_top(h, "restored")?;
        self.inner.set_trashed(h, false).await
    }

    async fn delete(&self, h: &Handle) -> Result<(), BackendError> {
        refuse_top(h, "deleted")?;
        self.inner.delete(h).await
    }

    async fn about(&self) -> Result<Quota, BackendError> {
        self.inner.about().await
    }

    fn now_ms(&self) -> u64 {
        let offset = self.inner.clock_offset_ms.load(Ordering::Relaxed);
        util::now_ms().saturating_add_signed(offset)
    }

    fn clock_offset_ms(&self) -> i64 {
        self.inner.clock_offset_ms.load(Ordering::Relaxed)
    }
}

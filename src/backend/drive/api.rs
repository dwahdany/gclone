//! Drive v3 request builders and wire structs (SPEC §6.4, §6.4.1) — owned by WP3.
//! Private to `backend::drive`.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use reqwest::header::{DATE, HeaderMap, RETRY_AFTER};
use serde::Deserialize;

use super::errors::{HttpClass, classify};
use super::pacer::{CallKind, Class};
use super::upload::Watch;
use super::{FIELDS, Inner, Root};
use crate::auth::login::describe;
use crate::backend::{Handle, ObjMeta, Quota};
use crate::consts::{ID_POOL_BATCH, ID_POOL_BATCH_FALLBACK};
use crate::error::{AuthError, BackendError, QuotaKind};
use crate::util;

pub(super) const FOLDER_MIME: &str = "application/vnd.google-apps.folder";
pub(super) const BLOB_MIME: &str = "application/octet-stream";
const LIST_FIELDS: &str =
    "nextPageToken,files(id,name,size,md5Checksum,createdTime,mimeType,trashed,parents)";
/// Largest error body read for classification.
const ERROR_BODY_MAX: usize = 64 * 1024;
/// A listing whose page token is rejected starts over this often before giving up.
const LIST_RESTARTS: u32 = 3;

// ---------------------------------------------------------------------------------------------
// Wire structs (§6.4.1)
// ---------------------------------------------------------------------------------------------

/// int64 values are JSON strings on the wire; a JSON number is accepted too.
fn u64_text<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Number {
        Text(String),
        Plain(u64),
    }
    Ok(match Option::<Number>::deserialize(d)? {
        None => None,
        Some(Number::Plain(n)) => Some(n),
        Some(Number::Text(s)) => Some(s.trim().parse().map_err(serde::de::Error::custom)?),
    })
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct File {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub parents: Option<Vec<String>>,
    #[serde(default, deserialize_with = "u64_text")]
    pub size: Option<u64>,
    #[serde(default)]
    pub md5_checksum: Option<String>,
    #[serde(default)]
    pub created_time: Option<String>,
    #[serde(default)]
    pub trashed: Option<bool>,
}

impl File {
    pub fn is_folder(&self) -> bool {
        self.mime_type.as_deref() == Some(FOLDER_MIME)
    }

    pub fn parent_id(&self) -> Option<&str> {
        self.parents.as_ref()?.first().map(String::as_str)
    }

    fn md5(&self) -> Option<[u8; 16]> {
        let hex = self.md5_checksum.as_ref()?.to_ascii_lowercase();
        util::unhex(&hex)?.try_into().ok()
    }

    fn created_ms(&self) -> Option<u64> {
        util::parse_rfc3339_ms(self.created_time.as_deref()?)
    }

    /// Whether a create answer carries everything `put` returns (it does not when Drive
    /// answered in its default projection, §6.2).
    pub fn is_complete_blob(&self) -> bool {
        self.name.is_some()
            && self.size.is_some()
            && self.md5().is_some()
            && self.created_ms().is_some()
    }

    /// Decoding rules of §6.4.1: a folder has size 0 and no md5.
    pub fn into_meta(self, parent: Handle) -> ObjMeta {
        let is_folder = self.is_folder();
        ObjMeta {
            size: if is_folder { 0 } else { self.size.unwrap_or(0) },
            md5: if is_folder { None } else { self.md5() },
            created_ms: self.created_ms().unwrap_or(0),
            trashed: self.trashed.unwrap_or(false),
            handle: Handle(self.id),
            name: self.name.unwrap_or_default(),
            parent,
            is_folder,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileList {
    #[serde(default)]
    next_page_token: Option<String>,
    #[serde(default)]
    files: Vec<File>,
}

#[derive(Deserialize)]
struct GeneratedIds {
    #[serde(default)]
    ids: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct About {
    #[serde(default)]
    storage_quota: StorageQuota,
    #[serde(default)]
    user: Option<User>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StorageQuota {
    /// Absent = unlimited.
    #[serde(default, deserialize_with = "u64_text")]
    limit: Option<u64>,
    #[serde(default, deserialize_with = "u64_text")]
    usage: Option<u64>,
    #[serde(default, deserialize_with = "u64_text")]
    usage_in_drive_trash: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    #[serde(default)]
    email_address: Option<String>,
}

pub(super) fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, BackendError> {
    serde_json::from_slice(body).map_err(|e| {
        BackendError::Transient(format!("Drive sent an answer that cannot be decoded: {e}"))
    })
}

/// JSON metadata of a create: `parents` is omitted for the top level.
pub(super) fn metadata(id: &Handle, parent: &Handle, name: &str, mime: &str) -> serde_json::Value {
    let mut m = serde_json::json!({ "id": id.0, "name": name, "mimeType": mime });
    if !parent.is_top() {
        m["parents"] = serde_json::json!([parent.0]);
    }
    m
}

/// A value inside single quotes of a `q` expression.
fn q_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Ids are URL-safe as issued; anything else is escaped rather than trusted.
fn path_segment(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for b in id.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// One logical call: pacing, bearer token, classification, retries (§6.5)
// ---------------------------------------------------------------------------------------------

pub(super) struct Reply {
    pub status: u16,
    pub headers: HeaderMap,
    /// The whole body of a buffered call; empty for a streaming one.
    pub body: Bytes,
    /// The unread response of a streaming call.
    pub stream: Option<reqwest::Response>,
}

/// A request ready to go out — with the watch over its upload body, if it carries one
/// (`Inner::upload_request`). Every other request is just its `RequestBuilder`.
pub(super) struct Outgoing {
    pub(super) request: reqwest::RequestBuilder,
    pub(super) watch: Option<Arc<Watch>>,
}

impl From<reqwest::RequestBuilder> for Outgoing {
    fn from(request: reqwest::RequestBuilder) -> Self {
        Outgoing {
            request,
            watch: None,
        }
    }
}

impl Outgoing {
    /// Sends the request with `token` as its bearer token. `Err` is the transport failure in
    /// words: a reqwest error, or an upload body that stopped moving (§6.4).
    pub(super) async fn send(self, token: &str) -> Result<reqwest::Response, String> {
        let sending = self.request.bearer_auth(token).send();
        let sent = match self.watch {
            None => sending.await,
            Some(watch) => {
                watch.start();
                tokio::select! {
                    sent = sending => sent,
                    // Dropping the request closes its connection.
                    () = watch.stalled() => return Err(watch.complaint()),
                }
            }
        };
        sent.map_err(|e| describe(&e.without_url()))
    }
}

/// Answers the retry loop does not settle itself.
pub(super) enum Failure {
    NotFound,
    Conflict,
    Abuse,
    Other(BackendError),
}

impl Failure {
    /// For calls that address an existing object by id.
    pub fn into_error(self) -> BackendError {
        match self {
            Failure::NotFound => BackendError::NotFound,
            Failure::Conflict => fatal(409, "conflict", "Drive reported a conflict"),
            Failure::Abuse => fatal(
                403,
                "cannotDownloadAbusiveFile",
                "Drive flagged this object as malware or spam",
            ),
            Failure::Other(e) => e,
        }
    }

    /// For creates: `put` and `create_folder` never answer `NotFound` — a 404 there means the
    /// parent folder is gone.
    pub fn into_create_error(self) -> BackendError {
        match self {
            Failure::NotFound => fatal(404, "notFound", "the parent folder does not exist"),
            other => other.into_error(),
        }
    }
}

impl From<BackendError> for Failure {
    fn from(e: BackendError) -> Self {
        Failure::Other(e)
    }
}

pub(super) fn fatal(status: u16, reason: &str, message: &str) -> BackendError {
    BackendError::Fatal {
        status,
        reason: reason.to_string(),
        message: message.to_string(),
    }
}

/// The terminal rows of §6.5 that mean the same on every route.
pub(super) fn terminal(class: HttpClass) -> Option<BackendError> {
    Some(match class {
        HttpClass::StorageFull => BackendError::QuotaExceeded(QuotaKind::StorageFull),
        HttpClass::DailyUpload => BackendError::QuotaExceeded(QuotaKind::DailyUpload),
        HttpClass::DailyDownload => BackendError::QuotaExceeded(QuotaKind::DailyDownload),
        HttpClass::ProjectApiQuota => BackendError::QuotaExceeded(QuotaKind::ProjectApiQuota),
        HttpClass::AppNotAuthorized => BackendError::AppNotAuthorized,
        _ => return None,
    })
}

pub(super) async fn error_body(mut response: reqwest::Response) -> Vec<u8> {
    let mut body = Vec::new();
    // A body that cannot be read classifies like an empty one: by status.
    while let Ok(Some(chunk)) = response.chunk().await {
        let room = ERROR_BODY_MAX.saturating_sub(body.len());
        body.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if room <= chunk.len() {
            break;
        }
    }
    body
}

pub(super) fn header_text<'a>(
    headers: &'a HeaderMap,
    name: &reqwest::header::HeaderName,
) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

impl Inner {
    pub(super) fn files_url(&self) -> String {
        format!("{}/drive/v3/files", self.ep.api)
    }

    pub(super) fn file_url(&self, id: &str) -> String {
        format!("{}/drive/v3/files/{}", self.ep.api, path_segment(id))
    }

    pub(super) fn upload_url(&self) -> String {
        format!("{}/drive/v3/files", self.ep.upload)
    }

    /// `Backend::now_ms` = local clock + the offset of the most recent `Date` header.
    pub(super) fn note_date(&self, headers: &HeaderMap) {
        if let Some(server_ms) = header_text(headers, &DATE).and_then(util::parse_http_date_ms) {
            let offset = server_ms as i64 - util::now_ms() as i64;
            self.clock_offset_ms.store(offset, Ordering::Relaxed);
        }
    }

    pub(super) async fn token(&self) -> Result<String, BackendError> {
        Ok(self.tokens.access_token().await?)
    }

    /// A buffered call: the body of a 2xx answer is read inside the retry loop.
    pub(super) async fn call<R: Into<Outgoing>>(
        &self,
        kind: CallKind,
        build: impl Fn() -> R,
    ) -> Result<Reply, Failure> {
        self.run(kind, build, true).await
    }

    /// A call whose 2xx answer is handed back unread (`Reply::stream`).
    pub(super) async fn call_streaming<R: Into<Outgoing>>(
        &self,
        kind: CallKind,
        build: impl Fn() -> R,
    ) -> Result<Reply, Failure> {
        self.run(kind, build, false).await
    }

    async fn run<R: Into<Outgoing>>(
        &self,
        kind: CallKind,
        build: impl Fn() -> R,
        buffered: bool,
    ) -> Result<Reply, Failure> {
        let max = self.pacer.max_attempts();
        // Throttled and transient rounds so far; the request is sent at most `max` times.
        let mut failures = 0u32;
        let mut refreshed = false;
        loop {
            self.pacer.acquire(kind).await;
            let token = self.token().await?;
            let transient = match build().into().send(&token).await {
                Err(detail) => detail,
                Ok(response) => {
                    self.note_date(response.headers());
                    let status = response.status().as_u16();
                    let headers = response.headers().clone();
                    if (200..300).contains(&status) {
                        let (body, stream) = if buffered {
                            match response.bytes().await {
                                Ok(body) => (body, None),
                                Err(e) => {
                                    self.pause(&mut failures, max, describe(&e.without_url()))
                                        .await?;
                                    continue;
                                }
                            }
                        } else {
                            (Bytes::new(), Some(response))
                        };
                        self.pacer.on_success(kind);
                        return Ok(Reply {
                            status,
                            headers,
                            body,
                            stream,
                        });
                    }
                    let body = error_body(response).await;
                    match classify(status, header_text(&headers, &RETRY_AFTER), &body) {
                        HttpClass::Unauthorized => {
                            // One refresh, one more try; a second 401 is final.
                            if refreshed {
                                return Err(BackendError::Auth(AuthError::Expired).into());
                            }
                            refreshed = true;
                            self.tokens
                                .force_refresh()
                                .await
                                .map_err(BackendError::from)?;
                            continue;
                        }
                        HttpClass::Throttle { retry_after } => {
                            let sleep = self.pacer.on_throttle(kind, retry_after, failures);
                            if kind.throttle_class() == Class::Write
                                && self.pacer.write_breaker_tripped()
                            {
                                return Err(
                                    BackendError::QuotaExceeded(QuotaKind::DailyUpload).into()
                                );
                            }
                            failures += 1;
                            if failures >= max {
                                return Err(BackendError::RateLimited.into());
                            }
                            tokio::time::sleep(sleep).await;
                            continue;
                        }
                        HttpClass::Transient => format!("Drive answered {status}"),
                        HttpClass::NotFound => return Err(Failure::NotFound),
                        HttpClass::Conflict => return Err(Failure::Conflict),
                        HttpClass::AbuseFlag => return Err(Failure::Abuse),
                        HttpClass::Fatal {
                            status,
                            reason,
                            message,
                        } => {
                            return Err(BackendError::Fatal {
                                status,
                                reason,
                                message,
                            }
                            .into());
                        }
                        class => {
                            let e = terminal(class)
                                .unwrap_or_else(|| fatal(status, "", "unexpected answer"));
                            return Err(e.into());
                        }
                    }
                }
            };
            self.pause(&mut failures, max, transient).await?;
        }
    }

    /// Counts one transient failure and sleeps `BACKOFF(n)`; `Transient` once the attempts are
    /// used up.
    async fn pause(
        &self,
        failures: &mut u32,
        max: u32,
        detail: String,
    ) -> Result<(), BackendError> {
        *failures += 1;
        if *failures >= max {
            return Err(BackendError::Transient(detail));
        }
        tokio::time::sleep(self.pacer.backoff_for(*failures - 1)).await;
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // My Drive's root id: Drive reports it as the parent of top-level objects
    // -----------------------------------------------------------------------------------------

    pub(super) fn learn_root(&self, id: &str) {
        let mut root = self.root.lock().unwrap_or_else(|e| e.into_inner());
        if !matches!(*root, Root::Known(_)) {
            *root = Root::Known(id.to_string());
        }
    }

    fn known_root(&self) -> Root {
        self.root.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The parent handle of an object found by id or by name: `Handle::top()` when Drive names
    /// My Drive's root. The root id is asked for once, and only when a parent has to be judged.
    pub(super) async fn parent_of(&self, file: &File) -> Result<Handle, BackendError> {
        let Some(parent) = file.parent_id() else {
            return Ok(Handle::top());
        };
        let root = match self.known_root() {
            Root::Known(id) => Some(id),
            Root::Unavailable => None,
            Root::Unknown => {
                let url = self.file_url("root");
                let asked = self
                    .call(CallKind::Get, || {
                        self.api.get(&url).query(&[("fields", "id")])
                    })
                    .await;
                match asked {
                    Ok(reply) => {
                        let root: File = decode(&reply.body)?;
                        self.learn_root(&root.id);
                        Some(root.id)
                    }
                    // Not visible to this login: then no parent can be the root.
                    Err(Failure::NotFound | Failure::Other(BackendError::Fatal { .. })) => {
                        *self.root.lock().unwrap_or_else(|e| e.into_inner()) = Root::Unavailable;
                        None
                    }
                    Err(f) => return Err(f.into_error()),
                }
            }
        };
        Ok(if root.as_deref() == Some(parent) {
            Handle::top()
        } else {
            Handle(parent.to_string())
        })
    }

    /// The meta of a create answer for an object that was sent with `parent`.
    pub(super) async fn created_meta(
        &self,
        file: File,
        parent: &Handle,
    ) -> Result<ObjMeta, BackendError> {
        let reported = file.parent_id();
        let parent = if parent.is_top() {
            if let Some(root) = reported {
                self.learn_root(root);
            }
            Handle::top()
        } else if reported == Some(parent.0.as_str()) {
            parent.clone()
        } else {
            self.parent_of(&file).await?
        };
        Ok(file.into_meta(parent))
    }

    /// `stat` by id for an upload: `parent` is where the caller put (or expected) the object, so
    /// a matching answer needs no look at the root id.
    pub(super) async fn stat_expecting(
        &self,
        id: &Handle,
        parent: &Handle,
    ) -> Result<Option<ObjMeta>, BackendError> {
        let Some(file) = self.stat_file(&id.0).await? else {
            return Ok(None);
        };
        let parent = if !parent.is_top() && file.parent_id() == Some(parent.0.as_str()) {
            parent.clone()
        } else {
            self.parent_of(&file).await?
        };
        Ok(Some(file.into_meta(parent)))
    }

    // -----------------------------------------------------------------------------------------
    // Metadata calls (§6.4)
    // -----------------------------------------------------------------------------------------

    /// `count = 100`; on `400` the pool falls back to 10 for good (probe 10).
    pub(super) async fn generate_ids(&self) -> Result<Vec<String>, BackendError> {
        let url = format!("{}/generateIds", self.files_url());
        loop {
            let small = self.small_id_batches.load(Ordering::Relaxed);
            let count = if small {
                ID_POOL_BATCH_FALLBACK
            } else {
                ID_POOL_BATCH
            }
            .to_string();
            let asked = self
                .call(CallKind::GenerateIds, || {
                    self.api.get(&url).query(&[
                        ("count", count.as_str()),
                        ("space", "drive"),
                        ("type", "files"),
                    ])
                })
                .await;
            match asked {
                Ok(reply) => return Ok(decode::<GeneratedIds>(&reply.body)?.ids),
                Err(Failure::Other(BackendError::Fatal { status: 400, .. })) if !small => {
                    self.small_id_batches.store(true, Ordering::Relaxed);
                }
                Err(f) => return Err(f.into_error()),
            }
        }
    }

    pub(super) async fn create_folder(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
    ) -> Result<(), BackendError> {
        let url = self.files_url();
        let body = metadata(id, parent, name, FOLDER_MIME);
        let created = self
            .call(CallKind::CreateFolder, || {
                self.api.post(&url).query(&[("fields", FIELDS)]).json(&body)
            })
            .await;
        match created {
            Ok(reply) => {
                if parent.is_top()
                    && let Ok(file) = decode::<File>(&reply.body)
                    && let Some(root) = file.parent_id()
                {
                    self.learn_root(root);
                }
                Ok(())
            }
            // The id exists already: creating it again is the idempotent case.
            Err(Failure::Conflict) => Ok(()),
            Err(f) => Err(f.into_create_error()),
        }
    }

    pub(super) async fn stat_file(&self, id: &str) -> Result<Option<File>, BackendError> {
        let url = self.file_url(id);
        let found = self
            .call(CallKind::Get, || {
                self.api.get(&url).query(&[("fields", FIELDS)])
            })
            .await;
        match found {
            Ok(reply) => Ok(Some(decode(&reply.body)?)),
            Err(Failure::NotFound) => Ok(None),
            Err(f) => Err(f.into_error()),
        }
    }

    pub(super) async fn stat(&self, h: &Handle) -> Result<Option<ObjMeta>, BackendError> {
        if h.is_top() {
            // The alias `root`; reported as the fakes report their top level.
            return Ok(self.stat_file("root").await?.map(|root| {
                self.learn_root(&root.id);
                ObjMeta {
                    handle: Handle::top(),
                    name: String::new(),
                    ..root.into_meta(Handle::top())
                }
            }));
        }
        match self.stat_file(&h.0).await? {
            Some(file) => {
                let parent = self.parent_of(&file).await?;
                Ok(Some(file.into_meta(parent)))
            }
            None => Ok(None),
        }
    }

    /// All pages of one `q`; a rejected page token restarts the listing. A `404` (the folder
    /// named in `q` is gone) is an empty listing, as on the other backends.
    async fn list_query(&self, q: &str) -> Result<Vec<File>, BackendError> {
        let url = self.files_url();
        let mut restarts = 0;
        'listing: loop {
            let mut files = Vec::new();
            let mut page_token: Option<String> = None;
            loop {
                let page = self
                    .call(CallKind::List, || {
                        let request = self.api.get(&url).query(&[
                            ("q", q),
                            ("pageSize", "1000"),
                            ("spaces", "drive"),
                            ("fields", LIST_FIELDS),
                        ]);
                        match &page_token {
                            Some(token) => request.query(&[("pageToken", token)]),
                            None => request,
                        }
                    })
                    .await;
                let reply = match page {
                    Ok(reply) => reply,
                    Err(Failure::NotFound) => return Ok(Vec::new()),
                    Err(Failure::Other(BackendError::Fatal { status: 400, .. }))
                        if page_token.is_some() && restarts < LIST_RESTARTS =>
                    {
                        restarts += 1;
                        continue 'listing;
                    }
                    Err(f) => return Err(f.into_error()),
                };
                let page: FileList = decode(&reply.body)?;
                files.extend(page.files);
                match page.next_page_token {
                    Some(token) if !token.is_empty() => page_token = Some(token),
                    _ => return Ok(files),
                }
            }
        }
    }

    pub(super) async fn list(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        let id = if parent.is_top() {
            "root"
        } else {
            parent.0.as_str()
        };
        let q = format!("'{}' in parents and trashed = false", q_escape(id));
        let files = self.list_query(&q).await?;
        if parent.is_top()
            && let Some(root) = files.first().and_then(File::parent_id)
        {
            self.learn_root(root);
        }
        // The query is what makes them children of `parent`.
        Ok(files
            .into_iter()
            .map(|f| f.into_meta(parent.clone()))
            .collect())
    }

    pub(super) async fn find_by_name(&self, name: &str) -> Result<Vec<ObjMeta>, BackendError> {
        let q = format!("name = '{}' and trashed = false", q_escape(name));
        let mut found = Vec::new();
        // Whatever Drive's `name =` matches, the contract is byte-exact.
        for file in self.list_query(&q).await? {
            if file.name.as_deref() == Some(name) {
                let parent = self.parent_of(&file).await?;
                found.push(file.into_meta(parent));
            }
        }
        Ok(found)
    }

    pub(super) async fn set_trashed(&self, h: &Handle, trashed: bool) -> Result<(), BackendError> {
        let url = self.file_url(&h.0);
        let body = serde_json::json!({ "trashed": trashed });
        self.call(CallKind::Trash, || {
            self.api
                .patch(&url)
                .query(&[("fields", FIELDS)])
                .json(&body)
        })
        .await
        .map(drop)
        .map_err(Failure::into_error)
    }

    pub(super) async fn delete(&self, h: &Handle) -> Result<(), BackendError> {
        let url = self.file_url(&h.0);
        self.call(CallKind::Delete, || self.api.delete(&url))
            .await
            .map(drop)
            .map_err(Failure::into_error)
    }

    pub(super) async fn about(&self) -> Result<Quota, BackendError> {
        let url = format!("{}/drive/v3/about", self.ep.api);
        let reply = self
            .call(CallKind::About, || {
                self.api
                    .get(&url)
                    .query(&[("fields", "storageQuota,user(emailAddress)")])
            })
            .await
            .map_err(Failure::into_error)?;
        let about: About = decode(&reply.body)?;
        Ok(Quota {
            limit: about.storage_quota.limit,
            usage: about.storage_quota.usage.unwrap_or(0),
            usage_in_trash: about.storage_quota.usage_in_drive_trash.unwrap_or(0),
            account: about.user.and_then(|u| u.email_address),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_shapes_decode() {
        let file: File = decode(
            br#"{"id":"1AbC","name":"s-0a","mimeType":"application/octet-stream","parents":["1Par"],
                 "size":"16777216","md5Checksum":"9e107d9d372bb6826bd81d3542a419d6",
                 "createdTime":"2026-11-11T09:14:03.123Z","trashed":false,"somethingNew":[1,2]}"#,
        )
        .unwrap();
        assert!(file.is_complete_blob());
        assert_eq!(file.parent_id(), Some("1Par"));
        let meta = file.into_meta(Handle("1Par".into()));
        assert_eq!(meta.handle, Handle("1AbC".into()));
        assert_eq!(meta.name, "s-0a");
        assert_eq!(meta.size, 16_777_216);
        assert_eq!(
            util::hex(&meta.md5.unwrap()),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
        assert_eq!(
            meta.created_ms,
            util::parse_rfc3339_ms("2026-11-11T09:14:03.123Z").unwrap()
        );
        assert!(!meta.is_folder && !meta.trashed);

        // a JSON number is accepted for size
        let file: File = decode(br#"{"id":"x","size":12}"#).unwrap();
        assert_eq!(file.size, Some(12));
        assert!(decode::<File>(br#"{"id":"x","size":"twelve"}"#).is_err());

        // a folder has neither size nor md5; a stray size on it is ignored
        let folder: File = decode(
            br#"{"id":"1Fld","name":"index","mimeType":"application/vnd.google-apps.folder","parents":["1Par"],
                 "createdTime":"2026-11-11T09:14:03.123Z","trashed":true}"#,
        )
        .unwrap();
        assert!(folder.is_folder() && !folder.is_complete_blob());
        let meta = folder.into_meta(Handle::top());
        assert_eq!((meta.size, meta.md5), (0, None));
        assert!(meta.is_folder && meta.trashed && meta.parent.is_top());

        // the default projection of a create answer is incomplete
        let bare: File =
            decode(br#"{"kind":"drive#file","id":"1AbC","name":"n","mimeType":"application/octet-stream"}"#).unwrap();
        assert!(!bare.is_complete_blob());
        assert_eq!(bare.parent_id(), None);

        let list: FileList =
            decode(br#"{"nextPageToken":"tok","files":[{"id":"a"},{"id":"b"}]}"#).unwrap();
        assert_eq!(
            (list.next_page_token.as_deref(), list.files.len()),
            (Some("tok"), 2)
        );
        let last: FileList = decode(br#"{"files":[]}"#).unwrap();
        assert!(last.next_page_token.is_none());

        let ids: GeneratedIds =
            decode(br#"{"kind":"drive#generatedIds","space":"drive","ids":["1a","1b"]}"#).unwrap();
        assert_eq!(ids.ids, ["1a", "1b"]);

        let about: About = decode(
            br#"{"storageQuota":{"limit":"2199023255552","usage":"442630144000","usageInDrive":"1","usageInDriveTrash":"3328599654"},
                 "user":{"emailAddress":"me@example.com"}}"#,
        )
        .unwrap();
        assert_eq!(about.storage_quota.limit, Some(2_199_023_255_552));
        assert_eq!(about.storage_quota.usage, Some(442_630_144_000));
        assert_eq!(
            about.storage_quota.usage_in_drive_trash,
            Some(3_328_599_654)
        );
        assert_eq!(
            about.user.unwrap().email_address.as_deref(),
            Some("me@example.com")
        );
        // unlimited storage and a missing user are tolerated
        let about: About = decode(br#"{"storageQuota":{"usage":"5"}}"#).unwrap();
        assert!(about.storage_quota.limit.is_none() && about.user.is_none());
    }

    #[test]
    fn request_text() {
        assert_eq!(q_escape(r"it's a \ name"), r"it\'s a \\ name");
        assert_eq!(path_segment("1AbC_-x"), "1AbC_-x");
        assert_eq!(path_segment("a/b?c"), "a%2Fb%3Fc");
        let top = metadata(&Handle("i".into()), &Handle::top(), "n", BLOB_MIME);
        assert_eq!(
            top,
            serde_json::json!({ "id": "i", "name": "n", "mimeType": "application/octet-stream" })
        );
        let nested = metadata(&Handle("i".into()), &Handle("p".into()), "n", FOLDER_MIME);
        assert_eq!(nested["parents"], serde_json::json!(["p"]));
        assert_eq!(nested["mimeType"], "application/vnd.google-apps.folder");
    }
}

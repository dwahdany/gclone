//! `FakeDrive` (SPEC §9.6): one local HTTP server that plays Google Drive (§6.4.1 wire shapes),
//! the auth Worker (§2.3, under `/auth`: its three JSON routes, with "Google" and the user who
//! enters the code behind them) and Google's revoke endpoint (`/revoke`).
//!
//! Included with `#[path = "support/fake_drive.rs"] mod fake_drive;` by `tests/drive_http.rs`,
//! `tests/auth.rs`, `tests/cli_e2e.rs` and `tests/restic_e2e.rs`. The Drive side follows the documented wire shapes,
//! not the client's expectations: int64 values are strings, folders have no size, a create
//! answers in the default projection unless `fields=` was sent where Drive reads it, a `308`
//! has no `Location`, top-level objects name the root folder's id as their parent, and
//! `name = '…'` matches without regard to case.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use gclone::auth::{AuthClient, AuthEndpoints, TokenProvider};
use gclone::backend::drive::{DriveBackend, DriveConfig, DriveEndpoints, PacerConfig};
use md5::Digest as _;
use serde_json::{Value, json};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const ROOT_ID: &str = "0AFakeRootOfMyDrive";
const FOLDER_MIME: &str = "application/vnd.google-apps.folder";
const BLOB_MIME: &str = "application/octet-stream";
const GRANULE: u64 = 256 * 1024;
/// Drive's documented limit for `uploadType=multipart`.
const MULTIPART_LIMIT: usize = 5 * 1024 * 1024;
const AUTH_BODY_MAX: usize = 8 * 1024;
/// What the fake Worker names as the user's destination; nothing in a test opens it.
pub const VERIFICATION_URL: &str = "https://www.google.com/device";
const SCOPE_DRIVE_FILE: &str = "https://www.googleapis.com/auth/drive.file";
const DEFAULT_SCOPE: &str = "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.file";
/// Every scope a grant of the Worker's client may carry (§2.3); anything else is refused.
const ALLOWED_SCOPES: [&str; 4] = [
    "openid",
    "email",
    "https://www.googleapis.com/auth/userinfo.email",
    SCOPE_DRIVE_FILE,
];
const JSON_UTF8: &str = "application/json; charset=utf-8";

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Route {
    /// `POST /auth/device/start`
    AuthStart,
    /// `POST /auth/device/poll`
    AuthPoll,
    AuthRefresh,
    Revoke,
    GenerateIds,
    CreateFolder,
    Multipart,
    ResumableInit,
    SessionPut,
    Media,
    Stat,
    List,
    Patch,
    Delete,
    About,
}

impl Route {
    fn is_auth(self) -> bool {
        matches!(
            self,
            Route::AuthStart | Route::AuthPoll | Route::AuthRefresh
        )
    }
}

/// One request as the fake saw it (bodies are not kept, except small JSON ones).
#[derive(Clone, Debug)]
pub struct Seen {
    pub route: Route,
    pub method: String,
    pub path: String,
    /// The raw query string.
    pub query: String,
    /// Header names in lower case.
    pub headers: HashMap<String, String>,
    /// A JSON body, or the metadata part of a multipart create.
    pub json: Option<Value>,
    /// `Content-Type` of each part of a multipart create, in order.
    pub part_types: Vec<String>,
    /// A small body as text (form posts and the like).
    pub text: Option<String>,
    pub body_len: usize,
    /// When the request arrived.
    pub at: Instant,
}

impl Seen {
    /// A decoded query parameter.
    pub fn param(&self, name: &str) -> Option<String> {
        url::form_urlencoded::parse(self.query.as_bytes())
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }
}

// ---------------------------------------------------------------------------------------------
// Answers
// ---------------------------------------------------------------------------------------------

struct Resp {
    status: u16,
    headers: Vec<(&'static str, String)>,
    content_type: Option<&'static str>,
    body: Vec<u8>,
}

impl Resp {
    fn empty(status: u16) -> Resp {
        Resp {
            status,
            headers: Vec::new(),
            content_type: None,
            body: Vec::new(),
        }
    }

    fn header(mut self, name: &'static str, value: impl Into<String>) -> Resp {
        self.headers.push((name, value.into()));
        self
    }

    /// A Drive answer.
    fn drive_json(status: u16, v: &Value) -> Resp {
        Resp {
            status,
            headers: Vec::new(),
            content_type: Some("application/json; charset=UTF-8"),
            body: v.to_string().into_bytes(),
        }
    }

    /// The error envelope of §6.4.1.
    fn envelope(status: u16, reason: &str, message: &str) -> Resp {
        Resp::drive_json(
            status,
            &json!({ "error": { "code": status, "message": message,
                "errors": [{ "domain": "global", "reason": reason, "message": message }] } }),
        )
    }

    /// A JSON answer of the auth Worker (§2.3).
    fn auth_json(status: u16, v: &Value) -> Resp {
        Resp {
            status,
            headers: Vec::new(),
            content_type: Some(JSON_UTF8),
            body: v.to_string().into_bytes(),
        }
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
    }

    fn auth_error(status: u16, code: &str, message: &str) -> Resp {
        Resp::auth_json(status, &json!({ "error": code, "message": message }))
    }

    fn into_template(self) -> ResponseTemplate {
        let mut t = ResponseTemplate::new(self.status);
        for (name, value) in self.headers {
            t = t.insert_header(name, value.as_str());
        }
        match self.content_type {
            Some(mime) => t.set_body_raw(self.body, mime),
            None if self.body.is_empty() => t,
            None => t.set_body_bytes(self.body),
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `2026-11-11T09:14:03.123Z`.
fn rfc3339(ms: u64) -> String {
    let (days, rest) = ((ms / 86_400_000) as i64, ms % 86_400_000);
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rest / 3_600_000,
        rest / 60_000 % 60,
        rest / 1000 % 60,
        rest % 1000
    )
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn all_chars(s: &str, extra: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------------

struct Obj {
    name: String,
    parent: String,
    mime: String,
    data: Arc<Vec<u8>>,
    md5: String,
    created_ms: u64,
    trashed: bool,
    abusive: bool,
    /// A Google-native file (`make_native`): no md5 in its metadata, no content to download.
    native: bool,
    /// Listings started before this number do not show the object (`set_list_lag`).
    visible_from_list: u64,
}

struct Meta {
    id: String,
    name: String,
    parent: String,
    mime: String,
}

struct Session {
    meta: Meta,
    total: Option<u64>,
    data: Vec<u8>,
    /// `fields=` was a query parameter of the initiation.
    fields: bool,
    /// The opaque query of the session URI; a request must repeat it byte for byte.
    query: String,
    done: bool,
}

struct Fault {
    times: u32,
    status: u16,
    /// `Ok(reason)` = the route's error shape; `Err(body)` = that raw text.
    body: Result<String, String>,
}

/// One login between `/device/start` and the poll that ends it. The two timing rules of the
/// grant are "Google's", kept per login: a code runs out `lifetime` after it was issued, and
/// a poll that comes less than `interval` after the previous one is answered `slow_down`.
struct DeviceLogin {
    user_code: String,
    state: DeviceState,
    started: Instant,
    last_poll: Option<Instant>,
    interval: Duration,
    lifetime: Duration,
}

enum DeviceState {
    Pending,
    /// The user entered the code at "Google" and approved, signed in as this account.
    Approved(String),
    Denied,
    Expired,
    /// A poll has redeemed it: Google's device code is single-use.
    Used,
}

/// The Worker's legacy pair of secrets (§2.3 "Configuration").
#[derive(Copy, Clone, PartialEq, Eq)]
enum LegacyClient {
    Absent,
    /// Exactly one of the two secrets is set: the legacy client is unusable, nothing else is.
    HalfSet,
    Configured,
}

/// What an error answer shows of an address: the first character and the domain (§2.3).
fn masked_email(email: &str) -> Option<String> {
    let presentable =
        (3..=254).contains(&email.len()) && email.bytes().all(|b| (0x21..=0x7e).contains(&b));
    let at = email
        .rfind('@')
        .filter(|at| *at >= 1 && *at + 1 < email.len())?;
    presentable.then(|| format!("{}***{}", &email[..1], &email[at..]))
}

/// A refresh token "Google" issued.
struct Issued {
    valid: bool,
    /// Issued to the Worker's legacy client (the browser sign-in before 0.2.0).
    legacy: bool,
}

struct State {
    base: String,
    // --- Drive
    objects: HashMap<String, Obj>,
    order: Vec<String>,
    sessions: HashMap<String, Session>,
    counter: u64,
    lists_started: u64,
    list_lag: u32,
    /// The `Date` header of every answer is this far from the machine's clock (0: the HTTP
    /// server's own header).
    date_skew_ms: i64,
    page_cap: Option<usize>,
    reject_page_token_once: bool,
    faults: HashMap<Route, VecDeque<Fault>>,
    lose_response: HashMap<Route, u32>,
    /// (bytes kept, part PUTs this still applies to).
    ack_only: Option<(u64, u32)>,
    drop_parts: u32,
    hold_completion: u32,
    omit_range_once: bool,
    sessions_expired: bool,
    conflict_at_completion: bool,
    phantom_conflicts: HashSet<Route>,
    strip_completion_once: bool,
    hits: HashMap<Route, u64>,
    seen: Vec<Seen>,
    session_requests: Vec<(u64, u64, u64)>,
    status_queries: u64,
    // --- auth
    /// Device code → its login.
    devices: HashMap<String, DeviceLogin>,
    last_user_code: Option<String>,
    /// `interval` and `expires_in` of `/device/start` answers, seconds.
    poll_interval: f64,
    code_lifetime: f64,
    /// Polls of a pending login that are answered `slow_down` whatever their timing.
    slow_down: u32,
    /// `slow_down` answers given because a poll came too early (not the injected ones).
    early_polls: u32,
    /// What /device/start names as the page to open.
    verification_url: String,
    /// "Google's" token answer for an approved login carries no ID token.
    no_id_token: bool,
    /// The Worker's GOOGLE_LEGACY_CLIENT_* secrets.
    legacy_client: LegacyClient,
    refresh_tokens: HashMap<String, Issued>,
    issued_refresh_tokens: Vec<String>,
    access_tokens: HashSet<String>,
    revoked: Vec<String>,
    login_email: String,
    allowed_emails: Vec<String>,
    granted_scope: String,
    client_broken: bool,
    refresh_expires_in: Option<u64>,
}

impl State {
    fn new(base: String) -> State {
        State {
            base,
            objects: HashMap::new(),
            order: Vec::new(),
            sessions: HashMap::new(),
            counter: 0,
            lists_started: 0,
            list_lag: 0,
            date_skew_ms: 0,
            page_cap: None,
            reject_page_token_once: false,
            faults: HashMap::new(),
            lose_response: HashMap::new(),
            ack_only: None,
            drop_parts: 0,
            hold_completion: 0,
            omit_range_once: false,
            sessions_expired: false,
            conflict_at_completion: false,
            phantom_conflicts: HashSet::new(),
            strip_completion_once: false,
            hits: HashMap::new(),
            seen: Vec::new(),
            session_requests: Vec::new(),
            status_queries: 0,
            devices: HashMap::new(),
            last_user_code: None,
            poll_interval: 0.02,
            code_lifetime: 1800.0,
            slow_down: 0,
            early_polls: 0,
            verification_url: VERIFICATION_URL.to_string(),
            no_id_token: false,
            legacy_client: LegacyClient::Absent,
            refresh_tokens: HashMap::from([(
                "rt-ok".to_string(),
                Issued {
                    valid: true,
                    legacy: false,
                },
            )]),
            issued_refresh_tokens: Vec::new(),
            access_tokens: HashSet::new(),
            revoked: Vec::new(),
            login_email: "me@example.com".to_string(),
            allowed_emails: vec!["me@example.com".to_string()],
            granted_scope: DEFAULT_SCOPE.to_string(),
            client_broken: false,
            refresh_expires_in: None,
        }
    }

    fn next(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }

    /// The pending login `user_code` belongs to.
    fn pending(&mut self, user_code: &str) -> &mut DeviceLogin {
        self.devices
            .values_mut()
            .find(|d| d.user_code == user_code && matches!(d.state, DeviceState::Pending))
            .unwrap_or_else(|| panic!("no pending login has the user code {user_code:?}"))
    }

    // -----------------------------------------------------------------------------------------
    // Dispatch
    // -----------------------------------------------------------------------------------------

    fn handle(&mut self, req: &Request) -> Resp {
        let path = req.url.path().to_string();
        if path == "/revoke" {
            return self.revoke(req);
        }
        if let Some(sub) = path.strip_prefix("/auth")
            && (sub.is_empty() || sub.starts_with('/'))
        {
            return self.auth(req, sub);
        }
        let query: HashMap<String, String> = req.url.query_pairs().into_owned().collect();
        let method = req.method.as_str();
        let file_id = path
            .strip_prefix("/drive/v3/files/")
            .filter(|id| !id.contains('/'));
        let route = match (method, path.as_str()) {
            ("GET", "/drive/v3/files/generateIds") => Route::GenerateIds,
            ("GET", "/drive/v3/about") => Route::About,
            ("GET", "/drive/v3/files") => Route::List,
            ("POST", "/drive/v3/files") => Route::CreateFolder,
            ("POST", "/upload/drive/v3/files") => match query.get("uploadType").map(String::as_str)
            {
                Some("multipart") => Route::Multipart,
                Some("resumable") => Route::ResumableInit,
                _ => return Resp::envelope(400, "badRequest", "unsupported uploadType"),
            },
            ("PUT", p) if p.starts_with("/upload/session/") => Route::SessionPut,
            ("GET", _)
                if file_id.is_some() && query.get("alt").map(String::as_str) == Some("media") =>
            {
                Route::Media
            }
            ("GET", _) if file_id.is_some() => Route::Stat,
            ("PATCH", _) if file_id.is_some() => Route::Patch,
            ("DELETE", _) if file_id.is_some() => Route::Delete,
            _ => return Resp::envelope(404, "notFound", "no such endpoint on the fake"),
        };
        self.note(route, req);
        if let Some(injected) = self.take_fault(route, req) {
            return injected;
        }
        let bearer = req
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if !bearer.is_some_and(|t| self.access_tokens.contains(t)) {
            return Resp::envelope(401, "authError", "Invalid Credentials");
        }
        let id = file_id.unwrap_or("");
        let answer = match route {
            Route::GenerateIds => self.generate_ids(&query),
            Route::About => self.about(),
            Route::List => self.list(&query),
            Route::CreateFolder => self.create_metadata_only(req, &query),
            Route::Multipart => self.multipart(req, &query),
            Route::ResumableInit => self.resumable_init(req, &query),
            Route::SessionPut => self.session_put(req, &path),
            Route::Media => self.media(req, id, &query),
            Route::Stat => self.stat(id, &query),
            Route::Patch => self.patch(req, id, &query),
            Route::Delete => self.delete(id),
            Route::AuthStart | Route::AuthPoll | Route::AuthRefresh | Route::Revoke => {
                unreachable!()
            }
        };
        if let Some(left) = self.lose_response.get_mut(&route).filter(|n| **n > 0) {
            *left -= 1;
            return Resp::envelope(503, "backendError", "Backend Error");
        }
        answer
    }

    fn note(&mut self, route: Route, req: &Request) {
        *self.hits.entry(route).or_default() += 1;
        let headers: HashMap<String, String> = req
            .headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();
        let content_type = headers.get("content-type").cloned().unwrap_or_default();
        let (mut json, mut part_types, mut text) = (None, Vec::new(), None);
        if content_type.starts_with("multipart/related") {
            if let Ok((meta, types, _)) = parse_multipart(&content_type, &req.body) {
                json = Some(meta);
                part_types = types;
            }
        } else if req.body.len() <= 64 * 1024 {
            json = serde_json::from_slice(&req.body).ok();
            text = String::from_utf8(req.body.clone()).ok();
        }
        if route == Route::SessionPut
            && let Some(range) = headers
                .get("content-range")
                .and_then(|r| r.strip_prefix("bytes "))
            && let Some((span, total)) = range.split_once('/')
            && let Ok(total) = total.parse::<u64>()
        {
            // Every Content-Range that arrives counts, whatever the answer will be.
            let part = span
                .split_once('-')
                .and_then(|(a, b)| Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?)));
            match part {
                Some((start, last)) if start <= last => {
                    self.session_requests.push((start, last - start + 1, total))
                }
                _ if span == "*" => self.status_queries += 1,
                _ => {}
            }
        }
        self.seen.push(Seen {
            route,
            method: req.method.as_str().to_string(),
            path: req.url.path().to_string(),
            query: req.url.query().unwrap_or("").to_string(),
            headers,
            json,
            part_types,
            text,
            body_len: req.body.len(),
            at: Instant::now(),
        });
    }

    /// The next injected failure of `route`, in the error shape of that route.
    fn take_fault(&mut self, route: Route, req: &Request) -> Option<Resp> {
        let queue = self.faults.get_mut(&route)?;
        let fault = queue.front_mut()?;
        let (status, body) = (fault.status, fault.body.clone());
        if fault.times != u32::MAX {
            fault.times -= 1;
            if fault.times == 0 {
                queue.pop_front();
            }
        }
        let mut resp = match body {
            Err(raw) => Resp {
                status,
                headers: Vec::new(),
                content_type: Some("text/html; charset=UTF-8"),
                body: raw.into_bytes(),
            },
            Ok(reason) if route.is_auth() => {
                Resp::auth_error(status, &reason, "This failure was injected by the test.")
            }
            Ok(reason) if route == Route::Revoke => {
                Resp::auth_json(status, &json!({ "error": reason }))
            }
            Ok(reason) => Resp::envelope(status, &reason, &format!("injected: {reason}")),
        };
        if route.is_auth() && status == 429 {
            resp = resp.header("Retry-After", "1");
        }
        if (300..400).contains(&status) && status != 308 {
            // A client that followed this would arrive at the same route again.
            let query = req.url.query().map(|q| format!("?{q}")).unwrap_or_default();
            resp = resp.header(
                "Location",
                format!("{}{}{query}", self.base, req.url.path()),
            );
        }
        Some(resp)
    }

    // -----------------------------------------------------------------------------------------
    // Drive
    // -----------------------------------------------------------------------------------------

    fn is_folder_id(&self, id: &str) -> bool {
        id == ROOT_ID || self.objects.get(id).is_some_and(|o| o.mime == FOLDER_MIME)
    }

    /// Trashed itself or inside a trashed folder.
    fn effectively_trashed(&self, id: &str) -> bool {
        let mut at = id;
        while let Some(obj) = self.objects.get(at) {
            if obj.trashed {
                return true;
            }
            at = &obj.parent;
        }
        false
    }

    fn file_json(&self, id: &str, full: bool) -> Value {
        if id == ROOT_ID {
            return if full {
                json!({ "id": ROOT_ID, "name": "My Drive", "mimeType": FOLDER_MIME,
                        "createdTime": "2020-01-01T00:00:00.000Z", "trashed": false })
            } else {
                json!({ "kind": "drive#file", "id": ROOT_ID, "name": "My Drive", "mimeType": FOLDER_MIME })
            };
        }
        let obj = &self.objects[id];
        if !full {
            return json!({ "kind": "drive#file", "id": id, "name": obj.name, "mimeType": obj.mime });
        }
        let mut v = json!({ "id": id, "name": obj.name, "mimeType": obj.mime, "parents": [obj.parent],
                            "createdTime": rfc3339(obj.created_ms), "trashed": self.effectively_trashed(id) });
        if obj.mime != FOLDER_MIME {
            v["size"] = obj.data.len().to_string().into();
            // Drive computes an md5 for binary content only.
            if !obj.native {
                v["md5Checksum"] = obj.md5.clone().into();
            }
        }
        v
    }

    /// Metadata of a create; `Err` is the answer for a bad one.
    fn create_meta(&mut self, v: &Value) -> Result<Meta, Resp> {
        let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let parent = match v.get("parents").and_then(Value::as_array) {
            None => ROOT_ID.to_string(),
            Some(list) => match list.as_slice() {
                [Value::String(p)] if p == "root" => ROOT_ID.to_string(),
                [Value::String(p)] => p.clone(),
                _ => {
                    return Err(Resp::envelope(
                        400,
                        "invalid",
                        "exactly one parent is allowed",
                    ));
                }
            },
        };
        if !self.is_folder_id(&parent) {
            return Err(Resp::envelope(
                404,
                "notFound",
                &format!("File not found: {parent}."),
            ));
        }
        let id = match text("id") {
            Some(id) => id,
            None => format!("1FakeAuto{:08}", self.next()),
        };
        Ok(Meta {
            id,
            name: text("name").unwrap_or_else(|| "Untitled".to_string()),
            parent,
            mime: text("mimeType").unwrap_or_else(|| BLOB_MIME.to_string()),
        })
    }

    fn store(&mut self, meta: Meta, data: Vec<u8>) {
        let obj = Obj {
            md5: hex(&md5::Md5::digest(&data)),
            name: meta.name,
            parent: meta.parent,
            mime: meta.mime,
            data: Arc::new(data),
            created_ms: now_ms(),
            trashed: false,
            abusive: false,
            native: false,
            visible_from_list: self.lists_started + u64::from(self.list_lag) + 1,
        };
        self.order.push(meta.id.clone());
        self.objects.insert(meta.id, obj);
    }

    fn id_in_use(id: &str) -> Resp {
        Resp::envelope(
            409,
            "fileIdInUse",
            &format!("A file already exists with the provided ID: {id}."),
        )
    }

    /// The answer of a finished create: the projection Drive would use.
    fn created(&mut self, id: &str, fields: bool) -> Resp {
        let full = fields && !std::mem::take(&mut self.strip_completion_once);
        Resp::drive_json(200, &self.file_json(id, full))
    }

    fn generate_ids(&mut self, q: &HashMap<String, String>) -> Resp {
        let count = q.get("count").map_or(Ok(10), |c| c.parse::<usize>());
        match count {
            Ok(n) if (1..=1000).contains(&n) => {
                let ids: Vec<String> = (0..n)
                    .map(|_| format!("1FakeId{:010}", self.next()))
                    .collect();
                Resp::drive_json(
                    200,
                    &json!({ "kind": "drive#generatedIds", "space": "drive", "ids": ids }),
                )
            }
            _ => Resp::envelope(400, "invalid", "Invalid value for count"),
        }
    }

    fn about(&self) -> Resp {
        let size = |trashed_only: bool| -> u64 {
            self.objects
                .iter()
                .filter(|(id, _)| !trashed_only || self.effectively_trashed(id))
                .map(|(_, o)| o.data.len() as u64)
                .sum()
        };
        Resp::drive_json(
            200,
            &json!({ "storageQuota": { "limit": "16106127360", "usage": size(false).to_string(),
                                       "usageInDrive": size(false).to_string(),
                                       "usageInDriveTrash": size(true).to_string() },
                     "user": { "emailAddress": "me@example.com" } }),
        )
    }

    /// `POST /drive/v3/files`: a folder (or an empty file) from metadata alone.
    fn create_metadata_only(&mut self, req: &Request, q: &HashMap<String, String>) -> Resp {
        let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
            return Resp::envelope(400, "parseError", "Parse Error");
        };
        let meta = match self.create_meta(&v) {
            Ok(meta) => meta,
            Err(resp) => return resp,
        };
        if self.objects.contains_key(&meta.id) {
            return State::id_in_use(&meta.id);
        }
        let id = meta.id.clone();
        self.store(meta, Vec::new());
        Resp::drive_json(200, &self.file_json(&id, q.contains_key("fields")))
    }

    fn multipart(&mut self, req: &Request, q: &HashMap<String, String>) -> Resp {
        let content_type = req
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let (v, types, media) = match parse_multipart(content_type, &req.body) {
            Ok(parts) => parts,
            Err(why) => return Resp::envelope(400, "badContent", &why),
        };
        if !types[0].starts_with("application/json") {
            return Resp::envelope(
                400,
                "badContent",
                "the first part must be the JSON metadata",
            );
        }
        if media.len() > MULTIPART_LIMIT {
            return Resp::envelope(413, "uploadTooLarge", "Request Entity Too Large");
        }
        let meta = match self.create_meta(&v) {
            Ok(meta) => meta,
            Err(resp) => return resp,
        };
        if self.phantom_conflicts.remove(&Route::Multipart) || self.objects.contains_key(&meta.id) {
            return State::id_in_use(&meta.id);
        }
        let id = meta.id.clone();
        self.store(meta, media.to_vec());
        self.created(&id, q.contains_key("fields"))
    }

    fn resumable_init(&mut self, req: &Request, q: &HashMap<String, String>) -> Resp {
        let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
            return Resp::envelope(400, "parseError", "Parse Error");
        };
        let meta = match self.create_meta(&v) {
            Ok(meta) => meta,
            Err(resp) => return resp,
        };
        let exists = self.objects.contains_key(&meta.id) && !self.conflict_at_completion;
        if self.phantom_conflicts.remove(&Route::ResumableInit) || exists {
            return State::id_in_use(&meta.id);
        }
        let total = req
            .headers
            .get("x-upload-content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let n = self.next();
        // Characters a client must not touch: escapes stay escapes, nothing is added.
        let query = format!("upload_id=AbC-{n}_x%2By%3D%3D&upload_protocol=resumable");
        let location = format!("{}/upload/session/s{n}?{query}", self.base);
        let session = Session {
            meta,
            total,
            data: Vec::new(),
            fields: q.contains_key("fields"),
            query,
            done: false,
        };
        self.sessions.insert(format!("s{n}"), session);
        Resp::empty(200).header("Location", location)
    }

    fn session_put(&mut self, req: &Request, path: &str) -> Resp {
        let sid = path.trim_start_matches("/upload/session/").to_string();
        let lost = || {
            Resp::envelope(
                404,
                "notFound",
                "the upload session does not exist or has expired",
            )
        };
        if self.sessions_expired {
            return lost();
        }
        let Some(session) = self.sessions.get_mut(&sid) else {
            return lost();
        };
        if req.url.query() != Some(session.query.as_str()) {
            return Resp::envelope(400, "badRequest", "the session URI was altered");
        }
        let range = req
            .headers
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let Some((span, total)) = range.strip_prefix("bytes ").and_then(|r| r.split_once('/'))
        else {
            return Resp::envelope(400, "badRequest", "missing or malformed Content-Range");
        };
        let Ok(total) = total.parse::<u64>() else {
            return Resp::envelope(400, "badRequest", "the total size must be given");
        };
        if session.total.is_some_and(|t| t != total) {
            return Resp::envelope(400, "badRequest", "the total size changed");
        }
        let progress = |held: usize| match held {
            0 => Resp::empty(308),
            n => Resp::empty(308).header("Range", format!("bytes=0-{}", n - 1)),
        };
        let fields = session.fields;
        let id = session.meta.id.clone();

        if span == "*" {
            if !req.body.is_empty() {
                return Resp::envelope(400, "badRequest", "a status query has no body");
            }
            if session.done {
                return Resp::drive_json(200, &self.file_json(&id, fields));
            }
            let held = session.data.len();
            if held as u64 != total {
                return progress(held);
            }
            // Every byte is here and the session is not complete (`hold_completion`).
            if self.hold_completion > 0 {
                self.hold_completion -= 1;
                return progress(held);
            }
            return self.complete_session(&sid);
        }
        let parsed = span
            .split_once('-')
            .and_then(|(a, b)| Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?)));
        let Some((start, last)) = parsed.filter(|(a, b)| a <= b && *b < total) else {
            return Resp::envelope(400, "badRequest", "malformed Content-Range");
        };
        let len = last - start + 1;
        if req.body.len() as u64 != len {
            return Resp::envelope(
                400,
                "badRequest",
                "the body length does not match Content-Range",
            );
        }
        if session.done {
            return Resp::drive_json(200, &self.file_json(&id, fields));
        }
        if start != session.data.len() as u64 {
            // Not where the session stands: nothing is taken, the answer says where to go on.
            return progress(session.data.len());
        }
        let is_last = last + 1 == total;
        if !is_last && len % GRANULE != 0 {
            return Resp::envelope(
                400,
                "badRequest",
                "a part that is not the last must be a multiple of 256 KiB",
            );
        }
        if self.drop_parts > 0 {
            // The part is not kept and the answer says so: a 308 with the Range as it was.
            self.drop_parts -= 1;
            return progress(session.data.len());
        }
        if let Some((keep, times)) = self.ack_only.take() {
            if times == u32::MAX {
                self.ack_only = Some((keep, times));
            } else if times > 1 {
                self.ack_only = Some((keep, times - 1));
            }
            let keep = (keep.min(len) / GRANULE * GRANULE) as usize;
            session.data.extend_from_slice(&req.body[..keep]);
            return Resp::envelope(503, "backendError", "Backend Error");
        }
        session.data.extend_from_slice(&req.body);
        if !is_last {
            if std::mem::take(&mut self.omit_range_once) {
                // "No Range header" means nothing is stored — and then nothing is.
                session.data.clear();
                return Resp::empty(308);
            }
            return progress(session.data.len());
        }
        if self.hold_completion > 0 {
            // Stored, but not finalised yet: the answer acknowledges every byte.
            self.hold_completion -= 1;
            return progress(session.data.len());
        }
        self.complete_session(&sid)
    }

    /// The session holds every byte: the object comes into being (or its id turns out taken).
    fn complete_session(&mut self, sid: &str) -> Resp {
        let Some(session) = self.sessions.get_mut(sid) else {
            return Resp::envelope(404, "notFound", "the upload session does not exist");
        };
        let (id, fields) = (session.meta.id.clone(), session.fields);
        if self.phantom_conflicts.remove(&Route::SessionPut) {
            self.sessions.remove(sid);
            return State::id_in_use(&id);
        }
        if self.objects.contains_key(&id) {
            self.sessions.remove(sid);
            return State::id_in_use(&id);
        }
        session.done = true;
        let data = std::mem::take(&mut session.data);
        let meta = Meta {
            id: id.clone(),
            name: session.meta.name.clone(),
            parent: session.meta.parent.clone(),
            mime: session.meta.mime.clone(),
        };
        self.store(meta, data);
        self.created(&id, fields)
    }

    fn not_found(id: &str) -> Resp {
        Resp::envelope(404, "notFound", &format!("File not found: {id}."))
    }

    fn resolve<'a>(&self, id: &'a str) -> Option<&'a str> {
        match id {
            "root" => Some(ROOT_ID),
            ROOT_ID => Some(ROOT_ID),
            _ if self.objects.contains_key(id) => Some(id),
            _ => None,
        }
    }

    fn media(&mut self, req: &Request, id: &str, q: &HashMap<String, String>) -> Resp {
        let Some(obj) = self.objects.get(id) else {
            return match self.resolve(id) {
                Some(_) => Resp::envelope(
                    403,
                    "fileNotDownloadable",
                    "Only files with binary content can be downloaded.",
                ),
                None => State::not_found(id),
            };
        };
        if obj.mime == FOLDER_MIME || obj.native {
            return Resp::envelope(
                403,
                "fileNotDownloadable",
                "Only files with binary content can be downloaded.",
            );
        }
        if obj.abusive && q.get("acknowledgeAbuse").map(String::as_str) != Some("true") {
            return Resp::envelope(
                403,
                "cannotDownloadAbusiveFile",
                "This file has been identified as malware or spam and cannot be downloaded.",
            );
        }
        let data = &obj.data;
        let whole = |status: u16, slice: &[u8]| Resp {
            status,
            headers: Vec::new(),
            content_type: Some(BLOB_MIME),
            body: slice.to_vec(),
        };
        let Some(range) = req.headers.get("range").and_then(|v| v.to_str().ok()) else {
            return whole(200, data);
        };
        let parsed = range
            .strip_prefix("bytes=")
            .and_then(|r| r.split_once('-'))
            .and_then(|(a, b)| {
                let start = a.parse::<u64>().ok()?;
                let last = if b.is_empty() {
                    u64::MAX
                } else {
                    b.parse::<u64>().ok()?
                };
                (start <= last).then_some((start, last))
            });
        let len = data.len() as u64;
        match parsed {
            Some((start, last)) if start < len => {
                let last = last.min(len - 1);
                whole(206, &data[start as usize..=last as usize])
                    .header("Content-Range", format!("bytes {start}-{last}/{len}"))
            }
            _ => Resp::envelope(
                416,
                "requestedRangeNotSatisfiable",
                "Requested range not satisfiable",
            )
            .header("Content-Range", format!("bytes */{len}")),
        }
    }

    fn stat(&self, id: &str, q: &HashMap<String, String>) -> Resp {
        match self.resolve(id) {
            Some(id) => Resp::drive_json(200, &self.file_json(id, q.contains_key("fields"))),
            None => State::not_found(id),
        }
    }

    fn patch(&mut self, req: &Request, id: &str, q: &HashMap<String, String>) -> Resp {
        let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
            return Resp::envelope(400, "parseError", "Parse Error");
        };
        let Some(obj) = self.objects.get_mut(id) else {
            return State::not_found(id);
        };
        if let Some(trashed) = v.get("trashed").and_then(Value::as_bool) {
            obj.trashed = trashed;
        }
        if let Some(name) = v.get("name").and_then(Value::as_str) {
            obj.name = name.to_string();
        }
        Resp::drive_json(200, &self.file_json(id, q.contains_key("fields")))
    }

    fn delete(&mut self, id: &str) -> Resp {
        if !self.objects.contains_key(id) {
            return State::not_found(id);
        }
        // A folder takes its content with it.
        let mut doomed = vec![id.to_string()];
        let mut at = 0;
        while at < doomed.len() {
            let parent = doomed[at].clone();
            doomed.extend(
                self.objects
                    .iter()
                    .filter(|(_, o)| o.parent == parent)
                    .map(|(k, _)| k.clone()),
            );
            at += 1;
        }
        for id in &doomed {
            self.objects.remove(id);
        }
        self.order.retain(|k| !doomed.contains(k));
        Resp::empty(204)
    }

    fn list(&mut self, q: &HashMap<String, String>) -> Resp {
        let Some(terms) = q.get("q").and_then(|q| parse_q(q)) else {
            return Resp::envelope(400, "invalid", "Invalid Value (q)");
        };
        let mut offset = 0usize;
        match q.get("pageToken") {
            None => self.lists_started += 1,
            Some(token) => {
                let parsed = token
                    .strip_prefix("page-")
                    .and_then(|n| n.parse::<usize>().ok());
                match parsed {
                    Some(n) if !std::mem::take(&mut self.reject_page_token_once) => offset = n,
                    _ => return Resp::envelope(400, "invalid", "Invalid Value (pageToken)"),
                }
            }
        }
        for term in &terms {
            if let Term::Parent(p) = term
                && self.resolve(p).is_none()
            {
                return Resp::envelope(404, "notFound", "File not found: .");
            }
        }
        let matching: Vec<&String> = self
            .order
            .iter()
            .filter(|id| {
                let obj = &self.objects[*id];
                obj.visible_from_list <= self.lists_started
                    && terms.iter().all(|term| match term {
                        Term::Parent(p) => self.resolve(p) == Some(obj.parent.as_str()),
                        // Drive compares names without regard to case.
                        Term::Name(n) => obj.name.to_lowercase() == n.to_lowercase(),
                        Term::Trashed(t) => self.effectively_trashed(id) == *t,
                    })
            })
            .collect();
        let asked = q
            .get("pageSize")
            .and_then(|n| n.parse::<usize>().ok())
            .unwrap_or(100);
        let page_size = asked
            .clamp(1, 1000)
            .min(self.page_cap.unwrap_or(usize::MAX));
        let full = q.contains_key("fields");
        let files: Vec<Value> = matching
            .iter()
            .skip(offset)
            .take(page_size)
            .map(|id| self.file_json(id, full))
            .collect();
        let mut answer = json!({ "files": files });
        if offset + page_size < matching.len() {
            answer["nextPageToken"] = format!("page-{}", offset + page_size).into();
        }
        Resp::drive_json(200, &answer)
    }

    // -----------------------------------------------------------------------------------------
    // The auth Worker (§2.3) and Google's revoke endpoint
    // -----------------------------------------------------------------------------------------

    fn auth(&mut self, req: &Request, sub: &str) -> Resp {
        let route = match sub {
            "/device/start" => Route::AuthStart,
            "/device/poll" => Route::AuthPoll,
            "/refresh" => Route::AuthRefresh,
            _ => return Resp::auth_error(404, "not_found", "There is nothing at this address."),
        };
        if req.method.as_str() != "POST" {
            return Resp::auth_error(
                405,
                "method_not_allowed",
                "This address only answers POST requests.",
            )
            .header("Allow", "POST");
        }
        self.note(route, req);
        // Where the Worker's rate limiter and configuration check stand: before the body.
        if let Some(injected) = self.take_fault(route, req) {
            return injected;
        }
        let body = match read_json_object(req) {
            Ok(body) => body,
            Err(resp) => return resp,
        };
        match route {
            Route::AuthStart => self.auth_start(),
            Route::AuthPoll => self.auth_poll(&body),
            _ => self.auth_refresh(&body),
        }
    }

    fn client_invalid() -> Resp {
        Resp::auth_error(
            500,
            "client_invalid",
            "Google does not accept this Worker's OAuth client (invalid_client).",
        )
    }

    /// `/device/start`: "Google" opens a login and names its two codes.
    fn auth_start(&mut self) -> Resp {
        if self.client_broken {
            return State::client_invalid();
        }
        let n = self.next();
        let device_code = format!("dc-{n}-{}", "x".repeat(24));
        let user_code = format!("TEST-{n:04}");
        self.devices.insert(
            device_code.clone(),
            DeviceLogin {
                user_code: user_code.clone(),
                state: DeviceState::Pending,
                started: Instant::now(),
                last_poll: None,
                interval: Duration::from_secs_f64(self.poll_interval),
                lifetime: Duration::from_secs_f64(self.code_lifetime),
            },
        );
        self.last_user_code = Some(user_code.clone());
        Resp::auth_json(
            200,
            &json!({ "device_code": device_code, "user_code": user_code, "verification_url": self.verification_url,
                     "expires_in": self.code_lifetime, "interval": self.poll_interval }),
        )
    }

    /// `/device/poll`: the state of the login, or — once — its tokens, after the checks of §2.3.
    fn auth_poll(&mut self, body: &serde_json::Map<String, Value>) -> Resp {
        let code = body
            .get("device_code")
            .and_then(Value::as_str)
            .filter(|c| all_chars(c, "_/.~+=-") && (16..=512).contains(&c.len()));
        let Some(code) = code else {
            return Resp::auth_error(
                400,
                "invalid_request",
                "The request needs a well-formed device_code.",
            );
        };
        if self.client_broken {
            return State::client_invalid();
        }
        let invalid_grant = || {
            Resp::auth_error(
                400,
                "invalid_grant",
                "Google rejected the sign-in code or refresh token: it is expired, revoked or already used.",
            )
        };
        let Some(login) = self.devices.get_mut(code) else {
            return invalid_grant();
        };
        let slow_down = || {
            Resp::auth_error(
                400,
                "slow_down",
                "Polling too fast: wait 5 seconds longer between requests.",
            )
        };
        // "Google's" two timing rules, for a code that is still open: it runs out by itself,
        // and a poll that comes sooner than `interval` after the previous one is refused —
        // without a look at whether the code was entered. The first poll has no previous one.
        if matches!(login.state, DeviceState::Pending | DeviceState::Approved(_)) {
            let now = Instant::now();
            if now.duration_since(login.started) >= login.lifetime {
                login.state = DeviceState::Expired;
            } else {
                let early = login
                    .last_poll
                    .is_some_and(|last| now.duration_since(last) < login.interval);
                login.last_poll = Some(now);
                if early {
                    self.early_polls += 1;
                    return slow_down();
                }
            }
        }
        let email = match &login.state {
            DeviceState::Pending if self.slow_down > 0 => {
                self.slow_down -= 1;
                return slow_down();
            }
            DeviceState::Pending => {
                return Resp::auth_error(
                    400,
                    "authorization_pending",
                    "Nobody has entered the code at Google yet.",
                );
            }
            DeviceState::Denied => {
                return Resp::auth_error(
                    403,
                    "access_denied",
                    "Google denied access (access_denied).",
                );
            }
            DeviceState::Expired => {
                return Resp::auth_error(
                    400,
                    "expired_token",
                    "The code expired before it was entered at Google. Run `gclone login` again.",
                );
            }
            DeviceState::Used => return invalid_grant(),
            DeviceState::Approved(email) => email.clone(),
        };
        // From here on "Google" has consumed the device code: every refusal below is final,
        // and none of them is a 5xx (which a device polls again on).
        login.state = DeviceState::Used;
        if self.no_id_token {
            return Resp::auth_error(
                403,
                "grant_unusable",
                "Google approved the sign-in, but its answer carried no ID token (the account cannot be checked without one), so nothing was handed out and the code is used up. If this happens on every login, see \"Troubleshooting\" in worker/README.md.",
            );
        }
        // Byte for byte but for the case of ASCII letters; an address outside printable ASCII
        // matches nothing. The answer shows the address masked: the caller is anonymous.
        let printable = |s: &str| s.bytes().all(|b| (0x21..=0x7e).contains(&b));
        if !(printable(&email)
            && self
                .allowed_emails
                .iter()
                .any(|a| a.trim().eq_ignore_ascii_case(&email)))
        {
            let who = match masked_email(&email) {
                Some(masked) => format!("The Google account {masked}"),
                None => "This Google account".to_string(),
            };
            return Resp::auth_error(
                403,
                "email_not_allowed",
                &format!("{who} is not allowed to sign in here."),
            );
        }
        if let Some(refused) = self.scope_not_allowed() {
            return refused;
        }
        if !self.granted_scope.split(' ').any(|s| s == SCOPE_DRIVE_FILE) {
            return Resp::auth_error(
                403,
                "scope_missing",
                "Google did not grant access to Google Drive files; approve every permission on the consent screen.",
            );
        }
        let refresh_token = format!("rt-{}", self.issued_refresh_tokens.len() + 1);
        self.issued_refresh_tokens.push(refresh_token.clone());
        self.refresh_tokens.insert(
            refresh_token.clone(),
            Issued {
                valid: true,
                legacy: false,
            },
        );
        let access_token = self.issue_access_token();
        let mut answer = json!({ "refresh_token": refresh_token, "access_token": access_token,
                                 "expires_in": 3599, "scope": self.granted_scope, "email": email });
        if let Some(secs) = self.refresh_expires_in {
            answer["refresh_token_expires_in"] = secs.into();
        }
        Resp::auth_json(200, &answer)
    }

    fn auth_refresh(&mut self, body: &serde_json::Map<String, Value>) -> Resp {
        // The Worker's pre-filter; the fake's own short tokens ("rt-ok", "rt-1") pass it too.
        let token = body
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|t| {
                all_chars(t, "_/.~+=-")
                    && ((20..=512).contains(&t.len()) || self.refresh_tokens.contains_key(*t))
            });
        let Some(token) = token else {
            return Resp::auth_error(
                400,
                "invalid_request",
                "The request needs a well-formed refresh_token.",
            );
        };
        // Which client: "device", or — no field — the legacy client of the browser sign-in.
        let legacy = match body.get("client") {
            None => true,
            Some(Value::String(c)) if c == "device" => false,
            Some(_) => {
                return Resp::auth_error(
                    400,
                    "invalid_request",
                    "The \"client\" of a refresh request is \"device\" or absent.",
                );
            }
        };
        if legacy && self.legacy_client == LegacyClient::HalfSet {
            return Resp::auth_error(
                500,
                "server_misconfigured",
                "Only one of GOOGLE_LEGACY_CLIENT_ID and GOOGLE_LEGACY_CLIENT_SECRET is set on this sign-in helper, so it cannot refresh a login made before gclone 0.2.0: set both, or delete both.",
            );
        }
        if legacy && self.legacy_client == LegacyClient::Absent {
            return Resp::auth_error(
                400,
                "invalid_grant",
                "This login was made with gclone's earlier browser sign-in, which this sign-in helper no longer serves. Run `gclone login` again.",
            );
        }
        if self.client_broken {
            return State::client_invalid();
        }
        // A token presented with the other client's credentials: what Google really answers is
        // unverified; the fake refuses it like a token it does not know.
        let usable = self
            .refresh_tokens
            .get(token)
            .is_some_and(|t| t.valid && t.legacy == legacy);
        if !usable {
            return Resp::auth_error(
                400,
                "invalid_grant",
                "Google rejected the sign-in code or refresh token: it is expired, revoked or already used.",
            );
        }
        if let Some(refused) = self.scope_not_allowed() {
            return refused;
        }
        let access_token = self.issue_access_token();
        Resp::auth_json(
            200,
            &json!({ "access_token": access_token, "expires_in": 3599, "scope": self.granted_scope }),
        )
    }

    /// `403 scope_not_allowed` when "Google" granted anything beyond the Worker's own scopes
    /// (§2.3): no token leaves the Worker then, on `/device/poll` or on `/refresh`.
    fn scope_not_allowed(&self) -> Option<Resp> {
        let excess: Vec<&str> = self
            .granted_scope
            .split(' ')
            .filter(|s| !s.is_empty() && !ALLOWED_SCOPES.contains(s))
            .collect();
        if excess.is_empty() {
            return None;
        }
        Some(Resp::auth_error(
            403,
            "scope_not_allowed",
            &format!(
                "Google granted more access than gclone asks for, so nothing was handed out. If you did not \
                 expect this, remove gclone at https://myaccount.google.com/permissions; then run `gclone login` \
                 again. Not asked for: {}",
                excess.join(", ")
            ),
        ))
    }

    fn issue_access_token(&mut self) -> String {
        let token = format!("at-{}", self.next());
        self.access_tokens.insert(token.clone());
        token
    }

    /// Grant-wide, as documented for Google: every refresh and access token dies.
    fn revoke_everything(&mut self) {
        self.refresh_tokens
            .values_mut()
            .for_each(|t| t.valid = false);
        self.access_tokens.clear();
    }

    fn revoke(&mut self, req: &Request) -> Resp {
        if req.method.as_str() != "POST" {
            return Resp::empty(405).header("Allow", "POST");
        }
        self.note(Route::Revoke, req);
        if let Some(injected) = self.take_fault(Route::Revoke, req) {
            return injected;
        }
        let token = url::form_urlencoded::parse(&req.body)
            .find(|(k, _)| k == "token")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        let live = self.refresh_tokens.get(&token).is_some_and(|t| t.valid)
            || self.access_tokens.contains(&token);
        if !live {
            return Resp::auth_json(
                400,
                &json!({ "error": "invalid_token", "error_description": "Token expired or revoked" }),
            );
        }
        self.revoke_everything();
        self.revoked.push(token);
        Resp::auth_json(200, &json!({}))
    }
}

/// A POST body of the auth Worker: `application/json`, at most 8 KiB, a JSON object.
fn read_json_object(req: &Request) -> Result<serde_json::Map<String, Value>, Resp> {
    let media_type = req
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media_type != "application/json" {
        return Err(Resp::auth_error(
            415,
            "unsupported_media_type",
            "The request body must be application/json.",
        ));
    }
    if req.body.len() > AUTH_BODY_MAX {
        return Err(Resp::auth_error(
            413,
            "payload_too_large",
            &format!("The request body is larger than {AUTH_BODY_MAX} bytes."),
        ));
    }
    match serde_json::from_slice::<Value>(&req.body) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(Resp::auth_error(
            400,
            "invalid_request",
            "The request body must be a JSON object.",
        )),
    }
}

/// `multipart/related` → (metadata JSON, content type of each part, media bytes).
fn parse_multipart<'a>(
    content_type: &str,
    body: &'a [u8],
) -> Result<(Value, Vec<String>, &'a [u8]), String> {
    if !content_type.starts_with("multipart/related") {
        return Err("Content-Type must be multipart/related".into());
    }
    let boundary = content_type
        .split(';')
        .find_map(|p| p.trim().strip_prefix("boundary="))
        .map(|b| b.trim_matches('"'))
        .filter(|b| !b.is_empty())
        .ok_or("no boundary parameter")?;
    let open = format!("--{boundary}\r\n");
    let next = format!("\r\n--{boundary}\r\n");
    let close = format!("\r\n--{boundary}--");
    let part_type = |headers: &[u8]| -> Result<String, String> {
        String::from_utf8_lossy(headers)
            .lines()
            .find_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.eq_ignore_ascii_case("content-type")
                    .then(|| value.trim().to_string())
            })
            .ok_or_else(|| "a part without Content-Type".to_string())
    };

    let rest = body
        .strip_prefix(open.as_bytes())
        .ok_or("the body does not start with the boundary")?;
    // The metadata part is small: bounded searches keep a 4 MiB body cheap.
    let head = &rest[..rest.len().min(64 * 1024)];
    let h1 = find(head, b"\r\n\r\n").ok_or("the first part has no header end")?;
    let m1 = find(&head[h1..], next.as_bytes()).ok_or("the first part is not terminated")? + h1;
    let metadata: Value = serde_json::from_slice(&rest[h1 + 4..m1])
        .map_err(|e| format!("metadata is not JSON: {e}"))?;
    let second = &rest[m1 + next.len()..];
    let head = &second[..second.len().min(4096)];
    let h2 = find(head, b"\r\n\r\n").ok_or("the second part has no header end")?;
    let media = &second[h2 + 4..];
    let media = media.strip_suffix(b"\r\n").unwrap_or(media);
    let media = media
        .strip_suffix(close.as_bytes())
        .ok_or("the body does not end with the closing boundary")?;
    Ok((
        metadata,
        vec![part_type(&rest[..h1])?, part_type(&second[..h2])?],
        media,
    ))
}

enum Term {
    Parent(String),
    Name(String),
    Trashed(bool),
}

/// The `q` shapes of §6.4: `'<id>' in parents`, `name = '<text>'`, `trashed = <bool>`, joined by `and`.
fn parse_q(q: &str) -> Option<Vec<Term>> {
    fn quoted(s: &str) -> Option<(String, &str)> {
        let mut out = String::new();
        let mut chars = s.strip_prefix('\'')?.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => out.push(chars.next()?.1),
                '\'' => return Some((out, &s[i + 2..])),
                c => out.push(c),
            }
        }
        None
    }
    let mut terms = Vec::new();
    let mut rest = q.trim();
    loop {
        if rest.starts_with('\'') {
            let (id, after) = quoted(rest)?;
            rest = after.strip_prefix(" in parents")?;
            terms.push(Term::Parent(id));
        } else if let Some(after) = rest.strip_prefix("name = ") {
            let (name, after) = quoted(after)?;
            rest = after;
            terms.push(Term::Name(name));
        } else {
            let after = rest.strip_prefix("trashed = ")?;
            let (value, after) = match after.strip_prefix("false") {
                Some(after) => (false, after),
                None => (true, after.strip_prefix("true")?),
            };
            rest = after;
            terms.push(Term::Trashed(value));
        }
        if rest.is_empty() {
            return Some(terms);
        }
        rest = rest.strip_prefix(" and ")?;
    }
}

// ---------------------------------------------------------------------------------------------
// The public face
// ---------------------------------------------------------------------------------------------

struct Responder(Arc<Mutex<State>>);

impl Respond for Responder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let template = state.handle(request).into_template();
        if state.date_skew_ms == 0 {
            return template;
        }
        let at = std::time::UNIX_EPOCH
            + Duration::from_millis(now_ms().saturating_add_signed(state.date_skew_ms));
        template.insert_header("date", httpdate::fmt_http_date(at).as_str())
    }
}

/// Clones share one server and one state.
#[derive(Clone)]
pub struct FakeDrive {
    server: Arc<MockServer>,
    state: Arc<Mutex<State>>,
    base: String,
}

impl FakeDrive {
    pub async fn start() -> Self {
        // No request recording: uploads of tens of MiB would be kept for good.
        let server = MockServer::builder()
            .disable_request_recording()
            .start()
            .await;
        let base = server.uri();
        let state = Arc::new(Mutex::new(State::new(base.clone())));
        Mock::given(wiremock::matchers::any())
            .respond_with(Responder(state.clone()))
            .mount(&server)
            .await;
        FakeDrive {
            server: Arc::new(server),
            state,
            base,
        }
    }

    fn st(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `http://127.0.0.1:<port>` — the server all three parts live on.
    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn endpoints(&self) -> DriveEndpoints {
        DriveEndpoints {
            api: self.base.clone(),
            upload: format!("{}/upload", self.base),
        }
    }

    /// base = "http://127.0.0.1:<port>/auth", revoke_url = "http://127.0.0.1:<port>/revoke".
    pub fn auth(&self) -> AuthEndpoints {
        AuthEndpoints {
            base: format!("{}/auth", self.base),
            revoke_url: format!("{}/revoke", self.base),
        }
    }

    /// Pre-issued refresh token "rt-ok" (of the device client); memory-only cache.
    pub fn token_provider(&self) -> Arc<TokenProvider> {
        self.token_provider_for("rt-ok")
    }

    pub fn token_provider_for(&self, refresh_token: &str) -> Arc<TokenProvider> {
        let http = gclone::auth::http_client().expect("http client");
        Arc::new(TokenProvider::new(
            http,
            self.auth(),
            refresh_token.to_string(),
            AuthClient::Device,
            None,
        ))
    }

    // --- the fake auth Worker (§2.3) and the fake user at google.com/device

    /// Plays the user: enters `user_code` at "Google" and approves, signed in as the account of
    /// `set_login_email`. The device's next poll then gets its answer. Panics on a code no
    /// `/device/start` handed out, or one that is not pending any more.
    pub fn approve(&self, user_code: &str) {
        let mut st = self.st();
        let email = st.login_email.clone();
        st.pending(user_code).state = DeviceState::Approved(email);
    }

    /// The user enters `user_code` and refuses: the next poll → 403 access_denied.
    pub fn deny(&self, user_code: &str) {
        self.st().pending(user_code).state = DeviceState::Denied;
    }

    /// Every login that is still pending runs out: its next poll → 400 expired_token.
    pub fn expire_codes(&self) {
        for login in self.st().devices.values_mut() {
            if matches!(login.state, DeviceState::Pending) {
                login.state = DeviceState::Expired;
            }
        }
    }

    /// The next `times` polls of a pending login → 400 slow_down, whatever their timing.
    pub fn slow_down(&self, times: u32) {
        self.st().slow_down = times;
    }

    /// How often a poll was answered 400 slow_down because it came less than the login's
    /// `interval` after the previous one (the injected `slow_down(n)` answers do not count).
    pub fn early_polls(&self) -> u32 {
        self.st().early_polls
    }

    /// `interval` of later /device/start answers, in seconds (default 0.02 — Google: 5). A
    /// login started afterwards is held to it: a poll that comes sooner after the previous
    /// one is answered 400 slow_down.
    pub fn set_poll_interval(&self, secs: f64) {
        self.st().poll_interval = secs;
    }

    /// `expires_in` of later /device/start answers, in seconds (default 1800, as Google). A
    /// login started afterwards runs out by itself after that time: 400 expired_token.
    pub fn set_code_lifetime(&self, secs: f64) {
        self.st().code_lifetime = secs;
    }

    /// `verification_url` of later /device/start answers (default: Google's page).
    pub fn set_verification_url(&self, url: &str) {
        self.st().verification_url = url.to_string();
    }

    /// "Google's" token answer for an approved login carries no ID token: the poll that
    /// redeems the code is answered 403 grant_unusable — and the code is used up by it.
    pub fn omit_id_token(&self) {
        self.st().no_id_token = true;
    }

    /// The user code of the newest /device/start answer.
    pub fn last_user_code(&self) -> Option<String> {
        self.st().last_user_code.clone()
    }

    /// An auth Worker before 0.4.0 that has (or lacks, the default) the GOOGLE_LEGACY_CLIENT_*
    /// secrets: whether /auth/refresh serves a request without `"client": "device"`. The
    /// Worker of 0.4.0 never serves one, whatever it has configured: that is the default here.
    pub fn set_legacy_client(&self, configured: bool) {
        self.st().legacy_client = if configured {
            LegacyClient::Configured
        } else {
            LegacyClient::Absent
        };
    }

    /// An auth Worker before 0.4.0 with exactly one of its two GOOGLE_LEGACY_CLIENT_* secrets:
    /// /auth/refresh without `"client": "device"` → 500 server_misconfigured; nothing else
    /// changes. (The Worker of 0.4.0 answers such a request 400 invalid_grant in every state.)
    pub fn set_legacy_client_half_set(&self) {
        self.st().legacy_client = LegacyClient::HalfSet;
    }

    /// A live refresh token of the legacy client, as a device that logged in before 0.2.0 holds.
    pub fn add_legacy_token(&self) -> String {
        let mut st = self.st();
        let token = format!("rt-legacy-{}", st.next());
        st.refresh_tokens.insert(
            token.clone(),
            Issued {
                valid: true,
                legacy: true,
            },
        );
        token
    }

    /// The account the fake user signs in with (default "me@example.com").
    pub fn set_login_email(&self, email: &str) {
        self.st().login_email = email.to_string();
    }

    /// Default ["me@example.com"].
    pub fn set_allowed_emails(&self, emails: &[&str]) {
        self.st().allowed_emails = emails.iter().map(|e| e.to_string()).collect();
    }

    /// The `scope` Google grants (default: openid + userinfo.email + drive.file).
    pub fn set_granted_scope(&self, scope: &str) {
        self.st().granted_scope = scope.to_string();
    }

    /// /auth/device/start, /auth/device/poll and /auth/refresh → 500 client_invalid.
    pub fn break_client(&self) {
        self.st().client_broken = true;
    }

    /// As if revoked at Google: every refresh token issued so far → 400 invalid_grant at
    /// /auth/refresh, and every access token → 401 on the Drive routes.
    pub fn revoke_refresh_token(&self) {
        self.st().revoke_everything();
    }

    /// One per completed login ("rt-1", "rt-2", …), all valid together.
    pub fn issued_refresh_tokens(&self) -> Vec<String> {
        self.st().issued_refresh_tokens.clone()
    }

    /// Tokens /revoke accepted (each time ALL refresh tokens were invalidated, like Google).
    pub fn revoked(&self) -> Vec<String> {
        self.st().revoked.clone()
    }

    /// /auth/device/poll answers carry refresh_token_expires_in.
    pub fn set_refresh_expires_in(&self, secs: Option<u64>) {
        self.st().refresh_expires_in = secs;
    }

    // --- Drive

    /// DriveConfig with these endpoints and a fast pacer (no pacing, millisecond backoff).
    pub fn backend(&self) -> DriveBackend {
        self.backend_with(self.token_provider(), fast_pacer())
    }

    pub fn backend_with(&self, tokens: Arc<TokenProvider>, pacer: PacerConfig) -> DriveBackend {
        let cfg = DriveConfig {
            endpoints: self.endpoints(),
            pacer,
            ..DriveConfig::default()
        };
        let backend = DriveBackend::new(tokens, cfg).expect("DriveBackend::new");
        backend.pacer().set_backoff_unit(Duration::from_millis(2));
        backend
    }

    /// Drive routes: JSON error envelope of §6.4.1; auth routes: the §2.3 error object with
    /// `reason` as its code (429 carries `Retry-After: 1`). `times = u32::MAX`: until further notice.
    pub fn fail_next(&self, route: Route, times: u32, status: u16, reason: &str) {
        self.push_fault(route, times, status, Ok(reason.to_string()));
    }

    /// Non-JSON body (HTML / plain text). A 3xx status carries a `Location` back to the route.
    pub fn fail_next_raw(&self, route: Route, times: u32, status: u16, body: &str) {
        self.push_fault(route, times, status, Err(body.to_string()));
    }

    fn push_fault(&self, route: Route, times: u32, status: u16, body: Result<String, String>) {
        if times > 0 {
            let fault = Fault {
                times,
                status,
                body,
            };
            self.st().faults.entry(route).or_default().push_back(fault);
        }
    }

    /// One 401 on that route (e.g. SessionPut for part k), then normal. Calls add up.
    pub fn unauthorized_once(&self, route: Route) {
        self.fail_next(route, 1, 401, "authError");
    }

    /// Perform the effect, answer 503.
    pub fn lose_response_once(&self, route: Route) {
        *self.st().lose_response.entry(route).or_default() += 1;
    }

    /// Next SessionPut persists only `bytes` (rounded down to 256 KiB) then 503.
    pub fn ack_only(&self, bytes: u64) {
        self.ack_only_times(bytes, 1);
    }

    /// The next `times` part PUTs each persist only `bytes` (rounded down to 256 KiB) and answer
    /// 503 — a link that cuts every part while Drive keeps what arrived. `u32::MAX`: until
    /// further notice.
    pub fn ack_only_times(&self, bytes: u64, times: u32) {
        self.st().ack_only = (times > 0).then_some((bytes, times));
    }

    /// The next `times` part PUTs are not kept; each is answered `308` with the `Range` the
    /// session had before (Google: "do not assume the server received all bytes sent").
    pub fn drop_parts(&self, times: u32) {
        self.st().drop_parts = times;
    }

    /// The next `answers` requests that would complete a session — its last part, then status
    /// queries — are answered `308` with the full `Range` instead; the object appears with the
    /// first status query after them. Injected: whether real Drive answers like this while it
    /// finalises is unverified.
    pub fn hold_completion(&self, answers: u32) {
        self.st().hold_completion = answers;
    }

    /// The next 308 has no Range header (and the session then holds nothing).
    pub fn omit_range_header_once(&self) {
        self.st().omit_range_once = true;
    }

    /// SessionPut → 404.
    pub fn expire_sessions(&self) {
        self.st().sessions_expired = true;
    }

    /// Where the 409 for an existing id arrives. Multipart and ResumableInit are the default
    /// places; `SessionPut` moves the resumable one to the completing request.
    pub fn conflict_at(&self, route: Route) {
        self.st().conflict_at_completion = route == Route::SessionPut;
    }

    /// 409 once although no object with that id exists (stat → 404). `SessionPut` = at completion.
    pub fn conflict_then_absent(&self, route: Route) {
        self.st().phantom_conflicts.insert(route);
    }

    /// The next finished create answers in the default projection although `fields=` was sent.
    pub fn strip_completion_body_once(&self) {
        self.st().strip_completion_once = true;
    }

    /// Every answer from now on carries a `Date` header that is `ms` away from this
    /// machine's clock (positive: the server's clock runs ahead). 0 restores the real one.
    pub fn set_date_skew_ms(&self, ms: i64) {
        self.st().date_skew_ms = ms;
    }

    /// New objects invisible for that many list calls.
    pub fn set_list_lag(&self, lists: u32) {
        self.st().list_lag = lists;
    }

    /// Short pages with nextPageToken.
    pub fn set_page_cap(&self, n: usize) {
        self.st().page_cap = Some(n.max(1));
    }

    /// The next request that carries a pageToken is refused with 400.
    pub fn reject_page_token_once(&self) {
        self.st().reject_page_token_once = true;
    }

    pub fn mark_abusive(&self, id: &str) {
        if let Some(obj) = self.st().objects.get_mut(id) {
            obj.abusive = true;
        }
    }

    /// Turns the object into a Google-native file (a Google Doc): its metadata keeps the name
    /// and reports a size, but carries no `md5Checksum`, and its content cannot be downloaded
    /// (403 `fileNotDownloadable`). Any token holder can create such a file under any name.
    pub fn make_native(&self, id: &str) {
        if let Some(obj) = self.st().objects.get_mut(id) {
            obj.native = true;
            obj.mime = "application/vnd.google-apps.document".into();
        }
    }

    pub fn hits(&self, route: Route) -> u64 {
        self.st().hits.get(&route).copied().unwrap_or(0)
    }

    pub fn object(&self, id: &str) -> Option<Vec<u8>> {
        self.st().objects.get(id).map(|o| o.data.to_vec())
    }

    /// Ids of all stored objects, oldest first.
    pub fn object_ids(&self) -> Vec<String> {
        self.st().order.clone()
    }

    /// Every Content-Range of a part PUT (start, len, total), for 256-KiB assertions.
    pub fn session_requests(&self) -> Vec<(u64, u64, u64)> {
        self.st().session_requests.clone()
    }

    /// Status queries (`Content-Range: bytes */total`) seen so far.
    pub fn status_queries(&self) -> u64 {
        self.st().status_queries
    }

    /// Every request of `route`, oldest first.
    pub fn requests(&self, route: Route) -> Vec<Seen> {
        self.st()
            .seen
            .iter()
            .filter(|s| s.route == route)
            .cloned()
            .collect()
    }

    /// Inspection only: the direct children of a folder, oldest first — those in the trash
    /// included, flagged.
    pub fn children(&self, parent: &str) -> Vec<Child> {
        let st = self.st();
        let children = st
            .order
            .iter()
            .filter(|id| st.objects[*id].parent == parent);
        children
            .map(|id| {
                let obj = &st.objects[id];
                Child {
                    id: id.clone(),
                    name: obj.name.clone(),
                    size: obj.data.len(),
                    trashed: st.effectively_trashed(id),
                    is_folder: obj.mime == FOLDER_MIME,
                }
            })
            .collect()
    }

    /// Inspection only: the folder at this path from the top of My Drive (the oldest one of
    /// each name that is not in the trash).
    pub fn path(&self, names: &[&str]) -> Option<String> {
        let mut at = ROOT_ID.to_string();
        for name in names {
            let next = self.children(&at).into_iter();
            at = next
                .filter(|c| c.is_folder && !c.trashed && c.name == *name)
                .map(|c| c.id)
                .next()?;
        }
        Some(at)
    }
}

/// One object as `FakeDrive::children` shows it.
#[derive(Clone, Debug)]
pub struct Child {
    pub id: String,
    pub name: String,
    pub size: usize,
    /// In the trash itself, or inside a folder that is.
    pub trashed: bool,
    pub is_folder: bool,
}

/// Practically no pacing (throttling still halves the rates); the §6.1 attempt count and breaker.
pub fn fast_pacer() -> PacerConfig {
    let (fast, floor) = (1_000_000.0, 10_000.0);
    PacerConfig {
        write_start: fast,
        write_min: floor,
        write_max: fast,
        read_start: fast,
        read_min: floor,
        read_max: fast,
        units_per_min: u32::MAX,
        ..PacerConfig::default()
    }
}

//! restic's REST protocol over hyper (SPEC §7.6): one request → one call of the store → one
//! response. Every failure becomes a status; nothing here fails a connection.
//!
//! Two front ends share it: `--stdio` (HTTP/2 over the pipes restic opened, one repository, no
//! authentication — the pipe belongs to the restic process that started gclone) and `--port`
//! (HTTP/1.1 on loopback, every repository of the account under its own prefix, behind a
//! token).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures_util::StreamExt as _;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::http::request::Parts;
use hyper::{Method, Request, Response, StatusCode};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::proto::{self, Route};
use super::{
    Asked, Error, FileType, H2_CONN_WINDOW, H2_MAX_STREAMS, H2_STREAM_WINDOW, Opened, Options,
    Repo, RepoName, Target, note,
};
use crate::backend::{Backend, ByteStream};
use crate::util;
use crate::web::http::{Body, Failure};

/// Request-body frames waiting between restic and the upload: restic is read only as fast as
/// Drive takes the bytes.
const BODY_QUEUE: usize = 4;
/// Download chunks waiting between Drive and restic.
const CHUNK_QUEUE: usize = 4;

enum Mode<B: Backend> {
    /// `--stdio`: the repository named on the command line, at `/`.
    Single(Arc<Repo<B>>),
    /// `--port`: `/<repo>/…`, for whoever holds the token.
    Multi {
        backend: Arc<B>,
        token: String,
        /// The `Host` values this listener answers to.
        hosts: Vec<String>,
        repos: Mutex<HashMap<RepoName, Arc<Repo<B>>>>,
    },
}

pub struct App<B: Backend> {
    mode: Mode<B>,
    opts: Options,
}

fn respond(
    status: StatusCode,
    content_type: &'static str,
    body: impl Into<Bytes>,
) -> Response<Body> {
    let body: Bytes = body.into();
    let mut res = Response::new(Body::full(body.clone()));
    *res.status_mut() = status;
    let headers = res.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    res
}

/// A status with one line of text — for a person with `curl`; restic ignores it.
fn text(status: StatusCode, message: &str) -> Response<Body> {
    respond(status, "text/plain; charset=utf-8", format!("{message}\n"))
}

fn set(res: &mut Response<Body>, name: header::HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        res.headers_mut().insert(name, value);
    }
}

fn internal() -> Error {
    Error::Integrity("internal error: a task failed".into())
}

/// The next data frame of a request body; trailers are skipped.
async fn next_data(body: &mut Incoming) -> Option<Result<Bytes, hyper::Error>> {
    use hyper::body::Body as _;
    loop {
        let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut *body).poll_frame(cx)).await;
        match frame? {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    return Some(Ok(data));
                }
            }
            Err(e) => return Some(Err(e)),
        }
    }
}

/// Reads a request body to its end and throws it away: Go's HTTP/1 client reliably sees a
/// status only after its body was taken.
async fn drain(mut body: Incoming) {
    while let Some(Ok(_)) = next_data(&mut body).await {}
}

/// Hands the request body to the store, frame by frame. When the store has stopped listening
/// the rest is read and dropped; when the body fails, the store is told.
async fn forward(mut body: Incoming, tx: mpsc::Sender<std::io::Result<Bytes>>) {
    let mut tx = Some(tx);
    loop {
        match next_data(&mut body).await {
            None => return,
            Some(Ok(data)) => {
                if let Some(open) = &tx
                    && open.send(Ok(data)).await.is_err()
                {
                    tx = None;
                }
            }
            Some(Err(e)) => {
                if let Some(open) = tx {
                    let _ = open.send(Err(std::io::Error::other(e))).await;
                }
                return;
            }
        }
    }
}

/// A download as a response body of exactly `len` bytes. A stream that fails or ends short is
/// an error of the body — HTTP/2 resets the stream, HTTP/1 cuts the connection — and restic
/// retries. Dropping the body stops the download.
fn stream_body(len: u64, mut stream: ByteStream) -> Body {
    if len == 0 {
        return Body::empty();
    }
    let (tx, rx) = mpsc::channel(CHUNK_QUEUE);
    tokio::spawn(async move {
        loop {
            let next = tokio::select! {
                next = stream.next() => next,
                () = tx.closed() => return,
            };
            let item = match next {
                None => return,
                Some(Ok(chunk)) if chunk.is_empty() => continue,
                Some(Ok(chunk)) => Ok(chunk),
                Some(Err(e)) => Err(Failure {
                    status: StatusCode::BAD_GATEWAY,
                    message: e.to_string(),
                }),
            };
            let failed = item.is_err();
            if tx.send(item).await.is_err() || failed {
                return;
            }
        }
    });
    Body::Stream {
        first: None,
        rx,
        left: len,
    }
}

impl<B: Backend> App<B> {
    /// `--stdio`: one repository, no prefix, no authentication.
    pub fn single(backend: Arc<B>, repo: RepoName, opts: Options) -> Arc<Self> {
        let opts = Options {
            listener: false,
            ..opts
        };
        Arc::new(App {
            mode: Mode::Single(Repo::new(backend, repo, opts)),
            opts,
        })
    }

    /// `--port`: `hosts` are the authorities the listener is reached under (the first one is
    /// the one that is documented), `token` the Basic password every request has to carry.
    pub fn listener(
        backend: Arc<B>,
        token: String,
        hosts: Vec<String>,
        opts: Options,
    ) -> Arc<Self> {
        let opts = Options {
            listener: true,
            ..opts
        };
        Arc::new(App {
            mode: Mode::Multi {
                backend,
                token,
                hosts,
                repos: Mutex::new(HashMap::new()),
            },
            opts,
        })
    }

    /// The end of the run: cancels the uploads that nobody can be answered for any more and
    /// waits until each has cleaned up after itself (`Repo::close`). The caller bounds the wait.
    pub async fn close(&self) {
        let repos: Vec<Arc<Repo<B>>> = match &self.mode {
            Mode::Single(repo) => vec![repo.clone()],
            Mode::Multi { repos, .. } => {
                let repos = repos.lock().unwrap_or_else(|e| e.into_inner());
                repos.values().cloned().collect()
            }
        };
        futures_util::future::join_all(repos.iter().map(|repo| repo.close())).await;
    }

    /// The listener's three checks, in this order: `Host`, no `Origin`, the token. A refusal
    /// is answered at once and closes the connection; the body of such a request is never read.
    fn refusal(&self, head: &Parts) -> Option<Response<Body>> {
        let Mode::Multi { token, hosts, .. } = &self.mode else {
            return None;
        };
        let mut res = if !crate::web::host_allowed(&head.headers, &head.uri, hosts) {
            let only = hosts.first().map_or("127.0.0.1", String::as_str);
            let message = format!("gclone serve restic answers only as http://{only}/");
            text(StatusCode::FORBIDDEN, &message)
        } else if head.headers.contains_key(header::ORIGIN) {
            // restic never sends one; a browser does on every cross-site write.
            text(
                StatusCode::FORBIDDEN,
                "Requests from web pages are refused.",
            )
        } else {
            let mut given = head.headers.get_all(header::AUTHORIZATION).iter();
            let password = match (given.next(), given.next()) {
                (Some(one), None) => one.to_str().ok().and_then(proto::basic_password),
                _ => None,
            };
            if password.is_some_and(|p| util::ct_eq(&p, token.as_bytes())) {
                return None;
            }
            let mut res = text(
                StatusCode::UNAUTHORIZED,
                "gclone serve restic: the password is the token printed at start \
                 (RESTIC_REST_PASSWORD).",
            );
            set(&mut res, header::WWW_AUTHENTICATE, "Basic realm=\"gclone\"");
            res
        };
        set(&mut res, header::CONNECTION, "close");
        Some(res)
    }

    /// The repository a path names, and the rest of the path.
    fn repo<'a>(&self, path: &'a str) -> Option<(Arc<Repo<B>>, &'a str)> {
        match &self.mode {
            Mode::Single(repo) => Some((repo.clone(), path.strip_prefix('/')?)),
            Mode::Multi { backend, repos, .. } => {
                let (name, rest) = proto::split_repo(path)?;
                let mut repos = repos.lock().unwrap_or_else(|e| e.into_inner());
                let repo = repos
                    .entry(name.clone())
                    .or_insert_with(|| Repo::new(backend.clone(), name, self.opts));
                Some((repo.clone(), rest))
            }
        }
    }

    /// One request → one response. Never fails.
    pub async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Response<Body> {
        let (head, body) = req.into_parts();
        tracing::debug!("restic: {} {}", head.method, head.uri.path());
        if let Some(refused) = self.refusal(&head) {
            return refused;
        }
        let mut body = Some(body);
        let mut res = self.answer(&head, &mut body).await;
        // An answer that did not need the body still waits for its end.
        if let Some(unread) = body {
            drain(unread).await;
        }
        if head.method == Method::HEAD {
            *res.body_mut() = Body::empty();
        }
        res
    }

    async fn answer(&self, head: &Parts, body: &mut Option<Incoming>) -> Response<Body> {
        // The raw path, byte for byte: nothing is decoded.
        let found = self.repo(head.uri.path());
        let Some((repo, route)) = found.and_then(|(repo, rest)| Some((repo, proto::route(rest)?)))
        else {
            return text(StatusCode::NOT_FOUND, "no such path");
        };
        let (method, name) = (&head.method, repo.name());
        let what = match route {
            Route::Create => format!("{method} {name}"),
            Route::List(ty) => format!("{method} {name}:{}/", ty.dir()),
            Route::File(Target::Config) => format!("{method} {name}:config"),
            Route::File(Target::File(ty, _)) => format!("{method} {name}:{}", ty.dir()),
        };
        let done = match (route, method) {
            (Route::Create, &Method::POST) => {
                let mut asked = head.uri.query().unwrap_or("").split('&');
                if !asked.any(|pair| pair == "create=true") {
                    return text(StatusCode::BAD_REQUEST, "POST here creates: ?create=true");
                }
                if let Some(empty) = body.take() {
                    drain(empty).await;
                }
                detached(async move { repo.create().await })
                    .await
                    .map(|()| text(StatusCode::OK, "created"))
            }
            (Route::List(ty), &Method::GET) => repo.list(ty).await.map(|entries| {
                respond(StatusCode::OK, proto::LIST_TYPE, proto::list_json(&entries))
            }),
            (Route::File(t), &Method::HEAD) => repo.head(&t).await.map(|size| {
                let mut res = Response::new(Body::empty());
                res.headers_mut()
                    .insert(header::CONTENT_LENGTH, HeaderValue::from(size));
                res
            }),
            (Route::File(t), &Method::GET) => {
                let range = head.headers.get(header::RANGE);
                let range = range.and_then(|v| v.to_str().ok());
                repo.open(&t, range).await.map(download)
            }
            (Route::File(t), &Method::POST) => match body.take() {
                Some(body) => upload(repo, t, head, body)
                    .await
                    .map(|()| text(StatusCode::OK, "stored")),
                None => Err(internal()),
            },
            (Route::File(t), &Method::DELETE) => detached(async move { repo.remove(&t).await })
                .await
                .map(|()| text(StatusCode::OK, "removed")),
            (route, _) => {
                let mut res = text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
                set(&mut res, header::ALLOW, route.allow());
                return res;
            }
        };
        done.unwrap_or_else(|e| {
            let listing = matches!(route, Route::List(_));
            let asked = match (route, method) {
                (Route::List(_), _) => Asked::Listing,
                (Route::File(Target::File(FileType::Locks, _)), &Method::POST) => Asked::Lock,
                _ => Asked::Other,
            };
            if let Some(line) = e.note(&what, asked) {
                note(&line);
            }
            tracing::debug!("restic: {what}: {e}");
            text(proto::status(&e, listing), &e.to_string())
        })
    }
}

/// Work that changes Drive runs in a task of its own: a request that restic gave up on must
/// not leave a Drive call cut in the middle.
async fn detached<T: Send + 'static>(
    work: impl Future<Output = Result<T, Error>> + Send + 'static,
) -> Result<T, Error> {
    tokio::spawn(work).await.unwrap_or_else(|_| Err(internal()))
}

/// `POST <file>`: the store works in its own task and reads the body through a channel. When
/// this handler is dropped before the result arrived — restic reset the stream, or went away —
/// the guard tells the store that nobody waits for the answer: the upload is aborted or, if
/// Drive has it already, trashed again (an index stays: `Repo::save`).
async fn upload<B: Backend>(
    repo: Arc<Repo<B>>,
    t: Target,
    head: &Parts,
    body: Incoming,
) -> Result<(), Error> {
    let announced = head.headers.get(header::CONTENT_LENGTH);
    let len = announced
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let Some(len) = len else {
        drain(body).await;
        return Err(Error::LengthRequired);
    };
    let cancel = CancellationToken::new();
    let guard = cancel.clone().drop_guard();
    let (tx, rx) = mpsc::channel(BODY_QUEUE);
    let task = tokio::spawn(async move { repo.save(&t, len, rx, cancel).await });
    forward(body, tx).await;
    let done = task.await;
    guard.disarm();
    done.unwrap_or_else(|_| Err(internal()))
}

fn download(opened: Opened) -> Response<Body> {
    let (status, size, range, stream) = match opened {
        Opened::Whole { size, stream } => (StatusCode::OK, size, 0..size, stream),
        Opened::Part {
            size,
            range,
            stream,
        } => (StatusCode::PARTIAL_CONTENT, size, range, stream),
        Opened::Unsatisfiable { size } => {
            let mut res = text(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "the range starts after the end",
            );
            set(&mut res, header::CONTENT_RANGE, &format!("bytes */{size}"));
            return res;
        }
    };
    let len = range.end - range.start;
    let mut res = Response::new(stream_body(len, stream));
    *res.status_mut() = status;
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    // Exact: restic takes a bounded range without it for a permanent error.
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if status == StatusCode::PARTIAL_CONTENT {
        let value = format!("bytes {}-{}/{size}", range.start, range.end - 1);
        set(&mut res, header::CONTENT_RANGE, &value);
    }
    res
}

/// Serves one HTTP/2 connection — restic's, over the two pipes — until the peer closes it.
/// gclone never closes it by itself (no GOAWAY): restic has this one connection and cannot
/// open another.
pub async fn serve_h2<B, IO>(app: Arc<App<B>>, io: IO) -> Result<(), hyper::Error>
where
    B: Backend,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |req| {
        let app = app.clone();
        async move { Ok::<_, std::convert::Infallible>(app.handle(req).await) }
    });
    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .timer(hyper_util::rt::TokioTimer::new())
        .max_concurrent_streams(H2_MAX_STREAMS)
        .initial_stream_window_size(H2_STREAM_WINDOW)
        .initial_connection_window_size(H2_CONN_WINDOW)
        .serve_connection(hyper_util::rt::TokioIo::new(io), service)
        .await
}

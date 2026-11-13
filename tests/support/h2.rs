//! A small HTTP/2 client for the tests of `gclone serve restic`: what restic is to the server
//! in `--stdio` mode, over any byte stream (an in-memory pipe, or the pipes of a child process).
//!
//! Included with `#[path = "support/h2.rs"] mod h2;` by `tests/restic_http.rs` and
//! `tests/restic_e2e.rs`.
#![allow(dead_code)]

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Frame, Incoming, SizeHint};
use hyper::header::HeaderMap;
use hyper::{Method, Request};
use tokio::sync::mpsc;

/// A request body: a buffer, or pieces from a channel (an `Err` resets the stream).
pub enum Out {
    Full(Option<Bytes>),
    Stream(mpsc::Receiver<std::io::Result<Bytes>>),
}

impl hyper::body::Body for Out {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match self.get_mut() {
            Out::Full(bytes) => Poll::Ready(bytes.take().map(|b| Ok(Frame::data(b)))),
            Out::Stream(rx) => rx
                .poll_recv(cx)
                .map(|item| item.map(|r| r.map(Frame::data))),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self, Out::Full(None))
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Out::Full(bytes) => SizeHint::with_exact(bytes.as_ref().map_or(0, |b| b.len() as u64)),
            Out::Stream(_) => SizeHint::default(),
        }
    }
}

pub fn full(data: &[u8]) -> Out {
    Out::Full((!data.is_empty()).then(|| Bytes::copy_from_slice(data)))
}

pub struct Res {
    pub status: u16,
    pub headers: HeaderMap,
    /// `Err`: the stream was reset while the body arrived.
    pub body: Result<Vec<u8>, String>,
}

impl Res {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    #[track_caller]
    pub fn bytes(&self) -> &[u8] {
        self.body.as_deref().expect("a complete body")
    }
}

async fn read_body(mut body: Incoming) -> Result<Vec<u8>, String> {
    use hyper::body::Body as _;
    let mut out = Vec::new();
    loop {
        let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        match frame {
            None => return Ok(out),
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    out.extend_from_slice(&data);
                }
            }
            Some(Err(e)) => return Err(e.to_string()),
        }
    }
}

/// The SHA-256 of `data` in hex: the name restic gives a file with these bytes.
pub fn sha(data: &[u8]) -> String {
    use sha2::Digest as _;
    gclone::util::hex(&sha2::Sha256::digest(data))
}

#[derive(Clone)]
pub struct H2 {
    pub send: hyper::client::conn::http2::SendRequest<Out>,
    /// Ends the connection (the server sees its input close) when aborted.
    connection: std::sync::Arc<tokio::task::JoinHandle<()>>,
}

impl H2 {
    /// HTTP/2 with prior knowledge over `io`, as restic speaks it.
    pub async fn over<IO>(io: IO) -> H2
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let io = hyper_util::rt::TokioIo::new(io);
        let exec = hyper_util::rt::TokioExecutor::new();
        let (send, connection) = hyper::client::conn::http2::handshake(exec, io)
            .await
            .expect("HTTP/2 handshake");
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        H2 {
            send,
            connection: std::sync::Arc::new(connection),
        }
    }

    /// Closes the connection, as restic does by exiting.
    pub async fn close(self) {
        self.connection.abort();
        drop(self.send);
        tokio::task::yield_now().await;
    }

    pub async fn send(
        &self,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Out,
    ) -> Res {
        let mut req = Request::builder()
            .method(method)
            .uri(format!("http://localhost{path}"));
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        let res = self
            .send
            .clone()
            .send_request(req.body(body).unwrap())
            .await
            .expect("a response");
        let (head, body) = res.into_parts();
        Res {
            status: head.status.as_u16(),
            headers: head.headers,
            body: read_body(body).await,
        }
    }

    pub async fn get(&self, path: &str) -> Res {
        self.send(Method::GET, path, &[], full(b"")).await
    }

    pub async fn range(&self, path: &str, range: &str) -> Res {
        self.send(Method::GET, path, &[("range", range)], full(b""))
            .await
    }

    pub async fn head(&self, path: &str) -> Res {
        self.send(Method::HEAD, path, &[], full(b"")).await
    }

    pub async fn post(&self, path: &str, data: &[u8]) -> Res {
        self.send(Method::POST, path, &[], full(data)).await
    }

    pub async fn delete(&self, path: &str) -> Res {
        self.send(Method::DELETE, path, &[], full(b"")).await
    }

    /// Uploads `data` under its own name.
    pub async fn save(&self, ty: &str, data: &[u8]) -> String {
        let path = format!("/{ty}/{}", sha(data));
        let res = self.post(&path, data).await;
        assert_eq!(res.status, 200, "POST {path}: {:?}", res.body);
        path
    }

    pub async fn create(&self) {
        assert_eq!(self.post("/?create=true", b"").await.status, 200);
    }
}

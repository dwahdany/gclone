//! HTTP pieces of the viewer that know nothing about the vault (SPEC §7.4): the response body,
//! query strings and entity tags. `Range`, `Content-Disposition` and the order of names are in
//! `rules` (shared with the hosted viewer) and re-exported here.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Frame, SizeHint};
use tokio::sync::mpsc;

pub use super::rules::{ByteRange, content_disposition, natural_cmp, parse_range};

/// Why a file's bytes stopped coming: the status and text of the error answer — or, once the
/// answer has begun, the reason the connection is cut.
#[derive(Debug)]
pub struct Failure {
    pub status: hyper::StatusCode,
    pub message: String,
}

/// A response body: a buffer, or decrypted file content as it arrives from the store.
pub enum Body {
    Full(Option<Bytes>),
    /// `left` bytes are still owed to the client. A stream that ends short, or with a
    /// `Failure`, is an error of the body: hyper then cuts the connection instead of ending
    /// the response, so a damaged or interrupted download never looks complete. Dropping the
    /// body (the client went away) closes the channel, which stops the download from the
    /// store.
    Stream {
        first: Option<Bytes>,
        rx: mpsc::Receiver<Result<Bytes, Failure>>,
        left: u64,
    },
}

impl Body {
    pub fn empty() -> Body {
        Body::Full(None)
    }

    pub fn full(bytes: impl Into<Bytes>) -> Body {
        let bytes = bytes.into();
        Body::Full((!bytes.is_empty()).then_some(bytes))
    }
}

impl hyper::body::Body for Body {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match self.get_mut() {
            Body::Full(bytes) => Poll::Ready(bytes.take().map(|b| Ok(Frame::data(b)))),
            Body::Stream { first, rx, left } => {
                if *left == 0 {
                    return Poll::Ready(None);
                }
                let next = match first.take() {
                    Some(bytes) => Some(Ok(bytes)),
                    None => std::task::ready!(rx.poll_recv(cx)),
                };
                Poll::Ready(Some(match next {
                    Some(Ok(mut bytes)) => {
                        bytes.truncate(usize::try_from(*left).unwrap_or(usize::MAX));
                        *left -= bytes.len() as u64;
                        Ok(Frame::data(bytes))
                    }
                    Some(Err(failure)) => Err(std::io::Error::other(failure.message)),
                    None => Err(std::io::Error::other("the download ended early")),
                }))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Body::Full(bytes) => bytes.is_none(),
            Body::Stream { left, .. } => *left == 0,
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(match self {
            Body::Full(bytes) => bytes.as_ref().map_or(0, |b| b.len() as u64),
            Body::Stream { left, .. } => *left,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Query strings
// ---------------------------------------------------------------------------------------------

/// Malformed input from the client (`400`).
#[derive(Debug, PartialEq, Eq)]
pub struct BadRequest(pub &'static str);

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `application/x-www-form-urlencoded` → text. Strict: a `%` that does not start two hex
/// digits, or bytes that are not UTF-8, are refused rather than repaired.
fn decode(s: &str) -> Result<String, BadRequest> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = bytes.get(i + 1).copied().and_then(hex_digit);
                let lo = bytes.get(i + 2).copied().and_then(hex_digit);
                match (hi, lo) {
                    (Some(hi), Some(lo)) => out.push(hi << 4 | lo),
                    _ => return Err(BadRequest("malformed percent-encoding")),
                }
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| BadRequest("the query is not UTF-8"))
}

/// The parameters of a query string. A name given twice is refused: which one a handler would
/// take must not depend on its order.
pub fn parse_query(query: Option<&str>) -> Result<Vec<(String, String)>, BadRequest> {
    let mut out: Vec<(String, String)> = Vec::new();
    for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = decode(name)?;
        if out.iter().any(|(n, _)| *n == name) {
            return Err(BadRequest("a query parameter is given twice"));
        }
        out.push((name, decode(value)?));
    }
    Ok(out)
}

pub fn param<'a>(query: &'a [(String, String)], name: &str) -> Option<&'a str> {
    query
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

// ---------------------------------------------------------------------------------------------
// Entity tags
// ---------------------------------------------------------------------------------------------

/// The entity tag of file content: its BLAKE3 hash from the authenticated index entry.
pub fn etag(hash: &[u8; 32]) -> String {
    format!("\"{}\"", crate::util::hex(hash))
}

/// `If-None-Match` (weak comparison, a list, or `*`) against the tag of what would be sent.
pub fn none_match(header: &str, etag: &str) -> bool {
    header.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_are_decoded_strictly() {
        let q = parse_query(Some("path=a%2Fb%20c+d&sort=name&flag&x=%E2%9C%93")).unwrap();
        assert_eq!(param(&q, "path"), Some("a/b c d"));
        assert_eq!(param(&q, "sort"), Some("name"));
        assert_eq!(param(&q, "flag"), Some(""));
        assert_eq!(param(&q, "x"), Some("✓"));
        assert_eq!(param(&q, "absent"), None);
        assert!(parse_query(None).unwrap().is_empty());
        assert!(parse_query(Some("")).unwrap().is_empty());
        assert_eq!(
            param(&parse_query(Some("a=1&&b=2&")).unwrap(), "b"),
            Some("2")
        );
        for bad in ["p=%", "p=%2", "p=%zz", "p=%FF", "p=%C3", "%ff=1", "p=1&p=2"] {
            assert!(parse_query(Some(bad)).is_err(), "{bad}");
        }
        // An encoded NUL or newline is data: the path rules decide about it.
        assert_eq!(
            param(&parse_query(Some("p=a%00b%0A")).unwrap(), "p"),
            Some("a\0b\n")
        );
    }

    #[test]
    fn entity_tags() {
        let tag = etag(&[0xab; 32]);
        assert_eq!(tag.len(), 66);
        assert!(tag.starts_with("\"abab") && tag.ends_with("ab\""));
        assert!(none_match(&tag, &tag));
        assert!(none_match(&format!("W/{tag}"), &tag));
        assert!(none_match(&format!("\"other\", {tag}"), &tag));
        assert!(none_match("*", &tag));
        assert!(!none_match("\"other\"", &tag));
        assert!(!none_match("", &tag));
    }
}

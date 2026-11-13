//! HTTP pieces of the viewer that know nothing about the vault (SPEC §7.4): the response body,
//! query strings, `Range`, entity tags, `Content-Disposition`, and the order of a listing.

use std::cmp::Ordering;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Frame, SizeHint};
use tokio::sync::mpsc;

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
// Range, entity tags
// ---------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum ByteRange {
    /// No `Range`, one this server does not understand, or several ranges: the whole file
    /// (`200`) — RFC 9110 §14.2 lets a server ignore the header, and a `multipart/byteranges`
    /// answer is not worth having here.
    Whole,
    /// `206` with these bytes (never empty).
    Part(std::ops::Range<u64>),
    /// `416`: a well-formed range that selects nothing of the file.
    Unsatisfiable,
}

/// One `Range` header against a file of `size` bytes: `bytes=a-b`, `bytes=a-`, `bytes=-n`.
pub fn parse_range(header: Option<&str>, size: u64) -> ByteRange {
    let Some(spec) = header.and_then(|h| h.trim().strip_prefix("bytes=")) else {
        return ByteRange::Whole;
    };
    if spec.contains(',') {
        return ByteRange::Whole;
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return ByteRange::Whole;
    };
    let number = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u64>().unwrap_or(u64::MAX))
    };
    let range = match (first.is_empty(), number(first), number(last)) {
        // The last n bytes.
        (true, _, Some(n)) => size.saturating_sub(n)..size,
        (false, Some(a), None) if last.is_empty() => a..size,
        (false, Some(a), Some(b)) if a <= b => a..b.saturating_add(1).min(size),
        _ => return ByteRange::Whole,
    };
    if range.start < range.end {
        ByteRange::Part(range)
    } else {
        ByteRange::Unsatisfiable
    }
}

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

// ---------------------------------------------------------------------------------------------
// Content-Disposition
// ---------------------------------------------------------------------------------------------

/// `inline` or `attachment` with the file's name in both forms of RFC 6266: `filename=` as a
/// quoted string of harmless ASCII for clients that know nothing else, and `filename*=` with
/// the real name in UTF-8, percent-encoded per RFC 5987 — quotes, non-ASCII characters and
/// control characters included, so nothing in a name can end or extend the header.
pub fn content_disposition(inline: bool, name: &str) -> String {
    let fallback: String = name
        .chars()
        .map(|c| match c {
            '"' | '\\' | '%' | '/' | ';' => '_',
            c if c.is_ascii_graphic() || c == ' ' => c,
            _ => '_',
        })
        .collect();
    let fallback = match fallback.trim() {
        "" => "download",
        trimmed => trimmed,
    };
    let mut out = format!(
        "{}; filename=\"{fallback}\"; filename*=UTF-8''",
        if inline { "inline" } else { "attachment" }
    );
    for b in name.bytes() {
        // attr-char of RFC 5987.
        if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Listing order
// ---------------------------------------------------------------------------------------------

/// Names the way a file browser orders them: case-insensitively, with runs of digits compared
/// as numbers (`img2` before `img10`). Total and deterministic: names that are equal under
/// that are ordered by their bytes.
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    fn run(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
        let mut digits = String::new();
        while let Some(c) = chars.peek().filter(|c| c.is_ascii_digit()) {
            digits.push(*c);
            chars.next();
        }
        digits
    }
    let (mut x, mut y) = (a.chars().peekable(), b.chars().peekable());
    loop {
        let ordering = match (x.peek().copied(), y.peek().copied()) {
            (None, None) => return a.cmp(b),
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(c), Some(d)) if c.is_ascii_digit() && d.is_ascii_digit() => {
                let (m, n) = (run(&mut x), run(&mut y));
                let (m, n) = (m.trim_start_matches('0'), n.trim_start_matches('0'));
                m.len().cmp(&n.len()).then_with(|| m.cmp(n))
            }
            (Some(c), Some(d)) => {
                x.next();
                y.next();
                c.to_lowercase().cmp(d.to_lowercase())
            }
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
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
    fn ranges() {
        use ByteRange::*;
        for (header, size, expected) in [
            (None, 100, Whole),
            (Some("bytes=0-0"), 100, Part(0..1)),
            (Some("bytes=0-"), 100, Part(0..100)),
            (Some("bytes=10-19"), 100, Part(10..20)),
            (Some("bytes=99-"), 100, Part(99..100)),
            (Some("bytes=90-1000"), 100, Part(90..100)),
            (Some("bytes=-10"), 100, Part(90..100)),
            (Some("bytes=-1000"), 100, Part(0..100)),
            (Some(" bytes=5-5 "), 100, Part(5..6)),
            (Some("bytes=0-18446744073709551615"), 100, Part(0..100)),
            // Selects nothing.
            (Some("bytes=100-"), 100, Unsatisfiable),
            (Some("bytes=100-200"), 100, Unsatisfiable),
            (Some("bytes=-0"), 100, Unsatisfiable),
            (Some("bytes=0-"), 0, Unsatisfiable),
            (Some("bytes=-5"), 0, Unsatisfiable),
            (Some("bytes=99999999999999999999-"), 100, Unsatisfiable),
            // Not understood, or more than one range: the whole file.
            (Some("bytes=0-1,5-6"), 100, Whole),
            (Some("bytes=5-1"), 100, Whole),
            (Some("bytes=a-b"), 100, Whole),
            (Some("bytes=-"), 100, Whole),
            (Some("bytes=+1-2"), 100, Whole),
            (Some("bytes=1"), 100, Whole),
            (Some("items=0-1"), 100, Whole),
            (Some(""), 100, Whole),
        ] {
            assert_eq!(parse_range(header, size), expected, "{header:?} of {size}");
        }
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

    #[test]
    fn content_disposition_survives_any_name() {
        assert_eq!(
            content_disposition(false, "report.pdf"),
            "attachment; filename=\"report.pdf\"; filename*=UTF-8''report.pdf"
        );
        assert_eq!(
            content_disposition(true, "my file (1).txt"),
            "inline; filename=\"my file (1).txt\"; filename*=UTF-8''my%20file%20%281%29.txt"
        );
        assert_eq!(
            content_disposition(false, "a\"b\\c;d.txt"),
            "attachment; filename=\"a_b_c_d.txt\"; filename*=UTF-8''a%22b%5Cc%3Bd.txt"
        );
        assert_eq!(
            content_disposition(false, "größe 🎉.txt"),
            "attachment; filename=\"gr__e _.txt\"; filename*=UTF-8''gr%C3%B6%C3%9Fe%20%F0%9F%8E%89.txt"
        );
        assert_eq!(
            content_disposition(false, "line\r\nbreak\t\u{7f}.txt"),
            "attachment; filename=\"line__break__.txt\"; filename*=UTF-8''line%0D%0Abreak%09%7F.txt"
        );
        assert_eq!(
            content_disposition(false, "100%.txt"),
            "attachment; filename=\"100_.txt\"; filename*=UTF-8''100%25.txt"
        );
        assert_eq!(
            content_disposition(false, "\n"),
            "attachment; filename=\"_\"; filename*=UTF-8''%0A"
        );
        assert_eq!(
            content_disposition(false, " "),
            "attachment; filename=\"download\"; filename*=UTF-8''%20"
        );
        // Whatever the name: one line of visible ASCII, and the quoted string stays closed.
        for name in [
            "\u{0}\u{1}\u{1f}",
            "\"; filename=\"evil.exe",
            "ä\u{202e}gpj.exe",
            "a/b",
        ] {
            let value = content_disposition(false, name);
            assert!(
                value.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
                "{value:?}"
            );
            assert_eq!(value.matches('"').count(), 2, "{value:?}");
            assert!(hyper::header::HeaderValue::from_str(&value).is_ok());
        }
    }

    #[test]
    fn names_are_ordered_like_a_file_browser() {
        let mut names = vec![
            "img10.png",
            "Img2.png",
            "img1.png",
            "b",
            "A",
            "a",
            "img02.png",
            "Zebra",
            "ähnlich",
            "10",
            "9",
            "",
        ];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(
            names,
            [
                "",
                "9",
                "10",
                "A",
                "a",
                "b",
                "img1.png",
                "Img2.png",
                "img02.png",
                "img10.png",
                "Zebra",
                "ähnlich"
            ]
        );
        assert_eq!(natural_cmp("a", "a"), Ordering::Equal);
        assert_eq!(natural_cmp("a1", "a01"), "a1".cmp("a01"));
        assert_eq!(natural_cmp("file", "file2"), Ordering::Less);
        // Digit runs longer than any integer type.
        assert_eq!(
            natural_cmp(&"9".repeat(40), &format!("1{}", "0".repeat(40))),
            Ordering::Less
        );
    }
}

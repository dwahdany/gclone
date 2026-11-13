//! The wire side of restic's REST protocol, without I/O (SPEC §7.6): which path means what, the
//! JSON of a listing, the Basic credentials of the listener, and the status of every error.

use base64::Engine as _;
use hyper::StatusCode;

use super::{Error, FileType, Name, RepoName, Target};
use crate::error::{AuthError, BackendError, QuotaKind};

/// The media type that tells restic a listing is version 2 (`[{"name":…,"size":…}]`). It is
/// compared byte for byte.
pub const LIST_TYPE: &str = "application/vnd.x.restic.rest.v2";

/// What a request path names, after the repository prefix.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// The repository itself: `POST ?create=true`.
    Create,
    /// One file: `config`, or `<type>/<64 hex>`.
    File(Target),
    /// `<type>/`: the listing.
    List(FileType),
}

impl Route {
    /// The `Allow` header of a `405`.
    pub fn allow(&self) -> &'static str {
        match self {
            Route::Create => "POST",
            Route::File(_) => "HEAD, GET, POST, DELETE",
            Route::List(_) => "GET",
        }
    }
}

/// The path after the prefix, matched byte for byte: nothing is percent-decoded, so `%2e`,
/// an upper-case digit, a doubled slash or an extra segment name nothing. `None` is `404`
/// without a Drive call — restic's readiness probe (`/file-<n>`) among them.
pub fn route(rest: &str) -> Option<Route> {
    match rest {
        "" => return Some(Route::Create),
        "config" => return Some(Route::File(Target::Config)),
        _ => {}
    }
    let (ty, name) = rest.split_once('/')?;
    let ty = FileType::parse(ty)?;
    match name {
        "" => Some(Route::List(ty)),
        name => Some(Route::File(Target::File(ty, Name::parse(name)?))),
    }
}

/// The listener's prefix: `/<repo>/<rest>`. Stdio mode has the prefix `/` (`path[1..]`).
pub fn split_repo(path: &str) -> Option<(RepoName, &str)> {
    let (repo, rest) = path.strip_prefix('/')?.split_once('/')?;
    Some((RepoName::parse(repo).ok()?, rest))
}

/// `[{"name":"<64 hex>","size":N},…]`, sorted by name; `[]` when empty, never `null`.
pub fn list_json(entries: &[(Name, u64)]) -> Vec<u8> {
    let mut sorted: Vec<&(Name, u64)> = entries.iter().collect();
    sorted.sort();
    let mut out = String::with_capacity(2 + sorted.len() * 90);
    out.push('[');
    for (i, (name, size)) in sorted.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("{{\"name\":\"{}\",\"size\":{size}}}", name.hex()));
    }
    out.push(']');
    out.into_bytes()
}

/// The password of an `Authorization: Basic …` header (any user name). restic sends
/// `Basic Og==` — empty user, empty password — when it has no credentials.
pub fn basic_password(header: &str) -> Option<Vec<u8>> {
    let (scheme, value) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .ok()?;
    let colon = raw.iter().position(|b| *b == b':')?;
    Some(raw[colon + 1..].to_vec())
}

/// The status of a Drive failure. restic retries everything for 15 minutes except `401`,
/// `403`, `404`, `416` and `507`, which end the run within seconds: what cannot clear within a
/// run is one of those, what may clear is `503`.
pub fn status_of(e: &BackendError) -> StatusCode {
    match e {
        BackendError::RateLimited
        | BackendError::Transient(_)
        | BackendError::SessionLost
        | BackendError::Io(_)
        | BackendError::Auth(AuthError::Network(_) | AuthError::Io(_))
        // A folder vanished: the layout is dropped and resolved again by the next request.
        | BackendError::NotFound => StatusCode::SERVICE_UNAVAILABLE,
        BackendError::QuotaExceeded(QuotaKind::StorageFull | QuotaKind::DailyUpload) => {
            StatusCode::INSUFFICIENT_STORAGE
        }
        BackendError::Auth(_) => StatusCode::UNAUTHORIZED,
        // The Drive client already retried what can be retried.
        BackendError::Fatal { .. }
        | BackendError::QuotaExceeded(QuotaKind::DailyDownload | QuotaKind::ProjectApiQuota)
        | BackendError::AppNotAuthorized => StatusCode::FORBIDDEN,
        // Not returned by the calls this command makes.
        BackendError::AlreadyExists => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// The status of a failed request. `listing`: the request was `GET <type>/`, where "no such
/// repository" must not be `404` — restic reads that as an empty folder.
pub fn status(e: &Error, listing: bool) -> StatusCode {
    match e {
        Error::NoRepo if listing => StatusCode::FORBIDDEN,
        Error::NoRepo | Error::NotFound => StatusCode::NOT_FOUND,
        Error::Exists | Error::Forbidden | Error::ConfigKept | Error::Layout(_) => {
            StatusCode::FORBIDDEN
        }
        Error::BadUpload(_) => StatusCode::BAD_REQUEST,
        Error::LengthRequired => StatusCode::LENGTH_REQUIRED,
        Error::Unconfirmed(_) => StatusCode::SERVICE_UNAVAILABLE,
        Error::Integrity(_) => StatusCode::INTERNAL_SERVER_ERROR,
        Error::Backend(e) => status_of(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(c: char) -> String {
        c.to_string().repeat(64)
    }

    /// U1.
    #[test]
    fn route_grammar() {
        let name = Name::parse(&hex('a')).unwrap();
        assert_eq!(route(""), Some(Route::Create));
        assert_eq!(route("config"), Some(Route::File(Target::Config)));
        for ty in FileType::ALL {
            let dir = ty.dir();
            assert_eq!(route(&format!("{dir}/")), Some(Route::List(ty)));
            assert_eq!(
                route(&format!("{dir}/{}", hex('a'))),
                Some(Route::File(Target::File(ty, name)))
            );
        }
        let upper = hex('A');
        let (short, long) = ("a".repeat(63), "a".repeat(65));
        for bad in [
            "file-2026821414756312606".to_string(),
            "config/".into(),
            "Config".into(),
            "data".into(),
            "locks".into(),
            "blobs/".into(),
            format!("locks/{upper}"),
            format!("locks/{short}"),
            format!("locks/{long}"),
            "locks/..".into(),
            "locks/%2e%2e".into(),
            "..".into(),
            "%2e%2e/config".into(),
            format!("locks//{}", hex('a')),
            format!("/locks/{}", hex('a')),
            format!("locks/{}/", hex('a')),
            format!("locks/{}/x", hex('a')),
            format!("data/aa/{}", hex('a')),
            format!("other/{}", hex('a')),
            "/".into(),
            "?create=true".into(),
        ] {
            assert_eq!(route(&bad), None, "{bad:?}");
        }
        assert_eq!(Route::Create.allow(), "POST");
        assert_eq!(Route::List(FileType::Keys).allow(), "GET");
        assert_eq!(
            Route::File(Target::Config).allow(),
            "HEAD, GET, POST, DELETE"
        );

        // The listener's prefix.
        let (repo, rest) = split_repo("/laptop/locks/").unwrap();
        assert_eq!((repo.as_str(), rest), ("laptop", "locks/"));
        assert_eq!(split_repo("/laptop/").unwrap().1, "");
        for bad in [
            "",
            "/",
            "/laptop",
            "laptop/config",
            "/Laptop/config",
            "/../config",
            "//config",
            "/a%2fb/config",
            "/.hidden/config",
        ] {
            assert!(split_repo(bad).is_none(), "{bad:?}");
        }
    }

    /// U2.
    #[test]
    fn list_json_is_sorted_and_exact() {
        assert_eq!(list_json(&[]), b"[]");
        let (a, b) = (Name([0xaa; 32]), Name([0x0b; 32]));
        let json = String::from_utf8(list_json(&[(a, u64::MAX), (b, 0)])).unwrap();
        assert_eq!(
            json,
            format!(
                "[{{\"name\":\"{}\",\"size\":0}},{{\"name\":\"{}\",\"size\":18446744073709551615}}]",
                "0b".repeat(32),
                "aa".repeat(32)
            )
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 2);
    }

    /// U3.
    #[test]
    fn basic_credentials() {
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        assert_eq!(basic_password("Basic Og=="), Some(Vec::new()));
        assert_eq!(
            basic_password(&format!("Basic {}", b64("gclone:secret"))),
            Some(b"secret".to_vec())
        );
        assert_eq!(
            basic_password(&format!("basic {}", b64(":s:with:colons"))),
            Some(b"s:with:colons".to_vec())
        );
        for bad in [
            "",
            "Basic",
            "Basic !!!",
            "Bearer abc",
            &format!("Basic {}", b64("no-colon")),
            &format!("Basic{}", b64("a:b")),
        ] {
            assert_eq!(basic_password(bad), None, "{bad:?}");
        }
    }

    /// U4.
    #[test]
    fn statuses() {
        use BackendError as B;
        let io = || std::io::Error::other("x");
        let fatal = B::Fatal {
            status: 400,
            reason: "badRequest".into(),
            message: "x".into(),
        };
        for (e, code) in [
            (B::RateLimited, 503),
            (B::Transient("x".into()), 503),
            (B::SessionLost, 503),
            (B::Io(io()), 503),
            (B::Auth(AuthError::Network("x".into())), 503),
            (B::Auth(AuthError::Io(io())), 503),
            (B::NotFound, 503),
            (B::QuotaExceeded(QuotaKind::StorageFull), 507),
            (B::QuotaExceeded(QuotaKind::DailyUpload), 507),
            (B::Auth(AuthError::Expired), 401),
            (B::Auth(AuthError::WorkerMisconfigured("x".into())), 401),
            (B::Auth(AuthError::NotAllowed("x".into())), 401),
            (fatal, 403),
            (B::QuotaExceeded(QuotaKind::DailyDownload), 403),
            (B::QuotaExceeded(QuotaKind::ProjectApiQuota), 403),
            (B::AppNotAuthorized, 403),
            (B::AlreadyExists, 500),
        ] {
            assert_eq!(status_of(&e).as_u16(), code, "{e:?}");
            assert_eq!(status(&Error::Backend(e), true).as_u16(), code);
        }
        for (e, file, list) in [
            (Error::NoRepo, 404, 403),
            (Error::NotFound, 404, 404),
            (Error::Exists, 403, 403),
            (Error::Forbidden, 403, 403),
            (Error::ConfigKept, 403, 403),
            (Error::BadUpload("x"), 400, 400),
            (Error::LengthRequired, 411, 411),
            (Error::Layout("x".into()), 403, 403),
            (Error::Unconfirmed("x".into()), 503, 503),
            (Error::Integrity("x".into()), 500, 500),
        ] {
            assert_eq!(status(&e, false).as_u16(), file, "{e:?}");
            assert_eq!(status(&e, true).as_u16(), list, "{e:?}");
        }
    }
}

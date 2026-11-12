//! Client of the auth Worker (SPEC §2.2–§2.4, §9.6) — owned by WP3. No Google OAuth endpoint
//! is called from Rust except revoke.

use serde::{Deserialize, Serialize};

use crate::consts::{AUTH_HTTP_READ_TIMEOUT, HTTP_CONNECT_TIMEOUT};
use crate::error::AuthError;

pub mod login;
pub mod token;

pub use login::*;
pub use token::TokenProvider;

pub const SCOPE_DRIVE_FILE: &str = "https://www.googleapis.com/auth/drive.file";
pub const GOOGLE_REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";
/// Compile-time default for the auth Worker URL (set when building one's own binary).
pub const DEFAULT_AUTH_URL: Option<&str> = option_env!("GCLONE_DEFAULT_AUTH_URL");

/// Which of the Worker's OAuth clients a refresh token belongs to (§2.3): the device says so on
/// every `/refresh`. In `secrets.json` it is the `client` field, and a file without it — written
/// by gclone before 0.2.0, whose login went through the Worker's "Web application" client — is
/// `Legacy`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthClient {
    #[default]
    Legacy,
    /// Every login since 0.2.0: Google's device authorization grant.
    Device,
}

impl AuthClient {
    pub fn is_legacy(&self) -> bool {
        *self == AuthClient::Legacy
    }
}

/// `base` = the validated auth Worker URL without a trailing slash; routes are appended
/// (`/device/start`, `/device/poll`, `/refresh`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthEndpoints {
    pub base: String,
    pub revoke_url: String,
}

impl AuthEndpoints {
    /// `validate_auth_url` + `GOOGLE_REVOKE_URL`; tests build the struct directly.
    pub fn new(auth_url: &str) -> Result<Self, AuthError> {
        Ok(AuthEndpoints {
            base: validate_auth_url(auth_url)?,
            revoke_url: GOOGLE_REVOKE_URL.to_string(),
        })
    }
}

/// §2.2: https only (http for 127.0.0.1 / localhost / [::1]), host required, no userinfo /
/// query / fragment; returns the normalised URL. `BadAuthUrl` otherwise.
pub fn validate_auth_url(s: &str) -> Result<String, AuthError> {
    let bad = |why: &str| AuthError::BadAuthUrl(format!("{why} (given: {s})"));
    let url = url::Url::parse(s.trim()).map_err(|e| bad(&format!("not a URL: {e}")))?;
    let loopback = match url.host() {
        None => return Err(bad("the URL has no host")),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip == std::net::Ipv4Addr::LOCALHOST,
        Some(url::Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
    };
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err(bad("the URL must start with https://")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(bad("the URL must not contain a user name or password"));
    }
    if url.query().is_some() {
        return Err(bad("the URL must not contain a query"));
    }
    if url.fragment().is_some() {
        return Err(bad("the URL must not contain a fragment"));
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// arg, else env `GCLONE_AUTH_URL` (passed in by the caller), else the stored value, else
/// `DEFAULT_AUTH_URL`; validated. None anywhere → `BadAuthUrl` with a message naming the three
/// ways to supply it. `stored` = what the caller found on disk: secrets.json's `auth_url`, else
/// config.json's (§2.2) — the CLI passes `secrets.auth_url.or(config.auth_url)`.
pub fn resolve_auth_url(
    arg: Option<&str>,
    env: Option<&str>,
    stored: Option<&str>,
) -> Result<String, AuthError> {
    resolve_from(arg, env, stored, DEFAULT_AUTH_URL)
}

fn resolve_from(
    arg: Option<&str>,
    env: Option<&str>,
    stored: Option<&str>,
    built_in: Option<&str>,
) -> Result<String, AuthError> {
    // An empty value (`GCLONE_AUTH_URL=`) counts as "not given".
    let given = [arg, env, stored, built_in]
        .into_iter()
        .flatten()
        .find(|s| !s.trim().is_empty());
    match given {
        Some(url) => validate_auth_url(url),
        None => Err(AuthError::BadAuthUrl(
            "no auth Worker URL is known: pass it as `gclone login <AUTH_URL>`, set \
             GCLONE_AUTH_URL, or build gclone with GCLONE_DEFAULT_AUTH_URL"
                .to_string(),
        )),
    }
}

/// reqwest client for the Worker and the revoke call: redirect `Policy::none()`, connect 10 s /
/// read 30 s timeouts, `User-Agent: gclone/<version>`.
pub fn http_client() -> Result<reqwest::Client, AuthError> {
    reqwest::Client::builder()
        // A 3xx answer is an error: a refresh token is never re-sent to another host (§2.2).
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .read_timeout(AUTH_HTTP_READ_TIMEOUT)
        .user_agent(concat!("gclone/", env!("CARGO_PKG_VERSION")))
        .build()
        // The cause is in the source chain — on Linux typically a system without CA
        // certificates (no `ca-certificates` package), which a bare "builder error" hides.
        .map_err(|e| {
            AuthError::Network(format!(
                "cannot set up the HTTP client: {}",
                login::describe(&e)
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_is_arg_env_stored_built_in() {
        let (a, e, s, b) = (
            "https://arg",
            "https://env",
            "https://stored",
            "https://built",
        );
        let r = |a, e, s, b| resolve_from(a, e, s, b).unwrap();
        assert_eq!(r(Some(a), Some(e), Some(s), Some(b)), a);
        assert_eq!(r(None, Some(e), Some(s), Some(b)), e);
        assert_eq!(r(None, None, Some(s), Some(b)), s);
        assert_eq!(r(None, None, None, Some(b)), b);
        assert_eq!(
            r(None, Some(""), Some(s), Some(b)),
            s,
            "an empty value is skipped"
        );
        let none = resolve_from(None, None, None, None).unwrap_err();
        let AuthError::BadAuthUrl(msg) = none else {
            panic!("expected BadAuthUrl")
        };
        assert!(msg.contains("gclone login <AUTH_URL>"));
        assert!(msg.contains("GCLONE_AUTH_URL"));
        assert!(msg.contains("GCLONE_DEFAULT_AUTH_URL"));
        // The first value given is the one validated: a bad argument is not skipped.
        assert!(matches!(
            resolve_from(Some("http://example.com"), Some(e), None, None),
            Err(AuthError::BadAuthUrl(_))
        ));
    }

    #[test]
    fn endpoints_use_googles_revoke_url() {
        let ep = AuthEndpoints::new("https://auth.example/").unwrap();
        assert_eq!(ep.base, "https://auth.example");
        assert_eq!(ep.revoke_url, GOOGLE_REVOKE_URL);
        assert!(AuthEndpoints::new("auth.example").is_err());
    }
}

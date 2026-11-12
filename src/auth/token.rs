//! Access-token cache and refresh (SPEC §2.4, §9.6) — owned by WP3.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::AuthEndpoints;
use crate::consts::ACCESS_TOKEN_SKEW_MS;
use crate::error::AuthError;
use crate::util;

/// A `token.json` larger than this is not ours.
const CACHE_FILE_MAX: u64 = 64 * 1024;

/// `token.json` (§8.2). No `Debug`: it holds the access token.
#[derive(Clone, Serialize, Deserialize)]
struct Cached {
    access_token: String,
    expires_at_ms: u64,
    /// Time of the last real `/refresh`; absent for a token that came with a fresh login.
    refreshed_at_ms: Option<u64>,
}

impl Cached {
    fn usable(&self, now_ms: u64) -> bool {
        !self.access_token.is_empty()
            && now_ms.saturating_add(ACCESS_TOKEN_SKEW_MS) < self.expires_at_ms
    }
}

/// http, endpoints, refresh token, cache path, `Mutex<cached>`, single-flight.
pub struct TokenProvider {
    http: reqwest::Client,
    ep: AuthEndpoints,
    refresh_token: String,
    cache_file: Option<PathBuf>,
    cached: Mutex<Option<Cached>>,
    /// Held across a `/refresh` round trip: concurrent callers wait and reuse its result.
    flight: tokio::sync::Mutex<()>,
}

impl TokenProvider {
    /// `cache_file`: `Some` = read at construction and rewritten after every REAL refresh (0600,
    /// `util::write_atomic`); a cache file that fails `util::is_private` (§8.1) is ignored and
    /// replaced. `None` = memory only — what `gclone login` uses (§2.4, §2.6).
    pub fn new(
        http: reqwest::Client,
        ep: AuthEndpoints,
        refresh_token: String,
        cache_file: Option<std::path::PathBuf>,
    ) -> Self {
        let cached = cache_file.as_deref().and_then(load_cache);
        TokenProvider {
            http,
            ep,
            refresh_token,
            cache_file,
            cached: Mutex::new(cached),
            flight: tokio::sync::Mutex::new(()),
        }
    }

    /// Seeds the IN-MEMORY cache with the access token that came with a fresh login, so `login`
    /// needs no extra `/refresh` round trip. Never writes the cache file, whatever `cache_file` is.
    pub fn prime(&self, access_token: &str, expires_at_ms: u64) {
        let mut cached = self.lock();
        let refreshed_at_ms = cached.as_ref().and_then(|c| c.refreshed_at_ms);
        *cached = Some(Cached {
            access_token: access_token.to_string(),
            expires_at_ms,
            refreshed_at_ms,
        });
    }

    /// Cached unless < `ACCESS_TOKEN_SKEW` to expiry.
    pub async fn access_token(&self) -> Result<String, AuthError> {
        if let Some(token) = self.usable_token() {
            return Ok(token);
        }
        let _flight = self.flight.lock().await;
        // Another caller may have refreshed while this one waited.
        if let Some(token) = self.usable_token() {
            return Ok(token);
        }
        self.refresh_now().await
    }

    pub async fn force_refresh(&self) -> Result<String, AuthError> {
        let rejected = self.lock().as_ref().map(|c| c.access_token.clone());
        let _flight = self.flight.lock().await;
        // Several requests that got a 401 for the same token share one refresh.
        if let Some(token) = self.usable_token()
            && rejected.as_deref() != Some(token.as_str())
        {
            return Ok(token);
        }
        self.refresh_now().await
    }

    pub fn last_refresh_ms(&self) -> Option<u64> {
        self.lock().as_ref().and_then(|c| c.refreshed_at_ms)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Cached>> {
        // The guarded value is replaced whole, so a poisoned lock still holds a valid state.
        self.cached.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn usable_token(&self) -> Option<String> {
        let now = util::now_ms();
        self.lock()
            .as_ref()
            .filter(|c| c.usable(now))
            .map(|c| c.access_token.clone())
    }

    /// A real `/refresh`; the caller holds `flight`.
    async fn refresh_now(&self) -> Result<String, AuthError> {
        let grant = super::refresh(&self.http, &self.ep, &self.refresh_token).await?;
        let fresh = Cached {
            access_token: grant.access_token,
            expires_at_ms: grant.expires_at_ms,
            refreshed_at_ms: Some(util::now_ms()),
        };
        *self.lock() = Some(fresh.clone());
        if let Some(path) = self.cache_file.clone() {
            let token = fresh.access_token.clone();
            // The cache is an optimisation: a failed write only costs the next command a refresh.
            let written = tokio::task::spawn_blocking(move || store_cache(&path, &fresh)).await;
            if !matches!(written, Ok(Ok(()))) {
                tracing::debug!("could not write the access-token cache");
            }
            return Ok(token);
        }
        Ok(fresh.access_token)
    }
}

/// §8.1 strict loading: the directory and the file must be private to this user; any failure
/// only discards the cache.
fn load_cache(path: &Path) -> Option<Cached> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let dir_md = std::fs::symlink_metadata(dir).ok()?;
    if !dir_md.is_dir() || !util::is_private(&dir_md) {
        return None;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let md = file.metadata().ok()?;
    if !md.is_file() || !util::is_private(&md) || md.len() > CACHE_FILE_MAX {
        return None;
    }
    let mut text = String::new();
    file.take(CACHE_FILE_MAX).read_to_string(&mut text).ok()?;
    serde_json::from_str(&text).ok()
}

fn store_cache(path: &Path, cached: &Cached) -> std::io::Result<()> {
    let json = serde_json::to_vec(cached).map_err(std::io::Error::other)?;
    util::write_atomic(path, &json, 0o600)
}

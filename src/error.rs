//! All error enums and the exit-code mapping (SPEC §7.2, §9.3).
//!
//! Wrapping variants (`#[from]`) are `#[error(transparent)]`: `Display` shows the innermost
//! message once, and — as a consequence — `std::error::Error::source()` skips the wrapped
//! enum. Code that needs to look *inside* an error must therefore not walk `source()` by hand:
//! use [`find`] (first nested error of a type) or [`exit_code`], which descend through the
//! wrapping variants explicitly.

use crate::types::DeviceId;
use std::error::Error as StdError;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("not a gclone stream (bad magic)")]
    BadMagic,
    #[error("unsupported stream format ({0}): this vault needs a newer gclone")]
    Unsupported(&'static str),
    #[error("wrong key or wrong stream type")]
    WrongKey,
    #[error("ciphertext is corrupt (authentication failed)")]
    Corrupt,
    #[error("ciphertext is truncated")]
    Truncated,
    #[error("unexpected data after the end of the stream")]
    TrailingData,
    #[error("unknown key epoch {0}")]
    UnknownEpoch(u32),
    #[error("key epoch {epoch} is older than the minimum accepted epoch {min}")]
    EpochTooOld { epoch: u32, min: u32 },
    #[error("crypto API misuse: {0}")]
    Misuse(&'static str),
    #[error("key derivation failed: {0}")]
    Kdf(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("empty path")]
    Empty,
    #[error("path must not start with '/'")]
    Absolute,
    #[error("path has an empty component")]
    EmptyComponent,
    #[error("path has a '.' or '..' component")]
    DotComponent,
    #[error("path contains a NUL byte")]
    Nul,
    #[error("a path component is longer than 255 bytes")]
    ComponentTooLong,
    #[error("path is longer than 4096 bytes")]
    TooLong,
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("the keyfile is damaged")]
    KeyfileDamaged,
    #[error("keyfile version {0} is not supported: this vault needs a newer gclone")]
    KeyfileVersion(u32),
    #[error("the keyfile's KDF parameters are out of bounds")]
    KdfParams,
    #[error("the passphrase is too short (at least 12 characters)")]
    WeakPassphrase,
    #[error("bad object name: {0}")]
    BadName(String),
    #[error("unknown index codec {0}: this vault needs a newer gclone")]
    Codec(u8),
    /// The tag of the versioned body enum inside an index object (§4.6 rule 3).
    #[error("index object body version {0} is not supported: this vault needs a newer gclone")]
    BodyVersion(u8),
    #[error("cannot decode: {0}")]
    Decode(String),
    #[error("identity mismatch: {0}")]
    IdentityMismatch(String),
    /// §4.6 rules 6–7.
    #[error("malformed entry: {0}")]
    BadEntry(String),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl FormatError {
    /// `Some(what)` when an index object was refused because of a **version** this build does
    /// not know — and not because it is damaged (§4.6 "Unreadable is not corrupt"): the stream
    /// suite, type, flags or chunk size (`CryptoError::Unsupported`), a key epoch this device
    /// does not hold (`UnknownEpoch`; `EpochTooOld` is a refusal, not a version), the index
    /// codec, the body version.
    pub fn newer_format(&self) -> Option<String> {
        match self {
            FormatError::Crypto(CryptoError::Unsupported(what)) => {
                Some(format!("unsupported {what}"))
            }
            FormatError::Crypto(CryptoError::UnknownEpoch(epoch)) => {
                Some(format!("key epoch {epoch}"))
            }
            FormatError::Codec(codec) => Some(format!("index codec {codec}")),
            FormatError::BodyVersion(version) => Some(format!("body version {version}")),
            _ => None,
        }
    }
}

/// Mapping from the auth Worker's answers: §2.4.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// `/refresh` answered `invalid_grant`: "run gclone login".
    #[error("Google no longer accepts this device's login; run `gclone login`")]
    Expired,
    #[error("the auth Worker cannot authenticate to Google: {0}")]
    WorkerMisconfigured(String),
    #[error("the auth Worker does not allow this account: {0}")]
    NotAllowed(String),
    #[error("access was denied: {0}")]
    Denied(String),
    #[error("the login does not include Google Drive file access")]
    ScopeMissing,
    /// The device code ran out before anyone entered it at Google.
    #[error("the sign-in code expired before it was entered at Google")]
    Timeout,
    #[error("sign-in failed: {0}")]
    LoginFailed(String),
    #[error("bad auth Worker URL: {0}")]
    BadAuthUrl(String),
    #[error("could not reach the auth Worker: {0}")]
    Network(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum QuotaKind {
    StorageFull,
    DailyUpload,
    DailyDownload,
    ProjectApiQuota,
}

impl std::fmt::Display for QuotaKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            QuotaKind::StorageFull => "Drive storage is full",
            QuotaKind::DailyUpload => "Google's daily upload limit is reached",
            QuotaKind::DailyDownload => "Google's daily download quota is used up",
            QuotaKind::ProjectApiQuota => "the Google Cloud project's API quota is used up",
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("object not found")]
    NotFound,
    #[error("object already exists")]
    AlreadyExists,
    #[error("rate limited by the backend")]
    RateLimited,
    #[error("temporary backend failure: {0}")]
    Transient(String),
    #[error("the upload session was lost")]
    SessionLost,
    #[error("quota exceeded: {0}")]
    QuotaExceeded(QuotaKind),
    #[error("this login is not authorized for the object")]
    AppNotAuthorized,
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("backend error {status} ({reason}): {message}")]
    Fatal {
        status: u16,
        reason: String,
        message: String,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl BackendError {
    /// `QuotaExceeded(_) | RateLimited | Transient(_)` — failures that a later run may not see.
    pub fn is_temporary(&self) -> bool {
        matches!(
            self,
            BackendError::QuotaExceeded(_) | BackendError::RateLimited | BackendError::Transient(_)
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[cfg(not(target_family = "wasm"))]
    #[error("local state database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("another gclone is running on this vault")]
    Locked,
    #[error("local state is corrupt: {0}")]
    Corrupt(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("the index has a gap: {} missing or unusable ({})", .names.len(), .names.join(", "))]
    Gap { names: Vec<String> },
    #[error("the index was rolled back: segment {seq} of device {device} is gone")]
    Rollback { device: DeviceId, seq: u64 },
    #[error("the vault folder is in the Drive trash")]
    VaultTrashed,
    #[error("the vault folder is missing")]
    VaultMissing,
    #[error("this login cannot see the vault")]
    VaultNotVisible,
    #[error("this vault needs a newer gclone")]
    NeedsNewerGclone,
    /// A stored index object whose name matches its content but whose format this build does
    /// not read (§4.6 "Unreadable is not corrupt"): a version mismatch, never "missing".
    #[error(
        "index object {name} is in a format this gclone cannot read ({what}): this vault needs a newer gclone"
    )]
    UnsupportedObject { name: String, what: String },
    /// A sealed segment could not be published yet; the text names the cause.
    #[error("index changes could not be published yet: {0}")]
    OutboxStuck(String),
    /// The replica may lack index state — its last refresh failed or ignored index objects —
    /// and the operation judges what is dead (§5.9). The text names the objects.
    #[error("the index of this device may be incomplete: {0}")]
    Incomplete(String),
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Backend(#[from] BackendError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardKind {
    EmptySource,
    RevertedTree {
        suspicious: usize,
    },
    DeleteLimit {
        deletes: u64,
        total: u64,
    },
    /// More deletes than an explicit `--max-delete` allows: a hard limit that neither `--yes`
    /// nor an answer on the terminal lifts (§5.5.2 G4).
    MaxDelete {
        deletes: u64,
        limit: u64,
    },
    RootChanged,
}

impl std::fmt::Display for GuardKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardKind::EmptySource => f.write_str("source is empty or not mounted"),
            GuardKind::RevertedTree { suspicious } => {
                write!(
                    f,
                    "local tree looks restored from an older copy ({suspicious} files are older than last synced)"
                )
            }
            GuardKind::DeleteLimit { deletes, total } => {
                write!(f, "refusing to delete {deletes} of {total} files")
            }
            GuardKind::MaxDelete { deletes, limit } => {
                write!(
                    f,
                    "refusing to delete {deletes} files: --max-delete {limit} allows no more"
                )
            }
            GuardKind::RootChanged => {
                f.write_str("the local root is not the directory last synced with this remote path")
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("{0} changed while it was read")]
    SourceChanged(String),
    #[error("cannot read {path}: {err}")]
    SourceUnreadable { path: String, err: std::io::Error },
    #[error("blob {0} is missing")]
    BlobMissing(String),
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("unsafe target: {0}")]
    UnsafeTarget(String),
    /// §5.7 step 3: a differently spelled entry that the file system folds onto the target.
    #[error("a differently spelled entry is in the way: {0}")]
    TargetCollision(String),
    #[error("cancelled")]
    Cancelled,
    #[error(transparent)]
    Backend(#[from] BackendError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn clock_skew_text(offset_ms: &i64, limit_ms: &u64) -> String {
    format!(
        "the store's clock is {} {} this device's clock, and gc judges every age by it (at \
         most {} apart is accepted): gc did nothing. Check this device's date and time",
        crate::util::human_age(offset_ms.unsigned_abs()),
        if *offset_ms >= 0 {
            "ahead of"
        } else {
            "behind"
        },
        crate::util::human_age(*limit_ms)
    )
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("safety guard: {0}")]
    Guard(GuardKind),
    #[error("{failed} failed, {skipped} skipped")]
    Partial { failed: usize, skipped: usize },
    #[error("interrupted")]
    Interrupted,
    /// `gc`: the store's clock (the `Date` header) is further from this device's than `gc`
    /// accepts (§5.9). Exit 5, like the planner's guards.
    #[error("safety guard: {}", clock_skew_text(.offset_ms, .limit_ms))]
    ClockSkew { offset_ms: i64, limit_ms: u64 },
    #[error("{0}")]
    Usage(String),
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Transfer(#[from] TransferError),
    #[error(transparent)]
    Backend(#[from] BackendError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// No `config.json`.
    #[error("this device is not connected; run `gclone login <AUTH_URL>`")]
    NotConfigured,
    /// `config.json` but no secrets file (either backend), or a Drive vault without a refresh token.
    #[error("this device is not connected (signed out); run `gclone login`")]
    NotLoggedIn,
    /// Secrets exist with `keys == []`.
    #[error("run `gclone login` to finish connecting this device")]
    Locked,
    /// Secrets file or its directory: foreign owner or group/other bits (§8.1). Carries the path.
    #[error("refusing to use {0}: it is readable by others")]
    InsecurePermissions(String),
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// `secrets.sealed` is this device's only copy of the secrets and cannot be opened (§8.2).
    /// Carries the whole user-facing text: what failed, and what to do — which is NOT always
    /// `gclone login`.
    #[error("{0}")]
    KeyStoreUnavailable(String),
    /// Another gclone holds the secrets lock (`login`, `logout`, `keystore use`; §8.3).
    #[error("another gclone is changing this device's sign-in; nothing was changed")]
    KeyStoreBusy,
    #[error("unsupported configuration version {0}")]
    Version(u32),
    #[error("invalid configuration file: {0}")]
    Json(String),
    /// A stored `auth_url` that no longer validates.
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------------------------
// Looking inside errors
// ---------------------------------------------------------------------------------------------

/// Calls `f` for `e` and for every error nested in it through a wrapping variant of the enums
/// above, outermost first. Unknown error types are visited but not descended into (their
/// `source()` chain is handled by the callers below).
fn visit<'a>(e: &'a (dyn StdError + 'static), f: &mut dyn FnMut(&'a (dyn StdError + 'static))) {
    f(e);
    if let Some(x) = e.downcast_ref::<FormatError>() {
        match x {
            FormatError::Path(i) => visit(i, f),
            FormatError::Crypto(i) => visit(i, f),
            _ => {}
        }
    } else if let Some(x) = e.downcast_ref::<AuthError>() {
        if let AuthError::Io(i) = x {
            visit(i, f)
        }
    } else if let Some(x) = e.downcast_ref::<BackendError>() {
        match x {
            BackendError::Auth(i) => visit(i, f),
            BackendError::Io(i) => visit(i, f),
            _ => {}
        }
    } else if let Some(x) = e.downcast_ref::<StateError>() {
        match x {
            #[cfg(not(target_family = "wasm"))]
            StateError::Sqlite(i) => visit(i, f),
            StateError::Io(i) => visit(i, f),
            _ => {}
        }
    } else if let Some(x) = e.downcast_ref::<IndexError>() {
        match x {
            IndexError::Format(i) => visit(i, f),
            IndexError::Crypto(i) => visit(i, f),
            IndexError::Backend(i) => visit(i, f),
            IndexError::State(i) => visit(i, f),
            IndexError::Io(i) => visit(i, f),
            _ => {}
        }
    } else if let Some(x) = e.downcast_ref::<TransferError>() {
        match x {
            TransferError::SourceUnreadable { err, .. } => visit(err, f),
            TransferError::Backend(i) => visit(i, f),
            TransferError::Crypto(i) => visit(i, f),
            TransferError::Format(i) => visit(i, f),
            TransferError::Index(i) => visit(i, f),
            TransferError::State(i) => visit(i, f),
            TransferError::Io(i) => visit(i, f),
            _ => {}
        }
    } else if let Some(x) = e.downcast_ref::<SyncError>() {
        match x {
            SyncError::Index(i) => visit(i, f),
            SyncError::Transfer(i) => visit(i, f),
            SyncError::Backend(i) => visit(i, f),
            SyncError::State(i) => visit(i, f),
            SyncError::Io(i) => visit(i, f),
            _ => {}
        }
    } else if let Some(x) = e.downcast_ref::<ConfigError>() {
        match x {
            ConfigError::Auth(i) => visit(i, f),
            ConfigError::Crypto(i) => visit(i, f),
            ConfigError::Io(i) => visit(i, f),
            _ => {}
        }
    }
}

/// Every error reachable from `e`: each link of the anyhow chain and everything nested in it.
fn visit_all<'a>(e: &'a anyhow::Error, f: &mut dyn FnMut(&'a (dyn StdError + 'static))) {
    for cause in e.chain() {
        visit(cause, f);
    }
    // A typed value attached with `.context(err)` is wrapped by anyhow and cannot be downcast
    // from the `dyn Error` links above; anyhow's own downcast looks through its context layers.
    macro_rules! context_values {
        ($($t:ty),*) => { $( if let Some(x) = e.downcast_ref::<$t>() { visit(x, f); } )* };
    }
    context_values!(
        CryptoError,
        PathError,
        FormatError,
        AuthError,
        BackendError,
        StateError,
        IndexError,
        TransferError,
        SyncError,
        ConfigError
    );
}

/// The first error of type `T` anywhere inside `e` — in the anyhow context chain or nested in
/// a wrapping variant (`IndexError::Backend(BackendError::Auth(AuthError::Expired))` is found
/// as `AuthError`, as `BackendError` and as `IndexError`). The CLI uses it to pick the §2.8 text.
pub fn find<T: StdError + 'static>(e: &anyhow::Error) -> Option<&T> {
    let mut found = None;
    visit_all(e, &mut |x| {
        if found.is_none() {
            found = x.downcast_ref::<T>();
        }
    });
    found
}

/// The exit code one error node asks for by itself (wrapping variants answer `None`: their
/// payload is visited separately).
fn own_code(e: &(dyn StdError + 'static)) -> Option<i32> {
    if e.is::<CryptoError>() {
        return Some(3);
    }
    if let Some(x) = e.downcast_ref::<FormatError>() {
        return match x {
            FormatError::KeyfileDamaged | FormatError::KeyfileVersion(_) => Some(3),
            FormatError::Path(_) | FormatError::Crypto(_) => None,
            _ => Some(1),
        };
    }
    if e.is::<AuthError>() {
        return Some(4);
    }
    if let Some(x) = e.downcast_ref::<BackendError>() {
        return match x {
            BackendError::QuotaExceeded(_) | BackendError::RateLimited => Some(75),
            BackendError::AppNotAuthorized => Some(4),
            BackendError::Auth(_) | BackendError::Io(_) => None,
            _ => Some(1),
        };
    }
    if let Some(x) = e.downcast_ref::<IndexError>() {
        return match x {
            IndexError::Gap { .. }
            | IndexError::Rollback { .. }
            | IndexError::VaultTrashed
            | IndexError::VaultMissing
            | IndexError::NeedsNewerGclone
            | IndexError::UnsupportedObject { .. }
            | IndexError::Incomplete(_) => Some(3),
            IndexError::VaultNotVisible => Some(4),
            IndexError::OutboxStuck(_) => Some(75),
            _ => None,
        };
    }
    if let Some(x) = e.downcast_ref::<TransferError>() {
        return match x {
            TransferError::Verify(_) => Some(3),
            TransferError::Cancelled => Some(130),
            TransferError::SourceChanged(_)
            | TransferError::SourceUnreadable { .. }
            | TransferError::BlobMissing(_)
            | TransferError::UnsafeTarget(_)
            | TransferError::TargetCollision(_) => Some(1),
            _ => None,
        };
    }
    if let Some(x) = e.downcast_ref::<SyncError>() {
        return match x {
            SyncError::Guard(_) | SyncError::ClockSkew { .. } => Some(5),
            SyncError::Partial { .. } => Some(6),
            SyncError::Interrupted => Some(130),
            SyncError::Usage(_) => Some(2),
            _ => None,
        };
    }
    if let Some(x) = e.downcast_ref::<ConfigError>() {
        return match x {
            ConfigError::NotConfigured
            | ConfigError::NotLoggedIn
            | ConfigError::Locked
            | ConfigError::InsecurePermissions(_)
            | ConfigError::WrongPassphrase
            | ConfigError::KeyStoreUnavailable(_) => Some(4),
            ConfigError::Version(_) | ConfigError::Json(_) | ConfigError::KeyStoreBusy => Some(1),
            _ => None,
        };
    }
    None
}

/// Precedence when several codes apply (§7.2): 3 > 4 > 75 > 5 > 6 > 130 > 2 > 1.
/// (§7.2 ranks neither 130 nor 2; in practice they only ever compete with 1.)
fn rank(code: i32) -> u8 {
    match code {
        3 => 8,
        4 => 7,
        75 => 6,
        5 => 5,
        6 => 4,
        130 => 3,
        2 => 2,
        _ => 1,
    }
}

/// Walks the whole chain; mapping and precedence of §7.2:
/// - 3 ← `CryptoError`, `FormatError::{KeyfileDamaged, KeyfileVersion}`,
///   `IndexError::{Gap, Rollback, VaultTrashed, VaultMissing, NeedsNewerGclone, UnsupportedObject}`,
///   `TransferError::Verify`
///   (a wrong passphrase never reaches this function as `CryptoError::WrongKey`: the login flow
///   turns the keyfile's `WrongKey` into `ConfigError::WrongPassphrase` first, §2.6)
/// - 4 ← `AuthError`, `ConfigError::{NotConfigured, NotLoggedIn, Locked, InsecurePermissions,
///   WrongPassphrase, KeyStoreUnavailable}`, `IndexError::VaultNotVisible`,
///   `BackendError::AppNotAuthorized`
/// - 75 ← `QuotaExceeded(_)`, `RateLimited`, `IndexError::OutboxStuck`
/// - 5 ← `SyncError::Guard` / `ClockSkew`, 6 ← `SyncError::Partial`, 130 ← `Interrupted` / `Cancelled`,
///   2 ← `SyncError::Usage` (a usage error detected after argument parsing; clap's own usage
///   errors exit 2 before any of this runs), 1 ← everything else
pub fn exit_code(e: &anyhow::Error) -> i32 {
    let mut best = 1;
    visit_all(e, &mut |x| {
        if let Some(c) = own_code(x)
            && rank(c) > rank(best)
        {
            best = c;
        }
    });
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code<E: StdError + Send + Sync + 'static>(e: E) -> i32 {
        exit_code(&anyhow::Error::new(e))
    }

    fn io() -> std::io::Error {
        std::io::Error::other("boom")
    }

    #[test]
    fn exit_code_table() {
        // 3 — integrity
        assert_eq!(code(CryptoError::Corrupt), 3);
        assert_eq!(code(CryptoError::WrongKey), 3);
        assert_eq!(code(CryptoError::Unsupported("suite")), 3);
        assert_eq!(code(FormatError::KeyfileDamaged), 3);
        assert_eq!(code(FormatError::KeyfileVersion(2)), 3);
        assert_eq!(code(FormatError::Crypto(CryptoError::Truncated)), 3);
        assert_eq!(
            code(IndexError::Gap {
                names: vec!["s-1".into()]
            }),
            3
        );
        assert_eq!(
            code(IndexError::Rollback {
                device: DeviceId([1; 8]),
                seq: 4
            }),
            3
        );
        assert_eq!(code(IndexError::VaultTrashed), 3);
        assert_eq!(code(IndexError::VaultMissing), 3);
        assert_eq!(code(IndexError::NeedsNewerGclone), 3);
        assert_eq!(
            code(IndexError::UnsupportedObject {
                name: "s-1".into(),
                what: "index codec 1".into()
            }),
            3
        );
        assert_eq!(code(IndexError::Incomplete("s-1 was ignored".into())), 3);
        assert_eq!(code(TransferError::Verify("x".into())), 3);
        assert_eq!(code(IndexError::Crypto(CryptoError::BadMagic)), 3);
        assert_eq!(code(ConfigError::Crypto(CryptoError::UnknownEpoch(2))), 3);

        // 4 — fixed by `gclone login`
        assert_eq!(code(AuthError::Expired), 4);
        assert_eq!(code(AuthError::WorkerMisconfigured("m".into())), 4);
        assert_eq!(code(AuthError::NotAllowed("m".into())), 4);
        assert_eq!(code(AuthError::Denied("m".into())), 4);
        assert_eq!(code(AuthError::ScopeMissing), 4);
        assert_eq!(code(AuthError::Timeout), 4);
        assert_eq!(code(AuthError::LoginFailed("m".into())), 4);
        assert_eq!(code(AuthError::BadAuthUrl("m".into())), 4);
        assert_eq!(code(AuthError::Network("m".into())), 4);
        assert_eq!(code(AuthError::Io(io())), 4);
        assert_eq!(code(ConfigError::NotConfigured), 4);
        assert_eq!(code(ConfigError::NotLoggedIn), 4);
        assert_eq!(code(ConfigError::Locked), 4);
        assert_eq!(code(ConfigError::InsecurePermissions("/x".into())), 4);
        assert_eq!(code(ConfigError::WrongPassphrase), 4);
        assert_eq!(code(ConfigError::KeyStoreUnavailable("text".into())), 4);
        assert_eq!(code(ConfigError::KeyStoreBusy), 1);
        assert_eq!(
            code(ConfigError::Auth(AuthError::BadAuthUrl("u".into()))),
            4
        );
        assert_eq!(code(IndexError::VaultNotVisible), 4);
        assert_eq!(code(BackendError::AppNotAuthorized), 4);
        assert_eq!(code(BackendError::Auth(AuthError::Expired)), 4);

        // 75 — temporary
        assert_eq!(
            code(BackendError::QuotaExceeded(QuotaKind::StorageFull)),
            75
        );
        assert_eq!(
            code(BackendError::QuotaExceeded(QuotaKind::DailyUpload)),
            75
        );
        assert_eq!(code(BackendError::RateLimited), 75);
        assert_eq!(code(IndexError::OutboxStuck("quota".into())), 75);

        // 5, 6, 130
        assert_eq!(code(SyncError::Guard(GuardKind::RootChanged)), 5);
        assert_eq!(
            code(SyncError::ClockSkew {
                offset_ms: -90_000_000,
                limit_ms: 86_400_000
            }),
            5
        );
        assert_eq!(code(SyncError::Guard(GuardKind::EmptySource)), 5);
        assert_eq!(
            code(SyncError::Guard(GuardKind::RevertedTree { suspicious: 12 })),
            5
        );
        assert_eq!(
            code(SyncError::Guard(GuardKind::DeleteLimit {
                deletes: 101,
                total: 300
            })),
            5
        );
        assert_eq!(
            code(SyncError::Partial {
                failed: 1,
                skipped: 2
            }),
            6
        );
        assert_eq!(code(SyncError::Interrupted), 130);
        assert_eq!(code(TransferError::Cancelled), 130);

        // 1 — everything else
        assert_eq!(code(io()), 1);
        assert_eq!(code(BackendError::NotFound), 1);
        assert_eq!(code(BackendError::Transient("x".into())), 1);
        assert_eq!(code(BackendError::SessionLost), 1);
        assert_eq!(
            code(BackendError::Fatal {
                status: 400,
                reason: "r".into(),
                message: "m".into()
            }),
            1
        );
        assert_eq!(code(StateError::Locked), 1);
        assert_eq!(code(StateError::Corrupt("x".into())), 1);
        assert_eq!(code(SyncError::Usage("u".into())), 2);
        assert_eq!(code(ConfigError::Version(9)), 1);
        assert_eq!(code(ConfigError::Json("j".into())), 1);
        assert_eq!(code(FormatError::WeakPassphrase), 1);
        assert_eq!(code(FormatError::KdfParams), 1);
        assert_eq!(code(FormatError::Path(PathError::Empty)), 1);
        assert_eq!(code(PathError::DotComponent), 1);
        assert_eq!(code(TransferError::BlobMissing("b".into())), 1);
        assert_eq!(exit_code(&anyhow::anyhow!("plain message")), 1);
    }

    #[test]
    fn exit_code_descends_through_wrappers() {
        // sync → transfer → index → backend → auth
        let e = SyncError::Transfer(TransferError::Index(IndexError::Backend(
            BackendError::Auth(AuthError::Expired),
        )));
        assert_eq!(code(e), 4);
        let e = SyncError::Index(IndexError::Backend(BackendError::QuotaExceeded(
            QuotaKind::DailyDownload,
        )));
        assert_eq!(code(e), 75);
        let e = SyncError::Transfer(TransferError::Crypto(CryptoError::Corrupt));
        assert_eq!(code(e), 3);
        let e = TransferError::Format(FormatError::Crypto(CryptoError::Corrupt));
        assert_eq!(code(e), 3);
        let e = SyncError::Transfer(TransferError::Backend(BackendError::RateLimited));
        assert_eq!(code(e), 75);
        let e = IndexError::State(StateError::Io(io()));
        assert_eq!(code(e), 1);
        let e = SyncError::Transfer(TransferError::Cancelled);
        assert_eq!(code(e), 130);
        let e = SyncError::Index(IndexError::Backend(BackendError::AppNotAuthorized));
        assert_eq!(code(e), 4);
    }

    #[test]
    fn exit_code_precedence_over_the_anyhow_chain() {
        // 3 > 4 > 75 > 5 > 6 > 1 when several apply
        let e = anyhow::Error::new(AuthError::Expired).context(SyncError::Partial {
            failed: 1,
            skipped: 0,
        });
        assert_eq!(exit_code(&e), 4);
        let e = anyhow::Error::new(SyncError::Partial {
            failed: 1,
            skipped: 0,
        })
        .context(AuthError::Expired);
        assert_eq!(exit_code(&e), 4);
        let e = anyhow::Error::new(CryptoError::Corrupt).context(AuthError::Expired);
        assert_eq!(exit_code(&e), 3);
        let e = anyhow::Error::new(BackendError::RateLimited)
            .context(SyncError::Guard(GuardKind::EmptySource));
        assert_eq!(exit_code(&e), 75);
        let e = anyhow::Error::new(SyncError::Partial {
            failed: 1,
            skipped: 0,
        })
        .context(SyncError::Guard(GuardKind::RootChanged));
        assert_eq!(exit_code(&e), 5);
        let e = anyhow::Error::new(io()).context(SyncError::Partial {
            failed: 1,
            skipped: 0,
        });
        assert_eq!(exit_code(&e), 6);
        let e =
            anyhow::Error::new(IndexError::OutboxStuck("q".into())).context(ConfigError::Locked);
        assert_eq!(exit_code(&e), 4);
        // plain string context keeps the inner code
        let e = anyhow::Error::new(IndexError::OutboxStuck("q".into())).context("while committing");
        assert_eq!(exit_code(&e), 75);
        let e = anyhow::Error::new(SyncError::Interrupted).context("ctrl-c");
        assert_eq!(exit_code(&e), 130);
    }

    #[test]
    fn find_looks_inside_wrappers() {
        let e = anyhow::Error::new(SyncError::Index(IndexError::Backend(BackendError::Auth(
            AuthError::Expired,
        ))))
        .context("sync failed");
        assert!(matches!(find::<AuthError>(&e), Some(AuthError::Expired)));
        assert!(matches!(
            find::<BackendError>(&e),
            Some(BackendError::Auth(_))
        ));
        assert!(matches!(
            find::<IndexError>(&e),
            Some(IndexError::Backend(_))
        ));
        assert!(matches!(find::<SyncError>(&e), Some(SyncError::Index(_))));
        assert!(find::<ConfigError>(&e).is_none());
        assert!(find::<CryptoError>(&e).is_none());

        let e = anyhow::Error::new(TransferError::SourceUnreadable {
            path: "p".into(),
            err: io(),
        });
        assert!(find::<std::io::Error>(&e).is_some());
    }

    #[test]
    fn messages_are_not_duplicated_by_wrappers() {
        let e = SyncError::Index(IndexError::Backend(BackendError::RateLimited));
        assert_eq!(e.to_string(), "rate limited by the backend");
        let e = anyhow::Error::new(e);
        assert_eq!(format!("{e:#}"), "rate limited by the backend");
        assert_eq!(
            IndexError::Gap {
                names: vec!["a".into(), "b".into()]
            }
            .to_string(),
            "the index has a gap: 2 missing or unusable (a, b)"
        );
    }

    #[test]
    fn is_temporary() {
        assert!(BackendError::QuotaExceeded(QuotaKind::StorageFull).is_temporary());
        assert!(BackendError::RateLimited.is_temporary());
        assert!(BackendError::Transient("x".into()).is_temporary());
        assert!(!BackendError::NotFound.is_temporary());
        assert!(!BackendError::SessionLost.is_temporary());
        assert!(!BackendError::AppNotAuthorized.is_temporary());
        assert!(!BackendError::Auth(AuthError::Expired).is_temporary());
        assert!(!BackendError::Io(io()).is_temporary());
    }

    #[test]
    fn errors_are_send_sync() {
        fn ok<T: Send + Sync + 'static>() {}
        ok::<CryptoError>();
        ok::<FormatError>();
        ok::<AuthError>();
        ok::<BackendError>();
        ok::<StateError>();
        ok::<IndexError>();
        ok::<TransferError>();
        ok::<SyncError>();
        ok::<ConfigError>();
    }
}

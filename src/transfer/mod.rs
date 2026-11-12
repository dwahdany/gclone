//! Transfer pipeline (SPEC §6.2, §6.3, §9.8) — owned by WP5.
//!
//! The transfer layer uses `backend`, `crypto`, `format` and `ui::Progress` only — **never
//! `index` or `state`**. Everything that needs the vault (data folder, blob records, ledger,
//! staging) is passed in or done by the caller.

use crate::backend::Backend;
use crate::crypto::Keyring;
use crate::error::{AuthError, BackendError, CryptoError, TransferError};
use crate::types::{BlobRec, DeviceId, Entry, StatSig};

pub mod download;
pub(crate) mod durable;
pub mod pack;
pub mod source;
pub mod upload;

pub use download::*;
pub use pack::*;
pub use source::*;
pub use upload::*;

pub struct TransferCtx<B: Backend> {
    pub backend: std::sync::Arc<B>,
    pub keys: Keyring,
    pub device: DeviceId,
    pub progress: crate::ui::Progress,
    pub cancel: tokio_util::sync::CancellationToken,
}

/// Manual impl: no `B: Clone` bound.
impl<B: Backend> Clone for TransferCtx<B> {
    fn clone(&self) -> Self {
        TransferCtx {
            backend: self.backend.clone(),
            keys: self.keys.clone(),
            device: self.device,
            progress: self.progress.clone(),
            cancel: self.cancel.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct UploadSource {
    pub abs: std::path::PathBuf,
    pub remote_path: String,
}

#[derive(Clone, Debug)]
pub struct Uploaded {
    pub remote_path: String,
    pub entry: Entry,
    pub sig: StatSig,
    pub observed_ns: i64,
}

#[derive(Clone, Debug)]
pub struct BlobUpload {
    /// `None`: the event carries only zero-length files.
    pub blob: Option<BlobRec>,
    pub files: Vec<Uploaded>,
}

pub enum UploadEvent {
    Blob(BlobUpload),
    Failed(UploadSource, TransferError),
}

/// What the plan expects at a local target path (§5.5.1 type changes, §5.7 step 3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LocalExpect {
    Absent,
    File(StatSig),
    EmptyDir,
}

/// Runs blocking work (file I/O, hashing, sealing) off the async threads with owned inputs.
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, TransferError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| TransferError::Io(std::io::Error::other(e)))
}

/// A second error value with the same meaning: one failed blob fails every file in it, and the
/// error enums cannot be `Clone` (they carry `io::Error`s). Variant and payload are kept, so
/// `error::exit_code` and `error::find` treat the copy like the original. The three variants
/// the transfer layer never produces (`Format`, `Index`, `State`) come back as `Io` with the
/// original message.
pub(crate) fn replicate(e: &TransferError) -> TransferError {
    use TransferError as T;
    match e {
        T::SourceChanged(p) => T::SourceChanged(p.clone()),
        T::SourceUnreadable { path, err } => T::SourceUnreadable {
            path: path.clone(),
            err: replicate_io(err),
        },
        T::BlobMissing(b) => T::BlobMissing(b.clone()),
        T::Verify(m) => T::Verify(m.clone()),
        T::UnsafeTarget(m) => T::UnsafeTarget(m.clone()),
        T::TargetCollision(m) => T::TargetCollision(m.clone()),
        T::Cancelled => T::Cancelled,
        T::Backend(b) => T::Backend(replicate_backend(b)),
        T::Crypto(c) => T::Crypto(replicate_crypto(c)),
        T::Io(err) => T::Io(replicate_io(err)),
        T::Format(_) | T::Index(_) | T::State(_) => T::Io(std::io::Error::other(e.to_string())),
    }
}

fn replicate_io(e: &std::io::Error) -> std::io::Error {
    match e.raw_os_error() {
        Some(code) => std::io::Error::from_raw_os_error(code),
        None => std::io::Error::new(e.kind(), e.to_string()),
    }
}

fn replicate_crypto(e: &CryptoError) -> CryptoError {
    use CryptoError as C;
    match e {
        C::BadMagic => C::BadMagic,
        C::Unsupported(what) => C::Unsupported(what),
        C::WrongKey => C::WrongKey,
        C::Corrupt => C::Corrupt,
        C::Truncated => C::Truncated,
        C::TrailingData => C::TrailingData,
        C::UnknownEpoch(epoch) => C::UnknownEpoch(*epoch),
        C::EpochTooOld { epoch, min } => C::EpochTooOld {
            epoch: *epoch,
            min: *min,
        },
        C::Misuse(what) => C::Misuse(what),
        C::Kdf(m) => C::Kdf(m.clone()),
    }
}

pub(crate) fn replicate_backend(e: &BackendError) -> BackendError {
    use BackendError as B;
    match e {
        B::NotFound => B::NotFound,
        B::AlreadyExists => B::AlreadyExists,
        B::RateLimited => B::RateLimited,
        B::Transient(m) => B::Transient(m.clone()),
        B::SessionLost => B::SessionLost,
        B::QuotaExceeded(kind) => B::QuotaExceeded(*kind),
        B::AppNotAuthorized => B::AppNotAuthorized,
        B::Auth(a) => B::Auth(replicate_auth(a)),
        B::Fatal {
            status,
            reason,
            message,
        } => B::Fatal {
            status: *status,
            reason: reason.clone(),
            message: message.clone(),
        },
        B::Io(err) => B::Io(replicate_io(err)),
    }
}

fn replicate_auth(e: &AuthError) -> AuthError {
    use AuthError as A;
    match e {
        A::Expired => A::Expired,
        A::WorkerMisconfigured(m) => A::WorkerMisconfigured(m.clone()),
        A::NotAllowed(m) => A::NotAllowed(m.clone()),
        A::Denied(m) => A::Denied(m.clone()),
        A::ScopeMissing => A::ScopeMissing,
        A::StateMismatch => A::StateMismatch,
        A::Timeout => A::Timeout,
        A::LoginFailed(m) => A::LoginFailed(m.clone()),
        A::BadAuthUrl(m) => A::BadAuthUrl(m.clone()),
        A::Network(m) => A::Network(m.clone()),
        A::Io(err) => A::Io(replicate_io(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{QuotaKind, exit_code};

    #[test]
    fn a_replicated_error_keeps_variant_message_and_exit_code() {
        let originals = [
            TransferError::SourceChanged("a/b".into()),
            TransferError::SourceUnreadable {
                path: "p".into(),
                err: std::io::Error::from_raw_os_error(libc::EACCES),
            },
            TransferError::Verify("hash".into()),
            TransferError::Cancelled,
            TransferError::Crypto(CryptoError::Corrupt),
            TransferError::Crypto(CryptoError::Unsupported("suite")),
            TransferError::Backend(BackendError::QuotaExceeded(QuotaKind::DailyUpload)),
            TransferError::Backend(BackendError::RateLimited),
            TransferError::Backend(BackendError::Auth(AuthError::Expired)),
            TransferError::Backend(BackendError::Fatal {
                status: 404,
                reason: "notFound".into(),
                message: "gone".into(),
            }),
            TransferError::Io(std::io::Error::other("boom")),
        ];
        for original in originals {
            let copy = replicate(&original);
            assert_eq!(copy.to_string(), original.to_string());
            assert_eq!(
                std::mem::discriminant(&copy),
                std::mem::discriminant(&original)
            );
            assert_eq!(exit_code(&copy.into()), exit_code(&original.into()));
        }
    }
}

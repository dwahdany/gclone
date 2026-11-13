//! gclone's read path for the hosted viewer (SPEC §7.5).
//!
//! The modules marked `#[path]` are the main crate's own source files, compiled a second
//! time: nothing of the formats, the cryptography, the merge rule or the viewer's listing rules
//! is re-implemented here. What this crate adds:
//!
//! - [`reader`]: a stateless, read-only replica — snapshot ⊕ segments in an in-memory index —
//!   with the queries of the viewer (`list`, `stat`, `search`, `info`) and per-file tickets;
//! - [`file`]: streaming, ranged decryption of one file from a ticket;
//! - [`ops`]: the calls that need no index (descriptor, keyfile, unlock, `Range`, headers);
//! - [`api`]: the wasm-bindgen surface over the three — compiled for wasm only.
//!
//! Everything but `api` is plain Rust and runs natively in `tests/parity.rs`. Nothing does
//! I/O, reads a clock or draws randomness.

#[allow(dead_code)]
#[path = "../../src/consts.rs"]
pub mod consts;
#[allow(dead_code)]
#[path = "../../src/crypto/mod.rs"]
pub mod crypto;
#[allow(dead_code)]
#[path = "../../src/error.rs"]
pub mod error;
#[allow(dead_code)]
#[path = "../../src/format/mod.rs"]
pub mod format;
pub mod index;
#[allow(dead_code)]
#[path = "../../src/path.rs"]
pub mod path;
#[allow(dead_code)]
#[path = "../../src/types.rs"]
pub mod types;
#[allow(dead_code)]
#[path = "../../src/util.rs"]
pub mod util;
pub mod web;

#[cfg(target_family = "wasm")]
pub mod api;
pub mod file;
pub mod ops;
pub mod reader;

/// How every failure of this crate is reported: a code from a closed set and a sentence. The
/// wasm API throws it as an `Error` whose message is `"<code>: <sentence>"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    /// `unlock`: the keyfile is intact, the passphrase is not its passphrase.
    WrongPassphrase,
    /// A keyfile, a descriptor or a key bundle that cannot be read at all.
    Damaged,
    /// `unlock`: the keyfile opened, and it is the keyfile of another vault.
    OtherVault,
    /// A format version this build does not know. Fail closed: stop, do not guess.
    NeedsNewer,
    /// A path that is not in the vault.
    NotFound,
    /// A ticket was asked for something that is not a file.
    NotAFile,
    /// Authenticated data that contradicts itself, or ciphertext that does not verify.
    Corrupt,
    /// The caller's mistake: a malformed argument, a call out of order.
    BadInput,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::WrongPassphrase => "wrong-passphrase",
            Code::Damaged => "damaged",
            Code::OtherVault => "other-vault",
            Code::NeedsNewer => "needs-newer",
            Code::NotFound => "not-found",
            Code::NotAFile => "not-a-file",
            Code::Corrupt => "corrupt",
            Code::BadInput => "bad-input",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: Code,
    pub message: String,
}

impl Error {
    pub fn new(code: Code, message: impl Into<String>) -> Error {
        Error {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// A size, an offset or a time that crossed the JS boundary as a number: it has to be a
/// non-negative integer that a double holds exactly (below 2^53).
pub fn integer(value: f64, what: &str) -> Result<u64> {
    const MAX: f64 = 9_007_199_254_740_991.0;
    if value.is_finite() && (0.0..=MAX).contains(&value) && value.fract() == 0.0 {
        Ok(value as u64)
    } else {
        Err(Error::new(
            Code::BadInput,
            format!("{what} is not a whole number between 0 and 2^53"),
        ))
    }
}

/// The other direction: every size this crate hands to JS is below 2^53 by construction
/// (file sizes and blob offsets of a store that holds no object that large); one that is not
/// is reported instead of being rounded.
pub fn number(value: u64, what: &str) -> Result<f64> {
    if value < (1 << 53) {
        Ok(value as f64)
    } else {
        Err(Error::new(
            Code::Corrupt,
            format!("{what} is too large for this viewer"),
        ))
    }
}

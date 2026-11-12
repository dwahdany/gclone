//! Crypto (SPEC §4, §9.4): key hierarchy, the stream container and the passphrase KDF.
//! No module other than `crypto` calls an AEAD.

pub mod kdf;
pub mod keys;
pub mod stream;

pub use kdf::*;
pub use keys::*;
pub use stream::*;

/// HKDF-SHA-256 (RFC 5869), Extract-then-Expand, filling `out`.
fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    // Expand fails only for more than 255 * 32 output bytes; every caller asks for 32 or 64.
    hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("HKDF-SHA-256 output length is at most 255 * 32 bytes");
}

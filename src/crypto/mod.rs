//! Crypto (SPEC §4, §9.4): key hierarchy, the stream container and the passphrase KDF.
//! Nothing of the vault's formats is sealed or opened anywhere else: no other module calls an
//! AEAD on vault data or with a vault key. (The one other AEAD call site of the crate is
//! outside §4 altogether: `web::FileIds`, the opaque file ids of the local viewer's URLs,
//! under a random key that lives as long as the `gclone web` process and never leaves it.)

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

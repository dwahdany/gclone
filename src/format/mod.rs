//! On-disk formats (SPEC §2.6, §3.3, §4.4–§4.6, §9.4): index objects, data blobs, the keyfile
//! and the vault descriptor. Everything encrypted goes through `crypto`'s stream container.

pub mod blob;
pub mod descriptor;
pub mod index;
pub mod keyfile;

pub use blob::*;
pub use descriptor::*;
pub use index::*;
pub use keyfile::*;

/// Exactly `2 * N` lowercase hex digits (the one accepted spelling in object names).
fn unhex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    crate::util::unhex(s)?.try_into().ok()
}

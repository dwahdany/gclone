//! gclone — client-side encrypted, rsync-style sync to Google Drive. Module declarations only;
//! the module tree and its owners are listed in SPEC §9.2.

pub mod auth;
pub mod backend;
pub mod cli;
pub mod config;
pub mod consts;
pub mod crypto;
pub mod error;
pub mod format;
pub mod index;
pub mod path;
pub mod state;
pub mod sync;
pub mod transfer;
pub mod types;
pub mod ui;
pub mod util;
pub mod web;

/// The seeded test PRNG of `tests/support/prng.rs`, compiled into the library's unit-test
/// build so that its self-tests (`util::tests::prng_selftest`) run; integration tests include
/// it with `mod support;`.
#[cfg(test)]
#[path = "../tests/support/prng.rs"]
mod test_prng;

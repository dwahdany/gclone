//! What both viewers do the same way (`src/web/rules.rs`), the vault as it was
//! (`src/web/past.rs`) and what a vault file is served as (`src/web/mime.rs`): the main crate's
//! files, compiled a second time.
#[path = "../../src/web/mime.rs"]
pub mod mime;
#[allow(dead_code)]
#[path = "../../src/web/past.rs"]
pub mod past;
#[allow(dead_code)]
#[path = "../../src/web/rules.rs"]
pub mod rules;

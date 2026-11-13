//! The merge rule of the main crate (`src/index/apply.rs`) and its in-memory index, without
//! the SQLite replica around them.
#[allow(dead_code)]
#[path = "../../src/index/apply.rs"]
pub mod apply;
pub use apply::{
    ApplyStats, HeadStore, MemIndex, apply_segment, causal_order, check_snapshot_format,
};

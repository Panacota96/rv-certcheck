//! Analysis side (OWNER: agent A). Implementation modules behind the frozen facades in lib.rs; split or add
//! files freely inside `analysis/`, keep the facade signatures.

pub mod anchors;
pub mod chain;
pub mod keymatch;
pub mod online;
pub mod parse;
pub mod revocation;
pub mod sniff;
pub mod text;
pub mod timestamp;
pub mod util;

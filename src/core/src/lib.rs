//! RV CertCheck core library.
//!
//! The core does all the work and never prints: front-ends (CLI, GUI) call [`run::run`] and
//! render the [`events::Event`] stream it emits.
//!
//! ```text
//! input ──► hash (1–2 algorithms, one read) ──► certscan per item (sniff, parse) ──► duplicates
//!       ──► certscan cross-item (chains, revocation, tokens, keys; chain.json + certificate.txt) ──► reports
//!   └──────────────── every step appended to the hash-chained audit log ──────────────────────────┘
//! ```
//! The certificate work itself lives in the `rv_certcheck_certs` crate (src/certs); `certscan` is the glue.

pub mod analyzer;
pub mod audit;
pub mod case;
pub mod certscan;
pub mod creation;
pub mod env;
pub mod events;
pub mod hash;
pub mod i18n;
pub mod input;
pub mod report;
pub mod run;
pub mod time;
pub mod trust;
pub mod verify;

pub use case::CaseRole;
pub use certscan::CertOptions;
pub use events::Event;
pub use hash::HashAlgo;
pub use run::{RunConfig, RunSummary, run};
pub use rv_certcheck_certs as certs;

pub const TOOL_NAME: &str = "rv-certcheck";
/// Product version = version.txt (bumped by release-please). The crate versions in Cargo.toml stay fixed so a
/// release never changes Cargo.lock (CI builds with --locked).
pub const TOOL_VERSION: &str = env!("RV_VERSION");

/// This tool's place in a shared case folder (see docs/case-folder.md): an ANALYSIS tool, it verifies every item
/// against the registry written by the intake tool (rv-hashinv). Kept in step with `case_role` in .forge.json.
pub const CASE_ROLE: CaseRole = CaseRole::Analysis;

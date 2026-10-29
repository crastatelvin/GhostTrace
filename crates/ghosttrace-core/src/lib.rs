//! GhostTrace core library.
//!
//! Module map (grows per the phased plan):
//!
//! - [`domain`] — lossless value types and case/event records (P1.1)
//! - [`error`] — shared error categories with stable machine codes
//! - [`storage`] — case directory layout, dedicated writer, read connections,
//!   checksummed migrations, and validated backups (P1.2)
//! - [`service`] — the shared `CaseSession` every front end queries (P1.2)
//! - [`sqlite_report`] — linked-runtime verification (P0.1)
//! - [`jobs`] — job states, checkpoints, and recovery detection (P1.2)
//! - [`integrity`] — streaming SHA-256 and the acquisition manifest (P2.2)
//! - [`analysis`] — timeline/snapshot analysis over captured evidence (P3.1)
//! - [`reports`] — versioned JSON/HTML report export (P3.2)
//! - [`ingest`] — bounded log adapters with explicit time assumptions (P4.1)

pub mod analysis;
pub mod capture;
pub mod domain;
pub mod error;
pub mod ingest;
pub mod integrity;
pub mod jobs;
pub mod reports;
pub mod service;
pub mod sqlite_report;
pub mod storage;
pub mod text;
pub mod worker;

pub use domain::*;
pub use error::{CoreError, CoreResult};

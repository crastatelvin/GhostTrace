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

pub mod domain;
pub mod error;
pub mod jobs;
pub mod service;
pub mod sqlite_report;
pub mod storage;

pub use domain::*;
pub use error::{CoreError, CoreResult};

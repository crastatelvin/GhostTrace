//! GhostTrace core library.
//!
//! Module map (grows per the phased plan; P0.1 verified the storage/runtime
//! stack, P1 adds the evidence model):
//!
//! - [`domain`] — lossless value types and case/event records (P1.1)
//! - [`error`] — shared error categories with stable machine codes
//! - [`sqlite_report`] — P0.1 linked-runtime verification

pub mod domain;
pub mod error;
pub mod sqlite_report;

pub use domain::*;
pub use error::{CoreError, CoreResult};

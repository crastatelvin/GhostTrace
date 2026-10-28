//! GhostTrace desktop shell (plan Sections 3, 9, 10).
//!
//! P6.1 scope: case create/open, evidence capture and import, background job
//! progress/cancel, and recovery review. P6.2 adds the timeline, histogram, and
//! provenance inspector; P6.3 adds snapshot comparison, relationships, findings,
//! notes, saved views, and unredacted report export with manifest verification.
//! The render pass never touches SQLite or evidence; see
//! `commands.rs` and `query.rs` for the worker boundaries.

pub mod app;
pub mod cases;
pub mod commands;
pub mod diff;
pub mod evidence;
pub mod findings;
pub mod import;
pub mod query;
pub mod relations;
pub mod report;
pub mod state;
pub mod timeline;

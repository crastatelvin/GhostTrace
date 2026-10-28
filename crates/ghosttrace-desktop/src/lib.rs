//! GhostTrace desktop shell (plan Sections 3, 9, 10).
//!
//! P6.1 scope: case create/open, evidence capture and import, background job
//! progress/cancel, and recovery review. The render pass never touches SQLite
//! or evidence; see `commands.rs` for the worker boundary.

pub mod app;
pub mod cases;
pub mod commands;
pub mod import;
pub mod state;

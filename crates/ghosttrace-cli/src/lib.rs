//! GhostTrace CLI library surface: command parsing, output helpers, and the
//! interactive terminal workflow.
//!
//! The `ghosttrace` binary is a thin wrapper so the TUI's state, key mapping,
//! and terminal guard can be tested without a terminal (plan P7).

pub mod commands;
pub mod output;
pub mod tui;

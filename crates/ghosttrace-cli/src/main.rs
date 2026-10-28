//! GhostTrace CLI entry point (plan Sections 9, 17/P2.3).
//!
//! stdout carries machine JSON only; progress and diagnostics go to stderr.
//! The library crate owns the commands and the TUI so their state and input
//! transitions are testable without a terminal.

use std::process::ExitCode;

use clap::Parser;
use ghosttrace_cli::commands;

fn main() -> ExitCode {
    let cli = commands::Cli::parse();
    ExitCode::from(commands::run(cli))
}

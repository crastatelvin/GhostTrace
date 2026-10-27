//! GhostTrace CLI entry point (plan Sections 9, 17/P2.3).
//!
//! stdout carries machine JSON only; progress and diagnostics go to stderr.

mod commands;
mod output;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = commands::Cli::parse();
    ExitCode::from(commands::run(cli))
}

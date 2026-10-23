//! GhostTrace CLI — P0.1 pilot entry point.
//!
//! Later phases add the planned command set (Section 9); for P0.1 it exposes
//! the verified runtime report so the linked SQLite stack is inspectable.

use clap::Parser;
use ghosttrace_core::sqlite_report;

#[derive(Parser)]
#[command(
    name = "ghosttrace",
    version,
    about = "GhostTrace forensic workbench (pilot)"
)]
enum Cli {
    /// Print the linked SQLite/runtime verification report as JSON.
    SqliteInfo,
}

fn main() {
    match Cli::parse() {
        Cli::SqliteInfo => {
            let report = sqlite_report::sqlite_report();
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("report serializes")
            );
        }
    }
}

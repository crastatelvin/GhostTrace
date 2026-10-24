//! GhostTrace xtask: reproducible checks and fixture tooling (plan P0.2).

mod check;
mod fixtures;

use clap::Parser;

#[derive(Parser)]
#[command(name = "xtask", about = "GhostTrace maintenance tasks")]
enum Cli {
    /// Run the documented check battery (format, lint, tests, features, policy).
    Check,
    /// Verify the tracked fixture catalog (digests, licenses, safety).
    Fixtures {
        /// Verify the fixture catalog against files on disk.
        #[arg(long)]
        verify: bool,
    },
}

fn main() {
    let result = match Cli::parse() {
        Cli::Check => check::run(),
        Cli::Fixtures { verify } => {
            assert!(verify, "fixtures currently supports only --verify");
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("workspace root")
                .join("tests/fixtures");
            fixtures::verify(&root)
        }
    };
    if let Err(problem) = result {
        eprintln!("xtask: {problem}");
        std::process::exit(1);
    }
}

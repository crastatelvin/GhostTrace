//! GhostTrace xtask: reproducible checks and fixture tooling (plan P0.2).

mod check;
mod deps;
mod fixtures;
mod package;
mod scale;

use clap::Parser;

#[derive(Parser)]
#[command(name = "xtask", about = "GhostTrace maintenance tasks")]
enum Cli {
    /// Run the documented check battery (format, lint, tests, features, policy).
    Check,
    /// Check dependency licenses (offline) and advisories (when cargo-audit is installed).
    Deps,
    /// Generate a deterministic corpus and measure capture/ingest/query/backup.
    Scale {
        #[command(subcommand)]
        command: scale::ScaleCommand,
    },
    /// Verify the tracked fixture catalog (digests, licenses, safety).
    Fixtures {
        /// Verify the fixture catalog against files on disk.
        #[arg(long)]
        verify: bool,
    },
    /// Build a checksummed prerelease archive from an already-built CLI/desktop pair.
    Package {
        /// Directory that receives the archive and its .sha256 file.
        #[arg(long, default_value = "dist")]
        output: std::path::PathBuf,
        /// CLI binary to package (default: target/release/ghosttrace).
        #[arg(long)]
        binary: Option<std::path::PathBuf>,
        /// Desktop binary to package (default: target/release/ghosttrace-desktop).
        #[arg(long)]
        desktop: Option<std::path::PathBuf>,
        /// Version string used in the package name.
        #[arg(long, default_value = env!("CARGO_PKG_VERSION"))]
        version: String,
    },
}

fn main() {
    let result = match Cli::parse() {
        Cli::Check => check::run(),
        Cli::Deps => deps::run(),
        Cli::Scale { command } => scale::run(command),
        Cli::Fixtures { verify } => {
            assert!(verify, "fixtures currently supports only --verify");
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("workspace root")
                .join("tests/fixtures");
            fixtures::verify(&root)
        }
        Cli::Package {
            output,
            binary,
            desktop,
            version,
        } => package::run(&package::Options {
            output,
            binary,
            desktop,
            version,
        })
        .map(|summary| println!("{}", serde_json::to_string(&summary).expect("summary"))),
    };
    if let Err(problem) = result {
        eprintln!("xtask: {problem}");
        std::process::exit(1);
    }
}

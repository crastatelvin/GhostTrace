//! `xtask check` — the documented local entry point for reproducible checks
//! (plan P0.2, Section 16 "Shared commands"). Runs the same gates CI runs:
//! format, lint, workspace tests, the documented feature combination, fixture
//! catalog verification, and repository policy checks. Heavy corpora, fuzzing,
//! and benchmarks are explicitly out of scope here.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::fixtures;

/// Repository-root-relative fixture directory.
const FIXTURES_DIR: &str = "tests/fixtures";

struct Repo(PathBuf);

impl Repo {
    fn run(&self, program: &str, args: &[&str]) -> Result<(), String> {
        println!("+ {program} {}", args.join(" "));
        let status = Command::new(program)
            .args(args)
            .current_dir(&self.0)
            .status()
            .map_err(|e| format!("failed to run {program}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{program} {} exited with {status}", args.join(" ")))
        }
    }
}

fn workspace_root() -> PathBuf {
    // xtask runs from the workspace root in practice; CARGO_MANIFEST_DIR's
    // parent is the workspace root for this member.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent directory")
        .to_path_buf()
}

pub fn run() -> Result<(), String> {
    let repo = Repo(workspace_root());

    repo.run("cargo", &["fmt", "--all", "--", "--check"])?;
    repo.run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    repo.run("cargo", &["test", "--workspace", "--locked"])?;

    // Documented supported feature combination: the wgpu backend of the
    // desktop. The default (glow) build is covered by the commands above.
    // `--all-features` is deliberately not used (plan Section 16).
    repo.run(
        "cargo",
        &[
            "build",
            "-p",
            "ghosttrace-desktop",
            "--no-default-features",
            "--features",
            "wgpu",
            "--locked",
        ],
    )?;

    fixtures::verify(&repo.0.join(FIXTURES_DIR))?;
    policy_checks(&repo)
}

/// Policy checks that must hold in a reviewed tree (plan P0.2).
fn policy_checks(repo: &Repo) -> Result<(), String> {
    let lockfile_tracked = tracked_files(repo)?.iter().any(|f| f == "Cargo.lock");
    if !lockfile_tracked {
        return Err("Cargo.lock must be tracked in Git".to_string());
    }

    let forbidden_suffixes = [".pem", ".key", ".p12", ".pfx", ".ghosttrace-case"];
    for file in tracked_files(repo)? {
        if forbidden_suffixes
            .iter()
            .any(|s| file.ends_with(s) || file.contains(&format!("{s}/")))
        {
            return Err(format!("forbidden tracked path: {file}"));
        }
    }

    Ok(())
}

fn tracked_files(repo: &Repo) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(&repo.0)
        .output()
        .map_err(|e| format!("failed to list tracked files: {e}"))?;
    if !output.status.success() {
        return Err("git ls-files failed".to_string());
    }
    Ok(output
        .stdout
        .split(|b| *b == 0)
        .filter(|raw| !raw.is_empty())
        .map(|raw| String::from_utf8_lossy(raw).to_string())
        .collect())
}

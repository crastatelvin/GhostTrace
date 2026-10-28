//! P7 terminal safety at the process boundary: redirected output is refused by
//! the TUI and never receives ANSI control bytes, while the plain CLI stays
//! machine-readable. The restoration guard itself is unit-tested in
//! `src/tui/terminal.rs` (normal exit, enter failure, and unwind paths); a
//! cancelled loop takes the same early-return path as a normal quit.

use std::path::{Path, PathBuf};
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ghosttrace"))
        .args(args)
        .output()
        .expect("cli runs")
}

fn scanned_case(dir: &Path) -> PathBuf {
    let evidence = dir.join("evidence");
    std::fs::create_dir_all(&evidence).expect("evidence dir");
    std::fs::write(
        evidence.join("app.jsonl"),
        "{\"ts\":\"2026-10-27T10:00:00Z\",\"msg\":\"hello\"}\n",
    )
    .expect("jsonl");
    let case = dir.join("demo.ghosttrace-case");
    assert!(
        run(&[
            "case",
            "create",
            "--case",
            case.to_str().unwrap(),
            "--label",
            "Demo",
        ])
        .status
        .success()
    );
    assert_eq!(
        run(&[
            "scan",
            "--case",
            case.to_str().unwrap(),
            "--source",
            evidence.to_str().unwrap(),
        ])
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        run(&[
            "import",
            "--case",
            case.to_str().unwrap(),
            "--path",
            "app.jsonl",
            "--format",
            "jsonl",
        ])
        .status
        .code(),
        Some(0)
    );
    case
}

#[test]
fn the_tui_refuses_redirected_output_instead_of_writing_ansi() {
    let dir = tempfile::tempdir().expect("tempdir");
    let case = scanned_case(dir.path());
    let output = run(&["tui", "--case", case.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(2), "a pipe is a usage error");
    assert!(output.stdout.is_empty(), "nothing is written to a pipe");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("interactive terminal"), "stderr: {stderr}");
    assert!(!stderr.contains('\u{1b}'), "stderr stays plain");
}

#[test]
fn plain_timeline_output_is_json_without_ansi() {
    let dir = tempfile::tempdir().expect("tempdir");
    let case = scanned_case(dir.path());
    let output = run(&["timeline", "--case", case.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        !output.stdout.contains(&0x1b),
        "stdout carries no ESC bytes"
    );
    let page: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(page["rows"].as_array().is_some_and(|rows| !rows.is_empty()));
}

#[test]
fn tui_help_is_plain_and_names_the_case_flag() {
    let output = run(&["tui", "--help"]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("--case"), "help names its inputs");
    assert!(!text.contains('\u{1b}'));
}

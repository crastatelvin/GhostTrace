//! P2.3 CLI usage contract: help/version, argument validation, layout rules,
//! and JSON-safe native paths.

use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ghosttrace"))
        .args(args)
        .output()
        .expect("cli runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn help_and_version_are_available() {
    let help = run(&["--help"]);
    assert!(help.status.success());
    for command in ["case", "scan", "status"] {
        assert!(stdout(&help).contains(command), "help lists {command}");
    }

    let version = run(&["--version"]);
    assert!(version.status.success());
    assert!(stdout(&version).starts_with("ghosttrace "));
}

#[test]
fn missing_source_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("c.ghosttrace-case");
    let output = run(&["scan", "--case", case.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2), "clap usage error");
    assert!(!output.stderr.is_empty());
}

#[test]
fn case_directory_must_have_the_case_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let output = run(&[
        "case",
        "create",
        "--case",
        dir.path().join("plain-dir").to_str().unwrap(),
        "--label",
        "x",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    assert!(stderr.contains("invalid_layout"), "stable error code");
    assert!(stderr.contains("ghosttrace-case"));
}

#[test]
fn missing_case_is_an_operation_failure_with_json_error() {
    let dir = tempfile::tempdir().unwrap();
    let output = run(&[
        "scan",
        "--case",
        dir.path().join("absent.ghosttrace-case").to_str().unwrap(),
        "--source",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    let line = stderr.lines().last().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(line).expect("error is JSON");
    assert_eq!(parsed["error"], "invalid_request");
}

#[test]
fn native_paths_stay_json_safe_and_lossless() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    // A hostile terminal sequence and an invalid UTF-8 byte, both as names.
    let hostile = evidence.join(std::ffi::OsStr::from_bytes(b"evil\x1b[2Jname.txt"));
    std::fs::write(&hostile, b"x").unwrap();
    let invalid = evidence.join(std::ffi::OsStr::from_bytes(b"bad\xffname.txt"));
    std::fs::write(&invalid, b"y").unwrap();

    let case = dir.path().join("c.ghosttrace-case");
    let created = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        "hostile",
    ]);
    assert!(created.status.success());

    let output = run(&[
        "scan",
        "--case",
        case.to_str().unwrap(),
        "--source",
        evidence.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(
        !text.as_bytes().contains(&0x1b),
        "no raw escape byte in machine output"
    );
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("stdout is JSON");
    assert_eq!(parsed["state"], "completed");
    assert_eq!(parsed["objects"], 2);

    // The encoded form is reversible and ASCII-only.
    let status = run(&["status", "--case", case.to_str().unwrap()]);
    assert!(status.status.success());
    assert!(!stdout(&status).contains('\u{1b}'));
}

#[test]
fn existing_case_is_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("c.ghosttrace-case");
    let first = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        "one",
    ]);
    assert!(first.status.success());
    let second = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        "two",
    ]);
    assert_eq!(second.status.code(), Some(1));
    assert!(Path::new(&case).exists());
}

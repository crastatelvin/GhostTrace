//! P5.2 CLI contract: `analyze` reads bounded TOML parameters, prints one
//! explainable report, and exits 2 on invalid parameters.

use std::path::{Path, PathBuf};
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

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn scanned_case(dir: &Path) -> PathBuf {
    let evidence = dir.join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("a.txt"), b"alpha\n").unwrap();
    let case = dir.join("case.ghosttrace-case");
    let created = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        "analyze",
    ]);
    assert!(created.status.success(), "{}", stdout(&created));
    let scanned = run(&[
        "scan",
        "--case",
        case.to_str().unwrap(),
        "--source",
        evidence.to_str().unwrap(),
    ]);
    assert_eq!(scanned.status.code(), Some(0), "{}", stdout(&scanned));
    case
}

#[test]
fn analyze_writes_a_bounded_report_and_replays_its_identity() {
    let dir = tempfile::tempdir().unwrap();
    let case = scanned_case(dir.path());

    let rules = dir.path().join("rules.toml");
    std::fs::write(
        &rules,
        "[auth.fail_then_success]\nfailures = 3\nwindow_seconds = 120\n",
    )
    .unwrap();
    let args = [
        "analyze",
        "--case",
        case.to_str().unwrap(),
        "--rules",
        rules.to_str().unwrap(),
    ];
    let first = run(&args);
    assert_eq!(first.status.code(), Some(0), "{}", stdout(&first));
    let report: serde_json::Value = serde_json::from_str(&stdout(&first)).unwrap();
    assert!(report["run_id"].as_str().unwrap().starts_with("arun-"));
    assert_eq!(report["state"], "completed");
    assert_eq!(report["outcomes"].as_array().unwrap().len(), 5);
    assert!(report["findings"].is_array());

    let second = run(&args);
    assert_eq!(second.status.code(), Some(0));
    let replay: serde_json::Value = serde_json::from_str(&stdout(&second)).unwrap();
    assert_eq!(
        replay["run_id"], report["run_id"],
        "same parameters, same run identity"
    );

    // No rule fired: a scan-only revision still has to explain that per rule.
    for outcome in report["outcomes"].as_array().unwrap() {
        assert!(outcome["reason"].is_string() || outcome["status"] == "evaluated");
    }
}

#[test]
fn invalid_rule_parameters_are_usage_errors() {
    let dir = tempfile::tempdir().unwrap();
    let case = scanned_case(dir.path());

    let rules = dir.path().join("rules.toml");
    std::fs::write(&rules, "[auth.fail_then_success]\nfailure = 3\n").unwrap();
    let output = run(&[
        "analyze",
        "--case",
        case.to_str().unwrap(),
        "--rules",
        rules.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("invalid_request"));

    let missing = run(&[
        "analyze",
        "--case",
        case.to_str().unwrap(),
        "--rules",
        dir.path().join("absent.toml").to_str().unwrap(),
    ]);
    assert_eq!(missing.status.code(), Some(2));

    // A case with no parse run says so instead of analyzing nothing.
    let empty = dir.path().join("empty.ghosttrace-case");
    let created = run(&[
        "case",
        "create",
        "--case",
        empty.to_str().unwrap(),
        "--label",
        "empty",
    ]);
    assert!(created.status.success());
    let output = run(&["analyze", "--case", empty.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("no parse run"));
}

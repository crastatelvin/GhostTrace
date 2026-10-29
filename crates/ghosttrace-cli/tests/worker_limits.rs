//! P8.2: the isolated worker path is bounded and produces the same records as
//! the trusted in-process baseline.
//!
//! Every case here runs the real CLI worker (`ghosttrace worker`), so the
//! handshake, staging, framing, validation, and commit path are exercised
//! end to end.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const SYSMON: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/evtx/sysmon.evtx"
));

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ghosttrace"))
        .args(args)
        .output()
        .expect("cli runs")
}

fn case_with_sysmon(dir: &Path, name: &str) -> PathBuf {
    let evidence = dir.join(format!("evidence-{name}"));
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("sysmon.evtx"), SYSMON).unwrap();
    let case = dir.join(format!("{name}.ghosttrace-case"));
    let created = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        name,
    ]);
    assert!(created.status.success(), "{created:?}");
    let scanned = run(&[
        "scan",
        "--case",
        case.to_str().unwrap(),
        "--source",
        evidence.to_str().unwrap(),
    ]);
    assert_eq!(scanned.status.code(), Some(0), "{scanned:?}");
    case
}

fn import(case: &Path, extra: &[&str]) -> (i32, Value) {
    let mut args = vec![
        "import",
        "--case",
        case.to_str().unwrap(),
        "--path",
        "sysmon.evtx",
    ];
    args.extend_from_slice(extra);
    let output = run(&args);
    let code = output.status.code().expect("exit code");
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "import output is not JSON: {error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (code, parsed)
}

fn diagnostics_codes(outcome: &Value) -> Vec<String> {
    outcome["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .map(|diagnostic| diagnostic["code"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn the_worker_path_matches_the_in_process_baseline() {
    let dir = tempfile::tempdir().unwrap();
    let isolated = case_with_sysmon(dir.path(), "isolated");
    let in_process = case_with_sysmon(dir.path(), "in-process");

    let (isolated_code, isolated_outcome) = import(&isolated, &[]);
    let (in_process_code, in_process_outcome) = import(&in_process, &["--no-worker"]);

    assert_eq!(isolated_code, 3, "the fixture has unreadable chunks");
    assert_eq!(in_process_code, isolated_code);
    for field in [
        "state",
        "records",
        "observations",
        "events",
        "diagnostics_total",
        "parser_id",
        "detected_format",
    ] {
        assert_eq!(
            isolated_outcome[field], in_process_outcome[field],
            "{field} differs between the worker and in-process paths"
        );
    }
    assert_eq!(
        diagnostics_codes(&isolated_outcome),
        diagnostics_codes(&in_process_outcome),
        "the worker path reports the same diagnostics"
    );
    assert_eq!(isolated_outcome["state"], "partial");
    assert_eq!(isolated_outcome["records"], 358);
}

#[test]
fn record_limit_is_enforced_across_the_worker() {
    let dir = tempfile::tempdir().unwrap();
    let case = case_with_sysmon(dir.path(), "limit");
    let (code, outcome) = import(&case, &["--max-records", "5"]);
    assert_eq!(code, 3);
    assert_eq!(outcome["state"], "partial");
    assert_eq!(outcome["records"], 5);
    assert_eq!(outcome["observations"], 5);
    assert_eq!(outcome["events"], 5);
    assert!(
        diagnostics_codes(&outcome)
            .iter()
            .any(|code| code == "record_limit"),
        "{}",
        outcome["diagnostics"]
    );
}

#[test]
fn oversize_records_are_reported_across_the_worker() {
    let dir = tempfile::tempdir().unwrap();
    let isolated = case_with_sysmon(dir.path(), "oversize-worker");
    let in_process = case_with_sysmon(dir.path(), "oversize-in-process");

    let (isolated_code, isolated_outcome) = import(&isolated, &["--max-record-bytes", "64"]);
    let (in_process_code, in_process_outcome) =
        import(&in_process, &["--max-record-bytes", "64", "--no-worker"]);

    assert_eq!(isolated_code, 3);
    assert_eq!(in_process_code, isolated_code);
    for field in [
        "state",
        "records",
        "observations",
        "events",
        "diagnostics_total",
    ] {
        assert_eq!(
            isolated_outcome[field], in_process_outcome[field],
            "{field} differs between the worker and in-process paths"
        );
    }
    assert_eq!(isolated_outcome["events"], 0, "no record fits 64 bytes");
    assert!(
        diagnostics_codes(&isolated_outcome)
            .iter()
            .any(|code| code == "record_too_large"),
        "{}",
        isolated_outcome["diagnostics"]
    );
}

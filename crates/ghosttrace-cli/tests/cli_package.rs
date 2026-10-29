//! P9.2 CLI contract: redacted exports, portable packages, and verified
//! backup/restore work end to end through the documented commands.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ghosttrace")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().expect("cli runs")
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("json stdout")
}

fn setup(dir: &Path) -> PathBuf {
    let evidence = dir.join("evidence");
    std::fs::create_dir_all(evidence.join("logs")).unwrap();
    std::fs::write(
        evidence.join("logs/app.jsonl"),
        b"{\"ts\":\"2026-10-27T10:00:00Z\",\"msg\":\"secret-one\"}\n\
{\"ts\":\"2026-10-27T10:01:00Z\",\"msg\":\"secret-two\"}\n",
    )
    .unwrap();
    let case = dir.join("case.ghosttrace-case");
    let created = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        "secret-case-label",
    ]);
    assert!(created.status.success(), "{created:?}");
    let scanned = run(&[
        "scan",
        "--case",
        case.to_str().unwrap(),
        "--source",
        evidence.to_str().unwrap(),
    ]);
    assert!(
        matches!(scanned.status.code(), Some(0) | Some(3)),
        "{scanned:?}"
    );
    let imported = run(&[
        "import",
        "--case",
        case.to_str().unwrap(),
        "--path",
        "logs/app.jsonl",
        "--message-field",
        "msg",
    ]);
    assert_eq!(imported.status.code(), Some(0), "{imported:?}");
    case
}

#[test]
fn a_redacted_report_writes_csv_and_a_value_free_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let case = setup(dir.path());
    let output = dir.path().join("reports");
    let published = run(&[
        "report",
        "--case",
        case.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--csv",
        "--redact",
        "timeline-summaries",
        "--redact",
        "case-label",
    ]);
    assert_eq!(published.status.code(), Some(0), "{published:?}");
    let report = json(&published);
    assert_eq!(report["redacted"], true);
    assert!(
        report["redaction"]
            .as_str()
            .unwrap()
            .contains("timeline.summary")
    );
    let csv = report["csv"].as_str().unwrap();
    assert!(Path::new(csv).is_file(), "{csv}");
    assert!(csv.ends_with("report.csv"));

    let directory = Path::new(report["directory"].as_str().unwrap());
    let report_json = std::fs::read_to_string(directory.join("report.json")).unwrap();
    assert!(report_json.contains("[redacted]"));
    assert!(!report_json.contains("secret-one"));
    assert!(!report_json.contains("secret-case-label"));
    let ledger = std::fs::read_to_string(directory.join("redaction.json")).unwrap();
    assert!(!ledger.contains("secret-one"));
    assert!(ledger.contains("\"count\""));
    let timeline = std::fs::read_to_string(directory.join("report.csv")).unwrap();
    assert!(!timeline.contains("secret-one"));
}

#[test]
fn a_package_verifies_and_a_modified_byte_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let case = setup(dir.path());
    let output = dir.path().join("packages");
    let published = run(&[
        "package",
        "--case",
        case.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(published.status.code(), Some(0), "{published:?}");
    let package = json(&published);
    let directory = PathBuf::from(package["directory"].as_str().unwrap());
    assert!(directory.join("package.json").is_file());
    assert!(directory.join("manifest.json").is_file());
    assert_eq!(package["signed"], false);

    let verified = run(&["verify-package", "--package", directory.to_str().unwrap()]);
    assert_eq!(verified.status.code(), Some(0), "{verified:?}");
    let report = json(&verified);
    assert_eq!(report["verified"], true);
    assert_eq!(report["signature"], "absent");
    assert_eq!(report["key_trust"], "not_applicable");

    let report_json = directory.join("report.json");
    let mut bytes = std::fs::read(&report_json).unwrap();
    bytes[0] ^= 0xff;
    std::fs::write(&report_json, bytes).unwrap();
    let rejected = run(&["verify-package", "--package", directory.to_str().unwrap()]);
    assert_eq!(rejected.status.code(), Some(4), "{rejected:?}");
    let stderr = String::from_utf8(rejected.stderr).unwrap();
    assert!(
        stderr.contains("corrupt_evidence") || stderr.contains("integrity_mismatch"),
        "{stderr}"
    );
}

#[test]
fn a_backup_restores_into_a_case_that_opens_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let case = setup(dir.path());
    let output = dir.path().join("backups");
    let backed_up = run(&[
        "backup",
        "--case",
        case.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(backed_up.status.code(), Some(0), "{backed_up:?}");
    let backup = json(&backed_up);
    let backup_directory = backup["directory"].as_str().unwrap().to_string();
    assert!(Path::new(&backup_directory).join("backup.json").is_file());

    let restored = dir.path().join("restored.ghosttrace-case");
    let restore = run(&[
        "restore",
        "--backup",
        &backup_directory,
        "--destination",
        restored.to_str().unwrap(),
    ]);
    assert_eq!(restore.status.code(), Some(0), "{restore:?}");
    assert_eq!(json(&restore)["case_id"], backup["case_id"]);

    let status = run(&["status", "--case", restored.to_str().unwrap()]);
    assert_eq!(status.status.code(), Some(0), "{status:?}");
    let verify = run(&["verify", "--case", restored.to_str().unwrap()]);
    assert_eq!(verify.status.code(), Some(0), "{verify:?}");
    let timeline = run(&["timeline", "--case", restored.to_str().unwrap()]);
    assert_eq!(timeline.status.code(), Some(0), "{timeline:?}");
    assert!(!json(&timeline)["rows"].as_array().unwrap().is_empty());

    let again = run(&[
        "restore",
        "--backup",
        &backup_directory,
        "--destination",
        restored.to_str().unwrap(),
    ]);
    assert_eq!(again.status.code(), Some(1), "{again:?}");
}

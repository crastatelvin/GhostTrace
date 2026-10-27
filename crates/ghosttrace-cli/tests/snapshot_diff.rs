//! P3.1 snapshot-diff contract: full-hash comparison with metadata, coverage
//! gaps, scope checks, and move candidates that never assert intent.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::UNIX_EPOCH;

use nix::sys::stat::UtimensatFlags;
use nix::sys::time::TimeSpec;

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ghosttrace"))
        .args(args)
        .output()
        .expect("cli runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn create_case(dir: &Path) -> PathBuf {
    let case = dir.join("case.ghosttrace-case");
    let output = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        "diff",
    ]);
    assert!(output.status.success());
    case
}

fn scan(case: &Path, source: &Path, extra: &[&str]) -> String {
    scan_expecting(case, source, extra, 0)
}

fn scan_expecting(case: &Path, source: &Path, extra: &[&str], expected: i32) -> String {
    let mut args = vec![
        "scan".to_string(),
        "--case".to_string(),
        case.to_str().unwrap().to_string(),
        "--source".to_string(),
        source.to_str().unwrap().to_string(),
    ];
    args.extend(extra.iter().map(|arg| arg.to_string()));
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&borrowed);
    assert_eq!(
        output.status.code(),
        Some(expected),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    parsed["acquisition_id"].as_str().unwrap().to_string()
}

fn diff(case: &Path, before: &str, after: &str, extra: &[&str]) -> serde_json::Value {
    let mut args = vec![
        "diff".to_string(),
        "--case".to_string(),
        case.to_str().unwrap().to_string(),
        "--before".to_string(),
        before.to_string(),
        "--after".to_string(),
        after.to_string(),
    ];
    args.extend(extra.iter().map(|arg| arg.to_string()));
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(&borrowed);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_str(&stdout(&output)).unwrap()
}

fn class_of<'a>(report: &'a serde_json::Value, path: &str) -> &'a str {
    report["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == path)
        .unwrap_or_else(|| panic!("missing row for {path}"))["class"]
        .as_str()
        .unwrap()
}

fn mtime(path: &Path) -> TimeSpec {
    let modified = std::fs::metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap();
    TimeSpec::new(modified.as_secs() as i64, modified.subsec_nanos() as i64)
}

fn set_mtime(path: &Path, stamp: TimeSpec) {
    nix::sys::stat::utimensat(
        nix::fcntl::AT_FDCWD,
        path,
        &stamp,
        &stamp,
        UtimensatFlags::FollowSymlink,
    )
    .unwrap();
}

fn seed(evidence: &Path) {
    std::fs::create_dir_all(evidence).unwrap();
    for (name, bytes) in [
        ("unchanged.txt", &b"same\n"[..]),
        ("same_meta.txt", &b"AAAA\n"[..]),
        ("metadata.txt", &b"meta\n"[..]),
        ("changed.txt", &b"before\n"[..]),
        ("gone.txt", &b"gone\n"[..]),
        ("moved-src.txt", &b"move me\n"[..]),
    ] {
        std::fs::write(evidence.join(name), bytes).unwrap();
    }
}

#[test]
fn diff_classifies_content_metadata_and_scope_honestly() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    seed(&evidence);
    let case = create_case(dir.path());
    let before = scan(&case, &evidence, &[]);

    // Same size and mtime, different bytes.
    let same_meta = evidence.join("same_meta.txt");
    let preserved = mtime(&same_meta);
    std::fs::write(&same_meta, b"BBBB\n").unwrap();
    set_mtime(&same_meta, preserved);

    // Same bytes, different mtime.
    let metadata = evidence.join("metadata.txt");
    let older = TimeSpec::new(preserved.tv_sec() - 500, 0);
    set_mtime(&metadata, older);

    // Different content and metadata.
    std::fs::write(evidence.join("changed.txt"), b"after and longer\n").unwrap();
    std::fs::remove_file(evidence.join("gone.txt")).unwrap();
    std::fs::rename(
        evidence.join("moved-src.txt"),
        evidence.join("moved-dst.txt"),
    )
    .unwrap();
    std::fs::write(evidence.join("appeared.txt"), b"new\n").unwrap();

    let after = scan(&case, &evidence, &[]);
    assert_ne!(before, after);
    let report = diff(&case, &before, &after, &["--limit", "100"]);

    assert_eq!(report["summary"]["scope_compatible"], true);
    assert_eq!(class_of(&report, "unchanged.txt"), "unchanged");
    assert_eq!(
        class_of(&report, "same_meta.txt"),
        "content_changed_equal_metadata",
        "timestamp preservation never hides changed bytes"
    );
    assert_eq!(class_of(&report, "metadata.txt"), "metadata_changed");
    assert_eq!(class_of(&report, "changed.txt"), "content_changed");
    assert_eq!(
        class_of(&report, "gone.txt"),
        "not_present_in_captured_scope"
    );
    assert_eq!(class_of(&report, "moved-src.txt"), "move_candidate");
    assert_eq!(class_of(&report, "moved-dst.txt"), "move_candidate");
    assert_eq!(class_of(&report, "appeared.txt"), "appeared");

    let summary = &report["summary"];
    assert_eq!(summary["unchanged"], 1);
    assert_eq!(summary["content_changed_equal_metadata"], 1);
    assert_eq!(summary["metadata_changed"], 1);
    assert_eq!(summary["content_changed"], 1);
    assert_eq!(summary["appeared"], 1);
    assert_eq!(summary["not_present_in_captured_scope"], 1, "gone.txt only");
    assert_eq!(summary["move_candidates"], 2);

    let gone = report["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "gone.txt")
        .unwrap();
    assert!(
        gone["reason"]
            .as_str()
            .unwrap()
            .contains("deletion not established")
    );
    let moved = report["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "moved-dst.txt")
        .unwrap();
    assert!(moved["reason"].as_str().unwrap().contains("not proven"));
}

#[test]
fn coverage_gap_makes_absence_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    seed(&evidence);
    let case = create_case(dir.path());
    let before = scan(&case, &evidence, &[]);
    // Every non-empty file is skipped: the later scope has coverage gaps.
    let after = scan_expecting(&case, &evidence, &["--max-file-bytes", "0"], 3);

    let report = diff(&case, &before, &after, &["--limit", "100"]);
    let row = report["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "unchanged.txt")
        .unwrap();
    assert_eq!(row["class"], "unknown");
    assert!(row["reason"].as_str().unwrap().contains("coverage gap"));
    assert_eq!(report["summary"]["not_present_in_captured_scope"], 0);
}

#[test]
fn different_roots_are_never_compared_as_deletion() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    seed(&first);
    std::fs::create_dir_all(&second).unwrap();
    std::fs::write(second.join("other.txt"), b"other\n").unwrap();
    let case = create_case(dir.path());
    let before = scan(&case, &first, &[]);
    let after = scan(&case, &second, &[]);

    let report = diff(&case, &before, &after, &["--limit", "100"]);
    assert_eq!(report["summary"]["scope_compatible"], false);
    assert_eq!(report["summary"]["appeared"], 0);
    assert_eq!(report["summary"]["not_present_in_captured_scope"], 0);
    assert!(report["summary"]["unknown"].as_u64().unwrap() > 0);
    assert!(
        report["summary"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("different roots"))
    );
}

#[test]
fn diff_pages_are_stable() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    seed(&evidence);
    let case = create_case(dir.path());
    let before = scan(&case, &evidence, &[]);
    let after = scan(&case, &evidence, &[]);

    let full = diff(&case, &before, &after, &["--limit", "100"]);
    let expected: Vec<String> = full["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["path"].as_str().unwrap().to_string())
        .collect();

    let mut collected = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut extra = vec!["--limit".to_string(), "2".to_string()];
        if let Some(cursor) = &cursor {
            extra.push("--cursor".to_string());
            extra.push(cursor.clone());
        }
        let borrowed: Vec<&str> = extra.iter().map(String::as_str).collect();
        let page = diff(&case, &before, &after, &borrowed);
        for row in page["rows"].as_array().unwrap() {
            collected.push(row["path"].as_str().unwrap().to_string());
        }
        if page["next_cursor"].is_null() {
            break;
        }
        cursor = page["next_cursor"].as_str().map(str::to_string);
    }
    assert_eq!(collected, expected, "paging never skips or repeats");
}

#[test]
fn unknown_acquisition_is_an_operation_failure() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    seed(&evidence);
    let case = create_case(dir.path());
    let before = scan(&case, &evidence, &[]);

    let output = run(&[
        "diff",
        "--case",
        case.to_str().unwrap(),
        "--before",
        &before,
        "--after",
        "acq-does-not-exist",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("\"error\""));
}

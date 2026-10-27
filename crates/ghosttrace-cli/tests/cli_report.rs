//! P3.2 report safety: hostile labels and paths stay inert in the HTML, the
//! JSON stays full fidelity, and publication is atomic and append-only.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ghosttrace")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().expect("cli runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn create_case(dir: &Path, label: &str) -> PathBuf {
    let case = dir.join("case.ghosttrace-case");
    let output = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        label,
    ]);
    assert!(output.status.success(), "{output:?}");
    case
}

fn scan(case: &Path, source: &Path, claimed_source: &str, extra: &[&str]) -> serde_json::Value {
    let mut args = vec![
        "scan",
        "--case",
        case.to_str().unwrap(),
        "--source",
        source.to_str().unwrap(),
        "--claimed-source",
        claimed_source,
    ];
    args.extend_from_slice(extra);
    let output = run(&args);
    assert!(
        matches!(output.status.code(), Some(0) | Some(3)),
        "{output:?}"
    );
    serde_json::from_str(&stdout(&output)).unwrap()
}

fn report(case: &Path, output_dir: &Path, extra: &[&str]) -> Output {
    let mut args = vec![
        "report",
        "--case",
        case.to_str().unwrap(),
        "--output",
        output_dir.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    run(&args)
}

const HOSTILE: &str = "<script>alert(1)</script>\"'& javascript:alert(1) https://evil.example/x \u{1b}[31m \u{202e}txt";

#[test]
fn hostile_text_stays_inert_in_html_and_full_fidelity_in_json() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    // A hostile *file name* too; the recorded path is encoded, so it cannot
    // become markup, but the report must still list it readably.
    std::fs::write(evidence.join("<img src=x onerror=alert(1)>.txt"), b"safe\n").unwrap();
    // Invalid UTF-8 path bytes must be reported in the reversible encoded form.
    use std::os::unix::ffi::OsStrExt;
    let invalid = std::ffi::OsStr::from_bytes(b"bad\xffname.txt");
    std::fs::write(evidence.join(invalid), b"raw\n").unwrap();
    let case = create_case(dir.path(), HOSTILE);
    scan(&case, &evidence, HOSTILE, &[]);

    let output_dir = dir.path().join("out");
    let output = report(&case, &output_dir, &["--report-id", "fixed"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");

    let html = std::fs::read_to_string(output_dir.join("fixed/report.html")).unwrap();
    let json_text = std::fs::read_to_string(output_dir.join("fixed/report.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&json_text).unwrap();

    assert_eq!(json["format"], "ghosttrace-report/1");
    assert_eq!(json["case"]["label"], HOSTILE, "JSON keeps the exact bytes");
    assert_eq!(json["provenance"]["claimed_source"], HOSTILE);

    // No active content, no navigation, no remote fetches.
    assert!(!html.contains("<script"), "{html}");
    assert!(!html.contains("href="), "{html}");
    assert!(!html.contains("src="), "{html}");
    assert!(
        !html.contains('\u{1b}'),
        "terminal control must not survive"
    );
    assert!(!html.contains('\u{202e}'), "bidi override must not survive");
    assert!(
        html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "{html}"
    );
    assert!(html.contains("\\u{1b}"), "{html}");
    assert!(html.contains("\\u{202e}"), "{html}");
    assert!(
        html.contains("https://evil.example/x"),
        "URL text stays readable"
    );
    assert!(
        html.contains("%FF"),
        "invalid path bytes use the encoded form"
    );
    // The encoder leaves no raw control bytes in the JSON either.
    assert!(
        !json_text.contains('\u{1b}'),
        "JSON must escape control bytes"
    );
}

#[test]
fn publication_never_overwrites_a_previous_report() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("a.txt"), b"alpha\n").unwrap();
    let case = create_case(dir.path(), "reports");
    scan(&case, &evidence, "seized laptop", &[]);
    let output_dir = dir.path().join("out");

    let first = report(&case, &output_dir, &["--report-id", "fixed"]);
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    let html_path = output_dir.join("fixed/report.html");
    let before = std::fs::read(&html_path).unwrap();

    let second = report(&case, &output_dir, &["--report-id", "fixed"]);
    assert_eq!(second.status.code(), Some(1), "{second:?}");
    assert!(
        stderr(&second).contains("refusing to overwrite"),
        "{second:?}"
    );
    assert_eq!(std::fs::read(&html_path).unwrap(), before);
    // No half-written staging directory is left looking like an export.
    let leftovers: Vec<_> = std::fs::read_dir(&output_dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name())
        .collect();
    assert_eq!(leftovers, vec![std::ffi::OsString::from("fixed")]);
}

#[test]
fn failed_publication_leaves_no_completed_export() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("a.txt"), b"alpha\n").unwrap();
    let case = create_case(dir.path(), "reports");
    scan(&case, &evidence, "seized laptop", &[]);

    // The output parent is a regular file, so nothing can be published.
    let output_dir = dir.path().join("blocked");
    std::fs::write(&output_dir, b"not a directory").unwrap();
    let output = report(&case, &output_dir, &["--report-id", "fixed"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!output_dir.join("fixed").exists());
}

#[test]
fn report_lists_coverage_omissions_and_unknown_acquisition_fails() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("big.bin"), b"larger than the cap").unwrap();
    let case = create_case(dir.path(), "partial");
    let scan = scan(
        &case,
        &evidence,
        "seized laptop",
        &["--max-file-bytes", "1"],
    );
    assert_eq!(scan["coverage"]["excluded"], 1);

    let output_dir = dir.path().join("out");
    let output = report(&case, &output_dir, &["--report-id", "partial"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(output_dir.join("partial/report.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(json["coverage"]["excluded"], 1);
    assert_eq!(json["coverage"]["gaps"][0]["status"], "excluded");
    assert_eq!(json["coverage"]["gaps_complete"], true);
    let limitations: Vec<&str> = json["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert!(limitations.iter().any(|text| text.contains("not captured")));

    let html = std::fs::read_to_string(output_dir.join("partial/report.html")).unwrap();
    assert!(html.contains("excluded"), "{html}");
    assert!(html.contains("big.bin"), "{html}");

    let missing = report(
        &case,
        &dir.path().join("other"),
        &["--acquisition", "acq-does-not-exist"],
    );
    assert_eq!(missing.status.code(), Some(1), "{missing:?}");
    assert!(!dir.path().join("other").join("acq-does-not-exist").exists());
}

#[test]
fn unsafe_report_id_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("a.txt"), b"alpha\n").unwrap();
    let case = create_case(dir.path(), "usage");
    scan(&case, &evidence, "seized laptop", &[]);
    let output = report(
        &case,
        &dir.path().join("out"),
        &["--report-id", "../escape"],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

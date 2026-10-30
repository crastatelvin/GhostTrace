//! P5.2 CLI contract for `annotate`: appends are revisioned and never
//! overwrite, usage errors are exit 2, and history reads back what was
//! recorded.

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

fn json_field(output: &Output, path: &[&str]) -> String {
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    let mut current = &value;
    for key in path {
        current = &current[key];
    }
    match current {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Number(number) => number.to_string(),
        _ => current.as_str().unwrap().to_string(),
    }
}

/// The tracked logon sample's evidence directory, found by walking the tracked
/// samples so the test never depends on a hand-typed directory name.
fn sample_evidence() -> PathBuf {
    let samples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples");
    for entry in std::fs::read_dir(&samples).unwrap() {
        let evidence = entry.unwrap().path().join("evidence");
        if evidence.join("events.jsonl").is_file() {
            return evidence;
        }
    }
    panic!(
        "no tracked sample with evidence/events.jsonl under {}",
        samples.display()
    );
}

/// The tracked sample: scan its evidence and import it with declared fields so
/// the compiled rules have supported events.
fn imported_case(dir: &Path) -> PathBuf {
    let evidence = sample_evidence();
    let case = dir.join("case.ghosttrace-case");
    let created = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        "annotate",
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
    let imported = run(&[
        "import",
        "--case",
        case.to_str().unwrap(),
        "--path",
        "events.jsonl",
        "--format",
        "jsonl",
        "--time-field",
        "ts",
        "--time-format",
        "rfc3339",
        "--kind-field",
        "kind",
        "--host-field",
        "host",
        "--message-field",
        "msg",
    ]);
    assert_eq!(imported.status.code(), Some(0), "{}", stdout(&imported));
    case
}

fn analyzed_finding(case: &Path) -> String {
    let analyzed = run(&["analyze", "--case", case.to_str().unwrap()]);
    assert_eq!(analyzed.status.code(), Some(0), "{}", stdout(&analyzed));
    let value: serde_json::Value = serde_json::from_slice(&analyzed.stdout).expect("json stdout");
    value["findings"][0]["id"].as_str().unwrap().to_string()
}

fn timeline_event(case: &Path) -> String {
    let listed = run(&["timeline", "--case", case.to_str().unwrap(), "--limit", "1"]);
    assert_eq!(listed.status.code(), Some(0), "{}", stdout(&listed));
    let value: serde_json::Value = serde_json::from_slice(&listed.stdout).expect("json stdout");
    value["rows"][0]["event_id"].as_str().unwrap().to_string()
}

#[test]
fn a_finding_disposition_is_an_append_that_names_its_predecessor() {
    let dir = tempfile::tempdir().unwrap();
    let case = imported_case(dir.path());
    let finding = analyzed_finding(&case);

    let recorded = run(&[
        "annotate",
        "--case",
        case.to_str().unwrap(),
        "record",
        "--finding",
        &finding,
        "--author",
        "analyst-a",
        "--text",
        "checked the source log",
        "--tags",
        "triage, needs context",
        "--disposition",
        "confirmed",
    ]);
    assert_eq!(recorded.status.code(), Some(0), "{}", stdout(&recorded));
    assert_eq!(json_field(&recorded, &["revision_id"]), "1");
    assert_eq!(json_field(&recorded, &["disposition"]), "confirmed");
    assert_eq!(json_field(&recorded, &["previous_revision"]), "null");

    let superseding = run(&[
        "annotate",
        "--case",
        case.to_str().unwrap(),
        "record",
        "--finding",
        &finding,
        "--author",
        "analyst-b",
        "--text",
        "correlated with the download",
        "--disposition",
        "commented",
    ]);
    assert_eq!(
        superseding.status.code(),
        Some(0),
        "{}",
        stdout(&superseding)
    );
    // The second revision names the first instead of overwriting it.
    assert_eq!(json_field(&superseding, &["revision_id"]), "2");
    assert_eq!(json_field(&superseding, &["previous_revision"]), "1");

    let history = run(&[
        "annotate",
        "--case",
        case.to_str().unwrap(),
        "history",
        "--finding",
        &finding,
    ]);
    assert_eq!(history.status.code(), Some(0), "{}", stdout(&history));
    let value: serde_json::Value = serde_json::from_slice(&history.stdout).expect("json stdout");
    let revisions = value["revisions"].as_array().unwrap();
    assert_eq!(revisions.len(), 2, "{}", stdout(&history));
    assert_eq!(revisions[0]["revision_id"].as_i64(), Some(2));
    assert_eq!(
        revisions[0]["previous_revision"].as_i64(),
        Some(1),
        "newest first, with the predecessor named"
    );
}

#[test]
fn an_event_note_carries_a_bookmark_tag_and_no_disposition() {
    let dir = tempfile::tempdir().unwrap();
    let case = imported_case(dir.path());
    let event = timeline_event(&case);

    let recorded = run(&[
        "annotate",
        "--case",
        case.to_str().unwrap(),
        "record",
        "--event",
        &event,
        "--author",
        "analyst-a",
        "--text",
        "revisit with the security log",
        "--tags",
        "bookmark",
    ]);
    assert_eq!(recorded.status.code(), Some(0), "{}", stdout(&recorded));
    assert_eq!(json_field(&recorded, &["disposition"]), "null");

    let history = run(&[
        "annotate",
        "--case",
        case.to_str().unwrap(),
        "history",
        "--event",
        &event,
    ]);
    let value: serde_json::Value = serde_json::from_slice(&history.stdout).expect("json stdout");
    assert_eq!(value["revisions"][0]["tags"][0].as_str(), Some("bookmark"));
    assert_eq!(
        value["revisions"][0]["text"].as_str(),
        Some("revisit with the security log")
    );
}

#[test]
fn usage_errors_are_rejected_before_the_case_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let case = imported_case(dir.path());
    let finding = analyzed_finding(&case);
    let event = timeline_event(&case);

    let no_target = &[
        "annotate",
        "--case",
        case.to_str().unwrap(),
        "record",
        "--author",
        "analyst-a",
        "--text",
        "no target",
    ];
    let output = run(no_target);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(stdout(&output).is_empty(), "errors belong on stderr");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("exactly one target")
    );

    let both_targets = &[
        "annotate",
        "--case",
        case.to_str().unwrap(),
        "history",
        "--event",
        &event,
        "--finding",
        &finding,
    ];
    assert_eq!(run(both_targets).status.code(), Some(2));

    let disposition_on_event = &[
        "annotate",
        "--case",
        case.to_str().unwrap(),
        "record",
        "--event",
        &event,
        "--author",
        "analyst-a",
        "--disposition",
        "confirmed",
    ];
    let rejected = run(disposition_on_event);
    assert_eq!(rejected.status.code(), Some(2), "{}", stdout(&rejected));
    assert!(
        String::from_utf8(rejected.stderr)
            .unwrap()
            .contains("applies to a finding")
    );

    // Nothing was written by the rejected attempts.
    let history = run(&[
        "annotate",
        "--case",
        case.to_str().unwrap(),
        "history",
        "--event",
        &event,
    ]);
    let value: serde_json::Value = serde_json::from_slice(&history.stdout).expect("json stdout");
    assert!(value["revisions"].as_array().unwrap().is_empty());
}

#[test]
fn an_empty_author_is_rejected_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let case = imported_case(dir.path());
    let finding = analyzed_finding(&case);

    let rejected = run(&[
        "annotate",
        "--case",
        case.to_str().unwrap(),
        "record",
        "--finding",
        &finding,
        "--author",
        "   ",
    ]);
    assert!(rejected.status.code().is_some_and(|code| code != 0));

    let history = run(&[
        "annotate",
        "--case",
        case.to_str().unwrap(),
        "history",
        "--finding",
        &finding,
    ]);
    let value: serde_json::Value = serde_json::from_slice(&history.stdout).expect("json stdout");
    assert!(value["revisions"].as_array().unwrap().is_empty());
}

//! P3.1 timeline contract: case-latest anchor, explicit bounds, the unresolved
//! view, kind/host/source filters, and stable repeated pages.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ghosttrace_core::domain::event::{Event, NamedEventTimeRef};
use ghosttrace_core::domain::time::{EventTime, TimeSemantic};
use ghosttrace_core::service::CaseSession;
use ghosttrace_core::storage::writer::{Param, WriteBatch, WriteOp};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ghosttrace"))
        .args(args)
        .output()
        .expect("cli runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn create_and_scan(dir: &Path) -> (PathBuf, Vec<String>) {
    let evidence = dir.join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("a.txt"), b"alpha\n").unwrap();
    std::fs::write(evidence.join("b.txt"), b"bravo\n").unwrap();
    let case = dir.join("case.ghosttrace-case");
    let created = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        "timeline",
    ]);
    assert!(created.status.success());
    let scanned = run(&[
        "scan",
        "--case",
        case.to_str().unwrap(),
        "--source",
        evidence.to_str().unwrap(),
    ]);
    assert_eq!(scanned.status.code(), Some(0));
    let acquisition: serde_json::Value = serde_json::from_str(&stdout(&scanned)).unwrap();
    let acquisition_id = acquisition["acquisition_id"].as_str().unwrap().to_string();
    (case, vec![acquisition_id])
}

/// Add one parse run plus events at controlled instants, including an event
/// with no resolved time at all.
fn seed_extra_events(case: &Path, acquisition_id: &str) {
    let session = CaseSession::open(case).unwrap().0;
    let writer = session.writer();
    writer
        .execute(
            WriteBatch::new()
                .push(WriteOp::fact(
                    "parse_runs",
                    vec![
                        "id",
                        "acquisition_id",
                        "parser_id",
                        "parser_version",
                        "config_digest",
                        "state",
                        "counts_json",
                        "diagnostics_json",
                    ],
                    vec![
                        Param::Text("run-demo".into()),
                        Param::Text(acquisition_id.to_string()),
                        Param::Text("demo.parser.v1".into()),
                        Param::Text("1.0".into()),
                        Param::Text(String::new()),
                        Param::Text("completed".into()),
                        Param::Text("{}".into()),
                        Param::Text("[]".into()),
                    ],
                ))
                .push(WriteOp::fact(
                    "parse_runs",
                    vec![
                        "id",
                        "acquisition_id",
                        "parser_id",
                        "parser_version",
                        "config_digest",
                        "state",
                        "counts_json",
                        "diagnostics_json",
                    ],
                    vec![
                        Param::Text("run-other".into()),
                        Param::Text(acquisition_id.to_string()),
                        Param::Text("other.parser.v1".into()),
                        Param::Text("1.0".into()),
                        Param::Text(String::new()),
                        Param::Text("completed".into()),
                        Param::Text("{}".into()),
                        Param::Text("[]".into()),
                    ],
                )),
        )
        .unwrap();

    let timed = |id: &str, run: &str, kind: &str, host: Option<&str>, seconds: i64| Event {
        id: id.to_string(),
        kind: kind.to_string(),
        summary: format!("{kind} at {seconds}"),
        observations: Vec::new(),
        times: vec![NamedEventTimeRef {
            name: "chosen".to_string(),
            semantic: TimeSemantic::OccurrenceTime,
            value: EventTime::from_unix_seconds(seconds, TimeSemantic::OccurrenceTime),
        }],
        host_claim: host.map(str::to_string),
        revision: run.to_string(),
    };
    writer
        .queue_event(
            &timed("evt-old", "run-demo", "log.entry", Some("host-1"), 1_000),
            "r1",
        )
        .unwrap();
    writer
        .queue_event(
            &timed("evt-new", "run-demo", "log.entry", Some("host-1"), 2_000),
            "r1",
        )
        .unwrap();
    writer
        .queue_event(
            &timed("evt-other", "run-other", "trace.line", None, 2_000),
            "r1",
        )
        .unwrap();
    let unresolved = Event {
        id: "evt-unresolved".to_string(),
        kind: "log.entry".to_string(),
        summary: "no resolved time".to_string(),
        observations: Vec::new(),
        times: Vec::new(),
        host_claim: None,
        revision: "run-other".to_string(),
    };
    writer.queue_event(&unresolved, "r1").unwrap();
}

#[test]
fn last_window_anchors_to_the_case_latest_event() {
    let dir = tempfile::tempdir().unwrap();
    let (case, acquisitions) = create_and_scan(dir.path());
    seed_extra_events(&case, &acquisitions[0]);

    let full = run(&[
        "timeline",
        "--case",
        case.to_str().unwrap(),
        "--limit",
        "1000",
    ]);
    let full: serde_json::Value = serde_json::from_str(&stdout(&full)).unwrap();
    let latest = full["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["chosen_seconds"].as_i64())
        .max()
        .unwrap();

    let output = run(&["timeline", "--case", case.to_str().unwrap(), "--last", "1h"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    let anchor = parsed["anchor_seconds"].as_i64().unwrap();
    let after = parsed["after_seconds"].as_i64().unwrap();
    assert_eq!(anchor, latest, "case-latest anchor");
    assert_eq!(after, anchor - 3_600);
    let ids: Vec<&str> = parsed["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["event_id"].as_str().unwrap())
        .collect();
    assert!(!ids.contains(&"evt-old"), "outside the window");
    assert!(
        ids.contains(&"evt-new") || !ids.is_empty(),
        "recent events stay reachable"
    );
}

#[test]
fn explicit_until_bounds_the_window() {
    let dir = tempfile::tempdir().unwrap();
    let (case, acquisitions) = create_and_scan(dir.path());
    seed_extra_events(&case, &acquisitions[0]);

    let output = run(&[
        "timeline",
        "--case",
        case.to_str().unwrap(),
        "--until",
        "1970-01-01T00:30:00Z",
    ]);
    assert!(output.status.success());
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(parsed["before_seconds"].as_i64(), Some(1_800));
    let ids: Vec<&str> = parsed["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["event_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec!["evt-old"],
        "only the earlier event is before 1800"
    );
}

#[test]
fn unresolved_view_is_explicit_and_separate() {
    let dir = tempfile::tempdir().unwrap();
    let (case, acquisitions) = create_and_scan(dir.path());
    seed_extra_events(&case, &acquisitions[0]);

    let resolved = run(&["timeline", "--case", case.to_str().unwrap()]);
    let unresolved = run(&["timeline", "--case", case.to_str().unwrap(), "--unresolved"]);
    let resolved: serde_json::Value = serde_json::from_str(&stdout(&resolved)).unwrap();
    let unresolved: serde_json::Value = serde_json::from_str(&stdout(&unresolved)).unwrap();

    assert_eq!(unresolved["resolved_view"], false);
    assert_eq!(unresolved["rows"].as_array().unwrap().len(), 1);
    assert_eq!(unresolved["rows"][0]["event_id"], "evt-unresolved");
    assert_eq!(unresolved["rows"][0]["time_status"], "unresolved");
    assert!(
        !resolved["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["event_id"] == "evt-unresolved"),
        "the resolved view never mixes unknown times in"
    );
}

#[test]
fn kind_host_and_source_filters_are_exact() {
    let dir = tempfile::tempdir().unwrap();
    let (case, acquisitions) = create_and_scan(dir.path());
    seed_extra_events(&case, &acquisitions[0]);

    let by_kind = run(&[
        "timeline",
        "--case",
        case.to_str().unwrap(),
        "--kind",
        "trace.line",
    ]);
    let by_kind: serde_json::Value = serde_json::from_str(&stdout(&by_kind)).unwrap();
    assert_eq!(by_kind["rows"].as_array().unwrap().len(), 1);
    assert_eq!(by_kind["rows"][0]["event_id"], "evt-other");

    let by_source = run(&[
        "timeline",
        "--case",
        case.to_str().unwrap(),
        "--source",
        "demo.parser.v1",
    ]);
    let by_source: serde_json::Value = serde_json::from_str(&stdout(&by_source)).unwrap();
    assert_eq!(by_source["rows"].as_array().unwrap().len(), 2);
    assert!(
        by_source["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["event_id"] == "evt-old" || row["event_id"] == "evt-new")
    );

    let by_host = run(&[
        "timeline",
        "--case",
        case.to_str().unwrap(),
        "--host",
        "host-1",
    ]);
    let by_host: serde_json::Value = serde_json::from_str(&stdout(&by_host)).unwrap();
    assert_eq!(by_host["rows"].as_array().unwrap().len(), 2);
}

#[test]
fn repeated_pages_are_stable_and_complete() {
    let dir = tempfile::tempdir().unwrap();
    let (case, acquisitions) = create_and_scan(dir.path());
    seed_extra_events(&case, &acquisitions[0]);

    let full = run(&[
        "timeline",
        "--case",
        case.to_str().unwrap(),
        "--limit",
        "100",
    ]);
    let full: serde_json::Value = serde_json::from_str(&stdout(&full)).unwrap();
    let expected: Vec<String> = full["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["event_id"].as_str().unwrap().to_string())
        .collect();
    assert!(expected.len() > 3);

    let mut collected = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut args = vec![
            "timeline".to_string(),
            "--case".to_string(),
            case.to_str().unwrap().to_string(),
            "--limit".to_string(),
            "2".to_string(),
        ];
        if let Some(cursor) = &cursor {
            args.push("--cursor".to_string());
            args.push(cursor.clone());
        }
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let page = run(&borrowed);
        assert!(page.status.success());
        let parsed: serde_json::Value = serde_json::from_str(&stdout(&page)).unwrap();
        for row in parsed["rows"].as_array().unwrap() {
            collected.push(row["event_id"].as_str().unwrap().to_string());
        }
        cursor = parsed["next_cursor"].as_str().map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(collected, expected, "keyset paging never skips or repeats");

    // Repeating the first page yields the identical page.
    let first = run(&["timeline", "--case", case.to_str().unwrap(), "--limit", "2"]);
    let first: serde_json::Value = serde_json::from_str(&stdout(&first)).unwrap();
    let again = run(&["timeline", "--case", case.to_str().unwrap(), "--limit", "2"]);
    let again: serde_json::Value = serde_json::from_str(&stdout(&again)).unwrap();
    assert_eq!(first["rows"], again["rows"]);
    assert_eq!(first["next_cursor"], again["next_cursor"]);
}

#[test]
fn invalid_windows_are_usage_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (case, _acquisitions) = create_and_scan(dir.path());
    for last in ["24x", "abc", "0h"] {
        let output = run(&["timeline", "--case", case.to_str().unwrap(), "--last", last]);
        assert_eq!(output.status.code(), Some(2), "{last}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("invalid_usage"), "{last}: {stderr}");
    }
    let negative = run(&["timeline", "--case", case.to_str().unwrap(), "--last=-1h"]);
    assert_eq!(negative.status.code(), Some(2));
    let output = run(&[
        "timeline",
        "--case",
        case.to_str().unwrap(),
        "--until",
        "yesterday",
    ]);
    assert_eq!(output.status.code(), Some(2));
}

//! P4.1 CLI contract: one documented import command, machine JSON, honest
//! exit codes, and imported events reachable through the normal timeline.

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

fn create_and_scan(dir: &Path, files: &[(&str, &[u8])]) -> PathBuf {
    let evidence = dir.join("evidence");
    for (path, bytes) in files {
        let full = evidence.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, bytes).unwrap();
    }
    let case = dir.join("case.ghosttrace-case");
    let created = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        "import",
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

#[test]
fn imported_jsonl_events_reach_the_timeline_and_replay_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let case = create_and_scan(
        dir.path(),
        &[(
            "logs/app.jsonl",
            b"{\"ts\":\"2026-10-27T10:00:00Z\",\"msg\":\"first\"}\n\
{\"ts\":\"2026-10-27T10:00:01Z\",\"msg\":\"second\"}\n",
        )],
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
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&imported)).unwrap();
    assert_eq!(parsed["parser_id"], "jsonl.fields");
    assert_eq!(parsed["detected_format"], "jsonl");
    assert_eq!(parsed["declared_format"], serde_json::Value::Null);
    assert_eq!(parsed["state"], "completed");
    assert_eq!(parsed["events"], 2);
    assert_eq!(parsed["observations"], 2);

    let timeline = run(&[
        "timeline",
        "--case",
        case.to_str().unwrap(),
        "--source",
        "jsonl.fields",
        "--limit",
        "50",
    ]);
    let timeline: serde_json::Value = serde_json::from_str(&stdout(&timeline)).unwrap();
    let rows = timeline["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{timeline}");
    assert_eq!(rows[0]["summary"], "first");
    assert_eq!(rows[1]["summary"], "second");

    let again = run(&[
        "import",
        "--case",
        case.to_str().unwrap(),
        "--path",
        "logs/app.jsonl",
        "--message-field",
        "msg",
    ]);
    assert_eq!(again.status.code(), Some(0), "{again:?}");
    let again: serde_json::Value = serde_json::from_str(&stdout(&again)).unwrap();
    assert_eq!(again["run_id"], parsed["run_id"]);
    let timeline = run(&[
        "timeline",
        "--case",
        case.to_str().unwrap(),
        "--source",
        "jsonl.fields",
        "--limit",
        "50",
    ]);
    let timeline: serde_json::Value = serde_json::from_str(&stdout(&timeline)).unwrap();
    assert_eq!(
        timeline["rows"].as_array().unwrap().len(),
        2,
        "no duplicates"
    );
}

#[test]
fn a_partial_import_exits_three_with_structured_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    let case = create_and_scan(
        dir.path(),
        &[(
            "logs/app.jsonl",
            b"{\"ts\":\"2026-10-27T10:00:00Z\",\"msg\":\"ok\"}\nnot json\n",
        )],
    );
    let imported = run(&[
        "import",
        "--case",
        case.to_str().unwrap(),
        "--path",
        "logs/app.jsonl",
    ]);
    assert_eq!(imported.status.code(), Some(3), "{imported:?}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&imported)).unwrap();
    assert_eq!(parsed["state"], "partial");
    assert_eq!(parsed["events"], 1);
    assert_eq!(parsed["diagnostics"][0]["code"], "malformed_record");
    assert!(stderr(&imported).contains("import partial"));
}

#[test]
fn declared_formats_and_usage_errors_are_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let case = create_and_scan(
        dir.path(),
        &[(
            "syslog.log",
            b"<34>Oct 27 10:00:00 host myapp[1]: service started\n",
        )],
    );
    let imported = run(&[
        "import",
        "--case",
        case.to_str().unwrap(),
        "--path",
        "syslog.log",
        "--format",
        "syslog-3164",
        "--timezone",
        "UTC",
        "--year",
        "2026",
    ]);
    assert_eq!(imported.status.code(), Some(0), "{imported:?}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&imported)).unwrap();
    assert_eq!(parsed["parser_id"], "syslog.rfc3164");
    assert_eq!(parsed["declared_format"], "syslog-3164");
    assert_eq!(parsed["events"], 0, "unmatched message stays raw");
    assert_eq!(parsed["observations"], 1);

    let both = run(&[
        "import",
        "--case",
        case.to_str().unwrap(),
        "--path",
        "syslog.log",
        "--object",
        "evi-x",
    ]);
    assert_eq!(both.status.code(), Some(2), "{both:?}");
    assert!(stderr(&both).contains("exactly one of --path or --object"));

    let bad_zone = run(&[
        "import",
        "--case",
        case.to_str().unwrap(),
        "--path",
        "syslog.log",
        "--format",
        "syslog-3164",
        "--timezone",
        "Mars/Olympus",
    ]);
    assert_eq!(bad_zone.status.code(), Some(2), "{bad_zone:?}");
    assert!(stderr(&bad_zone).contains("unknown IANA timezone"));
}

#[test]
fn an_unknown_signature_needs_a_declared_format() {
    let dir = tempfile::tempdir().unwrap();
    let case = create_and_scan(dir.path(), &[("notes.txt", b"plain text\n")]);
    let imported = run(&[
        "import",
        "--case",
        case.to_str().unwrap(),
        "--path",
        "notes.txt",
    ]);
    assert_eq!(imported.status.code(), Some(2), "{imported:?}");
    assert!(stderr(&imported).contains("does not match a supported signature"));
}

#[test]
fn a_journal_export_imports_with_binary_and_boot_scoped_times() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = b"__CURSOR=s=abc;i=1\n".to_vec();
    bytes.extend_from_slice(b"__REALTIME_TIMESTAMP=1342540861416409\n");
    bytes.extend_from_slice(b"__MONOTONIC_TIMESTAMP=21415215982\n");
    bytes.extend_from_slice(b"_BOOT_ID=6c7c6013a26343b29e964691ff25d04c\n");
    bytes.extend_from_slice(b"MESSAGE=first\n");
    bytes.extend_from_slice(b"MESSAGE=second\n");
    bytes.extend_from_slice(b"BINARY\n");
    bytes.extend_from_slice(&3_u64.to_le_bytes());
    bytes.extend_from_slice(b"a\nb");
    bytes.push(b'\n');
    bytes.push(b'\n');
    let case = create_and_scan(dir.path(), &[("journal.export", &bytes)]);
    let imported = run(&[
        "import",
        "--case",
        case.to_str().unwrap(),
        "--path",
        "journal.export",
    ]);
    assert_eq!(imported.status.code(), Some(0), "{imported:?}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&imported)).unwrap();
    assert_eq!(parsed["parser_id"], "journal.export");
    assert_eq!(parsed["detected_format"], "journal-export");
    assert_eq!(parsed["events"], 1);
    assert_eq!(parsed["observations"], 1);
    assert_eq!(parsed["state"], "completed");

    let timeline = run(&[
        "timeline",
        "--case",
        case.to_str().unwrap(),
        "--source",
        "journal.export",
        "--limit",
        "10",
    ]);
    let timeline: serde_json::Value = serde_json::from_str(&stdout(&timeline)).unwrap();
    let rows = timeline["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{timeline}");
    assert_eq!(rows[0]["summary"], "first");
    assert_eq!(rows[0]["chosen_seconds"], 1342540861_i64);
}

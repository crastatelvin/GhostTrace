//! P9.2 CSV contract: spreadsheet formula prefixes and control whitespace are
//! neutralized in the CSV projection, while the JSON report stays faithful.

mod support;

use ghosttrace_core::ingest::LogFormat;
use ghosttrace_core::reports::csv::{CSV_NOTE, neutralize, objects_csv, timeline_csv};
use ghosttrace_core::reports::{ReportContext, ReportSelection, build_report, json};
use support::Harness;

fn report(harness: &mut Harness) -> ghosttrace_core::reports::ReportV1 {
    let acquisition = harness.capture(&[("logs/events.jsonl", b"{\"msg\":\"safe\"}\n")]);
    let run = harness
        .import(&acquisition, "logs/events.jsonl", |request| {
            request.format = Some(LogFormat::Jsonl);
            request.jsonl.message_field = Some("msg".into());
        })
        .expect("import")
        .run_id;
    let context = ReportContext {
        case_id: harness.session().case_id().to_string(),
        label: "csv".into(),
        display_timezone: "UTC".into(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_by: "ghosttrace-test".into(),
    };
    let selection = ReportSelection {
        acquisition_id: Some(acquisition),
        revision: Some(run),
        event_limit: 10,
    };
    build_report(
        &harness.session().reader().expect("reader"),
        &context,
        &selection,
    )
    .expect("report")
}

#[test]
fn formula_leading_cells_are_prefixed_and_controls_are_escaped() {
    for (input, expected) in [
        ("=1+1", "'=1+1"),
        ("+cmd|' /C calc'!A0", "'+cmd|' /C calc'!A0"),
        ("-2+3", "'-2+3"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("  =1+1", "'  =1+1"),
        ("\t=1+1", "\\u{9}=1+1"),
        ("line\r\nbreak", "line\\u{d}\\u{a}break"),
        ("bell\u{7}", "bell\\u{7}"),
        ("plain text", "plain text"),
    ] {
        assert_eq!(neutralize(input), expected, "input {input:?}");
    }
    assert!(CSV_NOTE.contains("apostrophe"));
}

#[test]
fn the_csv_quotes_separators_and_keeps_one_row_per_event() {
    let mut harness = Harness::new();
    let mut report = report(&mut harness);
    report.timeline[0].summary = "a,b\"c".into();
    let csv = timeline_csv(&report);
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 1 + report.timeline.len());
    assert_eq!(
        lines[0],
        "event_id,source,kind,summary,host_claim,chosen_time_utc,time_status"
    );
    assert!(lines[1].contains("\"a,b\"\"c\""), "{}", lines[1]);
    assert!(!csv.contains('\r'), "no raw carriage returns");
}

#[test]
fn the_json_report_keeps_the_exact_hostile_value() {
    let mut harness = Harness::new();
    let mut report = report(&mut harness);
    let hostile = "=1+1\t\"quoted\", line\nbreak";
    report.timeline[0].summary = hostile.into();
    let json = json::render(&report).expect("json");
    assert!(
        json.contains("=1+1\\t\\\"quoted\\\", line\\nbreak"),
        "the JSON escapes but preserves every character: {json}"
    );
    assert!(!timeline_csv(&report).contains("=1+1\t"));
}

#[test]
fn the_object_csv_lists_digests_without_paths_leaking_formulas() {
    let mut harness = Harness::new();
    let mut report = report(&mut harness);
    report.objects[0].path = "=HYPERLINK(\"http://example\")".into();
    let csv = objects_csv(&report);
    assert!(csv.starts_with("path,sha256,byte_length\n"));
    assert!(csv.contains("'=HYPERLINK"));
    assert!(csv.contains(&report.objects[0].sha256));
}

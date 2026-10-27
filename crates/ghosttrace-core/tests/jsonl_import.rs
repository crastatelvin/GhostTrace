//! P4.1 JSONL mapping contract: fixed field names, fixed time formats, no
//! executable expressions, and explicit rejection of records that do not fit.

mod support;

use ghosttrace_core::ingest::TimeFormat;
use support::Harness;

#[test]
fn mapped_fields_and_numeric_times_become_events() {
    let mut harness = Harness::new();
    let line =
        b"{\"ts\":1793095200,\"kind\":\"file.read\",\"host\":\"host-a\",\"msg\":\"read report\"}\n";
    let acquisition = harness.capture(&[("app.jsonl", line)]);
    let outcome = harness
        .import(&acquisition, "app.jsonl", |request| {
            request.jsonl.time_field = "ts".into();
            request.jsonl.time_format = TimeFormat::UnixSeconds;
            request.jsonl.kind_field = Some("kind".into());
            request.jsonl.host_field = Some("host".into());
            request.jsonl.message_field = Some("msg".into());
        })
        .expect("import");
    assert_eq!(outcome.state, "completed");
    assert_eq!(outcome.records, 1);
    assert_eq!(outcome.events, 1);
    assert_eq!(
        harness
            .scalar(
                "SELECT kind FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("file.read")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT summary FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("read report")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT host_claim FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("host-a")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT chosen_seconds FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("1793095200")
    );
}

#[test]
fn a_missing_mapped_time_leaves_the_event_unresolved() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("app.jsonl", b"{\"msg\":\"no time here\"}\n")]);
    let outcome = harness
        .import(&acquisition, "app.jsonl", |request| {
            request.jsonl.message_field = Some("msg".into());
        })
        .expect("import");
    assert_eq!(outcome.events, 1);
    assert_eq!(outcome.state, "partial");
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "time_missing"),
        "{:?}",
        outcome.diagnostics
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT time_status FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("unresolved")
    );
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM events WHERE parse_run_id = ?1 AND chosen_seconds IS NULL",
            &[&outcome.run_id],
        ),
        1
    );
}

#[test]
fn an_unparseable_time_is_invalid_not_silently_dropped() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("app.jsonl", b"{\"ts\":\"not-a-time\"}\n")]);
    let outcome = harness
        .import(&acquisition, "app.jsonl", |_| {})
        .expect("import");
    assert_eq!(outcome.events, 1);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "invalid_time"),
        "{:?}",
        outcome.diagnostics
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT time_status FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("invalid")
    );
}

#[test]
fn wrong_field_types_are_preserved_without_an_event() {
    let mut harness = Harness::new();
    let line = b"{\"ts\":\"2026-10-27T10:00:00Z\",\"kind\":42}\n";
    let acquisition = harness.capture(&[("app.jsonl", line)]);
    let outcome = harness
        .import(&acquisition, "app.jsonl", |request| {
            request.jsonl.kind_field = Some("kind".into());
        })
        .expect("import");
    assert_eq!(outcome.observations, 1, "the parsed fields are preserved");
    assert_eq!(outcome.events, 0, "no event type is invented");
    assert_eq!(outcome.state, "partial");
    assert_eq!(outcome.diagnostics[0].code, "schema_mismatch");
    let raw = harness
        .scalar(
            "SELECT raw_fields_json FROM raw_observations WHERE parse_run_id = ?1",
            &[&outcome.run_id],
        )
        .expect("raw fields");
    assert!(raw.contains("\"kind\":42"), "{raw}");
}

#[test]
fn a_non_object_record_is_reported() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("app.jsonl", b"[1,2,3]\n")]);
    let outcome = harness
        .import(&acquisition, "app.jsonl", |_| {})
        .expect("import");
    assert_eq!(outcome.records, 1);
    assert_eq!(outcome.observations, 0);
    assert_eq!(outcome.events, 0);
    assert_eq!(outcome.diagnostics[0].code, "schema_mismatch");
}

#[test]
fn a_kind_field_must_be_present_when_mapped() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("app.jsonl", b"{\"ts\":1793095200}\n")]);
    let outcome = harness
        .import(&acquisition, "app.jsonl", |request| {
            request.jsonl.time_format = TimeFormat::UnixSeconds;
            request.jsonl.kind_field = Some("kind".into());
        })
        .expect("import");
    assert_eq!(outcome.observations, 1);
    assert_eq!(outcome.events, 0);
    assert_eq!(outcome.diagnostics[0].code, "schema_mismatch");
}

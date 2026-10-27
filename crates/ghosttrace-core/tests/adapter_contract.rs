//! P4.1 adapter contract: detection, explicit override recording, replay
//! idempotency, bounded records, encoding failures, cancellation, and
//! integrity checks against the captured store.

mod support;

use std::sync::atomic::AtomicBool;

use ghosttrace_core::ingest::LogFormat;
use support::Harness;

const JSONL: &[u8] = b"{\"ts\":\"2026-10-27T10:00:00Z\",\"msg\":\"hello\"}\n";

#[test]
fn signature_detection_and_manual_override_are_both_recorded() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("logs/app.jsonl", JSONL)]);

    let detected = harness
        .import(&acquisition, "logs/app.jsonl", |_| {})
        .expect("import");
    assert_eq!(detected.parser_id, "jsonl.fields");
    assert_eq!(detected.detected_format.as_deref(), Some("jsonl"));
    assert_eq!(detected.declared_format, None);
    assert_eq!(detected.state, "completed");
    assert_eq!(detected.events, 1);
    assert_eq!(detected.observations, 1);
    let chosen = harness
        .scalar(
            "SELECT chosen_seconds FROM events WHERE parse_run_id = ?1",
            &[&detected.run_id],
        )
        .expect("event time");
    assert_eq!(chosen, "1793095200");

    // Declaring the wrong format is allowed, but the run says exactly that.
    let overridden = harness
        .import(&acquisition, "logs/app.jsonl", |request| {
            request.format = Some(LogFormat::Syslog3164);
        })
        .expect("override import");
    assert_eq!(overridden.parser_id, "syslog.rfc3164");
    assert_eq!(overridden.detected_format.as_deref(), Some("jsonl"));
    assert_eq!(overridden.declared_format.as_deref(), Some("syslog-3164"));
    assert_ne!(
        overridden.run_id, detected.run_id,
        "config identity differs"
    );
    assert_eq!(overridden.state, "partial");
    assert!(
        overridden
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "malformed_record"),
        "{:?}",
        overridden.diagnostics
    );
}

#[test]
fn reimporting_the_same_object_is_idempotent() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("app.jsonl", JSONL)]);
    let first = harness
        .import(&acquisition, "app.jsonl", |_| {})
        .expect("first");
    let observations = harness.count(
        "SELECT count(*) FROM raw_observations WHERE parse_run_id = ?1",
        &[&first.run_id],
    );
    let events = harness.count(
        "SELECT count(*) FROM events WHERE parse_run_id = ?1",
        &[&first.run_id],
    );

    let second = harness
        .import(&acquisition, "app.jsonl", |_| {})
        .expect("second");
    assert_eq!(first.run_id, second.run_id, "run identity is deterministic");
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM raw_observations WHERE parse_run_id = ?1",
            &[&second.run_id],
        ),
        observations,
        "replays never duplicate observations"
    );
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM events WHERE parse_run_id = ?1",
            &[&second.run_id],
        ),
        events,
        "replays never duplicate events"
    );
}

#[test]
fn oversized_records_are_reported_and_skipped() {
    let mut harness = Harness::new();
    // Starts with a valid signature, then one hostile oversized record.
    let mut bytes = JSONL.to_vec();
    bytes.extend_from_slice(&vec![b'a'; 400]);
    bytes.push(b'\n');
    let acquisition = harness.capture(&[("app.jsonl", &bytes)]);

    let outcome = harness
        .import(&acquisition, "app.jsonl", |request| {
            request.max_record_bytes = 64;
        })
        .expect("import");
    assert_eq!(outcome.state, "partial");
    assert_eq!(outcome.records, 2, "the oversized line still counts");
    assert_eq!(outcome.observations, 1, "only the valid record is stored");
    assert_eq!(outcome.events, 1, "the valid record still becomes an event");
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "record_too_large"),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn invalid_utf8_is_reported_not_coerced() {
    let mut harness = Harness::new();
    let bytes = b"{\"ts\":\"2026-10-27T10:00:00Z\",\"msg\":\"\xff\"}\n";
    let acquisition = harness.capture(&[("app.jsonl", bytes)]);

    let outcome = harness
        .import(&acquisition, "app.jsonl", |_| {})
        .expect("import");
    assert_eq!(outcome.state, "partial");
    assert_eq!(outcome.records, 1);
    assert_eq!(outcome.observations, 0);
    assert_eq!(outcome.events, 0);
    assert_eq!(outcome.diagnostics[0].code, "invalid_encoding");
}

#[test]
fn a_cancelled_parser_is_recorded_as_cancelled() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("app.jsonl", JSONL)]);
    let cancelled = AtomicBool::new(true);

    let outcome = harness
        .import_with_token(&acquisition, "app.jsonl", &cancelled, |_| {})
        .expect("import");
    assert_eq!(outcome.state, "cancelled");
    assert_eq!(outcome.records, 0);
    assert_eq!(outcome.events, 0);
    assert_eq!(
        harness
            .scalar(
                "SELECT state FROM parse_runs WHERE id = ?1",
                &[&outcome.run_id],
            )
            .expect("run state"),
        "cancelled"
    );
}

#[test]
fn unsupported_signature_requires_a_declared_format() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("notes.txt", b"just some text\n")]);
    let error = harness
        .import(&acquisition, "notes.txt", |_| {})
        .expect_err("must refuse");
    assert_eq!(error.code(), "unsupported_format");
}

#[test]
fn a_tampered_object_is_refused_before_parsing() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("app.jsonl", JSONL)]);
    let subpath = harness.object_subpath(&acquisition, "app.jsonl");
    harness.tamper_object(&subpath);

    let error = harness
        .import(&acquisition, "app.jsonl", |_| {})
        .expect_err("must refuse");
    assert_eq!(error.code(), "integrity_mismatch");
}

#[test]
fn objects_resolve_by_path_or_identity_and_require_one() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("app.jsonl", JSONL)]);
    let by_path = harness
        .import(&acquisition, "app.jsonl", |_| {})
        .expect("by path");
    let by_id = harness
        .import(&acquisition, "app.jsonl", |request| {
            request.path = None;
            request.evidence_id = Some(by_path.evidence_id.clone());
        })
        .expect("by id");
    assert_eq!(by_path.run_id, by_id.run_id);
}

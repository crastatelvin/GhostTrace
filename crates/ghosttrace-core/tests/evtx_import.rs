//! P8.1: EVTX ingestion over real captured Windows event logs.
//!
//! These fixtures are tracked in `tests/fixtures/evtx` with their provenance;
//! they exercise known provider/channel/version records, the exact record-id
//! locator, UTC logging time, payload occurrence time, unreadable chunks, and
//! truncated evidence.

mod support;

use ghosttrace_core::analysis::rules::{AnalysisRequest, RuleConfig};
use ghosttrace_core::error::CoreError;
use ghosttrace_core::ingest::ImportOutcome;
use support::Harness;

const SYSMON: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/evtx/sysmon.evtx"
));
const SECURITY_FAILURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/evtx/security-failure.evtx"
));
const SECURITY_SUCCESS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/evtx/security-success.evtx"
));
const CAPTURE_LIMIT: u64 = 8 << 20;

fn count(harness: &Harness, run_id: &str, kind: &str) -> i64 {
    harness.count(
        "SELECT count(*) FROM events WHERE parse_run_id = ?1 AND kind = ?2",
        &[&run_id, &kind],
    )
}

fn text(harness: &Harness, sql: &str, run_id: &str) -> String {
    harness
        .scalar(sql, &[&run_id])
        .unwrap_or_else(|| panic!("no row for {sql}"))
}

#[test]
fn sysmon_records_are_detected_mapped_and_partially_readable() {
    let mut harness = Harness::new();
    let acquisition = harness.capture_with_limit(&[("sysmon.evtx", SYSMON)], CAPTURE_LIMIT);
    let outcome: ImportOutcome = harness
        .import(&acquisition, "sysmon.evtx", |_request| {})
        .expect("import");

    assert_eq!(outcome.parser_id, "evtx.records");
    assert_eq!(outcome.detected_format.as_deref(), Some("evtx"));
    assert_eq!(outcome.declared_format, None);
    assert_eq!(
        outcome.state, "partial",
        "the fixture has unreadable chunks; a partial read is never completed"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "evtx_parse_error"),
        "chunk failures are recorded: {:?}",
        outcome.diagnostics
    );
    assert!(outcome.records >= 300, "records: {}", outcome.records);
    assert_eq!(count(&harness, &outcome.run_id, "process.execute"), 227);

    // The known provider/channel/version record maps its path, hash, and user.
    let mapped = text(
        &harness,
        "SELECT mapped_fields_json FROM raw_observations
         WHERE parse_run_id = ?1 AND mapped_fields_json LIKE '%PING.EXE%' LIMIT 1",
        &outcome.run_id,
    );
    let mapped: serde_json::Value = serde_json::from_str(&mapped).expect("mapped json");
    assert_eq!(mapped["provider"], "Microsoft-Windows-Sysmon");
    assert_eq!(mapped["channel"], "Microsoft-Windows-Sysmon/Operational");
    assert_eq!(mapped["event_id"], 1);
    assert_eq!(mapped["version"], 5);
    assert_eq!(mapped["computer"], "DESKTOP-2KGM189");
    assert!(
        mapped["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("PING.EXE"))
    );
    assert_eq!(mapped["user"], "NT AUTHORITY\\SYSTEM");
    let sha256 = mapped["sha256"].as_str().expect("sha256");
    assert_eq!(sha256.len(), 64);
    assert!(sha256.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(
        harness.count(
            "SELECT count(*) FROM raw_observations
                 WHERE parse_run_id = ?1 AND mapped_fields_json LIKE '%8f16a431c919a0aa%'",
            &[&outcome.run_id],
        ) > 0,
        "the recorded SHA256= value is preserved"
    );

    // Exact record-id locators: scoped to this object and unique within the run.
    let locators = harness.count(
        "SELECT count(*) FROM raw_observations WHERE parse_run_id = ?1",
        &[&outcome.run_id],
    );
    let distinct = harness.count(
        "SELECT count(DISTINCT locator_identity) FROM raw_observations WHERE parse_run_id = ?1",
        &[&outcome.run_id],
    );
    assert_eq!(locators, distinct);
    let locator = text(
        &harness,
        "SELECT locator_identity FROM raw_observations WHERE parse_run_id = ?1 LIMIT 1",
        &outcome.run_id,
    );
    assert!(locator.starts_with("evtx-record:"), "locator: {locator}");

    // Logging time is UTC and resolved; Sysmon 1 also carries the payload time.
    let logged = text(
        &harness,
        "SELECT status || '|' || assumptions_json FROM event_times
         WHERE event_id = (SELECT id FROM events WHERE parse_run_id = ?1 LIMIT 1)
           AND name = 'logged'",
        &outcome.run_id,
    );
    assert!(logged.starts_with("resolved|"), "logged: {logged}");
    assert!(logged.contains("UTC"), "logged: {logged}");
    let occurred = harness.count(
        "SELECT count(*) FROM event_times t JOIN events e ON e.id = t.event_id
         WHERE e.parse_run_id = ?1 AND t.name = 'occurred' AND t.status = 'resolved'",
        &[&outcome.run_id],
    );
    assert_eq!(occurred, 227, "every Sysmon 1 record carries UtcTime");
    let assumption = text(
        &harness,
        "SELECT assumptions_json FROM event_times t JOIN events e ON e.id = t.event_id
         WHERE e.parse_run_id = ?1 AND t.name = 'occurred' LIMIT 1",
        &outcome.run_id,
    );
    assert!(
        assumption.contains("read as UTC"),
        "the zone assumption is recorded: {assumption}"
    );
}

#[test]
fn security_failures_and_successes_map_to_the_rule_kinds() {
    let mut harness = Harness::new();
    let acquisition = harness.capture_with_limit(
        &[
            ("failure.evtx", SECURITY_FAILURE),
            ("success.evtx", SECURITY_SUCCESS),
        ],
        CAPTURE_LIMIT,
    );
    let failure = harness
        .import(&acquisition, "failure.evtx", |_request| {})
        .expect("failure import");
    let success = harness
        .import(&acquisition, "success.evtx", |_request| {})
        .expect("success import");

    assert_eq!(
        failure.state, "completed",
        "diagnostics: {:?}",
        failure.diagnostics
    );
    assert_eq!(
        success.state, "completed",
        "diagnostics: {:?}",
        success.diagnostics
    );
    assert_eq!(count(&harness, &failure.run_id, "auth.login_failed"), 1);
    assert_eq!(
        count(&harness, &success.run_id, "auth.login_succeeded"),
        583
    );
    assert!(
        count(&harness, &failure.run_id, "windows.event_log") > 0,
        "unmapped Security events stay generic observations"
    );

    // Record locators are the payload EventRecordIDs: the exported log
    // renumbers the chunk-local record header from 1, so header ids would
    // collide and are only kept as `chunk_record_id`.
    let observations = harness.count(
        "SELECT count(*) FROM raw_observations WHERE parse_run_id = ?1",
        &[&success.run_id],
    );
    let distinct = harness.count(
        "SELECT count(DISTINCT locator_identity) FROM raw_observations WHERE parse_run_id = ?1",
        &[&success.run_id],
    );
    assert_eq!(
        observations, distinct,
        "record locators are unique per object"
    );
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM raw_observations
             WHERE parse_run_id = ?1 AND locator_identity NOT LIKE 'evtx-record:%'",
            &[&success.run_id],
        ),
        0,
        "every record carries its payload EventRecordID, not the ordinal"
    );

    let mapped = text(
        &harness,
        "SELECT mapped_fields_json FROM raw_observations
         WHERE parse_run_id = ?1 AND mapped_fields_json LIKE '%\"user\":\"Administrator\"%' LIMIT 1",
        &failure.run_id,
    );
    let mapped: serde_json::Value = serde_json::from_str(&mapped).expect("mapped json");
    assert_eq!(mapped["user"], "Administrator");
    assert_eq!(mapped["domain"], "TEMPORAL");
    assert_eq!(mapped["logon_type"], "10");
    assert_eq!(mapped["service"], "logon_type:10");
    assert_eq!(mapped["auth_package"], "Negotiate");

    // The rule consumes the mapping: the failed logon is considered, not
    // reported as "no supported authentication events".
    let report = harness
        .session()
        .analyze(&AnalysisRequest {
            revision: failure.run_id.clone(),
            config: RuleConfig::default(),
        })
        .expect("analyze");
    let auth = report
        .outcomes
        .iter()
        .find(|outcome| outcome.rule_id == "auth.fail_then_success")
        .expect("auth rule outcome");
    assert_eq!(auth.status, "evaluated", "reason: {:?}", auth.reason);
    assert_eq!(auth.events_considered, 1);
    assert_eq!(auth.excluded, 0);
    assert_eq!(auth.findings, 0, "there is no success in this revision");
}

#[test]
fn truncated_evidence_is_flagged_and_never_completed() {
    let mut harness = Harness::new();
    let acquisition = harness.capture_with_limit(
        &[
            ("header-only.evtx", &SYSMON[..5_000]),
            ("one-chunk.evtx", &SYSMON[..70_000]),
        ],
        CAPTURE_LIMIT,
    );

    let header_only = harness
        .import(&acquisition, "header-only.evtx", |_request| {})
        .expect("header-only import");
    assert_eq!(
        header_only.state, "partial",
        "an incomplete traversal is never a completed run"
    );
    assert_eq!(header_only.records, 0);
    assert!(
        header_only
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "truncated_evidence"),
        "diagnostics: {:?}",
        header_only.diagnostics
    );

    let one_chunk = harness
        .import(&acquisition, "one-chunk.evtx", |_request| {})
        .expect("one-chunk import");
    assert_eq!(one_chunk.state, "partial");
    assert!(one_chunk.records > 0, "the present chunk is read");
    assert!(
        one_chunk
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "truncated_evidence")
    );
}

#[test]
fn a_file_shorter_than_its_header_fails_instead_of_importing_nothing() {
    let mut harness = Harness::new();
    let acquisition = harness.capture_with_limit(&[("tiny.evtx", &SYSMON[..100])], CAPTURE_LIMIT);
    let error = harness
        .import(&acquisition, "tiny.evtx", |_request| {})
        .expect_err("a headerless prefix must fail");
    assert!(
        matches!(error, CoreError::Unsupported(_)),
        "expected an unsupported-object error, got {error:?}"
    );
}

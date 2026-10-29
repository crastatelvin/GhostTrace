//! P9.2 redaction contract: a redacted export removes selected values, the
//! ledger never leaks them, and the case and stored evidence are unchanged.

mod support;

use ghosttrace_core::ingest::LogFormat;
use ghosttrace_core::reports::redact::{REDACTED, RedactionPolicy, preview_counts, redact_report};
use ghosttrace_core::reports::{ReportContext, ReportSelection, build_report, publish_with};
use support::Harness;

const RECORDS: &[u8] = b"\
{\"ts\":\"2026-10-27T10:00:00Z\",\"user\":\"alice\",\"msg\":\"secret-needle-alpha\"}
{\"ts\":\"2026-10-27T10:01:00Z\",\"user\":\"bob\",\"msg\":\"secret-needle-beta\"}
";

fn report(harness: &mut Harness) -> ghosttrace_core::reports::ReportV1 {
    let acquisition = harness.capture(&[("logs/private-name.jsonl", RECORDS)]);
    let run = harness
        .import(&acquisition, "logs/private-name.jsonl", |request| {
            request.format = Some(LogFormat::Jsonl);
            request.jsonl.message_field = Some("msg".into());
        })
        .expect("import")
        .run_id;
    let context = ReportContext {
        case_id: harness.session().case_id().to_string(),
        label: "case-label-needle".into(),
        display_timezone: "UTC".into(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_by: "ghosttrace-test".into(),
    };
    let selection = ReportSelection {
        acquisition_id: Some(acquisition),
        revision: Some(run),
        event_limit: 50,
    };
    build_report(
        &harness.session().reader().expect("reader"),
        &context,
        &selection,
    )
    .expect("report")
}

fn everything() -> RedactionPolicy {
    RedactionPolicy {
        case_label: true,
        source_paths: true,
        object_paths: true,
        timeline_summaries: true,
        timeline_hosts: true,
    }
}

#[test]
fn selected_values_are_replaced_and_the_original_report_is_untouched() {
    let mut harness = Harness::new();
    let original = report(&mut harness);
    assert_eq!(original.timeline.len(), 2);
    let object_path = original.objects[0].path.clone();
    let summary = original.timeline[0].summary.clone();
    let source = original.acquisition.claimed_source.clone();

    let (redacted, _ledger) = redact_report(&original, &everything());
    assert_eq!(redacted.case.label, REDACTED);
    assert_eq!(redacted.acquisition.claimed_source, REDACTED);
    assert!(
        redacted
            .acquisition
            .roots
            .iter()
            .all(|root| root == REDACTED)
    );
    assert!(
        redacted
            .objects
            .iter()
            .all(|object| object.path == REDACTED)
    );
    assert!(redacted.timeline.iter().all(|row| row.summary == REDACTED));
    assert!(
        redacted
            .limitations
            .iter()
            .any(|line| line.contains("redacted"))
    );

    // The unredacted input is a projection source, never a mutation target.
    assert_eq!(original.case.label, "case-label-needle");
    assert_eq!(original.objects[0].path, object_path);
    assert_eq!(original.timeline[0].summary, summary);
    assert_eq!(original.acquisition.claimed_source, source);
}

#[test]
fn the_ledger_records_fields_and_counts_but_never_removed_text() {
    let mut harness = Harness::new();
    let original = report(&mut harness);
    let (_, ledger) = redact_report(&original, &everything());
    let json = ledger.to_json().expect("ledger json");

    for secret in [
        "case-label-needle",
        "secret-needle-alpha",
        "secret-needle-beta",
        "private-name.jsonl",
        &original.objects[0].path,
    ] {
        assert!(
            !json.contains(secret),
            "the ledger leaked {secret:?}: {json}"
        );
    }
    assert!(json.contains("\"objects.path\""));
    assert!(json.contains("\"count\""));
    assert_eq!(ledger.selected.len(), 5);
    assert!(ledger.summary().contains("timeline.summary"));
}

#[test]
fn a_published_redacted_export_writes_the_projection_and_its_ledger() {
    let mut harness = Harness::new();
    let original = report(&mut harness);
    let summary_before = harness.scalar("SELECT summary FROM events ORDER BY id LIMIT 1", &[]);
    let object = original.objects[0].clone();
    let stored = harness.case_root().join(format!(
        "objects/sha256/{}/{}",
        &object.sha256[..2],
        object.sha256
    ));
    let bytes_before = std::fs::read(&stored).expect("stored object");

    let (redacted, ledger) = redact_report(&original, &everything());
    let directory = tempfile::tempdir().expect("dir");
    let published = publish_with(
        &redacted,
        directory.path(),
        &[("redaction.json", &ledger.to_json().expect("ledger"))],
    )
    .expect("publish");
    let on_disk = std::fs::read_to_string(&published.json_path).expect("json");
    assert!(on_disk.contains(REDACTED));
    assert!(!on_disk.contains("secret-needle-alpha"));
    let ledger_on_disk =
        std::fs::read_to_string(published.directory.join("redaction.json")).expect("ledger file");
    assert!(!ledger_on_disk.contains("secret-needle-alpha"));

    // Neither the case rows nor the stored object bytes changed.
    assert_eq!(
        harness.scalar("SELECT summary FROM events ORDER BY id LIMIT 1", &[]),
        summary_before
    );
    assert_eq!(std::fs::read(&stored).expect("stored object"), bytes_before);
}

#[test]
fn preview_counts_match_the_applied_actions() {
    let mut harness = Harness::new();
    let original = report(&mut harness);
    let (_, ledger) = redact_report(&original, &everything());
    let preview = preview_counts(&original, &everything());
    let applied: Vec<(String, u64)> = ledger
        .actions
        .iter()
        .map(|action| (action.field.clone(), action.count))
        .collect();
    assert_eq!(preview, applied);
    assert!(!preview.is_empty());
}

#[test]
fn an_empty_policy_is_an_unredacted_export() {
    let mut harness = Harness::new();
    let original = report(&mut harness);
    let (redacted, ledger) = redact_report(&original, &RedactionPolicy::default());
    assert_eq!(redacted, original);
    assert!(ledger.actions.is_empty());
    assert!(ledger.selected.is_empty());
}

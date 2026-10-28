//! P6.2 provenance contract: one event resolves to its exact raw record,
//! recorded times, and assumptions, and a histogram is bounded, declared, and
//! never drops the events it cannot bin.

mod support;

use ghosttrace_core::domain::query::EventQuery;
use ghosttrace_core::ingest::LogFormat;
use support::Harness;

const RECORDS: &[u8] = b"\
{\"ts\":\"2026-10-27T10:00:00Z\",\"user\":\"alice\",\"msg\":\"needle one\"}
{\"ts\":\"2026-10-27T10:01:00Z\",\"user\":\"alice\",\"msg\":\"two\"}
{\"ts\":\"2026-10-27T10:02:00Z\",\"msg\":\"three\"}
{\"ts\":\"not-a-time\",\"user\":\"bob\",\"msg\":\"four\"}
";

fn imported(harness: &mut Harness) -> String {
    let acquisition = harness.capture(&[("logs/events.jsonl", RECORDS)]);
    harness
        .import(&acquisition, "logs/events.jsonl", |request| {
            request.format = Some(LogFormat::Jsonl);
            request.jsonl.message_field = Some("msg".into());
        })
        .expect("import")
        .run_id
}

fn event_ids(harness: &Harness, revision: &str) -> Vec<String> {
    let reader = harness.session().reader().expect("reader");
    let mut statement = reader
        .connection()
        .prepare(
            "SELECT id FROM events WHERE revision = ?1
             ORDER BY chosen_seconds IS NULL, chosen_seconds, id",
        )
        .expect("prepare");
    let rows = statement
        .query_map([revision], |row| row.get::<_, String>(0))
        .expect("query");
    rows.collect::<Result<Vec<_>, _>>().expect("ids")
}

#[test]
fn detail_opens_the_exact_raw_record_and_its_time_assumptions() {
    let mut harness = Harness::new();
    let revision = imported(&mut harness);
    let ids = event_ids(&harness, &revision);
    assert_eq!(ids.len(), 4);

    let detail = harness
        .session()
        .event_detail(&revision, &ids[0])
        .expect("detail");
    assert_eq!(detail.event.kind, "log.record");
    assert_eq!(detail.parser_id, LogFormat::Jsonl.parser_id());
    assert_eq!(detail.parse_run_id, revision);
    assert!(detail.source_linked, "the importer recorded the link");
    assert_eq!(detail.observations.len(), 1);
    let observation = &detail.observations[0];
    assert!(observation.evidence_path.ends_with("events.jsonl"));
    assert_eq!(observation.locator_kind, "byte_range");
    assert!(
        observation.raw_fields_json.contains("\"alice\""),
        "the raw record is shown verbatim: {}",
        observation.raw_fields_json
    );
    assert_eq!(detail.times.len(), 1);
    assert_eq!(detail.times[0].name, "logged");
    assert_eq!(detail.times[0].status, "resolved");
    assert_eq!(detail.times[0].raw_field.as_deref(), Some("ts"));
    assert!(
        detail.times[0]
            .raw_value
            .as_deref()
            .unwrap_or("")
            .contains("2026-10-27T10:00:00Z")
    );
    assert_eq!(detail.times[0].clock_domain, "host");
    // The run records its own diagnostics; the inspector labels them as
    // run-level rather than pretending they belong to this one record.
    assert!(
        detail
            .run_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "invalid_time"),
        "{:?}",
        detail.run_diagnostics
    );
    assert!(
        detail
            .run_diagnostics
            .iter()
            .all(|diagnostic| !diagnostic.detail.contains("alice")),
        "diagnostics never repeat record content"
    );
    serde_json::from_str::<serde_json::Value>(&detail.run_assumptions_json)
        .expect("recorded assumptions stay valid JSON");

    // The event with an unparseable timestamp keeps that fact visible.
    let last = harness
        .session()
        .event_detail(&revision, &ids[3])
        .expect("invalid detail");
    assert_eq!(last.times[0].status, "invalid");
    assert_eq!(last.event.time_status, "invalid");

    let missing = harness
        .session()
        .event_detail(&revision, "ev-does-not-exist")
        .expect_err("missing event");
    assert_eq!(missing.code(), "invalid_request");
}

#[test]
fn detail_lists_scoped_entities_once_they_are_resolved() {
    let mut harness = Harness::new();
    let revision = imported(&mut harness);
    harness
        .session()
        .build_entities(&revision)
        .expect("entities");
    let ids = event_ids(&harness, &revision);
    let detail = harness
        .session()
        .event_detail(&revision, &ids[0])
        .expect("detail");
    assert!(
        detail
            .entities
            .iter()
            .any(|entity| entity.kind == "user" && entity.display_form == "alice"),
        "{:?}",
        detail.entities
    );
}

#[test]
fn histogram_declares_its_bins_and_keeps_unbinnable_events_visible() {
    let mut harness = Harness::new();
    let revision = imported(&mut harness);
    let query = EventQuery {
        revision: revision.clone(),
        ..EventQuery::default()
    };

    let histogram = harness
        .session()
        .event_histogram(&query, None, 4)
        .expect("histogram");
    assert!((4..=120).contains(&(histogram.bins.len() as u32)));
    assert!(histogram.bin_seconds >= 1);
    assert_eq!(histogram.from_seconds, 1_793_095_200, "first chosen time");
    assert_eq!(
        histogram.bins.iter().map(|bin| bin.count).sum::<u64>(),
        3,
        "three events have a chosen time"
    );
    assert_eq!(histogram.unresolved_count, 1, "the invalid time is visible");
    assert_eq!(histogram.total, 4);
    assert!(
        histogram
            .bins
            .windows(2)
            .all(|pair| pair[0].end_seconds == pair[1].start_seconds),
        "bins are contiguous and uniform"
    );

    // The explicit unresolved view has no timed bins at all.
    let unresolved = harness
        .session()
        .event_histogram(
            &EventQuery {
                unresolved_only: true,
                ..query.clone()
            },
            None,
            4,
        )
        .expect("unresolved histogram");
    assert!(unresolved.bins.is_empty());
    assert_eq!(unresolved.unresolved_count, 1);
    assert_eq!(unresolved.total, 1);

    // Filters and the search expression restrict the aggregate.
    let filtered = harness
        .session()
        .event_histogram(
            &EventQuery {
                kind: Some("log.record".into()),
                ..query.clone()
            },
            None,
            4,
        )
        .expect("kind histogram");
    assert_eq!(filtered.total, 4);
    let none = harness
        .session()
        .event_histogram(
            &EventQuery {
                kind: Some("no.such.kind".into()),
                ..query.clone()
            },
            None,
            4,
        )
        .expect("empty histogram");
    assert_eq!(none.total, 0);
    let searched = harness
        .session()
        .event_histogram(&query, Some("two"), 4)
        .expect("search histogram");
    assert_eq!(searched.total, 1);

    // An explicit window bounds both the bins and the total.
    let windowed = harness
        .session()
        .event_histogram(
            &EventQuery {
                after_seconds: Some(1_793_095_230),
                before_seconds: Some(1_793_095_290),
                ..query.clone()
            },
            None,
            4,
        )
        .expect("windowed histogram");
    assert_eq!(
        windowed.bins.iter().map(|bin| bin.count).sum::<u64>(),
        1,
        "only the in-window event is binned"
    );
    assert_eq!(
        windowed.unresolved_count, 1,
        "events with no chosen time cannot be placed in a window and stay reported"
    );

    let invalid = harness
        .session()
        .event_histogram(&query, Some("\"unterminated"), 4)
        .expect_err("bad grammar");
    assert_eq!(invalid.code(), "invalid_request");
}

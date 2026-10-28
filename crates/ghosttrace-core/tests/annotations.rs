//! P5.2 analyst workflow contract: note history is append-only, a stale edit is
//! a conflict, dispositions survive re-analysis, and saved filters are typed
//! values that fail loudly when they no longer fit.

mod support;

use ghosttrace_core::analysis::annotations::{AppendAnnotation, MAX_TAGS};
use ghosttrace_core::analysis::rules::{AnalysisRequest, RuleConfig};
use ghosttrace_core::analysis::views::SavedFilter;
use ghosttrace_core::domain::finding::Disposition;
use ghosttrace_core::ingest::LogFormat;
use ghosttrace_core::storage::writer::{Param, WriteBatch, WriteOp};
use support::Harness;

fn note(
    harness: &Harness,
    text: &str,
    tags: &[&str],
    disposition: Option<Disposition>,
    expected_previous: Option<i64>,
) -> Result<
    ghosttrace_core::analysis::annotations::AnnotationRevision,
    ghosttrace_core::error::CoreError,
> {
    harness.session().append_annotation(&AppendAnnotation {
        target_id: "fnd-test".into(),
        author_label: "analyst".into(),
        text: text.into(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        disposition,
        expected_previous,
    })
}

#[test]
fn notes_append_and_keep_their_history() {
    let harness = Harness::new();
    let first = note(&harness, "first look", &["triage", "triage"], None, None).expect("first");
    assert_eq!(first.tags, vec!["triage".to_string()]);
    assert_eq!(first.previous_revision, None);

    let second = note(
        &harness,
        "reviewed the captures",
        &[],
        Some(Disposition::Confirmed),
        Some(first.id),
    )
    .expect("second");
    assert_eq!(second.previous_revision, Some(first.id));

    let history = harness
        .session()
        .annotations("fnd-test", 10)
        .expect("history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].id, second.id, "newest first");
    assert_eq!(history[1].text, "first look", "the earlier reading stays");
    assert_eq!(
        harness
            .session()
            .current_disposition("fnd-test")
            .expect("disposition"),
        Some(Disposition::Confirmed)
    );

    // A later note without a disposition keeps the last recorded one.
    note(&harness, "tag only", &["reviewed"], None, Some(second.id)).expect("third");
    assert_eq!(
        harness
            .session()
            .current_disposition("fnd-test")
            .expect("disposition"),
        Some(Disposition::Confirmed)
    );
}

#[test]
fn stale_edits_are_rejected_instead_of_overwriting() {
    let harness = Harness::new();
    let first = note(&harness, "draft", &[], None, None).expect("first");
    let error = note(&harness, "stale draft", &[], None, None).expect_err("stale edit");
    assert_eq!(error.code(), "conflict");
    assert_eq!(
        harness
            .session()
            .annotations("fnd-test", 10)
            .expect("history")
            .len(),
        1,
        "the rejected edit wrote nothing"
    );
    note(&harness, "corrected", &[], None, Some(first.id)).expect("refresh");
}

#[test]
fn annotations_are_bounded_and_validated() {
    let harness = Harness::new();
    let empty = note(&harness, "", &[], None, None).expect_err("empty");
    assert_eq!(empty.code(), "invalid_request");

    let control = note(&harness, "ok", &["bad\n"], None, None).expect_err("control");
    assert_eq!(control.code(), "invalid_request");

    let many: Vec<String> = (0..=MAX_TAGS).map(|index| format!("t{index}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let too_many = note(&harness, "ok", &many, None, None).expect_err("too many tags");
    assert_eq!(too_many.code(), "invalid_request");

    let unknown_target = harness.session().append_annotation(&AppendAnnotation {
        target_id: String::new(),
        author_label: "analyst".into(),
        text: "x".into(),
        tags: vec![],
        disposition: None,
        expected_previous: None,
    });
    assert_eq!(
        unknown_target.expect_err("target").code(),
        "invalid_request"
    );
}

fn import_activity(harness: &mut Harness) -> String {
    let records: &[u8] = b"\
{\"ts\":\"2026-10-27T10:00:00Z\",\"kind\":\"activity\",\"host\":\"edge-a\",\"msg\":\"needle one\"}
{\"ts\":\"2026-10-27T10:01:00Z\",\"kind\":\"activity\",\"host\":\"edge-a\",\"msg\":\"two\"}
{\"ts\":\"2026-10-27T10:02:00Z\",\"kind\":\"other.kind\",\"host\":\"edge-b\",\"msg\":\"three\"}
";
    let acquisition = harness.capture(&[("logs/events.jsonl", records)]);
    harness
        .import(&acquisition, "logs/events.jsonl", |request| {
            request.format = Some(LogFormat::Jsonl);
            request.jsonl.message_field = Some("msg".into());
            request.jsonl.host_field = Some("host".into());
            request.jsonl.kind_field = Some("kind".into());
        })
        .expect("import")
        .run_id
}

#[test]
fn dismissal_survives_re_analysis() {
    let mut harness = Harness::new();
    let revision = import_activity(&mut harness);
    let request = AnalysisRequest {
        revision,
        config: RuleConfig::default(),
    };
    let configured = RuleConfig::from_toml(
        "[activity.outside_declared_hours]\ntimezone = \"UTC\"\nweekdays = [\"Mon\"]\nstart = \"12:00\"\nend = \"12:30\"\n",
    )
    .expect("schedule");
    let first = harness
        .session()
        .analyze(&AnalysisRequest {
            revision: request.revision.clone(),
            config: configured.clone(),
        })
        .expect("first run");
    assert!(
        !first.findings.is_empty(),
        "the fixture must produce a finding"
    );
    let finding = first.findings[0].clone();
    assert_eq!(finding.disposition, Disposition::Undismissed);

    let annotation = harness
        .session()
        .append_annotation(&AppendAnnotation {
            target_id: finding.id.clone(),
            author_label: "analyst".into(),
            text: "known maintenance window".into(),
            tags: vec!["maintenance".into()],
            disposition: Some(Disposition::Dismissed),
            expected_previous: None,
        })
        .expect("dismiss");

    let second = harness
        .session()
        .analyze(&AnalysisRequest {
            revision: request.revision,
            config: configured,
        })
        .expect("second run");
    assert_eq!(second.run_id, first.run_id);
    assert_eq!(
        second.findings[0].id, finding.id,
        "the same inputs keep the same finding id"
    );
    assert_eq!(
        second.findings[0].disposition,
        Disposition::Dismissed,
        "re-analysis reports the analyst's state"
    );
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM findings WHERE id = ?1 AND disposition = 'undismissed'",
            &[&finding.id]
        ),
        1,
        "the evaluator's initial row is untouched"
    );
    assert_eq!(
        harness
            .session()
            .current_disposition(&finding.id)
            .expect("disposition"),
        Some(Disposition::Dismissed)
    );
    assert_eq!(
        harness
            .session()
            .annotations(&finding.id, 10)
            .expect("history")
            .len(),
        1
    );
    let _ = annotation;
}

#[test]
fn saved_views_round_trip_and_run_through_the_shared_query() {
    let mut harness = Harness::new();
    let revision = import_activity(&mut harness);

    let filter = SavedFilter {
        kind: Some("activity".into()),
        limit: 2,
        ..SavedFilter::default()
    };
    let saved = harness
        .session()
        .save_view("activity only", &filter)
        .expect("save");
    assert_eq!(saved.filter, filter);
    assert_eq!(
        harness.session().saved_views().expect("list").len(),
        1,
        "saving the same name replaces, not duplicates"
    );
    harness
        .session()
        .save_view("activity only", &filter)
        .expect("replace");
    assert_eq!(harness.session().saved_views().expect("list").len(), 1);

    let page = harness
        .session()
        .run_saved_view(&revision, "activity only")
        .expect("run");
    assert_eq!(page.rows.len(), 2);
    assert!(page.rows.iter().all(|event| event.kind == "activity"));

    let text = SavedFilter {
        text: Some("needle".into()),
        ..SavedFilter::default()
    };
    harness
        .session()
        .save_view("with text", &text)
        .expect("save text");
    let page = harness
        .session()
        .run_saved_view(&revision, "with text")
        .expect("run text");
    assert_eq!(page.rows.len(), 1, "only the indexed needle matches");

    let missing = harness
        .session()
        .run_saved_view(&revision, "not saved")
        .expect_err("unknown view");
    assert_eq!(missing.code(), "invalid_request");
}

#[test]
fn saved_filters_reject_out_of_range_and_unknown_values() {
    let mut harness = Harness::new();
    import_activity(&mut harness);

    let mut filter = SavedFilter {
        limit: 0,
        ..SavedFilter::default()
    };
    assert_eq!(
        harness
            .session()
            .save_view("bad limit", &filter)
            .expect_err("limit")
            .code(),
        "invalid_request"
    );

    filter.limit = 10;
    filter.after_seconds = Some(20);
    filter.before_seconds = Some(10);
    assert_eq!(
        harness
            .session()
            .save_view("bad window", &filter)
            .expect_err("window")
            .code(),
        "invalid_request"
    );

    let bad_text = SavedFilter {
        text: Some("\"unterminated".into()),
        ..SavedFilter::default()
    };
    assert_eq!(
        harness
            .session()
            .save_view("bad text", &bad_text)
            .expect_err("grammar")
            .code(),
        "invalid_request"
    );

    assert_eq!(
        harness
            .session()
            .save_view("", &SavedFilter::default())
            .expect_err("name")
            .code(),
        "invalid_request"
    );

    // A view written by a build that knew another field is refused, not
    // silently narrowed.
    harness
        .session()
        .writer()
        .execute(WriteBatch::new().push(WriteOp::upsert(
            "saved_views",
            vec!["name", "filter_json", "created_seconds"],
            vec![
                Param::Text("foreign".into()),
                Param::Text("{\"kind\":\"activity\",\"unknown_field\":1}".into()),
                Param::Int(0),
            ],
        )))
        .expect("inject foreign view");
    let error = harness
        .session()
        .saved_view("foreign")
        .expect_err("unknown field");
    assert_eq!(error.code(), "invalid_request");
    assert!(
        error.detail().contains("incompatible"),
        "{}",
        error.detail()
    );
    assert!(
        harness
            .session()
            .saved_views()
            .expect_err("list refuses foreign rows")
            .detail()
            .contains("incompatible")
    );
}

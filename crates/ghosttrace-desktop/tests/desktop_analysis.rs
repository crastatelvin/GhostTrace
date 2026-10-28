//! P6.3 analysis contract: scope mismatches and unknown diff rows stay
//! visible, findings show their explanation and record dispositions through an
//! append-only command, notes/tags/bookmarks are annotations, and saved views
//! are typed filters.

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use ghosttrace_core::analysis::diff::{DiffClass, DiffReport, DiffRow, DiffSummary, SnapshotEntry};
use ghosttrace_core::analysis::views::{SavedFilter, SavedView};
use ghosttrace_core::domain::finding::{Disposition, Finding, Severity};
use ghosttrace_desktop::commands::{Command, Outcome};
use ghosttrace_desktop::diff::class_label;
use ghosttrace_desktop::query::QueryRequest;
use ghosttrace_desktop::state::{AppState, OpenCaseView, Screen};

fn open_case(state: &mut AppState, acquisitions: &[&str]) {
    state.open = Some(OpenCaseView {
        directory: "/tmp/demo.ghosttrace-case".into(),
        label: "Demo".into(),
        timezone: "UTC".into(),
        acquisitions: acquisitions
            .iter()
            .map(|id| ghosttrace_desktop::state::AcquisitionSummary {
                acquisition_id: (*id).into(),
                state: "completed".into(),
            })
            .collect(),
        recovery: Vec::new(),
    });
}

fn snapshot(path: &str, digest: &str) -> SnapshotEntry {
    SnapshotEntry {
        path: path.into(),
        sha256: digest.into(),
        byte_length: 12,
        source_mtime_seconds: Some(1_793_095_200),
        source_mtime_nanos: Some(0),
    }
}

fn diff_report() -> DiffReport {
    DiffReport {
        before_acquisition: "acq-1".into(),
        after_acquisition: "acq-2".into(),
        summary: DiffSummary {
            scope_compatible: false,
            before_roots: vec!["logs".into()],
            after_roots: vec!["logs".into(), "home".into()],
            warnings: vec!["coverage gap at logs/rotated.log".into()],
            unknown: 1,
            ..DiffSummary::default()
        },
        rows: vec![DiffRow {
            path: "logs/rotated.log".into(),
            class: DiffClass::Unknown,
            before: Some(snapshot("logs/rotated.log", "aa")),
            after: None,
            reason: "the later capture did not observe this path".into(),
        }],
        next_cursor: None,
    }
}

fn finding() -> Finding {
    Finding {
        id: "fnd-1".into(),
        analysis_run_id: "arun-1".into(),
        rule_id: "auth.fail_then_success".into(),
        rule_version: "1".into(),
        event_ids: vec!["ev-1".into()],
        predicates: serde_json::json!({"failures": 3, "window_seconds": 600}),
        severity: Severity::Medium,
        rationale: "three failures preceded a success within ten minutes".into(),
        alternatives: vec!["a legitimate password reset".into()],
        disposition: Disposition::Undismissed,
    }
}

#[test]
fn scope_mismatch_and_unknown_rows_are_stated_not_folded_away() {
    let mut state = AppState::new();
    open_case(&mut state, &["acq-2", "acq-1"]);
    state.screen = Screen::Diff;
    state.diff.before = Some("acq-1".into());
    state.diff.after = Some("acq-2".into());
    state.diff.report = Some(diff_report());
    state.diff.status = "1 row(s) shown".into();
    state.diff.selected = Some("logs/rotated.log".into());

    assert_eq!(
        class_label(DiffClass::Unknown),
        "unknown (cannot be decided)"
    );

    let mut harness = Harness::new_ui_state(|ui, state| state.ui(ui), state);
    harness.run_steps(2);
    for text in [
        "Scope mismatch",
        "Warning:",
        "unknown (cannot be decided)",
        "the later capture did not observe this path",
    ] {
        assert!(
            harness.query_all_by_label_contains(text).next().is_some(),
            "the screen never states {text:?}"
        );
    }
}

#[test]
fn diff_paging_appends_rows_and_keeps_the_summary() {
    let mut state = AppState::new();
    open_case(&mut state, &["acq-2", "acq-1"]);
    state.diff.before = Some("acq-1".into());
    state.diff.after = Some("acq-2".into());
    let requests = state.diff.refresh();
    assert!(matches!(
        &requests[0],
        QueryRequest::Diff { query, .. } if query.after.is_none()
    ));
    let generation = state.diff.generation();

    let mut first = diff_report();
    first.next_cursor = Some("logs/rotated.log".into());
    state.diff.apply(generation, first);
    assert_eq!(state.diff.report.as_ref().map(|r| r.rows.len()), Some(1));

    let requests = state.diff.load_more();
    match &requests[0] {
        QueryRequest::Diff { query, .. } => {
            assert_eq!(query.after.as_deref(), Some("logs/rotated.log"));
            assert_eq!(query.limit, 200);
        }
        other => panic!("unexpected request: {other:?}"),
    }
    let mut second = diff_report();
    second.summary = DiffSummary::default();
    second.rows = vec![DiffRow {
        path: "logs/new.log".into(),
        class: DiffClass::Appeared,
        before: None,
        after: Some(snapshot("logs/new.log", "bb")),
        reason: "present only in the later capture".into(),
    }];
    state.diff.apply(generation, second);

    let report = state.diff.report.expect("report");
    assert_eq!(report.rows.len(), 2, "the second page is appended");
    assert!(
        !report.summary.scope_compatible,
        "the first page's scope verdict is kept, not replaced by the page's summary"
    );
}

#[test]
fn a_stale_diff_page_is_dropped() {
    let mut state = AppState::new();
    open_case(&mut state, &["acq-2", "acq-1"]);
    state.diff.before = Some("acq-1".into());
    state.diff.after = Some("acq-2".into());
    state.diff.refresh();
    let generation = state.diff.generation();
    state.diff.refresh(); // a newer comparison superseded the first

    state.diff.apply(generation, diff_report());
    assert!(state.diff.report.is_none());
}

#[test]
fn a_disposition_is_an_append_that_names_the_revision_it_saw() {
    let mut state = AppState::new();
    open_case(&mut state, &["acq-2", "acq-1"]);
    state.findings.revision = Some("run-1".into());
    state.findings.findings = vec![finding()];
    state.findings.run_id = Some("arun-1".into());
    state.findings.selected = Some("fnd-1".into());
    state.findings.history = vec![ghosttrace_core::analysis::annotations::AnnotationRevision {
        id: 7,
        target_id: "fnd-1".into(),
        author_label: "ana".into(),
        created_seconds: 1_793_095_200,
        previous_revision: None,
        text: "first look".into(),
        tags: Vec::new(),
        disposition: None,
    }];
    state.findings.disposition = Disposition::Confirmed;
    state.findings.author = "ana".into();
    state.findings.note = "matches the incident window".into();
    state.findings.tags = "triage, reviewed, triage".into();

    state.record_finding_annotation();
    let commands = state.take_commands();
    assert_eq!(commands.len(), 1);
    match &commands[0] {
        Command::Annotate { request, .. } => {
            assert_eq!(request.target_id, "fnd-1");
            assert_eq!(request.expected_previous, Some(7));
            assert_eq!(request.disposition, Some(Disposition::Confirmed));
            assert_eq!(request.tags, vec!["triage", "reviewed"]);
            assert_eq!(request.author_label, "ana");
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn an_event_note_can_be_a_bookmark_tag() {
    let mut state = AppState::new();
    open_case(&mut state, &["acq-2", "acq-1"]);
    state.timeline.revision = Some("run-1".into());
    state.timeline.selected = Some("ev-1".into());
    state.timeline.note = "check the session id".into();
    state.timeline.bookmark = true;

    state.record_event_annotation();
    let commands = state.take_commands();
    match &commands[0] {
        Command::Annotate { request, .. } => {
            assert_eq!(request.target_id, "ev-1");
            assert_eq!(request.expected_previous, None);
            assert_eq!(request.tags, vec!["bookmark"]);
            assert_eq!(request.text, "check the session id");
        }
        other => panic!("unexpected command: {other:?}"),
    }

    // An empty note and no tags is refused before a command is built.
    state.timeline.note.clear();
    state.timeline.bookmark = false;
    state.timeline.tags.clear();
    state.record_event_annotation();
    assert!(state.take_commands().is_empty());
    assert!(
        state
            .notices
            .iter()
            .any(|notice| notice.text.contains("needs text or a tag"))
    );
}

#[test]
fn saved_views_store_the_typed_filter_and_apply_it() {
    let mut state = AppState::new();
    open_case(&mut state, &["acq-2", "acq-1"]);
    state.timeline.revision = Some("run-1".into());
    state.timeline.filters.text = "login".into();
    state.timeline.filters.kind = "auth.record".into();
    state.timeline.filters.unresolved_only = true;
    state.timeline.view_name = "failed logins".into();

    state.save_current_view();
    let commands = state.take_commands();
    match &commands[0] {
        Command::SaveView { name, filter, .. } => {
            assert_eq!(name, "failed logins");
            assert_eq!(filter.text.as_deref(), Some("login"));
            assert_eq!(filter.kind.as_deref(), Some("auth.record"));
            assert!(filter.unresolved_only);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    state.timeline.filters = Default::default();
    state.timeline.views = vec![SavedView {
        name: "failed logins".into(),
        filter: SavedFilter {
            text: Some("login".into()),
            kind: Some("auth.record".into()),
            unresolved_only: true,
            ..SavedFilter::default()
        },
        created_seconds: 1_793_095_200,
    }];
    state.apply_view("failed logins");
    assert_eq!(state.timeline.filters.text, "login");
    assert_eq!(state.timeline.filters.kind, "auth.record");
    assert!(state.timeline.filters.unresolved_only);
    assert!(
        state
            .take_queries()
            .iter()
            .any(|request| matches!(request, QueryRequest::Events { .. })),
        "applying a view re-runs the query"
    );
}

#[test]
fn a_half_open_saved_window_keeps_the_bound_it_stores() {
    let mut state = AppState::new();
    open_case(&mut state, &["acq-2", "acq-1"]);
    state.timeline.revision = Some("run-1".into());
    state.timeline.views = vec![SavedView {
        name: "after only".into(),
        filter: SavedFilter {
            after_seconds: Some(1_000),
            ..SavedFilter::default()
        },
        created_seconds: 1_793_095_200,
    }];

    state.apply_view("after only");
    assert_eq!(state.timeline.filters.after_seconds, Some(1_000));
    assert_eq!(
        state.timeline.filters.before_seconds, None,
        "an absent bound stays absent instead of being invented"
    );
    let queries = state.take_queries();
    match queries
        .iter()
        .find(|request| matches!(request, QueryRequest::Events { .. }))
    {
        Some(QueryRequest::Events { query, .. }) => {
            assert_eq!(query.after_seconds, Some(1_000));
            assert_eq!(query.before_seconds, None);
        }
        other => panic!("unexpected request: {other:?}"),
    }
}

#[test]
fn analysis_and_correlation_are_job_commands_for_the_open_case() {
    let mut state = AppState::new();
    open_case(&mut state, &["acq-2", "acq-1"]);
    state.timeline.revision = Some("run-1".into());

    state.run_analysis();
    let commands = state.take_commands();
    match &commands[0] {
        Command::Analyze {
            case_directory,
            revision,
            ..
        } => {
            assert_eq!(case_directory, "/tmp/demo.ghosttrace-case");
            assert_eq!(revision, "run-1");
        }
        other => panic!("unexpected command: {other:?}"),
    }
    state.apply(ghosttrace_desktop::commands::CommandEvent::Finished {
        id: commands[0].id(),
        outcome: Outcome::Analyzed {
            run_id: "arun-1".into(),
            state: "completed".into(),
            findings: 1,
        },
    });
    assert!(
        state
            .take_queries()
            .iter()
            .any(|request| matches!(request, QueryRequest::Findings { .. })),
        "a finished analysis loads its findings"
    );

    state.derive_relationships();
    let commands = state.take_commands();
    assert!(matches!(commands[0], Command::Correlate { .. }));

    // Without a parse run the commands are refused with a visible reason.
    let mut empty = AppState::new();
    open_case(&mut empty, &["acq-2", "acq-1"]);
    empty.run_analysis();
    assert!(empty.take_commands().is_empty());
    assert!(!empty.notices.is_empty());
}

#[test]
fn findings_show_their_explanation_and_alternatives() {
    let mut state = AppState::new();
    open_case(&mut state, &["acq-2", "acq-1"]);
    state.screen = Screen::Findings;
    state.findings.revision = Some("run-1".into());
    state.findings.run_id = Some("arun-1".into());
    state.findings.findings = vec![finding()];
    state.findings.selected = Some("fnd-1".into());
    state.findings.status = "1 finding(s) from arun-1".into();

    let mut harness = Harness::new_ui_state(|ui, state| state.ui(ui), state);
    harness.run_steps(2);
    for text in [
        "Why: three failures preceded a success within ten minutes",
        "Alternative: a legitimate password reset",
        "Disposition",
        "Record disposition",
        "Rule auth.fail_then_success",
    ] {
        assert!(
            harness.query_all_by_label_contains(text).next().is_some(),
            "the finding screen never states {text:?}"
        );
    }
    // The severity is a documented band, never a percentage.
    assert!(
        harness.query_all_by_label_contains("%").next().is_none(),
        "no score or percentage is shown"
    );
}

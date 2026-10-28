//! P6.2 timeline state contract: debounced queries, supersession, bounded page
//! cache, unresolved view, histogram bin selection, and detail supersession.

use ghosttrace_core::domain::detail::{EventDetail, Histogram, HistogramBin};
use ghosttrace_core::domain::query::{EventPage, EventRow, TimeCursor};
use ghosttrace_desktop::query::{QueryRequest, QueryTarget};
use ghosttrace_desktop::state::{AppState, TIMELINE_MAX_ROWS, TimelineState};

fn row(index: usize, time_status: &str) -> EventRow {
    EventRow {
        event_id: format!("ev-{index:04}"),
        revision: "run-1".into(),
        kind: "log.record".into(),
        summary: format!("event {index}"),
        host_claim: Some("host-a".into()),
        chosen_seconds: if time_status == "unresolved" {
            None
        } else {
            Some(1_793_095_200 + index as i64)
        },
        chosen_nanos: 0,
        time_status: time_status.into(),
    }
}

fn page(rows: Vec<EventRow>, next: bool) -> EventPage {
    let next_cursor = next.then(|| {
        let last = rows.last().expect("rows");
        TimeCursor {
            seconds: last.chosen_seconds.unwrap_or(0),
            nanos: last.chosen_nanos,
            event_id: last.event_id.clone(),
        }
    });
    EventPage {
        rows,
        next_cursor,
        display_timezone: "UTC".into(),
    }
}

fn detail(event_id: &str) -> EventDetail {
    let mut detail = EventDetail {
        event: row(0, "resolved"),
        parse_run_id: "run-1".into(),
        parser_id: "jsonl.fields".into(),
        parser_version: "1".into(),
        source_linked: true,
        observations: Vec::new(),
        times: Vec::new(),
        entities: Vec::new(),
        run_diagnostics: Vec::new(),
        run_assumptions_json: "[]".into(),
    };
    detail.event.event_id = event_id.into();
    detail
}

fn timeline() -> TimelineState {
    let mut timeline = TimelineState::new("UTC");
    timeline.revision = Some("run-1".into());
    timeline
}

#[test]
fn typing_debounces_into_one_query_after_the_pause() {
    let mut state = AppState::new();
    state.timeline = timeline();
    state.timeline.filters.text = "login".into();
    state.timeline.schedule_search(10.0);

    // Before the pause elapses nothing is queued.
    state.begin_frame(10.1);
    assert!(state.take_queries().is_empty());
    assert!(state.timeline.is_debouncing());

    state.begin_frame(10.4);
    let queries = state.take_queries();
    assert_eq!(queries.len(), 2, "one page plus one histogram");
    match &queries[0] {
        QueryRequest::Events {
            generation,
            query,
            text,
        } => {
            assert_eq!(*generation, 1);
            assert_eq!(text.as_deref(), Some("login"));
            assert_eq!(query.revision, "run-1");
            assert_eq!(query.limit, 200);
        }
        other => panic!("unexpected request: {other:?}"),
    }
    assert!(matches!(&queries[1], QueryRequest::Histogram { .. }));
    assert!(!state.timeline.is_debouncing());
}

#[test]
fn a_superseded_page_changes_nothing() {
    let mut timeline = timeline();
    timeline.refresh(); // generation 1
    timeline.refresh(); // generation 2, the current filter scope
    let generation = timeline.generation();

    timeline.apply_events(generation - 1, page(vec![row(0, "resolved")], false));
    assert!(timeline.events.is_empty(), "stale pages are dropped");

    timeline.apply_events(generation, page(vec![row(0, "resolved")], false));
    assert_eq!(timeline.events.len(), 1);
    assert!(!timeline.is_loading());
}

#[test]
fn the_page_cache_is_bounded_and_stops_asking_for_more() {
    let mut timeline = timeline();
    timeline.refresh();
    let generation = timeline.generation();

    for page_index in 0..6 {
        let rows = (0..200)
            .map(|offset| row(page_index * 200 + offset, "resolved"))
            .collect();
        timeline.apply_events(generation, page(rows, true));
        if !timeline.truncated {
            timeline.load_more();
        }
    }

    assert_eq!(timeline.events.len(), TIMELINE_MAX_ROWS);
    assert!(timeline.truncated);
    assert!(timeline.next_cursor.is_none());
    assert!(
        timeline.status.contains("cache limit reached"),
        "{}",
        timeline.status
    );
    assert!(
        timeline.load_more().is_empty(),
        "a full cache never queues another page"
    );
}

#[test]
fn the_unresolved_view_changes_the_query() {
    let mut timeline = timeline();
    timeline.filters.unresolved_only = true;
    let queries = timeline.refresh();
    match &queries[0] {
        QueryRequest::Events { query, .. } => assert!(query.unresolved_only),
        other => panic!("unexpected request: {other:?}"),
    }
}

#[test]
fn selecting_a_bin_filters_to_its_window_and_restarts_paging() {
    let mut timeline = timeline();
    timeline.refresh();
    timeline.apply_events(timeline.generation(), page(vec![row(0, "resolved")], false));
    let queries = timeline.select_bin(1_000, 2_000);
    assert_eq!(timeline.filters.window, Some((1_000, 2_000)));
    assert_eq!(timeline.generation(), 2);
    match &queries[0] {
        QueryRequest::Events { query, .. } => {
            assert_eq!(query.after_seconds, Some(1_000));
            assert_eq!(query.before_seconds, Some(2_000));
            assert!(query.after.is_none(), "a new filter scope restarts paging");
        }
        other => panic!("unexpected request: {other:?}"),
    }
}

#[test]
fn detail_results_are_superseded_and_selection_follows_the_keyboard() {
    let mut timeline = timeline();
    timeline.events = vec![row(0, "resolved"), row(1, "resolved"), row(2, "unresolved")];

    let first = timeline.move_selection(1);
    assert_eq!(timeline.selected.as_deref(), Some("ev-0000"));
    assert!(matches!(
        first[0],
        QueryRequest::Detail { generation: 1, .. }
    ));

    let second = timeline.move_selection(1);
    assert_eq!(timeline.selected.as_deref(), Some("ev-0001"));
    assert!(matches!(
        second[0],
        QueryRequest::Detail { generation: 2, .. }
    ));

    timeline.apply_detail(1, detail("ev-0000"));
    assert!(
        timeline.detail.is_none(),
        "the detail for the previous selection is dropped"
    );
    timeline.apply_detail(2, detail("ev-0001"));
    assert_eq!(
        timeline
            .detail
            .as_ref()
            .map(|detail| detail.event.event_id.as_str()),
        Some("ev-0001")
    );

    // Clamps at both ends instead of wrapping into a different event.
    timeline.move_selection(10);
    assert_eq!(timeline.selected.as_deref(), Some("ev-0002"));
    timeline.move_selection(-10);
    assert_eq!(timeline.selected.as_deref(), Some("ev-0000"));
}

#[test]
fn query_failures_are_actionable_and_stale_failures_are_ignored() {
    let mut state = AppState::new();
    state.timeline = timeline();
    state.timeline.refresh();
    let generation = state.timeline.generation();

    state.apply_query(ghosttrace_desktop::query::QueryResult::Failed {
        generation: generation + 1,
        target: QueryTarget::Events,
        code: "invalid_request".into(),
        message: "stale".into(),
    });
    assert!(state.notices.is_empty());

    state.apply_query(ghosttrace_desktop::query::QueryResult::Failed {
        generation,
        target: QueryTarget::Events,
        code: "invalid_request".into(),
        message: "search expression is not valid".into(),
    });
    assert!(
        state
            .notices
            .iter()
            .any(|notice| notice.text.contains("invalid_request")),
        "{:?}",
        state.notices
    );
    assert!(!state.timeline.is_loading(), "a failed query stops waiting");
    assert!(state.timeline.status.contains("invalid_request"));
}

#[test]
fn histogram_aggregates_are_kept_only_for_the_current_generation() {
    let mut timeline = timeline();
    timeline.refresh();
    let histogram = Histogram {
        bin_seconds: 60,
        from_seconds: 0,
        to_seconds: 120,
        bins: vec![HistogramBin {
            start_seconds: 0,
            end_seconds: 60,
            count: 2,
        }],
        unresolved_count: 1,
        total: 3,
    };
    timeline.apply_histogram(0, histogram.clone());
    assert!(timeline.histogram.is_none());
    timeline.apply_histogram(timeline.generation(), histogram);
    assert_eq!(timeline.histogram.as_ref().map(|h| h.total), Some(3));
}

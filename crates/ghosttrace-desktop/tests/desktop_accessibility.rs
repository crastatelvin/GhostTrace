//! P6.2 accessibility contract: every timeline control has an accessible name,
//! keyboard selection works without a mouse, scaling keeps the controls
//! reachable, and uncertainty is never encoded by color alone.

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use ghosttrace_core::domain::detail::{
    EntityRef, EventDetail, EventTimeDetail, Histogram, HistogramBin, ObservationDetail,
};
use ghosttrace_core::domain::query::EventRow;
use ghosttrace_desktop::state::{AppState, OpenCaseView, Screen};

fn harness(state: AppState) -> Harness<'static, AppState> {
    Harness::new_ui_state(|ui, state| state.ui(ui), state)
}

fn row(event_id: &str, time_status: &str, seconds: Option<i64>) -> EventRow {
    EventRow {
        event_id: event_id.into(),
        revision: "run-1".into(),
        kind: "log.record".into(),
        summary: format!("record {event_id}"),
        host_claim: Some("host-a".into()),
        chosen_seconds: seconds,
        chosen_nanos: 0,
        time_status: time_status.into(),
    }
}

fn detail() -> EventDetail {
    EventDetail {
        event: row("ev-unresolved", "unresolved", None),
        parse_run_id: "run-1".into(),
        parser_id: "jsonl.fields".into(),
        parser_version: "1".into(),
        source_linked: true,
        observations: vec![ObservationDetail {
            evidence_id: "evd-1".into(),
            acquisition_id: "acq-1".into(),
            evidence_path: "unix:%2Fvar%2Flog%2Fauth.log".into(),
            locator_kind: "byte_range".into(),
            locator_identity: "offset:0:len:64".into(),
            raw_fields_json: "{\"ts\":null,\"msg\":\"no time\"}".into(),
        }],
        times: vec![EventTimeDetail {
            name: "logged".into(),
            semantic: "logged_time".into(),
            status: "unresolved".into(),
            candidates_json: "[]".into(),
            raw_field: Some("ts".into()),
            raw_value_kind: None,
            raw_value: None,
            epoch: "unix".into(),
            unit: "seconds".into(),
            declared_precision: "seconds".into(),
            clock_domain: "host".into(),
            assumptions_json: "[{\"description\":\"no timestamp was recorded\"}]".into(),
        }],
        entities: vec![EntityRef {
            entity_id: "ent-1".into(),
            kind: "user".into(),
            display_form: "alice".into(),
            role: "actor".into(),
        }],
        run_diagnostics: Vec::new(),
        run_assumptions_json: "[]".into(),
    }
}

fn seeded() -> AppState {
    let mut state = AppState::new();
    state.open = Some(OpenCaseView {
        directory: "/tmp/demo.ghosttrace-case".into(),
        label: "Demo".into(),
        timezone: "UTC".into(),
        acquisitions: Vec::new(),
        recovery: Vec::new(),
    });
    state.screen = Screen::Timeline;
    state.timeline.revision = Some("run-1".into());
    state.timeline.events = vec![
        row("ev-resolved", "resolved", Some(1_793_095_200)),
        row("ev-unresolved", "unresolved", None),
    ];
    state.timeline.histogram = Some(Histogram {
        bin_seconds: 60,
        from_seconds: 1_793_095_200,
        to_seconds: 1_793_095_320,
        bins: vec![
            HistogramBin {
                start_seconds: 1_793_095_200,
                end_seconds: 1_793_095_260,
                count: 1,
            },
            HistogramBin {
                start_seconds: 1_793_095_260,
                end_seconds: 1_793_095_320,
                count: 0,
            },
        ],
        unresolved_count: 1,
        total: 2,
    });
    state.timeline.selected = Some("ev-unresolved".into());
    state.timeline.detail = Some(detail());
    state.timeline.status = "2 event(s) loaded".into();
    state
}

#[test]
fn every_timeline_control_has_an_accessible_name() {
    let mut harness = harness(seeded());
    harness.run_steps(2);

    for label in [
        "Search events",
        "Filter by kind",
        "Filter by host",
        "Filter by source",
        "Unresolved times only",
        "Reset filters",
        "Evidence inspector",
        "Copy event id",
        "Copy locator",
        "Copy raw record",
    ] {
        harness.get_by_label(label);
    }
    harness.get_by_label_contains("Time histogram");
    harness.get_by_label_contains("Time status: unresolved time");
    harness.get_by_label_contains("Raw record");
    harness.get_by_label_contains("Parse run diagnostics");
}

#[test]
fn uncertainty_is_stated_in_words_and_bins_are_listed_with_counts() {
    let mut harness = harness(seeded());
    harness.run_steps(2);

    // The row, the detail pane, and the histogram all state the unresolved
    // count in text; a color-only encoding would fail these queries.
    for fragment in [
        "unresolved time",
        "have no chosen time",
        "2026-10-27 10:00:00 UTC",
        "1 event(s)",
    ] {
        assert!(
            harness
                .query_all_by_label_contains(fragment)
                .next()
                .is_some(),
            "no visible text states {fragment:?}"
        );
    }
}

#[test]
fn keyboard_selection_and_the_unresolved_shortcut_work_without_focus() {
    let mut harness = harness(seeded());
    harness.run_steps(2);
    harness.state_mut().timeline.selected = None;

    harness.key_press(egui::Key::J);
    harness.run_steps(2);
    assert_eq!(
        harness.state().timeline.selected.as_deref(),
        Some("ev-resolved"),
        "J selects the first row"
    );

    harness.key_press(egui::Key::J);
    harness.run_steps(2);
    assert_eq!(
        harness.state().timeline.selected.as_deref(),
        Some("ev-unresolved")
    );

    harness.key_press(egui::Key::U);
    harness.run_steps(2);
    assert!(harness.state().timeline.filters.unresolved_only);
}

#[test]
fn the_search_shortcut_focuses_the_named_search_field() {
    let mut harness = harness(seeded());
    harness.run_steps(2);
    assert!(!harness.ctx.egui_wants_keyboard_input());

    harness.key_press(egui::Key::Slash);
    harness.run_steps(2);
    assert!(
        harness.ctx.egui_wants_keyboard_input(),
        "the / shortcut moves focus into the search field"
    );
}

#[test]
fn controls_stay_findable_at_larger_scaling() {
    let mut harness = harness(seeded());
    harness.ctx.set_pixels_per_point(1.5);
    harness.run_steps(2);
    harness.get_by_label("Search events");
    harness.get_by_label("Unresolved times only");
    harness.get_by_label_contains("Evidence inspector");
}

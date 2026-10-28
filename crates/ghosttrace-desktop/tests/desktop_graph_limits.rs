//! P6.3 graph bounds: a large neighborhood never makes layout or painting
//! unbounded, expansion adds pages instead of nodes without limit, and the
//! list remains the complete, keyboard-reachable representation.

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use ghosttrace_core::analysis::correlate::{EntityRef, RelationshipPage, RelationshipRow};
use ghosttrace_desktop::query::QueryRequest;
use ghosttrace_desktop::state::{
    AppState, GRAPH_MAX_EDGES, GRAPH_MAX_NODES, OpenCaseView, Screen, graph_model, support_events,
};

fn entity(id: &str) -> EntityRef {
    EntityRef {
        id: id.into(),
        kind: "path".into(),
        scoped_identity: id.into(),
        display_form: id.into(),
    }
}

fn row(id: i64, source: &str, target: &str) -> RelationshipRow {
    RelationshipRow {
        id,
        kind: "shared_digest".into(),
        rule_id: "correlate.shared_digest".into(),
        rule_version: "1".into(),
        source: entity(source),
        target: entity(target),
        support_json: format!("{{\"matching_fields\":[\"sha256:aa\"],\"events\":[\"ev-{id}\"]}}"),
        strength_basis: "equal full digest".into(),
    }
}

fn open_case(state: &mut AppState) {
    state.open = Some(OpenCaseView {
        directory: "/tmp/demo.ghosttrace-case".into(),
        label: "Demo".into(),
        timezone: "UTC".into(),
        acquisitions: Vec::new(),
        recovery: Vec::new(),
    });
    state.screen = Screen::Relations;
    state.relations.revision = Some("run-1".into());
}

#[test]
fn a_large_neighborhood_is_capped_and_says_so() {
    let rows: Vec<RelationshipRow> = (0..200)
        .map(|index| row(index, "path-a", "path-b"))
        .collect();
    let model = graph_model(&rows, GRAPH_MAX_NODES, GRAPH_MAX_EDGES);
    assert_eq!(model.nodes.len(), 2);
    assert_eq!(model.edges.len(), GRAPH_MAX_EDGES);
    assert!(model.capped_edges, "the drawing reports the omitted edges");
    assert!(!model.capped_nodes);
    assert_eq!(rows.len(), 200, "every loaded row stays in the list");
}

#[test]
fn many_distinct_entities_stop_at_the_node_cap() {
    let rows: Vec<RelationshipRow> = (0..100)
        .map(|index| {
            row(
                index,
                &format!("source-{index}"),
                &format!("target-{index}"),
            )
        })
        .collect();
    let model = graph_model(&rows, GRAPH_MAX_NODES, GRAPH_MAX_EDGES);
    assert_eq!(model.nodes.len(), GRAPH_MAX_NODES);
    assert!(model.capped_nodes);
    assert!(
        model.edges.len() <= GRAPH_MAX_EDGES,
        "the edge cap still holds"
    );
    for edge in &model.edges {
        assert!(
            model.nodes.iter().any(|node| node.id == edge.source),
            "a drawn edge never points at an off-screen source"
        );
        assert!(
            model.nodes.iter().any(|node| node.id == edge.target),
            "a drawn edge never points at an off-screen target"
        );
    }
}

#[test]
fn expansion_appends_a_page_and_the_drawing_stays_bounded() {
    let mut state = AppState::new();
    open_case(&mut state);
    let requests = state.relations.refresh();
    assert!(matches!(
        &requests[0],
        QueryRequest::Relationships { query, .. } if query.after_id.is_none()
    ));
    let generation = state.relations.generation();

    state.relations.apply(
        generation,
        RelationshipPage {
            rows: (0..100)
                .map(|index| row(index, "path-a", &format!("path-{index}")))
                .collect(),
            next_cursor: Some(100),
        },
    );
    assert_eq!(state.relations.rows.len(), 100);

    let requests = state.relations.load_more();
    match &requests[0] {
        QueryRequest::Relationships { query, .. } => {
            assert_eq!(
                query.after_id,
                Some(100),
                "keyset paging resumes after the last id"
            );
        }
        other => panic!("unexpected request: {other:?}"),
    }
    state.relations.apply(
        generation,
        RelationshipPage {
            rows: (100..200)
                .map(|index| row(index, "path-a", &format!("path-{index}")))
                .collect(),
            next_cursor: None,
        },
    );
    assert_eq!(state.relations.rows.len(), 200);
    let model = state.relations.graph();
    assert!(model.nodes.len() <= GRAPH_MAX_NODES);
    assert!(model.edges.len() <= GRAPH_MAX_EDGES);
    assert!(model.capped_nodes || model.capped_edges);
}

#[test]
fn keyboard_selection_walks_the_loaded_rows_and_clamps() {
    let mut state = AppState::new();
    open_case(&mut state);
    state.relations.rows = vec![row(1, "a", "b"), row(2, "b", "c")];

    state.move_relation_selection(1);
    assert_eq!(state.relations.selected, Some(1));
    state.move_relation_selection(1);
    assert_eq!(state.relations.selected, Some(2));
    state.move_relation_selection(10);
    assert_eq!(state.relations.selected, Some(2));
    state.move_relation_selection(-10);
    assert_eq!(state.relations.selected, Some(1));
}

#[test]
fn support_is_read_from_the_recorded_value_not_guessed() {
    assert_eq!(
        support_events("{\"events\":[\"ev-1\",\"ev-2\"]}"),
        ["ev-1", "ev-2"]
    );
    assert!(support_events("not json").is_empty());
    assert!(support_events("{\"matching_fields\":[]}").is_empty());
}

#[test]
fn every_loaded_relationship_is_reachable_from_the_list_and_named_in_the_graph() {
    let mut state = AppState::new();
    open_case(&mut state);
    state.relations.rows = vec![row(1, "path-a", "path-b"), row(2, "path-b", "path-c")];
    state.relations.status = "2 relationship(s) loaded".into();

    let mut harness = Harness::new_ui_state(|ui, state| state.ui(ui), state);
    harness.run_steps(2);

    harness.get_by_label_contains("2 relationship(s) loaded");
    harness.get_by_label_contains("Relationship 1 shared_digest");
    harness.get_by_label_contains("Relationship 2 shared_digest");

    harness.key_press(egui::Key::J);
    harness.run_steps(2);
    assert_eq!(harness.state().relations.selected, Some(1));
    harness.get_by_label_contains("1 supporting event(s)");

    harness.key_press(egui::Key::J);
    harness.run_steps(2);
    assert_eq!(harness.state().relations.selected, Some(2));
    harness.get_by_label_contains("Strength basis: equal full digest");
}

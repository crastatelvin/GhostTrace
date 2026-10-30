//! Relationship list and bounded graph (plan P5.1/P6.3).
//!
//! The list is the primary representation: every edge is a named, focusable
//! row, and selecting one reveals the recorded support. The graph is a bounded
//! drawing over the same rows, so a large neighborhood can never make painting
//! or layout unbounded. Selecting an edge either way opens the same support.

use eframe::egui;
use ghosttrace_core::text::escape_for_display;

use crate::state::{AppState, GRAPH_MAX_EDGES, GRAPH_MAX_NODES, support_events, support_fields};

pub fn ui(state: &mut AppState, ui: &mut egui::Ui) {
    let theme = state.theme;
    crate::theme::title(ui, theme, "Relationships");
    crate::theme::muted(
        ui,
        theme,
        "Candidate links derived from recorded entities. A link is a hypothesis with recorded \
         support; equal values do not prove an action.",
    );

    ui.horizontal_wrapped(|ui| {
        crate::state::labeled_text(ui, "Filter by entity id", &mut state.relations.entity);
        crate::state::labeled_text(ui, "Filter by relationship kind", &mut state.relations.kind);
        if crate::theme::quiet(ui, theme, "Apply filters").clicked() {
            state.load_relations();
        }
        if crate::theme::quiet(ui, theme, "Derive relationships").clicked() {
            state.derive_relationships();
        }
    });

    if state.relations.revision.is_none() {
        crate::theme::muted(ui, theme, "This case has no parse run yet.");
        return;
    }

    egui::Panel::right("ghosttrace-relations-detail")
        .resizable(true)
        .default_size(380.0)
        .frame(crate::theme::side_frame(ui.style(), theme))
        .show(ui, |ui| detail(state, ui));

    graph(state, ui);
    list(state, ui);
    handle_keys(state, ui);
    crate::theme::muted(ui, theme, "Keys: J/K next/previous relationship");
}

/// Draw the bounded graph. Node positions are a fixed circle, so the layout
/// cost is linear in the drawn caps and independent of the case size.
fn graph(state: &mut AppState, ui: &mut egui::Ui) {
    let model = state.relations.graph();
    if model.nodes.is_empty() {
        ui.label("No relationships loaded. Derive them, or relax the filters.");
        return;
    }
    let palette = crate::theme::Palette::of(state.theme);
    let height = (ui.available_height() * 0.4).clamp(120.0, 280.0);
    let size = egui::vec2(ui.available_width().min(460.0), height);
    let (response, painter) = ui.allocate_painter(size, egui::Sense::hover());
    let rect = response.rect.shrink(34.0);
    let center = rect.center();
    let radius = rect.width().min(rect.height()) * 0.5;
    let position = |index: usize| {
        let angle = std::f32::consts::TAU * index as f32 / model.nodes.len().max(1) as f32;
        center + egui::vec2(angle.cos(), angle.sin()) * radius
    };
    let index_of = |id: &str| model.nodes.iter().position(|node| node.id == id);

    let mut clicked = None;
    for edge in &model.edges {
        let (Some(source), Some(target)) = (index_of(&edge.source), index_of(&edge.target)) else {
            continue;
        };
        let (from, to) = (position(source), position(target));
        let selected = state.relations.selected == Some(edge.id);
        painter.line_segment(
            [from, to],
            if selected {
                egui::Stroke::new(3.0, palette.accent)
            } else {
                egui::Stroke::new(1.0, palette.border_strong)
            },
        );
        let midpoint = from + (to - from) * 0.5;
        let hit = egui::Rect::from_center_size(midpoint, egui::vec2(20.0, 20.0));
        let response = ui.interact(
            hit,
            ui.make_persistent_id(("ghosttrace-relation-edge", edge.id)),
            egui::Sense::click(),
        );
        let label = format!(
            "Relationship {} {} from {} to {}",
            edge.id,
            edge.kind,
            short(&edge.source),
            short(&edge.target)
        );
        response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, &label));
        if response.clicked() {
            clicked = Some(edge.id);
        }
        painter.circle_filled(
            midpoint,
            3.0,
            if selected {
                palette.accent
            } else {
                palette.border_strong
            },
        );
    }
    for (index, node) in model.nodes.iter().enumerate() {
        let position = position(index);
        painter.circle_filled(position, 5.0, palette.accent);
        let (label, _) = escape_for_display(&node.label, 20);
        painter.text(
            position + egui::vec2(8.0, -8.0),
            egui::Align2::LEFT_BOTTOM,
            label,
            egui::FontId::proportional(11.0),
            palette.text_muted,
        );
    }
    if let Some(id) = clicked {
        state.relations.select(id);
    }
    if model.capped_nodes || model.capped_edges {
        crate::theme::muted(
            ui,
            state.theme,
            format!(
                "Graph is bounded to {GRAPH_MAX_NODES} node(s) and {GRAPH_MAX_EDGES} edge(s); it \
                 draws {} node(s) and {} edge(s). The list below has every loaded row, so nothing \
                 is reachable only through the drawing.",
                model.nodes.len(),
                model.edges.len()
            ),
        );
    }
}

fn list(state: &mut AppState, ui: &mut egui::Ui) {
    let theme = state.theme;
    let rows = state.relations.rows.clone();
    let selected = state.relations.selected;
    let mut clicked = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show_rows(ui, 24.0, rows.len(), |ui, range| {
            for index in range.clone() {
                let row = &rows[index];
                let label = format!(
                    "{} · {} · {} to {} · {}",
                    row.id,
                    row.kind,
                    short(&row.source.display_form),
                    short(&row.target.display_form),
                    row.strength_basis
                );
                if ui
                    .selectable_label(selected == Some(row.id), label)
                    .clicked()
                {
                    clicked = Some(row.id);
                }
            }
        });
    if let Some(id) = clicked {
        state.relations.select(id);
    }
    crate::theme::section(ui, theme, "Relationships");
    ui.horizontal(|ui| {
        crate::theme::muted(ui, theme, state.relations.status.clone());
        if state.relations.next_cursor.is_some()
            && crate::theme::quiet(ui, theme, "Load more").clicked()
        {
            state.load_more_relations();
        }
    });
}

fn detail(state: &mut AppState, ui: &mut egui::Ui) {
    let theme = state.theme;
    crate::theme::title(ui, theme, "Relationship detail");
    let Some(row) = state.relations.selected_row().cloned() else {
        crate::theme::muted(
            ui,
            theme,
            "Select a relationship to see its recorded support.",
        );
        return;
    };
    crate::theme::section(ui, theme, "Recorded link");
    crate::theme::muted(
        ui,
        theme,
        format!(
            "Kind: {} · rule {} · version {}",
            row.kind, row.rule_id, row.rule_version
        ),
    );
    crate::theme::muted(ui, theme, format!("Strength basis: {}", row.strength_basis));
    crate::theme::muted(
        ui,
        theme,
        format!(
            "Source: {} ({})",
            short(&row.source.display_form),
            row.source.kind
        ),
    );
    crate::theme::muted(
        ui,
        theme,
        format!(
            "Target: {} ({})",
            short(&row.target.display_form),
            row.target.kind
        ),
    );
    let fields = support_fields(&row.support_json);
    if fields.is_empty() {
        crate::theme::muted(
            ui,
            theme,
            "Matching fields: none recorded in the stored support value.",
        );
    } else {
        crate::theme::muted(
            ui,
            theme,
            format!(
                "Matching fields: {}",
                fields
                    .iter()
                    .map(|field| escape_for_display(field, 240).0)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    let events = support_events(&row.support_json);
    crate::theme::muted(
        ui,
        theme,
        format!(
            "{} supporting event(s). Opening one shows its raw record and locator.",
            events.len()
        ),
    );
    egui::ScrollArea::vertical()
        .max_height(320.0)
        .show(ui, |ui| {
            for event_id in &events {
                if crate::theme::quiet(ui, theme, &format!("Open event {}", short(event_id)))
                    .clicked()
                {
                    state.open_event(event_id);
                }
            }
        });
}

/// Apply keyboard selection for this screen. Called from the screen because
/// the state borrow lives there.
pub fn handle_keys(state: &mut AppState, ui: &egui::Ui) {
    if ui.ctx().egui_wants_keyboard_input() {
        return;
    }
    if ui.input(|input| input.key_pressed(egui::Key::J)) {
        state.move_relation_selection(1);
    }
    if ui.input(|input| input.key_pressed(egui::Key::K)) {
        state.move_relation_selection(-1);
    }
}

fn short(text: &str) -> String {
    escape_for_display(text, 40).0
}

//! Evidence inspector: the exact provenance of one selected event (plan P6.2).
//!
//! Shows the recorded raw record and locator, every time value with its
//! assumptions, scoped entities, parser identity, and the parse run's own
//! diagnostics. Recorded text is escaped and bounded; nothing here is
//! interpreted as markup, a link, or a terminal sequence.

use eframe::egui;
use ghosttrace_core::domain::detail::{EntityRef, EventDetail, EventTimeDetail};
use ghosttrace_core::text::{MAX_PREVIEW_BYTES, escape_for_display};

use crate::state::{AppState, labeled_text};

pub fn ui(state: &mut AppState, ui: &mut egui::Ui) {
    crate::theme::title(ui, state.theme, "Evidence inspector");
    let Some(detail) = state.timeline.detail.clone() else {
        crate::theme::muted(
            ui,
            state.theme,
            "Select an event to inspect its exact provenance.",
        );
        return;
    };
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            body(ui, state.theme, &detail);
            notes(ui, state);
        });
}

/// Analyst notes and tags are annotations on the event id, never edits to the
/// recorded observation. Each append names the revision it supersedes.
fn notes(ui: &mut egui::Ui, state: &mut AppState) {
    let theme = state.theme;
    ui.add_space(crate::theme::SECTION_GAP);
    crate::theme::card(ui, theme, |ui| {
        crate::theme::section(ui, theme, "Notes and tags");
        ui.label(
        "Notes are append-only: each edit records a new revision that names the one it          supersedes. A bookmark is a recorded tag, not a new fact about the event.",
    );
        labeled_text(ui, "Author label", &mut state.timeline.author);
        let label = ui.label("Event note");
        ui.add(
            egui::TextEdit::multiline(&mut state.timeline.note)
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        )
        .labelled_by(label.id);
        labeled_text(ui, "Event tags", &mut state.timeline.tags);
        ui.checkbox(&mut state.timeline.bookmark, "Bookmark this event");
        if crate::theme::quiet(ui, theme, "Record note").clicked() {
            state.record_event_annotation();
        }
        crate::theme::muted(ui, theme, state.timeline.annotation_status.clone());
        for revision in state.timeline.annotations.clone() {
            let (text, _) = escape_for_display(&revision.text, 2_048);
            crate::theme::muted(
                ui,
                theme,
                format!(
                    "{} · {} · {} · tags: {}",
                    crate::timeline::format_instant(
                        revision.created_seconds,
                        &state.timeline.display_timezone
                    ),
                    revision.author_label,
                    if text.is_empty() { "no text" } else { &text },
                    if revision.tags.is_empty() {
                        "none".into()
                    } else {
                        revision.tags.join(", ")
                    }
                ),
            );
        }
    });
}

fn body(ui: &mut egui::Ui, theme: crate::state::ThemeChoice, detail: &EventDetail) {
    crate::theme::card(ui, theme, |ui| {
        ui.label(
            egui::RichText::new(format!("Event {}", detail.event.event_id))
                .monospace()
                .strong(),
        );
        crate::theme::muted(
            ui,
            theme,
            format!(
                "Kind {} · host {}",
                detail.event.kind,
                detail
                    .event
                    .host_claim
                    .as_deref()
                    .unwrap_or("none recorded")
            ),
        );
        crate::theme::muted(
            ui,
            theme,
            format!(
                "Parser {} · version {}",
                detail.parser_id, detail.parser_version
            ),
        );
        crate::theme::muted(ui, theme, format!("Parse run {}", detail.parse_run_id));
        crate::theme::muted(
            ui,
            theme,
            format!(
                "Time status: {}",
                match detail.event.time_status.as_str() {
                    "resolved" => "resolved",
                    "ambiguous" => "ambiguous time — candidates remain",
                    "unresolved" => "unresolved time — no chosen instant",
                    "invalid" => "invalid time — the recorded value cannot be used",
                    _ => "unknown time status",
                }
            ),
        );
        if !detail.source_linked {
            crate::theme::muted(
                ui,
                theme,
                "Source link not recorded for this event. The raw record cannot be reopened \
                 without guessing, so none is shown.",
            );
        }

        ui.horizontal_wrapped(|ui| {
            if crate::theme::quiet(ui, theme, "Copy event id").clicked() {
                ui.ctx().copy_text(detail.event.event_id.clone());
            }
            for observation in &detail.observations {
                if crate::theme::quiet(ui, theme, "Copy locator").clicked() {
                    ui.ctx().copy_text(observation.locator_identity.clone());
                }
                if crate::theme::quiet(ui, theme, "Copy raw record").clicked() {
                    ui.ctx().copy_text(observation.raw_fields_json.clone());
                }
            }
        });

        crate::theme::section(ui, theme, "Times");
        if detail.times.is_empty() {
            crate::theme::muted(ui, theme, "No named time was recorded for this event.");
        }
        for time in &detail.times {
            time_entry(ui, theme, time);
        }

        crate::theme::section(ui, theme, "Raw record");
        if detail.observations.is_empty() {
            crate::theme::muted(ui, theme, "No raw observation is linked to this event.");
        }
        for observation in &detail.observations {
            crate::theme::muted(
                ui,
                theme,
                format!(
                    "Evidence {} · acquisition {}",
                    observation.evidence_id, observation.acquisition_id
                ),
            );
            crate::theme::muted(ui, theme, format!("Path {}", observation.evidence_path));
            crate::theme::muted(
                ui,
                theme,
                format!(
                    "Locator {} {}",
                    observation.locator_kind, observation.locator_identity
                ),
            );
            let (raw, truncated) =
                escape_for_display(&observation.raw_fields_json, MAX_PREVIEW_BYTES);
            let mut buffer = raw;
            ui.add(
                egui::TextEdit::multiline(&mut buffer)
                    .code_editor()
                    .interactive(false)
                    .desired_rows(8)
                    .desired_width(f32::INFINITY),
            );
            if truncated {
                crate::theme::muted(
                    ui,
                    theme,
                    "Preview truncated; use Copy raw record for the full value.",
                );
            }
        }

        crate::theme::section(ui, theme, "Entities");
        if detail.entities.is_empty() {
            crate::theme::muted(
                ui,
                theme,
                "No scoped entities were resolved for this revision yet.",
            );
        }
        for entity in &detail.entities {
            entity_entry(ui, theme, entity);
        }

        ui.collapsing("Parse run diagnostics", |ui| {
            crate::theme::muted(
                ui,
                theme,
                "Diagnostics are recorded for the whole parse run, not this record.",
            );
            if detail.run_diagnostics.is_empty() {
                crate::theme::muted(ui, theme, "The run recorded no diagnostics.");
            }
            for diagnostic in &detail.run_diagnostics {
                let (detail_text, _) = escape_for_display(&diagnostic.detail, 2_048);
                crate::theme::muted(
                    ui,
                    theme,
                    format!(
                        "{} · {} · {}",
                        diagnostic.code, diagnostic.locator, detail_text
                    ),
                );
            }
            let (assumptions, _) = escape_for_display(&detail.run_assumptions_json, 4_096);
            crate::theme::muted(
                ui,
                theme,
                format!("Recorded run assumptions: {assumptions}"),
            );
        });
    });
}

fn time_entry(ui: &mut egui::Ui, theme: crate::state::ThemeChoice, time: &EventTimeDetail) {
    crate::theme::muted(
        ui,
        theme,
        format!("{} · {} · {}", time.name, time.status, time.semantic),
    );
    if time.status != "resolved" {
        crate::theme::muted(
            ui,
            theme,
            format!(
                "{} time: the recorded value is shown below but cannot be placed on the timeline.",
                time.status
            ),
        );
    }
    crate::theme::muted(
        ui,
        theme,
        format!(
            "Raw field {} = {}",
            time.raw_field.as_deref().unwrap_or("none"),
            time.raw_value.as_deref().unwrap_or("none")
        ),
    );
    crate::theme::muted(
        ui,
        theme,
        format!(
            "Epoch {} · unit {} · precision {} · clock domain {}",
            time.epoch, time.unit, time.declared_precision, time.clock_domain
        ),
    );
    for assumption in assumption_lines(&time.assumptions_json) {
        crate::theme::muted(ui, theme, format!("Assumption: {assumption}"));
    }
}

fn entity_entry(ui: &mut egui::Ui, theme: crate::state::ThemeChoice, entity: &EntityRef) {
    crate::theme::muted(
        ui,
        theme,
        format!(
            "{} · {} · role {}",
            entity.kind, entity.display_form, entity.role
        ),
    );
}

fn assumption_lines(json: &str) -> Vec<String> {
    let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(json) else {
        return vec![escape_for_display(json, 512).0];
    };
    items
        .iter()
        .map(|item| {
            let mut line = item
                .get("description")
                .and_then(|value| value.as_str())
                .unwrap_or("recorded assumption")
                .to_string();
            if let Some(zone) = item.get("zone").and_then(|value| value.as_str()) {
                line.push_str(&format!(" (zone {zone})"));
            }
            if let Some(year) = item.get("year_assumed").and_then(|value| value.as_i64()) {
                line.push_str(&format!(" (year {year} assumed)"));
            }
            escape_for_display(&line, 512).0
        })
        .collect()
}

//! Findings screen: explanations, dispositions, and annotation history
//! (plan P5.2/P6.3).
//!
//! A finding is a rule result with recorded predicates and named alternatives.
//! The screen never shows a score or a probability: severity is a coarse,
//! documented band, and the analyst's disposition is recorded as append-only
//! history rather than written over a finding row.

use eframe::egui;
use ghosttrace_core::domain::finding::{Disposition, Finding};
use ghosttrace_core::text::escape_for_display;

use crate::state::{AppState, ThemeChoice, labeled_text};

pub fn ui(state: &mut AppState, ui: &mut egui::Ui) {
    let theme = state.theme;
    crate::theme::title(ui, theme, "Findings");
    crate::theme::muted(
        ui,
        theme,
        "Rule results are hypotheses with recorded predicates and named alternatives. They are \
         not a probability and not a verdict.",
    );

    if state.findings.revision.is_none() {
        crate::theme::muted(
            ui,
            theme,
            "This case has no parse run yet. Import a captured object first.",
        );
        return;
    }

    ui.horizontal_wrapped(|ui| {
        if crate::theme::primary(ui, theme, "Run analysis").clicked() {
            state.run_analysis();
        }
        crate::theme::muted(ui, theme, state.findings.status.clone());
    });

    egui::Panel::right("ghosttrace-findings-detail")
        .resizable(true)
        .default_size(440.0)
        .frame(crate::theme::side_frame(ui.style(), theme))
        .show(ui, |ui| detail(state, ui));

    list(state, ui);
    handle_keys(state, ui);
    crate::theme::muted(ui, theme, "Keys: J/K next/previous finding");
}

fn list(state: &mut AppState, ui: &mut egui::Ui) {
    let theme = state.theme;
    let findings = state.findings.findings.clone();
    let selected = state.findings.selected.clone();
    let mut clicked = None;
    if findings.is_empty() {
        crate::theme::muted(
            ui,
            theme,
            "No findings recorded by the current analysis run.",
        );
        return;
    }
    crate::theme::section(ui, theme, "Findings");
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show_rows(ui, 24.0, findings.len(), |ui, range| {
            for index in range.clone() {
                let finding = &findings[index];
                let (rationale, _) = escape_for_display(&finding.rationale, 120);
                let label = format!(
                    "{} · {} · {} · {}",
                    finding.severity.as_str(),
                    finding.rule_id,
                    finding.disposition.as_str(),
                    rationale
                );
                if ui
                    .selectable_label(selected.as_deref() == Some(finding.id.as_str()), label)
                    .clicked()
                {
                    clicked = Some(finding.id.clone());
                }
            }
        });
    if let Some(id) = clicked {
        state.select_finding(&id);
    }
}

fn detail(state: &mut AppState, ui: &mut egui::Ui) {
    let theme = state.theme;
    crate::theme::title(ui, theme, "Finding detail");
    let Some(finding) = state.findings.selected_finding().cloned() else {
        crate::theme::muted(ui, theme, "Select a finding to see why it was recorded.");
        return;
    };
    let clicked_event = explanation(ui, theme, &finding);

    crate::theme::section(ui, theme, "Disposition");
    crate::theme::muted(
        ui,
        theme,
        "Each change appends a revision that names the one it supersedes. A concurrent edit is \
         reported as a conflict instead of overwriting it.",
    );
    let mut disposition = state.findings.disposition;
    ui.horizontal_wrapped(|ui| {
        for option in [
            Disposition::Undismissed,
            Disposition::Confirmed,
            Disposition::Dismissed,
            Disposition::Commented,
        ] {
            ui.radio_value(&mut disposition, option, option.as_str());
        }
    });
    state.findings.disposition = disposition;
    labeled_text(ui, "Author label", &mut state.findings.author);
    let note_label = ui.label("Disposition note");
    ui.add(
        egui::TextEdit::multiline(&mut state.findings.note)
            .desired_rows(3)
            .desired_width(f32::INFINITY),
    )
    .labelled_by(note_label.id);
    labeled_text(ui, "Disposition tags", &mut state.findings.tags);
    if crate::theme::quiet(ui, theme, "Record disposition").clicked() {
        state.record_finding_annotation();
    }

    if let Some(event_id) = clicked_event {
        state.open_event(&event_id);
    }

    crate::theme::section(ui, theme, "Recorded history");
    if state.findings.history.is_empty() {
        crate::theme::muted(
            ui,
            theme,
            "No note or disposition has been recorded for this finding yet.",
        );
    }
    for revision in &state.findings.history {
        let (text, _) = escape_for_display(&revision.text, 2_048);
        let disposition = revision
            .disposition
            .map(|disposition| disposition.as_str())
            .unwrap_or("no disposition change");
        crate::theme::muted(
            ui,
            theme,
            format!(
                "{} · {} · {disposition} · {} · tags: {}",
                crate::timeline::format_instant(
                    revision.created_seconds,
                    &state.timeline.display_timezone
                ),
                revision.author_label,
                if text.is_empty() {
                    "no text".into()
                } else {
                    text
                },
                if revision.tags.is_empty() {
                    "none".into()
                } else {
                    revision.tags.join(", ")
                }
            ),
        );
    }
}

fn explanation(ui: &mut egui::Ui, theme: ThemeChoice, finding: &Finding) -> Option<String> {
    crate::theme::muted(
        ui,
        theme,
        format!(
            "Rule {} · version {} · severity {}",
            finding.rule_id,
            finding.rule_version,
            finding.severity.as_str()
        ),
    );
    let (rationale, _) = escape_for_display(&finding.rationale, 4_096);
    crate::theme::muted(ui, theme, format!("Why: {rationale}"));
    if finding.alternatives.is_empty() {
        crate::theme::muted(ui, theme, "Alternatives: none recorded.");
    } else {
        for alternative in &finding.alternatives {
            let (alternative, _) = escape_for_display(alternative, 1_024);
            crate::theme::muted(ui, theme, format!("Alternative: {alternative}"));
        }
    }
    let predicates = serde_json::to_string_pretty(&finding.predicates)
        .unwrap_or_else(|_| "unreadable predicate value".into());
    let (predicates, truncated) = escape_for_display(&predicates, 4_096);
    let mut buffer = predicates;
    ui.add(
        egui::TextEdit::multiline(&mut buffer)
            .code_editor()
            .interactive(false)
            .desired_rows(6)
            .desired_width(f32::INFINITY),
    );
    if truncated {
        crate::theme::muted(ui, theme, "Predicate preview truncated.");
    }
    crate::theme::muted(
        ui,
        theme,
        format!(
            "{} recorded event(s) support this finding.",
            finding.event_ids.len()
        ),
    );
    let mut clicked = None;
    egui::ScrollArea::vertical()
        .max_height(160.0)
        .show(ui, |ui| {
            for event_id in &finding.event_ids {
                if crate::theme::quiet(ui, theme, &format!("Open event {}", short(event_id)))
                    .clicked()
                {
                    clicked = Some(event_id.clone());
                }
            }
        });
    clicked
}

fn handle_keys(state: &mut AppState, ui: &egui::Ui) {
    if ui.ctx().egui_wants_keyboard_input() {
        return;
    }
    if ui.input(|input| input.key_pressed(egui::Key::J)) {
        state.move_finding_selection(1);
    }
    if ui.input(|input| input.key_pressed(egui::Key::K)) {
        state.move_finding_selection(-1);
    }
}

fn short(text: &str) -> String {
    escape_for_display(text, 40).0
}

//! Snapshot comparison screen (plan P6.3).
//!
//! Two recorded captures are chosen explicitly. Scope mismatches, coverage
//! gaps, and undecidable rows stay visible: the screen never turns "cannot be
//! decided" into "appeared" or "deleted".

use eframe::egui;
use ghosttrace_core::analysis::diff::{DiffClass, DiffReport, DiffRow};
use ghosttrace_core::text::escape_for_display;

use crate::state::{AcquisitionSummary, AppState};

pub fn ui(state: &mut AppState, ui: &mut egui::Ui) {
    ui.heading("Compare captures");
    ui.label(
        "Compares two recorded captures of the same case. Equal bytes are never reported as a \
         copy or move action; scope and coverage limits are stated with the result.",
    );

    let acquisitions = state
        .open
        .as_ref()
        .map(|open| open.acquisitions.clone())
        .unwrap_or_default();
    if acquisitions.len() < 2 {
        ui.label(format!(
            "{} recorded capture(s). Two are required for a comparison.",
            acquisitions.len()
        ));
        return;
    }

    egui::Panel::right("ghosttrace-diff-detail")
        .resizable(true)
        .default_size(360.0)
        .show(ui, |ui| row_detail(state, ui));

    ui.horizontal_wrapped(|ui| {
        picker(ui, "Earlier capture", &mut state.diff.before, &acquisitions);
        picker(ui, "Later capture", &mut state.diff.after, &acquisitions);
        if ui.button("Compare").clicked() {
            state.open_diff();
        }
    });

    let Some(report) = state.diff.report.clone() else {
        ui.label(&state.diff.status);
        return;
    };

    summary(ui, &report);
    ui.separator();

    let selected = state.diff.selected.clone();
    let mut clicked = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show_rows(ui, 20.0, report.rows.len(), |ui, range| {
            for index in range.clone() {
                let row = &report.rows[index];
                let (path, truncated) = escape_for_display(&row.path, 240);
                let mut label = format!("{} · {path}", class_label(row.class));
                if truncated {
                    label.push_str("...");
                }
                if ui
                    .selectable_label(selected.as_deref() == Some(row.path.as_str()), label)
                    .clicked()
                {
                    clicked = Some(row.path.clone());
                }
            }
        });
    if let Some(path) = clicked {
        state.diff.selected = Some(path);
    }

    ui.horizontal(|ui| {
        ui.label(&state.diff.status);
        if report.next_cursor.is_some() && ui.button("Load more").clicked() {
            state.load_more_diff();
        }
    });
}

fn picker(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut Option<String>,
    acquisitions: &[AcquisitionSummary],
) {
    egui::ComboBox::from_label(label)
        .selected_text(
            value
                .as_deref()
                .map(short_id)
                .unwrap_or_else(|| "not chosen".into()),
        )
        .show_ui(ui, |ui| {
            for acquisition in acquisitions {
                ui.selectable_value(
                    value,
                    Some(acquisition.acquisition_id.clone()),
                    format!(
                        "{} · {}",
                        short_id(&acquisition.acquisition_id),
                        acquisition.state
                    ),
                );
            }
        });
}

fn short_id(id: &str) -> String {
    id.chars().take(18).collect()
}

fn summary(ui: &mut egui::Ui, report: &DiffReport) {
    let summary = &report.summary;
    if summary.scope_compatible {
        ui.label("Scope: both captures recorded the same roots.");
    } else {
        ui.label(
            "Scope mismatch: the two captures recorded different roots. Paths outside the \
             shared scope are reported as unknown, never as appeared or deleted.",
        );
    }
    ui.label(format!(
        "Roots before: {} · after: {}",
        joined(&summary.before_roots),
        joined(&summary.after_roots)
    ));
    for warning in &summary.warnings {
        let (warning, _) = escape_for_display(warning, 1_024);
        ui.label(format!("Warning: {warning}"));
    }
    ui.label(format!(
        "unchanged {} · metadata changed {} · content changed {} · content changed with equal \
         metadata {} · appeared {} · not present in captured scope {} · move candidates {} · \
         unknown {} · same-content relations {}",
        summary.unchanged,
        summary.metadata_changed,
        summary.content_changed,
        summary.content_changed_equal_metadata,
        summary.appeared,
        summary.not_present_in_captured_scope,
        summary.move_candidates,
        summary.unknown,
        summary.same_content_relations
    ));
}

fn joined(values: &[String]) -> String {
    if values.is_empty() {
        "none recorded".into()
    } else {
        values
            .iter()
            .map(|value| escape_for_display(value, 240).0)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn row_detail(state: &mut AppState, ui: &mut egui::Ui) {
    ui.heading("Row detail");
    let Some(report) = state.diff.report.clone() else {
        ui.label("Compare two captures to inspect a row.");
        return;
    };
    let Some(path) = state.diff.selected.clone() else {
        ui.label("Select a row to see its recorded values.");
        return;
    };
    let Some(row) = report.rows.iter().find(|row| row.path == path) else {
        ui.label("The selected row is not in the current page.");
        return;
    };
    body(ui, row, &state.timeline.display_timezone);
}

fn body(ui: &mut egui::Ui, row: &DiffRow, zone: &str) {
    let (path, _) = escape_for_display(&row.path, 4_096);
    ui.label(format!("Class: {}", class_label(row.class)));
    ui.label(format!("Path: {path}"));
    let (reason, _) = escape_for_display(&row.reason, 2_048);
    ui.label(format!("Reason: {reason}"));
    entry(ui, "Earlier", row.before.as_ref(), zone);
    entry(ui, "Later", row.after.as_ref(), zone);
}

fn entry(
    ui: &mut egui::Ui,
    label: &str,
    entry: Option<&ghosttrace_core::analysis::diff::SnapshotEntry>,
    zone: &str,
) {
    let Some(entry) = entry else {
        ui.label(format!("{label}: not present in the recorded scope"));
        return;
    };
    ui.label(format!(
        "{label}: {} bytes · sha256 {} · mtime {}",
        entry.byte_length,
        &entry.sha256[..entry.sha256.len().min(16)],
        entry
            .source_mtime_seconds
            .map(|seconds| crate::timeline::format_instant(seconds, zone))
            .unwrap_or_else(|| "not recorded".into())
    ));
}

/// Plain-language class names. `unknown` is its own class, never folded into
/// another one.
pub fn class_label(class: DiffClass) -> &'static str {
    match class {
        DiffClass::Unchanged => "unchanged",
        DiffClass::MetadataChanged => "metadata changed",
        DiffClass::ContentChangedEqualMetadata => "content changed (metadata equal)",
        DiffClass::ContentChanged => "content changed",
        DiffClass::Appeared => "appeared in the later capture",
        DiffClass::NotPresentInCapturedScope => "not present in the later captured scope",
        DiffClass::MoveCandidate => "move candidate (equal bytes only)",
        DiffClass::Unknown => "unknown (cannot be decided)",
    }
}

//! Report export and manifest verification (plan P6.4).
//!
//! Both actions are writes that publish files, so they run on the single job
//! worker and report through job outcomes. The screen states the scope before
//! the button: P6.4 exports an **unredacted** report; the redaction workflow
//! arrives with P9.2. Verification re-hashes stored objects and never touches
//! source evidence.

use eframe::egui;
use ghosttrace_core::text::escape_for_display;

use crate::state::{AcquisitionSummary, AppState, labeled_text};

pub fn ui(state: &mut AppState, ui: &mut egui::Ui) {
    ui.heading("Report and verification");
    ui.label(
        "The report describes the recorded case only: coverage, stored objects, provenance, \
         and a bounded timeline. This phase exports an unredacted report — recorded values are \
         included as stored. Redaction arrives with P9.2.",
    );

    let Some(open) = state.open.clone() else {
        ui.label("Open or create a case first.");
        return;
    };

    ui.separator();
    ui.label(format!(
        "Case: {} · display time zone: {} · case directory: {}",
        open.label,
        open.timezone,
        escape_for_display(&open.directory, 512).0
    ));
    if open.acquisitions.is_empty() {
        ui.label("Record a capture before exporting a report.");
        return;
    }

    ui.heading("Export");
    ui.horizontal_wrapped(|ui| {
        picker(
            ui,
            "Report acquisition",
            &mut state.report.acquisition,
            &open.acquisitions,
        );
        labeled_text(ui, "Report revision", &mut state.report.revision);
    });
    ui.label(
        "An empty revision means the newest parse run of the chosen acquisition, so a report \
         never mixes two revisions.",
    );
    ui.add(
        egui::Slider::new(&mut state.report.event_limit, 1..=10_000)
            .text("Timeline events in the report"),
    );
    labeled_text(ui, "Destination directory", &mut state.report.destination);
    labeled_text(ui, "Report id (optional)", &mut state.report.report_id);
    if ui.button("Export report").clicked() {
        state.export_report();
    }

    if let Some(report) = state.report.last.clone() {
        ui.separator();
        ui.heading("Last published report");
        ui.label(format!(
            "Report {} · {} object(s) · {} event(s) · {} coverage gap(s)",
            report.report_id, report.objects, report.events, report.gaps
        ));
        for (label, path) in [
            ("Directory", &report.directory),
            ("JSON", &report.json),
            ("HTML", &report.html),
        ] {
            ui.label(format!("{label}: {}", escape_for_display(path, 1_024).0));
        }
    }

    ui.separator();
    ui.heading("Verify stored bytes");
    ui.label(
        "Re-hashes every stored object referenced by one acquisition manifest and compares it \
         with the recorded digest. A mismatch fails the job; verification never modifies the \
         case or the source evidence.",
    );
    labeled_text(
        ui,
        "Manifest path (optional)",
        &mut state.report.manifest_path,
    );
    ui.label("When a manifest path is entered, the acquisition choice is ignored.");
    picker(
        ui,
        "Manifest acquisition",
        &mut state.report.verify_acquisition,
        &open.acquisitions,
    );
    if ui.button("Verify manifest").clicked() {
        state.verify_case();
    }

    if let Some(result) = state.report.verification.clone() {
        ui.label(format!(
            "Verified manifest {} for acquisition {} · format {} · {} object(s) · {} byte(s) · \
             captured {} · coverage gaps {}",
            result.manifest_id,
            result.acquisition_id,
            result.format,
            result.objects,
            result.total_bytes,
            result.captured,
            result.gaps
        ));
    }

    ui.horizontal(|ui| {
        if state.report.verifying {
            ui.spinner();
        }
        ui.label(&state.report.status);
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

//! Case screen: create, open, and review recovery notices (P6.1).

use eframe::egui;

use crate::commands::Command;
use crate::state::{AppState, labeled_text};

pub fn ui(state: &mut AppState, ui: &mut egui::Ui) {
    ui.heading("Case");

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.group(|ui| {
            ui.label("Create a case");
            labeled_text(ui, "Case directory", &mut state.case_form.directory);
            labeled_text(ui, "Case label", &mut state.case_form.label);
            labeled_text(ui, "Display time zone", &mut state.case_form.timezone);
            ui.label(
                "The directory must end with .ghosttrace-case and must not already exist. \
                 Cases are created private to the current user.",
            );
            let enabled = !state.is_running();
            ui.add_enabled_ui(enabled, |ui| {
                if ui.button("Create case").clicked() {
                    create(state);
                }
            });
        });

        ui.group(|ui| {
            ui.label("Open an existing case");
            labeled_text(
                ui,
                "Open case directory",
                &mut state.case_form.open_directory,
            );
            let enabled = !state.is_running();
            ui.add_enabled_ui(enabled, |ui| {
                if ui.button("Open case").clicked() {
                    let directory = state.case_form.open_directory.trim().to_string();
                    if directory.is_empty() {
                        state.notice_error("open case directory is required");
                    } else {
                        state.start(|id| Command::OpenCase { id, directory });
                    }
                }
            });
        });

        if let Some(open) = state.open.clone() {
            ui.separator();
            ui.group(|ui| {
                ui.heading(format!("Open case: {}", open.label));
                ui.label(format!("Case directory: {}", open.directory));
                ui.label(format!("Display time zone: {}", open.timezone));
                ui.label(format!(
                    "Recorded captures: {} (newest first)",
                    open.acquisitions.len()
                ));
                for acquisition in open.acquisitions.iter().take(10) {
                    ui.label(format!(
                        "capture {} · {}",
                        acquisition.acquisition_id, acquisition.state
                    ));
                }
            });

            if state.show_recovery && !open.recovery.is_empty() {
                ui.group(|ui| {
                    ui.heading("Recovery review");
                    ui.label(
                        "This case was closed while a job was still running. Nothing was \
                         completed automatically, and the interrupted state stays recorded.",
                    );
                    for job in &open.recovery {
                        ui.label(format!(
                            "interrupted {} job {}: last committed locator {}",
                            job.kind,
                            job.job_id,
                            job.committed_locator.as_deref().unwrap_or("none")
                        ));
                    }
                    ui.label(
                        "To continue this work, start a new capture or import; the earlier \
                         partial output remains visible in the case.",
                    );
                    if ui.button("Acknowledge recovery").clicked() {
                        state.show_recovery = false;
                        state.notice_info(
                            "recovery acknowledged; the interrupted job stays recorded as \
                             recoverable",
                        );
                    }
                });
            }
        }
    });
}

fn create(state: &mut AppState) {
    let directory = state.case_form.directory.trim().to_string();
    let label = state.case_form.label.trim().to_string();
    let timezone = state.case_form.timezone.trim().to_string();
    if directory.is_empty() {
        state.notice_error("case directory is required");
        return;
    }
    if !directory.ends_with(".ghosttrace-case") {
        state.notice_error("case directory must end with .ghosttrace-case");
        return;
    }
    if timezone.is_empty() {
        state.notice_error("display time zone is required (for example UTC)");
        return;
    }
    state.start(|id| Command::CreateCase {
        id,
        directory,
        label,
        timezone,
    });
}

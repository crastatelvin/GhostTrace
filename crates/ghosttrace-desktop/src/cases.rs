//! Case screen: create, open, and review recovery notices (P6.1).

use eframe::egui;

use crate::commands::Command;
use crate::state::{AppState, labeled_text};

pub fn ui(state: &mut AppState, ui: &mut egui::Ui) {
    let theme = state.theme;
    egui::ScrollArea::vertical().show(ui, |ui| {
        crate::theme::title(ui, theme, "Case");

        // A recovery review is the one thing a new opening must answer first,
        // so it sits above the create/open cards.
        if state.show_recovery
            && state
                .open
                .as_ref()
                .is_some_and(|open| !open.recovery.is_empty())
        {
            crate::theme::card(ui, theme, |ui| {
                crate::theme::section(ui, theme, "Recovery review");
                crate::theme::chip(ui, theme, "interrupted", crate::theme::Tone::Warn);
                crate::theme::muted(
                    ui,
                    theme,
                    "This case was closed while a job was still running. Nothing was \
                     completed automatically, and the interrupted state stays recorded.",
                );
                for job in state
                    .open
                    .as_ref()
                    .map(|open| open.recovery.clone())
                    .unwrap_or_default()
                {
                    crate::theme::muted(
                        ui,
                        theme,
                        format!(
                            "interrupted {} job {}: last committed locator {}",
                            job.kind,
                            job.job_id,
                            job.committed_locator.as_deref().unwrap_or("none")
                        ),
                    );
                }
                crate::theme::muted(
                    ui,
                    theme,
                    "To continue this work, start a new capture or import; the earlier \
                     partial output remains visible in the case.",
                );
                ui.add_space(4.0);
                if crate::theme::quiet(ui, theme, "Acknowledge recovery").clicked() {
                    state.show_recovery = false;
                    state.notice_info(
                        "recovery acknowledged; the interrupted job stays recorded as \
                         recoverable",
                    );
                }
            });
            ui.add_space(crate::theme::SECTION_GAP);
        }

        crate::theme::card(ui, theme, |ui| {
            crate::theme::section(ui, theme, "Create a case");
            labeled_text(ui, "Case directory", &mut state.case_form.directory);
            labeled_text(ui, "Case label", &mut state.case_form.label);
            labeled_text(ui, "Display time zone", &mut state.case_form.timezone);
            crate::theme::muted(
                ui,
                theme,
                "The directory must end with .ghosttrace-case and must not already exist. \
                 Cases are created private to the current user.",
            );
            ui.add_space(4.0);
            let enabled = !state.is_running();
            ui.add_enabled_ui(enabled, |ui| {
                if crate::theme::primary(ui, theme, "Create case").clicked() {
                    create(state);
                }
            });
        });

        ui.add_space(crate::theme::SECTION_GAP);

        crate::theme::card(ui, theme, |ui| {
            crate::theme::section(ui, theme, "Open an existing case");
            labeled_text(
                ui,
                "Open case directory",
                &mut state.case_form.open_directory,
            );
            ui.add_space(4.0);
            let enabled = !state.is_running();
            ui.add_enabled_ui(enabled, |ui| {
                if crate::theme::primary(ui, theme, "Open case").clicked() {
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
            ui.add_space(crate::theme::SECTION_GAP);
            crate::theme::card(ui, theme, |ui| {
                crate::theme::section(ui, theme, &format!("Open case: {}", open.label));
                ui.horizontal_wrapped(|ui| {
                    crate::theme::stat(ui, theme, "Display time zone", open.timezone.clone());
                    ui.add_space(24.0);
                    crate::theme::stat(
                        ui,
                        theme,
                        "Recorded captures",
                        open.acquisitions.len().to_string(),
                    );
                });
                crate::theme::muted(ui, theme, format!("Case directory: {}", open.directory));
                ui.add_space(6.0);
                for acquisition in &open.acquisitions {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!("capture {}", acquisition.acquisition_id))
                                .monospace()
                                .small()
                                .color(crate::theme::Palette::of(theme).text_muted),
                        );
                        crate::theme::chip(
                            ui,
                            theme,
                            &acquisition.state,
                            state_tone(&acquisition.state),
                        );
                    });
                }
            });
        }
    });
}

/// The acquisition state as a tone. The word stays the chip text: this only
/// picks its hint, never replaces it.
pub(crate) fn state_tone(state: &str) -> crate::theme::Tone {
    match state {
        "completed" => crate::theme::Tone::Ok,
        "partial" => crate::theme::Tone::Warn,
        "interrupted" | "failed" => crate::theme::Tone::Error,
        _ => crate::theme::Tone::Neutral,
    }
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

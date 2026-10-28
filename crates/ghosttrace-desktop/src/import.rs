//! Import screen: capture a source, review method/time assumptions, and import
//! one captured object (P6.1).

use eframe::egui;
use ghosttrace_core::domain::case::AcquisitionMethod;

use crate::commands::Command;
use crate::state::{
    AppState, DEFAULT_MAX_DEPTH, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_FILE_BYTES, FormatChoice,
    labeled_text,
};

pub fn ui(state: &mut AppState, ui: &mut egui::Ui) {
    let Some(open) = state.open.clone() else {
        ui.label("Open or create a case to capture or import evidence.");
        return;
    };

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.heading("Evidence");
        ui.label(format!("Case: {} · {}", open.label, open.directory));

        ui.group(|ui| {
            ui.label("Capture a source directory");
            labeled_text(ui, "Source directory", &mut state.import_form.source);
            labeled_text(ui, "Acquisition label", &mut state.import_form.label);
            ui.label("Method");
            ui.radio_value(
                &mut state.import_form.method,
                AcquisitionMethod::ProtectedCopy,
                "Protected copy",
            );
            ui.radio_value(
                &mut state.import_form.method,
                AcquisitionMethod::LiveBestEffort,
                "Live best effort",
            );
            match state.import_form.method {
                AcquisitionMethod::ProtectedCopy => ui.label(
                    "Protected copy is recommended: verify the copy was made by a write-blocked \
                     or equivalent process before relying on it in production.",
                ),
                AcquisitionMethod::LiveBestEffort => ui.label(
                    "Live best effort can miss changes or files that vanish mid-copy; coverage \
                     records what was seen, and access-time metadata may be affected.",
                ),
            };
            ui.label(format!(
                "Limits: depth {DEFAULT_MAX_DEPTH}, {DEFAULT_MAX_ENTRIES} entries, {} MiB per file. \
                 Roots overlapping the case store are rejected before anything is read.",
                DEFAULT_MAX_FILE_BYTES / (1024 * 1024)
            ));
            let source = state.import_form.source.trim();
            ui.label(format!(
                "Summary: capture {} as {} ({}).",
                if source.is_empty() { "<source>" } else { source },
                if state.import_form.label.trim().is_empty() {
                    "<source path>"
                } else {
                    state.import_form.label.trim()
                },
                method_label(state.import_form.method),
            ));
            let enabled = !state.is_running();
            ui.add_enabled_ui(enabled, |ui| {
                if ui.button("Start capture").clicked() {
                    start_capture(state);
                }
            });
        });

        ui.group(|ui| {
            ui.label("Import a captured object");
            labeled_text(
                ui,
                "Captured object path",
                &mut state.import_form.object_path,
            );
            ui.label("Format");
            ui.horizontal_wrapped(|ui| {
                for choice in FormatChoice::ALL {
                    ui.radio_value(
                        &mut state.import_form.format,
                        choice,
                        choice.label(),
                    );
                }
            });
            labeled_text(
                ui,
                "Syslog time zone",
                &mut state.import_form.syslog_timezone,
            );
            labeled_text(ui, "Syslog year", &mut state.import_form.syslog_year);
            ui.label(
                "Time zone and year apply only to RFC 3164 syslog. Neither is inferred from the \
                 file: leave them empty to keep those times unresolved.",
            );
            let enabled = !state.is_running();
            ui.add_enabled_ui(enabled, |ui| {
                if ui.button("Start import").clicked() {
                    start_import(state);
                }
            });
        });

        ui.separator();
        ui.label("Recorded captures");
        if open.acquisitions.is_empty() {
            ui.label("none yet");
        }
        for acquisition in open.acquisitions.iter().take(20) {
            ui.label(format!(
                "capture {} · {}",
                acquisition.acquisition_id, acquisition.state
            ));
        }
    });
}

fn method_label(method: AcquisitionMethod) -> &'static str {
    match method {
        AcquisitionMethod::ProtectedCopy => "protected copy",
        AcquisitionMethod::LiveBestEffort => "live best effort",
    }
}

fn start_capture(state: &mut AppState) {
    let Some(open) = state.open.clone() else {
        state.notice_error("open or create a case before capturing evidence");
        return;
    };
    let source = state.import_form.source.trim().to_string();
    if source.is_empty() {
        state.notice_error("source directory is required");
        return;
    }
    let label = state.import_form.label.trim().to_string();
    let method = state.import_form.method;
    state.start(|id| Command::Capture {
        id,
        case_directory: open.directory,
        source,
        label,
        method,
        max_depth: DEFAULT_MAX_DEPTH,
        max_entries: DEFAULT_MAX_ENTRIES,
        max_file_bytes: DEFAULT_MAX_FILE_BYTES,
    });
}

fn start_import(state: &mut AppState) {
    let Some(open) = state.open.clone() else {
        state.notice_error("open or create a case before importing evidence");
        return;
    };
    let object_path = state.import_form.object_path.trim().to_string();
    if object_path.is_empty() {
        state.notice_error("captured object path is required");
        return;
    }
    let year = match state.import_form.syslog_year.trim() {
        "" => None,
        text => match text.parse::<i32>() {
            Ok(year) => Some(year),
            Err(_) => {
                state.notice_error("syslog year must be an integer year, or empty");
                return;
            }
        },
    };
    let timezone = match state.import_form.syslog_timezone.trim() {
        "" => None,
        zone => Some(zone.to_string()),
    };
    let format = state.import_form.format.format();
    state.start(|id| Command::Import {
        id,
        case_directory: open.directory,
        object_path,
        format,
        syslog_timezone: timezone,
        syslog_year: year,
    });
}

//! Report export and manifest verification (plan P6.4).
//!
//! Both actions are writes that publish files, so they run on the single job
//! worker and report through job outcomes. The screen states the scope before
//! the button: P9.2 adds an explicit redaction selection whose projection is
//! applied to the exported copy only. Verification re-hashes stored objects
//! and never touches source evidence.

use eframe::egui;
use ghosttrace_core::text::escape_for_display;

use crate::state::{AcquisitionSummary, AppState, labeled_text};

pub fn ui(state: &mut AppState, ui: &mut egui::Ui) {
    let theme = state.theme;
    crate::theme::title(ui, theme, "Report and verification");
    crate::theme::muted(
        ui,
        theme,
        "The report describes the recorded case only: coverage, stored objects, provenance, \
         and a bounded timeline. Without redaction the export is unredacted and contains \
         recorded values as stored. Redaction replaces selected values with [redacted] in the \
         published copy; the case itself is never changed.",
    );

    let Some(open) = state.open.clone() else {
        crate::theme::muted(ui, theme, "Open or create a case first.");
        return;
    };

    ui.separator();
    crate::theme::muted(
        ui,
        theme,
        format!(
            "Case: {} · display time zone: {} · case directory: {}",
            open.label,
            open.timezone,
            escape_for_display(&open.directory, 512).0
        ),
    );
    if open.acquisitions.is_empty() {
        crate::theme::muted(ui, theme, "Record a capture before exporting a report.");
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
    crate::theme::muted(
        ui,
        theme,
        "An empty revision means the newest parse run of the chosen acquisition, so a report \
         never mixes two revisions.",
    );
    ui.add(
        egui::Slider::new(&mut state.report.event_limit, 1..=10_000)
            .text("Timeline events in the report"),
    );
    labeled_text(ui, "Destination directory", &mut state.report.destination);
    labeled_text(ui, "Report id (optional)", &mut state.report.report_id);

    crate::theme::section(ui, theme, "Redaction (applies to the export)");
    crate::theme::muted(
        ui,
        theme,
        "Each selected category is replaced with [redacted]. The published ledger lists field \
         names and counts only, never the removed text. A report is always exported with a \
         spreadsheet-safe report.csv.",
    );
    ui.checkbox(&mut state.report.redact_case_label, "Case label");
    ui.checkbox(
        &mut state.report.redact_source_paths,
        "Source paths (claimed source, roots, coverage gaps)",
    );
    ui.checkbox(
        &mut state.report.redact_object_paths,
        "Stored object paths (digests and lengths stay)",
    );
    ui.checkbox(
        &mut state.report.redact_timeline_summaries,
        "Timeline summaries",
    );
    ui.checkbox(
        &mut state.report.redact_timeline_hosts,
        "Timeline host claims",
    );
    crate::theme::muted(
        ui,
        theme,
        format!(
            "Selection: {}",
            if state.report.redaction().any() {
                state.report.redaction().selected().join(", ")
            } else {
                "none (unredacted export)".to_string()
            }
        ),
    );
    if crate::theme::primary(ui, theme, "Export report").clicked() {
        state.export_report();
    }

    if let Some(report) = state.report.last.clone() {
        ui.add_space(crate::theme::SECTION_GAP);
        crate::theme::card(ui, theme, |ui| {
            crate::theme::section(ui, theme, "Last published report");
            ui.horizontal_wrapped(|ui| {
                crate::theme::stat(ui, theme, "objects", report.objects.to_string());
                crate::theme::stat(ui, theme, "events", report.events.to_string());
                crate::theme::stat(ui, theme, "coverage gaps", report.gaps.to_string());
            });
            crate::theme::muted(
                ui,
                theme,
                format!(
                    "Report {} · {} object(s) · {} event(s) · {} coverage gap(s)",
                    report.report_id, report.objects, report.events, report.gaps
                ),
            );
            if report.redacted {
                crate::theme::chip(ui, theme, "redacted", crate::theme::Tone::Warn);
                crate::theme::muted(
                    ui,
                    theme,
                    "This export is redacted; see redaction.json in the report directory.",
                );
            }
            for (label, path) in [
                ("Directory", &report.directory),
                ("JSON", &report.json),
                ("HTML", &report.html),
            ] {
                crate::theme::muted(
                    ui,
                    theme,
                    format!("{label}: {}", escape_for_display(path, 1_024).0),
                );
            }
            if let Some(csv) = &report.csv {
                crate::theme::muted(
                    ui,
                    theme,
                    format!("CSV: {}", escape_for_display(csv, 1_024).0),
                );
            }
        });
    }

    ui.add_space(crate::theme::SECTION_GAP);
    crate::theme::card(ui, theme, |ui| {
        crate::theme::section(ui, theme, "Verify stored bytes");
        crate::theme::muted(
            ui,
            theme,
            "Re-hashes every stored object referenced by one acquisition manifest and compares \
             it with the recorded digest. A mismatch fails the job; verification never modifies \
             the case or the source evidence.",
        );
        labeled_text(
            ui,
            "Manifest path (optional)",
            &mut state.report.manifest_path,
        );
        crate::theme::muted(
            ui,
            theme,
            "When a manifest path is entered, the acquisition choice is ignored.",
        );
        picker(
            ui,
            "Manifest acquisition",
            &mut state.report.verify_acquisition,
            &open.acquisitions,
        );
        labeled_text(
            ui,
            "Signature sidecar (optional)",
            &mut state.report.signature_path,
        );
        crate::theme::muted(
            ui,
            theme,
            "Default: <manifest>.sig.json when that file exists.",
        );
        labeled_text(
            ui,
            "Trusted-key list (optional)",
            &mut state.report.trust_path,
        );
        crate::theme::muted(
            ui,
            theme,
            "One 64-character key fingerprint per line. A valid signature from a key that is not \
             in this list is reported as mathematically valid but untrusted; that is different \
             from a signature that does not cover these bytes.",
        );
        if crate::theme::primary(ui, theme, "Verify manifest").clicked() {
            state.verify_case();
        }

        if let Some(result) = state.report.verification.clone() {
            crate::theme::section(ui, theme, "Verification result");
            ui.horizontal_wrapped(|ui| {
                crate::theme::stat(ui, theme, "manifest", result.manifest_id.clone());
                crate::theme::stat(ui, theme, "acquisition", result.acquisition_id.clone());
                crate::theme::stat(ui, theme, "objects", result.objects.to_string());
                crate::theme::stat(ui, theme, "bytes", result.total_bytes.to_string());
            });
            crate::theme::muted(
                ui,
                theme,
                format!(
                    "Verified manifest {} for acquisition {} · format {} · {} object(s) · \
                     {} byte(s) · captured {} · coverage gaps {}",
                    result.manifest_id,
                    result.acquisition_id,
                    result.format,
                    result.objects,
                    result.total_bytes,
                    result.captured,
                    result.gaps
                ),
            );
            crate::theme::chip(
                ui,
                theme,
                result.signature.clone(),
                trust_tone(&result.key_trust),
            );
            crate::theme::muted(
                ui,
                theme,
                format!(
                    "Signature: {} · key trust: {}{}",
                    result.signature,
                    result.key_trust,
                    result
                        .key_fingerprint
                        .as_deref()
                        .map(|fingerprint| format!(" · key {fingerprint}"))
                        .unwrap_or_default()
                ),
            );
            if let Some(detail) = result.signature_detail.as_deref() {
                crate::theme::muted(ui, theme, format!("Signature detail: {detail}"));
            }
            if let Some(complete) = result.capture_complete {
                crate::theme::muted(
                    ui,
                    theme,
                    if complete {
                        "Capture completeness: no coverage gaps recorded for the declared scope."
                    } else {
                        "Capture completeness: coverage gaps recorded; complete only for the \
                         captured scope."
                    },
                );
            }
            crate::theme::muted(ui, theme, result.explanation.clone());
        }

        ui.horizontal(|ui| {
            if state.report.verifying {
                ui.spinner();
            }
            crate::theme::muted(ui, theme, state.report.status.clone());
        });
    });

    ui.add_space(crate::theme::SECTION_GAP);
    crate::theme::card(ui, theme, |ui| {
        crate::theme::section(ui, theme, "Sign manifest");
        crate::theme::muted(
            ui,
            theme,
            "Signs the exact stored manifest bytes with an encrypted Ed25519 key. If the key \
             file does not exist yet it is generated (mode 0600, never overwritten). The \
             passphrase is read from this field, moved into the job, and cleared; it is never \
             stored in the case or a report. An existing signature sidecar is never replaced.",
        );
        labeled_text(ui, "Key file", &mut state.report.sign_key_path);
        ui.horizontal(|ui| {
            ui.label("Passphrase");
            ui.add(
                egui::TextEdit::singleline(&mut state.report.sign_passphrase)
                    .password(true)
                    .hint_text("at least 8 characters"),
            );
        });
        if crate::theme::quiet(ui, theme, "Sign manifest").clicked() {
            state.sign_case();
        }
        ui.horizontal(|ui| {
            if state.report.signing {
                ui.spinner();
            }
            crate::theme::muted(ui, theme, state.report.sign_status.clone());
        });
    });

    ui.add_space(crate::theme::SECTION_GAP);
    crate::theme::card(ui, theme, |ui| {
        crate::theme::section(ui, theme, "Portable backup and restore");
        crate::theme::muted(
            ui,
            theme,
            "A backup is a consistent SQLite snapshot plus every referenced immutable object, \
             the config, and the manifests, with a SHA-256 inventory over all of it. Signing \
             keys and trusted-key lists are excluded on purpose. Restore verifies every digest, \
             the database integrity, the schema version, and every object reference before \
             publishing a new case directory; the destination must not exist.",
        );
        labeled_text(
            ui,
            "Backup destination directory",
            &mut state.report.backup_output,
        );
        if crate::theme::quiet(ui, theme, "Back up this case").clicked() {
            state.backup_case();
        }
        ui.horizontal(|ui| {
            if state.report.backing_up {
                ui.spinner();
            }
            crate::theme::muted(ui, theme, state.report.backup_status.clone());
        });
        labeled_text(
            ui,
            "Backup directory to restore",
            &mut state.report.restore_backup,
        );
        labeled_text(
            ui,
            "Restore destination (must not exist)",
            &mut state.report.restore_destination,
        );
        if crate::theme::quiet(ui, theme, "Restore backup").clicked() {
            state.restore_case();
        }
        ui.horizontal(|ui| {
            if state.report.restoring {
                ui.spinner();
            }
            crate::theme::muted(ui, theme, state.report.restore_status.clone());
        });
    });
}

/// Key trust as a tone. The words stay the chip text; this only picks the
/// hint, never replaces it.
fn trust_tone(trust: &str) -> crate::theme::Tone {
    match trust {
        "trusted" => crate::theme::Tone::Ok,
        "untrusted" => crate::theme::Tone::Warn,
        _ => crate::theme::Tone::Neutral,
    }
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

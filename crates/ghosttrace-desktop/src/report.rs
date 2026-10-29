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
    ui.heading("Report and verification");
    ui.label(
        "The report describes the recorded case only: coverage, stored objects, provenance, \
         and a bounded timeline. Without redaction the export is unredacted and contains \
         recorded values as stored. Redaction replaces selected values with [redacted] in the \
         published copy; the case itself is never changed.",
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

    ui.separator();
    ui.heading("Redaction (applies to the export)");
    ui.label(
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
    ui.label(format!(
        "Selection: {}",
        if state.report.redaction().any() {
            state.report.redaction().selected().join(", ")
        } else {
            "none (unredacted export)".to_string()
        }
    ));
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
        if let Some(csv) = &report.csv {
            ui.label(format!("CSV: {}", escape_for_display(csv, 1_024).0));
        }
        if report.redacted {
            ui.label("This export is redacted; see redaction.json in the report directory.");
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
    labeled_text(
        ui,
        "Signature sidecar (optional)",
        &mut state.report.signature_path,
    );
    ui.label("Default: <manifest>.sig.json when that file exists.");
    labeled_text(
        ui,
        "Trusted-key list (optional)",
        &mut state.report.trust_path,
    );
    ui.label(
        "One 64-character key fingerprint per line. A valid signature from a key that is not in \
         this list is reported as mathematically valid but untrusted; that is different from a \
         signature that does not cover these bytes.",
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
        ui.label(format!(
            "Signature: {} · key trust: {}{}",
            result.signature,
            result.key_trust,
            result
                .key_fingerprint
                .as_deref()
                .map(|fingerprint| format!(" · key {fingerprint}"))
                .unwrap_or_default()
        ));
        if let Some(detail) = result.signature_detail.as_deref() {
            ui.label(format!("Signature detail: {detail}"));
        }
        if let Some(complete) = result.capture_complete {
            ui.label(if complete {
                "Capture completeness: no coverage gaps recorded for the declared scope."
            } else {
                "Capture completeness: coverage gaps recorded; complete only for the captured scope."
            });
        }
        ui.label(&result.explanation);
    }

    ui.horizontal(|ui| {
        if state.report.verifying {
            ui.spinner();
        }
        ui.label(&state.report.status);
    });

    ui.separator();
    ui.heading("Sign manifest");
    ui.label(
        "Signs the exact stored manifest bytes with an encrypted Ed25519 key. If the key file \
         does not exist yet it is generated (mode 0600, never overwritten). The passphrase is \
         read from this field, moved into the job, and cleared; it is never stored in the case \
         or a report. An existing signature sidecar is never replaced.",
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
    if ui.button("Sign manifest").clicked() {
        state.sign_case();
    }
    ui.horizontal(|ui| {
        if state.report.signing {
            ui.spinner();
        }
        ui.label(&state.report.sign_status);
    });

    ui.separator();
    ui.heading("Portable backup and restore");
    ui.label(
        "A backup is a consistent SQLite snapshot plus every referenced immutable object, the \
         config, and the manifests, with a SHA-256 inventory over all of it. Signing keys and \
         trusted-key lists are excluded on purpose. Restore verifies every digest, the database \
         integrity, the schema version, and every object reference before publishing a new case \
         directory; the destination must not exist.",
    );
    labeled_text(
        ui,
        "Backup destination directory",
        &mut state.report.backup_output,
    );
    if ui.button("Back up this case").clicked() {
        state.backup_case();
    }
    ui.horizontal(|ui| {
        if state.report.backing_up {
            ui.spinner();
        }
        ui.label(&state.report.backup_status);
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
    if ui.button("Restore backup").clicked() {
        state.restore_case();
    }
    ui.horizontal(|ui| {
        if state.report.restoring {
            ui.spinner();
        }
        ui.label(&state.report.restore_status);
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

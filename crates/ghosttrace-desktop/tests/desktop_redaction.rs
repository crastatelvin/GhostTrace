//! P9.2 desktop contract: the redaction selection is explicit before export,
//! the published summary names the ledger without values, and backup/restore
//! run as jobs on the same worker.

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use ghosttrace_desktop::commands::{Command, CommandEvent, Outcome};
use ghosttrace_desktop::state::{AcquisitionSummary, AppState, OpenCaseView, Screen};

fn open_case(state: &mut AppState) {
    let acquisitions = vec![AcquisitionSummary {
        acquisition_id: "acq-1".into(),
        state: "completed".into(),
    }];
    state.open = Some(OpenCaseView {
        directory: "/tmp/demo.ghosttrace-case".into(),
        label: "Demo".into(),
        timezone: "UTC".into(),
        acquisitions: acquisitions.clone(),
        recovery: Vec::new(),
    });
    state.report.reset(&acquisitions, Some("run-1".into()));
    state.screen = Screen::Report;
}

#[test]
fn the_redaction_selection_reaches_the_export_job() {
    let mut state = AppState::new();
    open_case(&mut state);
    state.report.destination = "/tmp/opencode/reports".into();
    state.report.redact_timeline_summaries = true;
    state.report.redact_source_paths = true;

    state.export_report();
    let commands = state.take_commands();
    match &commands[0] {
        Command::Report { redaction, .. } => {
            assert!(redaction.timeline_summaries);
            assert!(redaction.source_paths);
            assert!(!redaction.case_label);
            assert_eq!(
                redaction.selected(),
                vec!["source-paths", "timeline-summaries"]
            );
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn a_redacted_publication_is_summarized_without_removed_values() {
    let mut state = AppState::new();
    open_case(&mut state);
    state.report.destination = "/tmp/opencode/reports".into();
    state.report.redact_timeline_summaries = true;
    state.export_report();
    let id = state.take_commands()[0].id();

    state.apply(CommandEvent::Finished {
        id,
        outcome: Outcome::ReportPublished {
            report_id: "report-acq-1-1".into(),
            directory: "/tmp/opencode/reports/report-acq-1-1".into(),
            json: "/tmp/opencode/reports/report-acq-1-1/report.json".into(),
            html: "/tmp/opencode/reports/report-acq-1-1/report.html".into(),
            objects: 1,
            events: 2,
            gaps: 0,
            csv: "/tmp/opencode/reports/report-acq-1-1/report.csv".into(),
            redacted: true,
            redaction: Some("2 timeline.summary value(s)".into()),
        },
    });
    let published = state.report.last.clone().expect("summary");
    assert!(published.redacted);
    assert_eq!(
        published.csv.as_deref(),
        Some("/tmp/opencode/reports/report-acq-1-1/report.csv")
    );
    assert!(
        state
            .report
            .status
            .contains("ledger lists fields and counts only")
    );
}

#[test]
fn the_screen_states_the_selection_before_the_button() {
    let mut state = AppState::new();
    open_case(&mut state);
    state.report.redact_case_label = true;
    state.report.redact_object_paths = true;

    let mut harness = Harness::new_ui_state(|ui, state| state.ui(ui), state);
    harness.run_steps(2);
    for text in [
        "Redaction (applies to the export)",
        "Case label",
        "Timeline summaries",
        "Selection: case-label, object-paths",
    ] {
        assert!(
            harness.query_all_by_label_contains(text).next().is_some(),
            "the report screen never states {text:?}"
        );
    }
}

#[test]
fn backup_and_restore_are_jobs_and_restore_opens_the_new_case() {
    let mut state = AppState::new();
    open_case(&mut state);
    state.report.backup_output = "/tmp/opencode/backups".into();
    state.backup_case();
    let commands = state.take_commands();
    match &commands[0] {
        Command::Backup { output, .. } => assert_eq!(output, "/tmp/opencode/backups"),
        other => panic!("unexpected command: {other:?}"),
    }
    let id = commands[0].id();
    state.apply(CommandEvent::Finished {
        id,
        outcome: Outcome::BackedUp {
            directory: "/tmp/opencode/backups/backup-1".into(),
            case_id: "case-1".into(),
            files: 4,
            total_bytes: 1_024,
        },
    });
    assert!(state.report.backup_status.contains("backed up case case-1"));

    state.report.restore_backup = "/tmp/opencode/backups/backup-1".into();
    state.report.restore_destination = "/tmp/opencode/restored.ghosttrace-case".into();
    state.restore_case();
    let commands = state.take_commands();
    match &commands[0] {
        Command::Restore {
            backup,
            destination,
            ..
        } => {
            assert_eq!(backup, "/tmp/opencode/backups/backup-1");
            assert_eq!(destination, "/tmp/opencode/restored.ghosttrace-case");
        }
        other => panic!("unexpected command: {other:?}"),
    }
    let id = commands[0].id();
    state.apply(CommandEvent::Finished {
        id,
        outcome: Outcome::Restored {
            directory: "/tmp/opencode/restored.ghosttrace-case".into(),
            case_id: "case-1".into(),
            objects: 3,
            manifests: 1,
        },
    });
    let commands = state.take_commands();
    match &commands[0] {
        Command::OpenCase { directory, .. } => {
            assert_eq!(directory, "/tmp/opencode/restored.ghosttrace-case");
        }
        other => panic!("restore did not open the new case: {other:?}"),
    }
}

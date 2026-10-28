//! P6.4 report contract: the export selection is stated with its revision and
//! time zone, the unredacted scope is visible before the button, destinations
//! are validated, a failed publication stays visible, and a cancelled report
//! publishes nothing.

use std::time::{Duration, Instant};

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use ghosttrace_desktop::commands::{Command, CommandBus, CommandEvent, JobPhase, Outcome};
use ghosttrace_desktop::state::{
    AcquisitionSummary, AppState, OpenCaseView, ReportSummary, Screen, VerifySummary,
};

fn acquisition() -> AcquisitionSummary {
    AcquisitionSummary {
        acquisition_id: "acq-1".into(),
        state: "completed".into(),
    }
}

fn open_case(state: &mut AppState) {
    let acquisitions = vec![acquisition()];
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
fn the_export_scope_is_stated_before_the_button() {
    let mut state = AppState::new();
    open_case(&mut state);
    state.report.destination = "/tmp/opencode/reports".into();

    let mut harness = Harness::new_ui_state(|ui, state| state.ui(ui), state);
    harness.run_steps(2);

    for text in [
        "display time zone: UTC",
        "unredacted",
        "Export report",
        "Verify manifest",
        "Report revision",
        "Destination directory",
    ] {
        assert!(
            harness.query_all_by_label_contains(text).next().is_some(),
            "the report screen never states {text:?}"
        );
    }
}

#[test]
fn a_destination_must_be_absolute_and_outside_the_case() {
    let mut state = AppState::new();
    open_case(&mut state);

    for (destination, expected) in [
        ("", "destination directory is required"),
        ("relative/reports", "absolute path"),
        (
            "/tmp/demo.ghosttrace-case/reports",
            "outside the case directory",
        ),
    ] {
        state.report.destination = destination.into();
        state.export_report();
        assert!(
            state.take_commands().is_empty(),
            "{destination:?} must not start a job"
        );
        assert!(
            state
                .notices
                .iter()
                .any(|notice| notice.text.contains(expected)),
            "{destination:?} did not explain {expected:?}: {:?}",
            state.notices
        );
    }

    state.report.destination = "/tmp/opencode/reports".into();
    state.report.event_limit = 0; // clamped before it reaches the core
    state.export_report();
    let commands = state.take_commands();
    match &commands[0] {
        Command::Report {
            output,
            acquisition_id,
            revision,
            event_limit,
            ..
        } => {
            assert_eq!(output, "/tmp/opencode/reports");
            assert_eq!(acquisition_id.as_deref(), Some("acq-1"));
            assert_eq!(revision.as_deref(), Some("run-1"));
            assert_eq!(*event_limit, 1);
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn a_published_report_and_a_verification_result_are_shown() {
    let mut state = AppState::new();
    open_case(&mut state);
    state.report.destination = "/tmp/opencode/reports".into();
    state.export_report();
    let commands = state.take_commands();
    let id = commands[0].id();
    state.apply(CommandEvent::Finished {
        id,
        outcome: Outcome::ReportPublished {
            report_id: "report-acq-1-1".into(),
            directory: "/tmp/opencode/reports/report-acq-1-1".into(),
            json: "/tmp/opencode/reports/report-acq-1-1/report.json".into(),
            html: "/tmp/opencode/reports/report-acq-1-1/report.html".into(),
            objects: 3,
            events: 12,
            gaps: 1,
        },
    });
    let published = state.report.last.clone().expect("published summary");
    assert_eq!(
        published,
        ReportSummary {
            report_id: "report-acq-1-1".into(),
            directory: "/tmp/opencode/reports/report-acq-1-1".into(),
            json: "/tmp/opencode/reports/report-acq-1-1/report.json".into(),
            html: "/tmp/opencode/reports/report-acq-1-1/report.html".into(),
            objects: 3,
            events: 12,
            gaps: 1,
        }
    );

    state.verify_case();
    let commands = state.take_commands();
    let id = commands[0].id();
    state.apply(CommandEvent::Finished {
        id,
        outcome: Outcome::Verified {
            manifest_id: "manifest-acq-1".into(),
            acquisition_id: "acq-1".into(),
            format: "ghosttrace-manifest-v1".into(),
            objects: 3,
            total_bytes: 4_096,
            captured: 3,
            gaps: 1,
        },
    });
    assert_eq!(
        state.report.verification,
        Some(VerifySummary {
            manifest_id: "manifest-acq-1".into(),
            acquisition_id: "acq-1".into(),
            format: "ghosttrace-manifest-v1".into(),
            objects: 3,
            total_bytes: 4_096,
            captured: 3,
            gaps: 1,
        })
    );

    let mut harness = Harness::new_ui_state(|ui, state| state.ui(ui), state);
    harness.run_steps(2);
    for text in [
        "Last published report",
        "Report report-acq-1-1",
        "Verified manifest manifest-acq-1",
    ] {
        assert!(
            harness.query_all_by_label_contains(text).next().is_some(),
            "the report screen never states {text:?}"
        );
    }
}

#[test]
fn a_failed_publication_stays_visible() {
    let mut state = AppState::new();
    open_case(&mut state);
    state.report.destination = "/tmp/opencode/reports".into();
    state.export_report();
    let commands = state.take_commands();
    let id = commands[0].id();
    state.apply(CommandEvent::Failed {
        id,
        phase: JobPhase::Report,
        code: "storage".into(),
        message: "report report-acq-1-1 already exists; refusing to overwrite".into(),
    });

    assert!(state.report.status.starts_with("export failed"));
    assert!(state.report.status.contains("already exists"));
    assert!(
        state
            .notices
            .iter()
            .any(|notice| notice.text.contains("already exists")),
        "the failure is reported, not swallowed"
    );
    assert!(state.report.last.is_none());
}

#[test]
fn a_cancelled_report_publishes_nothing() {
    let bus = CommandBus::spawn().expect("worker");
    let dir = tempfile::tempdir().expect("tempdir");
    let output = dir.path().join("never");
    // Cancel before the worker receives the command: the pre-cancel set must
    // survive registration, so the job never opens the case or writes a file.
    bus.cancel(11);
    bus.send(Command::Report {
        id: 11,
        case_directory: "/nonexistent.ghosttrace-case".into(),
        output: output.display().to_string(),
        acquisition_id: None,
        revision: None,
        event_limit: 10,
        report_id: None,
    });

    let started = Instant::now();
    let mut seen = Vec::new();
    while started.elapsed() < Duration::from_secs(30) {
        if let Some(event) = bus.try_recv() {
            seen.push(event.clone());
            match event {
                CommandEvent::Finished {
                    id: 11,
                    outcome: Outcome::ReportCancelled,
                } => {
                    assert!(!output.exists());
                    return;
                }
                CommandEvent::Finished { .. } | CommandEvent::Failed { .. } => {
                    panic!("unexpected event: {event:?}")
                }
                _ => {}
            }
            continue;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out; events seen: {seen:?}");
}

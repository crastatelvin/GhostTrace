//! P6.1 desktop workflow contract: controls are addressed by accessible name,
//! the render pass only queues commands, and stale results are ignored.

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use ghosttrace_core::domain::case::AcquisitionMethod;
use ghosttrace_desktop::commands::{Command, CommandEvent, JobPhase, Outcome};
use ghosttrace_desktop::state::{AppState, JobState, NoticeLevel, RecoveryItem, Screen};

fn harness() -> Harness<'static, AppState> {
    Harness::new_ui_state(|ui, state| state.ui(ui), AppState::new())
}

/// The running job shows an animated progress bar, so the harness never
/// "settles"; step a fixed number of frames instead.
fn step(harness: &mut Harness<'_, AppState>) {
    harness.run_steps(2);
}

fn set_text(harness: &mut Harness<'_, AppState>, label: &str, value: &str) {
    harness.get_by_label(label).set_text_value_accesskit(value);
    step(harness);
}

/// Drive a completed create so the import screen has an open case, without a
/// worker: the reducer is the same code the real app uses.
fn open_case(state: &mut AppState) {
    state.start(|id| Command::CreateCase {
        id,
        directory: "/tmp/demo.ghosttrace-case".into(),
        label: "Demo".into(),
        timezone: "UTC".into(),
    });
    let id = state.job.id.expect("queued");
    let _ = state.take_commands();
    state.apply(CommandEvent::Finished {
        id,
        outcome: Outcome::CaseCreated {
            directory: "/tmp/demo.ghosttrace-case".into(),
            database_path: "/tmp/demo.ghosttrace-case/case.sqlite".into(),
            label: "Demo".into(),
            timezone: "UTC".into(),
        },
    });
}

#[test]
fn create_case_queues_one_command_from_labeled_controls() {
    let mut harness = harness();
    set_text(&mut harness, "Case directory", "/tmp/demo.ghosttrace-case");
    set_text(&mut harness, "Case label", "Demo investigation");
    set_text(&mut harness, "Display time zone", "Europe/Berlin");
    harness.get_by_label("Create case").click();
    step(&mut harness);

    let commands = harness.state_mut().take_commands();
    assert_eq!(commands.len(), 1);
    match &commands[0] {
        Command::CreateCase {
            directory,
            label,
            timezone,
            ..
        } => {
            assert_eq!(directory, "/tmp/demo.ghosttrace-case");
            assert_eq!(label, "Demo investigation");
            assert_eq!(timezone, "Europe/Berlin");
        }
        other => panic!("unexpected command: {other:?}"),
    }
    assert_eq!(harness.state().job.state, JobState::Running);
    assert_eq!(harness.state().job.phase, Some(JobPhase::Create));
}

#[test]
fn invalid_case_destination_is_reported_without_a_command() {
    let mut harness = harness();
    set_text(&mut harness, "Case directory", "not-a-case-directory");
    harness.get_by_label("Create case").click();
    step(&mut harness);

    assert!(harness.state_mut().take_commands().is_empty());
    assert!(
        harness
            .state()
            .notices
            .iter()
            .any(|notice| notice.level == NoticeLevel::Error
                && notice.text.contains(".ghosttrace-case")),
        "{:?}",
        harness.state().notices
    );
    // `get_by_label_contains` panics when the text is not rendered.
    harness.get_by_label_contains("case directory must end with");

    // An empty destination is refused too.
    set_text(&mut harness, "Case directory", "");
    harness.get_by_label("Create case").click();
    step(&mut harness);
    assert!(harness.state_mut().take_commands().is_empty());
    harness.get_by_label_contains("case directory is required");
}

#[test]
fn import_screen_reviews_method_and_queues_a_capture() {
    let mut harness = harness();
    open_case(harness.state_mut());
    step(&mut harness);
    assert_eq!(harness.state().screen, Screen::Import);

    set_text(&mut harness, "Source directory", "/tmp/evidence");
    set_text(&mut harness, "Acquisition label", "snapshot-a");
    harness.get_by_label("Live best effort").click();
    step(&mut harness);
    assert_eq!(
        harness.state().import_form.method,
        AcquisitionMethod::LiveBestEffort
    );
    harness
        .get_by_label_contains("Summary: capture /tmp/evidence as snapshot-a (live best effort)");

    harness.get_by_label("Start capture").click();
    step(&mut harness);
    let commands = harness.state_mut().take_commands();
    assert_eq!(commands.len(), 1);
    match &commands[0] {
        Command::Capture {
            case_directory,
            source,
            label,
            method,
            ..
        } => {
            assert_eq!(case_directory, "/tmp/demo.ghosttrace-case");
            assert_eq!(source, "/tmp/evidence");
            assert_eq!(label, "snapshot-a");
            assert_eq!(*method, AcquisitionMethod::LiveBestEffort);
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn a_running_job_blocks_starts_and_can_be_cancelled() {
    let mut harness = harness();
    open_case(harness.state_mut());
    step(&mut harness);
    set_text(&mut harness, "Source directory", "/tmp/evidence");
    harness.get_by_label("Start capture").click();
    step(&mut harness);
    let first = harness.state_mut().take_commands();
    assert_eq!(first.len(), 1);
    let id = harness.state().job.id.expect("running job");

    // Start buttons are disabled while the first job runs: no second command.
    harness.get_by_label("Start capture").click();
    step(&mut harness);
    assert!(harness.state_mut().take_commands().is_empty());

    harness.get_by_label("Cancel").click();
    step(&mut harness);
    assert_eq!(harness.state_mut().take_cancels(), vec![id]);
    assert!(harness.state().job.message.contains("cancelling"));
}

#[test]
fn recovery_review_lists_interrupted_jobs_and_can_be_acknowledged() {
    let mut harness = harness();
    let state = harness.state_mut();
    state.start(|id| Command::OpenCase {
        id,
        directory: "/tmp/demo.ghosttrace-case".into(),
    });
    let id = state.job.id.expect("queued");
    let _ = state.take_commands();
    state.apply(CommandEvent::Finished {
        id,
        outcome: Outcome::CaseOpened {
            directory: "/tmp/demo.ghosttrace-case".into(),
            database_path: "/tmp/demo.ghosttrace-case/case.sqlite".into(),
            label: "Demo".into(),
            timezone: "UTC".into(),
            revision: None,
            acquisitions: Vec::new(),
            recovery: vec![RecoveryItem {
                job_id: "job-1".into(),
                kind: "acquisition".into(),
                committed_locator: Some("offset:0:len:10".into()),
            }],
        },
    });
    assert!(harness.state().show_recovery);
    step(&mut harness);
    harness.get_by_label_contains("interrupted acquisition job job-1");
    harness.get_by_label_contains("Nothing was completed automatically");

    harness.get_by_label("Acknowledge recovery").click();
    step(&mut harness);
    assert!(!harness.state().show_recovery);
    assert!(
        harness
            .state()
            .notices
            .iter()
            .any(|notice| notice.text.contains("stays recorded as recoverable"))
    );
}

#[test]
fn stale_results_are_ignored() {
    let mut state = AppState::new();
    state.start(|id| Command::CreateCase {
        id,
        directory: "/tmp/demo.ghosttrace-case".into(),
        label: "Demo".into(),
        timezone: "UTC".into(),
    });
    let id = state.job.id.expect("queued");
    let _ = state.take_commands();

    // A result from another job generation changes nothing.
    state.apply(CommandEvent::Finished {
        id: id + 99,
        outcome: Outcome::CaseCreated {
            directory: "/tmp/other.ghosttrace-case".into(),
            database_path: "/tmp/other.ghosttrace-case/case.sqlite".into(),
            label: "Other".into(),
            timezone: "UTC".into(),
        },
    });
    assert!(state.open.is_none());
    assert_eq!(state.job.state, JobState::Running);

    state.apply(CommandEvent::Finished {
        id,
        outcome: Outcome::CaseCreated {
            directory: "/tmp/demo.ghosttrace-case".into(),
            database_path: "/tmp/demo.ghosttrace-case/case.sqlite".into(),
            label: "Demo".into(),
            timezone: "UTC".into(),
        },
    });
    assert!(state.open.is_some());
    assert_eq!(state.job.state, JobState::Finished);

    // A late failure for the finished job cannot overwrite the outcome.
    let notices = state.notices.len();
    state.apply(CommandEvent::Failed {
        id,
        phase: JobPhase::Create,
        code: "storage".into(),
        message: "late".into(),
    });
    assert_eq!(state.notices.len(), notices);
    assert_eq!(state.job.state, JobState::Finished);
}

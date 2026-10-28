//! P6.1 background job contract: the worker runs the real core service off the
//! render thread, reports progress, and honours cancellation by job id.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ghosttrace_core::analysis::annotations::AppendAnnotation;
use ghosttrace_core::analysis::views::SavedFilter;
use ghosttrace_core::domain::case::AcquisitionMethod;
use ghosttrace_core::domain::finding::Disposition;
use ghosttrace_desktop::commands::{Command, CommandBus, CommandEvent, Outcome};

const TIMEOUT: Duration = Duration::from_secs(60);

fn wait_for(
    bus: &CommandBus,
    predicate: impl Fn(&CommandEvent) -> bool,
) -> (Vec<CommandEvent>, CommandEvent) {
    let started = Instant::now();
    let mut seen = Vec::new();
    while started.elapsed() < TIMEOUT {
        if let Some(event) = bus.try_recv() {
            let matched = predicate(&event);
            seen.push(event.clone());
            if matched {
                return (seen, event);
            }
            continue;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out; events seen: {seen:?}");
}

fn case_directory(dir: &Path) -> String {
    dir.join("demo.ghosttrace-case")
        .to_string_lossy()
        .into_owned()
}

fn write_source(dir: &Path, files: usize) -> PathBuf {
    let source = dir.join("source");
    std::fs::create_dir_all(&source).expect("source dir");
    for index in 0..files {
        std::fs::write(
            source.join(format!("file-{index:03}.txt")),
            format!("record {index}\n"),
        )
        .expect("write source");
    }
    std::fs::write(
        source.join("app.jsonl"),
        b"{\"ts\":\"2026-10-27T10:00:00Z\",\"msg\":\"hello\"}\n",
    )
    .expect("write jsonl");
    source
}

#[test]
fn worker_creates_captures_and_imports_a_case() {
    let dir = tempfile::tempdir().expect("tempdir");
    let case = case_directory(dir.path());
    let source = write_source(dir.path(), 3);
    let bus = CommandBus::spawn().expect("worker");

    bus.send(Command::CreateCase {
        id: 1,
        directory: case.clone(),
        label: "Demo".into(),
        timezone: "UTC".into(),
    });
    let (_, event) = wait_for(&bus, |event| {
        matches!(event, CommandEvent::Finished { id: 1, .. })
    });
    match event {
        CommandEvent::Finished {
            outcome: Outcome::CaseCreated { label, .. },
            ..
        } => assert_eq!(label, "Demo"),
        other => panic!("unexpected event: {other:?}"),
    }

    bus.send(Command::Capture {
        id: 2,
        case_directory: case.clone(),
        source: source.to_string_lossy().into_owned(),
        label: "snapshot-a".into(),
        method: AcquisitionMethod::ProtectedCopy,
        max_depth: 8,
        max_entries: 10_000,
        max_file_bytes: 1 << 20,
    });
    let (seen, event) = wait_for(&bus, |event| {
        matches!(event, CommandEvent::Finished { id: 2, .. })
    });
    assert!(
        seen.iter()
            .any(|event| matches!(event, CommandEvent::Started { id: 2, .. })),
        "the worker announces the phase"
    );
    match event {
        CommandEvent::Finished {
            outcome: Outcome::Captured { state, objects, .. },
            ..
        } => {
            assert_eq!(state, "completed");
            assert_eq!(objects, 4, "three files and the JSONL object");
        }
        other => panic!("unexpected event: {other:?}"),
    }

    bus.send(Command::Import {
        id: 3,
        case_directory: case.clone(),
        object_path: "app.jsonl".into(),
        format: None,
        syslog_timezone: None,
        syslog_year: None,
    });
    let (_, event) = wait_for(&bus, |event| {
        matches!(event, CommandEvent::Finished { id: 3, .. })
    });
    match event {
        CommandEvent::Finished {
            outcome:
                Outcome::Imported {
                    run_id,
                    state,
                    events,
                },
            ..
        } => {
            assert!(run_id.starts_with("pr-"));
            assert_eq!(state, "completed");
            assert_eq!(events, 1);

            // P6.3 writes go through the same single worker: analysis,
            // relationships, an append-only annotation, and a saved view.
            bus.send(Command::Analyze {
                id: 4,
                case_directory: case.clone(),
                revision: run_id.clone(),
            });
            let (_, event) = wait_for(&bus, |event| {
                matches!(event, CommandEvent::Finished { id: 4, .. })
            });
            let analysis_run = match event {
                CommandEvent::Finished {
                    outcome:
                        Outcome::Analyzed {
                            run_id,
                            state,
                            findings: _,
                        },
                    ..
                } => {
                    assert_eq!(state, "completed");
                    assert!(run_id.starts_with("arun-"));
                    run_id
                }
                other => panic!("unexpected event: {other:?}"),
            };

            bus.send(Command::Correlate {
                id: 5,
                case_directory: case.clone(),
            });
            let (_, event) = wait_for(&bus, |event| {
                matches!(event, CommandEvent::Finished { id: 5, .. })
            });
            match event {
                CommandEvent::Finished {
                    outcome: Outcome::Correlated { inserted, .. },
                    ..
                } => assert!(inserted <= 64, "a tiny case derives few edges"),
                other => panic!("unexpected event: {other:?}"),
            }

            bus.send(Command::Annotate {
                id: 6,
                case_directory: case.clone(),
                request: AppendAnnotation {
                    target_id: analysis_run,
                    author_label: "ana".into(),
                    text: "checked the run".into(),
                    tags: vec!["triage".into()],
                    disposition: Some(Disposition::Confirmed),
                    expected_previous: None,
                },
            });
            let (_, event) = wait_for(&bus, |event| {
                matches!(event, CommandEvent::Finished { id: 6, .. })
            });
            match event {
                CommandEvent::Finished {
                    outcome: Outcome::Annotated { revision_id, .. },
                    ..
                } => assert!(revision_id > 0),
                other => panic!("unexpected event: {other:?}"),
            }

            bus.send(Command::SaveView {
                id: 7,
                case_directory: case.clone(),
                name: "hello events".into(),
                filter: SavedFilter {
                    text: Some("hello".into()),
                    ..SavedFilter::default()
                },
            });
            let (_, event) = wait_for(&bus, |event| {
                matches!(event, CommandEvent::Finished { id: 7, .. })
            });
            match event {
                CommandEvent::Finished {
                    outcome: Outcome::ViewSaved { name },
                    ..
                } => assert_eq!(name, "hello events"),
                other => panic!("unexpected event: {other:?}"),
            }

            // Reopening lists the recorded capture. This exercises the real
            // acquisition query, which the workflow tests only stubbed.
            bus.send(Command::OpenCase {
                id: 11,
                directory: case.clone(),
            });
            let (_, event) = wait_for(&bus, |event| {
                matches!(event, CommandEvent::Finished { id: 11, .. })
            });
            match event {
                CommandEvent::Finished {
                    outcome: Outcome::CaseOpened { acquisitions, .. },
                    ..
                } => {
                    assert_eq!(acquisitions.len(), 1);
                    assert_eq!(acquisitions[0].state, "completed");
                }
                other => panic!("unexpected event: {other:?}"),
            }

            // P6.4: export the unredacted report, verify the stored bytes, and
            // prove a second publication of the same id is refused.
            let reports = dir.path().join("reports");
            bus.send(Command::Report {
                id: 8,
                case_directory: case.clone(),
                output: reports.display().to_string(),
                acquisition_id: None,
                revision: None,
                event_limit: 50,
                report_id: None,
            });
            let (_, event) = wait_for(&bus, |event| {
                matches!(event, CommandEvent::Finished { id: 8, .. })
            });
            let report_id = match event {
                CommandEvent::Finished {
                    outcome:
                        Outcome::ReportPublished {
                            report_id,
                            json,
                            html,
                            objects,
                            ..
                        },
                    ..
                } => {
                    assert!(objects >= 1, "the capture recorded at least one object");
                    assert!(Path::new(&json).is_file());
                    assert!(Path::new(&html).is_file());
                    report_id
                }
                other => panic!("unexpected event: {other:?}"),
            };

            bus.send(Command::Verify {
                id: 9,
                case_directory: case.clone(),
                manifest_path: None,
                acquisition_id: None,
            });
            let (_, event) = wait_for(&bus, |event| {
                matches!(event, CommandEvent::Finished { id: 9, .. })
            });
            match event {
                CommandEvent::Finished {
                    outcome: Outcome::Verified { objects, .. },
                    ..
                } => assert!(objects >= 1),
                other => panic!("unexpected event: {other:?}"),
            }

            bus.send(Command::Report {
                id: 10,
                case_directory: case,
                output: reports.display().to_string(),
                acquisition_id: None,
                revision: None,
                event_limit: 50,
                report_id: Some(report_id),
            });
            let (_, event) = wait_for(&bus, |event| {
                matches!(event, CommandEvent::Failed { id: 10, .. })
            });
            match event {
                CommandEvent::Failed { code, message, .. } => {
                    assert_eq!(code, "storage");
                    assert!(message.contains("already exists"), "{message}");
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn cancellation_before_the_copy_starts_is_honoured() {
    let dir = tempfile::tempdir().expect("tempdir");
    let case = case_directory(dir.path());
    let source = write_source(dir.path(), 500);
    let bus = CommandBus::spawn().expect("worker");

    bus.send(Command::CreateCase {
        id: 1,
        directory: case.clone(),
        label: "Demo".into(),
        timezone: "UTC".into(),
    });
    let _ = wait_for(&bus, |event| {
        matches!(event, CommandEvent::Finished { id: 1, .. })
    });

    bus.send(Command::Capture {
        id: 2,
        case_directory: case,
        source: source.to_string_lossy().into_owned(),
        label: "snapshot-a".into(),
        method: AcquisitionMethod::ProtectedCopy,
        max_depth: 8,
        max_entries: 10_000,
        max_file_bytes: 1 << 20,
    });
    // Cancel immediately: the worker must not lose a request that arrives
    // before it registers the copy handle.
    bus.cancel(2);
    let (_, event) = wait_for(&bus, |event| {
        matches!(event, CommandEvent::Finished { id: 2, .. })
    });
    match event {
        CommandEvent::Finished {
            outcome: Outcome::Captured { state, .. },
            ..
        } => assert_eq!(state, "cancelled"),
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn failures_carry_a_stable_code_and_no_evidence_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bus = CommandBus::spawn().expect("worker");
    bus.send(Command::OpenCase {
        id: 9,
        directory: dir
            .path()
            .join("absent.ghosttrace-case")
            .to_string_lossy()
            .into_owned(),
    });
    let (_, event) = wait_for(&bus, |event| {
        matches!(event, CommandEvent::Failed { id: 9, .. })
    });
    match event {
        CommandEvent::Failed {
            code,
            phase,
            message,
            ..
        } => {
            assert_eq!(code, "invalid_request");
            assert_eq!(phase, ghosttrace_desktop::commands::JobPhase::Open);
            assert!(message.contains("no case at"), "{message}");
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

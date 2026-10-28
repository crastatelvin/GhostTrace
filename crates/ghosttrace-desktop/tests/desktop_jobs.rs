//! P6.1 background job contract: the worker runs the real core service off the
//! render thread, reports progress, and honours cancellation by job id.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ghosttrace_core::domain::case::AcquisitionMethod;
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
        case_directory: case,
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

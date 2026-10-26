//! P1.2 concurrency and query contract: one writer per case (while readers
//! keep working), identical-time events paginate without skips or
//! duplicates, and unknown times stay reachable in an explicit view.

use ghosttrace_core::domain::event::{Event, NamedEventTimeRef};
use ghosttrace_core::domain::query::{EventQuery, TimeCursor};
use ghosttrace_core::domain::time::{
    ClockDomain, Epoch, EventTime, RawTimeValue, TimeSemantic, TimeUnit,
};
use ghosttrace_core::error::CoreError;
use ghosttrace_core::jobs::{JobCheckpoint, JobKind, JobState};
use ghosttrace_core::service::{CaseSession, CreateCaseSpec};
use ghosttrace_core::storage::writer::{CaseWriter, Param, WriteBatch, WriteOp};
use std::path::Path;

fn create_case(dir: &Path) -> CaseSession {
    CaseSession::create(dir, "pagination", CreateCaseSpec::default()).expect("case")
}

fn event(id: &str, seconds: Option<i64>, kind: &str) -> Event {
    let time = match seconds {
        Some(seconds) => EventTime::from_raw(
            RawTimeValue::integer_raw("mtime", i128::from(seconds), Epoch::Unix, TimeUnit::Seconds),
            TimeSemantic::ContentModified,
            ClockDomain::Host,
        ),
        None => EventTime::from_local_wall_clock(
            chrono::NaiveDateTime::parse_from_str("2024-01-05T09:00:00", "%Y-%m-%dT%H:%M:%S")
                .unwrap(),
            None,
            TimeSemantic::Other("legacy syslog".into()),
        ),
    };
    Event {
        id: id.into(),
        kind: kind.into(),
        summary: format!("event {id}"),
        observations: Vec::new(),
        times: vec![NamedEventTimeRef {
            name: "mtime".into(),
            semantic: TimeSemantic::ContentModified,
            value: time,
        }],
        host_claim: Some("host-1".into()),
        revision: "run-1".into(),
    }
}

fn seed_events(session: &CaseSession, count: usize) {
    let writer = session.writer();
    // Required parents for the parse-run foreign key.
    writer
        .execute(
            WriteBatch::new()
                .push(WriteOp::fact(
                    "cases",
                    vec!["id", "label", "schema_version", "created_seconds"],
                    vec![
                        Param::Text("case-1".into()),
                        Param::Text("l".into()),
                        Param::Int(1),
                        Param::Int(0),
                    ],
                ))
                .push(WriteOp::fact(
                    "acquisitions",
                    vec!["id", "case_id", "method", "claimed_source", "state"],
                    vec![
                        Param::Text("acq-1".into()),
                        Param::Text("case-1".into()),
                        Param::Text("protected_copy".into()),
                        Param::Text("src".into()),
                        Param::Text("completed".into()),
                    ],
                ))
                .push(WriteOp::fact(
                    "parse_runs",
                    vec![
                        "id",
                        "acquisition_id",
                        "parser_id",
                        "parser_version",
                        "state",
                    ],
                    vec![
                        Param::Text("run-1".into()),
                        Param::Text("acq-1".into()),
                        Param::Text("jsonl".into()),
                        Param::Text("1.0.0".into()),
                        Param::Text("completed".into()),
                    ],
                )),
        )
        .unwrap();

    for index in 0..count {
        // Every event shares one time: keyset ordering must use the id tiebreak.
        let seconds = if index % 3 == 0 {
            None
        } else {
            Some(1_700_000_000)
        };
        writer
            .queue_event(
                &event(&format!("ev-{index:02}"), seconds, "file.write"),
                "r1",
            )
            .unwrap();
    }
}

#[test]
fn second_writer_is_rejected_while_readers_keep_working() {
    let dir = tempfile::tempdir().unwrap();
    let session = create_case(dir.path());
    let database = session.layout().database_path().clone();

    // Read-only viewing works while the writer owns writes.
    let reader = session.reader().unwrap();
    assert!(
        reader
            .connection()
            .query_row("SELECT count(*) FROM events", [], |r| r.get::<_, i64>(0))
            .is_ok()
    );

    let second = CaseWriter::spawn(&database);
    assert!(
        matches!(second, Err(CoreError::Storage(_))),
        "one writer per case per process"
    );
    drop(reader);

    // Releasing the session allows a fresh writer (new process or reopen).
    drop(session);
    let third = CaseWriter::spawn_with_queue(&database, 4).unwrap();
    assert_eq!(third.queue_depth(), 4);
}

#[test]
fn identical_time_events_paginate_without_skips_or_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    let session = create_case(dir.path());
    seed_events(&session, 40);

    let mut seen = Vec::new();
    let mut cursor: Option<TimeCursor> = None;
    let mut pages = 0;
    loop {
        let mut query = EventQuery::with_revision("r1");
        query.limit = 5;
        query.after = cursor;
        let page = session.query_events(&query).unwrap();
        let rows = page.rows;
        for row in &rows {
            assert_eq!(row.chosen_seconds, Some(1_700_000_000));
            seen.push(row.event_id.clone());
        }
        pages += 1;
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
        assert!(pages < 100, "pagination must terminate");
    }

    let mut sorted = seen.clone();
    sorted.sort();
    assert_eq!(
        seen.len(),
        26,
        "26 resolved events; 14 unresolved are excluded"
    );
    assert_eq!(
        seen, sorted,
        "keyset order is total: no skips or duplicates"
    );
}

#[test]
fn unknown_times_live_in_the_explicit_unresolved_view() {
    let dir = tempfile::tempdir().unwrap();
    let session = create_case(dir.path());
    seed_events(&session, 6);

    let mut query = EventQuery::with_revision("r1");
    query.unresolved_only = true;
    query.limit = 100;
    let page = session.query_events(&query).unwrap();
    assert_eq!(page.rows.len(), 2);
    assert!(page.rows.iter().all(|row| row.chosen_seconds.is_none()));
    assert!(page.rows.iter().all(|row| row.time_status == "unresolved"));
    let ids: Vec<&str> = page.rows.iter().map(|row| row.event_id.as_str()).collect();
    assert_eq!(ids, vec!["ev-00", "ev-03"]);
}

#[test]
fn unresolved_view_paginates_by_id() {
    let dir = tempfile::tempdir().unwrap();
    let session = create_case(dir.path());
    seed_events(&session, 30);

    let mut count = 0;
    let mut last: Option<String> = None;
    loop {
        let mut query = EventQuery::with_revision("r1");
        query.unresolved_only = true;
        query.limit = 3;
        query.after = last.as_ref().map(|event_id| TimeCursor {
            seconds: 0,
            nanos: 0,
            event_id: event_id.clone(),
        });
        let page = session.query_events(&query).unwrap();
        count += page.rows.len();
        match page.next_cursor {
            Some(next) => {
                assert!(!next.event_id.is_empty());
                last = Some(next.event_id);
            }
            None => break,
        }
    }
    assert_eq!(count, 10, "every third event is unresolved");
}

#[test]
fn running_jobs_are_recoverable_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let root = {
        let session = create_case(dir.path());
        let checkpoint = JobCheckpoint::queued("job-1", JobKind::Acquisition, "root:x", "digest-x");
        session.writer().queue_job_checkpoint(&checkpoint).unwrap();
        let mut running = checkpoint.clone();
        running.state = JobState::Running;
        running.committed_locator = Some("record:17".into());
        session.writer().queue_job_checkpoint(&running).unwrap();
        session.layout().root().to_path_buf()
    };

    let (session, report) = CaseSession::open(root).unwrap();
    assert_eq!(report.recoverable_jobs.len(), 1);
    let recoverable = &report.recoverable_jobs[0];
    assert_eq!(recoverable.job_id, "job-1");
    assert_eq!(recoverable.found_state, JobState::Running);
    assert_eq!(recoverable.committed_locator.as_deref(), Some("record:17"));
    drop(session);

    // Still running, never silently completed by the reopen.
    let reader_session = CaseSession::open(dir.path().join("pagination.ghosttrace-case"))
        .unwrap()
        .0;
    let state: String = reader_session
        .reader()
        .unwrap()
        .connection()
        .query_row(
            "SELECT state FROM job_checkpoints WHERE job_id = 'job-1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "running");
}

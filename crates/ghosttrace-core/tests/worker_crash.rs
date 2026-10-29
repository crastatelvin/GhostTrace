//! P8.2: a crashing, hanging, or lying worker can never produce a completed
//! run, and never blocks the caller.
//!
//! Each test starts a fake worker that completes the handshake and then
//! misbehaves, so the parent's kill/timeout/validation paths run for real.
//! Unix only: the fake worker is a shell script.
#![cfg(unix)]

mod support;

use std::time::{Duration, Instant};

use ghosttrace_core::error::CoreError;
use ghosttrace_core::ingest::ImportOutcome;
use support::{Harness, fake_worker, frame_printf};

const SYSMON: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/evtx/sysmon.evtx"
));
const CAPTURE_LIMIT: u64 = 8 << 20;

fn import_with(
    worker: &std::path::Path,
    timeout: Duration,
) -> (Harness, ghosttrace_core::error::CoreResult<ImportOutcome>) {
    let mut harness = Harness::new();
    let acquisition = harness.capture_with_limit(&[("sysmon.evtx", SYSMON)], CAPTURE_LIMIT);
    let worker = worker.to_path_buf();
    let outcome = harness.import(&acquisition, "sysmon.evtx", |request| {
        request.worker = Some(worker.clone());
        request.isolation_required = true;
        request.worker_timeout = timeout;
        request.worker_job_timeout = Duration::from_secs(30);
    });
    (harness, outcome)
}

fn recorded_state(harness: &Harness) -> String {
    harness
        .scalar(
            "SELECT state FROM parse_runs ORDER BY rowid DESC LIMIT 1",
            &[],
        )
        .expect("a parse run")
}

#[test]
fn a_hanging_worker_is_killed_and_the_run_is_failed() {
    let worker = fake_worker(env!("CARGO_PKG_VERSION"), "sleep 60");
    let started = Instant::now();
    let (harness, outcome) = import_with(&worker, Duration::from_secs(1));
    let elapsed = started.elapsed();
    let outcome = outcome.expect("a failed run is recorded, not an error");
    assert!(
        elapsed < Duration::from_secs(15),
        "the parent waited {elapsed:?}"
    );
    assert_eq!(outcome.state, "failed");
    assert_eq!(outcome.records, 0);
    assert_eq!(outcome.events, 0);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "worker_timeout"),
        "{:?}",
        outcome.diagnostics
    );
    assert_eq!(recorded_state(&harness), "failed");
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM events WHERE parse_run_id = ?1",
            &[&outcome.run_id]
        ),
        0,
        "a killed worker contributes no events"
    );
}

#[test]
fn a_crashing_worker_leaves_a_failed_run_never_completed() {
    // Stay alive past the handshake so this exercises the crash path, not the
    // separate "worker never started" path. The previous `exit 1` body raced
    // the parent's Hello write and failed the release gate intermittently.
    let worker = fake_worker(env!("CARGO_PKG_VERSION"), "sleep 3; exit 1");
    let (harness, outcome) = import_with(&worker, Duration::from_secs(10));
    let outcome = outcome.expect("a failed run is recorded");
    assert_eq!(outcome.state, "failed");
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "worker_crashed"),
        "{:?}",
        outcome.diagnostics
    );
    assert_eq!(recorded_state(&harness), "failed");
}

#[test]
fn invalid_output_is_a_protocol_failure() {
    let garbage = format!("{}; sleep 60", frame_printf("hello"));
    let worker = fake_worker(env!("CARGO_PKG_VERSION"), &garbage);
    let (harness, outcome) = import_with(&worker, Duration::from_secs(10));
    let outcome = outcome.expect("a failed run is recorded");
    assert_eq!(outcome.state, "failed");
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "worker_protocol"),
        "{:?}",
        outcome.diagnostics
    );
    assert_eq!(recorded_state(&harness), "failed");
}

#[test]
fn an_oversize_frame_is_refused_before_it_is_read() {
    // A 4-byte length prefix over the batch bound, then nothing.
    let worker = fake_worker(
        env!("CARGO_PKG_VERSION"),
        "printf '\\177\\377\\377\\377'; sleep 60",
    );
    let (harness, outcome) = import_with(&worker, Duration::from_secs(10));
    let outcome = outcome.expect("a failed run is recorded");
    assert_eq!(outcome.state, "failed");
    let diagnostic = outcome
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "worker_protocol")
        .expect("a protocol diagnostic");
    assert!(diagnostic.detail.contains("over the"), "{diagnostic:?}");
    assert_eq!(recorded_state(&harness), "failed");
}

#[test]
fn a_build_mismatch_is_refused_and_the_run_is_failed() {
    let worker = fake_worker("0.0.0-other", "sleep 60");
    let (harness, outcome) = import_with(&worker, Duration::from_secs(5));
    let error = outcome.expect_err("a mismatched build is refused");
    assert!(
        matches!(error, CoreError::Unsupported(_)),
        "unexpected error: {error:?}"
    );
    assert_eq!(recorded_state(&harness), "failed");
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM events e JOIN parse_runs r ON r.id = e.parse_run_id
             WHERE r.parser_id = 'evtx.records'",
            &[]
        ),
        0
    );
}

#[test]
fn a_cancelled_job_kills_the_worker_and_records_cancelled() {
    use std::sync::atomic::AtomicBool;

    let worker = fake_worker(env!("CARGO_PKG_VERSION"), "sleep 60");
    let mut harness = Harness::new();
    let acquisition = harness.capture_with_limit(&[("sysmon.evtx", SYSMON)], CAPTURE_LIMIT);
    let cancelled = AtomicBool::new(true);
    let started = Instant::now();
    let outcome = harness
        .import_with_token(&acquisition, "sysmon.evtx", &cancelled, |request| {
            request.worker = Some(worker.clone());
            request.isolation_required = true;
            request.worker_timeout = Duration::from_secs(30);
        })
        .expect("a cancelled run is recorded");
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(outcome.state, "cancelled");
    assert_eq!(outcome.records, 0);
    assert_eq!(recorded_state(&harness), "cancelled");
}

#[test]
fn a_batch_for_another_job_is_refused() {
    let batch = format!(
        "{}; sleep 60",
        frame_printf(r#"{"type":"batch","job_id":"job-other","seq":0,"records":[]}"#)
    );
    let worker = fake_worker(env!("CARGO_PKG_VERSION"), &batch);
    let (harness, outcome) = import_with(&worker, Duration::from_secs(10));
    let outcome = outcome.expect("a failed run is recorded");
    assert_eq!(outcome.state, "failed");
    let diagnostic = outcome
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "worker_protocol")
        .expect("a protocol diagnostic");
    assert!(diagnostic.detail.contains("another job"), "{diagnostic:?}");
    assert_eq!(recorded_state(&harness), "failed");
}

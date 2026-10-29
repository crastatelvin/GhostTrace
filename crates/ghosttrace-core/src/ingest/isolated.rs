//! Parent side of the isolated parser worker (plan P8.2).
//!
//! The risky adapter runs in a child process with no case handle. The parent
//! stages a private copy of the captured object, hands the worker that path,
//! validates every frame it receives, and commits the records itself. A worker
//! that crashes, hangs, or emits malformed output ends the run `failed` with a
//! diagnostic; it can never produce a completed run or block the caller.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::error::{CoreError, CoreResult};
use crate::storage::writer::CaseWriter;
use crate::worker::protocol::{MAX_BATCH_RECORDS, Response};
use crate::worker::{Deadline, WorkerBinary, WorkerProcess};

use super::{
    Committer, Counts, Diagnostics, ImportOutcome, ImportPlan, ImportRequest, RecordSink,
    RunSummary, finalize_run,
};

/// The worker answers a handshake immediately; a slow answer is a broken build.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn run(
    writer: &CaseWriter,
    request: &ImportRequest<'_>,
    plan: ImportPlan,
    worker: &Path,
) -> CoreResult<ImportOutcome> {
    let worker = WorkerBinary::explicit(worker)?;
    let ImportPlan {
        evidence,
        store_path,
        detected,
        format,
        mut run,
    } = plan;
    let job_id = format!("job-{}", uuid::Uuid::new_v4());
    let mut counts = Counts::default();
    let mut diagnostics = Diagnostics::default();
    let mut cancelled = false;
    let mut failure: Option<Failure> = None;
    let mut deadline = Deadline::new(request.worker_timeout, request.worker_job_timeout);
    let mut next_seq = 0_u64;
    let mut committed = 0_u64;

    // A missing, mismatched, or unstageable worker is a failed run, not a
    // dangling "running" row: nothing about this import can be claimed done.
    let staged = match StagedInput::create(&store_path) {
        Ok(staged) => staged,
        Err(error) => {
            fail_start(
                writer,
                run,
                counts,
                diagnostics,
                &evidence,
                format,
                detected,
                request,
                error.detail(),
            )?;
            return Err(error);
        }
    };
    let mut process = match WorkerProcess::spawn(&worker, staged.dir(), &job_id, HANDSHAKE_TIMEOUT)
    {
        Ok(process) => process,
        Err(error) => {
            fail_start(
                writer,
                run,
                counts,
                diagnostics,
                &evidence,
                format,
                detected,
                request,
                error.detail(),
            )?;
            return Err(error);
        }
    };
    if process
        .send_parse(
            format.id(),
            staged.path(),
            request.max_records,
            request.max_record_bytes as u64,
        )
        .is_err()
    {
        // The worker died between the handshake and the job.
        failure = Some(Failure::Crash);
    }

    {
        let run_id = run.id.clone();
        let mut committer = Committer {
            writer,
            run: &mut run,
            evidence: &evidence,
            run_id: &run_id,
            counts: &mut counts,
            diagnostics: &mut diagnostics,
            pending_observations: Vec::new(),
            pending_events: Vec::new(),
        };
        'frames: loop {
            if failure.is_some() {
                break;
            }
            if request.cancelled.load(Ordering::Relaxed) {
                cancelled = true;
                process.kill();
                break;
            }
            let Some(remaining) = deadline.remaining() else {
                process.kill();
                failure = Some(Failure::Timeout);
                break;
            };
            let frame = match process.recv(remaining) {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    failure = Some(Failure::Crash);
                    break;
                }
                Err(CoreError::ResourceLimit) => {
                    process.kill();
                    failure = Some(Failure::Timeout);
                    break;
                }
                Err(error) => {
                    process.kill();
                    failure = Some(Failure::Protocol(error.detail().to_string()));
                    break;
                }
            };
            let response: Response = match serde_json::from_slice(&frame) {
                Ok(response) => response,
                Err(error) => {
                    process.kill();
                    failure = Some(Failure::Protocol(format!(
                        "a frame is not a valid message: {error}"
                    )));
                    break;
                }
            };
            match response {
                Response::Batch {
                    job_id: id,
                    seq,
                    records,
                } => {
                    if id != job_id {
                        failure = Some(Failure::Protocol("a batch names another job".to_string()));
                        break;
                    }
                    if seq != next_seq {
                        failure = Some(Failure::Protocol(format!(
                            "batch sequence {seq} arrived where {next_seq} was expected"
                        )));
                        break;
                    }
                    next_seq += 1;
                    if records.is_empty() || records.len() > MAX_BATCH_RECORDS {
                        failure = Some(Failure::Protocol(format!(
                            "batch has {} records",
                            records.len()
                        )));
                        break;
                    }
                    if committed + records.len() as u64 > request.max_records {
                        failure = Some(Failure::Protocol(
                            "the worker sent more records than the configured limit".to_string(),
                        ));
                        break;
                    }
                    for wire in records {
                        match wire.into_record(request.max_record_bytes) {
                            Ok(record) => {
                                committer.record(record)?;
                                committed += 1;
                            }
                            Err(message) => {
                                failure = Some(Failure::Protocol(format!(
                                    "a record is not valid: {message}"
                                )));
                                break 'frames;
                            }
                        }
                    }
                    deadline.progress();
                }
                Response::Progress {
                    job_id: id,
                    records,
                } => {
                    if id != job_id || records > request.max_records {
                        failure = Some(Failure::Protocol(
                            "progress names another job or exceeds the limit".to_string(),
                        ));
                        break;
                    }
                    deadline.progress();
                }
                Response::Done {
                    job_id: id,
                    records,
                    observations,
                    events,
                    diagnostics: worker_diagnostics,
                    diagnostics_total,
                } => {
                    if id != job_id {
                        failure = Some(Failure::Protocol("done names another job".to_string()));
                        break;
                    }
                    if records != committed
                        || observations != committer.counts.observations
                        || events != committer.counts.events
                    {
                        failure = Some(Failure::Protocol(format!(
                            "done reports {records} records/{observations} observations/{events} events but the parent committed {committed}/{} /{}",
                            committer.counts.observations, committer.counts.events
                        )));
                        break;
                    }
                    for diagnostic in &worker_diagnostics {
                        committer.diagnostics.push(
                            &diagnostic.code,
                            &diagnostic.locator,
                            &diagnostic.detail,
                        );
                    }
                    if diagnostics_total > worker_diagnostics.len() as u64 {
                        committer.diagnostics.push(
                            "diagnostics_truncated",
                            "worker",
                            &format!(
                                "{diagnostics_total} diagnostics recorded; only the first {} are stored",
                                worker_diagnostics.len()
                            ),
                        );
                    }
                    break;
                }
                Response::Failed {
                    job_id: id,
                    code,
                    message,
                } => {
                    if id != job_id {
                        failure = Some(Failure::Protocol("failure names another job".to_string()));
                        break;
                    }
                    failure = Some(Failure::Worker {
                        code,
                        message: sanitize(&message, staged.dir()),
                    });
                    break;
                }
                Response::Ready { .. } => {
                    failure = Some(Failure::Protocol(
                        "the worker repeated the handshake".to_string(),
                    ));
                    break;
                }
            }
        }
        if failure.is_some() {
            process.kill();
        }
        committer.flush()?;
    }

    if let Some(failure) = &failure {
        match failure {
            Failure::Timeout => diagnostics.push(
                "worker_timeout",
                "worker",
                &format!(
                    "the parser worker produced no output within {}s and was killed",
                    request.worker_timeout.as_secs()
                ),
            ),
            Failure::Crash => diagnostics.push(
                "worker_crashed",
                "worker",
                "the parser worker exited before reporting a result",
            ),
            Failure::Protocol(message) => diagnostics.push("worker_protocol", "worker", message),
            Failure::Worker { code, message } => {
                diagnostics.push("worker_error", "worker", &format!("{code}: {message}"))
            }
        }
    }
    let failed = failure.as_ref().map(|failure| failure.code());
    let outcome = finalize_run(
        writer,
        RunSummary {
            run,
            counts,
            diagnostics,
            cancelled,
            failed,
            evidence: &evidence,
            parser_id: format.parser_id(),
            detected,
            declared: request.format,
        },
    )?;
    match failure {
        // The worker refused the input the same way the in-process adapter
        // would; keep the CLI error contract while the run stays recorded.
        Some(Failure::Worker { code, message }) => Err(mapped_error(&code, &message)),
        _ => Ok(outcome),
    }
}

#[allow(clippy::too_many_arguments)]
fn fail_start(
    writer: &CaseWriter,
    run: super::ParseRunRecord,
    counts: Counts,
    diagnostics: Diagnostics,
    evidence: &super::EvidenceRef,
    format: super::LogFormat,
    detected: Option<super::LogFormat>,
    request: &ImportRequest<'_>,
    detail: &str,
) -> CoreResult<()> {
    let mut diagnostics = diagnostics;
    diagnostics.push("worker_start_failed", "worker", detail);
    finalize_run(
        writer,
        RunSummary {
            run,
            counts,
            diagnostics,
            cancelled: false,
            failed: Some("worker_start_failed"),
            evidence,
            parser_id: format.parser_id(),
            detected,
            declared: request.format,
        },
    )?;
    Ok(())
}

enum Failure {
    Timeout,
    Crash,
    Protocol(String),
    Worker { code: String, message: String },
}

impl Failure {
    fn code(&self) -> &'static str {
        match self {
            Failure::Timeout => "worker_timeout",
            Failure::Crash => "worker_crashed",
            Failure::Protocol(_) => "worker_protocol",
            Failure::Worker { .. } => "worker_error",
        }
    }
}

fn mapped_error(code: &str, message: &str) -> CoreError {
    let message = format!("parser worker: {message}");
    match code {
        "invalid_request" | "invalid_input" => CoreError::InvalidInput(message),
        "unsupported_format" => CoreError::Unsupported(message),
        "permission" => CoreError::Permission(message),
        "input_changed" => CoreError::InputChanged,
        "corrupt_evidence" => CoreError::CorruptEvidence,
        "integrity_mismatch" => CoreError::IntegrityMismatch,
        "resource_limit" => CoreError::ResourceLimit,
        "cancelled" => CoreError::Cancelled,
        "schema_incompatible" => CoreError::SchemaIncompatible(message),
        _ => CoreError::Internal(message),
    }
}

/// Remove the private staging path from worker text. The worker never sees the
/// case path, and the staged copy's name is disposable; its location is still a
/// filesystem path and does not belong in a diagnostic.
fn sanitize(message: &str, staged_dir: &Path) -> String {
    let message = message.replace(&staged_dir.display().to_string(), "<worker-staging>");
    let cleaned: String = message
        .chars()
        .filter(|character| !character.is_control())
        .take(4096)
        .collect();
    if cleaned.is_empty() {
        "the parser worker reported a failure without detail".to_string()
    } else {
        cleaned
    }
}

/// A private read-only copy of the captured object, handed to the worker so it
/// has no path to the case store. Removed when the job ends, success or not.
struct StagedInput {
    dir: PathBuf,
    path: PathBuf,
}

impl StagedInput {
    fn create(source: &Path) -> CoreResult<Self> {
        let dir = std::env::temp_dir().join(format!("ghosttrace-worker-{}", uuid::Uuid::new_v4()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir).map_err(|error| {
            CoreError::Storage(format!("create the worker staging directory: {error}"))
        })?;
        let name = match source.file_name() {
            Some(name) => name.to_os_string(),
            None => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(CoreError::InvalidInput(
                    "the captured object has no file name".to_string(),
                ));
            }
        };
        let path = dir.join(name);
        let result = (|| {
            std::fs::copy(source, &path)?;
            let copied = std::fs::metadata(&path)?.len();
            let expected = std::fs::metadata(source)?.len();
            if copied != expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the staged copy is shorter than the captured object",
                ));
            }
            Ok(())
        })();
        if let Err(error) = result {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(CoreError::Storage(format!(
                "stage the captured object for the worker: {error}"
            )));
        }
        Ok(Self { dir, path })
    }

    fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagedInput {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

//! CLI commands (plan Sections 9, 17/P2.3).
//!
//! Contract: machine-readable JSON on stdout, progress and diagnostics on
//! stderr, and documented exit codes — `0` clean, `1` failed, `2` invalid
//! usage, `3` partial result or coverage omission.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;

use ghosttrace_core::capture::copy::{
    AcquisitionOptions, CopyProgress, inspect_recovery, run_acquisition,
};
use ghosttrace_core::capture::{CaptureRoot, CaptureSpec};
use ghosttrace_core::domain::case::AcquisitionMethod;
use ghosttrace_core::domain::path::NativePath;
use ghosttrace_core::error::CoreError;
use ghosttrace_core::service::{CaseSession, CreateCaseSpec};
use ghosttrace_core::storage::CASE_DIR_SUFFIX;

use crate::output;

pub const EXIT_OK: u8 = 0;
pub const EXIT_FAILED: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_PARTIAL: u8 = 3;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[derive(Parser)]
#[command(
    name = "ghosttrace",
    version,
    about = "GhostTrace forensic workbench: local-first, evidence read-only"
)]
pub enum Cli {
    /// Print the linked SQLite/runtime verification report as JSON.
    SqliteInfo,
    /// Case lifecycle commands.
    Case {
        #[command(subcommand)]
        command: CaseCommand,
    },
    /// Capture a source folder into a case (copy + SHA-256 + coverage).
    Scan(ScanArgs),
    /// Report stored acquisitions, coverage, and recovery leftovers.
    Status(StatusArgs),
}

#[derive(Subcommand)]
pub enum CaseCommand {
    /// Create a new case directory. The path must end in `.ghosttrace-case`.
    Create(CaseCreateArgs),
}

#[derive(Args)]
pub struct CaseCreateArgs {
    /// Case directory, e.g. `/cases/investigation.ghosttrace-case`.
    #[arg(long)]
    pub case: PathBuf,
    /// Investigator-visible case label.
    #[arg(long)]
    pub label: String,
    /// Display timezone (IANA name); never applied to source timestamps.
    #[arg(long, default_value = "UTC")]
    pub timezone: String,
    /// Free-text case description.
    #[arg(long, default_value = "")]
    pub description: String,
}

#[derive(Args)]
pub struct ScanArgs {
    /// Existing case directory.
    #[arg(long)]
    pub case: PathBuf,
    /// Evidence root to capture. Repeat for multiple roots.
    #[arg(long = "source", required = true)]
    pub sources: Vec<PathBuf>,
    /// How the source was reached. `live-best-effort` is explicitly best effort.
    #[arg(long, value_enum, default_value_t = MethodArg::ProtectedCopy)]
    pub method: MethodArg,
    /// Where the source came from, as claimed by the investigator.
    #[arg(long, default_value = "not recorded")]
    pub claimed_source: String,
    /// Maximum traversal depth below each root.
    #[arg(long, default_value_t = 64)]
    pub max_depth: u32,
    /// Maximum entries visited per root.
    #[arg(long, default_value_t = 1_000_000)]
    pub max_entries: u64,
    /// Files larger than this are recorded as excluded, never read.
    #[arg(long, default_value_t = 16 * 1024 * 1024 * 1024)]
    pub max_file_bytes: u64,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum MethodArg {
    ProtectedCopy,
    LiveBestEffort,
}

#[derive(Args)]
pub struct StatusArgs {
    /// Existing case directory.
    #[arg(long)]
    pub case: PathBuf,
}

#[derive(Serialize)]
struct CaseCreated {
    case_id: String,
    case_dir: String,
    label: String,
    display_timezone: String,
}

#[derive(Serialize)]
struct CoverageCounts {
    captured: u64,
    excluded: u64,
    inaccessible: u64,
    unstable: u64,
    vanished: u64,
    unsupported: u64,
    unobserved: u64,
    hardlink_aliases: u64,
}

#[derive(Serialize)]
struct Gap {
    path: String,
    status: &'static str,
    code: &'static str,
    detail: String,
}

#[derive(Serialize)]
struct ScanOutput {
    acquisition_id: String,
    state: &'static str,
    objects: usize,
    bytes: u64,
    coverage: CoverageCounts,
    gaps: Vec<Gap>,
    manifest: Option<String>,
}

#[derive(Serialize)]
struct AcquisitionRow {
    id: String,
    method: String,
    state: String,
    started_seconds: Option<i64>,
    ended_seconds: Option<i64>,
    objects: i64,
    coverage_rows: i64,
}

#[derive(Serialize)]
struct RecoverableRow {
    job_id: String,
    kind: String,
}

#[derive(Serialize)]
struct RecoveryRow {
    abandoned_staging: usize,
    orphan_objects: usize,
}

#[derive(Serialize)]
struct StatusOutput {
    case_id: String,
    display_timezone: String,
    acquisitions: Vec<AcquisitionRow>,
    coverage: BTreeMap<String, i64>,
    recoverable_jobs: Vec<RecoverableRow>,
    recovery: RecoveryRow,
}

/// Run one parsed command and return the process exit code.
pub fn run(cli: Cli) -> u8 {
    match cli {
        Cli::SqliteInfo => {
            output::emit_json(&ghosttrace_core::sqlite_report::sqlite_report());
            EXIT_OK
        }
        Cli::Case {
            command: CaseCommand::Create(args),
        } => case_create(args),
        Cli::Scan(args) => scan(args),
        Cli::Status(args) => status(args),
    }
}

fn case_create(args: CaseCreateArgs) -> u8 {
    let (parent, id) = match split_case_directory(&args.case) {
        Ok(parts) => parts,
        Err(message) => {
            output::emit_error("invalid_layout", &message);
            return EXIT_USAGE;
        }
    };
    let spec = CreateCaseSpec {
        label: args.label,
        display_timezone: args.timezone,
        description: args.description,
    };
    match CaseSession::create(parent, &id, spec) {
        Ok(session) => {
            let created = CaseCreated {
                case_id: session.case_id().to_string(),
                case_dir: native_path(session.layout().root()).encoded(),
                label: session.config().label.clone(),
                display_timezone: session.config().display_timezone.clone(),
            };
            output::emit_json(&created);
            EXIT_OK
        }
        Err(error) => fail(&error),
    }
}

fn scan(args: ScanArgs) -> u8 {
    let session = match CaseSession::open(&args.case) {
        Ok((session, _report)) => session,
        Err(error) => return fail(&error),
    };
    let roots: Vec<CaptureRoot> = args
        .sources
        .iter()
        .enumerate()
        .map(|(index, source)| CaptureRoot {
            native: native_path(source),
            label: format!("source-{}", index + 1),
        })
        .collect();
    let spec = CaptureSpec {
        roots,
        follow_symlinks: false,
        max_depth: args.max_depth,
        max_entries: args.max_entries,
        max_file_bytes: args.max_file_bytes,
        case_directory: session.layout().root().to_path_buf(),
    };
    if let Err(error) = spec.validate().into_result() {
        return fail(&error);
    }
    let method = match args.method {
        MethodArg::ProtectedCopy => AcquisitionMethod::ProtectedCopy,
        MethodArg::LiveBestEffort => AcquisitionMethod::LiveBestEffort,
    };
    let options = AcquisitionOptions::new(method, args.claimed_source, &spec);
    transport_warning(method);

    let progress = CopyProgress::new();
    install_interrupt_handler();
    output::emit_progress(0, 0);
    let (sender, receiver) = std::sync::mpsc::channel();
    let mut last = (0u64, 0u64);
    let outcome = std::thread::scope(|scope| {
        scope.spawn(|| {
            let result = run_acquisition(&session, &spec, &options, &progress);
            let _ = sender.send(result);
        });
        loop {
            if INTERRUPTED.swap(false, Ordering::SeqCst) {
                progress.cancel();
                eprintln!("interrupt received: finishing the current file, then stopping");
            }
            match receiver.recv_timeout(Duration::from_millis(250)) {
                Ok(result) => break result,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    let snapshot = (
                        progress.bytes_copied.load(Ordering::Relaxed),
                        progress.objects_published.load(Ordering::Relaxed),
                    );
                    if snapshot != last {
                        output::emit_progress(snapshot.0, snapshot.1);
                        last = snapshot;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(CoreError::Internal("acquisition thread vanished".into()));
                }
            }
        }
    });

    let report = match outcome {
        Ok(report) => report,
        Err(error) => return fail(&error),
    };
    output::emit_progress(
        progress.bytes_copied.load(Ordering::Relaxed),
        progress.objects_published.load(Ordering::Relaxed),
    );

    let coverage = &report.coverage;
    let gaps = coverage
        .examples
        .iter()
        .map(|outcome| Gap {
            path: outcome.native_relative.encoded(),
            status: outcome.status.as_str(),
            code: outcome.reason.code(),
            detail: output::escape(outcome.reason.detail()),
        })
        .collect();
    let state = match report.state {
        ghosttrace_core::domain::case::AcquisitionState::Completed => "completed",
        ghosttrace_core::domain::case::AcquisitionState::Partial => "partial",
        ghosttrace_core::domain::case::AcquisitionState::Cancelled => "cancelled",
        ghosttrace_core::domain::case::AcquisitionState::Failed => "failed",
        ghosttrace_core::domain::case::AcquisitionState::Queued => "queued",
        ghosttrace_core::domain::case::AcquisitionState::Running => "running",
    };
    let bytes = report
        .manifest
        .as_ref()
        .map(|manifest| {
            manifest
                .objects
                .iter()
                .map(|object| object.byte_length)
                .sum()
        })
        .unwrap_or_default();
    output::emit_json(&ScanOutput {
        acquisition_id: report.acquisition_id.clone(),
        state,
        objects: report.published_objects(),
        bytes,
        coverage: CoverageCounts {
            captured: coverage.captured,
            excluded: coverage.excluded,
            inaccessible: coverage.inaccessible,
            unstable: coverage.unstable,
            vanished: coverage.vanished,
            unsupported: coverage.unsupported,
            unobserved: coverage.unobserved,
            hardlink_aliases: coverage.hardlink_aliases,
        },
        gaps,
        manifest: report
            .manifest_path
            .as_ref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .map(str::to_string),
    });
    eprintln!(
        "scan {state}: {} objects, {} captured, {} gaps",
        report.published_objects(),
        coverage.captured,
        coverage.gaps()
    );
    match report.state {
        ghosttrace_core::domain::case::AcquisitionState::Completed => EXIT_OK,
        ghosttrace_core::domain::case::AcquisitionState::Partial
        | ghosttrace_core::domain::case::AcquisitionState::Cancelled => EXIT_PARTIAL,
        _ => EXIT_FAILED,
    }
}

fn status(args: StatusArgs) -> u8 {
    let (session, open_report) = match CaseSession::open(&args.case) {
        Ok(open) => open,
        Err(error) => return fail(&error),
    };
    let reader = match session.reader() {
        Ok(reader) => reader,
        Err(error) => return fail(&error),
    };
    let connection = reader.connection();

    let acquisitions = match connection
        .prepare(
            "SELECT a.id, a.method, a.state, a.started_seconds, a.ended_seconds,
                    (SELECT count(*) FROM evidence_objects o WHERE o.acquisition_id = a.id),
                    (SELECT count(*) FROM coverage c WHERE c.acquisition_id = a.id)
             FROM acquisitions a
             ORDER BY a.started_seconds, a.id",
        )
        .and_then(|mut statement| {
            statement
                .query_map([], |row| {
                    Ok(AcquisitionRow {
                        id: row.get(0)?,
                        method: row.get(1)?,
                        state: row.get(2)?,
                        started_seconds: row.get(3)?,
                        ended_seconds: row.get(4)?,
                        objects: row.get(5)?,
                        coverage_rows: row.get(6)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()
        }) {
        Ok(rows) => rows,
        Err(error) => {
            return fail(&CoreError::Storage(format!("status acquisitions: {error}")));
        }
    };

    let coverage = match connection
        .prepare("SELECT status, count(*) FROM coverage GROUP BY status ORDER BY status")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()
        }) {
        Ok(rows) => rows.into_iter().collect(),
        Err(error) => return fail(&CoreError::Storage(format!("status coverage: {error}"))),
    };

    let recovery = match inspect_recovery(session.layout(), &reader) {
        Ok(report) => RecoveryRow {
            abandoned_staging: report.abandoned_staging.len(),
            orphan_objects: report.orphan_objects.len(),
        },
        Err(error) => return fail(&error),
    };

    let recoverable_jobs = open_report
        .recoverable_jobs
        .iter()
        .map(|job| RecoverableRow {
            job_id: job.job_id.clone(),
            kind: format!("{:?}", job.kind).to_lowercase(),
        })
        .collect();

    output::emit_json(&StatusOutput {
        case_id: session.case_id().to_string(),
        display_timezone: session.config().display_timezone.clone(),
        acquisitions,
        coverage,
        recoverable_jobs,
        recovery,
    });
    EXIT_OK
}

fn fail(error: &CoreError) -> u8 {
    output::emit_error(error.code(), &error.to_string());
    EXIT_FAILED
}

/// The plan requires the trade-off to be visible where the choice is made.
fn transport_warning(method: AcquisitionMethod) {
    match method {
        AcquisitionMethod::ProtectedCopy => eprintln!(
            "source method: protected copy (recommended). Verify the copy was made by a \
             write-blocked or equivalent process before relying on this case in production."
        ),
        AcquisitionMethod::LiveBestEffort => eprintln!(
            "source method: live best effort. Files can change or vanish during capture; \
             coverage records what was seen, and access-time metadata may be affected."
        ),
    }
}

/// Split `.../name.ghosttrace-case` into its parent and case ID.
fn split_case_directory(path: &Path) -> Result<(PathBuf, String), String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "case directory must have a UTF-8 file name".to_string())?;
    let id = name
        .strip_suffix(CASE_DIR_SUFFIX)
        .ok_or_else(|| format!("case directory must end with {CASE_DIR_SUFFIX}"))?;
    if id.is_empty() {
        return Err(format!(
            "case directory needs a name before {CASE_DIR_SUFFIX}"
        ));
    }
    let parent = path.parent().filter(|path| !path.as_os_str().is_empty());
    Ok((
        parent.unwrap_or(Path::new(".")).to_path_buf(),
        id.to_string(),
    ))
}

#[cfg(unix)]
fn native_path(path: &Path) -> NativePath {
    use std::os::unix::ffi::OsStrExt;
    NativePath::unix(path.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
fn native_path(path: &Path) -> NativePath {
    use std::os::windows::ffi::OsStrExt;
    NativePath::windows(path.as_os_str().encode_wide().collect::<Vec<u16>>())
}

#[cfg(unix)]
fn install_interrupt_handler() {
    use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
    // An async-signal-safe flag: the worker observes it between chunks and the
    // command then reports a cancelled, partial acquisition.
    unsafe {
        let action = SigAction::new(
            SigHandler::Handler(mark_interrupted),
            SaFlags::empty(),
            SigSet::empty(),
        );
        let _ = sigaction(Signal::SIGINT, &action);
    }
}

#[cfg(unix)]
extern "C" fn mark_interrupted(_signal: i32) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

#[cfg(not(unix))]
fn install_interrupt_handler() {}

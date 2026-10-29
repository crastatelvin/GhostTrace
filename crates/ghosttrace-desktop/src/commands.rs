//! Desktop command/result messages and the background worker (P6.1).
//!
//! Rules embodied here:
//! - The render pass never touches SQLite or evidence. It only builds
//!   [`Command`] values; one worker thread owns the [`CaseSession`] work.
//! - Progress and cancellation are shared atomics, so `Cancel` acts on the
//!   running copy immediately instead of queueing behind it.
//! - Every command carries a monotonically increasing id; results are tagged
//!   with it so a superseded or late result can be dropped.
//! - Errors cross the boundary as a stable machine code plus a message, never
//!   as raw evidence values.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ghosttrace_core::analysis::annotations::AppendAnnotation;
use ghosttrace_core::analysis::rules::{AnalysisRequest, RuleConfig};
use ghosttrace_core::analysis::views::SavedFilter;
use ghosttrace_core::capture::copy::{AcquisitionOptions, CopyProgress, run_acquisition};
use ghosttrace_core::capture::{CaptureRoot, CaptureSpec};
use ghosttrace_core::domain::case::AcquisitionMethod;
use ghosttrace_core::domain::path::NativePath;
use ghosttrace_core::error::{CoreError, CoreResult};
use ghosttrace_core::ingest::{ImportRequest, LogFormat, run_import};
use ghosttrace_core::integrity::manifest::ManifestV1;
use ghosttrace_core::reports::{self, ReportContext, ReportSelection};
use ghosttrace_core::service::{CaseSession, CreateCaseSpec};

use crate::state::{AcquisitionSummary, RecoveryItem};

pub type JobId = u64;

const PROGRESS_POLL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobPhase {
    Create,
    Open,
    Capture,
    Import,
    Analyze,
    Correlate,
    Annotate,
    SaveView,
    Report,
    Verify,
}

impl JobPhase {
    pub fn label(self) -> &'static str {
        match self {
            JobPhase::Create => "create case",
            JobPhase::Open => "open case",
            JobPhase::Capture => "capture",
            JobPhase::Import => "import",
            JobPhase::Analyze => "analyze",
            JobPhase::Correlate => "derive relationships",
            JobPhase::Annotate => "record note",
            JobPhase::SaveView => "save view",
            JobPhase::Report => "export report",
            JobPhase::Verify => "verify manifest",
        }
    }
}

/// A request from the UI to the worker. No core type is borrowed across the
/// channel; the worker builds the real request from these plain values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    CreateCase {
        id: JobId,
        directory: String,
        label: String,
        timezone: String,
    },
    OpenCase {
        id: JobId,
        directory: String,
    },
    Capture {
        id: JobId,
        case_directory: String,
        source: String,
        label: String,
        method: AcquisitionMethod,
        max_depth: u32,
        max_entries: u64,
        max_file_bytes: u64,
    },
    Import {
        id: JobId,
        case_directory: String,
        object_path: String,
        format: Option<LogFormat>,
        syslog_timezone: Option<String>,
        syslog_year: Option<i32>,
    },
    /// Evaluate the compiled rules against one revision (P5.2).
    Analyze {
        id: JobId,
        case_directory: String,
        revision: String,
    },
    /// Derive relationships from recorded entities (P5.1).
    Correlate {
        id: JobId,
        case_directory: String,
    },
    /// Append a note, tag set, or disposition (P5.2). Append-only.
    Annotate {
        id: JobId,
        case_directory: String,
        request: AppendAnnotation,
    },
    /// Record a named, typed filter over the shared query contract.
    SaveView {
        id: JobId,
        case_directory: String,
        name: String,
        filter: SavedFilter,
    },
    /// Export the recorded report for one acquisition. P6.4 exports
    /// unredacted reports; the redaction workflow arrives with P9.2.
    Report {
        id: JobId,
        case_directory: String,
        output: String,
        acquisition_id: Option<String>,
        revision: Option<String>,
        event_limit: u32,
        report_id: Option<String>,
    },
    /// Verify the stored bytes of one acquisition manifest.
    Verify {
        id: JobId,
        case_directory: String,
        manifest_path: Option<String>,
        acquisition_id: Option<String>,
    },
}

impl Command {
    pub fn id(&self) -> JobId {
        match self {
            Command::CreateCase { id, .. }
            | Command::OpenCase { id, .. }
            | Command::Capture { id, .. }
            | Command::Import { id, .. }
            | Command::Analyze { id, .. }
            | Command::Correlate { id, .. }
            | Command::Annotate { id, .. }
            | Command::SaveView { id, .. }
            | Command::Report { id, .. }
            | Command::Verify { id, .. } => *id,
        }
    }

    pub fn phase(&self) -> JobPhase {
        match self {
            Command::CreateCase { .. } => JobPhase::Create,
            Command::OpenCase { .. } => JobPhase::Open,
            Command::Capture { .. } => JobPhase::Capture,
            Command::Import { .. } => JobPhase::Import,
            Command::Analyze { .. } => JobPhase::Analyze,
            Command::Correlate { .. } => JobPhase::Correlate,
            Command::Annotate { .. } => JobPhase::Annotate,
            Command::SaveView { .. } => JobPhase::SaveView,
            Command::Report { .. } => JobPhase::Report,
            Command::Verify { .. } => JobPhase::Verify,
        }
    }
}

/// A completed command's user-facing outcome. Deliberately a small value type:
/// the session and every core type stay inside the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    CaseCreated {
        directory: String,
        /// Absolute case database path for the read-only query worker. The
        /// desktop only accepts UTF-8 paths, so this conversion loses nothing.
        database_path: String,
        label: String,
        timezone: String,
    },
    CaseOpened {
        directory: String,
        database_path: String,
        label: String,
        timezone: String,
        /// Active revision at open time; `None` when the case has no parse run.
        revision: Option<String>,
        acquisitions: Vec<AcquisitionSummary>,
        recovery: Vec<RecoveryItem>,
    },
    Captured {
        acquisition_id: String,
        state: String,
        objects: usize,
        gaps: u64,
    },
    Imported {
        run_id: String,
        state: String,
        events: u64,
    },
    Analyzed {
        run_id: String,
        state: String,
        findings: usize,
    },
    Correlated {
        derived: u64,
        inserted: u64,
        truncated: bool,
    },
    Annotated {
        target_id: String,
        revision_id: i64,
    },
    ViewSaved {
        name: String,
    },
    ReportPublished {
        report_id: String,
        directory: String,
        json: String,
        html: String,
        objects: usize,
        events: usize,
        gaps: u64,
    },
    /// The report job observed a cancel request and published nothing.
    ReportCancelled,
    Verified {
        manifest_id: String,
        acquisition_id: String,
        format: String,
        objects: u64,
        total_bytes: u64,
        captured: u64,
        gaps: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandEvent {
    Started {
        id: JobId,
        phase: JobPhase,
    },
    Progress {
        id: JobId,
        objects: u64,
        bytes: u64,
    },
    Finished {
        id: JobId,
        outcome: Outcome,
    },
    Failed {
        id: JobId,
        phase: JobPhase,
        code: String,
        message: String,
    },
}

#[derive(Default)]
struct Registry {
    handles: Mutex<HashMap<JobId, CancelHandle>>,
    /// Cancel requests that arrived before the worker registered its handle.
    pre_cancelled: Mutex<HashSet<JobId>>,
}

#[derive(Clone)]
struct CancelHandle {
    copy: Option<Arc<CopyProgress>>,
    import: Arc<AtomicBool>,
}

impl CancelHandle {
    fn cancel(&self) {
        if let Some(copy) = &self.copy {
            copy.cancel();
        }
        self.import.store(true, Ordering::Relaxed);
    }
}

impl Registry {
    fn register(&self, id: JobId, handle: CancelHandle) {
        let cancelled = self
            .pre_cancelled
            .lock()
            .expect("cancel registry")
            .remove(&id);
        self.handles
            .lock()
            .expect("cancel registry")
            .insert(id, handle.clone());
        if cancelled {
            handle.cancel();
        }
    }

    fn cancel(&self, id: JobId) {
        let handle = self
            .handles
            .lock()
            .expect("cancel registry")
            .get(&id)
            .cloned();
        match handle {
            Some(handle) => handle.cancel(),
            None => {
                self.pre_cancelled
                    .lock()
                    .expect("cancel registry")
                    .insert(id);
            }
        }
    }

    fn finish(&self, id: JobId) {
        self.handles.lock().expect("cancel registry").remove(&id);
        self.pre_cancelled
            .lock()
            .expect("cancel registry")
            .remove(&id);
    }
}

/// The UI side of the worker: send commands, receive events, cancel by id.
pub struct CommandBus {
    commands: Sender<Command>,
    events: Receiver<CommandEvent>,
    registry: Arc<Registry>,
}

impl CommandBus {
    /// Start the single background worker. It exits when the bus is dropped.
    pub fn spawn() -> std::io::Result<Self> {
        let (command_tx, command_rx) = channel();
        let (event_tx, event_rx) = channel();
        let registry = Arc::new(Registry::default());
        let worker_registry = Arc::clone(&registry);
        std::thread::Builder::new()
            .name("ghosttrace-desktop-worker".into())
            .spawn(move || worker(command_rx, event_tx, worker_registry))?;
        Ok(Self {
            commands: command_tx,
            events: event_rx,
            registry,
        })
    }

    pub fn send(&self, command: Command) {
        // A closed channel means the worker stopped; the UI keeps running and
        // the command's absence shows up as a job that never starts.
        let _ = self.commands.send(command);
    }

    pub fn cancel(&self, id: JobId) {
        self.registry.cancel(id);
    }

    /// Non-blocking drain; the render loop never waits for the worker.
    pub fn try_recv(&self) -> Option<CommandEvent> {
        self.events.try_recv().ok()
    }
}

fn worker(commands: Receiver<Command>, events: Sender<CommandEvent>, registry: Arc<Registry>) {
    while let Ok(command) = commands.recv() {
        let id = command.id();
        let phase = command.phase();
        if events.send(CommandEvent::Started { id, phase }).is_err() {
            return;
        }
        let result = match command {
            Command::CreateCase {
                directory,
                label,
                timezone,
                ..
            } => create_case(&directory, label, timezone),
            Command::OpenCase { directory, .. } => open_case(&directory),
            Command::Capture {
                case_directory,
                source,
                label,
                method,
                max_depth,
                max_entries,
                max_file_bytes,
                ..
            } => capture(
                &events,
                &registry,
                id,
                &case_directory,
                &source,
                label,
                method,
                max_depth,
                max_entries,
                max_file_bytes,
            ),
            Command::Import {
                case_directory,
                object_path,
                format,
                syslog_timezone,
                syslog_year,
                ..
            } => import(
                &registry,
                id,
                &case_directory,
                &object_path,
                format,
                syslog_timezone,
                syslog_year,
            ),
            Command::Analyze {
                case_directory,
                revision,
                ..
            } => analyze(&case_directory, revision),
            Command::Correlate { case_directory, .. } => correlate(&case_directory),
            Command::Annotate {
                case_directory,
                request,
                ..
            } => annotate(&case_directory, request),
            Command::SaveView {
                case_directory,
                name,
                filter,
                ..
            } => save_view(&case_directory, &name, &filter),
            Command::Report {
                case_directory,
                output,
                acquisition_id,
                revision,
                event_limit,
                report_id,
                ..
            } => export_report(
                &registry,
                id,
                &case_directory,
                &output,
                acquisition_id,
                revision,
                event_limit,
                report_id,
            ),
            Command::Verify {
                case_directory,
                manifest_path,
                acquisition_id,
                ..
            } => verify_manifest(&case_directory, manifest_path, acquisition_id),
        };
        registry.finish(id);
        let event = match result {
            Ok(outcome) => CommandEvent::Finished { id, outcome },
            Err(error) => CommandEvent::Failed {
                id,
                phase,
                code: error.code().to_string(),
                message: error.to_string(),
            },
        };
        if events.send(event).is_err() {
            return;
        }
    }
}

fn create_case(directory: &str, label: String, timezone: String) -> CoreResult<Outcome> {
    let (parent, id) = split_case_directory(Path::new(directory))?;
    let label = if label.trim().is_empty() {
        id.clone()
    } else {
        label
    };
    let spec = CreateCaseSpec {
        label: label.clone(),
        display_timezone: timezone.clone(),
        description: String::new(),
    };
    let session = CaseSession::create(parent, &id, spec)?;
    Ok(Outcome::CaseCreated {
        directory: native_path(session.layout().root()).encoded(),
        database_path: session
            .layout()
            .database_path()
            .to_string_lossy()
            .into_owned(),
        label,
        timezone,
    })
}

fn open_case(directory: &str) -> CoreResult<Outcome> {
    let (session, report) = CaseSession::open(PathBuf::from(directory))?;
    let reader = session.reader()?;
    let acquisitions = list_acquisitions(&reader)?;
    let revision = reader.latest_revision(None)?;
    Ok(Outcome::CaseOpened {
        directory: native_path(session.layout().root()).encoded(),
        database_path: session
            .layout()
            .database_path()
            .to_string_lossy()
            .into_owned(),
        label: session.config().label.clone(),
        timezone: session.config().display_timezone.clone(),
        revision,
        acquisitions,
        recovery: report
            .recoverable_jobs
            .iter()
            .map(|job| RecoveryItem {
                job_id: job.job_id.clone(),
                kind: job.kind.as_str().to_string(),
                committed_locator: job.committed_locator.clone(),
            })
            .collect(),
    })
}

#[allow(clippy::too_many_arguments)]
fn capture(
    events: &Sender<CommandEvent>,
    registry: &Registry,
    id: JobId,
    case_directory: &str,
    source: &str,
    label: String,
    method: AcquisitionMethod,
    max_depth: u32,
    max_entries: u64,
    max_file_bytes: u64,
) -> CoreResult<Outcome> {
    let (session, _report) = CaseSession::open(PathBuf::from(case_directory))?;
    let source_path = PathBuf::from(source);
    let root_label = if label.trim().is_empty() {
        source.to_string()
    } else {
        label
    };
    let spec = CaptureSpec {
        roots: vec![CaptureRoot {
            native: native_from_path(&source_path),
            label: root_label.clone(),
        }],
        follow_symlinks: false,
        max_depth,
        max_entries,
        max_file_bytes,
        case_directory: session.layout().root().to_path_buf(),
    };
    // Reject overlap before the walker touches the filesystem.
    spec.validate().into_result()?;
    let options = AcquisitionOptions::new(method, root_label, &spec);
    let progress = Arc::new(CopyProgress::new());
    registry.register(
        id,
        CancelHandle {
            copy: Some(Arc::clone(&progress)),
            import: Arc::new(AtomicBool::new(false)),
        },
    );
    let stop = Arc::new(AtomicBool::new(false));
    let reporter = {
        let events = events.clone();
        let progress = Arc::clone(&progress);
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("ghosttrace-desktop-progress".into())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(PROGRESS_POLL);
                    let objects = progress.objects_published.load(Ordering::Relaxed);
                    let bytes = progress.bytes_copied.load(Ordering::Relaxed);
                    if events
                        .send(CommandEvent::Progress { id, objects, bytes })
                        .is_err()
                    {
                        return;
                    }
                }
            })
            .ok()
    };
    let result = run_acquisition(&session, &spec, &options, &progress);
    stop.store(true, Ordering::Relaxed);
    if let Some(reporter) = reporter {
        let _ = reporter.join();
    }
    let report = result?;
    let objects = report.published_objects();
    let state = report.state.as_str().to_string();
    let coverage = &report.coverage;
    Ok(Outcome::Captured {
        acquisition_id: report.acquisition_id,
        state,
        objects,
        gaps: coverage.excluded
            + coverage.inaccessible
            + coverage.unstable
            + coverage.vanished
            + coverage.unsupported
            + coverage.unobserved,
    })
}

fn import(
    registry: &Registry,
    id: JobId,
    case_directory: &str,
    object_path: &str,
    format: Option<LogFormat>,
    syslog_timezone: Option<String>,
    syslog_year: Option<i32>,
) -> CoreResult<Outcome> {
    let (session, _report) = CaseSession::open(PathBuf::from(case_directory))?;
    let reader = session.reader()?;
    let cancelled = Arc::new(AtomicBool::new(false));
    registry.register(
        id,
        CancelHandle {
            copy: None,
            import: Arc::clone(&cancelled),
        },
    );
    let worker = std::env::current_exe()
        .ok()
        .and_then(|exe| ghosttrace_core::worker::WorkerBinary::resolve_beside(&exe).ok());
    let mut request = ImportRequest::new(&cancelled);
    request.worker = worker.map(|worker| worker.path().to_path_buf());
    request.isolation_required = true;
    request.path = Some(object_path.to_string());
    request.format = format;
    request.syslog.timezone = syslog_timezone;
    request.syslog.year = syslog_year;
    let outcome = run_import(&reader, session.writer(), session.layout().root(), &request)?;
    Ok(Outcome::Imported {
        run_id: outcome.run_id,
        state: outcome.state,
        events: outcome.events,
    })
}

fn analyze(case_directory: &str, revision: String) -> CoreResult<Outcome> {
    let (session, _report) = CaseSession::open(PathBuf::from(case_directory))?;
    let report = session.analyze(&AnalysisRequest {
        revision,
        config: RuleConfig::default(),
    })?;
    Ok(Outcome::Analyzed {
        run_id: report.run_id,
        state: report.state,
        findings: report.findings.len(),
    })
}

fn correlate(case_directory: &str) -> CoreResult<Outcome> {
    let (session, _report) = CaseSession::open(PathBuf::from(case_directory))?;
    let report =
        session.correlate(&ghosttrace_core::analysis::correlate::CorrelateConfig::default())?;
    Ok(Outcome::Correlated {
        derived: report.derived,
        inserted: report.inserted,
        truncated: report.truncated,
    })
}

fn annotate(case_directory: &str, request: AppendAnnotation) -> CoreResult<Outcome> {
    let (session, _report) = CaseSession::open(PathBuf::from(case_directory))?;
    let revision = session.append_annotation(&request)?;
    Ok(Outcome::Annotated {
        target_id: revision.target_id,
        revision_id: revision.id,
    })
}

fn save_view(case_directory: &str, name: &str, filter: &SavedFilter) -> CoreResult<Outcome> {
    let (session, _report) = CaseSession::open(PathBuf::from(case_directory))?;
    session.save_view(name, filter)?;
    Ok(Outcome::ViewSaved {
        name: name.to_string(),
    })
}

#[allow(clippy::too_many_arguments)]
fn export_report(
    registry: &Registry,
    id: JobId,
    case_directory: &str,
    output: &str,
    acquisition_id: Option<String>,
    revision: Option<String>,
    event_limit: u32,
    report_id: Option<String>,
) -> CoreResult<Outcome> {
    let cancelled = Arc::new(AtomicBool::new(false));
    registry.register(
        id,
        CancelHandle {
            copy: None,
            import: Arc::clone(&cancelled),
        },
    );
    // A cancel that arrived before the job started must publish nothing.
    if cancelled.load(Ordering::Relaxed) {
        return Ok(Outcome::ReportCancelled);
    }
    let (session, _open) = CaseSession::open(PathBuf::from(case_directory))?;
    let reader = session.reader()?;
    let context = ReportContext {
        case_id: session.case_id().to_string(),
        label: session.config().label.clone(),
        display_timezone: session.config().display_timezone.clone(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_by: "ghosttrace-desktop".to_string(),
    };
    let selection = ReportSelection {
        acquisition_id,
        revision,
        event_limit,
    };
    let mut report = reports::build_report(&reader, &context, &selection)?;
    if let Some(report_id) = report_id.filter(|id| !id.trim().is_empty()) {
        if !report_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
            || report_id.starts_with('.')
        {
            return Err(CoreError::InvalidInput(
                "report id may only contain letters, digits, '-', '_' and '.'".into(),
            ));
        }
        report.report_id = report_id;
    }
    if cancelled.load(Ordering::Relaxed) {
        return Ok(Outcome::ReportCancelled);
    }
    let published = reports::publish(&report, Path::new(output))?;
    Ok(Outcome::ReportPublished {
        report_id: report.report_id.clone(),
        directory: native_path(&published.directory).encoded(),
        json: native_path(&published.json_path).encoded(),
        html: native_path(&published.html_path).encoded(),
        objects: report.objects.len(),
        events: report.timeline.len(),
        gaps: report.coverage.total_gaps(),
    })
}

fn verify_manifest(
    case_directory: &str,
    manifest_path: Option<String>,
    acquisition_id: Option<String>,
) -> CoreResult<Outcome> {
    let (session, _open) = CaseSession::open(PathBuf::from(case_directory))?;
    let path = match manifest_path.filter(|path| !path.trim().is_empty()) {
        Some(path) => PathBuf::from(path),
        None => {
            let acquisition = match acquisition_id {
                Some(id) => id,
                None => {
                    let reader = session.reader()?;
                    list_acquisitions(&reader)?
                        .into_iter()
                        .next()
                        .map(|summary| summary.acquisition_id)
                        .ok_or_else(|| {
                            CoreError::InvalidInput("no acquisition in this case".into())
                        })?
                }
            };
            session
                .layout()
                .manifests_root()
                .join(format!("manifest-{acquisition}.json"))
        }
    };
    let result = ManifestV1::verify_file(&path, session.layout().root())?;
    Ok(Outcome::Verified {
        manifest_id: result.manifest_id,
        acquisition_id: result.acquisition_id,
        format: result.format,
        objects: result.objects_verified as u64,
        total_bytes: result.total_bytes,
        captured: result.captured,
        gaps: result.gaps,
    })
}

fn list_acquisitions(
    reader: &ghosttrace_core::storage::read::CaseReader,
) -> CoreResult<Vec<AcquisitionSummary>> {
    let mut statement = reader
        .connection()
        // `acquisitions` records `started_seconds`, not a created timestamp.
        // Newest first, then id, matching the report builder's selection.
        .prepare(
            "SELECT id, state FROM acquisitions
             ORDER BY started_seconds DESC, id LIMIT 50",
        )
        .map_err(|error| CoreError::Storage(format!("prepare acquisitions: {error}")))?;
    let rows = statement
        .query_map([], |row| {
            Ok(AcquisitionSummary {
                acquisition_id: row.get(0)?,
                state: row.get(1)?,
            })
        })
        .map_err(|error| CoreError::Storage(format!("read acquisitions: {error}")))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| CoreError::Storage(format!("read acquisitions: {error}")))
}

/// Split `.../name.ghosttrace-case` into its parent and case id, matching the
/// CLI's layout rule. The case id is never taken from free-form input.
fn split_case_directory(path: &Path) -> CoreResult<(PathBuf, String)> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            CoreError::InvalidInput("case directory needs a name ending in .ghosttrace-case".into())
        })?;
    let id = name.strip_suffix(".ghosttrace-case").ok_or_else(|| {
        CoreError::InvalidInput("case directory must end with .ghosttrace-case".into())
    })?;
    if id.is_empty() {
        return Err(CoreError::InvalidInput(
            "case directory name needs a part before .ghosttrace-case".into(),
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    Ok((
        parent.map_or_else(|| PathBuf::from("."), Path::to_path_buf),
        id.to_string(),
    ))
}

#[cfg(unix)]
fn native_from_path(path: &Path) -> NativePath {
    use std::os::unix::ffi::OsStrExt;
    NativePath::unix(path.as_os_str().as_bytes().to_vec())
}

#[cfg(windows)]
fn native_from_path(path: &Path) -> NativePath {
    use std::os::windows::ffi::OsStrExt;
    NativePath::windows(path.as_os_str().encode_wide().collect::<Vec<_>>())
}

fn native_path(path: &Path) -> NativePath {
    native_from_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_directories_need_the_documented_suffix() {
        let (parent, id) = split_case_directory(Path::new("/tmp/demo.ghosttrace-case")).unwrap();
        assert_eq!(parent, PathBuf::from("/tmp"));
        assert_eq!(id, "demo");

        assert!(split_case_directory(Path::new("/tmp/demo")).is_err());
        assert!(split_case_directory(Path::new("/tmp/.ghosttrace-case")).is_err());
    }

    #[test]
    fn cancel_before_registration_is_not_lost() {
        let registry = Registry::default();
        registry.cancel(7);
        let flag = Arc::new(AtomicBool::new(false));
        registry.register(
            7,
            CancelHandle {
                copy: None,
                import: Arc::clone(&flag),
            },
        );
        assert!(flag.load(Ordering::Relaxed));
        registry.finish(7);
        assert!(registry.handles.lock().unwrap().is_empty());
    }
}

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

use ghosttrace_core::capture::copy::{AcquisitionOptions, CopyProgress, run_acquisition};
use ghosttrace_core::capture::{CaptureRoot, CaptureSpec};
use ghosttrace_core::domain::case::AcquisitionMethod;
use ghosttrace_core::domain::path::NativePath;
use ghosttrace_core::error::{CoreError, CoreResult};
use ghosttrace_core::ingest::{ImportRequest, LogFormat, run_import};
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
}

impl JobPhase {
    pub fn label(self) -> &'static str {
        match self {
            JobPhase::Create => "create case",
            JobPhase::Open => "open case",
            JobPhase::Capture => "capture",
            JobPhase::Import => "import",
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
}

impl Command {
    pub fn id(&self) -> JobId {
        match self {
            Command::CreateCase { id, .. }
            | Command::OpenCase { id, .. }
            | Command::Capture { id, .. }
            | Command::Import { id, .. } => *id,
        }
    }

    pub fn phase(&self) -> JobPhase {
        match self {
            Command::CreateCase { .. } => JobPhase::Create,
            Command::OpenCase { .. } => JobPhase::Open,
            Command::Capture { .. } => JobPhase::Capture,
            Command::Import { .. } => JobPhase::Import,
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
    let mut request = ImportRequest::new(&cancelled);
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

fn list_acquisitions(
    reader: &ghosttrace_core::storage::read::CaseReader,
) -> CoreResult<Vec<AcquisitionSummary>> {
    let mut statement = reader
        .connection()
        .prepare("SELECT id, state FROM acquisitions ORDER BY created_seconds DESC, id LIMIT 50")
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

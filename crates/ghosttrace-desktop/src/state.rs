//! Desktop state and the command/result reducer (P6.1).
//!
//! The render pass only reads and writes this value; it never opens a case,
//! SQLite database, or evidence file. Commands leave through
//! `take_commands()` and results enter through `apply()`, which drops events
//! whose job id is no longer current.

use eframe::egui;
use ghosttrace_core::domain::case::AcquisitionMethod;
use ghosttrace_core::ingest::LogFormat;

use crate::commands::{Command, CommandEvent, JobId, JobPhase, Outcome};

const MAX_NOTICES: usize = 8;
pub const DEFAULT_MAX_DEPTH: u32 = 8;
pub const DEFAULT_MAX_ENTRIES: u64 = 100_000;
pub const DEFAULT_MAX_FILE_BYTES: u64 = 1 << 30;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Screen {
    #[default]
    Cases,
    Import,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatChoice {
    Auto,
    Jsonl,
    Syslog5424,
    Syslog3164,
    JournalExport,
    Browser,
}

impl FormatChoice {
    pub const ALL: [FormatChoice; 6] = [
        FormatChoice::Auto,
        FormatChoice::Jsonl,
        FormatChoice::Syslog5424,
        FormatChoice::Syslog3164,
        FormatChoice::JournalExport,
        FormatChoice::Browser,
    ];

    pub fn label(self) -> &'static str {
        match self {
            FormatChoice::Auto => "Auto-detect",
            FormatChoice::Jsonl => "JSONL",
            FormatChoice::Syslog5424 => "Syslog RFC 5424",
            FormatChoice::Syslog3164 => "Syslog RFC 3164",
            FormatChoice::JournalExport => "Journal export",
            FormatChoice::Browser => "Browser history",
        }
    }

    pub fn format(self) -> Option<LogFormat> {
        match self {
            FormatChoice::Auto => None,
            FormatChoice::Jsonl => Some(LogFormat::Jsonl),
            FormatChoice::Syslog5424 => Some(LogFormat::Syslog5424),
            FormatChoice::Syslog3164 => Some(LogFormat::Syslog3164),
            FormatChoice::JournalExport => Some(LogFormat::JournalExport),
            FormatChoice::Browser => Some(LogFormat::Browser),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Idle,
    Running,
    Finished,
    Failed,
}

impl JobState {
    pub fn label(self) -> &'static str {
        match self {
            JobState::Idle => "idle",
            JobState::Running => "running",
            JobState::Finished => "finished",
            JobState::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct JobView {
    pub id: Option<JobId>,
    pub phase: Option<JobPhase>,
    pub state: JobState,
    pub message: String,
    /// `Some` only when the phase can estimate completion (capture).
    pub progress: Option<f32>,
}

impl Default for JobView {
    fn default() -> Self {
        Self {
            id: None,
            phase: None,
            state: JobState::Idle,
            message: "no job has run".into(),
            progress: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeLevel {
    Info,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub level: NoticeLevel,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquisitionSummary {
    pub acquisition_id: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryItem {
    pub job_id: String,
    pub kind: String,
    pub committed_locator: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenCaseView {
    pub directory: String,
    pub label: String,
    pub timezone: String,
    pub acquisitions: Vec<AcquisitionSummary>,
    pub recovery: Vec<RecoveryItem>,
}

#[derive(Debug, Clone, Default)]
pub struct CaseForm {
    pub directory: String,
    pub label: String,
    pub timezone: String,
    pub open_directory: String,
}

#[derive(Debug, Clone)]
pub struct ImportForm {
    pub source: String,
    pub label: String,
    pub method: AcquisitionMethod,
    pub object_path: String,
    pub format: FormatChoice,
    pub syslog_timezone: String,
    pub syslog_year: String,
}

impl Default for ImportForm {
    fn default() -> Self {
        Self {
            source: String::new(),
            label: String::new(),
            method: AcquisitionMethod::ProtectedCopy,
            object_path: String::new(),
            format: FormatChoice::Auto,
            syslog_timezone: String::new(),
            syslog_year: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AppState {
    pub screen: Screen,
    pub case_form: CaseForm,
    pub import_form: ImportForm,
    pub open: Option<OpenCaseView>,
    pub job: JobView,
    pub notices: Vec<Notice>,
    pub show_recovery: bool,
    next_id: u64,
    pending: Vec<Command>,
    cancels: Vec<JobId>,
}

impl AppState {
    pub fn new() -> Self {
        let mut state = Self::default();
        state.case_form.timezone = "UTC".into();
        state.import_form.syslog_timezone = "UTC".into();
        state
    }

    pub fn is_running(&self) -> bool {
        self.job.state == JobState::Running
    }

    /// Queue a command under a fresh id. Refused while another job runs, so
    /// two workers can never race over one case.
    pub fn start(&mut self, build: impl FnOnce(JobId) -> Command) {
        if self.is_running() {
            self.notice_error("a job is already running; cancel it before starting another");
            return;
        }
        self.next_id += 1;
        let id = self.next_id;
        let command = build(id);
        self.job = JobView {
            id: Some(id),
            phase: Some(command.phase()),
            state: JobState::Running,
            message: format!("{} queued", command.phase().label()),
            progress: None,
        };
        self.pending.push(command);
    }

    pub fn request_cancel(&mut self) {
        if let Some(id) = self.job.id
            && self.is_running()
        {
            self.cancels.push(id);
            self.job.message = "cancelling; the current chunk finishes first".into();
        }
    }

    pub fn take_commands(&mut self) -> Vec<Command> {
        std::mem::take(&mut self.pending)
    }

    pub fn take_cancels(&mut self) -> Vec<JobId> {
        std::mem::take(&mut self.cancels)
    }

    pub fn notice_info(&mut self, text: impl Into<String>) {
        self.push_notice(NoticeLevel::Info, text.into());
    }

    pub fn notice_error(&mut self, text: impl Into<String>) {
        self.push_notice(NoticeLevel::Error, text.into());
    }

    fn push_notice(&mut self, level: NoticeLevel, text: String) {
        if self.notices.len() == MAX_NOTICES {
            self.notices.remove(0);
        }
        self.notices.push(Notice { level, text });
    }

    fn current(&self, id: JobId) -> bool {
        self.job.id == Some(id) && self.is_running()
    }

    /// Apply one worker result. Late or superseded results change nothing.
    pub fn apply(&mut self, event: CommandEvent) {
        match event {
            CommandEvent::Started { id, phase } => {
                if self.current(id) {
                    self.job.phase = Some(phase);
                    self.job.message = format!("{} started", phase.label());
                }
            }
            CommandEvent::Progress { id, objects, bytes } => {
                if self.current(id) {
                    self.job.message = format!("{objects} objects · {bytes} bytes copied");
                    self.job.progress = None;
                }
            }
            CommandEvent::Finished { id, outcome } => {
                if !self.current(id) {
                    return;
                }
                self.job.state = JobState::Finished;
                self.job.progress = Some(1.0);
                self.apply_outcome(outcome);
            }
            CommandEvent::Failed {
                id,
                phase,
                code,
                message,
            } => {
                if !self.current(id) {
                    return;
                }
                self.job.state = JobState::Failed;
                self.job.message = format!("{} failed", phase.label());
                self.notice_error(format!("{code}: {message}"));
            }
        }
    }

    fn apply_outcome(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::CaseCreated {
                directory,
                label,
                timezone,
            } => {
                self.job.message = format!("case created: {label}");
                self.notice_info(format!("case created: {directory}"));
                self.open = Some(OpenCaseView {
                    directory,
                    label,
                    timezone,
                    acquisitions: Vec::new(),
                    recovery: Vec::new(),
                });
                self.screen = Screen::Import;
                self.show_recovery = false;
            }
            Outcome::CaseOpened {
                directory,
                label,
                timezone,
                acquisitions,
                recovery,
            } => {
                self.job.message = format!("case opened: {label}");
                self.notice_info(format!(
                    "case opened with {} recorded capture(s)",
                    acquisitions.len()
                ));
                self.show_recovery = !recovery.is_empty();
                self.open = Some(OpenCaseView {
                    directory,
                    label,
                    timezone,
                    acquisitions,
                    recovery,
                });
            }
            Outcome::Captured {
                acquisition_id,
                state,
                objects,
                gaps,
            } => {
                self.job.message = format!("capture {state}: {objects} object(s)");
                self.notice_info(format!(
                    "capture {acquisition_id} {state}: {objects} object(s), {gaps} gap(s)"
                ));
                if let Some(open) = self.open.as_mut() {
                    open.acquisitions.insert(
                        0,
                        AcquisitionSummary {
                            acquisition_id,
                            state,
                        },
                    );
                }
            }
            Outcome::Imported {
                run_id,
                state,
                events,
            } => {
                self.job.message = format!("import {state}: {events} event(s)");
                self.notice_info(format!("import {run_id} {state}: {events} event(s)"));
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("ghosttrace-header").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("GhostTrace");
                ui.separator();
                match &self.open {
                    Some(open) => {
                        ui.label(format!("Case: {}", open.label));
                        ui.separator();
                        ui.label(format!("Time zone: {}", open.timezone));
                    }
                    None => {
                        ui.label("No case open");
                    }
                }
            });
            ui.horizontal(|ui| {
                if ui
                    .selectable_label(self.screen == Screen::Cases, "Cases")
                    .clicked()
                {
                    self.screen = Screen::Cases;
                }
                if ui
                    .selectable_label(self.screen == Screen::Import, "Import evidence")
                    .clicked()
                {
                    if self.open.is_some() {
                        self.screen = Screen::Import;
                    } else {
                        self.notice_error("open or create a case before importing evidence");
                    }
                }
            });
        });

        egui::Panel::bottom("ghosttrace-job").show(ui, |ui| {
            ui.horizontal(|ui| {
                let phase = self.job.phase.map(JobPhase::label).unwrap_or("no phase");
                ui.label(format!("Job: {} ({phase})", self.job.state.label()));
                ui.separator();
                ui.label(&self.job.message);
                if self.is_running() && ui.button("Cancel").clicked() {
                    self.request_cancel();
                }
            });
            if let Some(progress) = self.job.progress {
                ui.add(egui::ProgressBar::new(progress).show_percentage());
            } else if self.is_running() {
                ui.add(egui::ProgressBar::new(0.0).animate(true));
            }
        });

        egui::CentralPanel::default().show(ui, |ui| {
            if !self.notices.is_empty() {
                for notice in &self.notices {
                    let prefix = match notice.level {
                        NoticeLevel::Info => "Info",
                        NoticeLevel::Error => "Error",
                    };
                    ui.label(format!("{prefix}: {}", notice.text));
                }
                ui.separator();
            }
            match self.screen {
                Screen::Cases => crate::cases::ui(self, ui),
                Screen::Import => crate::import::ui(self, ui),
            }
        });
    }
}

/// A labeled text field: the label is the control's accessible name, so tests
/// (and screen readers) can address the field by name instead of position.
pub(crate) fn labeled_text(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        let label = ui.label(label);
        ui.add(egui::TextEdit::singleline(value))
            .labelled_by(label.id);
    });
}

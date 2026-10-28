//! Desktop state and the command/result reducer (P6.1).
//!
//! The render pass only reads and writes this value; it never opens a case,
//! SQLite database, or evidence file. Commands leave through
//! `take_commands()` and results enter through `apply()`, which drops events
//! whose job id is no longer current.

use eframe::egui;
use ghosttrace_core::domain::case::AcquisitionMethod;
use ghosttrace_core::domain::detail::{EventDetail, Histogram};
use ghosttrace_core::domain::query::{EventPage, EventQuery, EventRow, TimeCursor};
use ghosttrace_core::ingest::LogFormat;

use crate::commands::{Command, CommandEvent, JobId, JobPhase, Outcome};
use crate::query::{QueryRequest, QueryResult, QueryTarget};

const MAX_NOTICES: usize = 8;
pub const DEFAULT_MAX_DEPTH: u32 = 8;
pub const DEFAULT_MAX_ENTRIES: u64 = 100_000;
pub const DEFAULT_MAX_FILE_BYTES: u64 = 1 << 30;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Screen {
    #[default]
    Cases,
    Import,
    Timeline,
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

/// One page of timeline rows. Bounded by the core query contract.
pub const TIMELINE_PAGE_SIZE: u32 = 200;
/// The desktop never caches more than this many rows, whatever the scroll
/// position; narrowing the filters is the documented way to see more.
pub const TIMELINE_MAX_ROWS: usize = 1000;
/// Typing pause before a search/filter query is issued.
pub const SEARCH_DEBOUNCE_SECONDS: f64 = 0.35;
/// Histogram bins requested for the current filter scope.
pub const HISTOGRAM_BINS: u32 = 24;

/// Filters shown in the timeline. Structured fields only: the text goes
/// through the same validated search grammar as the CLI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimelineFilters {
    pub text: String,
    pub kind: String,
    pub host: String,
    pub source: String,
    pub unresolved_only: bool,
    /// Selected histogram bin, `[start, end)` in Unix seconds.
    pub window: Option<(i64, i64)>,
}

impl TimelineFilters {
    pub fn query(&self, revision: &str, limit: u32) -> EventQuery {
        EventQuery {
            revision: revision.to_string(),
            kind: non_empty(&self.kind),
            host: non_empty(&self.host),
            source: non_empty(&self.source),
            after_seconds: self.window.map(|(start, _)| start),
            before_seconds: self.window.map(|(_, end)| end),
            unresolved_only: self.unresolved_only,
            limit,
            after: None,
        }
    }
}

/// Timeline view state: filters, bounded page cache, histogram, selection, and
/// the generation counters that make superseded results harmless.
#[derive(Debug, Clone)]
pub struct TimelineState {
    pub revision: Option<String>,
    pub display_timezone: String,
    pub filters: TimelineFilters,
    pub events: Vec<EventRow>,
    pub next_cursor: Option<TimeCursor>,
    pub histogram: Option<Histogram>,
    pub selected: Option<String>,
    pub detail: Option<EventDetail>,
    pub status: String,
    /// The cache hit [`TIMELINE_MAX_ROWS`]; more rows exist but are not loaded.
    pub truncated: bool,
    generation: u64,
    detail_generation: u64,
    loading: bool,
    loading_first_page: bool,
    needs_refresh: bool,
    debounce_deadline: Option<f64>,
    /// Id of the search field, for the `/` shortcut.
    pub search_id: Option<egui::Id>,
}

impl Default for TimelineState {
    fn default() -> Self {
        Self::new("UTC")
    }
}

impl TimelineState {
    pub fn new(display_timezone: impl Into<String>) -> Self {
        Self {
            revision: None,
            display_timezone: display_timezone.into(),
            filters: TimelineFilters::default(),
            events: Vec::new(),
            next_cursor: None,
            histogram: None,
            selected: None,
            detail: None,
            status: "no events loaded".into(),
            truncated: false,
            generation: 0,
            detail_generation: 0,
            loading: false,
            loading_first_page: false,
            needs_refresh: false,
            debounce_deadline: None,
            search_id: None,
        }
    }

    /// Point the timeline at a revision (or none) and request a fresh first
    /// page on the next tick.
    pub fn reset(&mut self, revision: Option<String>) {
        self.revision = revision;
        self.events.clear();
        self.next_cursor = None;
        self.histogram = None;
        self.selected = None;
        self.detail = None;
        self.truncated = false;
        self.loading = false;
        self.loading_first_page = false;
        self.debounce_deadline = None;
        self.needs_refresh = true;
        self.status = if self.revision.is_some() {
            "loading events…".into()
        } else {
            "this case has no parse run yet".into()
        };
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn detail_generation(&self) -> u64 {
        self.detail_generation
    }

    pub fn is_loading(&self) -> bool {
        self.loading
    }

    pub fn is_debouncing(&self) -> bool {
        self.debounce_deadline.is_some()
    }

    /// Typing schedules one query after a pause instead of one per keystroke.
    pub fn schedule_search(&mut self, now: f64) {
        self.debounce_deadline = Some(now + SEARCH_DEBOUNCE_SECONDS);
        self.status = "typing…".into();
    }

    /// Fire a due debounce or a pending reset. Called once per frame.
    pub fn tick(&mut self, now: f64) -> Vec<QueryRequest> {
        let due = self
            .debounce_deadline
            .is_some_and(|deadline| now >= deadline);
        if due {
            self.debounce_deadline = None;
        }
        if due || self.needs_refresh {
            self.refresh()
        } else {
            Vec::new()
        }
    }

    /// Start a new first page. Bumps the generation, so every in-flight page
    /// or detail from the previous filter scope is discarded on arrival.
    pub fn refresh(&mut self) -> Vec<QueryRequest> {
        self.needs_refresh = false;
        let Some(revision) = self.revision.clone() else {
            return Vec::new();
        };
        self.generation += 1;
        self.loading = true;
        self.loading_first_page = true;
        self.events.clear();
        self.next_cursor = None;
        self.truncated = false;
        self.selected = None;
        self.detail = None;
        self.status = "loading events…".into();
        let query = self.filters.query(&revision, TIMELINE_PAGE_SIZE);
        let text = non_empty(&self.filters.text);
        vec![
            QueryRequest::Events {
                generation: self.generation,
                query: query.clone(),
                text: text.clone(),
            },
            QueryRequest::Histogram {
                generation: self.generation,
                query,
                text,
                bins: HISTOGRAM_BINS,
            },
        ]
    }

    /// Append the next page of the current filter scope.
    pub fn load_more(&mut self) -> Vec<QueryRequest> {
        if self.loading || self.truncated || self.next_cursor.is_none() {
            return Vec::new();
        }
        let Some(revision) = self.revision.clone() else {
            return Vec::new();
        };
        self.loading = true;
        self.loading_first_page = false;
        let mut query = self.filters.query(&revision, TIMELINE_PAGE_SIZE);
        query.after = self.next_cursor.clone();
        vec![QueryRequest::Events {
            generation: self.generation,
            query,
            text: non_empty(&self.filters.text),
        }]
    }

    pub fn apply_events(&mut self, generation: u64, page: EventPage) {
        if generation != self.generation {
            return;
        }
        self.loading = false;
        if self.loading_first_page {
            self.events = page.rows;
            self.loading_first_page = false;
        } else {
            self.events.extend(page.rows);
        }
        self.next_cursor = page.next_cursor;
        if self.events.len() > TIMELINE_MAX_ROWS {
            self.events.truncate(TIMELINE_MAX_ROWS);
            self.next_cursor = None;
            self.truncated = true;
        }
        self.status = format!(
            "{} event(s) loaded{}",
            self.events.len(),
            if self.truncated {
                "; cache limit reached, refine the filters to see more"
            } else if self.next_cursor.is_some() {
                "; more available"
            } else {
                ""
            }
        );
    }

    /// Stop waiting after a failed query and keep the reason visible.
    pub fn fail(&mut self, message: String) {
        self.loading = false;
        self.status = message;
    }

    pub fn apply_histogram(&mut self, generation: u64, histogram: Histogram) {
        if generation == self.generation {
            self.histogram = Some(histogram);
        }
    }

    pub fn apply_detail(&mut self, generation: u64, detail: EventDetail) {
        if generation == self.detail_generation
            && self.selected.as_deref() == Some(detail.event.event_id.as_str())
        {
            self.detail = Some(detail);
        }
    }

    /// Select one event and request its provenance.
    pub fn select(&mut self, event_id: &str) -> Vec<QueryRequest> {
        let Some(revision) = self.revision.clone() else {
            return Vec::new();
        };
        if self.selected.as_deref() == Some(event_id) && self.detail.is_some() {
            return Vec::new();
        }
        self.selected = Some(event_id.to_string());
        self.detail = None;
        self.detail_generation += 1;
        vec![QueryRequest::Detail {
            generation: self.detail_generation,
            revision,
            event_id: event_id.to_string(),
        }]
    }

    /// Keyboard selection over the loaded rows. Clamps at both ends.
    pub fn move_selection(&mut self, delta: isize) -> Vec<QueryRequest> {
        if self.events.is_empty() {
            return Vec::new();
        }
        let current = self
            .selected
            .as_ref()
            .and_then(|id| self.events.iter().position(|row| &row.event_id == id));
        let next = match current {
            Some(index) => {
                (index as isize + delta).clamp(0, self.events.len() as isize - 1) as usize
            }
            None => {
                if delta >= 0 {
                    0
                } else {
                    self.events.len() - 1
                }
            }
        };
        let id = self.events[next].event_id.clone();
        self.select(&id)
    }

    /// Selecting a histogram bin filters to its interval.
    pub fn select_bin(&mut self, start: i64, end: i64) -> Vec<QueryRequest> {
        self.filters.window = Some((start, end));
        self.refresh()
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
    /// Case database the query worker reads, set when a case opens.
    pub case_database: Option<String>,
    pub timeline: TimelineState,
    next_id: u64,
    pending: Vec<Command>,
    pending_queries: Vec<QueryRequest>,
    cancels: Vec<JobId>,
}

impl AppState {
    pub fn new() -> Self {
        let mut state = Self::default();
        state.case_form.timezone = "UTC".into();
        state.import_form.syslog_timezone = "UTC".into();
        state.timeline = TimelineState::new("UTC");
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

    pub fn take_queries(&mut self) -> Vec<QueryRequest> {
        std::mem::take(&mut self.pending_queries)
    }

    /// Per-frame timeline tick: fire a due search or a pending reset.
    pub fn begin_frame(&mut self, now: f64) {
        let requests = self.timeline.tick(now);
        self.pending_queries.extend(requests);
    }

    pub fn refresh_timeline(&mut self) {
        let requests = self.timeline.refresh();
        self.pending_queries.extend(requests);
    }

    pub fn load_more_timeline(&mut self) {
        let requests = self.timeline.load_more();
        self.pending_queries.extend(requests);
    }

    pub fn select_event(&mut self, event_id: &str) {
        let requests = self.timeline.select(event_id);
        self.pending_queries.extend(requests);
    }

    pub fn move_selection(&mut self, delta: isize) {
        let requests = self.timeline.move_selection(delta);
        self.pending_queries.extend(requests);
    }

    pub fn select_bin(&mut self, start: i64, end: i64) {
        let requests = self.timeline.select_bin(start, end);
        self.pending_queries.extend(requests);
    }

    pub fn toggle_unresolved(&mut self) {
        self.timeline.filters.unresolved_only = !self.timeline.filters.unresolved_only;
        self.refresh_timeline();
    }

    /// Apply one query result. Results from a superseded generation change
    /// nothing; failures stay actionable instead of silently emptying a pane.
    pub fn apply_query(&mut self, result: QueryResult) {
        match result {
            QueryResult::Events { generation, page } => {
                self.timeline.apply_events(generation, *page);
            }
            QueryResult::Histogram {
                generation,
                histogram,
            } => self.timeline.apply_histogram(generation, *histogram),
            QueryResult::Detail { generation, detail } => {
                self.timeline.apply_detail(generation, *detail);
            }
            QueryResult::Failed {
                generation,
                target,
                code,
                message,
            } => {
                let current = match target {
                    QueryTarget::Events | QueryTarget::Histogram => {
                        generation == 0 || generation == self.timeline.generation()
                    }
                    QueryTarget::Detail => {
                        generation == 0 || generation == self.timeline.detail_generation()
                    }
                };
                if current {
                    if matches!(target, QueryTarget::Events | QueryTarget::Histogram) {
                        self.timeline.fail(format!("{code}: {message}"));
                    }
                    self.notice_error(format!("{code}: {message}"));
                }
            }
        }
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
                database_path,
                label,
                timezone,
            } => {
                self.job.message = format!("case created: {label}");
                self.notice_info(format!("case created: {directory}"));
                self.open = Some(OpenCaseView {
                    directory,
                    label,
                    timezone: timezone.clone(),
                    acquisitions: Vec::new(),
                    recovery: Vec::new(),
                });
                self.case_database = Some(database_path.clone());
                self.pending_queries.push(QueryRequest::SetCase {
                    database_path,
                    display_timezone: timezone.clone(),
                });
                self.timeline = TimelineState::new(timezone);
                self.timeline.reset(None);
                self.screen = Screen::Import;
                self.show_recovery = false;
            }
            Outcome::CaseOpened {
                directory,
                database_path,
                label,
                timezone,
                revision,
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
                    timezone: timezone.clone(),
                    acquisitions,
                    recovery,
                });
                self.case_database = Some(database_path.clone());
                self.pending_queries.push(QueryRequest::SetCase {
                    database_path,
                    display_timezone: timezone.clone(),
                });
                self.timeline = TimelineState::new(timezone);
                self.timeline.reset(revision);
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
                if self.case_database.is_some() {
                    self.timeline.reset(Some(run_id));
                }
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
                if ui
                    .selectable_label(self.screen == Screen::Timeline, "Timeline")
                    .clicked()
                {
                    if self.open.is_some() {
                        self.screen = Screen::Timeline;
                    } else {
                        self.notice_error("open or create a case before opening the timeline");
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
                Screen::Timeline => crate::timeline::ui(self, ui),
            }
        });
    }
}

/// A labeled text field: the label is the control's accessible name, so tests
/// (and screen readers) can address the field by name instead of position.
pub(crate) fn labeled_text(ui: &mut egui::Ui, label: &str, value: &mut String) -> egui::Response {
    ui.horizontal(|ui| {
        let label = ui.label(label);
        ui.add(egui::TextEdit::singleline(value))
            .labelled_by(label.id)
    })
    .inner
}

fn non_empty(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

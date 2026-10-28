//! Desktop state and the command/result reducer (P6.1).
//!
//! The render pass only reads and writes this value; it never opens a case,
//! SQLite database, or evidence file. Commands leave through
//! `take_commands()` and results enter through `apply()`, which drops events
//! whose job id is no longer current.

use eframe::egui;
use ghosttrace_core::analysis::annotations::{AnnotationRevision, AppendAnnotation};
use ghosttrace_core::analysis::correlate::{RelationshipPage, RelationshipQuery, RelationshipRow};
use ghosttrace_core::analysis::diff::{DiffQuery, DiffReport};
use ghosttrace_core::analysis::views::{SavedFilter, SavedView};
use ghosttrace_core::domain::case::AcquisitionMethod;
use ghosttrace_core::domain::detail::{EventDetail, Histogram};
use ghosttrace_core::domain::finding::{Disposition, Finding};
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
    Diff,
    Relations,
    Findings,
    Report,
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
/// Rows per snapshot-comparison page; the comparison re-reads both snapshots.
pub const DIFF_PAGE_SIZE: u32 = 200;
/// Edges per relationship page. The graph draws at most these bounds.
pub const RELATION_PAGE_SIZE: u32 = 200;
/// Hard graph bounds: work and paint cost never follow the case size.
pub const GRAPH_MAX_NODES: usize = 40;
pub const GRAPH_MAX_EDGES: usize = 80;
pub const ANNOTATION_HISTORY_LIMIT: u32 = 50;
/// The tag a bookmark records; a bookmark is an annotation, not a new fact.
pub const BOOKMARK_TAG: &str = "bookmark";

/// Filters shown in the timeline. Structured fields only: the text goes
/// through the same validated search grammar as the CLI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimelineFilters {
    pub text: String,
    pub kind: String,
    pub host: String,
    pub source: String,
    pub unresolved_only: bool,
    /// Selected histogram bin bounds, `[after, before)` in Unix seconds. They
    /// are stored separately because a saved view may carry only one of them;
    /// dropping an unseen bound would silently widen the filter.
    pub after_seconds: Option<i64>,
    pub before_seconds: Option<i64>,
}

impl TimelineFilters {
    /// The typed, bounded filter a saved view stores.
    pub fn saved(&self) -> SavedFilter {
        SavedFilter {
            kind: non_empty(&self.kind),
            host: non_empty(&self.host),
            source: non_empty(&self.source),
            text: non_empty(&self.text),
            after_seconds: self.after_seconds,
            before_seconds: self.before_seconds,
            unresolved_only: self.unresolved_only,
            limit: TIMELINE_PAGE_SIZE,
        }
    }

    /// Restore a saved filter. Values were validated on write and again on
    /// read; nothing here is interpreted as SQL or an expression.
    pub fn from_saved(filter: &SavedFilter) -> Self {
        Self {
            text: filter.text.clone().unwrap_or_default(),
            kind: filter.kind.clone().unwrap_or_default(),
            host: filter.host.clone().unwrap_or_default(),
            source: filter.source.clone().unwrap_or_default(),
            unresolved_only: filter.unresolved_only,
            after_seconds: filter.after_seconds,
            before_seconds: filter.before_seconds,
        }
    }

    pub fn query(&self, revision: &str, limit: u32) -> EventQuery {
        EventQuery {
            revision: revision.to_string(),
            kind: non_empty(&self.kind),
            host: non_empty(&self.host),
            source: non_empty(&self.source),
            after_seconds: self.after_seconds,
            before_seconds: self.before_seconds,
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
    /// Saved filters for this case, newest first.
    pub views: Vec<SavedView>,
    pub view_name: String,
    pub view_status: String,
    /// Annotation history for the selected event.
    pub annotations: Vec<AnnotationRevision>,
    pub note: String,
    pub tags: String,
    pub author: String,
    pub bookmark: bool,
    pub annotation_status: String,
    generation: u64,
    detail_generation: u64,
    annotation_generation: u64,
    views_generation: u64,
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
            views: Vec::new(),
            view_name: String::new(),
            view_status: "no saved views loaded".into(),
            annotations: Vec::new(),
            note: String::new(),
            tags: String::new(),
            author: String::new(),
            bookmark: false,
            annotation_status: "select an event to record a note".into(),
            generation: 0,
            detail_generation: 0,
            annotation_generation: 0,
            views_generation: 0,
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
        self.annotations.clear();
        self.annotation_generation += 1;
        self.annotation_status = "select an event to record a note".into();
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

    pub fn annotation_generation(&self) -> u64 {
        self.annotation_generation
    }

    pub fn views_generation(&self) -> u64 {
        self.views_generation
    }

    /// Ask the query worker for this case's saved views.
    pub fn reload_views(&mut self) -> Vec<QueryRequest> {
        self.views_generation += 1;
        vec![QueryRequest::Views {
            generation: self.views_generation,
        }]
    }

    pub fn apply_views(&mut self, generation: u64, views: Vec<SavedView>) {
        if generation != self.views_generation {
            return;
        }
        self.view_status = if views.is_empty() {
            "no saved views yet".into()
        } else {
            format!("{} saved view(s)", views.len())
        };
        self.views = views;
    }

    /// Refresh the annotation history of the selected event.
    pub fn reload_annotations(&mut self) -> Vec<QueryRequest> {
        let Some(event_id) = self.selected.clone() else {
            return Vec::new();
        };
        self.annotation_generation += 1;
        vec![QueryRequest::Annotations {
            generation: self.annotation_generation,
            target_id: event_id,
            limit: ANNOTATION_HISTORY_LIMIT,
        }]
    }

    pub fn apply_annotations(
        &mut self,
        generation: u64,
        target_id: &str,
        revisions: Vec<AnnotationRevision>,
    ) {
        if generation != self.annotation_generation || self.selected.as_deref() != Some(target_id) {
            return;
        }
        self.annotation_status = if revisions.is_empty() {
            "no notes recorded for this event".into()
        } else {
            format!("{} recorded revision(s)", revisions.len())
        };
        self.annotations = revisions;
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
        self.annotations.clear();
        self.annotation_generation += 1;
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
        self.annotations.clear();
        self.note.clear();
        self.tags.clear();
        self.bookmark = false;
        self.detail_generation += 1;
        self.annotation_generation += 1;
        vec![
            QueryRequest::Detail {
                generation: self.detail_generation,
                revision,
                event_id: event_id.to_string(),
            },
            QueryRequest::Annotations {
                generation: self.annotation_generation,
                target_id: event_id.to_string(),
                limit: ANNOTATION_HISTORY_LIMIT,
            },
        ]
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
        self.filters.after_seconds = Some(start);
        self.filters.before_seconds = Some(end);
        self.refresh()
    }
}

/// Snapshot comparison state (P6.3). Two acquisitions are chosen explicitly;
/// scope mismatches and undecidable rows stay in the report and on screen.
#[derive(Debug, Clone)]
pub struct DiffState {
    pub before: Option<String>,
    pub after: Option<String>,
    pub report: Option<DiffReport>,
    pub status: String,
    pub selected: Option<String>,
    pub loading: bool,
    generation: u64,
    loading_more: bool,
}

impl Default for DiffState {
    fn default() -> Self {
        Self::new()
    }
}

impl DiffState {
    pub fn new() -> Self {
        Self {
            before: None,
            after: None,
            report: None,
            status: "choose two recorded captures to compare".into(),
            selected: None,
            loading: false,
            generation: 0,
            loading_more: false,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn is_loading(&self) -> bool {
        self.loading
    }

    /// New captures change the comparison; the chosen pair follows the newest
    /// two recordings but is never guessed from a missing one.
    pub fn reset(&mut self, acquisitions: &[AcquisitionSummary]) {
        self.before = acquisitions.get(1).map(|item| item.acquisition_id.clone());
        self.after = acquisitions.first().map(|item| item.acquisition_id.clone());
        self.report = None;
        self.selected = None;
        self.loading = false;
        self.loading_more = false;
        self.status = if self.before.is_some() && self.after.is_some() {
            "ready to compare".into()
        } else {
            "two recorded captures are required".into()
        };
    }

    pub fn refresh(&mut self) -> Vec<QueryRequest> {
        let (Some(before), Some(after)) = (self.before.clone(), self.after.clone()) else {
            self.status = "two recorded captures are required".into();
            return Vec::new();
        };
        self.generation += 1;
        self.loading = true;
        self.loading_more = false;
        self.report = None;
        self.selected = None;
        self.status = "comparing recorded captures…".into();
        vec![QueryRequest::Diff {
            generation: self.generation,
            before,
            after,
            query: DiffQuery {
                after: None,
                limit: DIFF_PAGE_SIZE,
            },
        }]
    }

    pub fn load_more(&mut self) -> Vec<QueryRequest> {
        if self.loading {
            return Vec::new();
        }
        let cursor = self
            .report
            .as_ref()
            .and_then(|report| report.next_cursor.clone());
        let (Some(before), Some(after), Some(cursor)) =
            (self.before.clone(), self.after.clone(), cursor)
        else {
            return Vec::new();
        };
        self.loading = true;
        self.loading_more = true;
        vec![QueryRequest::Diff {
            generation: self.generation,
            before,
            after,
            query: DiffQuery {
                after: Some(cursor),
                limit: DIFF_PAGE_SIZE,
            },
        }]
    }

    pub fn apply(&mut self, generation: u64, report: DiffReport) {
        if generation != self.generation {
            return;
        }
        self.loading = false;
        if self.loading_more
            && let Some(current) = self.report.as_mut()
        {
            current.rows.extend(report.rows);
            current.next_cursor = report.next_cursor;
            self.loading_more = false;
            self.status = format!(
                "{} row(s) shown{}",
                current.rows.len(),
                if current.next_cursor.is_some() {
                    "; more available"
                } else {
                    ""
                }
            );
            return;
        }
        self.loading_more = false;
        self.status = format!(
            "{} row(s) shown{}",
            report.rows.len(),
            if report.next_cursor.is_some() {
                "; more available"
            } else {
                ""
            }
        );
        self.report = Some(report);
    }

    pub fn fail(&mut self, message: String) {
        self.loading = false;
        self.loading_more = false;
        self.status = message;
    }
}

/// One drawn graph node. Labels are recorded display forms, escaped by the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEdge {
    pub id: i64,
    pub kind: String,
    pub source: String,
    pub target: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GraphModel {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    /// Some loaded entity is not drawn.
    pub capped_nodes: bool,
    /// Some loaded edge is not drawn.
    pub capped_edges: bool,
}

/// Build a bounded graph from loaded relationship rows. Work is linear in the
/// page and stops at the caps; an edge whose endpoint was not admitted is
/// dropped, so the drawing never shows an edge to an off-screen node.
pub fn graph_model(rows: &[RelationshipRow], max_nodes: usize, max_edges: usize) -> GraphModel {
    let mut model = GraphModel::default();
    for row in rows {
        for entity in [&row.source, &row.target] {
            if model.nodes.iter().any(|node| node.id == entity.id) {
                continue;
            }
            if model.nodes.len() >= max_nodes {
                model.capped_nodes = true;
                continue;
            }
            model.nodes.push(GraphNode {
                id: entity.id.clone(),
                label: entity.display_form.clone(),
            });
        }
    }
    for row in rows {
        if model.edges.len() >= max_edges {
            model.capped_edges = true;
            break;
        }
        let drawn = |id: &str| model.nodes.iter().any(|node| node.id == id);
        if !drawn(&row.source.id) || !drawn(&row.target.id) {
            model.capped_edges = true;
            continue;
        }
        model.edges.push(GraphEdge {
            id: row.id,
            kind: row.kind.clone(),
            source: row.source.id.clone(),
            target: row.target.id.clone(),
        });
    }
    model
}

/// Supporting event ids recorded on a relationship. A malformed value is
/// reported as empty by the view, never turned into a guessed reference.
pub fn support_events(support_json: &str) -> Vec<String> {
    let value: serde_json::Value = match serde_json::from_str(support_json) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    value
        .get("events")
        .and_then(|events| events.as_array())
        .map(|events| {
            events
                .iter()
                .filter_map(|event| event.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The matching fields recorded on a relationship, for the explanation line.
pub fn support_fields(support_json: &str) -> Vec<String> {
    let value: serde_json::Value = match serde_json::from_str(support_json) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    value
        .get("matching_fields")
        .and_then(|fields| fields.as_array())
        .map(|fields| {
            fields
                .iter()
                .filter_map(|field| field.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Relationship list state. The list is the primary, keyboard-reachable
/// representation; the graph is a bounded view over the same rows.
#[derive(Debug, Clone)]
pub struct RelationsState {
    pub revision: Option<String>,
    pub entity: String,
    pub kind: String,
    pub rows: Vec<RelationshipRow>,
    pub selected: Option<i64>,
    pub status: String,
    pub loading: bool,
    pub next_cursor: Option<i64>,
    generation: u64,
    loading_more: bool,
}

impl Default for RelationsState {
    fn default() -> Self {
        Self::new()
    }
}

impl RelationsState {
    pub fn new() -> Self {
        Self {
            revision: None,
            entity: String::new(),
            kind: String::new(),
            rows: Vec::new(),
            selected: None,
            status: "no relationships loaded".into(),
            loading: false,
            next_cursor: None,
            generation: 0,
            loading_more: false,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn is_loading(&self) -> bool {
        self.loading
    }

    pub fn reset(&mut self, revision: Option<String>) {
        self.revision = revision;
        self.rows.clear();
        self.selected = None;
        self.next_cursor = None;
        self.loading = false;
        self.loading_more = false;
        self.status = "no relationships loaded".into();
    }

    fn query(&self, after_id: Option<i64>) -> RelationshipQuery {
        RelationshipQuery {
            entity_id: non_empty(&self.entity),
            kind: non_empty(&self.kind),
            rule_id: None,
            limit: RELATION_PAGE_SIZE,
            after_id,
        }
    }

    pub fn refresh(&mut self) -> Vec<QueryRequest> {
        if self.revision.is_none() {
            self.status = "this case has no parse run yet".into();
            return Vec::new();
        }
        self.generation += 1;
        self.loading = true;
        self.loading_more = false;
        self.rows.clear();
        self.selected = None;
        self.next_cursor = None;
        self.status = "loading relationships…".into();
        vec![QueryRequest::Relationships {
            generation: self.generation,
            query: self.query(None),
        }]
    }

    pub fn load_more(&mut self) -> Vec<QueryRequest> {
        if self.loading || self.next_cursor.is_none() || self.revision.is_none() {
            return Vec::new();
        }
        self.loading = true;
        self.loading_more = true;
        vec![QueryRequest::Relationships {
            generation: self.generation,
            query: self.query(self.next_cursor),
        }]
    }

    pub fn apply(&mut self, generation: u64, page: RelationshipPage) {
        if generation != self.generation {
            return;
        }
        self.loading = false;
        if self.loading_more {
            self.rows.extend(page.rows);
        } else {
            self.rows = page.rows;
        }
        self.loading_more = false;
        self.next_cursor = page.next_cursor;
        self.status = format!(
            "{} relationship(s) loaded{}",
            self.rows.len(),
            if self.next_cursor.is_some() {
                "; more available"
            } else {
                ""
            }
        );
    }

    pub fn fail(&mut self, message: String) {
        self.loading = false;
        self.loading_more = false;
        self.status = message;
    }

    pub fn select(&mut self, id: i64) {
        self.selected = Some(id);
    }

    pub fn move_selection(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let current = self
            .selected
            .and_then(|id| self.rows.iter().position(|row| row.id == id));
        let next = match current {
            Some(index) => (index as isize + delta).clamp(0, self.rows.len() as isize - 1) as usize,
            None => {
                if delta >= 0 {
                    0
                } else {
                    self.rows.len() - 1
                }
            }
        };
        self.selected = Some(self.rows[next].id);
    }

    pub fn selected_row(&self) -> Option<&RelationshipRow> {
        let id = self.selected?;
        self.rows.iter().find(|row| row.id == id)
    }

    pub fn graph(&self) -> GraphModel {
        graph_model(&self.rows, GRAPH_MAX_NODES, GRAPH_MAX_EDGES)
    }
}

/// Findings and their annotation history (P5.2/P6.3).
#[derive(Debug, Clone)]
pub struct FindingsState {
    pub revision: Option<String>,
    pub run_id: Option<String>,
    pub findings: Vec<Finding>,
    pub selected: Option<String>,
    pub history: Vec<AnnotationRevision>,
    pub author: String,
    pub note: String,
    pub tags: String,
    pub disposition: Disposition,
    pub status: String,
    pub loading: bool,
    generation: u64,
    history_generation: u64,
}

impl Default for FindingsState {
    fn default() -> Self {
        Self::new()
    }
}

impl FindingsState {
    pub fn new() -> Self {
        Self {
            revision: None,
            run_id: None,
            findings: Vec::new(),
            selected: None,
            history: Vec::new(),
            author: String::new(),
            note: String::new(),
            tags: String::new(),
            disposition: Disposition::Undismissed,
            status: "no analysis run for this revision yet".into(),
            loading: false,
            generation: 0,
            history_generation: 0,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn history_generation(&self) -> u64 {
        self.history_generation
    }

    pub fn is_loading(&self) -> bool {
        self.loading
    }

    pub fn reset(&mut self, revision: Option<String>) {
        self.revision = revision;
        self.run_id = None;
        self.findings.clear();
        self.selected = None;
        self.history.clear();
        self.note.clear();
        self.tags.clear();
        self.disposition = Disposition::Undismissed;
        self.loading = false;
        self.status = "no analysis run for this revision yet".into();
    }

    /// Ask for the findings recorded by the current analysis run.
    pub fn reload(&mut self) -> Vec<QueryRequest> {
        let Some(run_id) = self.run_id.clone() else {
            self.status = "run an analysis first".into();
            return Vec::new();
        };
        self.generation += 1;
        self.loading = true;
        vec![QueryRequest::Findings {
            generation: self.generation,
            analysis_run_id: run_id,
        }]
    }

    pub fn apply_findings(&mut self, generation: u64, run_id: String, findings: Vec<Finding>) {
        if generation != self.generation {
            return;
        }
        self.loading = false;
        self.run_id = Some(run_id.clone());
        self.status = format!("{} finding(s) from {run_id}", findings.len());
        if self
            .selected
            .as_ref()
            .is_some_and(|id| !findings.iter().any(|finding| &finding.id == id))
        {
            self.selected = None;
            self.history.clear();
        }
        self.findings = findings;
    }

    pub fn fail(&mut self, message: String) {
        self.loading = false;
        self.status = message;
    }

    /// Select one finding and ask for its annotation history.
    pub fn select(&mut self, finding_id: &str) -> Vec<QueryRequest> {
        self.selected = Some(finding_id.to_string());
        self.history.clear();
        self.note.clear();
        self.tags.clear();
        self.history_generation += 1;
        vec![QueryRequest::Annotations {
            generation: self.history_generation,
            target_id: finding_id.to_string(),
            limit: ANNOTATION_HISTORY_LIMIT,
        }]
    }

    pub fn apply_history(
        &mut self,
        generation: u64,
        target_id: &str,
        revisions: Vec<AnnotationRevision>,
    ) {
        if generation != self.history_generation || self.selected.as_deref() != Some(target_id) {
            return;
        }
        self.disposition = revisions
            .iter()
            .find_map(|revision| revision.disposition)
            .unwrap_or(Disposition::Undismissed);
        self.history = revisions;
    }

    pub fn reload_history(&mut self) -> Vec<QueryRequest> {
        let Some(id) = self.selected.clone() else {
            return Vec::new();
        };
        self.select(&id)
    }

    pub fn move_selection(&mut self, delta: isize) -> Vec<QueryRequest> {
        if self.findings.is_empty() {
            return Vec::new();
        }
        let current = self
            .selected
            .as_ref()
            .and_then(|id| self.findings.iter().position(|finding| &finding.id == id));
        let next = match current {
            Some(index) => {
                (index as isize + delta).clamp(0, self.findings.len() as isize - 1) as usize
            }
            None => {
                if delta >= 0 {
                    0
                } else {
                    self.findings.len() - 1
                }
            }
        };
        let id = self.findings[next].id.clone();
        self.select(&id)
    }

    pub fn selected_finding(&self) -> Option<&Finding> {
        let id = self.selected.as_deref()?;
        self.findings.iter().find(|finding| finding.id == id)
    }

    /// The newest revision the analyst has seen; an append names it so a
    /// concurrent edit becomes a visible conflict instead of an overwrite.
    pub fn previous_revision(&self) -> Option<i64> {
        self.history.first().map(|revision| revision.id)
    }
}

/// Appearance choices. Restrained by design: three complete palettes, no
/// per-widget customization and no colour-only meaning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ThemeChoice {
    #[default]
    Dark,
    Light,
    HighContrast,
}

impl ThemeChoice {
    pub const ALL: [ThemeChoice; 3] = [
        ThemeChoice::Dark,
        ThemeChoice::Light,
        ThemeChoice::HighContrast,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ThemeChoice::Dark => "Dark",
            ThemeChoice::Light => "Light",
            ThemeChoice::HighContrast => "High contrast",
        }
    }

    /// High contrast is a dark base with maximum text/stroke contrast and an
    /// opaque selection, so focus and selection never rely on hue alone.
    pub fn visuals(self) -> egui::Visuals {
        match self {
            ThemeChoice::Dark => egui::Visuals::dark(),
            ThemeChoice::Light => egui::Visuals::light(),
            ThemeChoice::HighContrast => {
                let mut visuals = egui::Visuals::dark();
                visuals.override_text_color = Some(egui::Color32::WHITE);
                visuals.panel_fill = egui::Color32::BLACK;
                visuals.window_fill = egui::Color32::BLACK;
                visuals.extreme_bg_color = egui::Color32::BLACK;
                visuals.faint_bg_color = egui::Color32::from_gray(24);
                visuals.selection.bg_fill = egui::Color32::from_rgb(0, 84, 200);
                visuals.selection.stroke = egui::Stroke::new(2.0, egui::Color32::WHITE);
                visuals.widgets.noninteractive.bg_stroke =
                    egui::Stroke::new(1.5, egui::Color32::from_gray(200));
                visuals.widgets.inactive.bg_stroke =
                    egui::Stroke::new(1.5, egui::Color32::from_gray(220));
                visuals.widgets.hovered.bg_stroke = egui::Stroke::new(2.0, egui::Color32::WHITE);
                visuals.widgets.active.bg_stroke = egui::Stroke::new(2.0, egui::Color32::WHITE);
                visuals.widgets.active.bg_fill = egui::Color32::from_gray(70);
                visuals
            }
        }
    }
}

/// One published report, as reported by the job worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportSummary {
    pub report_id: String,
    pub directory: String,
    pub json: String,
    pub html: String,
    pub objects: usize,
    pub events: usize,
    pub gaps: u64,
}

/// One manifest verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifySummary {
    pub manifest_id: String,
    pub acquisition_id: String,
    pub format: String,
    pub objects: u64,
    pub total_bytes: u64,
    pub captured: u64,
    pub gaps: u64,
}

/// Report export and manifest verification state (P6.4).
#[derive(Debug, Clone)]
pub struct ReportState {
    pub acquisition: Option<String>,
    /// Revision to report; empty means the newest parse run of the acquisition.
    pub revision: String,
    pub event_limit: u32,
    pub destination: String,
    pub report_id: String,
    pub last: Option<ReportSummary>,
    pub manifest_path: String,
    pub verify_acquisition: Option<String>,
    pub verification: Option<VerifySummary>,
    pub status: String,
    pub verifying: bool,
}

impl Default for ReportState {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportState {
    pub fn new() -> Self {
        Self {
            acquisition: None,
            revision: String::new(),
            event_limit: 500,
            destination: String::new(),
            report_id: String::new(),
            last: None,
            manifest_path: String::new(),
            verify_acquisition: None,
            verification: None,
            status: "no report exported yet".into(),
            verifying: false,
        }
    }

    pub fn reset(&mut self, acquisitions: &[AcquisitionSummary], revision: Option<String>) {
        self.acquisition = acquisitions.first().map(|item| item.acquisition_id.clone());
        self.verify_acquisition = self.acquisition.clone();
        self.revision = revision.unwrap_or_default();
        self.last = None;
        self.verification = None;
        self.verifying = false;
        self.status = if acquisitions.is_empty() {
            "record a capture before exporting a report".into()
        } else {
            "ready to export".into()
        };
    }

    /// A destination is a real, absolute directory outside the case: a report
    /// never lands inside case storage by accident.
    pub fn destination_problem(&self, case_directory: &str) -> Option<String> {
        let destination = self.destination.trim();
        if destination.is_empty() {
            return Some("a destination directory is required".into());
        }
        let path = std::path::Path::new(destination);
        if !path.is_absolute() {
            return Some("the destination must be an absolute path".into());
        }
        let case_root = std::path::Path::new(case_directory);
        if path.starts_with(case_root) {
            return Some("the destination must be outside the case directory".into());
        }
        None
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
    pub diff: DiffState,
    pub relations: RelationsState,
    pub findings: FindingsState,
    pub report: ReportState,
    pub theme: ThemeChoice,
    applied_theme: Option<ThemeChoice>,
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
        state.diff = DiffState::new();
        state.relations = RelationsState::new();
        state.findings = FindingsState::new();
        state.report = ReportState::new();
        state
    }

    fn case_directory(&self) -> Option<String> {
        self.open.as_ref().map(|open| open.directory.clone())
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

    // ---- P6.3: diff, relationships, findings, notes, saved views ----

    pub fn reload_views(&mut self) {
        let requests = self.timeline.reload_views();
        self.pending_queries.extend(requests);
    }

    pub fn open_diff(&mut self) {
        let requests = self.diff.refresh();
        self.pending_queries.extend(requests);
    }

    pub fn load_more_diff(&mut self) {
        let requests = self.diff.load_more();
        self.pending_queries.extend(requests);
    }

    pub fn load_relations(&mut self) {
        let requests = self.relations.refresh();
        self.pending_queries.extend(requests);
    }

    pub fn load_more_relations(&mut self) {
        let requests = self.relations.load_more();
        self.pending_queries.extend(requests);
    }

    pub fn move_relation_selection(&mut self, delta: isize) {
        self.relations.move_selection(delta);
    }

    pub fn select_finding(&mut self, finding_id: &str) {
        let requests = self.findings.select(finding_id);
        self.pending_queries.extend(requests);
    }

    pub fn move_finding_selection(&mut self, delta: isize) {
        let requests = self.findings.move_selection(delta);
        self.pending_queries.extend(requests);
    }

    /// Open one supporting event in the timeline inspector.
    pub fn open_event(&mut self, event_id: &str) {
        if self.timeline.revision.is_none() {
            self.notice_error("this case has no parse run to open an event from");
            return;
        }
        self.screen = Screen::Timeline;
        self.select_event(event_id);
    }

    /// Derive relationships for the active revision on the job worker: it is a
    /// write, so it is serialized with captures and imports.
    pub fn derive_relationships(&mut self) {
        let Some(case_directory) = self.case_directory() else {
            self.notice_error("open a case before deriving relationships");
            return;
        };
        if self.timeline.revision.is_none() {
            self.notice_error("import a captured object before deriving relationships");
            return;
        }
        self.start(|id| Command::Correlate { id, case_directory });
    }

    pub fn run_analysis(&mut self) {
        let (Some(case_directory), Some(revision)) =
            (self.case_directory(), self.timeline.revision.clone())
        else {
            self.notice_error("open a case with a parse run before running an analysis");
            return;
        };
        self.start(|id| Command::Analyze {
            id,
            case_directory,
            revision,
        });
    }

    pub fn save_current_view(&mut self) {
        let name = self.timeline.view_name.trim().to_string();
        if name.is_empty() {
            self.notice_error("a saved view needs a name");
            return;
        }
        let Some(case_directory) = self.case_directory() else {
            self.notice_error("open a case before saving a view");
            return;
        };
        let filter = self.timeline.filters.saved();
        self.start(|id| Command::SaveView {
            id,
            case_directory,
            name,
            filter,
        });
    }

    /// Apply a stored view to the timeline. The filter is typed and was
    /// validated on write; running it goes through the shared query path.
    pub fn apply_view(&mut self, name: &str) {
        let Some(view) = self
            .timeline
            .views
            .iter()
            .find(|view| view.name == name)
            .cloned()
        else {
            self.notice_error("that saved view is not loaded");
            return;
        };
        self.timeline.filters = TimelineFilters::from_saved(&view.filter);
        self.refresh_timeline();
    }

    pub fn record_event_annotation(&mut self) {
        let Some(target_id) = self.timeline.selected.clone() else {
            self.notice_error("select an event before recording a note");
            return;
        };
        let Some(case_directory) = self.case_directory() else {
            self.notice_error("open a case before recording a note");
            return;
        };
        let mut tags = parse_tags(&self.timeline.tags);
        if self.timeline.bookmark && !tags.iter().any(|tag| tag == BOOKMARK_TAG) {
            tags.push(BOOKMARK_TAG.to_string());
        }
        let text = self.timeline.note.trim().to_string();
        if text.is_empty() && tags.is_empty() {
            self.notice_error("a note needs text or a tag");
            return;
        }
        let request = AppendAnnotation {
            target_id,
            author_label: author_label(&self.timeline.author),
            text,
            tags,
            disposition: None,
            expected_previous: self
                .timeline
                .annotations
                .first()
                .map(|revision| revision.id),
        };
        self.start(|id| Command::Annotate {
            id,
            case_directory,
            request,
        });
    }

    pub fn record_finding_annotation(&mut self) {
        let Some(target_id) = self.findings.selected.clone() else {
            self.notice_error("select a finding before recording a disposition");
            return;
        };
        let Some(case_directory) = self.case_directory() else {
            self.notice_error("open a case before recording a disposition");
            return;
        };
        let request = AppendAnnotation {
            target_id,
            author_label: author_label(&self.findings.author),
            text: self.findings.note.trim().to_string(),
            tags: parse_tags(&self.findings.tags),
            disposition: Some(self.findings.disposition),
            expected_previous: self.findings.previous_revision(),
        };
        self.start(|id| Command::Annotate {
            id,
            case_directory,
            request,
        });
    }

    /// Export a report for the chosen acquisition and revision. The output is
    /// unredacted in this phase and the screen says so before the button.
    pub fn export_report(&mut self) {
        if self.is_running() {
            self.notice_error("a job is already running; cancel it before exporting");
            return;
        }
        let Some(case_directory) = self.case_directory() else {
            self.notice_error("open a case before exporting a report");
            return;
        };
        if let Some(problem) = self.report.destination_problem(&case_directory) {
            self.notice_error(problem.clone());
            self.report.status = problem;
            return;
        }
        let output = self.report.destination.trim().to_string();
        let acquisition_id = self.report.acquisition.clone();
        let revision = non_empty(&self.report.revision);
        let event_limit = self.report.event_limit.clamp(1, 10_000);
        let report_id = non_empty(&self.report.report_id);
        self.report.status = "exporting report…".into();
        self.start(|id| Command::Report {
            id,
            case_directory,
            output,
            acquisition_id,
            revision,
            event_limit,
            report_id,
        });
    }

    /// Verify the stored bytes of one manifest (the latest by default).
    pub fn verify_case(&mut self) {
        if self.is_running() {
            self.notice_error("a job is already running; cancel it before verifying");
            return;
        }
        let Some(case_directory) = self.case_directory() else {
            self.notice_error("open a case before verifying a manifest");
            return;
        };
        let manifest_path = non_empty(&self.report.manifest_path);
        let acquisition_id = self.report.verify_acquisition.clone();
        self.report.verifying = true;
        self.report.status = "verifying stored bytes…".into();
        self.start(|id| Command::Verify {
            id,
            case_directory,
            manifest_path,
            acquisition_id,
        });
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
            QueryResult::Diff { generation, report } => {
                self.diff.apply(generation, *report);
            }
            QueryResult::Relationships { generation, page } => {
                self.relations.apply(generation, *page);
            }
            QueryResult::Findings {
                generation,
                run_id,
                findings,
            } => self.findings.apply_findings(generation, run_id, findings),
            QueryResult::Annotations {
                generation,
                target_id,
                revisions,
            } => {
                self.timeline
                    .apply_annotations(generation, &target_id, revisions.clone());
                self.findings
                    .apply_history(generation, &target_id, revisions);
            }
            QueryResult::Views { generation, views } => {
                self.timeline.apply_views(generation, views);
            }
            QueryResult::Failed {
                generation,
                target,
                code,
                message,
            } => {
                let current = generation == 0
                    || match target {
                        QueryTarget::Events | QueryTarget::Histogram => {
                            generation == self.timeline.generation()
                        }
                        QueryTarget::Detail => generation == self.timeline.detail_generation(),
                        QueryTarget::Diff => generation == self.diff.generation(),
                        QueryTarget::Relationships => generation == self.relations.generation(),
                        QueryTarget::Findings => generation == self.findings.generation(),
                        QueryTarget::Annotations => {
                            generation == self.timeline.annotation_generation()
                                || generation == self.findings.history_generation()
                        }
                        QueryTarget::Views => generation == self.timeline.views_generation(),
                    };
                if current {
                    match target {
                        QueryTarget::Events | QueryTarget::Histogram => {
                            self.timeline.fail(format!("{code}: {message}"))
                        }
                        QueryTarget::Diff => self.diff.fail(format!("{code}: {message}")),
                        QueryTarget::Relationships => {
                            self.relations.fail(format!("{code}: {message}"))
                        }
                        QueryTarget::Findings => self.findings.fail(format!("{code}: {message}")),
                        _ => {}
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
                if phase == JobPhase::Verify {
                    self.report.verifying = false;
                    self.report.status = format!("verification failed: {code}: {message}");
                } else if phase == JobPhase::Report {
                    self.report.status = format!("export failed: {code}: {message}");
                }
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
                self.diff.reset(&[]);
                self.relations.reset(None);
                self.findings.reset(None);
                self.report.reset(&[], None);
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
                self.diff.reset(&acquisitions);
                self.relations.reset(revision.clone());
                self.findings.reset(revision.clone());
                self.report.reset(&acquisitions, revision.clone());
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
                let requests = self.timeline.reload_views();
                self.pending_queries.extend(requests);
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
                let acquisitions = self
                    .open
                    .as_ref()
                    .map(|open| open.acquisitions.clone())
                    .unwrap_or_default();
                self.diff.reset(&acquisitions);
                let revision = self.timeline.revision.clone();
                self.report.reset(&acquisitions, revision);
            }
            Outcome::Imported {
                run_id,
                state,
                events,
            } => {
                self.job.message = format!("import {state}: {events} event(s)");
                self.notice_info(format!("import {run_id} {state}: {events} event(s)"));
                if self.case_database.is_some() {
                    self.timeline.reset(Some(run_id.clone()));
                    self.relations.reset(Some(run_id.clone()));
                    self.findings.reset(Some(run_id.clone()));
                    self.report.revision = run_id;
                    self.report.last = None;
                    self.report.verification = None;
                    self.report.status = "ready to export".into();
                }
            }
            Outcome::Analyzed {
                run_id,
                state,
                findings,
            } => {
                self.job.message = format!("analysis {state}: {findings} finding(s)");
                self.notice_info(format!("analysis {run_id} {state}: {findings} finding(s)"));
                self.findings.run_id = Some(run_id);
                let requests = self.findings.reload();
                self.pending_queries.extend(requests);
            }
            Outcome::Correlated {
                derived,
                inserted,
                truncated,
            } => {
                self.job.message = format!("relationships: {inserted} recorded");
                self.notice_info(format!(
                    "relationships derived: {derived}, newly recorded: {inserted}{}",
                    if truncated {
                        "; a bound stopped the pass, narrow the revision"
                    } else {
                        ""
                    }
                ));
                let requests = self.relations.refresh();
                self.pending_queries.extend(requests);
            }
            Outcome::Annotated {
                target_id,
                revision_id,
            } => {
                self.job.message = format!("annotation revision {revision_id} recorded");
                self.notice_info(format!(
                    "annotation revision {revision_id} recorded for {target_id}"
                ));
                if self.timeline.selected.as_deref() == Some(target_id.as_str()) {
                    self.timeline.note.clear();
                    self.timeline.tags.clear();
                    self.timeline.bookmark = false;
                    let requests = self.timeline.reload_annotations();
                    self.pending_queries.extend(requests);
                }
                if self.findings.selected.as_deref() == Some(target_id.as_str()) {
                    self.findings.note.clear();
                    self.findings.tags.clear();
                    let requests = self.findings.reload_history();
                    self.pending_queries.extend(requests);
                }
            }
            Outcome::ViewSaved { name } => {
                self.job.message = format!("saved view: {name}");
                self.notice_info(format!("saved view {name} recorded"));
                self.timeline.view_name.clear();
                let requests = self.timeline.reload_views();
                self.pending_queries.extend(requests);
            }
            Outcome::ReportPublished {
                report_id,
                directory,
                json,
                html,
                objects,
                events,
                gaps,
            } => {
                self.job.message = format!("report {report_id} published");
                self.notice_info(format!(
                    "report {report_id} published: {objects} object(s), {events} event(s), {gaps} gap(s)"
                ));
                self.report.status = format!("published {report_id}");
                self.report.last = Some(ReportSummary {
                    report_id,
                    directory,
                    json,
                    html,
                    objects,
                    events,
                    gaps,
                });
            }
            Outcome::ReportCancelled => {
                self.job.message = "report cancelled".into();
                self.notice_info("report cancelled; nothing was published");
                self.report.status = "cancelled; nothing was published".into();
            }
            Outcome::Verified {
                manifest_id,
                acquisition_id,
                format,
                objects,
                total_bytes,
                captured,
                gaps,
            } => {
                self.job.message = format!("manifest {manifest_id} verified");
                self.notice_info(format!(
                    "manifest {manifest_id} verified: {objects} object(s), {total_bytes} byte(s)"
                ));
                self.report.verifying = false;
                self.report.status = format!(
                    "manifest {manifest_id} verified: {objects} stored object(s) match their recorded digests"
                );
                self.report.verification = Some(VerifySummary {
                    manifest_id,
                    acquisition_id,
                    format,
                    objects,
                    total_bytes,
                    captured,
                    gaps,
                });
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        if self.applied_theme != Some(self.theme) {
            ui.ctx().set_visuals(self.theme.visuals());
            self.applied_theme = Some(self.theme);
        }
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
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    egui::ComboBox::from_label("Appearance")
                        .selected_text(self.theme.label())
                        .show_ui(ui, |ui| {
                            for choice in ThemeChoice::ALL {
                                ui.selectable_value(&mut self.theme, choice, choice.label());
                            }
                        });
                });
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
                if ui
                    .selectable_label(self.screen == Screen::Diff, "Diff captures")
                    .clicked()
                {
                    if self.open.is_some() {
                        self.screen = Screen::Diff;
                    } else {
                        self.notice_error("open or create a case before comparing captures");
                    }
                }
                if ui
                    .selectable_label(self.screen == Screen::Relations, "Relationships")
                    .clicked()
                {
                    if self.open.is_some() {
                        self.screen = Screen::Relations;
                        self.load_relations();
                    } else {
                        self.notice_error("open or create a case before listing relationships");
                    }
                }
                if ui
                    .selectable_label(self.screen == Screen::Findings, "Findings")
                    .clicked()
                {
                    if self.open.is_some() {
                        self.screen = Screen::Findings;
                    } else {
                        self.notice_error("open or create a case before reviewing findings");
                    }
                }
                if ui
                    .selectable_label(self.screen == Screen::Report, "Report and verify")
                    .clicked()
                {
                    if self.open.is_some() {
                        self.screen = Screen::Report;
                    } else {
                        self.notice_error("open or create a case before exporting a report");
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
                Screen::Diff => crate::diff::ui(self, ui),
                Screen::Relations => crate::relations::ui(self, ui),
                Screen::Findings => crate::findings::ui(self, ui),
                Screen::Report => crate::report::ui(self, ui),
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

/// Comma-separated tags, trimmed, deduplicated, order preserved. The core
/// validates length and control characters before anything is written.
pub fn parse_tags(text: &str) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    for tag in text.split(',') {
        let tag = tag.trim();
        if !tag.is_empty() && !tags.iter().any(|existing| existing == tag) {
            tags.push(tag.to_string());
        }
    }
    tags
}

/// An annotation needs a non-empty author label; an empty field records the
/// generic role rather than inventing a person.
fn author_label(text: &str) -> String {
    let text = text.trim();
    if text.is_empty() {
        "analyst".into()
    } else {
        text.to_string()
    }
}

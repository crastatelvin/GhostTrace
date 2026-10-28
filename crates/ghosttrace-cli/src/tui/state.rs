//! Pure TUI state and actions (plan P7).
//!
//! Rendering lives in [`views`], key mapping in [`input`], and the terminal
//! guard in [`terminal`]. Everything here is testable without a terminal: an
//! [`App`] owns one open case and applies [`Action`]s to a [`TuiState`].
//!
//! The TUI reads through the same contracts as the CLI and desktop
//! (`EventQuery`, `query_events`/`search_events`, `event_detail`,
//! `findings_for_run`), so a selection produces the same records as the GUI.

use std::path::Path;

use ghosttrace_core::analysis::rules::{AnalysisRequest, RuleConfig, findings_for_run};
use ghosttrace_core::domain::detail::EventDetail;
use ghosttrace_core::domain::finding::Finding;
use ghosttrace_core::domain::query::{EventQuery, EventRow, TimeCursor};
use ghosttrace_core::error::{CoreError, CoreResult};
use ghosttrace_core::service::CaseSession;
use ghosttrace_core::storage::read::CaseReader;
use ghosttrace_core::storage::search::{search_events, validate_search_text};
use ratatui::widgets::TableState;

/// One timeline page in the TUI. Same bound as the desktop's first page.
pub const TUI_PAGE_SIZE: u32 = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Timeline,
    Findings,
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Browse,
    Search,
    Filters,
}

/// One user intent, independent of the key that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    MoveUp,
    MoveDown,
    PageUp,
    PageDown,
    First,
    Last,
    NextPage,
    PreviousPage,
    ToggleUnresolved,
    StartSearch,
    StartFilters,
    Input(char),
    Backspace,
    Commit,
    Cancel,
    Analyze,
    ToggleView,
    Help,
    Quit,
}

/// Exact-match filters typed as `key=value` tokens. Values cannot contain
/// spaces; that is stated in the help line instead of being guessed around.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filters {
    pub kind: Option<String>,
    pub host: Option<String>,
    pub source: Option<String>,
    pub after_seconds: Option<i64>,
    pub before_seconds: Option<i64>,
}

/// Parse the TUI's filter prompt. Unknown keys and bad instants are errors, so
/// a typo never silently widens or narrows the view.
pub fn parse_filters(text: &str) -> Result<Filters, String> {
    let mut filters = Filters::default();
    let mut seen = std::collections::HashSet::new();
    for token in text.split_whitespace() {
        let (key, value) = token
            .split_once('=')
            .ok_or_else(|| format!("filter `{token}` must be key=value"))?;
        if value.is_empty() {
            return Err(format!("filter `{key}` has an empty value"));
        }
        if !seen.insert(key) {
            return Err(format!("filter `{key}` is repeated; give it once"));
        }
        match key {
            "kind" => filters.kind = Some(value.to_string()),
            "host" => filters.host = Some(value.to_string()),
            "source" => filters.source = Some(value.to_string()),
            "after" => filters.after_seconds = Some(crate::commands::parse_instant(value)?),
            "before" => filters.before_seconds = Some(crate::commands::parse_instant(value)?),
            other => {
                return Err(format!(
                    "unknown filter `{other}`; use kind, host, source, after, before"
                ));
            }
        }
    }
    if let (Some(after), Some(before)) = (filters.after_seconds, filters.before_seconds)
        && after >= before
    {
        return Err("`after` must be earlier than `before`".into());
    }
    Ok(filters)
}

/// The filters as the prompt shows them back.
pub fn describe_filters(filters: &Filters) -> String {
    let mut parts = Vec::new();
    for (name, value) in [
        ("kind", filters.kind.as_deref()),
        ("host", filters.host.as_deref()),
        ("source", filters.source.as_deref()),
    ] {
        if let Some(value) = value {
            parts.push(format!("{name}={value}"));
        }
    }
    for (name, value) in [
        ("after", filters.after_seconds),
        ("before", filters.before_seconds),
    ] {
        if let Some(value) = value {
            parts.push(format!("{name}={value}"));
        }
    }
    parts.join(" ")
}

#[derive(Debug)]
pub struct TuiState {
    pub case_label: String,
    pub display_timezone: String,
    pub revision: String,
    pub view: View,
    pub mode: Mode,
    pub query: EventQuery,
    pub rows: Vec<EventRow>,
    pub next_cursor: Option<TimeCursor>,
    pub selected: usize,
    pub detail: Option<EventDetail>,
    pub findings: Vec<Finding>,
    pub findings_selected: usize,
    pub findings_run: Option<String>,
    /// Committed search text (validated by the shared grammar).
    pub search: String,
    /// Edit buffer for the search/filter prompt.
    pub draft: String,
    pub filters: Filters,
    pub status: String,
    pub status_is_error: bool,
    pub page: usize,
    pub table: TableState,
    pub findings_table: TableState,
    /// Where `?` returns to.
    pub help_return: View,
}

impl TuiState {
    fn new(case_label: String, display_timezone: String, revision: String) -> Self {
        Self {
            case_label,
            display_timezone,
            revision,
            view: View::Timeline,
            mode: Mode::Browse,
            query: EventQuery {
                limit: TUI_PAGE_SIZE,
                ..EventQuery::default()
            },
            rows: Vec::new(),
            next_cursor: None,
            selected: 0,
            detail: None,
            findings: Vec::new(),
            findings_selected: 0,
            findings_run: None,
            search: String::new(),
            draft: String::new(),
            filters: Filters::default(),
            status: String::new(),
            status_is_error: false,
            page: 1,
            table: TableState::default(),
            findings_table: TableState::default(),
            help_return: View::Timeline,
        }
    }

    pub fn selected_finding(&self) -> Option<&Finding> {
        self.findings.get(self.findings_selected)
    }

    /// The filter prompt's starting text, so a second edit starts from the
    /// applied filters instead of a blank line.
    pub fn filter_text(&self) -> String {
        describe_filters(&self.filters)
    }
}

/// One open case plus the page cursors needed for back paging.
pub struct App {
    session: CaseSession,
    reader: CaseReader,
    pub state: TuiState,
    /// `None` starts page 1; each later entry resumes after that cursor.
    cursors: Vec<Option<TimeCursor>>,
}

impl App {
    pub fn open(case: &Path, revision: Option<String>) -> CoreResult<Self> {
        let (session, _report) = CaseSession::open(case)?;
        let reader = session.reader()?;
        let revision = match revision {
            Some(revision) => revision,
            None => reader.latest_revision(None)?.unwrap_or_default(),
        };
        let mut app = Self {
            state: TuiState::new(
                session.config().label.clone(),
                session.config().display_timezone.clone(),
                revision,
            ),
            session,
            reader,
            cursors: vec![None],
        };
        app.refresh();
        Ok(app)
    }

    /// Apply one action. Returns true when the loop should quit. Query and
    /// analysis failures are shown in the status line; they never leave a
    /// blank pane pretending the query succeeded.
    pub fn handle(&mut self, action: Action) -> bool {
        match action {
            Action::Quit => return true,
            Action::MoveUp => self.move_selection(-1),
            Action::MoveDown => self.move_selection(1),
            Action::PageUp => self.move_selection(-10),
            Action::PageDown => self.move_selection(10),
            Action::First => self.select(0),
            Action::Last => {
                if !self.state.rows.is_empty() {
                    self.select(self.state.rows.len() - 1);
                }
            }
            Action::NextPage => self.next_page(),
            Action::PreviousPage => self.previous_page(),
            Action::ToggleUnresolved => {
                self.state.query.unresolved_only = !self.state.query.unresolved_only;
                self.reset_pages();
                self.refresh();
            }
            Action::StartSearch => {
                self.state.mode = Mode::Search;
                // Start blank; the active search stays visible in the timeline
                // title, and Cancel leaves it untouched.
                self.state.draft.clear();
            }
            Action::StartFilters => {
                self.state.mode = Mode::Filters;
                // Start blank: a prefilled line silently concatenates with new
                // typing. The footer shows the filters already applied.
                self.state.draft.clear();
            }
            Action::Input(ch) => {
                if self.state.mode != Mode::Browse {
                    self.state.draft.push(ch);
                }
            }
            Action::Backspace => {
                if self.state.mode != Mode::Browse {
                    self.state.draft.pop();
                }
            }
            Action::Commit => self.commit_prompt(),
            Action::Cancel => self.cancel_prompt(),
            Action::Analyze => self.analyze(),
            Action::ToggleView => {
                self.state.view = match self.state.view {
                    View::Timeline => View::Findings,
                    View::Findings => View::Timeline,
                    View::Help => self.state.help_return,
                };
            }
            Action::Help => {
                if self.state.view == View::Help {
                    self.state.view = self.state.help_return;
                } else {
                    self.state.help_return = self.state.view;
                    self.state.view = View::Help;
                }
            }
        }
        false
    }

    fn commit_prompt(&mut self) {
        match self.state.mode {
            Mode::Browse => {}
            Mode::Search => {
                let text = self.state.draft.trim().to_string();
                if !text.is_empty()
                    && let Err(error) = validate_search_text(&text)
                {
                    self.fail(&error);
                    return;
                }
                self.state.search = text;
                self.state.mode = Mode::Browse;
                self.state.draft.clear();
                self.reset_pages();
                self.refresh();
            }
            Mode::Filters => match parse_filters(&self.state.draft) {
                Ok(filters) => {
                    self.state.filters = filters;
                    self.state.query.kind = self.state.filters.kind.clone();
                    self.state.query.host = self.state.filters.host.clone();
                    self.state.query.source = self.state.filters.source.clone();
                    self.state.query.after_seconds = self.state.filters.after_seconds;
                    self.state.query.before_seconds = self.state.filters.before_seconds;
                    self.state.mode = Mode::Browse;
                    self.reset_pages();
                    self.refresh();
                }
                Err(message) => self.fail(&CoreError::InvalidInput(message)),
            },
        }
    }

    fn cancel_prompt(&mut self) {
        match self.state.mode {
            Mode::Browse => {
                if self.state.view == View::Help {
                    self.state.view = self.state.help_return;
                }
            }
            Mode::Search | Mode::Filters => {
                self.state.mode = Mode::Browse;
                self.state.draft.clear();
            }
        }
    }

    fn reset_pages(&mut self) {
        self.cursors = vec![None];
        self.state.page = 1;
    }

    fn next_page(&mut self) {
        let Some(cursor) = self.state.next_cursor.clone() else {
            self.state.status = "no more events match this view".into();
            self.state.status_is_error = false;
            return;
        };
        self.cursors.push(Some(cursor));
        self.state.page = self.cursors.len();
        self.refresh();
    }

    fn previous_page(&mut self) {
        if self.cursors.len() <= 1 {
            self.state.status = "already on the first page".into();
            self.state.status_is_error = false;
            return;
        }
        self.cursors.pop();
        self.state.page = self.cursors.len();
        self.refresh();
    }

    fn move_selection(&mut self, delta: isize) {
        if self.state.view == View::Findings {
            let len = self.state.findings.len();
            if len == 0 {
                return;
            }
            let next = self.state.findings_selected as isize + delta;
            self.state.findings_selected = next.clamp(0, len as isize - 1) as usize;
            return;
        }
        if self.state.rows.is_empty() {
            return;
        }
        let next = self.state.selected as isize + delta;
        self.select(next.clamp(0, self.state.rows.len() as isize - 1) as usize);
    }

    fn select(&mut self, index: usize) {
        if self.state.rows.is_empty() {
            return;
        }
        self.state.selected = index.min(self.state.rows.len() - 1);
        self.load_detail();
    }

    fn ensure_revision(&mut self) {
        if !self.state.revision.is_empty() {
            return;
        }
        match self.reader.latest_revision(None) {
            Ok(Some(revision)) => self.state.revision = revision,
            Ok(None) => {}
            Err(error) => self.fail(&error),
        }
    }

    /// Re-run the current page through the shared query path.
    fn refresh(&mut self) {
        self.ensure_revision();
        if self.state.revision.is_empty() {
            self.state.rows.clear();
            self.state.next_cursor = None;
            self.state.detail = None;
            self.state.status =
                "this case has no parse run yet; import an object or scan the case first".into();
            self.state.status_is_error = true;
            return;
        }
        self.state.query.revision = self.state.revision.clone();
        self.state.query.after = self.cursors.last().cloned().flatten();
        let page = match optional_search(&self.state.search) {
            Ok(Some(text)) => search_events(
                &self.reader,
                &self.state.display_timezone,
                &self.state.query,
                &text,
            ),
            Ok(None) => self
                .reader
                .query_events(&self.state.display_timezone, &self.state.query),
            Err(error) => Err(error),
        };
        match page {
            Ok(page) => {
                self.state.rows = page.rows;
                self.state.next_cursor = page.next_cursor;
                self.state.selected = 0;
                self.state.status = format!(
                    "{} event(s) on page {}{}",
                    self.state.rows.len(),
                    self.state.page,
                    if self.state.query.unresolved_only {
                        " · unresolved only"
                    } else {
                        ""
                    }
                );
                self.state.status_is_error = false;
                self.load_detail();
            }
            Err(error) => {
                self.state.rows.clear();
                self.state.next_cursor = None;
                self.state.detail = None;
                self.fail(&error);
            }
        }
    }

    fn load_detail(&mut self) {
        let Some(row) = self.state.rows.get(self.state.selected) else {
            self.state.detail = None;
            return;
        };
        match self
            .reader
            .event_detail(&self.state.revision, &row.event_id)
        {
            Ok(detail) => self.state.detail = Some(detail),
            Err(error) => {
                self.state.detail = None;
                self.fail(&error);
            }
        }
    }

    fn analyze(&mut self) {
        if self.state.revision.is_empty() {
            self.fail(&CoreError::InvalidInput(
                "this case has no parse run to analyze".into(),
            ));
            return;
        }
        self.state.status = "analyzing the active revision…".into();
        self.state.status_is_error = false;
        let report = match self.session.analyze(&AnalysisRequest {
            revision: self.state.revision.clone(),
            config: RuleConfig::default(),
        }) {
            Ok(report) => report,
            Err(error) => {
                self.fail(&error);
                return;
            }
        };
        match findings_for_run(&self.reader, &report.run_id) {
            Ok(findings) => {
                self.state.findings = findings;
                self.state.findings_selected = 0;
                self.state.findings_run = Some(report.run_id);
                self.state.view = View::Findings;
                self.state.status = format!(
                    "analysis {} · {} finding(s){}",
                    report.state,
                    self.state.findings.len(),
                    if report.state == "partial" {
                        " (bounded pass, not complete)"
                    } else {
                        ""
                    }
                );
                self.state.status_is_error = report.state == "partial";
            }
            Err(error) => self.fail(&error),
        }
    }

    fn fail(&mut self, error: &CoreError) {
        self.state.status = format!("{}: {error}", error.code());
        self.state.status_is_error = true;
    }
}

fn optional_search(text: &str) -> CoreResult<Option<ghosttrace_core::storage::search::FtsQuery>> {
    match text.trim() {
        "" => Ok(None),
        text => validate_search_text(text).map(Some),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_parse_exact_tokens_and_reject_typos() {
        let filters =
            parse_filters("kind=auth host=web-1 after=2026-10-27T00:00:00Z").expect("filters");
        assert_eq!(filters.kind.as_deref(), Some("auth"));
        assert_eq!(filters.host.as_deref(), Some("web-1"));
        assert_eq!(filters.after_seconds, Some(1_793_059_200));
        assert_eq!(filters.before_seconds, None);
        assert_eq!(
            describe_filters(&filters),
            "kind=auth host=web-1 after=1793059200"
        );

        assert!(parse_filters("typo=value").is_err());
        assert!(parse_filters("kind=").is_err());
        assert!(parse_filters("kind").is_err());
        assert!(parse_filters("after=yesterday").is_err());
        assert!(parse_filters("after=2026-10-28T00:00:00Z before=2026-10-27T00:00:00Z").is_err());
    }

    #[test]
    fn empty_filters_describe_as_empty() {
        assert_eq!(parse_filters("   ").expect("empty"), Filters::default());
        assert_eq!(describe_filters(&Filters::default()), "");
    }
}

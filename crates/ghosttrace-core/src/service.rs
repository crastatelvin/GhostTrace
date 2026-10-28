//! The shared case session (plan Sections 8, 9, P1.2).
//!
//! `create_case` is exclusive: an existing case is never overwritten. `open_case`
//! refuses a schema newer than this application, records migration evidence,
//! and reports previously running jobs as recoverable (never auto-completed).
//! Both return a session that hands out read-only connections through the
//! same query contract the desktop, TUI, and CLI consume.

use std::path::PathBuf;

use rusqlite::Connection;

use crate::analysis::annotations::{AnnotationRevision, AppendAnnotation};
use crate::analysis::correlate::{
    CorrelateConfig, CorrelateReport, RelationshipPage, RelationshipQuery,
};
use crate::analysis::diff::{DiffQuery, DiffReport};
use crate::analysis::entities::EntityBuildReport;
use crate::analysis::rules::{AnalysisReport, AnalysisRequest};
use crate::analysis::views::{SavedFilter, SavedView};
use crate::domain::detail::{EventDetail, Histogram};
use crate::domain::finding::Finding;
use crate::domain::query::{EventPage, EventQuery};
use crate::error::{CoreError, CoreResult};
use crate::jobs::RecoverableJob;
use crate::storage::backup::BackupArtifact;
use crate::storage::migrate::AppliedMigration;
use crate::storage::read::CaseReader;
use crate::storage::writer::{CaseWriter, Param, WriteBatch, WriteOp};
use crate::storage::{CaseConfig, CaseLayout, StorageDiagnostics, collect_diagnostics};

/// Requested case metadata. The case ID is generated, never taken from input.
#[derive(Debug, Clone, Default)]
pub struct CreateCaseSpec {
    pub label: String,
    pub display_timezone: String,
    pub description: String,
}

/// What an open observed: honest evidence, not a success claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseOpenReport {
    pub diagnostics: StorageDiagnostics,
    pub migrations_applied: Vec<AppliedMigration>,
    /// Present when an existing case was migrated (fresh cases: `None`).
    pub backup: Option<BackupArtifact>,
    /// Running jobs found at open; recoverable, never completed here.
    pub recoverable_jobs: Vec<RecoverableJob>,
}

/// An open case: layout + config + the one writer + readers on demand.
pub struct CaseSession {
    layout: CaseLayout,
    case_id: String,
    config: CaseConfig,
    writer: CaseWriter,
    display_timezone: String,
}

impl CaseSession {
    /// Create a new case at `<parent_dir>/<id>.ghosttrace-case`. Fails if the
    /// case already exists (exclusive creation, storage as evidence).
    pub fn create(
        parent_dir: impl Into<PathBuf>,
        id: &str,
        spec: CreateCaseSpec,
    ) -> CoreResult<Self> {
        let id = sanitize_case_id(id)?;
        let layout = CaseLayout::new(
            parent_dir
                .into()
                .join(format!("{id}{}", crate::storage::CASE_DIR_SUFFIX)),
        );
        if layout.database_path().exists() || layout.root().exists() {
            return Err(CoreError::InvalidInput(format!(
                "case already exists: {}",
                layout.root().display()
            )));
        }
        layout.create_private_tree()?;

        let config = CaseConfig {
            label: spec.label,
            display_timezone: if spec.display_timezone.is_empty() {
                "UTC".to_string()
            } else {
                spec.display_timezone
            },
            description: spec.description,
        };
        std::fs::write(
            layout.config_path(),
            toml::to_string(&config).map_err(|e| CoreError::Storage(format!("case.toml: {e}")))?,
        )
        .map_err(|e| CoreError::Storage(format!("case.toml: {e}")))?;

        // Schema first, then the long-lived writer adopts the database.
        let connection = Connection::open(layout.database_path())
            .map_err(|e| CoreError::Storage(format!("create case database: {e}")))?;
        crate::storage::migrate::create_schema(&connection)?;
        drop(connection);

        let writer = CaseWriter::spawn(layout.database_path())?;
        // The case row is the app's own record: creation instant is generated
        // here, never taken from the spec.
        let created_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0);
        writer.execute(WriteBatch::new().push(WriteOp::fact(
            "cases",
            vec![
                "id",
                "label",
                "schema_version",
                "created_seconds",
                "display_timezone",
                "description",
            ],
            vec![
                Param::Text(id.clone()),
                Param::Text(config.label.clone()),
                Param::Int(1),
                Param::Int(created_seconds),
                Param::Text(config.display_timezone.clone()),
                Param::Text(config.description.clone()),
            ],
        )))?;
        let display_timezone = config.display_timezone.clone();
        Ok(Self {
            layout,
            case_id: id,
            config,
            writer,
            display_timezone,
        })
    }

    /// Open an existing case and bring its schema up to the supported version.
    pub fn open(root: impl Into<PathBuf>) -> CoreResult<(Self, CaseOpenReport)> {
        let layout = CaseLayout::new(root.into());
        if !layout.exists() {
            return Err(CoreError::InvalidInput(format!(
                "no case at {}",
                layout.root().display()
            )));
        }
        let config = read_case_config(&layout)?;
        let display_timezone = config.display_timezone.clone();

        let connection = Connection::open(layout.database_path())
            .map_err(|e| CoreError::Storage(format!("open case database: {e}")))?;
        let outcome =
            crate::storage::migrate::migrate(&connection, Some(&layout.diagnostics_root()))?;
        let diagnostics = collect_diagnostics(&connection)?;
        drop(connection);

        let writer = CaseWriter::spawn(layout.database_path())?;
        let (case_id, recoverable_jobs) = {
            let reader = CaseReader::open(&layout.database_path())?;
            let case_id: String = reader
                .connection()
                .query_row(
                    "SELECT id FROM cases ORDER BY created_seconds LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| CoreError::Storage(format!("case id: {error}")))?;
            (case_id, reader.recoverable_jobs()?)
        };

        let session = Self {
            layout,
            case_id,
            config,
            writer,
            display_timezone,
        };
        let report = CaseOpenReport {
            diagnostics,
            migrations_applied: outcome.applied,
            backup: outcome.backup,
            recoverable_jobs,
        };
        Ok((session, report))
    }

    pub fn layout(&self) -> &CaseLayout {
        &self.layout
    }

    /// The opaque application-generated case ID (stable across opens).
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    pub fn config(&self) -> &CaseConfig {
        &self.config
    }

    pub fn writer(&self) -> &CaseWriter {
        &self.writer
    }

    /// A read-only connection. Short-lived by design; readers never write.
    pub fn reader(&self) -> CoreResult<CaseReader> {
        CaseReader::open(&self.layout.database_path())
    }

    /// The shared query contract used by every front end.
    pub fn query_events(&self, query: &EventQuery) -> CoreResult<EventPage> {
        let reader = self.reader()?;
        reader.query_events(&self.display_timezone, query)
    }

    /// Search the indexed text of one revision (plan P4.4 contract).
    pub fn search_events(&self, query: &EventQuery, text: &str) -> CoreResult<EventPage> {
        let reader = self.reader()?;
        let text = crate::storage::search::validate_search_text(text)?;
        crate::storage::search::search_events(&reader, &self.display_timezone, query, &text)
    }

    /// Everything the inspector shows for one event.
    pub fn event_detail(&self, revision: &str, event_id: &str) -> CoreResult<EventDetail> {
        self.reader()?.event_detail(revision, event_id)
    }

    /// Bounded time histogram over the same filters, optionally restricted to
    /// the search expression. The bin width is returned with the counts.
    pub fn event_histogram(
        &self,
        query: &EventQuery,
        text: Option<&str>,
        bins: u32,
    ) -> CoreResult<Histogram> {
        let reader = self.reader()?;
        let text = match text.map(str::trim).filter(|text| !text.is_empty()) {
            Some(text) => Some(crate::storage::search::validate_search_text(text)?),
            None => None,
        };
        reader.event_histogram(query, text.as_ref(), bins)
    }

    /// Coverage-aware comparison of two recorded acquisitions (P3.1/P6.3).
    /// Both must belong to this case; scope mismatches stay `unknown` rows.
    pub fn compare_acquisitions(
        &self,
        before: &str,
        after: &str,
        query: &DiffQuery,
    ) -> CoreResult<DiffReport> {
        let reader = self.reader()?;
        crate::analysis::diff::compare_acquisitions(&reader, before, after, query)
    }

    /// Resolve scoped entities for one parse run (plan P5.1). Idempotent.
    pub fn build_entities(&self, revision: &str) -> CoreResult<EntityBuildReport> {
        let reader = self.reader()?;
        crate::analysis::entities::build_entities(&self.writer, &reader, revision)
    }

    /// Derive bounded, explainable relationships over the recorded entities.
    pub fn correlate(&self, config: &CorrelateConfig) -> CoreResult<CorrelateReport> {
        let reader = self.reader()?;
        crate::analysis::correlate::correlate(&self.writer, &reader, config)
    }

    /// Read relationships with a bounded page size and keyset cursor.
    pub fn query_relationships(&self, query: &RelationshipQuery) -> CoreResult<RelationshipPage> {
        let reader = self.reader()?;
        crate::analysis::correlate::query_relationships(&reader, query)
    }

    /// Evaluate the compiled rules against one parse run (plan P5.2).
    pub fn analyze(&self, request: &AnalysisRequest) -> CoreResult<AnalysisReport> {
        let reader = self.reader()?;
        crate::analysis::rules::run_analysis(&self.writer, &reader, request)
    }

    /// Findings recorded by one analysis run, including preserved dispositions.
    pub fn findings(&self, analysis_run_id: &str) -> CoreResult<Vec<Finding>> {
        let reader = self.reader()?;
        crate::analysis::rules::findings_for_run(&reader, analysis_run_id)
    }

    /// Append a note, tag set, or disposition. A stale `expected_previous`
    /// returns `conflict` instead of overwriting someone else's edit.
    pub fn append_annotation(&self, request: &AppendAnnotation) -> CoreResult<AnnotationRevision> {
        let reader = self.reader()?;
        crate::analysis::annotations::append(&self.writer, &reader, request)
    }

    /// Newest-first annotation history for one target.
    pub fn annotations(&self, target_id: &str, limit: u32) -> CoreResult<Vec<AnnotationRevision>> {
        let reader = self.reader()?;
        crate::analysis::annotations::history(&reader, target_id, limit)
    }

    /// The newest recorded disposition for a target, if any.
    pub fn current_disposition(
        &self,
        target_id: &str,
    ) -> CoreResult<Option<crate::domain::finding::Disposition>> {
        let reader = self.reader()?;
        crate::analysis::annotations::current_disposition(&reader, target_id)
    }

    /// Save or replace a named, validated filter.
    pub fn save_view(&self, name: &str, filter: &SavedFilter) -> CoreResult<SavedView> {
        let reader = self.reader()?;
        crate::analysis::views::save(&self.writer, &reader, name, filter)
    }

    pub fn saved_views(&self) -> CoreResult<Vec<SavedView>> {
        let reader = self.reader()?;
        crate::analysis::views::list(&reader)
    }

    pub fn saved_view(&self, name: &str) -> CoreResult<SavedView> {
        let reader = self.reader()?;
        crate::analysis::views::load(&reader, name)
    }

    /// Run a stored view against one revision through the shared query path.
    pub fn run_saved_view(&self, revision: &str, name: &str) -> CoreResult<EventPage> {
        let reader = self.reader()?;
        let view = crate::analysis::views::load(&reader, name)?;
        crate::analysis::views::run(&reader, &self.display_timezone, revision, &view)
    }
}

fn read_case_config(layout: &CaseLayout) -> CoreResult<CaseConfig> {
    std::fs::read_to_string(layout.config_path())
        .ok()
        .map(|text| {
            toml::from_str(&text).map_err(|e| CoreError::Storage(format!("case.toml: {e}")))
        })
        .unwrap_or_else(|| Ok(CaseConfig::default()))
}

/// Case IDs are application-safe filenames: letters, digits, dot, dash,
/// underscore only. Investigative labels are not permitted to steer storage
/// paths, and evidence paths never enter them.
fn sanitize_case_id(id: &str) -> CoreResult<String> {
    if id.is_empty() || id.len() > 64 {
        return Err(CoreError::InvalidInput(
            "case id must be 1..=64 chars".into(),
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(CoreError::InvalidInput(
            "case id may contain [A-Za-z0-9._-] only".into(),
        ));
    }
    Ok(id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_is_conservative() {
        assert!(sanitize_case_id("case-1").is_ok());
        assert!(sanitize_case_id("case 1").is_err(), "no spaces");
        assert!(sanitize_case_id("../escape").is_err(), "no traversal");
        assert!(sanitize_case_id("a/b").is_err());
        assert!(sanitize_case_id(&"x".repeat(65)).is_err());
    }
}

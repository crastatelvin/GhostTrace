//! The shared case session (plan Sections 8, 9, P1.2).
//!
//! `create_case` is exclusive: an existing case is never overwritten. `open_case`
//! refuses a schema newer than this application, records migration evidence,
//! and reports previously running jobs as recoverable (never auto-completed).
//! Both return a session that hands out read-only connections through the
//! same query contract the desktop, TUI, and CLI consume.

use std::path::PathBuf;

use rusqlite::Connection;

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

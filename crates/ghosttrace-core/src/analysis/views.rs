//! Named saved filters over the shared query contract (P5.2).
//!
//! Rules embodied here:
//! - A saved view is a bounded, typed value set. No SQL, no expressions, no
//!   arbitrary JSON: unknown fields are rejected on write *and* on read, so a
//!   view saved by an older or newer build fails loudly instead of silently
//!   dropping a criterion.
//! - Running a view goes through the same `query_events`/`search_events` path
//!   as the CLI, with the same keyset order and page bounds.

use chrono::Utc;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::domain::query::{EventPage, EventQuery};
use crate::error::{CoreError, CoreResult};
use crate::storage::read::CaseReader;
use crate::storage::search::{search_events, validate_search_text};
use crate::storage::writer::{CaseWriter, Param, WriteBatch, WriteOp};

const MAX_NAME_CHARS: usize = 64;
const MAX_FIELD_CHARS: usize = 512;

/// The stored filter. Every field is optional (or explicitly defaulted); all
/// values are validated before they reach a query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SavedFilter {
    pub kind: Option<String>,
    pub host: Option<String>,
    pub source: Option<String>,
    /// Indexed search text, validated by the same grammar as `search`.
    pub text: Option<String>,
    pub after_seconds: Option<i64>,
    pub before_seconds: Option<i64>,
    pub unresolved_only: bool,
    pub limit: u32,
}

impl Default for SavedFilter {
    fn default() -> Self {
        Self {
            kind: None,
            host: None,
            source: None,
            text: None,
            after_seconds: None,
            before_seconds: None,
            unresolved_only: false,
            limit: EventQuery::DEFAULT_LIMIT,
        }
    }
}

impl SavedFilter {
    pub fn validate(&self) -> CoreResult<()> {
        for (name, value) in [
            ("kind", &self.kind),
            ("host", &self.host),
            ("source", &self.source),
        ] {
            if let Some(value) = value
                && (value.is_empty()
                    || value.len() > MAX_FIELD_CHARS
                    || value.chars().any(char::is_control))
            {
                return Err(CoreError::InvalidInput(format!(
                    "saved view {name} is non-empty, control-free, and bounded"
                )));
            }
        }
        if let Some(text) = &self.text {
            if text.is_empty() || text.len() > MAX_FIELD_CHARS {
                return Err(CoreError::InvalidInput(
                    "saved view text is non-empty and bounded".into(),
                ));
            }
            validate_search_text(text)?;
        }
        if let (Some(after), Some(before)) = (self.after_seconds, self.before_seconds)
            && after >= before
        {
            return Err(CoreError::InvalidInput(
                "saved view after_seconds must be before before_seconds".into(),
            ));
        }
        if !(1..=EventQuery::MAX_LIMIT).contains(&self.limit) {
            return Err(CoreError::InvalidInput(format!(
                "saved view limit must be 1..={}",
                EventQuery::MAX_LIMIT
            )));
        }
        Ok(())
    }

    fn to_query(&self, revision: &str) -> EventQuery {
        let mut query = EventQuery::with_revision(revision);
        query.kind = self.kind.clone();
        query.host = self.host.clone();
        query.source = self.source.clone();
        query.after_seconds = self.after_seconds;
        query.before_seconds = self.before_seconds;
        query.unresolved_only = self.unresolved_only;
        query.limit = self.limit;
        query
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedView {
    pub name: String,
    pub filter: SavedFilter,
    pub created_seconds: i64,
}

pub fn save(
    writer: &CaseWriter,
    reader: &CaseReader,
    name: &str,
    filter: &SavedFilter,
) -> CoreResult<SavedView> {
    validate_name(name)?;
    filter.validate()?;
    let filter_json = serde_json::to_string(filter)
        .map_err(|error| CoreError::Storage(format!("serialize saved view: {error}")))?;
    let created_seconds = Utc::now().timestamp();
    writer.execute(WriteBatch::new().push(WriteOp::upsert(
        "saved_views",
        vec!["name", "filter_json", "created_seconds"],
        vec![
            Param::Text(name.to_string()),
            Param::Text(filter_json),
            Param::Int(created_seconds),
        ],
    )))?;
    load(reader, name)
}

fn validate_name(name: &str) -> CoreResult<()> {
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return Err(CoreError::InvalidInput(
            "saved view name is required, control-free, and at most 64 characters".into(),
        ));
    }
    Ok(())
}

pub fn load(reader: &CaseReader, name: &str) -> CoreResult<SavedView> {
    validate_name(name)?;
    let (filter_json, created_seconds): (String, i64) = reader
        .connection()
        .query_row(
            "SELECT filter_json, created_seconds FROM saved_views WHERE name = ?1",
            params![name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                CoreError::InvalidInput(format!("no saved view named {name}"))
            }
            other => CoreError::Storage(format!("read saved view: {other}")),
        })?;
    let filter: SavedFilter = serde_json::from_str(&filter_json).map_err(|error| {
        CoreError::InvalidInput(format!("saved view {name} is incompatible: {error}"))
    })?;
    filter.validate().map_err(|error| {
        CoreError::InvalidInput(format!("saved view {name} is incompatible: {error}"))
    })?;
    Ok(SavedView {
        name: name.to_string(),
        filter,
        created_seconds,
    })
}

pub fn list(reader: &CaseReader) -> CoreResult<Vec<SavedView>> {
    let mut statement = reader
        .connection()
        .prepare("SELECT name, filter_json, created_seconds FROM saved_views ORDER BY name")
        .map_err(|error| CoreError::Storage(format!("prepare saved views: {error}")))?;
    let mut rows = statement
        .query([])
        .map_err(|error| CoreError::Storage(format!("read saved views: {error}")))?;
    let mut views = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| CoreError::Storage(format!("read saved view row: {error}")))?
    {
        let name: String = row.get(0).map_err(storage_error)?;
        let filter_json: String = row.get(1).map_err(storage_error)?;
        let filter: SavedFilter = serde_json::from_str(&filter_json).map_err(|error| {
            CoreError::InvalidInput(format!("saved view {name} is incompatible: {error}"))
        })?;
        filter.validate()?;
        views.push(SavedView {
            name,
            filter,
            created_seconds: row.get(2).map_err(storage_error)?,
        });
    }
    Ok(views)
}

/// Run a stored view against one revision through the shared query path.
pub fn run(
    reader: &CaseReader,
    display_timezone: &str,
    revision: &str,
    view: &SavedView,
) -> CoreResult<EventPage> {
    let query = view.filter.to_query(revision);
    match &view.filter.text {
        Some(text) => {
            let expression = validate_search_text(text)?;
            search_events(reader, display_timezone, &query, &expression)
        }
        None => reader.query_events(display_timezone, &query),
    }
}

fn storage_error(error: rusqlite::Error) -> CoreError {
    CoreError::Storage(format!("read saved view field: {error}"))
}

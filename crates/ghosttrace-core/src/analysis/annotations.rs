//! Analyst notes, tags, and dispositions as append-only history (P5.2).
//!
//! Rules embodied here:
//! - A note is never rewritten. Editing appends a revision that names the one
//!   it supersedes, so an earlier reading stays readable.
//! - A stale edit is a conflict, not a silent last-write-wins overwrite: the
//!   caller must name the revision it based its change on.
//! - Dispositions live in history, not on the finding row, so re-running an
//!   analysis cannot destroy an analyst's dismissal.
//! - Targets are opaque ids supplied by the caller; text, tags, and the author
//!   label are bounded and control characters are rejected.

use chrono::Utc;
use rusqlite::params;

use crate::domain::finding::Disposition;
use crate::error::{CoreError, CoreResult};
use crate::storage::read::CaseReader;
use crate::storage::writer::{CaseWriter, Param, WriteBatch, WriteOp};

pub const MAX_TEXT_BYTES: usize = 16 * 1024;
pub const MAX_TAGS: usize = 16;
pub const MAX_TAG_CHARS: usize = 64;
pub const MAX_LABEL_CHARS: usize = 128;
pub const MAX_TARGET_CHARS: usize = 256;
const MAX_PAGE: u32 = 1_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnotationRevision {
    pub id: i64,
    pub target_id: String,
    pub author_label: String,
    pub created_seconds: i64,
    pub previous_revision: Option<i64>,
    pub text: String,
    pub tags: Vec<String>,
    pub disposition: Option<Disposition>,
}

/// One append operation. `expected_previous` is the revision the author saw;
/// `None` means "no revision existed when I started".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendAnnotation {
    pub target_id: String,
    pub author_label: String,
    pub text: String,
    pub tags: Vec<String>,
    pub disposition: Option<Disposition>,
    pub expected_previous: Option<i64>,
}

pub fn append(
    writer: &CaseWriter,
    reader: &CaseReader,
    request: &AppendAnnotation,
) -> CoreResult<AnnotationRevision> {
    validate_target(&request.target_id)?;
    if request.author_label.is_empty() || request.author_label.len() > MAX_LABEL_CHARS {
        return Err(CoreError::InvalidInput(
            "annotation author label is required and bounded to 128 characters".into(),
        ));
    }
    if request
        .author_label
        .chars()
        .any(|character| character.is_control())
    {
        return Err(CoreError::InvalidInput(
            "annotation author label contains control characters".into(),
        ));
    }
    if request.text.len() > MAX_TEXT_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "annotation text is limited to {MAX_TEXT_BYTES} bytes"
        )));
    }
    if request.text.is_empty() && request.tags.is_empty() && request.disposition.is_none() {
        return Err(CoreError::InvalidInput(
            "an annotation needs text, a tag, or a disposition".into(),
        ));
    }
    let mut tags = Vec::new();
    for tag in &request.tags {
        if tag.is_empty()
            || tag.chars().count() > MAX_TAG_CHARS
            || tag.chars().any(|character| character.is_control())
        {
            return Err(CoreError::InvalidInput(
                "annotation tags are non-empty, control-free, and at most 64 characters".into(),
            ));
        }
        if !tags.contains(tag) {
            tags.push(tag.clone());
        }
    }
    tags.sort();
    if tags.len() > MAX_TAGS {
        return Err(CoreError::InvalidInput(format!(
            "an annotation carries at most {MAX_TAGS} tags"
        )));
    }

    let tip = tip_id(reader, &request.target_id)?;
    if tip != request.expected_previous {
        return Err(CoreError::Conflict(format!(
            "annotation for {} moved: expected revision {:?}, current {:?}",
            request.target_id, request.expected_previous, tip
        )));
    }

    let created_seconds = Utc::now().timestamp();
    let tags_json = serde_json::to_string(&tags)
        .map_err(|error| CoreError::Storage(format!("serialize tags: {error}")))?;
    writer.execute(WriteBatch::new().push(WriteOp::fact(
        "annotation_revisions",
        vec![
            "target_id",
            "author_label",
            "created_seconds",
            "previous_revision",
            "text",
            "tags_json",
            "disposition",
        ],
        vec![
            Param::Text(request.target_id.clone()),
            Param::Text(request.author_label.clone()),
            Param::Int(created_seconds),
            Param::OptInt(request.expected_previous),
            Param::Text(request.text.clone()),
            Param::Text(tags_json),
            Param::OptText(
                request
                    .disposition
                    .map(|disposition| disposition.as_str().to_string()),
            ),
        ],
    )))?;

    current(reader, &request.target_id)?.ok_or_else(|| {
        CoreError::Storage("the annotation revision just written was not readable".into())
    })
}

/// Newest revision for one target, or `None` when it has never been annotated.
pub fn current(reader: &CaseReader, target_id: &str) -> CoreResult<Option<AnnotationRevision>> {
    validate_target(target_id)?;
    let mut statement = reader
        .connection()
        .prepare(
            "SELECT id, target_id, author_label, created_seconds, previous_revision,
                    text, tags_json, disposition
             FROM annotation_revisions
             WHERE target_id = ?1
             ORDER BY id DESC
             LIMIT 1",
        )
        .map_err(|error| CoreError::Storage(format!("prepare current annotation: {error}")))?;
    let mut rows = statement
        .query(params![target_id])
        .map_err(|error| CoreError::Storage(format!("read current annotation: {error}")))?;
    let row = rows
        .next()
        .map_err(|error| CoreError::Storage(format!("read current annotation row: {error}")))?;
    row.map(row_to_revision).transpose()
}

/// Revision history for one target, newest first.
pub fn history(
    reader: &CaseReader,
    target_id: &str,
    limit: u32,
) -> CoreResult<Vec<AnnotationRevision>> {
    validate_target(target_id)?;
    let limit = limit.clamp(1, MAX_PAGE) as i64;
    let mut statement = reader
        .connection()
        .prepare(
            "SELECT id, target_id, author_label, created_seconds, previous_revision,
                    text, tags_json, disposition
             FROM annotation_revisions
             WHERE target_id = ?1
             ORDER BY id DESC
             LIMIT ?2",
        )
        .map_err(|error| CoreError::Storage(format!("prepare annotation history: {error}")))?;
    let mut rows = statement
        .query(params![target_id, limit])
        .map_err(|error| CoreError::Storage(format!("read annotation history: {error}")))?;
    let mut revisions = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| CoreError::Storage(format!("read annotation history row: {error}")))?
    {
        revisions.push(row_to_revision(row)?);
    }
    Ok(revisions)
}

/// The newest disposition recorded for a target, if any. Findings keep their
/// initial `undismissed` row; analyst state is this history.
pub fn current_disposition(
    reader: &CaseReader,
    target_id: &str,
) -> CoreResult<Option<Disposition>> {
    let label: Option<String> = reader
        .connection()
        .query_row(
            "SELECT disposition FROM annotation_revisions
             WHERE target_id = ?1 AND disposition IS NOT NULL
             ORDER BY id DESC LIMIT 1",
            params![target_id],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(CoreError::Storage(format!(
                "read current disposition: {other}"
            ))),
        })?;
    label
        .map(|label| {
            Disposition::parse(&label).ok_or_else(|| {
                CoreError::Storage(format!("unknown annotation disposition: {label}"))
            })
        })
        .transpose()
}

fn tip_id(reader: &CaseReader, target_id: &str) -> CoreResult<Option<i64>> {
    reader
        .connection()
        .query_row(
            "SELECT id FROM annotation_revisions WHERE target_id = ?1 ORDER BY id DESC LIMIT 1",
            params![target_id],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(CoreError::Storage(format!("read annotation tip: {other}"))),
        })
}

fn row_to_revision(row: &rusqlite::Row<'_>) -> CoreResult<AnnotationRevision> {
    let label: Option<String> = row
        .get(7)
        .map_err(|error| CoreError::Storage(format!("read annotation disposition: {error}")))?;
    let disposition = label
        .map(|label| {
            Disposition::parse(&label).ok_or_else(|| {
                CoreError::Storage(format!("unknown annotation disposition: {label}"))
            })
        })
        .transpose()?;
    let tags: String = row
        .get(6)
        .map_err(|error| CoreError::Storage(format!("read annotation tags: {error}")))?;
    Ok(AnnotationRevision {
        id: row
            .get(0)
            .map_err(|error| CoreError::Storage(format!("read annotation id: {error}")))?,
        target_id: row
            .get(1)
            .map_err(|error| CoreError::Storage(format!("read annotation target: {error}")))?,
        author_label: row
            .get(2)
            .map_err(|error| CoreError::Storage(format!("read annotation author: {error}")))?,
        created_seconds: row
            .get(3)
            .map_err(|error| CoreError::Storage(format!("read annotation time: {error}")))?,
        previous_revision: row
            .get(4)
            .map_err(|error| CoreError::Storage(format!("read annotation parent: {error}")))?,
        text: row
            .get(5)
            .map_err(|error| CoreError::Storage(format!("read annotation text: {error}")))?,
        tags: serde_json::from_str(&tags).unwrap_or_default(),
        disposition,
    })
}

fn validate_target(target_id: &str) -> CoreResult<()> {
    if target_id.is_empty()
        || target_id.len() > MAX_TARGET_CHARS
        || target_id.chars().any(|character| character.is_control())
    {
        return Err(CoreError::InvalidInput(
            "annotation target id is required, control-free, and bounded".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_ids_and_dispositions_are_validated() {
        assert!(validate_target("").is_err());
        assert!(validate_target("ev-abc").is_ok());
        assert!(validate_target("ev-\n").is_err());
        assert_eq!(
            Disposition::parse("dismissed"),
            Some(Disposition::Dismissed)
        );
    }
}

//! Coverage-aware snapshot comparison (plan Sections 7, 17/P3.1).
//!
//! Rules embodied here:
//! - Scope comes first: two acquisitions with different root sets are not
//!   comparable. Their paths are reported `unknown`, never "appeared" or
//!   "disappeared".
//! - "Absent in the later capture" means *not present in the captured scope*,
//!   not "deleted". A coverage gap at that path makes the result `unknown`.
//! - A path that vanished while the same full hash appeared elsewhere is a
//!   **move candidate**; equal bytes never prove a copy or move action.
//! - Equal full hashes with equal size and mtime still mean "unchanged bytes",
//!   never "unchanged file": timestamps can be preserved deliberately.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::integrity::manifest::ManifestRoot;
use crate::storage::read::CaseReader;

/// One captured file in one acquisition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// Root-relative path, encoded losslessly.
    pub path: String,
    pub sha256: String,
    pub byte_length: i64,
    pub source_mtime_seconds: Option<i64>,
    pub source_mtime_nanos: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffClass {
    /// Same full hash and same recorded size/mtime.
    Unchanged,
    /// Same full hash; recorded size or mtime differs (metadata-only change).
    MetadataChanged,
    /// Different bytes while size *and* mtime match (timestamps preserved).
    ContentChangedEqualMetadata,
    /// Different bytes with different metadata.
    ContentChanged,
    /// Present only in the later acquisition.
    Appeared,
    /// Present in the earlier capture, absent from the later captured scope.
    NotPresentInCapturedScope,
    /// Same full hash at a different path across the two captures.
    MoveCandidate,
    /// Cannot be decided: scope mismatch, coverage gap, or missing digest.
    Unknown,
}

impl DiffClass {
    pub fn as_str(self) -> &'static str {
        match self {
            DiffClass::Unchanged => "unchanged",
            DiffClass::MetadataChanged => "metadata_changed",
            DiffClass::ContentChangedEqualMetadata => "content_changed_equal_metadata",
            DiffClass::ContentChanged => "content_changed",
            DiffClass::Appeared => "appeared",
            DiffClass::NotPresentInCapturedScope => "not_present_in_captured_scope",
            DiffClass::MoveCandidate => "move_candidate",
            DiffClass::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffRow {
    pub path: String,
    pub class: DiffClass,
    pub before: Option<SnapshotEntry>,
    pub after: Option<SnapshotEntry>,
    /// Stable explanation; never evidence content.
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffSummary {
    pub unchanged: u64,
    pub metadata_changed: u64,
    pub content_changed_equal_metadata: u64,
    pub content_changed: u64,
    pub appeared: u64,
    pub not_present_in_captured_scope: u64,
    pub move_candidates: u64,
    pub unknown: u64,
    /// Paths that share one full hash inside a snapshot. Equal bytes only.
    pub same_content_relations: u64,
    pub scope_compatible: bool,
    pub before_roots: Vec<String>,
    pub after_roots: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffReport {
    pub before_acquisition: String,
    pub after_acquisition: String,
    pub summary: DiffSummary,
    pub rows: Vec<DiffRow>,
    /// Present when more rows match beyond this page.
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffQuery {
    /// Resume strictly after this path (keyset paging).
    pub after: Option<String>,
    pub limit: u32,
}

impl DiffQuery {
    pub const MAX_LIMIT: u32 = 1_000;
    pub const DEFAULT_LIMIT: u32 = 200;

    fn effective_limit(&self) -> usize {
        self.limit.clamp(1, Self::MAX_LIMIT) as usize
    }
}

struct Loaded {
    roots: Vec<String>,
    entries: BTreeMap<String, SnapshotEntry>,
    /// Later-acquisition coverage gaps by `root/path` key.
    gaps: BTreeSet<String>,
}

/// Compare two acquisitions. Both must belong to the case behind `reader`.
pub fn compare_acquisitions(
    reader: &CaseReader,
    before_acquisition: &str,
    after_acquisition: &str,
    query: &DiffQuery,
) -> CoreResult<DiffReport> {
    let before = load(reader, before_acquisition)?;
    let after = load(reader, after_acquisition)?;
    let mut rows = Vec::new();
    let mut summary = DiffSummary {
        scope_compatible: before.roots == after.roots,
        before_roots: before.roots.clone(),
        after_roots: after.roots.clone(),
        ..DiffSummary::default()
    };
    if !summary.scope_compatible {
        summary
            .warnings
            .push("acquisitions cover different roots; results are unknown".into());
        let paths: BTreeSet<&String> = before.entries.keys().chain(after.entries.keys()).collect();
        for path in paths {
            rows.push(DiffRow {
                path: path.clone(),
                class: DiffClass::Unknown,
                before: before.entries.get(path).cloned(),
                after: after.entries.get(path).cloned(),
                reason: "acquisition roots differ".to_string(),
            });
        }
        summary.unknown = rows.len() as u64;
        return finish(before_acquisition, after_acquisition, summary, rows, query);
    }

    let mut before_only = Vec::new();
    let mut after_only = Vec::new();
    let paths: BTreeSet<&String> = before.entries.keys().chain(after.entries.keys()).collect();
    for path in paths {
        match (before.entries.get(path), after.entries.get(path)) {
            (Some(earlier), Some(later)) => {
                let (class, reason) = classify_pair(earlier, later);
                rows.push(DiffRow {
                    path: path.clone(),
                    class,
                    before: Some(earlier.clone()),
                    after: Some(later.clone()),
                    reason: reason.to_string(),
                });
            }
            (None, Some(later)) => after_only.push((path.clone(), later.clone())),
            (Some(earlier), None) => before_only.push((path.clone(), earlier.clone())),
            (None, None) => {}
        }
    }

    // Move candidates: disappeared full hash that reappears at another path.
    let mut vanished_by_digest: HashMap<&str, &str> = HashMap::new();
    for (path, entry) in &before_only {
        vanished_by_digest.insert(entry.sha256.as_str(), path.as_str());
    }
    let mut moved_before: BTreeSet<String> = BTreeSet::new();
    let mut moved_after: BTreeSet<String> = BTreeSet::new();
    for (path, entry) in &after_only {
        if let Some(vanished_path) = vanished_by_digest.get(entry.sha256.as_str()) {
            moved_before.insert((*vanished_path).to_string());
            moved_after.insert(path.clone());
        }
    }
    for (path, entry) in before_only {
        if moved_before.contains(&path) {
            rows.push(DiffRow {
                path,
                class: DiffClass::MoveCandidate,
                before: Some(entry),
                after: None,
                reason: "same full hash appears at a different path; move not proven".to_string(),
            });
        } else {
            let key = root_joined(&after.roots, &path);
            let (class, reason) = if after.gaps.contains(&key) {
                (
                    DiffClass::Unknown,
                    "coverage gap in the later acquisition; absence is not established",
                )
            } else {
                (
                    DiffClass::NotPresentInCapturedScope,
                    "not present in the later captured scope; deletion not established",
                )
            };
            rows.push(DiffRow {
                path,
                class,
                before: Some(entry),
                after: None,
                reason: reason.to_string(),
            });
        }
    }
    for (path, entry) in after_only {
        if moved_after.contains(&path) {
            rows.push(DiffRow {
                path,
                class: DiffClass::MoveCandidate,
                before: None,
                after: Some(entry),
                reason: "same full hash appears at a different path; move not proven".to_string(),
            });
        } else {
            rows.push(DiffRow {
                path,
                class: DiffClass::Appeared,
                before: None,
                after: Some(entry),
                reason: "present only in the later captured scope".to_string(),
            });
        }
    }

    rows.sort_by(|left, right| left.path.cmp(&right.path));
    summary.same_content_relations =
        same_content_relations(&before.entries) + same_content_relations(&after.entries);
    for row in &rows {
        match row.class {
            DiffClass::Unchanged => summary.unchanged += 1,
            DiffClass::MetadataChanged => summary.metadata_changed += 1,
            DiffClass::ContentChangedEqualMetadata => summary.content_changed_equal_metadata += 1,
            DiffClass::ContentChanged => summary.content_changed += 1,
            DiffClass::Appeared => summary.appeared += 1,
            DiffClass::NotPresentInCapturedScope => summary.not_present_in_captured_scope += 1,
            DiffClass::MoveCandidate => summary.move_candidates += 1,
            DiffClass::Unknown => summary.unknown += 1,
        }
    }
    finish(before_acquisition, after_acquisition, summary, rows, query)
}

fn finish(
    before_acquisition: &str,
    after_acquisition: &str,
    summary: DiffSummary,
    rows: Vec<DiffRow>,
    query: &DiffQuery,
) -> CoreResult<DiffReport> {
    let start = match &query.after {
        Some(cursor) => rows.partition_point(|row| &row.path <= cursor),
        None => 0,
    };
    let limit = query.effective_limit();
    let remaining = rows.len().saturating_sub(start);
    let page: Vec<DiffRow> = rows.into_iter().skip(start).take(limit).collect();
    let next_cursor = (remaining > page.len())
        .then(|| page.last().map(|row| row.path.clone()))
        .flatten();
    Ok(DiffReport {
        before_acquisition: before_acquisition.to_string(),
        after_acquisition: after_acquisition.to_string(),
        summary,
        rows: page,
        next_cursor,
    })
}

fn classify_pair(earlier: &SnapshotEntry, later: &SnapshotEntry) -> (DiffClass, &'static str) {
    let same_digest = earlier.sha256 == later.sha256;
    let same_size = earlier.byte_length == later.byte_length;
    let same_mtime = earlier.source_mtime_seconds == later.source_mtime_seconds
        && earlier.source_mtime_nanos == later.source_mtime_nanos;
    match (same_digest, same_size, same_mtime) {
        (true, true, true) => (DiffClass::Unchanged, "same full hash and metadata"),
        (true, _, _) => (
            DiffClass::MetadataChanged,
            "same full hash with different recorded metadata",
        ),
        (false, true, true) => (
            DiffClass::ContentChangedEqualMetadata,
            "different full hash with equal size and mtime",
        ),
        (false, _, _) => (
            DiffClass::ContentChanged,
            "different full hash and metadata",
        ),
    }
}

fn same_content_relations(entries: &BTreeMap<String, SnapshotEntry>) -> u64 {
    let mut by_digest: HashMap<&str, u64> = HashMap::new();
    for entry in entries.values() {
        *by_digest.entry(entry.sha256.as_str()).or_insert(0) += 1;
    }
    by_digest.values().filter(|count| **count > 1).count() as u64
}

fn root_joined(roots: &[String], path: &str) -> String {
    if path.is_empty() {
        roots.first().cloned().unwrap_or_default()
    } else {
        format!("{}/{}", roots.first().cloned().unwrap_or_default(), path)
    }
}

fn load(reader: &CaseReader, acquisition_id: &str) -> CoreResult<Loaded> {
    let roots_json: String = reader
        .connection()
        .query_row(
            "SELECT roots_json FROM acquisitions WHERE id = ?1",
            [acquisition_id],
            |row| row.get(0),
        )
        .map_err(|error| {
            CoreError::InvalidInput(format!("acquisition {acquisition_id}: {error}"))
        })?;
    let roots: Vec<ManifestRoot> = serde_json::from_str(&roots_json)
        .map_err(|error| CoreError::Storage(format!("roots json: {error}")))?;
    let roots: Vec<String> = roots
        .into_iter()
        .map(|root| root.native_path_encoded)
        .collect();

    let mut entries = BTreeMap::new();
    {
        let mut statement = reader
            .connection()
            .prepare(
                "SELECT o.native_path_encoded, o.sha256, o.byte_length,
                        f.source_mtime_seconds, f.source_mtime_nanos
                 FROM evidence_objects o
                 LEFT JOIN file_observations f ON f.evidence_id = o.id
                 WHERE o.acquisition_id = ?1
                   AND o.kind = 'file_content'
                   AND o.digest_status = 'complete'
                 ORDER BY o.native_path_encoded",
            )
            .map_err(|error| CoreError::Storage(format!("diff objects: {error}")))?;
        let rows = statement
            .query_map([acquisition_id], |row| {
                Ok(SnapshotEntry {
                    path: row.get(0)?,
                    sha256: row.get::<_, Vec<u8>>(1).map(|bytes| {
                        bytes
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>()
                    })?,
                    byte_length: row.get(2)?,
                    source_mtime_seconds: row.get(3)?,
                    source_mtime_nanos: row.get(4)?,
                })
            })
            .map_err(|error| CoreError::Storage(format!("diff objects: {error}")))?;
        for row in rows {
            let entry = row.map_err(|error| CoreError::Storage(format!("diff row: {error}")))?;
            entries.entry(entry.path.clone()).or_insert(entry);
        }
    }

    let mut gaps = BTreeSet::new();
    {
        let mut statement = reader
            .connection()
            .prepare(
                "SELECT path_key FROM coverage
                 WHERE acquisition_id = ?1 AND status <> 'captured'",
            )
            .map_err(|error| CoreError::Storage(format!("diff coverage: {error}")))?;
        let rows = statement
            .query_map([acquisition_id], |row| row.get::<_, String>(0))
            .map_err(|error| CoreError::Storage(format!("diff coverage: {error}")))?;
        for row in rows {
            gaps.insert(row.map_err(|error| CoreError::Storage(format!("diff gap: {error}")))?);
        }
    }

    Ok(Loaded {
        roots,
        entries,
        gaps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, digest: &str, size: i64, mtime: i64) -> SnapshotEntry {
        SnapshotEntry {
            path: path.into(),
            sha256: digest.into(),
            byte_length: size,
            source_mtime_seconds: Some(mtime),
            source_mtime_nanos: Some(0),
        }
    }

    #[test]
    fn equal_digest_with_new_mtime_is_metadata_only() {
        let earlier = entry("a", "aa", 4, 10);
        let later = entry("a", "aa", 4, 20);
        assert_eq!(
            classify_pair(&earlier, &later).0,
            DiffClass::MetadataChanged
        );
    }

    #[test]
    fn different_digest_with_equal_size_and_mtime_is_content_change() {
        let earlier = entry("a", "aa", 4, 10);
        let later = entry("a", "bb", 4, 10);
        assert_eq!(
            classify_pair(&earlier, &later).0,
            DiffClass::ContentChangedEqualMetadata
        );
    }

    #[test]
    fn equal_fields_are_unchanged() {
        let earlier = entry("a", "aa", 4, 10);
        assert_eq!(
            classify_pair(&earlier, &earlier.clone()).0,
            DiffClass::Unchanged
        );
    }
}

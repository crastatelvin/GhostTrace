//! The coverage ledger (plan Sections 6, 8; P2.1).
//!
//! Every path that was *not* fully captured gets an outcome and a stable
//! reason. A partial traversal is data, not a failure: the ledger is the
//! evidence that the scope was respected and the gaps are visible.
//!
//! Diagnostics aggregate **bounded** examples: the full list is written to the
//! coverage table rows, while the in-memory example list is capped so a
//! pathological tree cannot exhaust memory.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::domain::path::NativePath;
use crate::error::CoreError;
use crate::storage::writer::{Param, WriteBatch, WriteOp};

/// What happened to one path during traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageStatus {
    /// Captured (content immutable, verified digest in P2.2).
    Captured,
    /// Excluded by policy (exclusion patterns, depth/size caps).
    Excluded,
    /// Inaccessible now (permissions, ACL, transient I/O).
    Inaccessible,
    /// Source changed between observation and capture.
    Unstable,
    /// Vanished before capture could start.
    Vanished,
    /// A type the tool cannot capture (device, FIFO, socket).
    Unsupported,
    /// Present but unobserved: inside a skipped subtree or deferred.
    Unobserved,
}

impl CoverageStatus {
    /// True when the path's *content* was captured.
    pub fn is_captured(self) -> bool {
        matches!(self, CoverageStatus::Captured)
    }

    /// True when the outcome represents a real gap and must be reported.
    pub fn is_gap(self) -> bool {
        !self.is_captured()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CoverageStatus::Captured => "captured",
            CoverageStatus::Excluded => "excluded",
            CoverageStatus::Inaccessible => "inaccessible",
            CoverageStatus::Unstable => "unstable",
            CoverageStatus::Vanished => "vanished",
            CoverageStatus::Unsupported => "unsupported",
            CoverageStatus::Unobserved => "unobserved",
        }
    }
}

/// Stable reason codes shared with the CLI/desktop (plan Section 6 table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageReason {
    /// Policy excluded this path (pattern, depth, size, type).
    PolicyExcluded(String),
    /// Permission denied to the tool as run.
    PermissionDenied(String),
    /// Symlink or reparse point was not followed.
    NotFollowed,
    /// A special file type (FIFO, socket, device) that is never read.
    SpecialFile(String),
    /// The entry could not be opened (unknown I/O error).
    OpenFailed(String),
    /// Metadata changed between observation and use.
    MetadataChanged(String),
    /// The entry disappeared mid-traversal.
    Vanished(String),
    /// Too deep or too many entries (bounded traversal).
    TraversalLimited(String),
    /// Hardlink dedupe: bytes were captured via another path observation.
    DeduplicatedHardlink(String),
}

impl CoverageReason {
    pub fn code(&self) -> &'static str {
        match self {
            CoverageReason::PolicyExcluded(_) => "policy_excluded",
            CoverageReason::PermissionDenied(_) => "permission_denied",
            CoverageReason::NotFollowed => "symlink_not_followed",
            CoverageReason::SpecialFile(_) => "special_file",
            CoverageReason::OpenFailed(_) => "open_failed",
            CoverageReason::MetadataChanged(_) => "metadata_changed",
            CoverageReason::Vanished(_) => "vanished",
            CoverageReason::TraversalLimited(_) => "traversal_limited",
            CoverageReason::DeduplicatedHardlink(_) => "deduplicated_hardlink",
        }
    }

    /// Detail for humans; never contains evidence content.
    pub fn detail(&self) -> &str {
        match self {
            CoverageReason::PolicyExcluded(detail)
            | CoverageReason::PermissionDenied(detail)
            | CoverageReason::SpecialFile(detail)
            | CoverageReason::OpenFailed(detail)
            | CoverageReason::MetadataChanged(detail)
            | CoverageReason::Vanished(detail)
            | CoverageReason::TraversalLimited(detail)
            | CoverageReason::DeduplicatedHardlink(detail) => detail,
            CoverageReason::NotFollowed => "link metadata captured, link not followed",
        }
    }
}

/// One coverage row: the strongest per-path record of what happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageOutcome {
    /// Root-relative native path, bytes preserved.
    pub native_relative: NativePath,
    /// Traversal depth relative to the root (root itself is 0).
    pub depth: u32,
    pub status: CoverageStatus,
    pub reason: CoverageReason,
    /// Object identity when observed (device/ino or file index).
    pub object_identity: Option<String>,
    /// True for a hardlink observed at a second or later path.
    pub hardlink_alias: bool,
}

/// Scope of the coverage record (plan Section 6 locator table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageScope {
    /// A single filesystem entry.
    Entry,
    /// A subtree skipped as a whole.
    Subtree,
}

/// Bounded aggregate for progress and diagnostics. The full detail lives in
/// the database; this structure is bounded on purpose.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub captured: u64,
    pub excluded: u64,
    pub inaccessible: u64,
    pub unstable: u64,
    pub vanished: u64,
    pub unsupported: u64,
    pub unobserved: u64,
    pub hardlink_aliases: u64,
    /// Capped examples per gap category for diagnostics.
    pub examples: Vec<CoverageOutcome>,
    pub examples_complete: bool,
}

/// Cap on retained examples per gap category.
const EXAMPLES_PER_CATEGORY: usize = 3;
/// Cap on total retained examples across the whole summary.
const TOTAL_EXAMPLES: usize = 32;

impl CoverageSummary {
    pub fn new() -> Self {
        Self {
            examples_complete: true,
            ..Self::default()
        }
    }

    /// Record one outcome, keeping only bounded examples.
    pub fn record(&mut self, outcome: CoverageOutcome) {
        match outcome.status {
            CoverageStatus::Captured => self.captured += 1,
            CoverageStatus::Excluded => self.excluded += 1,
            CoverageStatus::Inaccessible => self.inaccessible += 1,
            CoverageStatus::Unstable => self.unstable += 1,
            CoverageStatus::Vanished => self.vanished += 1,
            CoverageStatus::Unsupported => self.unsupported += 1,
            CoverageStatus::Unobserved => self.unobserved += 1,
        }
        if outcome.hardlink_alias {
            self.hardlink_aliases += 1;
        }
        if outcome.status.is_gap() && self.examples.len() < TOTAL_EXAMPLES {
            let same_category = self
                .examples
                .iter()
                .filter(|existing| existing.status == outcome.status)
                .count();
            if same_category < EXAMPLES_PER_CATEGORY {
                self.examples.push(outcome);
            } else {
                self.examples_complete = false;
            }
        }
    }

    pub fn total(&self) -> u64 {
        self.captured
            + self.excluded
            + self.inaccessible
            + self.unstable
            + self.vanished
            + self.unsupported
            + self.unobserved
    }

    pub fn gaps(&self) -> u64 {
        self.total() - self.captured
    }

    /// Aggregate counts by stable reason code for reports.
    pub fn reason_counts(&self) -> HashMap<&'static str, u64> {
        let mut counts = HashMap::new();
        for example in &self.examples {
            *counts.entry(example.reason.code()).or_insert(0) += 1;
        }
        counts
    }
}

/// Build coverage-table write batches (idempotent upserts keyed by
/// acquisition + path + scope, matching the SQL unique index). The `error_code`
/// column carries the stable category plus its bounded detail.
pub fn coverage_batch(
    acquisition_id: &str,
    outcomes: &[CoverageOutcome],
) -> Result<WriteBatch, CoreError> {
    let mut batch = WriteBatch::new();
    for outcome in outcomes {
        batch = batch.push(WriteOp::upsert(
            "coverage",
            vec![
                "acquisition_id",
                "path_key",
                "status",
                "error_code",
                "scope",
                "attempts",
            ],
            vec![
                Param::Text(acquisition_id.to_string()),
                Param::Text(coverage_key(outcome)),
                Param::Text(outcome.status.as_str().to_string()),
                Param::Text(format!(
                    "{}: {}",
                    outcome.reason.code(),
                    outcome.reason.detail()
                )),
                Param::Text("entry".to_string()),
                Param::Int(1),
            ],
        ));
    }
    Ok(batch)
}

/// Stable key for the coverage unique index: the encoded native path.
pub fn coverage_key(outcome: &CoverageOutcome) -> String {
    outcome.native_relative.encoded()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(status: CoverageStatus, path: &[u8]) -> CoverageOutcome {
        CoverageOutcome {
            native_relative: NativePath::unix(path.to_vec()),
            depth: 1,
            status,
            reason: CoverageReason::PermissionDenied("EACCES".into()),
            object_identity: None,
            hardlink_alias: false,
        }
    }

    #[test]
    fn gaps_are_counted_and_bounded() {
        let mut summary = CoverageSummary::new();
        for index in 0..100 {
            summary.record(outcome(
                CoverageStatus::Inaccessible,
                format!("p{index}").as_bytes(),
            ));
        }
        assert_eq!(summary.inaccessible, 100);
        assert_eq!(summary.gaps(), 100);
        assert!(summary.examples.len() <= TOTAL_EXAMPLES);
        assert!(!summary.examples_complete);
    }

    #[test]
    fn captured_is_not_a_gap() {
        let mut summary = CoverageSummary::new();
        summary.record(outcome(CoverageStatus::Captured, b"a"));
        summary.record(outcome(CoverageStatus::Excluded, b"b"));
        assert_eq!(summary.gaps(), 1);
        assert_eq!(summary.total(), 2);
        assert!(summary.examples_complete);
    }

    #[test]
    fn reason_codes_are_stable() {
        assert_eq!(CoverageReason::NotFollowed.code(), "symlink_not_followed");
        assert_eq!(CoverageStatus::Vanished.as_str(), "vanished");
        assert!(CoverageStatus::Captured.is_captured());
        assert_eq!(
            CoverageReason::SpecialFile("fifo".into()).code(),
            "special_file"
        );
    }
}

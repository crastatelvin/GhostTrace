//! No-follow, bounded traversal (plan Sections 6, 8; P2.1).
//!
//! The walker never follows symlinks or reparse points. It preserves native
//! relative paths exactly, classifies every entry, records coverage outcomes
//! for everything it skips, and stops at depth/entry caps. Object identity
//! (Unix device + inode; Windows file index) is observed per entry so
//! hardlinks are recorded as aliases of one captured set of bytes rather
//! than being silently duplicated.

use serde::{Deserialize, Serialize};

use crate::capture::coverage::{CoverageOutcome, CoverageReason, CoverageStatus, CoverageSummary};
use crate::capture::{CaptureRejection, CaptureSpec, CaptureValidation};
use crate::domain::path::NativePath;
use crate::error::{CoreError, CoreResult};

/// Progress reporting for bounded traversal (plan Section 9: bounded, in-order
/// progress with visible percent and path scope).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraversalProgress {
    pub entries_visited: u64,
    pub directories_visited: u64,
    pub depth_cap_hit: bool,
    pub entry_cap_hit: bool,
    pub elapsed_millis: u64,
}

/// One classified filesystem entry, before any bytes are read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Fifo,
    Socket,
    BlockDevice,
    CharDevice,
    Unknown,
}

/// What the walker saw at one path.
#[derive(Debug, Clone)]
pub struct WalkedEntry {
    /// Root-relative native path, bytes preserved.
    pub native_relative: NativePath,
    /// Depth relative to the root (root itself is 0).
    pub depth: u32,
    pub kind: EntryKind,
    pub size: Option<u64>,
    /// Device and inode / file index when observable.
    pub object_identity: Option<String>,
    /// True when this identity was already observed elsewhere.
    pub hardlink_alias: bool,
    /// True when the entry is a directory that can be descended into.
    pub is_directory: bool,
}

/// Result of one traversal, ready for coverage writing.
#[derive(Debug, Clone)]
pub struct WalkOutcome {
    pub entries: Vec<WalkedEntry>,
    pub summary: CoverageSummary,
    pub outcomes: Vec<CoverageOutcome>,
    pub progress: TraversalProgress,
}

/// Traversal guard rails: stop before pathological trees consume memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkLimits {
    pub max_depth: u32,
    pub max_entries: u64,
}

impl WalkLimits {
    pub fn from_spec(spec: &CaptureSpec) -> Self {
        Self {
            max_depth: spec.max_depth,
            max_entries: spec.max_entries,
        }
    }
}

/// Platform walker selection. Unix is the verified baseline; Windows gets a
/// reviewed, honest "unsupported" until its handle-based traversal lands.
#[cfg(unix)]
pub use crate::capture::unix::walk as platform_walk;
#[cfg(not(unix))]
pub use crate::capture::windows::walk as platform_walk;

/// Traverse one root and return everything observed plus coverage for gaps.
/// The spec is validated first: an invalid spec never reaches the filesystem.
pub fn walk_root(
    root: &crate::capture::CaptureRoot,
    spec: &CaptureSpec,
) -> CoreResult<WalkOutcome> {
    match spec.validate() {
        CaptureValidation::Valid => {}
        CaptureValidation::Rejected(rejection) => {
            return Err(CaptureRejectionError(rejection).into());
        }
    }
    platform_walk(root, spec)
}

/// Error type for a rejected spec, used internally by the walker.
#[derive(Debug, Clone)]
pub struct CaptureRejectionError(pub CaptureRejection);

impl std::fmt::Display for CaptureRejectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.0.code(), self.0.detail())
    }
}

impl std::error::Error for CaptureRejectionError {}

impl From<CaptureRejectionError> for CoreError {
    fn from(error: CaptureRejectionError) -> Self {
        CoreError::InvalidInput(error.to_string())
    }
}

/// Stable classification of one directory entry by its platform metadata.
pub fn classify(kind: &EntryKind) -> (CoverageStatus, bool) {
    // Returns (coverage status when not capturable, is_capturable).
    match kind {
        EntryKind::File => (CoverageStatus::Captured, true),
        EntryKind::Directory => (CoverageStatus::Captured, false),
        EntryKind::Symlink => (CoverageStatus::Captured, false),
        EntryKind::Fifo | EntryKind::Socket | EntryKind::BlockDevice | EntryKind::CharDevice => {
            (CoverageStatus::Unsupported, false)
        }
        EntryKind::Unknown => (CoverageStatus::Unobserved, false),
    }
}

/// Helper used by platform walkers to record a not-followed symlink.
pub fn symlink_outcome(native_relative: NativePath, depth: u32) -> CoverageOutcome {
    CoverageOutcome {
        native_relative,
        depth,
        status: CoverageStatus::Captured,
        reason: CoverageReason::NotFollowed,
        object_identity: None,
        hardlink_alias: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_files_are_unsupported() {
        for kind in [
            EntryKind::Fifo,
            EntryKind::Socket,
            EntryKind::BlockDevice,
            EntryKind::CharDevice,
        ] {
            let (status, capturable) = classify(&kind);
            assert_eq!(status, CoverageStatus::Unsupported);
            assert!(!capturable, "{kind:?} must never be read");
        }
    }

    #[test]
    fn files_are_capturable_and_directories_are_not_files() {
        assert_eq!(classify(&EntryKind::File), (CoverageStatus::Captured, true));
        assert_eq!(
            classify(&EntryKind::Directory),
            (CoverageStatus::Captured, false)
        );
        assert_eq!(
            classify(&EntryKind::Symlink),
            (CoverageStatus::Captured, false)
        );
    }

    #[test]
    fn limits_come_from_the_spec() {
        let spec = crate::capture::CaptureSpec {
            roots: Vec::new(),
            follow_symlinks: false,
            max_depth: 6,
            max_entries: 42,
            max_file_bytes: 16,
            case_directory: std::path::PathBuf::from("/tmp/x"),
        };
        let limits = WalkLimits::from_spec(&spec);
        assert_eq!(limits.max_depth, 6);
        assert_eq!(limits.max_entries, 42);
    }
}

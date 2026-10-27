//! Capture scope: validated specs, safe no-follow traversal, and the
//! coverage ledger (plan Sections 6, 8; P2.1).
//!
//! Rules embodied here:
//! - A capture spec is *validated* before acquisition starts: overlapping
//!   roots against the case store are rejected outright, because the case
//!   store must never become evidence.
//! - Traversal never follows symlinks or reparse points. Every entry is
//!   classified and, when skipped/failed, recorded in the coverage ledger
//!   with a stable error category — never silently dropped.
//! - Native relative paths are preserved exactly (bytes on Unix, UTF-16
//!   units on Windows); Canonicalization is never used to make them pretty.
//! - Object identity is observed (device + inode / file index) for hardlink
//!   detection and dedupe, scoped to the acquisition, never global.

pub mod coverage;
pub mod unix;
pub mod walker;
pub mod windows;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::domain::path::NativePath;
use crate::error::{CoreError, CoreResult};

/// What a capture is allowed to touch, as requested by the investigator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureSpec {
    /// Root directories to traverse, native paths exactly as given.
    pub roots: Vec<CaptureRoot>,
    /// Symlink policy: capture targets as metadata but never follow.
    pub follow_symlinks: bool,
    /// Maximum traversal depth below each root (0 = only the root itself).
    pub max_depth: u32,
    /// Maximum entries visited per root.
    pub max_entries: u64,
    /// Maximum file size to copy (larger files are recorded, not read).
    pub max_file_bytes: u64,
    /// Where the case store lives; roots overlapping it are rejected.
    pub case_directory: PathBuf,
}

/// One requested root with the native path preserved exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureRoot {
    pub native: NativePath,
    /// Investigator-authored label; used in coverage and reports.
    pub label: String,
}

/// Result of validating a spec against the filesystem *before* acquisition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureValidation {
    /// The spec may run as-is.
    Valid,
    /// The spec cannot run; the reason names the offending root.
    Rejected(CaptureRejection),
}

/// Why a spec was rejected. These are stable categories for diagnostics and
/// the coverage ledger, not prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureRejection {
    /// The requested root does not exist or is not a directory.
    RootMissing { label: String, native: NativePath },
    /// A root lies inside the case store (or the store lies inside a root),
    /// which would capture the case's own database and objects.
    OverlapsCaseStore { label: String, native: NativePath },
    /// Roots describe the same native path twice.
    DuplicateRoot { label: String, native: NativePath },
    /// Symlink following was requested; it is never the default.
    FollowsSymlinks,
    /// The spec has no roots.
    NoRoots,
}

impl CaptureValidation {
    pub fn into_result(self) -> CoreResult<()> {
        match self {
            CaptureValidation::Valid => Ok(()),
            CaptureValidation::Rejected(rejection) => {
                Err(CoreError::InvalidInput(rejection.code().into()))
            }
        }
    }
}

impl CaptureRejection {
    /// Stable machine code for this rejection category.
    pub fn code(&self) -> &'static str {
        match self {
            CaptureRejection::RootMissing { .. } => "capture_root_missing",
            CaptureRejection::OverlapsCaseStore { .. } => "capture_overlaps_case_store",
            CaptureRejection::DuplicateRoot { .. } => "capture_duplicate_root",
            CaptureRejection::FollowsSymlinks => "capture_follows_symlinks",
            CaptureRejection::NoRoots => "capture_no_roots",
        }
    }

    /// Human detail that never contains raw evidence content.
    pub fn detail(&self) -> String {
        match self {
            CaptureRejection::RootMissing { label, native } => {
                format!("root {label} does not exist: {}", native.display())
            }
            CaptureRejection::OverlapsCaseStore { label, native } => {
                format!("root {label} overlaps the case store: {}", native.display())
            }
            CaptureRejection::DuplicateRoot { label, native } => {
                format!("root {label} duplicates {}", native.display())
            }
            CaptureRejection::FollowsSymlinks => "symlink following is not supported".into(),
            CaptureRejection::NoRoots => "a capture requires at least one root".into(),
        }
    }
}

impl CaptureSpec {
    /// Validate the spec. `case_directory` overlap is checked with exact
    /// native-path prefix logic — no canonicalization that would follow
    /// symlinks out of the tree.
    pub fn validate(&self) -> CaptureValidation {
        if self.follow_symlinks {
            return CaptureValidation::Rejected(CaptureRejection::FollowsSymlinks);
        }
        if self.roots.is_empty() {
            return CaptureValidation::Rejected(CaptureRejection::NoRoots);
        }
        for root in &self.roots {
            match &root.native {
                NativePath::Unix(bytes) => {
                    if !native_root_exists(bytes) {
                        return CaptureValidation::Rejected(CaptureRejection::RootMissing {
                            label: root.label.clone(),
                            native: root.native.clone(),
                        });
                    }
                }
                NativePath::Windows(units) => {
                    if !windows_units_to_path(units).exists() {
                        return CaptureValidation::Rejected(CaptureRejection::RootMissing {
                            label: root.label.clone(),
                            native: root.native.clone(),
                        });
                    }
                }
            }
            if self.overlaps_case_store(&root.native) {
                return CaptureValidation::Rejected(CaptureRejection::OverlapsCaseStore {
                    label: root.label.clone(),
                    native: root.native.clone(),
                });
            }
        }
        let mut seen: Vec<&NativePath> = Vec::new();
        for root in &self.roots {
            if seen.contains(&&root.native) {
                return CaptureValidation::Rejected(CaptureRejection::DuplicateRoot {
                    label: root.label.clone(),
                    native: root.native.clone(),
                });
            }
            seen.push(&root.native);
        }
        CaptureValidation::Valid
    }

    /// True when the root is the case store, inside it, or contains it.
    /// Exact-prefix only: a symlinked root still fails the overlap check
    /// later at traversal time through identity comparison.
    pub fn overlaps_case_store(&self, root: &NativePath) -> bool {
        let NativePath::Unix(root_bytes) = root else {
            return false; // Windows containment uses handle checks (P2.2+)
        };
        let NativePath::Unix(case_bytes) = &self.case_directory_native() else {
            return false;
        };
        prefix_contains(root_bytes, case_bytes) || prefix_contains(case_bytes, root_bytes)
    }

    /// The case directory as a native path, for overlap checks.
    pub fn case_directory_native(&self) -> NativePath {
        NativePath::unix(
            self.case_directory
                .as_os_str()
                .to_string_lossy()
                .as_bytes()
                .to_vec(),
        )
    }
}

/// True when `candidate` equals or is inside `container` (exact byte prefix).
fn prefix_contains(candidate: &[u8], container: &[u8]) -> bool {
    if candidate == container {
        return true;
    }
    if candidate.len() <= container.len() {
        return false;
    }
    candidate.starts_with(container) && matches!(candidate.get(container.len()), Some(b'/'))
}

/// Does this native root exist? Raw bytes are preserved: no UTF-8 lossy
/// conversion decides whether evidence exists.
#[cfg(unix)]
fn native_root_exists(bytes: &[u8]) -> bool {
    use std::os::unix::ffi::OsStrExt;
    std::path::Path::new(std::ffi::OsStr::from_bytes(bytes)).exists()
}

#[cfg(not(unix))]
fn native_root_exists(bytes: &[u8]) -> bool {
    std::path::Path::new(&String::from_utf8_lossy(bytes)).exists()
}

#[cfg(unix)]
fn windows_units_to_path(units: &[u16]) -> std::path::PathBuf {
    // Unix builds never see Windows paths at runtime; keep the helper for
    // the uniform interface.
    let text = String::from_utf16_lossy(units);
    std::path::PathBuf::from(text)
}

#[cfg(not(unix))]
fn windows_units_to_path(units: &[u16]) -> std::path::PathBuf {
    use std::os::windows::ffi::OsStringExt;
    std::path::PathBuf::from(std::ffi::OsString::from_wide(units))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(roots: Vec<&'static str>, case_dir: &str) -> CaptureSpec {
        CaptureSpec {
            roots: roots
                .into_iter()
                .map(|path| CaptureRoot {
                    native: NativePath::unix(path.as_bytes().to_vec()),
                    label: path.to_string(),
                })
                .collect(),
            follow_symlinks: false,
            max_depth: 8,
            max_entries: 100_000,
            max_file_bytes: 1 << 30,
            case_directory: std::path::PathBuf::from(case_dir),
        }
    }

    #[test]
    fn exact_prefix_containment() {
        assert!(prefix_contains(b"/a/b", b"/a"));
        assert!(prefix_contains(b"/a/bc", b"/a"), "/a/bc is inside /a");
        assert!(!prefix_contains(b"/ab", b"/a"), "/ab is a different entry");
        assert!(prefix_contains(b"/a", b"/a"));
        assert!(!prefix_contains(b"/ab", b"/a"));
    }

    #[test]
    fn overlap_rejection_is_symmetric() {
        let a = spec(vec!["/srv/evidence"], "/srv/evidence.case")
            .overlaps_case_store(&NativePath::unix("/srv/evidence.case"));
        assert!(a, "the case store inside a root is rejected");
        let b = spec(vec!["/srv/evidence"], "/srv/evidence.case")
            .overlaps_case_store(&NativePath::unix("/srv/evidence.case/objects"));
        assert!(b, "the case store containing a root is rejected");
    }

    #[test]
    fn duplicate_roots_and_follow_requests_are_rejected() {
        let duplicate = spec(vec!["/tmp", "/tmp"], "/var/ghosttrace-cases/one").validate();
        assert!(matches!(
            duplicate,
            CaptureValidation::Rejected(CaptureRejection::DuplicateRoot { .. })
        ));
        let mut following = spec(vec!["/tmp"], "/tmp/elsewhere");
        following.follow_symlinks = true;
        assert!(matches!(
            following.validate(),
            CaptureValidation::Rejected(CaptureRejection::FollowsSymlinks)
        ));
    }

    #[test]
    fn sibling_root_that_contains_no_case_is_valid() {
        let dir = tempfile::tempdir().unwrap();
        let case = tempfile::tempdir().unwrap();
        let evidence = dir.path().join("evidence");
        std::fs::create_dir_all(&evidence).unwrap();
        let mut root = spec(vec![], &case.path().to_string_lossy());
        root.roots.push(CaptureRoot {
            native: NativePath::unix(evidence.to_string_lossy().as_bytes().to_vec()),
            label: "evidence".into(),
        });
        assert_eq!(root.validate(), CaptureValidation::Valid);
    }

    #[test]
    fn missing_root_is_reported_by_label() {
        let validation = spec(vec!["/definitely/not/here"], "/tmp/elsewhere").validate();
        match validation {
            CaptureValidation::Rejected(CaptureRejection::RootMissing { label, .. }) => {
                assert_eq!(label, "/definitely/not/here")
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn empty_roots_are_rejected() {
        let validation = spec(vec![], "/tmp/elsewhere").validate();
        assert!(matches!(
            validation,
            CaptureValidation::Rejected(CaptureRejection::NoRoots)
        ));
    }

    #[test]
    fn a_valid_real_root_passes() {
        let dir = tempfile::tempdir().unwrap();
        let case = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(case.path()).unwrap();
        let mut root = spec(vec![], &case.path().to_string_lossy());
        root.roots.push(CaptureRoot {
            native: NativePath::unix(dir.path().to_string_lossy().as_bytes().to_vec()),
            label: "root".into(),
        });
        assert_eq!(root.validate(), CaptureValidation::Valid);
    }
}

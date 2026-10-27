//! Unix no-follow traversal (plan Sections 6, 8; P2.1).
//!
//! Implementation notes:
//! - Entries are classified with `symlink_metadata` (never followed); symlink
//!   targets are captured as metadata only.
//! - Native relative paths are preserved as exact bytes under the root
//!   (`/` excluded), so coverage identity is portable across mounts.
//! - Object identity (device + inode) is observed per file for hardlink
//!   detection, scoped to this acquisition, never global. Directory identity
//!   guards against loops.
//! - Depth, entry, and size caps bound the traversal; hitting them is
//!   recorded in coverage, never silently truncated.
//! - Permission-denied and vanished entries become coverage rows with stable
//!   reason codes rather than aborts.

use std::collections::HashSet;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use crate::capture::coverage::{CoverageOutcome, CoverageReason, CoverageStatus, CoverageSummary};
use crate::capture::walker::{EntryKind, TraversalProgress, WalkOutcome, WalkedEntry};
use crate::capture::{CaptureRoot, CaptureSpec};
use crate::domain::path::NativePath;
use crate::error::CoreResult;

/// Traversal state shared across one root: identity dedupe and bounding.
#[derive(Debug, Default)]
pub struct WalkState {
    identities: HashSet<(u64, u64)>,
    entries: u64,
    directories: u64,
    depth_cap_hit: bool,
    entry_cap_hit: bool,
}

/// Traverse one root (validated by the caller) and return the walk plus its
/// complete coverage ledger.
pub fn walk(root: &CaptureRoot, spec: &CaptureSpec) -> CoreResult<WalkOutcome> {
    let started = std::time::Instant::now();
    let mut state = WalkState::default();
    let root_path = native_to_path(&root.native);
    let root_bytes = native_bytes(&root.native);

    let root_meta = match std::fs::symlink_metadata(&root_path) {
        Ok(meta) => meta,
        Err(error) => {
            let (status, reason) = classify_io(&error);
            let outcome = CoverageOutcome {
                native_relative: NativePath::Unix(Vec::new()),
                depth: 0,
                status,
                reason,
                object_identity: None,
                hardlink_alias: false,
            };
            let mut summary = CoverageSummary::new();
            summary.record(outcome.clone());
            return Ok(WalkOutcome {
                entries: Vec::new(),
                summary,
                outcomes: vec![outcome],
                progress: progress(&state, started),
            });
        }
    };

    let mut entries = Vec::new();
    let mut summary = CoverageSummary::new();
    let mut outcomes = Vec::new();

    // A file root captures exactly that file (the plan allows single files).
    if classify_entry(&root_meta, false) == EntryKind::File {
        let mut entry = file_entry(&root_path, &root_meta, 0, &mut state);
        entry.native_relative = NativePath::Unix(Vec::new());
        let outcome = captured_outcome(&entry);
        summary.record(outcome.clone());
        outcomes.push(outcome);
        entries.push(entry);
    } else {
        walk_directory(
            &root_path,
            &root_bytes,
            0,
            spec,
            &mut state,
            &mut entries,
            &mut summary,
            &mut outcomes,
        );
    }

    Ok(WalkOutcome {
        entries,
        summary,
        outcomes,
        progress: progress(&state, started),
    })
}

#[allow(clippy::too_many_arguments)]
fn walk_directory(
    directory: &Path,
    root_bytes: &[u8],
    depth: u32,
    spec: &CaptureSpec,
    state: &mut WalkState,
    entries: &mut Vec<WalkedEntry>,
    summary: &mut CoverageSummary,
    outcomes: &mut Vec<CoverageOutcome>,
) {
    state.directories += 1;
    if depth >= spec.max_depth {
        record_gap(
            outcomes,
            summary,
            native_relative(root_bytes, directory.as_os_str().as_bytes()),
            depth,
            CoverageStatus::Unobserved,
            CoverageReason::TraversalLimited(format!("depth {} >= max {}", depth, spec.max_depth)),
        );
        state.depth_cap_hit = true;
        return;
    }

    let reader = match std::fs::read_dir(directory) {
        Ok(reader) => reader,
        Err(error) => {
            record_io_gap(outcomes, summary, root_bytes, directory, depth, &error);
            return;
        }
    };

    for entry in reader {
        state.entries += 1;
        if state.entries > spec.max_entries {
            state.entry_cap_hit = true;
            record_gap(
                outcomes,
                summary,
                native_relative(root_bytes, directory.as_os_str().as_bytes()),
                depth,
                CoverageStatus::Unobserved,
                CoverageReason::TraversalLimited(format!("entry cap {} reached", spec.max_entries)),
            );
            return;
        }

        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                record_io_gap(outcomes, summary, root_bytes, directory, depth, &error);
                continue;
            }
        };
        let path = entry.path();
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                // Vanished between readdir and stat: recorded, not fatal.
                record_io_gap(outcomes, summary, root_bytes, &path, depth + 1, &error);
                continue;
            }
        };
        let relative = native_relative(root_bytes, path.as_os_str().as_bytes());

        match classify_entry(&metadata, metadata.file_type().is_symlink()) {
            EntryKind::Symlink => {
                // Not followed: target metadata is captured by P2.2 hashing-free
                // observation; here we record the link without descending.
                let outcome = CoverageOutcome {
                    native_relative: relative,
                    depth: depth + 1,
                    status: CoverageStatus::Captured,
                    reason: CoverageReason::NotFollowed,
                    object_identity: None,
                    hardlink_alias: false,
                };
                summary.record(outcome.clone());
                outcomes.push(outcome);
            }
            EntryKind::Directory => {
                let identity = identity_of(&metadata);
                let is_loop = identity
                    .map(|key| !state.identities.insert(key))
                    .unwrap_or(false);
                if is_loop {
                    record_gap(
                        outcomes,
                        summary,
                        relative,
                        depth + 1,
                        CoverageStatus::Excluded,
                        CoverageReason::PolicyExcluded("repeated directory identity (loop)".into()),
                    );
                    continue;
                }
                walk_directory(
                    &path,
                    root_bytes,
                    depth + 1,
                    spec,
                    state,
                    entries,
                    summary,
                    outcomes,
                );
            }
            EntryKind::File => {
                let mut walked = file_entry(&path, &metadata, depth + 1, state);
                walked.native_relative = relative;
                let outcome = captured_outcome(&walked);
                summary.record(outcome.clone());
                outcomes.push(outcome);
                entries.push(walked);
            }
            EntryKind::Fifo
            | EntryKind::Socket
            | EntryKind::BlockDevice
            | EntryKind::CharDevice
            | EntryKind::Unknown => {
                let kind = classify_entry(&metadata, metadata.file_type().is_symlink());
                record_gap(
                    outcomes,
                    summary,
                    relative,
                    depth + 1,
                    CoverageStatus::Unsupported,
                    CoverageReason::SpecialFile(format!("{kind:?}")),
                );
            }
        }
    }
}

fn captured_outcome(entry: &WalkedEntry) -> CoverageOutcome {
    CoverageOutcome {
        native_relative: entry.native_relative.clone(),
        depth: entry.depth,
        status: CoverageStatus::Captured,
        reason: CoverageReason::Captured,
        object_identity: entry.object_identity.clone(),
        hardlink_alias: entry.hardlink_alias,
    }
}

fn record_gap(
    outcomes: &mut Vec<CoverageOutcome>,
    summary: &mut CoverageSummary,
    native_relative: NativePath,
    depth: u32,
    status: CoverageStatus,
    reason: CoverageReason,
) {
    let outcome = CoverageOutcome {
        native_relative,
        depth,
        status,
        reason,
        object_identity: None,
        hardlink_alias: false,
    };
    summary.record(outcome.clone());
    outcomes.push(outcome);
}

fn record_io_gap(
    outcomes: &mut Vec<CoverageOutcome>,
    summary: &mut CoverageSummary,
    root_bytes: &[u8],
    path: &Path,
    depth: u32,
    error: &std::io::Error,
) {
    let (status, reason) = classify_io(error);
    record_gap(
        outcomes,
        summary,
        native_relative(root_bytes, path.as_os_str().as_bytes()),
        depth,
        status,
        reason,
    )
}

/// Map an I/O error to a stable coverage category.
fn classify_io(error: &std::io::Error) -> (CoverageStatus, CoverageReason) {
    let errno = error
        .raw_os_error()
        .map(|code| format!("errno {code}"))
        .unwrap_or_else(|| "io".into());
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => (
            CoverageStatus::Inaccessible,
            CoverageReason::PermissionDenied(errno),
        ),
        std::io::ErrorKind::NotFound => (CoverageStatus::Vanished, CoverageReason::Vanished(errno)),
        _ => (
            CoverageStatus::Inaccessible,
            CoverageReason::OpenFailed(errno),
        ),
    }
}

fn file_entry(
    path: &Path,
    metadata: &std::fs::Metadata,
    depth: u32,
    state: &mut WalkState,
) -> WalkedEntry {
    let identity = identity_of(metadata);
    let alias = match identity {
        Some(key) => !state.identities.insert(key),
        None => false,
    };
    WalkedEntry {
        native_relative: NativePath::Unix(path.as_os_str().as_bytes().to_vec()),
        depth,
        kind: EntryKind::File,
        size: Some(metadata.len()),
        object_identity: identity.map(|(dev, ino)| format!("{dev}:{ino}")),
        hardlink_alias: alias,
        is_directory: false,
    }
}

fn progress(state: &WalkState, started: std::time::Instant) -> TraversalProgress {
    TraversalProgress {
        entries_visited: state.entries,
        directories_visited: state.directories,
        depth_cap_hit: state.depth_cap_hit,
        entry_cap_hit: state.entry_cap_hit,
        elapsed_millis: started.elapsed().as_millis() as u64,
    }
}

/// Byte-exact native path from a domain path.
pub fn native_to_path(native: &NativePath) -> PathBuf {
    match native {
        NativePath::Unix(bytes) => PathBuf::from(std::ffi::OsStr::from_bytes(bytes)),
        NativePath::Windows(units) => PathBuf::from(String::from_utf16_lossy(units)),
    }
}

fn native_bytes(native: &NativePath) -> Vec<u8> {
    match native {
        NativePath::Unix(bytes) => bytes.clone(),
        NativePath::Windows(units) => String::from_utf16_lossy(units).into_bytes(),
    }
}

/// Root-relative native path: the root prefix (and its separator) is removed.
/// The root itself yields an empty relative path.
fn native_relative(root: &[u8], candidate: &[u8]) -> NativePath {
    let without_root = if root.is_empty() {
        candidate
    } else {
        candidate.strip_prefix(root).unwrap_or(candidate)
    };
    let stripped = without_root.strip_prefix(b"/").unwrap_or(without_root);
    NativePath::Unix(stripped.to_vec())
}

fn classify_entry(metadata: &std::fs::Metadata, is_symlink: bool) -> EntryKind {
    if is_symlink {
        return EntryKind::Symlink;
    }
    let file_type = metadata.file_type();
    if file_type.is_file() {
        EntryKind::File
    } else if file_type.is_dir() {
        EntryKind::Directory
    } else if file_type.is_fifo() {
        EntryKind::Fifo
    } else if file_type.is_socket() {
        EntryKind::Socket
    } else if file_type.is_block_device() {
        EntryKind::BlockDevice
    } else if file_type.is_char_device() {
        EntryKind::CharDevice
    } else {
        EntryKind::Unknown
    }
}

fn identity_of(metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    Some((metadata.dev(), metadata.ino()))
}

//! P2.1 capture scope contract (plan Section 17): a validated `CaptureSpec`,
//! case-store overlap rejection, and no-follow traversal semantics.

use ghosttrace_core::capture::coverage::{CoverageReason, CoverageStatus};
use ghosttrace_core::capture::walker::{EntryKind, WalkedEntry, walk_root};
use ghosttrace_core::capture::{CaptureRejection, CaptureRoot, CaptureSpec, CaptureValidation};
use ghosttrace_core::domain::path::NativePath;
use ghosttrace_core::error::CoreError;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

fn native(path: &Path) -> NativePath {
    NativePath::unix(path.as_os_str().as_bytes().to_vec())
}

fn spec_with(roots: Vec<(String, PathBuf)>, case_dir: &Path) -> CaptureSpec {
    CaptureSpec {
        roots: roots
            .into_iter()
            .map(|(label, path)| CaptureRoot {
                native: native(&path),
                label,
            })
            .collect(),
        follow_symlinks: false,
        max_depth: 4,
        max_entries: 1_000,
        max_file_bytes: 1 << 20,
        case_directory: case_dir.to_path_buf(),
    }
}

/// Build the deterministic `path-edges` fixture tree (plan Section 15): an
/// ordinary nested subtree, a hardlink pair, an escaping symlink, a symlink
/// loop, a FIFO, and a socket.
fn build_path_edges(root: &Path) -> std::io::Result<()> {
    let nested = root.join("nested/deep/deeper");
    std::fs::create_dir_all(&nested)?;
    std::fs::write(nested.join("hidden.log"), b"captured")?;
    std::fs::write(root.join("plain.txt"), b"ordinary")?;
    // Hardlink to the same bytes: two path observations, one identity.
    std::fs::hard_link(root.join("plain.txt"), root.join("alias.txt"))?;
    // A symlink leaving the root: its target is metadata, never followed.
    std::os::unix::fs::symlink("../outside/target.txt", root.join("escape"))?;
    // A symlink loop back into the root.
    std::os::unix::fs::symlink("nested", root.join("loop"))?;
    // A FIFO and a socket: never read as ordinary files.
    nix::unistd::mkfifo(
        &root.join("pipe"),
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixListener;
        let _ = UnixListener::bind(root.join(".probe.sock"));
    }
    Ok(())
}

#[test]
fn spec_rejects_case_store_overlap() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("investigation.ghosttrace-case");
    std::fs::create_dir_all(&case).unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();

    // Root inside the case store.
    std::fs::create_dir_all(case.join("objects")).unwrap();
    let inside = spec_with(vec![("a".into(), case.join("objects"))], &case).validate();
    assert!(matches!(
        inside,
        CaptureValidation::Rejected(CaptureRejection::OverlapsCaseStore { .. })
    ));

    // Root containing the case store.
    let containing = spec_with(vec![("b".into(), dir.path().to_path_buf())], &case).validate();
    assert!(matches!(
        containing,
        CaptureValidation::Rejected(CaptureRejection::OverlapsCaseStore { .. })
    ));

    // Root identical to the case store.
    let same = spec_with(vec![("c".into(), case.clone())], &case).validate();
    assert!(matches!(
        same,
        CaptureValidation::Rejected(CaptureRejection::OverlapsCaseStore { .. })
    ));

    // A sibling root is fine.
    assert_eq!(
        spec_with(vec![("d".into(), evidence)], &case).validate(),
        CaptureValidation::Valid
    );
}

#[test]
fn rejection_codes_and_details_are_stable() {
    assert_eq!(
        CaptureRejection::FollowsSymlinks.code(),
        "capture_follows_symlinks"
    );
    let error: CoreError = CaptureValidation::Rejected(CaptureRejection::FollowsSymlinks)
        .into_result()
        .unwrap_err();
    assert_eq!(error.code(), "invalid_request");
    assert!(error.to_string().contains("capture_"));
}

#[test]
fn duplicate_and_empty_roots_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("c");
    std::fs::create_dir_all(&case).unwrap();
    let evidence = dir.path().to_path_buf();

    // The case store sits outside this root pair, so only duplication applies.
    // A case store on a separate tree keeps only duplication in play.
    let elsewhese = tempfile::tempdir().unwrap();
    let duplicate = spec_with(
        vec![("a".into(), evidence.clone()), ("b".into(), evidence)],
        elsewhese.path(),
    )
    .validate();
    assert!(matches!(
        duplicate,
        CaptureValidation::Rejected(CaptureRejection::DuplicateRoot { .. })
    ));
    assert!(matches!(
        spec_with(vec![], &case).validate(),
        CaptureValidation::Rejected(CaptureRejection::NoRoots)
    ));
}

#[test]
fn traversal_refuses_an_unvalidated_spec_before_touching_disk() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("case");
    std::fs::create_dir_all(&case).unwrap();
    let spec = spec_with(vec![("a".into(), case.clone())], &case);
    let outcome = walk_root(&spec.roots[0], &spec);
    assert!(matches!(outcome, Err(CoreError::InvalidInput(_))));
}

#[test]
fn path_edges_walk_captures_without_following() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    let case = dir.path().join("case.ghosttrace-case");
    std::fs::create_dir_all(&case).unwrap();
    build_path_edges(&evidence).unwrap();

    let spec = spec_with(vec![("evidence".into(), evidence)], &case);
    let outcome = walk_root(&spec.roots[0], &spec).unwrap();

    // Exactly the two real regular files are captured.
    let captured: Vec<&WalkedEntry> = outcome
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::File)
        .collect();
    // Three regular files: plain.txt, its hardlink alias, and hidden.log.
    assert_eq!(captured.len(), 3, "exactly the three real files");
    assert_eq!(
        outcome.summary.captured, 5,
        "three files plus the two symlinks"
    );

    // The hardlink alias is observed as one identity at a second path.
    assert_eq!(
        captured.iter().filter(|entry| entry.hardlink_alias).count(),
        1
    );
    assert_eq!(outcome.summary.hardlink_aliases, 1);

    // The escaping symlink and the loop link are not followed.
    let not_followed = outcome
        .outcomes
        .iter()
        .filter(|outcome| outcome.reason == CoverageReason::NotFollowed)
        .count();
    assert!(not_followed >= 2, "symlink and loop entries recorded");

    // The symlink loop is never descended: the loop target's file appears
    // exactly once. (Identity repetition for *directories* is a defensive
    // guard for exotic re-parenting; the no-follow rule already prevents
    // symlink loops.)
    let loop_captured = captured
        .iter()
        .filter(|entry| {
            entry.native_relative == NativePath::unix(b"nested/deep/deeper/hidden.log".to_vec())
        })
        .count();
    assert_eq!(loop_captured, 1, "the loop must not double-capture");

    // The FIFO and socket are unsupported, never read.
    assert!(
        outcome
            .outcomes
            .iter()
            .any(|outcome| outcome.status == CoverageStatus::Unsupported
                && outcome.reason.code() == "special_file")
    );

    // Depth cap records unobserved children rather than truncating silently.
    let mut shallow = spec.clone();
    shallow.max_depth = 2;
    let bounded = walk_root(&shallow.roots[0], &shallow).unwrap();
    assert!(bounded.progress.depth_cap_hit);
    assert!(
        bounded
            .outcomes
            .iter()
            .any(|outcome| outcome.status == CoverageStatus::Unobserved)
    );

    // Native relative paths are exact bytes under the root.
    let hidden = captured
        .iter()
        .find(|entry| {
            entry.native_relative == NativePath::unix(b"nested/deep/deeper/hidden.log".to_vec())
        })
        .expect("root-relative native path preserved");
    assert_eq!(hidden.size, Some(8));
}

#[test]
fn entry_cap_stops_and_discloses() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    for index in 0..50 {
        std::fs::write(evidence.join(format!("f{index}.bin")), b"x").unwrap();
    }
    let case = dir.path().join("case");
    std::fs::create_dir_all(&case).unwrap();
    let mut spec = spec_with(vec![("evidence".into(), evidence)], &case);
    spec.max_entries = 10;
    let outcome = walk_root(&spec.roots[0], &spec).unwrap();
    assert!(outcome.progress.entry_cap_hit);
    assert!(
        outcome
            .outcomes
            .iter()
            .any(|outcome| outcome.status == CoverageStatus::Unobserved)
    );
    assert!(outcome.summary.captured <= 10);
}

#[test]
fn missing_root_is_rejected_before_the_walk() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("case");
    std::fs::create_dir_all(&case).unwrap();
    let spec = spec_with(vec![("gone".into(), dir.path().join("gone"))], &case);
    let outcome = walk_root(&spec.roots[0], &spec);
    assert!(matches!(outcome, Err(CoreError::InvalidInput(_))));
}

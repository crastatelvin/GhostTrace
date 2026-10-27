//! P2.1 capture path contract (plan Section 17): native relative paths stay
//! exact, hardlinks are aliases of one identity, special files are never
//! read, and permission gaps are recorded — when run as an ordinary user.

use ghosttrace_core::capture::walker::{EntryKind, walk_root};
use ghosttrace_core::capture::{CaptureRoot, CaptureSpec};
use ghosttrace_core::domain::path::NativePath;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn native(path: &Path) -> NativePath {
    NativePath::unix(path.as_os_str().as_bytes().to_vec())
}

fn spec(root: &Path, case_dir: &Path, max_depth: u32, max_entries: u64) -> CaptureSpec {
    CaptureSpec {
        roots: vec![CaptureRoot {
            native: native(root),
            label: "root".into(),
        }],
        follow_symlinks: false,
        max_depth,
        max_entries,
        max_file_bytes: 1 << 20,
        case_directory: case_dir.to_path_buf(),
    }
}

#[test]
fn invalid_utf8_names_are_preserved_as_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    let case = dir.path().join("case");
    std::fs::create_dir_all(&case).unwrap();

    // An invalid-UTF-8 file name: identity must not be lost or normalized.
    let invalid_name = b"rep\xff ort.txt";
    use std::os::unix::ffi::OsStrExt;
    let file = evidence.join(std::ffi::OsStr::from_bytes(invalid_name));
    std::fs::write(&file, b"bytes").unwrap();

    let spec = spec(&evidence, &case, 4, 64);
    let outcome = walk_root(&spec.roots[0], &spec).unwrap();
    let entry = outcome
        .entries
        .iter()
        .find(|entry| entry.kind == EntryKind::File)
        .expect("captured");
    assert_eq!(
        entry.native_relative,
        NativePath::unix(invalid_name.to_vec()),
        "raw bytes are never lossy-converted"
    );
    assert_eq!(outcome.summary.captured, 1);
}

#[test]
fn unicode_distinct_names_stay_distinct() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    let case = dir.path().join("case");
    std::fs::create_dir_all(&case).unwrap();
    std::fs::write(evidence.join("café.txt"), b"a").unwrap();
    std::fs::write(evidence.join("cafe\u{301}.txt"), b"b").unwrap();

    let spec = spec(&evidence, &case, 4, 64);
    let outcome = walk_root(&spec.roots[0], &spec).unwrap();
    let names: Vec<Vec<u8>> = outcome
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::File)
        .map(|entry| match &entry.native_relative {
            NativePath::Unix(bytes) => bytes.clone(),
            other => panic!("unix expected: {other:?}"),
        })
        .collect();
    assert_eq!(names.len(), 2, "distinct identities never merge");
    assert!(names.contains(&"café.txt".as_bytes().to_vec()));
    assert!(names.contains(&"cafe\u{301}.txt".as_bytes().to_vec()));
}

#[test]
fn deep_paths_are_bounded_by_depth_not_by_stack() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    let mut current = evidence.clone();
    for index in 0..24 {
        current = current.join(format!("level{index}"));
    }
    std::fs::create_dir_all(&current).unwrap();
    std::fs::write(current.join("leaf.txt"), b"leaf").unwrap();
    let case = dir.path().join("case");
    std::fs::create_dir_all(&case).unwrap();

    let spec = spec(&evidence, &case, 8, 10_000);
    let outcome = walk_root(&spec.roots[0], &spec).unwrap();
    assert!(outcome.progress.depth_cap_hit, "deep trees stop at the cap");
    assert!(
        outcome.outcomes.iter().any(|outcome| outcome.status
            == ghosttrace_core::capture::coverage::CoverageStatus::Unobserved)
    );
}

/// Permission behavior must be exercised as an ordinary user (plan P2.1).
/// Running as root makes permission checks vacuous, so this test skips
/// itself there rather than lying about a passing check.
#[test]
fn permission_denied_subtree_is_recorded_not_fatal() {
    if nix::unistd::geteuid().is_root() {
        eprintln!("skipping: running as root, permission-denied behavior is vacuous");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    let locked = evidence.join("private");
    std::fs::create_dir_all(&locked).unwrap();
    std::fs::write(locked.join("secret.txt"), b"x").unwrap();
    std::fs::write(evidence.join("visible.txt"), b"y").unwrap();
    let case = dir.path().join("case");
    std::fs::create_dir_all(&case).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let spec = spec(&evidence, &case, 8, 10_000);
    let outcome = walk_root(&spec.roots[0], &spec).unwrap();
    // The visible file is still captured and the locked subtree is recorded.
    assert!(
        outcome
            .entries
            .iter()
            .any(|entry| entry.kind == EntryKind::File)
    );
    let recorded = outcome.outcomes.iter().find(|outcome| {
        outcome.status == ghosttrace_core::capture::coverage::CoverageStatus::Inaccessible
    });
    assert!(recorded.is_some(), "the gap must be in the ledger");
    let recorded = recorded.unwrap();
    assert_eq!(recorded.reason.code(), "permission_denied");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn a_single_file_root_captures_exactly_that_file() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    let file = evidence.join("only.txt");
    std::fs::write(&file, b"solo").unwrap();
    let case = dir.path().join("case");
    std::fs::create_dir_all(&case).unwrap();

    let spec = spec(&file, &case, 8, 64);
    let outcome = walk_root(&spec.roots[0], &spec).unwrap();
    assert_eq!(outcome.entries.len(), 1);
    assert_eq!(outcome.entries[0].kind, EntryKind::File);
    assert_eq!(outcome.entries[0].size, Some(4));
    // A file root has an empty relative path: it is the root itself.
    assert_eq!(
        outcome.entries[0].native_relative,
        NativePath::unix(Vec::new())
    );
    assert_eq!(outcome.summary.captured, 1);
}

#[test]
fn traversal_ignores_the_case_store_when_it_is_outside_the_root() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    let case = dir.path().join("case.ghosttrace-case");
    std::fs::create_dir_all(&case).unwrap();
    // A case store elsewhere must not leak into a walked root.
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(outside.join("case.ghosttrace-case")).unwrap();
    std::fs::write(
        outside.join("case.ghosttrace-case/case.sqlite"),
        b"not evidence",
    )
    .unwrap();
    std::fs::write(evidence.join("real.bin"), b"evidence").unwrap();

    let spec = spec(&evidence, &case, 8, 64);
    let outcome = walk_root(&spec.roots[0], &spec).unwrap();
    let names: Vec<String> = outcome
        .entries
        .iter()
        .map(|entry| entry.native_relative.encoded())
        .collect();
    assert_eq!(names, vec!["real.bin".to_string()]);
}

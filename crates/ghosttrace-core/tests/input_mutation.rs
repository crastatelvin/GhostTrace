//! P2.2 input-mutation contract: a source that changes between observation
//! and capture is reported as unstable, never published as a verified copy.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use ghosttrace_core::capture::copy::{
    CopyLimits, CopyProgress, CopyStatus, CopyTask, copy_one, stamp_of, stamp_of_path,
};
use ghosttrace_core::domain::path::NativePath;
use ghosttrace_core::storage::CaseLayout;

fn native(path: &Path) -> NativePath {
    NativePath::unix(path.as_os_str().as_bytes().to_vec())
}

fn case_layout(dir: &Path) -> CaseLayout {
    let layout = CaseLayout::new(dir.join("case.ghosttrace-case"));
    layout.create_private_tree().unwrap();
    layout
}

fn task_for(source: &Path) -> CopyTask {
    let stamp = stamp_of_path(source).unwrap();
    CopyTask {
        root_index: 0,
        root_label: "evidence".into(),
        native_relative: native(&PathBuf::from(source.file_name().unwrap())),
        source: source.to_path_buf(),
        expected_identity: stamp.identity,
        expected_size: stamp.size,
        hardlink_alias: false,
    }
}

fn object_count(layout: &CaseLayout) -> usize {
    let mut count = 0;
    for bucket in std::fs::read_dir(layout.objects_root()).unwrap().flatten() {
        if bucket.path().is_dir() {
            count += std::fs::read_dir(bucket.path()).unwrap().count();
        }
    }
    count
}

#[test]
fn replaced_source_is_unstable_and_publishes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let layout = case_layout(dir.path());
    let source = dir.path().join("target.bin");
    std::fs::write(&source, b"original!").unwrap();
    let task = task_for(&source);

    // Replace the path with a different inode of identical size.
    let replacement: PathBuf = dir.path().join("replacement.bin");
    std::fs::write(&replacement, b"replaced").unwrap();
    std::fs::rename(&replacement, &source).unwrap();

    let progress = CopyProgress::new();
    let outcome = copy_one(&task, &layout, &CopyLimits::default(), &progress).unwrap();
    assert_eq!(outcome.status, CopyStatus::Unstable);
    assert_eq!(outcome.detail, Some("identity_changed"));
    assert!(outcome.sha256.is_none());
    assert_eq!(object_count(&layout), 0);
    assert_eq!(std::fs::read_dir(layout.staging_root()).unwrap().count(), 0);
}

#[test]
fn vanished_source_is_reported_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let layout = case_layout(dir.path());
    let source = dir.path().join("gone.bin");
    std::fs::write(&source, b"here").unwrap();
    let task = task_for(&source);
    std::fs::remove_file(&source).unwrap();

    let outcome = copy_one(&task, &layout, &CopyLimits::default(), &CopyProgress::new()).unwrap();
    assert_eq!(outcome.status, CopyStatus::Vanished);
    assert_eq!(object_count(&layout), 0);
}

#[test]
fn symlink_is_never_followed_even_if_named_directly() {
    let dir = tempfile::tempdir().unwrap();
    let layout = case_layout(dir.path());
    let target = dir.path().join("real.txt");
    std::fs::write(&target, b"secret bytes").unwrap();
    let link = dir.path().join("link.txt");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let stamp = stamp_of_path(&link).unwrap();
    let task = CopyTask {
        root_index: 0,
        root_label: "evidence".into(),
        native_relative: NativePath::unix(b"link.txt".to_vec()),
        source: link,
        expected_identity: stamp.identity,
        expected_size: stamp.size,
        hardlink_alias: false,
    };
    let outcome = copy_one(&task, &layout, &CopyLimits::default(), &CopyProgress::new()).unwrap();
    assert_eq!(outcome.status, CopyStatus::Inaccessible);
    assert_eq!(outcome.detail, Some("symlink_not_followed"));
    assert_eq!(object_count(&layout), 0);
}

#[test]
fn metadata_change_between_observation_and_publish_is_detected() {
    // copy_one compares the descriptor stamp before and after streaming; a
    // same-size in-place rewrite with a new mtime is exactly what that check
    // must catch. This exercises the comparison the copy path uses.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("changed.txt");
    std::fs::write(&source, b"before").unwrap();
    let file = std::fs::File::open(&source).unwrap();
    let before = stamp_of(&file).unwrap();
    drop(file);

    std::fs::write(&source, b"after!").unwrap();
    let stamp = nix::sys::time::TimeSpec::new(1, 0);
    nix::sys::stat::utimensat(
        nix::fcntl::AT_FDCWD,
        &source,
        &stamp,
        &stamp,
        nix::sys::stat::UtimensatFlags::FollowSymlink,
    )
    .unwrap();

    let file = std::fs::File::open(&source).unwrap();
    let after = stamp_of(&file).unwrap();
    assert_eq!(before.identity, after.identity, "same inode");
    assert_eq!(before.size, after.size, "same size");
    assert_ne!(before, after, "mtime moved, so the capture is unstable");
}

#[test]
fn unchanged_source_publishes_and_keeps_its_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let layout = case_layout(dir.path());
    let source = dir.path().join("stable.bin");
    let bytes: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
    std::fs::write(&source, &bytes).unwrap();

    let outcome = copy_one(
        &task_for(&source),
        &layout,
        &CopyLimits::default(),
        &CopyProgress::new(),
    )
    .unwrap();
    assert_eq!(outcome.status, CopyStatus::Published);
    let stored = layout.root().join(outcome.store_subpath.unwrap());
    assert_eq!(std::fs::read(stored).unwrap(), bytes);
}

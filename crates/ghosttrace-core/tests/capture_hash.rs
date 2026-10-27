//! P2.2 copy/hash contract: known vectors, bounded memory, exact captured
//! bytes, and the rule that a digest always describes the stored copy.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use ghosttrace_core::capture::copy::{
    CopyLimits, CopyOutcome, CopyProgress, CopyStatus, CopyTask, copy_one,
};
use ghosttrace_core::domain::path::NativePath;
use ghosttrace_core::integrity::hash::{
    HASH_BUFFER_BYTES, StreamDigest, digest_file, digest_reader, sha256_hex,
};
use ghosttrace_core::storage::CaseLayout;

fn case_layout(dir: &Path) -> CaseLayout {
    let layout = CaseLayout::new(dir.join("case.ghosttrace-case"));
    layout.create_private_tree().unwrap();
    layout
}

fn task(source: &Path, relative: &[u8]) -> CopyTask {
    let stamp = ghosttrace_core::capture::copy::stamp_of_path(source).unwrap();
    CopyTask {
        root_index: 0,
        root_label: "root".into(),
        native_relative: NativePath::unix(relative.to_vec()),
        source: source.to_path_buf(),
        expected_identity: stamp.identity,
        expected_size: stamp.size,
        hardlink_alias: false,
    }
}

fn copy(source: &Path, layout: &CaseLayout) -> (CopyOutcome, PathBuf) {
    let progress = CopyProgress::new();
    let outcome = copy_one(
        &task(source, b"file.bin"),
        layout,
        &CopyLimits::default(),
        &progress,
    )
    .unwrap();
    let stored = layout
        .root()
        .join(outcome.store_subpath.clone().expect("published copy"));
    (outcome, stored)
}

#[test]
fn known_sha256_vectors() {
    let never = AtomicBool::new(false);
    assert_eq!(
        sha256_hex(&digest_reader(&mut &b""[..], &never).unwrap().sha256),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(&digest_reader(&mut &b"abc"[..], &never).unwrap().sha256),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// A reader that never emits more than the fixed buffer: proves hashing
/// memory does not scale with input size.
struct CountingReader {
    remaining: u64,
    largest_request: usize,
}

impl std::io::Read for CountingReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.largest_request = self.largest_request.max(buffer.len());
        if self.remaining == 0 {
            return Ok(0);
        }
        let take = (buffer.len() as u64).min(self.remaining) as usize;
        buffer[..take].fill(0x5a);
        self.remaining -= take as u64;
        Ok(take)
    }
}

#[test]
fn large_file_hashes_in_bounded_memory() {
    const SIZE: u64 = 8 * 1024 * 1024;
    let mut reader = CountingReader {
        remaining: SIZE,
        largest_request: 0,
    };
    let never = AtomicBool::new(false);
    let digest = digest_reader(&mut reader, &never).unwrap();
    assert_eq!(digest.byte_length, SIZE);
    assert_eq!(
        reader.largest_request, HASH_BUFFER_BYTES,
        "one fixed 64 KiB buffer regardless of file size"
    );
}

#[test]
fn copied_bytes_are_the_hashed_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let layout = case_layout(dir.path());
    let source = dir.path().join("source.txt");
    std::fs::write(&source, b"ghosttrace\n").unwrap();

    let (outcome, stored) = copy(&source, &layout);
    assert_eq!(outcome.status, CopyStatus::Published);
    assert_eq!(outcome.byte_length, 11);
    assert_eq!(
        sha256_hex(&outcome.sha256.unwrap()),
        "6f1c48e66bc86b08cd1476a8f66fc5047196d290699538ce1ebdff651a7ef378"
    );
    assert_eq!(
        std::fs::read(&stored).unwrap(),
        std::fs::read(&source).unwrap(),
        "stored bytes equal source bytes"
    );
    assert_eq!(digest_file(&stored).unwrap(), digest_file(&source).unwrap());
}

#[test]
fn same_size_and_mime_still_hash_differently() {
    let dir = tempfile::tempdir().unwrap();
    let layout = case_layout(dir.path());
    let first = dir.path().join("a.txt");
    let second = dir.path().join("b.txt");
    std::fs::write(&first, b"lorem ipsum dolor\n").unwrap();
    std::fs::write(&second, b"lorem ipsum DOLOR\n").unwrap();

    let (first_outcome, first_stored) = copy(&first, &layout);
    let (second_outcome, second_stored) = copy(&second, &layout);
    assert_ne!(first_outcome.sha256, second_outcome.sha256);
    assert_ne!(
        first_outcome.store_subpath, second_outcome.store_subpath,
        "different bytes never share one object path"
    );
    assert!(first_stored.exists() && second_stored.exists());
}

#[test]
fn identical_content_is_stored_once() {
    let dir = tempfile::tempdir().unwrap();
    let layout = case_layout(dir.path());
    let first = dir.path().join("one.txt");
    let second = dir.path().join("two.txt");
    std::fs::write(&first, b"same bytes\n").unwrap();
    std::fs::write(&second, b"same bytes\n").unwrap();

    let (first_outcome, _) = copy(&first, &layout);
    let (second_outcome, _) = copy(&second, &layout);
    assert_eq!(first_outcome.status, CopyStatus::Published);
    assert_eq!(second_outcome.status, CopyStatus::Deduplicated);
    assert_eq!(first_outcome.store_subpath, second_outcome.store_subpath);
    // No staging leftovers from the deduplicated copy.
    assert_eq!(std::fs::read_dir(layout.staging_root()).unwrap().count(), 0);
}

#[test]
fn captured_hash_verifies_the_stored_copy_not_the_source() {
    let dir = tempfile::tempdir().unwrap();
    let layout = case_layout(dir.path());
    let source = dir.path().join("mutable.txt");
    std::fs::write(&source, b"original content\n").unwrap();

    let (outcome, stored) = copy(&source, &layout);
    let captured = StreamDigest {
        byte_length: outcome.byte_length,
        sha256: outcome.sha256.unwrap(),
    };

    // Mutate the source after capture, keeping the same length.
    std::fs::write(&source, b"mutated! content\n").unwrap();
    assert_ne!(
        digest_file(&source).unwrap(),
        captured,
        "the source no longer matches"
    );
    assert_eq!(
        digest_file(&stored).unwrap(),
        captured,
        "verification is against the stored copy"
    );
    ghosttrace_core::integrity::hash::verify_file(&stored, &captured).unwrap();
}

#[test]
fn cancelled_copy_publishes_nothing_and_leaves_no_partial_digest() {
    let dir = tempfile::tempdir().unwrap();
    let layout = case_layout(dir.path());
    let source = dir.path().join("big.bin");
    std::fs::write(&source, vec![0u8; 4 * 1024 * 1024]).unwrap();

    let progress = CopyProgress::new();
    progress.cancel();
    let outcome = copy_one(
        &task(&source, b"big.bin"),
        &layout,
        &CopyLimits::default(),
        &progress,
    )
    .unwrap();
    assert_eq!(outcome.status, CopyStatus::Cancelled);
    assert!(outcome.sha256.is_none(), "no digest for a cancelled copy");
    assert_eq!(std::fs::read_dir(layout.staging_root()).unwrap().count(), 0);

    // The hashing primitive itself refuses to emit a digest when cancelled.
    let cancelled = AtomicBool::new(true);
    let mut bytes = &b"partial"[..];
    let error = digest_reader(&mut bytes, &cancelled).unwrap_err();
    assert_eq!(error.code(), "cancelled");
    assert!(cancelled.load(Ordering::Relaxed));
}

#[test]
fn oversized_files_are_recorded_and_never_read() {
    let dir = tempfile::tempdir().unwrap();
    let layout = case_layout(dir.path());
    let source = dir.path().join("huge.bin");
    std::fs::write(&source, vec![1u8; 4096]).unwrap();

    let limits = CopyLimits {
        max_file_bytes: 1024,
        ..CopyLimits::default()
    };
    let progress = CopyProgress::new();
    let outcome = copy_one(&task(&source, b"huge.bin"), &layout, &limits, &progress).unwrap();
    assert_eq!(outcome.status, CopyStatus::TooLarge);
    assert!(outcome.sha256.is_none());
    assert_eq!(progress.bytes_copied.load(Ordering::Relaxed), 0);
    assert_eq!(std::fs::read_dir(layout.objects_root()).unwrap().count(), 0);
}

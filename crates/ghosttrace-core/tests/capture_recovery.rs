//! P2.2 recovery contract: staged writes are atomic, interrupted objects are
//! reported rather than silently deleted, and an end-to-end acquisition is
//! verifiable from the manifest alone.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ghosttrace_core::capture::copy::{
    AcquisitionOptions, CopyLimits, CopyProgress, CopyStatus, CopyTask, available_bytes, copy_one,
    ensure_reserve, inspect_recovery, run_acquisition,
};
use ghosttrace_core::capture::{CaptureRoot, CaptureSpec};
use ghosttrace_core::domain::case::AcquisitionMethod;
use ghosttrace_core::domain::path::NativePath;
use ghosttrace_core::integrity::hash::{digest_file, sha256_hex};
use ghosttrace_core::jobs::{JobCheckpoint, JobKind, JobState};
use ghosttrace_core::service::{CaseSession, CreateCaseSpec};
use ghosttrace_core::storage::CaseLayout;

fn native(path: &Path) -> NativePath {
    NativePath::unix(path.as_os_str().as_bytes().to_vec())
}

fn new_session(dir: &Path) -> CaseSession {
    CaseSession::create(dir, "case-1", CreateCaseSpec::default()).unwrap()
}

fn small_tree(evidence: &Path) {
    std::fs::create_dir_all(evidence.join("nested/deep")).unwrap();
    std::fs::write(evidence.join("report.txt"), b"ghosttrace\n").unwrap();
    std::fs::write(evidence.join("nested/notes.md"), b"notes\n").unwrap();
    std::fs::write(evidence.join("nested/deep/payload.bin"), [0u8, 1, 2, 3]).unwrap();
    std::os::unix::fs::symlink("report.txt", evidence.join("link.txt")).unwrap();
    nix::unistd::mkfifo(
        &evidence.join("pipe"),
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )
    .unwrap();
}

fn spec(evidence: &Path, case_root: &Path) -> CaptureSpec {
    CaptureSpec {
        roots: vec![CaptureRoot {
            native: native(evidence),
            label: "evidence".into(),
        }],
        follow_symlinks: false,
        max_depth: 8,
        max_entries: 10_000,
        max_file_bytes: 1 << 20,
        case_directory: case_root.to_path_buf(),
    }
}

fn acquisition(
    session: &CaseSession,
    spec: &CaptureSpec,
) -> ghosttrace_core::capture::copy::AcquisitionReport {
    let options = AcquisitionOptions::new(
        AcquisitionMethod::ProtectedCopy,
        "controlled test folder",
        spec,
    );
    run_acquisition(session, spec, &options, &CopyProgress::new()).unwrap()
}

#[test]
fn small_acquisition_is_complete_verified_and_clean() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    small_tree(&evidence);
    let before: Vec<_> = ["report.txt", "nested/notes.md", "nested/deep/payload.bin"]
        .iter()
        .map(|name| digest_file(&evidence.join(name)).unwrap())
        .collect();

    let session = new_session(&dir.path().join("cases"));
    let spec = spec(&evidence, session.layout().root());
    let report = acquisition(&session, &spec);

    assert_eq!(
        report.state,
        ghosttrace_core::domain::case::AcquisitionState::Completed
    );
    assert_eq!(report.published_objects(), 3, "three regular files");
    assert_eq!(report.coverage.captured, 4, "files plus the captured link");
    assert_eq!(report.coverage.unsupported, 1, "the FIFO is disclosed");
    assert!(
        report
            .copies
            .iter()
            .all(|copy| copy.status == CopyStatus::Published)
    );

    // Source bytes are unchanged by capture (the P2 gate's core promise).
    let after: Vec<_> = ["report.txt", "nested/notes.md", "nested/deep/payload.bin"]
        .iter()
        .map(|name| digest_file(&evidence.join(name)).unwrap())
        .collect();
    assert_eq!(before, after);

    // Manifest verifies the stored copies, not the source.
    let manifest = report.manifest.as_ref().unwrap();
    assert_eq!(manifest.objects.len(), 3);
    assert!(manifest.verify_objects(session.layout().root()).is_ok());
    let manifest_path = report.manifest_path.as_ref().unwrap();
    let text = std::fs::read_to_string(manifest_path).unwrap();
    assert!(text.ends_with("}\n"), "stable manifest formatting");
    let parsed: ghosttrace_core::integrity::manifest::ManifestV1 =
        serde_json::from_str(&text).unwrap();
    assert_eq!(&parsed, manifest);

    // Database rows agree with the report.
    let reader = session.reader().unwrap();
    let objects: i64 = reader
        .connection()
        .query_row("SELECT count(*) FROM evidence_objects", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(objects, 3);
    let stored: Vec<(Vec<u8>, i64)> = {
        let mut statement = reader
            .connection()
            .prepare(
                "SELECT sha256, byte_length FROM evidence_objects ORDER BY native_path_encoded",
            )
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    let mut stored_hex: Vec<String> = stored
        .iter()
        .map(|(hash, _)| sha256_hex(hash.as_slice().try_into().unwrap()))
        .collect();
    let mut source_hex: Vec<String> = before.iter().map(|digest| digest.hex()).collect();
    stored_hex.sort();
    source_hex.sort();
    assert_eq!(stored_hex, source_hex);
    let coverage: i64 = reader
        .connection()
        .query_row("SELECT count(*) FROM coverage", [], |row| row.get(0))
        .unwrap();
    assert_eq!(coverage, 5, "every observed path has a ledger row");
    let events: i64 = reader
        .connection()
        .query_row(
            "SELECT count(*) FROM events WHERE kind = 'file.observed'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(events, 5, "capture metadata events exist for the timeline");
    let acquisitions: String = reader
        .connection()
        .query_row("SELECT state FROM acquisitions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(acquisitions, "completed");
    drop(reader);

    // Nothing left to recover; reopen sees no interruption.
    let reader = session.reader().unwrap();
    assert!(
        inspect_recovery(session.layout(), &reader)
            .unwrap()
            .is_empty()
    );
    drop(reader);
    drop(session);
    let (reopened, open_report) =
        CaseSession::open(dir.path().join("cases/case-1.ghosttrace-case")).unwrap();
    assert!(open_report.recoverable_jobs.is_empty());
    assert_eq!(reopened.case_id(), "case-1");
}

#[test]
fn repeated_acquisition_deduplicates_content_but_keeps_two_acquisitions() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    small_tree(&evidence);
    let session = new_session(&dir.path().join("cases"));
    let spec = spec(&evidence, session.layout().root());

    let first = acquisition(&session, &spec);
    let second = acquisition(&session, &spec);
    assert_ne!(first.acquisition_id, second.acquisition_id);
    assert!(
        second
            .copies
            .iter()
            .filter(|copy| copy.status == CopyStatus::Deduplicated)
            .count()
            == 3
    );

    let reader = session.reader().unwrap();
    let acquisitions: i64 = reader
        .connection()
        .query_row("SELECT count(*) FROM acquisitions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(acquisitions, 2);
    let objects: i64 = reader
        .connection()
        .query_row("SELECT count(*) FROM evidence_objects", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(objects, 6, "each acquisition owns its own object rows");
    let stored_files = walkdir_count(session.layout().objects_root());
    assert_eq!(stored_files, 3, "one immutable file per distinct content");
}

fn walkdir_count(root: PathBuf) -> usize {
    let mut count = 0;
    for bucket in std::fs::read_dir(root).unwrap().flatten() {
        if bucket.path().is_dir() {
            count += std::fs::read_dir(bucket.path()).unwrap().count();
        }
    }
    count
}

#[test]
fn crash_after_rename_before_commit_is_reported_not_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    let source = evidence.join("orphan.txt");
    std::fs::write(&source, b"published but uncommitted\n").unwrap();
    let session = new_session(&dir.path().join("cases"));
    let layout = CaseLayout::new(session.layout().root());
    let stamp = ghosttrace_core::capture::copy::stamp_of_path(&source).unwrap();
    let task = CopyTask {
        root_index: 0,
        root_label: "evidence".into(),
        native_relative: NativePath::unix(b"orphan.txt".to_vec()),
        source: source.clone(),
        expected_identity: stamp.identity,
        expected_size: stamp.size,
        hardlink_alias: false,
    };

    // Step 6 succeeds, step 7 (the DB commit) is simulated by not happening.
    let outcome = copy_one(&task, &layout, &CopyLimits::default(), &CopyProgress::new()).unwrap();
    assert_eq!(outcome.status, CopyStatus::Published);
    let stored = layout.root().join(outcome.store_subpath.clone().unwrap());
    assert!(stored.exists());

    let reader = session.reader().unwrap();
    let report = inspect_recovery(&layout, &reader).unwrap();
    assert_eq!(report.orphan_objects.len(), 1);
    assert_eq!(
        report.orphan_objects[0].store_subpath,
        outcome.store_subpath.unwrap()
    );
    assert!(stored.exists(), "recovery never deletes published bytes");
    assert!(report.abandoned_staging.is_empty());
}

#[test]
fn abandoned_staging_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let session = new_session(&dir.path().join("cases"));
    let layout = CaseLayout::new(session.layout().root());
    let leftover = layout.staging_root().join("copy.part");
    std::fs::write(&leftover, b"half copied").unwrap();

    let reader = session.reader().unwrap();
    let report = inspect_recovery(&layout, &reader).unwrap();
    assert_eq!(report.abandoned_staging, vec!["copy.part".to_string()]);
    assert!(report.orphan_objects.is_empty());
    assert!(leftover.exists());
}

#[test]
fn free_space_reserve_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let session = new_session(&dir.path().join("cases"));
    let staging = session.layout().staging_root();
    let Some(available) = available_bytes(&staging) else {
        eprintln!("skipping: filesystem reports no free-space figures");
        return;
    };
    assert!(
        ensure_reserve(&staging, available.saturating_add(1), 0).is_err(),
        "a copy needing more than the free space must be refused"
    );
    assert!(
        ensure_reserve(&staging, available, 1).is_err(),
        "the reserve itself is never consumed"
    );
    assert!(ensure_reserve(&staging, 1, 0).is_ok());
}

#[test]
fn unwritable_staging_fails_without_publishing() {
    if nix::unistd::geteuid().is_root() {
        eprintln!("skipping: root bypasses directory permissions");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    let source = evidence.join("blocked.txt");
    std::fs::write(&source, b"data").unwrap();
    let session = new_session(&dir.path().join("cases"));
    let layout = CaseLayout::new(session.layout().root());
    std::fs::set_permissions(
        layout.staging_root(),
        std::fs::Permissions::from_mode(0o500),
    )
    .unwrap();

    let stamp = ghosttrace_core::capture::copy::stamp_of_path(&source).unwrap();
    let task = CopyTask {
        root_index: 0,
        root_label: "evidence".into(),
        native_relative: NativePath::unix(b"blocked.txt".to_vec()),
        source: source.clone(),
        expected_identity: stamp.identity,
        expected_size: stamp.size,
        hardlink_alias: false,
    };
    let error = copy_one(&task, &layout, &CopyLimits::default(), &CopyProgress::new()).unwrap_err();
    assert_eq!(error.code(), "storage");
    assert_eq!(walkdir_count(layout.objects_root()), 0);
    std::fs::set_permissions(
        layout.staging_root(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert_eq!(std::fs::read_dir(layout.staging_root()).unwrap().count(), 0);
}

#[test]
fn running_checkpoint_from_a_crashed_acquisition_is_recoverable() {
    let dir = tempfile::tempdir().unwrap();
    let session = new_session(&dir.path().join("cases"));
    let mut checkpoint =
        JobCheckpoint::queued("job-crashed", JobKind::Acquisition, "roots:[]", "digest");
    checkpoint.state = JobState::Running;
    session.writer().queue_job_checkpoint(&checkpoint).unwrap();
    let case_root = session.layout().root().to_path_buf();
    drop(session);

    let (_session, report) = CaseSession::open(case_root).unwrap();
    assert_eq!(report.recoverable_jobs.len(), 1);
    assert_eq!(report.recoverable_jobs[0].job_id, "job-crashed");
    assert_eq!(report.recoverable_jobs[0].found_state, JobState::Running);
}

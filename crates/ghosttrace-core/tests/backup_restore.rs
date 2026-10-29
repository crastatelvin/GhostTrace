//! P9.2 backup/restore contract: a consistent snapshot plus referenced objects
//! restores into a new private case, and every failure leaves no published
//! directory that looks complete.

mod support;

use ghosttrace_core::capture::copy::ensure_reserve;
use ghosttrace_core::error::CoreError;
use ghosttrace_core::ingest::LogFormat;
use ghosttrace_core::integrity::signature::verify_manifest;
use ghosttrace_core::service::CaseSession;
use ghosttrace_core::storage::backup::{backup_case, restore_case, verify_backup};
use support::Harness;

const RECORDS: &[u8] = b"\
{\"ts\":\"2026-10-27T10:00:00Z\",\"msg\":\"one\"}
{\"ts\":\"2026-10-27T10:01:00Z\",\"msg\":\"two\"}
";

fn imported(harness: &mut Harness) -> String {
    let acquisition = harness.capture(&[("logs/events.jsonl", RECORDS)]);
    harness
        .import(&acquisition, "logs/events.jsonl", |request| {
            request.format = Some(LogFormat::Jsonl);
            request.jsonl.message_field = Some("msg".into());
        })
        .expect("import");
    acquisition
}

fn has_published_backup(directory: &std::path::Path) -> bool {
    std::fs::read_dir(directory)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .any(|entry| entry.path().join("backup.json").is_file())
        })
        .unwrap_or(false)
}

#[test]
fn a_backup_restores_into_a_new_private_case_that_reopens() {
    let mut harness = Harness::new();
    let acquisition = imported(&mut harness);
    let expected_events = harness.count("SELECT count(*) FROM events", &[]);
    let object = harness
        .scalar(
            "SELECT object_location FROM evidence_objects WHERE object_location IS NOT NULL LIMIT 1",
            &[],
        )
        .expect("object");

    let output = tempfile::tempdir().expect("output");
    let backup = backup_case(&harness.case_root(), output.path(), "test").expect("backup");
    assert!(backup.inventory_path.is_file());
    assert!(backup.directory.join("case.sqlite").is_file());
    assert!(backup.directory.join("case.toml").is_file());
    assert!(backup.directory.join(&object).is_file());
    let verification = verify_backup(&backup.directory).expect("verify");
    assert_eq!(verification.files_verified, backup.files.len());

    // The snapshot contains committed rows, not just the main database file.
    let snapshot =
        rusqlite::Connection::open(backup.directory.join("case.sqlite")).expect("snapshot");
    let snapshot_events: i64 = snapshot
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .expect("count");
    assert_eq!(snapshot_events, expected_events);
    assert!(snapshot_events > 0);
    drop(snapshot);

    let restore_dir = tempfile::tempdir().expect("restore");
    let destination = restore_dir.path().join("restored.ghosttrace-case");
    let restored = restore_case(&backup.directory, &destination).expect("restore");
    assert_eq!(restored.case_id, backup.case_id);
    assert_eq!(restored.objects, 1);
    assert!(destination.join(&object).is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&destination)
            .expect("destination")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "the restored case is private");
    }

    // The relocated case opens through the normal path and keeps its rows and
    // its relative object references.
    let (session, _) = CaseSession::open(&destination).expect("open restored");
    let events: i64 = session
        .reader()
        .expect("reader")
        .connection()
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .expect("count");
    assert_eq!(events, expected_events);
    let manifest = destination
        .join("manifests")
        .join(format!("manifest-{acquisition}.json"));
    let verification = verify_manifest(&destination, &manifest, None, None).expect("manifest");
    assert!(verification.is_accepted());
}

#[test]
fn a_missing_object_aborts_the_backup_and_publishes_nothing() {
    let mut harness = Harness::new();
    imported(&mut harness);
    let object = harness
        .scalar(
            "SELECT object_location FROM evidence_objects WHERE object_location IS NOT NULL LIMIT 1",
            &[],
        )
        .expect("object");
    std::fs::remove_file(harness.case_root().join(&object)).expect("remove object");

    let output = tempfile::tempdir().expect("output");
    let error = backup_case(&harness.case_root(), output.path(), "test").expect_err("backup");
    assert!(matches!(error, CoreError::CorruptEvidence), "{error:?}");
    assert!(!has_published_backup(output.path()));
}

#[test]
fn a_corrupt_or_escaped_inventory_is_rejected() {
    let mut harness = Harness::new();
    imported(&mut harness);
    let output = tempfile::tempdir().expect("output");
    let backup = backup_case(&harness.case_root(), output.path(), "test").expect("backup");
    let inventory = backup.inventory_path.clone();
    let original = std::fs::read_to_string(&inventory).expect("inventory");

    std::fs::write(&inventory, "not json").expect("corrupt");
    assert!(verify_backup(&backup.directory).is_err());

    let mut escaped: serde_json::Value = serde_json::from_str(&original).expect("json");
    let index = escaped["files"]
        .as_array()
        .expect("files")
        .iter()
        .position(|file| file["path"] == "README.txt")
        .expect("readme entry");
    escaped["files"][index]["path"] = "../escape".into();
    std::fs::write(&inventory, escaped.to_string()).expect("escape");
    let error = verify_backup(&backup.directory).expect_err("traversal");
    assert!(error.to_string().contains("escapes"), "{error}");

    let mut duplicate: serde_json::Value = serde_json::from_str(&original).expect("json");
    let first = duplicate["files"][0].clone();
    duplicate["files"]
        .as_array_mut()
        .expect("files")
        .push(first);
    std::fs::write(&inventory, duplicate.to_string()).expect("duplicate");
    let error = verify_backup(&backup.directory).expect_err("collision");
    assert!(error.to_string().contains("twice"), "{error}");
}

#[test]
fn restore_refuses_an_existing_destination_and_a_missing_object() {
    let mut harness = Harness::new();
    imported(&mut harness);
    let output = tempfile::tempdir().expect("output");
    let backup = backup_case(&harness.case_root(), output.path(), "test").expect("backup");

    let restore_dir = tempfile::tempdir().expect("restore");
    let destination = restore_dir.path().join("existing.ghosttrace-case");
    std::fs::create_dir(&destination).expect("existing");
    let error = restore_case(&backup.directory, &destination).expect_err("existing");
    assert!(error.to_string().contains("already exists"), "{error}");

    let object = backup
        .files
        .iter()
        .find(|file| file.role == "object")
        .expect("object file");
    std::fs::remove_file(backup.directory.join(&object.path)).expect("remove");
    let destination = restore_dir.path().join("missing.ghosttrace-case");
    let error = restore_case(&backup.directory, &destination).expect_err("missing");
    assert!(matches!(error, CoreError::CorruptEvidence), "{error:?}");
    assert!(!destination.exists(), "a failed restore publishes nothing");
}

#[test]
fn an_interrupted_staging_directory_is_never_trusted() {
    let dir = tempfile::tempdir().expect("dir");
    let partial = dir.path().join(".backup-interrupted.part");
    std::fs::create_dir(&partial).expect("partial");
    std::fs::write(
        partial.join("backup.json"),
        b"{\"format\":\"ghosttrace-backup/1\"}",
    )
    .expect("junk");
    assert!(verify_backup(&partial).is_err());
    let destination = dir.path().join("never.ghosttrace-case");
    assert!(restore_case(&partial, &destination).is_err());
    assert!(!destination.exists());
}

#[test]
fn insufficient_space_is_refused_before_any_copy() {
    let dir = tempfile::tempdir().expect("dir");
    let error = ensure_reserve(dir.path(), u64::MAX, 0).expect_err("space");
    assert!(matches!(error, CoreError::ResourceLimit), "{error:?}");
}

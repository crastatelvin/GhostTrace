//! P1.2 backup-before-migrate discipline: upgrade backups retain committed
//! WAL data, a failed backup prevents migration, and a failed migration
//! leaves the original schema and data recoverable.

use ghosttrace_core::service::{CaseSession, CreateCaseSpec};
use ghosttrace_core::storage::backup;
use ghosttrace_core::storage::migrate::{self, MIGRATIONS, Migration};
use rusqlite::Connection;
use std::path::Path;

fn custom(version: u32, name: &'static str, sql: &'static str) -> Migration {
    Migration { version, name, sql }
}

fn seeded_case(dir: &Path) -> CaseSession {
    let session = CaseSession::create(dir, "upgrade", CreateCaseSpec::default()).expect("case");
    session
        .writer()
        .execute(ghosttrace_core::storage::writer::WriteBatch::new().push(
            ghosttrace_core::storage::writer::WriteOp::fact(
                "cases",
                vec!["id", "label", "created_seconds"],
                vec![
                    ghosttrace_core::storage::writer::Param::Text("case-1".into()),
                    ghosttrace_core::storage::writer::Param::Text("before upgrade".into()),
                    ghosttrace_core::storage::writer::Param::Int(1_700_000_000),
                ],
            ),
        ))
        .unwrap();
    session
}

#[test]
fn upgrade_backup_retains_committed_wal_data() {
    let dir = tempfile::tempdir().unwrap();
    let session = seeded_case(dir.path());
    let database = session.layout().database_path().clone();
    let backup_dir = session.layout().diagnostics_root().clone();
    drop(session);

    let connection = Connection::open(&database).unwrap();
    // Version 6 is the next free version: the embedded set now ends at
    // 0005_findings (P5.2).
    let add_note = custom(
        6,
        "0006_test_note",
        "CREATE TABLE note (id INTEGER PRIMARY KEY, body TEXT);",
    );
    let outcome = migrate::apply_with(
        &connection,
        &[
            MIGRATIONS[0],
            MIGRATIONS[1],
            MIGRATIONS[2],
            MIGRATIONS[3],
            MIGRATIONS[4],
            add_note,
        ],
        Some(&backup_dir),
    )
    .unwrap();

    let artifact = outcome
        .backup
        .expect("an existing case must be backed up first");
    assert!(artifact.integrity_ok, "the backup must verify");
    assert_eq!(
        artifact.schema_version, 5,
        "backup captured the pre-upgrade schema"
    );
    assert_eq!(artifact.applied_migrations.len(), 5);
    assert_eq!(artifact.applied_migrations[0].1, "0001_case");
    assert_eq!(artifact.applied_migrations[1].1, "0002_file_times");

    // The upgraded database now has the new table...
    let table: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='note'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(table, 1);

    // ...while the backup holds the committed WAL data as it was before.
    let verification = backup::validate_backup(&artifact.path).unwrap();
    assert!(verification.integrity_ok);
    assert_eq!(verification.applied_migrations.len(), 5);
    assert_eq!(verification.applied_migrations[0].1, "0001_case");
    assert_eq!(verification.applied_migrations[1].1, "0002_file_times");
    let backup_connection =
        Connection::open_with_flags(&artifact.path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let label: String = backup_connection
        .query_row("SELECT label FROM cases WHERE id = 'case-1'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(label, "before upgrade");
}

#[test]
fn backup_failure_prevents_migration() {
    let dir = tempfile::tempdir().unwrap();
    let session = seeded_case(dir.path());
    let database = session.layout().database_path().clone();
    // A regular file is not a backup directory: the backup cannot be written.
    let blocker = dir.path().join("not-a-directory");
    std::fs::write(&blocker, b"blocked").unwrap();
    drop(session);

    let connection = Connection::open(&database).unwrap();
    // Version 6 is the next free version: the embedded set now ends at
    // 0005_findings (P5.2).
    let add_note = custom(
        6,
        "0006_test_note",
        "CREATE TABLE note (id INTEGER PRIMARY KEY, body TEXT);",
    );
    let outcome = migrate::apply_with(
        &connection,
        &[
            MIGRATIONS[0],
            MIGRATIONS[1],
            MIGRATIONS[2],
            MIGRATIONS[3],
            MIGRATIONS[4],
            add_note,
        ],
        Some(&blocker),
    );
    assert!(outcome.is_err(), "a failed backup must abort the migration");

    // The original schema and data are untouched.
    let table: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='note'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(table, 0, "no migration may run without a validated backup");
    let label: String = connection
        .query_row("SELECT label FROM cases WHERE id = 'case-1'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(label, "before upgrade");
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    // The seeded case already carries the full embedded schema (0005_findings).
    assert_eq!(version, 5);
}

#[test]
fn failed_migration_leaves_the_original_recoverable() {
    let dir = tempfile::tempdir().unwrap();
    let session = seeded_case(dir.path());
    let database = session.layout().database_path().clone();
    let backup_dir = session.layout().diagnostics_root().clone();
    drop(session);

    let connection = Connection::open(&database).unwrap();
    let broken = custom(
        6,
        "0006_broken",
        "CREATE TABLE note (id INTEGER PRIMARY KEY",
    ); // unterminated
    let outcome = migrate::apply_with(
        &connection,
        &[
            MIGRATIONS[0],
            MIGRATIONS[1],
            MIGRATIONS[2],
            MIGRATIONS[3],
            MIGRATIONS[4],
            broken,
        ],
        Some(&backup_dir),
    );
    assert!(outcome.is_err());

    // The seeded case row survives the failed migration.
    let label: String = connection
        .query_row("SELECT label FROM cases WHERE id = 'case-1'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(label, "before upgrade");
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 5, "the failed migration did not bump the schema");
    // The pre-migration backup validates and can be restored.
    let backups: Vec<_> = std::fs::read_dir(&backup_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sqlite"))
        .collect();
    assert_eq!(backups.len(), 1, "a validated backup exists for recovery");
    let verification = backup::validate_backup(&backups[0]).unwrap();
    assert!(verification.integrity_ok);
    assert_eq!(verification.applied_migrations.len(), 5);
    assert_eq!(verification.applied_migrations[0].1, "0001_case");
    assert_eq!(verification.applied_migrations[1].1, "0002_file_times");
}

//! P1.2 migration discipline (plan Section 17): sequential checksummed
//! migrations, newer-schema rejection, and honest open diagnostics.

use ghosttrace_core::error::CoreError;
use ghosttrace_core::service::CaseSession;
use ghosttrace_core::storage::{CaseLayout, MIGRATIONS, SUPPORTED_SCHEMA_VERSION, migrate};
use rusqlite::Connection;
use std::path::Path;

fn fresh_database(dir: &Path) -> Connection {
    let layout = CaseLayout::new(dir);
    layout.create_private_tree().unwrap();
    Connection::open(layout.database_path()).unwrap()
}

fn stored_version(connection: &Connection) -> u32 {
    connection
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn fresh_case_applies_schema_and_records_checksum() {
    let dir = tempfile::tempdir().unwrap();
    let connection = fresh_database(dir.path());
    let created = migrate::create_schema(&connection).unwrap();
    assert_eq!(created.applied.len(), 1);
    assert_eq!(created.applied[0].name, "0001_case");
    assert_eq!(created.applied[0].checksum, MIGRATIONS[0].checksum());
    assert!(created.backup.is_none(), "a new empty case needs no backup");
    let reopened = migrate::migrate(&connection, None).unwrap();
    assert!(reopened.applied.is_empty(), "nothing pending on reopen");
    assert_eq!(stored_version(&connection), SUPPORTED_SCHEMA_VERSION);
}

#[test]
fn embedded_migrations_are_ordered_and_checksum_stable() {
    let versions: Vec<u32> = MIGRATIONS.iter().map(|m| m.version).collect();
    assert_eq!(versions, vec![1]);
    assert_eq!(MIGRATIONS[0].checksum(), MIGRATIONS[0].checksum());
    assert!(MIGRATIONS[0].sql.contains("CREATE TABLE"));
}

#[test]
fn newer_schema_is_rejected_not_downgraded() {
    let dir = tempfile::tempdir().unwrap();
    let connection = fresh_database(dir.path());
    migrate::create_schema(&connection).unwrap();
    connection
        .execute_batch("PRAGMA user_version = 99;")
        .unwrap();
    let outcome = migrate::migrate(&connection, Some(dir.path()));
    assert!(matches!(outcome, Err(CoreError::SchemaIncompatible(_))));
    assert_eq!(
        stored_version(&connection),
        99,
        "the failed open changed nothing"
    );
}

#[test]
fn tampered_migration_history_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let connection = fresh_database(dir.path());
    migrate::create_schema(&connection).unwrap();
    connection
        .execute_batch("UPDATE schema_migrations SET checksum = 'deadbeef' WHERE version = 1;")
        .unwrap();
    let outcome = migrate::migrate(&connection, Some(dir.path()));
    assert!(matches!(outcome, Err(CoreError::SchemaIncompatible(_))));
}

#[test]
fn create_schema_refuses_an_initialized_case() {
    let dir = tempfile::tempdir().unwrap();
    let connection = fresh_database(dir.path());
    migrate::create_schema(&connection).unwrap();
    let again = migrate::create_schema(&connection);
    assert!(matches!(again, Err(CoreError::InvalidInput(_))));
}

#[test]
fn session_open_reports_diagnostics_and_migration_state() {
    let dir = tempfile::tempdir().unwrap();
    let session = CaseSession::create(
        dir.path(),
        "investigation",
        ghosttrace_core::service::CreateCaseSpec::default(),
    )
    .unwrap();
    {
        let reader = session.reader().unwrap();
        let pragma: String = reader
            .connection()
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(pragma, "wal", "cases run in WAL mode");
    }
    drop(session);

    let (_reopened, report) =
        CaseSession::open(dir.path().join("investigation.ghosttrace-case")).unwrap();
    assert!(report.diagnostics.wal_enabled);
    assert!(!report.diagnostics.linked_sqlite_version.is_empty());
    assert!(report.diagnostics.foreign_keys, "foreign keys are enforced");
    assert!(report.migrations_applied.is_empty(), "already current");
    assert!(report.recoverable_jobs.is_empty(), "no interrupted jobs");
    assert!(report.backup.is_none());
}

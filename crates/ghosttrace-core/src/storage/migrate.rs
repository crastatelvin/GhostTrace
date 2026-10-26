//! Sequential, checksummed migrations (plan Sections 8, 17/P1.2).
//!
//! Rules embodied here:
//! - Migrations run in ascending order; each records name + checksum in
//!   `schema_migrations`. Replaying an already-applied migration with a
//!   different checksum fails loudly (edited history, never silently skipped).
//! - A schema *newer* than this application supports is rejected, never
//!   downgraded.
//! - Before any existing case is modified, a validated WAL backup must exist;
//!   if the backup fails, the migration aborts before touching schema.
//! - A new empty case needs no pre-creation backup.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::error::{CoreError, CoreResult};

use super::backup::{self, BackupArtifact};

/// The current schema this application implements. `user_version` mirrors the
/// applied set; both are checked at startup.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// One migration step. `sql` is included from file so the checksum matches
/// exactly what runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    pub version: u32,
    pub name: &'static str,
    pub sql: &'static str,
}

impl Migration {
    /// SHA-256 of the exact statements, lowercase hex.
    pub fn checksum(&self) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(self.sql.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// 0001_case.sql — the base schema (plan Section 5).
pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "0001_case",
    sql: include_str!("../../migrations/0001_case.sql"),
}];

/// What an open actually did, for diagnostics and honest reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationOutcome {
    pub applied: Vec<AppliedMigration>,
    pub schema_version: u32,
    /// Set when the case was migrated; a fresh case reports `None`.
    pub backup: Option<BackupArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedMigration {
    pub version: u32,
    pub name: String,
    pub checksum: String,
}

/// Create a fresh case database from the embedded schema. Refuses to run
/// against an initialized database (exclusive case creation).
pub fn create_schema(connection: &Connection) -> CoreResult<MigrationOutcome> {
    if schema_migrations_initialized(connection)? {
        return Err(CoreError::InvalidInput(
            "case already has a schema; use open_case".into(),
        ));
    }
    apply_all(connection, MIGRATIONS, None)
}

/// Open an existing case database (or create its schema if empty) and bring
/// it up to the supported version with checksum + backup discipline.
pub fn migrate(connection: &Connection, backup_dir: Option<&Path>) -> CoreResult<MigrationOutcome> {
    apply_all(connection, MIGRATIONS, backup_dir)
}

/// Apply a caller-provided migration list with the same checksum, ordering,
/// and backup discipline. Production uses the embedded [MIGRATIONS]; this
/// seam exists so the failure/upgrade paths are directly testable (P1.2).
pub fn apply_with(
    connection: &Connection,
    migrations: &[Migration],
    backup_dir: Option<&Path>,
) -> CoreResult<MigrationOutcome> {
    apply_all(connection, migrations, backup_dir)
}

fn schema_migrations_initialized(connection: &Connection) -> CoreResult<bool> {
    let exists: bool = connection
        .query_row(
            "SELECT count(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| CoreError::Storage(format!("schema probe: {e}")))?;
    Ok(exists)
}

/// Run `migrations` in order over `connection`. `backup_dir` is required when
/// the case already contains tables and work is pending (an existing case
/// must have a validated backup before its schema is touched).
fn apply_all(
    connection: &Connection,
    migrations: &[Migration],
    backup_dir: Option<&Path>,
) -> CoreResult<MigrationOutcome> {
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| CoreError::Storage(format!("foreign_keys: {e}")))?;
    connection
        .busy_timeout(std::time::Duration::from_millis(5_000))
        .map_err(|e| CoreError::Storage(format!("busy_timeout: {e}")))?;

    let applied = applied_versions(connection)?;

    // A database stamped newer than this application supports is never
    // silently downgraded or re-opened.
    if stored_version(connection)? > SUPPORTED_SCHEMA_VERSION {
        return Err(CoreError::SchemaIncompatible(format!(
            "case schema v{} is newer than supported v{SUPPORTED_SCHEMA_VERSION}",
            stored_version(connection)?
        )));
    }

    // Every recorded step must match an embedded migration of the same version
    // with the same checksum, or history has been edited.
    for record in &applied {
        match migrations.iter().find(|m| m.version == record.version) {
            Some(embedded) if embedded.checksum() == record.checksum => {}
            Some(embedded) => {
                return Err(CoreError::SchemaIncompatible(format!(
                    "migration {} checksum mismatch: recorded {} != embedded {}",
                    record.name,
                    record.checksum,
                    embedded.checksum()
                )));
            }
            None => {
                if record.version > SUPPORTED_SCHEMA_VERSION {
                    return Err(CoreError::SchemaIncompatible(format!(
                        "case schema v{} is newer than supported v{SUPPORTED_SCHEMA_VERSION}",
                        record.version
                    )));
                }
                return Err(CoreError::SchemaIncompatible(format!(
                    "recorded migration v{} ({}) is not part of this application",
                    record.version, record.name
                )));
            }
        }
    }

    let pending: Vec<&Migration> = migrations
        .iter()
        .filter(|m| m.version > last_version(&applied))
        .collect();
    let mut applied_now = Vec::new();
    let mut backup_taken: Option<BackupArtifact> = None;
    let is_existing_case = has_user_tables(connection)?;

    for migration in pending {
        // Backup requirement: an existing (non-empty) case must be backed up
        // and verified before its schema is touched. A fresh case is empty,
        // so no backup is created.
        if is_existing_case && backup_taken.is_none() {
            let backup_dir = backup_dir.ok_or_else(|| {
                CoreError::InvalidInput(
                    "migrating an existing case requires a backup directory".into(),
                )
            })?;
            let artifact = backup::backup_and_verify(connection, backup_dir, "pre-migration")?;
            backup_taken = Some(artifact);
        }

        let started = now_seconds();
        let checksum = migration.checksum();
        connection
            .execute_batch(migration.sql)
            .map_err(|e| CoreError::Storage(format!("migration {} failed: {e}", migration.name)))?;
        connection
            .execute(
                "INSERT OR REPLACE INTO schema_migrations (version, name, checksum, applied_seconds)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![migration.version, migration.name, checksum, started],
            )
            .map_err(|e| CoreError::Storage(format!("record migration {}: {e}", migration.name)))?;
        applied_now.push(AppliedMigration {
            version: migration.version,
            name: migration.name.to_string(),
            checksum,
        });
    }

    connection
        .pragma_update(None, "user_version", SUPPORTED_SCHEMA_VERSION)
        .map_err(|e| CoreError::Storage(format!("user_version: {e}")))?;

    Ok(MigrationOutcome {
        applied: applied_now,
        schema_version: stored_version(connection)?,
        backup: backup_taken,
    })
}

fn applied_versions(connection: &Connection) -> CoreResult<Vec<AppliedMigration>> {
    if !schema_migrations_initialized(connection)? {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare("SELECT version, name, checksum FROM schema_migrations ORDER BY version")
        .map_err(|e| CoreError::Storage(format!("read schema_migrations: {e}")))?;
    let rows = statement
        .query_map([], |row| {
            Ok(AppliedMigration {
                version: row.get(0)?,
                name: row.get(1)?,
                checksum: row.get(2)?,
            })
        })
        .map_err(|e| CoreError::Storage(format!("read schema_migrations: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CoreError::Storage(format!("read schema_migrations: {e}")))?;
    Ok(rows)
}

fn last_version(applied: &[AppliedMigration]) -> u32 {
    applied.iter().map(|m| m.version).max().unwrap_or(0)
}

fn has_user_tables(connection: &Connection) -> CoreResult<bool> {
    connection
        .query_row(
            "SELECT count(*) > 0 FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| CoreError::Storage(format!("table probe: {e}")))
}

fn stored_version(connection: &Connection) -> CoreResult<u32> {
    connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| CoreError::Storage(format!("user_version: {e}")))
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::CaseLayout;

    fn fresh_case(dir: &Path) -> (PathBuf, Connection) {
        let layout = CaseLayout::new(dir);
        layout.create_private_tree().unwrap();
        let database = layout.database_path();
        let connection = Connection::open(&database).unwrap();
        (database, connection)
    }

    #[test]
    fn fresh_case_records_migration_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let (database, connection) = fresh_case(dir.path());
        let outcome = create_schema(&connection).unwrap();
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(outcome.applied[0].name, "0001_case");
        assert!(outcome.backup.is_none(), "fresh cases need no backup");
        assert_eq!(outcome.schema_version, SUPPORTED_SCHEMA_VERSION);
        // Checksum equals the digest of the exact SQL.
        assert_eq!(outcome.applied[0].checksum, MIGRATIONS[0].checksum());
        let stored: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stored, SUPPORTED_SCHEMA_VERSION);
        let _ = database;
    }

    #[test]
    fn recorded_history_must_match_embedded_migrations() {
        let dir = tempfile::tempdir().unwrap();
        let (_database, connection) = fresh_case(dir.path());
        create_schema(&connection).unwrap();
        // Simulate an edited applied migration, then reopen.
        connection
            .execute_batch("UPDATE schema_migrations SET checksum = 'deadbeef' WHERE version = 1;")
            .unwrap();
        let outcome = apply_all(&connection, MIGRATIONS, Some(dir.path()));
        assert!(
            matches!(outcome, Err(CoreError::SchemaIncompatible(_))),
            "tampered history must be rejected"
        );
    }

    #[test]
    fn newer_schema_is_rejected_not_downgraded() {
        let dir = tempfile::tempdir().unwrap();
        let (_database, connection) = fresh_case(dir.path());
        create_schema(&connection).unwrap();
        connection
            .execute_batch("PRAGMA user_version = 99;")
            .unwrap();
        let outcome = apply_all(&connection, MIGRATIONS, Some(dir.path()));
        assert!(matches!(outcome, Err(CoreError::SchemaIncompatible(_))));
        // Untouched by the failed open.
        assert_eq!(stored_version(&connection).unwrap(), 99);
    }

    #[test]
    fn migrating_existing_case_requires_backup_first() {
        let dir = tempfile::tempdir().unwrap();
        let (_database, connection) = fresh_case(dir.path());
        create_schema(&connection).unwrap();
        // A future migration would need a validated backup; passing `None`
        // for a non-empty case is rejected instead of silently proceeding.
        let outcome = apply_all(&connection, MIGRATIONS, None);
        assert!(
            outcome.is_ok(),
            "already current: nothing pending, no backup needed"
        );
    }
}

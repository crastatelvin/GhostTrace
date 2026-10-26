//! WAL-aware case backup and validation (plan Section 8, P1.2; full portable
//! backup/restore arrives in P9.2).
//!
//! The migration path uses this as an internal prerequisite: a consistent
//! online backup is taken to `diagnostics/` (never outside the case for P1.2),
//! fsynced, hashed, integrity-checked, and schema-verified. If any step fails
//! the caller aborts *before* modifying the schema.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::error::{CoreError, CoreResult};

/// A validated backup file with its integrity evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupArtifact {
    pub path: PathBuf,
    pub sha256: String,
    pub byte_length: u64,
    /// Pages the backup captured (a proxy for completeness, not a guarantee).
    pub page_count: i64,
    pub integrity_ok: bool,
    pub schema_version: u32,
    /// Migration history seen in the backup, `[(version, name, checksum)]`.
    pub applied_migrations: Vec<(u32, String, String)>,
}

/// Take a consistent online backup (sees committed WAL data) to
/// `<destination_dir>/case-pre-<tag>-<unix-seconds>.sqlite`, fsync it, hash
/// it, then open it read-only and validate integrity + schema.
pub fn backup_and_verify(
    source: &Connection,
    destination_dir: &Path,
    tag: &str,
) -> CoreResult<BackupArtifact> {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let safe_tag: String = tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = destination_dir.join(format!("case-pre-{safe_tag}-{unix}.sqlite"));
    let _ = std::fs::remove_file(&path); // a stale artifact must never be trusted

    {
        use rusqlite::backup::Backup;
        let mut destination = Connection::open(&path)
            .map_err(|e| CoreError::Storage(format!("backup target: {e}")))?;
        {
            let backup = Backup::new(source, &mut destination)
                .map_err(|e| CoreError::Storage(format!("backup init: {e}")))?;
            // Copy everything in as few steps as possible while yielding
            // between pages; P9.2 replaces this with chunked progress.
            backup
                .run_to_completion(1024, std::time::Duration::from_millis(1), None)
                .map_err(|e| CoreError::Storage(format!("backup run: {e}")))?;
        }
        destination
            .close()
            .map_err(|(_connection, error)| CoreError::Storage(format!("backup close: {error}")))?;
    }

    fsync_file(&path)?;
    let (sha256, byte_length) = hash_file(&path)?;
    let verification = validate_backup(&path)?;
    if !verification.integrity_ok {
        return Err(CoreError::CorruptEvidence);
    }
    if verification.schema_version == 0 && verification.applied_migrations.is_empty() {
        return Err(CoreError::CorruptEvidence);
    }

    Ok(BackupArtifact {
        path,
        sha256,
        byte_length,
        page_count: verification.page_count,
        integrity_ok: verification.integrity_ok,
        schema_version: verification.schema_version,
        applied_migrations: verification.applied_migrations,
    })
}

/// Open a backup read-only and verify: integrity check, schema version,
/// recorded migrations, and page count.
pub fn validate_backup(path: &Path) -> CoreResult<BackupVerification> {
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY;
    let connection = Connection::open_with_flags(path, flags)
        .map_err(|e| CoreError::Storage(format!("open backup for verification: {e}")))?;
    // An unreadable backup is a corrupt backup (validation verdict), not a
    // storage-layer failure of the case itself.
    let integrity: String =
        match connection.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0)) {
            Ok(value) => value,
            Err(_) => "unreadable".to_string(),
        };
    let page_count: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .unwrap_or(0); // an unreadable image has no trustworthy page count
    let schema_version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap_or(0);
    let applied_migrations = read_applied_migrations(&connection)?;
    Ok(BackupVerification {
        integrity_ok: integrity == "ok",
        page_count,
        schema_version,
        applied_migrations,
    })
}

/// The public result of validation (used by callers to report evidence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupVerification {
    pub integrity_ok: bool,
    pub page_count: i64,
    pub schema_version: u32,
    pub applied_migrations: Vec<(u32, String, String)>,
}

fn read_applied_migrations(connection: &Connection) -> CoreResult<Vec<(u32, String, String)>> {
    let has_table: bool = connection
        .query_row(
            "SELECT count(*) > 0 FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);
    if !has_table {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare("SELECT version, name, checksum FROM schema_migrations ORDER BY version")
        .map_err(|e| CoreError::Storage(format!("backup migrations: {e}")))?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|e| CoreError::Storage(format!("backup migrations: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CoreError::Storage(format!("backup migrations: {e}")))?;
    Ok(rows)
}

/// fsync a file so its bytes are on disk before they are hashed.
fn fsync_file(path: &Path) -> CoreResult<()> {
    let file =
        std::fs::File::open(path).map_err(|e| CoreError::Storage(format!("fsync open: {e}")))?;
    file.sync_all()
        .map_err(|e| CoreError::Storage(format!("fsync: {e}")))?;
    Ok(())
}

fn hash_file(path: &Path) -> CoreResult<(String, u64)> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file =
        std::fs::File::open(path).map_err(|e| CoreError::Storage(format!("hash open: {e}")))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| CoreError::Storage(format!("hash read: {e}")))?;
        if read == 0 {
            break;
        }
        total += read as u64;
        hasher.update(&buffer[..read]);
    }
    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((digest, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::CaseLayout;
    use crate::storage::migrate::create_schema;

    fn case_with_data(dir: &Path) -> (Connection, PathBuf) {
        let layout = CaseLayout::new(dir);
        layout.create_private_tree().unwrap();
        let connection = Connection::open(layout.database_path()).unwrap();
        create_schema(&connection).unwrap();
        connection
            .execute_batch(
                "INSERT INTO cases (id, label, schema_version, created_seconds) VALUES ('c1','l',1,0);",
            )
            .unwrap();
        (connection, layout.diagnostics_root())
    }

    #[test]
    fn backup_retains_committed_wal_data_and_validates() {
        let dir = tempfile::tempdir().unwrap();
        let (connection, destination) = case_with_data(dir.path());
        let artifact = backup_and_verify(&connection, &destination, "upgrade").unwrap();
        assert!(artifact.integrity_ok);
        assert_eq!(artifact.schema_version, 1);
        assert_eq!(artifact.applied_migrations.len(), 1);
        assert_eq!(artifact.applied_migrations[0].1, "0001_case");

        // The backup separately contains the committed row.
        let verification = validate_backup(&artifact.path).unwrap();
        assert!(verification.integrity_ok);
        let rows: i64 =
            Connection::open_with_flags(&artifact.path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap()
                .query_row("SELECT count(*) FROM cases", [], |row| row.get(0))
                .unwrap();
        assert_eq!(rows, 1, "committed WAL data must reach the backup");
    }

    #[test]
    fn corrupt_backup_fails_validation() {
        let dir = tempfile::tempdir().unwrap();
        let (connection, destination) = case_with_data(dir.path());
        let artifact = backup_and_verify(&connection, &destination, "upgrade").unwrap();
        // Corrupt mid-file magic: header corruption is caught by integrity_check.
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&artifact.path)
            .unwrap();
        file.seek(SeekFrom::Start(28)).unwrap();
        file.write_all(&[0xff, 0xff, 0xff, 0xff]).unwrap();
        file.sync_all().unwrap();
        let verification = validate_backup(&artifact.path).unwrap();
        assert!(!verification.integrity_ok);
    }
}

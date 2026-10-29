//! WAL-aware case backup, validation, and portable backup/restore (plan
//! Sections 8 and 12; P1.2 and P9.2).
//!
//! The migration path uses this as an internal prerequisite: a consistent
//! online backup is taken to `diagnostics/` (never outside the case for P1.2),
//! fsynced, hashed, integrity-checked, and schema-verified. If any step fails
//! the caller aborts *before* modifying the schema.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::integrity::inventory::{InventoryFile, ensure_no_unlisted, verify_files};
use crate::integrity::manifest::reject_duplicate_keys;
use crate::reports::{create_private_dir, create_private_dir_all, sync_directory, write_synced};
use crate::storage::CaseLayout;

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
                .map_err(|e| {
                    CoreError::Storage(format!("backup run: {e} ({:?})", e.sqlite_error_code()))
                })?;
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
    let digest = crate::integrity::hash::digest_file(path)?;
    Ok((digest.hex(), digest.byte_length))
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
        assert_eq!(artifact.schema_version, 5);
        assert_eq!(artifact.applied_migrations.len(), 5);
        assert_eq!(artifact.applied_migrations[0].1, "0001_case");
        assert_eq!(artifact.applied_migrations[1].1, "0002_file_times");
        assert_eq!(artifact.applied_migrations[2].1, "0003_search");
        assert_eq!(artifact.applied_migrations[3].1, "0004_analysis");
        assert_eq!(artifact.applied_migrations[4].1, "0005_findings");

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

// ---------------------------------------------------------------------------
// P9.2: portable backup and verified restore.
// ---------------------------------------------------------------------------

/// Backup format identity.
pub const BACKUP_FORMAT: &str = "ghosttrace-backup/1";
/// Inventory file name inside a backup directory.
pub const BACKUP_INVENTORY: &str = "backup.json";
/// Upper bound for an inventory this build will read.
pub const MAX_BACKUP_INVENTORY_BYTES: u64 = 8 * 1024 * 1024;

/// One portable backup: a consistent SQLite snapshot plus every referenced
/// immutable object, the config, and the manifests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedBackup {
    pub directory: PathBuf,
    pub inventory_path: PathBuf,
    pub files: Vec<InventoryFile>,
    pub total_bytes: u64,
    pub case_id: String,
    pub schema_version: u32,
}

/// The versioned backup inventory. Contains names and digests, never evidence
/// values and never signing secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupInventoryV1 {
    pub format: String,
    pub backup_id: String,
    pub created_utc: String,
    pub tool_version: String,
    pub case_id: String,
    pub schema_version: u32,
    pub files: Vec<InventoryFile>,
    pub excluded: Vec<String>,
}

/// Result of verifying a backup directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupVerificationReport {
    pub inventory: BackupInventoryV1,
    pub files_verified: usize,
    pub total_bytes: u64,
}

/// Result of restoring a backup into a new case directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredCase {
    pub directory: PathBuf,
    pub case_id: String,
    pub schema_version: u32,
    pub objects: usize,
    pub manifests: usize,
}

/// Take a consistent portable backup of `case_root` into a new directory under
/// `output`. Publication is atomic; a failure leaves no backup directory.
pub fn backup_case(
    case_root: &Path,
    output: &Path,
    tool_version: &str,
) -> CoreResult<PublishedBackup> {
    let layout = CaseLayout::new(case_root);
    if !layout.exists() {
        return Err(CoreError::Storage(format!(
            "case database not found: {}",
            layout.database_path().display()
        )));
    }
    std::fs::create_dir_all(output)
        .map_err(|error| CoreError::Storage(format!("backup output dir: {error}")))?;
    let source = Connection::open(layout.database_path())
        .map_err(|error| CoreError::Storage(format!("open case for backup: {error}")))?;
    let case_id: String = source
        .query_row("SELECT id FROM cases LIMIT 1", [], |row| row.get(0))
        .map_err(|error| CoreError::Storage(format!("case id: {error}")))?;
    let schema_version: u32 = source
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map(|value| value.max(0) as u32)
        .map_err(|error| CoreError::Storage(format!("schema version: {error}")))?;
    let objects = referenced_objects(&source)?;
    let estimate = objects
        .iter()
        .map(|object| object.byte_length)
        .sum::<u64>()
        .saturating_add(
            std::fs::metadata(layout.database_path())
                .map(|metadata| metadata.len())
                .unwrap_or(0)
                .saturating_mul(2),
        )
        .saturating_add(64 * 1024 * 1024);
    crate::capture::copy::ensure_reserve(output, estimate, 0)?;

    // Best effort: fold the WAL back into the main file before snapshotting.
    // The backup API sees committed WAL data either way; this keeps the
    // snapshot from needing a second copy of a large WAL on disk.
    let _ = source.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");

    let created = chrono::Utc::now();
    let backup_id = format!(
        "backup-{}-{}",
        created.timestamp(),
        &case_id[..8.min(case_id.len())]
    );
    let target = output.join(&backup_id);
    if target.exists() {
        return Err(CoreError::Storage(format!(
            "backup {backup_id} already exists; refusing to overwrite"
        )));
    }
    let staging = output.join(format!(".{backup_id}.part"));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .map_err(|error| CoreError::Storage(format!("backup staging cleanup: {error}")))?;
    }

    let mut files = Vec::new();
    let result = (|| -> CoreResult<()> {
        create_private_dir(&staging)?;
        // Consistent snapshot first: it sees committed WAL data.
        let artifact = backup_and_verify(&source, &staging, "portable")?;
        let database = staging.join("case.sqlite");
        std::fs::rename(&artifact.path, &database)
            .map_err(|error| CoreError::Storage(format!("backup database rename: {error}")))?;
        // A portable backup is one self-contained file. The backup API can
        // leave WAL side files behind; checkpoint them into the main file and
        // remove the leftovers so the inventory has no unlisted entries.
        {
            let connection = Connection::open(&database)
                .map_err(|error| CoreError::Storage(format!("backup database: {error}")))?;
            let _mode: String = connection
                .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
                .map_err(|error| CoreError::Storage(format!("backup journal mode: {error}")))?;
            connection.close().map_err(|(_connection, error)| {
                CoreError::Storage(format!("backup database close: {error}"))
            })?;
        }
        for suffix in ["-wal", "-shm"] {
            let leftover = PathBuf::from(format!("{}{suffix}", artifact.path.display()));
            let _ = std::fs::remove_file(leftover);
        }

        std::fs::copy(layout.config_path(), staging.join("case.toml"))
            .map_err(|error| CoreError::Storage(format!("backup config copy: {error}")))?;

        if layout.manifests_root().is_dir() {
            create_private_dir(&staging.join("manifests"))?;
            for entry in std::fs::read_dir(layout.manifests_root())
                .map_err(|error| CoreError::Storage(format!("backup manifests: {error}")))?
            {
                let entry = entry
                    .map_err(|error| CoreError::Storage(format!("backup manifests: {error}")))?;
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                    CoreError::Storage(format!("backup manifest stat: {error}"))
                })?;
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                    return Err(CoreError::Unsupported(format!(
                        "unexpected manifest entry {}",
                        path.display()
                    )));
                }
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| CoreError::Unsupported("manifest name is not UTF-8".into()))?;
                std::fs::copy(&path, staging.join("manifests").join(name)).map_err(|error| {
                    CoreError::Storage(format!("backup manifest copy: {error}"))
                })?;
            }
        }

        for object in &objects {
            let source_path = case_root.join(&object.location);
            let destination = staging.join(&object.location);
            if let Some(parent) = destination.parent() {
                create_private_dir_all(parent)?;
            }
            std::fs::copy(&source_path, &destination).map_err(|_| CoreError::CorruptEvidence)?;
            let digest = crate::integrity::hash::digest_file(&destination)?;
            if digest.hex() != object.sha256 || digest.byte_length != object.byte_length {
                return Err(CoreError::CorruptEvidence);
            }
        }

        write_synced(
            &staging.join("README.txt"),
            backup_readme(&backup_id).as_bytes(),
        )?;

        for relative in ["case.sqlite", "case.toml", "README.txt", "manifests"] {
            let path = staging.join(relative);
            if path.is_file() {
                files.push(InventoryFile::of(
                    &staging,
                    relative,
                    backup_role(relative),
                )?);
            } else if path.is_dir() {
                let mut names = std::fs::read_dir(&path)
                    .map_err(|error| CoreError::Storage(format!("backup walk: {error}")))?
                    .map(|entry| {
                        entry.map_err(|error| CoreError::Storage(format!("backup walk: {error}")))
                    })
                    .collect::<CoreResult<Vec<_>>>()?;
                names.sort_by_key(|entry| entry.file_name());
                for entry in names {
                    let name = entry
                        .file_name()
                        .to_str()
                        .ok_or_else(|| CoreError::Unsupported("manifest name is not UTF-8".into()))?
                        .to_string();
                    files.push(InventoryFile::of(
                        &staging,
                        &format!("{relative}/{name}"),
                        "manifest",
                    )?);
                }
            }
        }
        for object in &objects {
            files.push(InventoryFile::of(&staging, &object.location, "object")?);
        }

        let inventory = BackupInventoryV1 {
            format: BACKUP_FORMAT.into(),
            backup_id: backup_id.clone(),
            created_utc: created.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            tool_version: tool_version.into(),
            case_id: case_id.clone(),
            schema_version,
            files: files.clone(),
            excluded: vec![
                "signing keys and trusted-key lists (outside the case)".into(),
                "reports (reproducible from the case)".into(),
                "diagnostics and staging artifacts".into(),
            ],
        };
        let mut inventory_text = serde_json::to_string_pretty(&inventory)
            .map_err(|error| CoreError::Storage(format!("backup inventory: {error}")))?;
        inventory_text.push('\n');
        write_synced(&staging.join(BACKUP_INVENTORY), inventory_text.as_bytes())?;

        sync_directory(&staging)?;
        std::fs::rename(&staging, &target)
            .map_err(|error| CoreError::Storage(format!("backup publish: {error}")))?;
        sync_directory(output)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(error);
    }
    let total_bytes = files.iter().map(|file| file.byte_length).sum();
    Ok(PublishedBackup {
        directory: target.clone(),
        inventory_path: target.join(BACKUP_INVENTORY),
        files,
        total_bytes,
        case_id,
        schema_version,
    })
}

/// Verify a backup directory: strict inventory paths, every listed file's
/// exact length and digest, and no unlisted files.
pub fn verify_backup(directory: &Path) -> CoreResult<BackupVerificationReport> {
    let inventory_path = directory.join(BACKUP_INVENTORY);
    let metadata = std::fs::metadata(&inventory_path)
        .map_err(|error| CoreError::Storage(format!("backup inventory: {error}")))?;
    if metadata.len() > MAX_BACKUP_INVENTORY_BYTES {
        return Err(CoreError::Unsupported(
            "the backup inventory is implausibly large".into(),
        ));
    }
    let text = std::fs::read_to_string(&inventory_path)
        .map_err(|error| CoreError::Storage(format!("backup inventory: {error}")))?;
    reject_duplicate_keys(&text)?;
    let inventory: BackupInventoryV1 = serde_json::from_str(&text)
        .map_err(|error| CoreError::Unsupported(format!("backup inventory: {error}")))?;
    if inventory.format != BACKUP_FORMAT {
        return Err(CoreError::Unsupported(format!(
            "backup format {} is not supported",
            inventory.format
        )));
    }
    let total_bytes = verify_files(directory, &inventory.files)?;
    ensure_no_unlisted(directory, &inventory.files, &[BACKUP_INVENTORY])?;
    Ok(BackupVerificationReport {
        files_verified: inventory.files.len(),
        inventory,
        total_bytes,
    })
}

/// Restore a verified backup into a destination that does not exist yet. The
/// case is materialized in a private sibling staging directory, re-verified,
/// and only then renamed into place.
pub fn restore_case(backup_directory: &Path, destination: &Path) -> CoreResult<RestoredCase> {
    let verification = verify_backup(backup_directory)?;
    let inventory = verification.inventory;
    if destination.exists() {
        return Err(CoreError::Storage(format!(
            "restore destination {} already exists; refusing to overwrite",
            destination.display()
        )));
    }
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(CoreError::Storage(format!(
            "restore parent {} is not a directory",
            parent.display()
        )));
    }
    crate::capture::copy::ensure_reserve(parent, verification.total_bytes.saturating_mul(2), 0)?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CoreError::InvalidInput("restore destination name is not UTF-8".into()))?;
    let staging = parent.join(format!(".{name}.restore-part"));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .map_err(|error| CoreError::Storage(format!("restore staging cleanup: {error}")))?;
    }

    let result = (|| -> CoreResult<()> {
        create_private_dir(&staging)?;
        for file in &inventory.files {
            let target = staging.join(&file.path);
            if let Some(parent) = target.parent() {
                create_private_dir_all(parent)?;
            }
            std::fs::copy(backup_directory.join(&file.path), &target)
                .map_err(|error| CoreError::Storage(format!("restore copy: {error}")))?;
            let digest = crate::integrity::hash::digest_file(&target)?;
            if digest.hex() != file.sha256 || digest.byte_length != file.byte_length {
                return Err(CoreError::CorruptEvidence);
            }
        }

        // Reopen the restored database and prove every referenced object is
        // present, complete, and at the recorded relative location.
        let database = staging.join("case.sqlite");
        let restored =
            Connection::open_with_flags(&database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|error| CoreError::Storage(format!("restore database: {error}")))?;
        let integrity: String = restored
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|error| CoreError::Storage(format!("restore integrity: {error}")))?;
        if integrity != "ok" {
            return Err(CoreError::CorruptEvidence);
        }
        let version: u32 = restored
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .map(|value| value.max(0) as u32)
            .map_err(|error| CoreError::Storage(format!("restore schema: {error}")))?;
        if version != inventory.schema_version
            || version == 0
            || version > crate::storage::migrate::SUPPORTED_SCHEMA_VERSION
        {
            return Err(CoreError::Unsupported(format!(
                "backup schema {version} is not supported by this build"
            )));
        }
        let restored_case: String = restored
            .query_row("SELECT id FROM cases LIMIT 1", [], |row| row.get(0))
            .map_err(|error| CoreError::Storage(format!("restore case id: {error}")))?;
        if restored_case != inventory.case_id {
            return Err(CoreError::CorruptEvidence);
        }
        let objects = referenced_objects(&restored)?;
        for object in &objects {
            let path = staging.join(&object.location);
            let metadata = std::fs::metadata(&path).map_err(|_| CoreError::CorruptEvidence)?;
            if metadata.len() != object.byte_length {
                return Err(CoreError::CorruptEvidence);
            }
            let digest = crate::integrity::hash::digest_file(&path)?;
            if digest.hex() != object.sha256 {
                return Err(CoreError::CorruptEvidence);
            }
        }
        drop(restored);

        sync_directory(&staging)?;
        std::fs::rename(&staging, destination)
            .map_err(|error| CoreError::Storage(format!("restore publish: {error}")))?;
        sync_directory(parent)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(error);
    }

    // Prove the relocated case opens through the normal read path.
    let reader = crate::storage::read::CaseReader::open(
        &crate::storage::CaseLayout::new(destination).database_path(),
    )?;
    let reopened: String = reader
        .connection()
        .query_row("SELECT id FROM cases LIMIT 1", [], |row| row.get(0))
        .map_err(|error| CoreError::Storage(format!("reopen case id: {error}")))?;
    if reopened != inventory.case_id {
        return Err(CoreError::CorruptEvidence);
    }
    let objects = referenced_objects(reader.connection())?.len();
    let manifests =
        std::fs::read_dir(crate::storage::CaseLayout::new(destination).manifests_root())
            .map(|entries| entries.filter_map(|entry| entry.ok()).count())
            .unwrap_or(0);
    Ok(RestoredCase {
        directory: destination.to_path_buf(),
        case_id: inventory.case_id,
        schema_version: inventory.schema_version,
        objects,
        manifests,
    })
}

struct ReferencedObject {
    location: String,
    sha256: String,
    byte_length: u64,
}

/// Every complete object the case references, at a path this code can trust.
fn referenced_objects(connection: &Connection) -> CoreResult<Vec<ReferencedObject>> {
    let mut statement = connection
        .prepare(
            "SELECT DISTINCT object_location, sha256, byte_length
             FROM evidence_objects
             WHERE object_location IS NOT NULL AND digest_status = 'complete'
             ORDER BY object_location",
        )
        .map_err(|error| CoreError::Storage(format!("object query: {error}")))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        })
        .map_err(|error| CoreError::Storage(format!("object query: {error}")))?;
    let mut objects = Vec::new();
    for row in rows {
        let (location, sha256, byte_length) =
            row.map_err(|error| CoreError::Storage(format!("object row: {error}")))?;
        let sha256 = sha256.ok_or(CoreError::CorruptEvidence)?;
        if sha256.len() != 32 {
            return Err(CoreError::CorruptEvidence);
        }
        let sha256 = sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let byte_length = byte_length.ok_or(CoreError::CorruptEvidence)?.max(0) as u64;
        let expected = format!("objects/sha256/{}/{}", &sha256[..2], sha256);
        if location != expected {
            return Err(CoreError::Unsupported(format!(
                "object location {location:?} is not the content-addressed store path"
            )));
        }
        objects.push(ReferencedObject {
            location,
            sha256,
            byte_length,
        });
    }
    Ok(objects)
}

fn backup_role(relative: &str) -> &'static str {
    match relative {
        "case.sqlite" => "database",
        "case.toml" => "config",
        "README.txt" => "instructions",
        _ => "manifest",
    }
}

fn backup_readme(backup_id: &str) -> String {
    format!(
        "GhostTrace portable case backup {backup_id}\n\
         \n\
         backup.json   digest inventory over every file in this directory\n\
         case.sqlite   consistent SQLite snapshot taken with the online backup API\n\
         case.toml     case configuration\n\
         manifests/    acquisition manifests and their detached signatures\n\
         objects/      immutable stored objects at their relative store paths\n\
         \n\
         Restore with `ghosttrace restore --backup <this directory> --destination <new case path>`.\n\
         Restore verifies every digest, the database integrity, the schema version, and every\n\
         object reference before publishing anything. The destination must not exist.\n\
         \n\
         Excluded on purpose: signing keys and trusted-key lists (they live outside the case),\n\
         generated reports, diagnostics, and staging artifacts. Paths inside the case are\n\
         relative, so a restored case does not depend on where it used to live.\n"
    )
}

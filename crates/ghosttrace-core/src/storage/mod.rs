//! Case directory layout, the dedicated writer, read connections, and
//! checksummed migrations (plan Sections 5, 8, P1.2).
//!
//! Rules embodied here:
//! - A case is a directory `*.ghosttrace-case` whose database is a fixed
//!   schema file; objects are content-addressed; everything else is
//!   append-only storage.
//! - Exactly one writer thread owns the write connection per case per process
//!   (a process-local registry enforces this; cross-process concurrent writers
//!   are serialized by SQLite WAL write locks and fail at first write).
//! - Readers use their own read-only connections with short transactions.
//! - Migration of an existing schema is preceded by a validated backup;
//!   a failed backup aborts before any schema change.

pub mod backup;
pub mod migrate;
pub mod read;
pub mod search;
pub mod writer;

pub use migrate::{MIGRATIONS, SUPPORTED_SCHEMA_VERSION};

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

/// Directory suffix of a case; ignored by tooling and never committed.
pub const CASE_DIR_SUFFIX: &str = ".ghosttrace-case";

/// User-authored config stored next to the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseConfig {
    pub label: String,
    /// IANA zone name for display (never for source interpretation).
    pub display_timezone: String,
    pub description: String,
}

impl Default for CaseConfig {
    fn default() -> Self {
        Self {
            label: String::new(),
            display_timezone: "UTC".to_string(),
            description: String::new(),
        }
    }
}

/// The on-disk names inside a case directory (plan Section 5).
#[derive(Debug, Clone)]
pub struct CaseLayout {
    root: PathBuf,
}

impl CaseLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn database_path(&self) -> PathBuf {
        self.root.join("case.sqlite")
    }

    pub fn config_path(&self) -> PathBuf {
        self.root.join("case.toml")
    }

    pub fn objects_root(&self) -> PathBuf {
        self.root.join("objects/sha256")
    }

    pub fn staging_root(&self) -> PathBuf {
        self.root.join("staging")
    }

    pub fn manifests_root(&self) -> PathBuf {
        self.root.join("manifests")
    }

    pub fn reports_root(&self) -> PathBuf {
        self.root.join("reports")
    }

    pub fn diagnostics_root(&self) -> PathBuf {
        self.root.join("diagnostics")
    }

    pub fn locks_root(&self) -> PathBuf {
        self.root.join("locks")
    }

    /// Create a case directory tree with private permissions where the
    /// platform supports them (Unix 0o700; Windows ACLs come with P9). A
    /// fresh directory is empty and needs no pre-creation backup.
    pub fn create_private_tree(&self) -> CoreResult<()> {
        create_private_dir(&self.root)?;
        for dir in [
            self.objects_root(),
            self.staging_root(),
            self.manifests_root(),
            self.reports_root(),
            self.diagnostics_root(),
            self.locks_root(),
        ] {
            create_private_dir(&dir)?;
        }
        Ok(())
    }

    pub fn exists(&self) -> bool {
        self.root.join("case.sqlite").exists()
    }
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> CoreResult<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| CoreError::Storage(format!("cannot create {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> CoreResult<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| CoreError::Storage(format!("cannot create {}: {e}", path.display())))
}

/// Startup SQLite diagnostics (plan P1.2): what runtime are we linked to and
/// with which options. Recorded, never assumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageDiagnostics {
    pub linked_sqlite_version: String,
    pub foreign_keys: bool,
    pub journal_mode: String,
    pub synchronous: String,
    pub wal_enabled: bool,
    pub page_size: i64,
}

pub fn collect_diagnostics(connection: &rusqlite::Connection) -> CoreResult<StorageDiagnostics> {
    let text = |statement: &str| -> CoreResult<String> {
        connection
            .query_row(statement, [], |row| row.get(0))
            .map_err(|e| CoreError::Storage(format!("{statement}: {e}")))
    };
    // `foreign_keys` is an integer pragma; reading it as text fails.
    let flag = |statement: &str| -> CoreResult<i64> {
        connection
            .query_row(statement, [], |row| row.get(0))
            .map_err(|e| CoreError::Storage(format!("{statement}: {e}")))
    };
    Ok(StorageDiagnostics {
        linked_sqlite_version: text("SELECT sqlite_version()")?,
        foreign_keys: flag("PRAGMA foreign_keys")? == 1,
        wal_enabled: text("PRAGMA journal_mode")? == "wal",
        journal_mode: text("PRAGMA journal_mode")?,
        synchronous: flag("PRAGMA synchronous")?.to_string(),
        page_size: flag("PRAGMA page_size")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_tree_is_created_private() {
        let dir = tempfile::tempdir().unwrap();
        let layout = CaseLayout::new(dir.path().join("investigation.ghosttrace-case"));
        layout.create_private_tree().unwrap();
        assert!(
            layout
                .database_path()
                .parent()
                .unwrap()
                .join("objects/sha256")
                .is_dir()
        );
        assert!(layout.locks_root().is_dir());
        assert!(layout.reports_root().is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&layout.root)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "case root must be owner-only");
        }
    }

    #[test]
    fn config_round_trips_exact_text() {
        let dir = tempfile::tempdir().unwrap();
        let layout = CaseLayout::new(dir.path());
        std::fs::create_dir_all(&layout.root).unwrap();
        let config = CaseConfig {
            label: "review 2026-10-24".to_string(),
            display_timezone: "Europe/Berlin".to_string(),
            description: "evidence lines".to_string(),
        };
        let text = toml::to_string(&config).unwrap();
        std::fs::write(layout.config_path(), &text).unwrap();
        let back: CaseConfig =
            toml::from_str(&std::fs::read_to_string(layout.config_path()).unwrap()).unwrap();
        assert_eq!(config, back);
    }
}

//! Shared harness for the P4.1 adapter tests: a real case, a real acquisition,
//! and imports against the captured store (never the source tree).
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use ghosttrace_core::capture::copy::{AcquisitionOptions, CopyProgress, run_acquisition};
use ghosttrace_core::capture::{CaptureRoot, CaptureSpec};
use ghosttrace_core::domain::case::AcquisitionMethod;
use ghosttrace_core::domain::path::NativePath;
use ghosttrace_core::error::CoreResult;
use ghosttrace_core::ingest::{ImportOutcome, ImportRequest, run_import};
use ghosttrace_core::service::{CaseSession, CreateCaseSpec};

pub struct Harness {
    dir: tempfile::TempDir,
    session: CaseSession,
    captures: usize,
}

impl Harness {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let session = CaseSession::create(
            dir.path().join("cases"),
            "case-1",
            CreateCaseSpec::default(),
        )
        .expect("case");
        Self {
            dir,
            session,
            captures: 0,
        }
    }

    pub fn root(&self) -> &Path {
        self.session.layout().root()
    }

    /// Direct access to the session for tests that query or maintain storage.
    pub fn session(&self) -> &CaseSession {
        &self.session
    }

    /// Write `files` into a fresh source folder, acquire it, and return the
    /// acquisition ID. File contents are exactly the bytes given.
    pub fn capture(&mut self, files: &[(&str, &[u8])]) -> String {
        self.capture_with_mtime(files, None)
    }

    /// Like `capture`, but every written file gets the same source mtime.
    /// Used to exercise metadata-preserving rewrites.
    pub fn capture_at(&mut self, files: &[(&str, &[u8])], mtime_seconds: i64) -> String {
        self.capture_with_mtime(files, Some(mtime_seconds))
    }

    /// Capture with an explicit per-file bound. The EVTX fixtures are larger
    /// than the 1 MiB default used by the synthetic text fixtures.
    pub fn capture_with_limit(&mut self, files: &[(&str, &[u8])], max_file_bytes: u64) -> String {
        self.capture_inner(files, None, max_file_bytes)
    }

    fn capture_with_mtime(
        &mut self,
        files: &[(&str, &[u8])],
        mtime_seconds: Option<i64>,
    ) -> String {
        self.capture_inner(files, mtime_seconds, 1 << 20)
    }

    fn capture_inner(
        &mut self,
        files: &[(&str, &[u8])],
        mtime_seconds: Option<i64>,
        max_file_bytes: u64,
    ) -> String {
        self.captures += 1;
        let evidence = self.dir.path().join(format!("evidence-{}", self.captures));
        for (path, bytes) in files {
            let full = evidence.join(path);
            std::fs::create_dir_all(full.parent().expect("parent")).expect("dirs");
            std::fs::write(&full, bytes).expect("write evidence");
            if let Some(seconds) = mtime_seconds {
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&full)
                    .expect("open for mtime");
                let times = std::fs::FileTimes::new().set_modified(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds as u64),
                );
                file.set_times(times).expect("set mtime");
            }
        }
        std::fs::create_dir_all(&evidence).expect("evidence dir");
        let spec = CaptureSpec {
            roots: vec![CaptureRoot {
                native: native(&evidence),
                label: "source".into(),
            }],
            follow_symlinks: false,
            max_depth: 8,
            max_entries: 10_000,
            max_file_bytes,
            case_directory: self.session.layout().root().to_path_buf(),
        };
        let options =
            AcquisitionOptions::new(AcquisitionMethod::ProtectedCopy, "controlled test", &spec);
        let report = run_acquisition(&self.session, &spec, &options, &CopyProgress::new())
            .expect("acquisition");
        report.acquisition_id
    }

    pub fn import(
        &self,
        acquisition: &str,
        path: &str,
        configure: impl FnOnce(&mut ImportRequest<'_>),
    ) -> CoreResult<ImportOutcome> {
        let cancelled = AtomicBool::new(false);
        self.import_with_token(acquisition, path, &cancelled, configure)
    }

    pub fn import_with_token(
        &self,
        acquisition: &str,
        path: &str,
        cancelled: &AtomicBool,
        configure: impl FnOnce(&mut ImportRequest<'_>),
    ) -> CoreResult<ImportOutcome> {
        let reader = self.session.reader().expect("reader");
        let mut request = ImportRequest::new(cancelled);
        request.path = Some(path.to_string());
        request.acquisition_id = Some(acquisition.to_string());
        configure(&mut request);
        run_import(
            &reader,
            self.session.writer(),
            self.session.layout().root(),
            &request,
        )
    }

    /// Read one column from one row, for assertions about recorded state.
    pub fn scalar(&self, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Option<String> {
        let reader = self.session.reader().expect("reader");
        reader
            .connection()
            .query_row(sql, params, |row| {
                Ok(match row.get_ref(0)? {
                    rusqlite::types::ValueRef::Null => String::new(),
                    rusqlite::types::ValueRef::Integer(value) => value.to_string(),
                    rusqlite::types::ValueRef::Real(value) => value.to_string(),
                    rusqlite::types::ValueRef::Text(text) => {
                        String::from_utf8_lossy(text).into_owned()
                    }
                    rusqlite::types::ValueRef::Blob(bytes) => format!("<{} bytes>", bytes.len()),
                })
            })
            .ok()
    }

    pub fn count(&self, sql: &str, params: &[&dyn rusqlite::ToSql]) -> i64 {
        let reader = self.session.reader().expect("reader");
        reader
            .connection()
            .query_row(sql, params, |row| row.get::<_, i64>(0))
            .unwrap_or(-1)
    }

    pub fn case_root(&self) -> PathBuf {
        self.session.layout().root().to_path_buf()
    }

    /// Rewrite a stored content object in place (tamper simulation).
    pub fn tamper_object(&self, subpath: &str) {
        let path = self.case_root().join(subpath);
        let mut bytes = std::fs::read(&path).expect("object");
        bytes[0] ^= 0xff;
        std::fs::write(path, bytes).expect("tamper");
    }

    pub fn object_subpath(&self, acquisition: &str, encoded_path: &str) -> String {
        self.scalar(
            "SELECT object_location FROM evidence_objects
             WHERE acquisition_id = ?1 AND native_path_encoded = ?2",
            &[&acquisition, &encoded_path],
        )
        .expect("stored object")
    }
}

fn native(path: &Path) -> NativePath {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        NativePath::unix(path.as_os_str().as_bytes().to_vec())
    }
    #[cfg(not(unix))]
    {
        use std::os::windows::ffi::OsStrExt;
        NativePath::windows(path.as_os_str().encode_wide().collect::<Vec<u16>>())
    }
}

/// Build a SQLite database file with the given schema and row statements.
pub fn sqlite_bytes(dir: &Path, name: &str, schema: &str, rows: &[&str]) -> Vec<u8> {
    let path = dir.join(name);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("db dirs");
    let connection = rusqlite::Connection::open(&path).expect("open fixture db");
    connection.execute_batch(schema).expect("fixture schema");
    for row in rows {
        connection.execute_batch(row).expect("fixture row");
    }
    let bytes = std::fs::read(&path).expect("read fixture db");
    drop(connection);
    bytes
}

pub struct WalFiles {
    pub main: Vec<u8>,
    pub wal: Vec<u8>,
    pub shm: Option<Vec<u8>>,
}

/// Build a WAL-mode database and copy the three files while the writer is
/// still open, so committed rows live in the WAL rather than the main file.
pub fn wal_database(dir: &Path, schema: &str, rows: &[&str]) -> WalFiles {
    let path = dir.join("History");
    let connection = rusqlite::Connection::open(&path).expect("open WAL fixture");
    let mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .expect("WAL mode");
    assert_eq!(mode.to_ascii_lowercase(), "wal");
    connection.execute_batch(schema).expect("fixture schema");
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint");
    for row in rows {
        connection.execute_batch(row).expect("fixture row");
    }
    let main = std::fs::read(&path).expect("main db");
    let wal = std::fs::read(with_suffix(&path, "-wal")).expect("WAL");
    let shm = std::fs::read(with_suffix(&path, "-shm")).ok();
    drop(connection);
    WalFiles { main, wal, shm }
}

pub fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

/// A fake worker script that completes the handshake, then runs `body`. The
/// script speaks the frame format with `printf`; the body must not contain a
/// single quote. Unix only: Windows has no `/bin/sh` in the test image.
#[cfg(unix)]
pub fn fake_worker(ready_version: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("ghosttrace-fake-worker-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("fake worker dir");
    let path = dir.join("fake-worker");
    let ready = format!(r#"{{"type":"ready","protocol":1,"version":"{ready_version}"}}"#);
    let script = format!("#!/bin/sh\n{}\n{body}\n", frame_printf(&ready));
    std::fs::write(&path, script).expect("write fake worker");
    let mut permissions = std::fs::metadata(&path).expect("stat").permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).expect("chmod");
    path
}

/// `printf` invocation that writes one length-prefixed frame.
#[cfg(unix)]
pub fn frame_printf(body: &str) -> String {
    let mut prefix = String::new();
    for byte in (body.len() as u32).to_be_bytes() {
        prefix.push_str(&format!("\\{byte:03o}"));
    }
    format!("printf '{prefix}%s' '{body}'")
}

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

    /// Write `files` into a fresh source folder, acquire it, and return the
    /// acquisition ID. File contents are exactly the bytes given.
    pub fn capture(&mut self, files: &[(&str, &[u8])]) -> String {
        self.captures += 1;
        let evidence = self.dir.path().join(format!("evidence-{}", self.captures));
        for (path, bytes) in files {
            let full = evidence.join(path);
            std::fs::create_dir_all(full.parent().expect("parent")).expect("dirs");
            std::fs::write(&full, bytes).expect("write evidence");
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
            max_file_bytes: 1 << 20,
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

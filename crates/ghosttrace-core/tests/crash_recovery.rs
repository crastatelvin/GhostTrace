//! P10.1 crash-recovery boundaries: a failed publish leaves no directory that
//! looks complete, abandoned staging is cleaned rather than trusted, and a
//! damaged case is refused on reopen instead of opening silently.
//!
//! Disk-full is exercised through the same preflight reserve the capture and
//! backup paths use (`ensure_reserve` with an impossible size) plus unwritable
//! output directories. A root CI user cannot be denied by mode bits, so those
//! cases skip under root and the reserve case still runs.

mod support;

use std::path::Path;

use ghosttrace_core::capture::copy::ensure_reserve;
use ghosttrace_core::error::CoreError;
use ghosttrace_core::ingest::LogFormat;
use ghosttrace_core::integrity::signature::verify_manifest;
use ghosttrace_core::reports::package::{PackageRequest, publish_package};
use ghosttrace_core::reports::{ReportContext, ReportSelection, build_report, publish};
use ghosttrace_core::service::CaseSession;
use support::Harness;

const RECORDS: &[u8] = b"{\"ts\":\"2026-10-27T10:00:00Z\",\"msg\":\"recover\"}\n";

fn setup(harness: &mut Harness) -> (ghosttrace_core::reports::ReportV1, std::path::PathBuf) {
    let acquisition = harness.capture(&[("logs/events.jsonl", RECORDS)]);
    let run = harness
        .import(&acquisition, "logs/events.jsonl", |request| {
            request.format = Some(LogFormat::Jsonl);
            request.jsonl.message_field = Some("msg".into());
        })
        .expect("import")
        .run_id;
    let context = ReportContext {
        case_id: harness.session().case_id().to_string(),
        label: "recovery".into(),
        display_timezone: "UTC".into(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_by: "ghosttrace-test".into(),
    };
    let selection = ReportSelection {
        acquisition_id: Some(acquisition.clone()),
        revision: Some(run),
        event_limit: 10,
    };
    let report = build_report(
        &harness.session().reader().expect("reader"),
        &context,
        &selection,
    )
    .expect("report");
    let manifest = harness
        .case_root()
        .join("manifests")
        .join(format!("manifest-{acquisition}.json"));
    (report, manifest)
}

#[cfg(unix)]
fn make_read_only(path: &Path) -> Option<std::fs::Permissions> {
    use std::os::unix::fs::PermissionsExt;
    let previous = std::fs::metadata(path).ok()?.permissions();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500)).ok()?;
    Some(previous)
}

#[cfg(unix)]
fn restore(path: &Path, previous: std::fs::Permissions) {
    let _ = std::fs::set_permissions(path, previous);
}

fn root_user() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[test]
fn a_report_publish_that_cannot_stage_leaves_no_report() {
    let mut harness = Harness::new();
    let (report, _manifest) = setup(&mut harness);
    let output = tempfile::tempdir().expect("output");
    #[cfg(unix)]
    if !root_user() {
        let previous = make_read_only(output.path()).expect("mode");
        let error = publish(&report, output.path()).expect_err("unwritable output");
        restore(output.path(), previous);
        assert!(matches!(error, CoreError::Storage(_)), "{error:?}");
        assert!(!output.path().join(&report.report_id).exists());
        assert!(
            !std::fs::read_dir(output.path())
                .expect("list")
                .any(|entry| entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".part")),
            "a failed publish must remove its staging directory"
        );
    }
    // The same report publishes once the destination is writable again.
    let published = publish(&report, output.path()).expect("publish after recovery");
    assert!(published.json_path.is_file());
}

#[test]
fn abandoned_report_staging_is_removed_not_trusted() {
    let mut harness = Harness::new();
    let (mut report, _manifest) = setup(&mut harness);
    report.report_id = "report-recovery-1".into();
    let output = tempfile::tempdir().expect("output");
    let staging = output.path().join(".report-recovery-1.part");
    std::fs::create_dir_all(&staging).expect("staging");
    std::fs::write(staging.join("report.json"), b"{\"partial\":true}").expect("partial");

    let published = publish(&report, output.path()).expect("publish");
    assert!(!staging.exists(), "stale staging is removed");
    let json = std::fs::read_to_string(&published.json_path).expect("json");
    assert!(json.contains("\"report_id\": \"report-recovery-1\""));
    assert!(!json.contains("partial"));
}

#[test]
fn a_package_publish_that_cannot_stage_leaves_no_package() {
    let mut harness = Harness::new();
    let (report, manifest) = setup(&mut harness);
    let output = tempfile::tempdir().expect("output");
    #[cfg(unix)]
    if !root_user() {
        let previous = make_read_only(output.path()).expect("mode");
        let error = publish_package(PackageRequest {
            case_root: &harness.case_root(),
            output: output.path(),
            report: &report,
            redaction: None,
            manifest_path: &manifest,
            manifest_signature: None,
            key: None,
            tool_version: env!("CARGO_PKG_VERSION"),
        })
        .expect_err("unwritable output");
        restore(output.path(), previous);
        assert!(matches!(error, CoreError::Storage(_)), "{error:?}");
        assert!(
            !std::fs::read_dir(output.path())
                .expect("list")
                .any(|entry| entry.expect("entry").path().join("package.json").is_file())
        );
    }
}

#[test]
fn a_backup_that_cannot_stage_leaves_no_backup() {
    use ghosttrace_core::storage::backup::backup_case;
    let mut harness = Harness::new();
    setup(&mut harness);
    let output = tempfile::tempdir().expect("output");
    #[cfg(unix)]
    if !root_user() {
        let previous = make_read_only(output.path()).expect("mode");
        let error =
            backup_case(&harness.case_root(), output.path(), "test").expect_err("unwritable");
        restore(output.path(), previous);
        assert!(matches!(error, CoreError::Storage(_)), "{error:?}");
        assert!(
            !std::fs::read_dir(output.path())
                .expect("list")
                .any(|entry| entry.expect("entry").path().join("backup.json").is_file())
        );
    }
}

#[test]
fn an_impossible_disk_reserve_is_refused_before_work() {
    let dir = tempfile::tempdir().expect("dir");
    let error = ensure_reserve(dir.path(), u64::MAX, 0).expect_err("reserve");
    assert!(matches!(error, CoreError::ResourceLimit), "{error:?}");
}

#[test]
fn a_truncated_database_is_refused_on_reopen() {
    let dir = tempfile::tempdir().expect("dir");
    let case = dir.path().join("truncated.ghosttrace-case");
    {
        let session =
            CaseSession::create(dir.path(), "truncated", Default::default()).expect("create");
        assert_eq!(session.layout().root(), case);
    }
    let database = case.join("case.sqlite");
    let bytes = std::fs::read(&database).expect("database");
    std::fs::write(&database, &bytes[..bytes.len().min(64)]).expect("truncate");
    let error = match CaseSession::open(&case) {
        Ok(_) => panic!("a truncated database must not open"),
        Err(error) => error,
    };
    assert!(
        matches!(error, CoreError::Storage(_) | CoreError::CorruptEvidence),
        "{error:?}"
    );
}

#[test]
fn a_corrupted_stored_object_is_reported_not_ignored() {
    let mut harness = Harness::new();
    let (report, manifest) = setup(&mut harness);
    let object = &report.objects[0];
    let stored = harness
        .case_root()
        .join("objects/sha256")
        .join(&object.sha256[..2])
        .join(&object.sha256);
    let mut bytes = std::fs::read(&stored).expect("object");
    bytes[0] ^= 0xff;
    std::fs::write(&stored, bytes).expect("corrupt object");

    let verification =
        verify_manifest(&harness.case_root(), &manifest, None, None).expect("verification runs");
    assert!(
        !verification.is_accepted(),
        "a corrupt object must fail verification: {verification:?}"
    );
}

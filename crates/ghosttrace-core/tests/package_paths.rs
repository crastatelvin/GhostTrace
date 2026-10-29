//! P9.2 package contract: an untampered package verifies, any modified byte is
//! rejected, and paths or entries cannot escape or collide.

mod support;

use ghosttrace_core::ingest::LogFormat;
use ghosttrace_core::integrity::keys::{generate_key_file, load_key_file};
use ghosttrace_core::integrity::signature::{KeyTrust, SignatureStatus, TrustedKeys};
use ghosttrace_core::reports::package::{
    PackageRequest, object_path, publish_package, verify_package,
};
use ghosttrace_core::reports::redact::{RedactionPolicy, redact_report};
use ghosttrace_core::reports::{ReportContext, ReportSelection, build_report};
use support::Harness;

const PASS: &[u8] = b"correct horse battery staple";

fn setup(harness: &mut Harness) -> (ghosttrace_core::reports::ReportV1, std::path::PathBuf) {
    let acquisition = harness.capture(&[("logs/events.jsonl", b"{\"msg\":\"package\"}\n")]);
    let run = harness
        .import(&acquisition, "logs/events.jsonl", |request| {
            request.format = Some(LogFormat::Jsonl);
            request.jsonl.message_field = Some("msg".into());
        })
        .expect("import")
        .run_id;
    let context = ReportContext {
        case_id: harness.session().case_id().to_string(),
        label: "package".into(),
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

fn publish(
    harness: &Harness,
    report: &ghosttrace_core::reports::ReportV1,
    manifest: &std::path::Path,
    output: &std::path::Path,
    key: Option<&ghosttrace_core::integrity::keys::UnlockedKey>,
) -> ghosttrace_core::reports::package::PublishedPackage {
    publish_package(PackageRequest {
        case_root: &harness.case_root(),
        output,
        report,
        redaction: None,
        manifest_path: manifest,
        manifest_signature: None,
        key,
        tool_version: env!("CARGO_PKG_VERSION"),
    })
    .expect("package")
}

#[test]
fn an_untampered_package_verifies_with_every_file() {
    let mut harness = Harness::new();
    let (report, manifest) = setup(&mut harness);
    let output = tempfile::tempdir().expect("output");
    let published = publish(&harness, &report, &manifest, output.path(), None);
    assert!(!published.signed);
    assert!(published.directory.join("README.txt").is_file());
    assert!(published.directory.join("report.csv").is_file());
    assert!(published.directory.join("manifest.json").is_file());
    assert!(
        published
            .directory
            .join("objects")
            .join(&report.objects[0].sha256)
            .is_file()
    );

    let verification = verify_package(&published.directory, None).expect("verify");
    assert!(verification.is_accepted());
    assert_eq!(verification.signature, SignatureStatus::Absent);
    assert_eq!(verification.key_trust, KeyTrust::NotApplicable);
    assert_eq!(verification.files_verified, published.files.len());
    assert_eq!(verification.inventory.case_id, report.case.case_id);
}

#[test]
fn any_modified_byte_is_rejected() {
    let mut harness = Harness::new();
    let (report, manifest) = setup(&mut harness);
    let output = tempfile::tempdir().expect("output");
    let published = publish(&harness, &report, &manifest, output.path(), None);
    let report_json = published.directory.join("report.json");
    let mut bytes = std::fs::read(&report_json).expect("report");
    bytes[0] ^= 0xff;
    std::fs::write(&report_json, bytes).expect("tamper");

    let error = verify_package(&published.directory, None).expect_err("tamper must fail");
    assert!(
        matches!(error, ghosttrace_core::error::CoreError::CorruptEvidence),
        "{error:?}"
    );
}

#[test]
fn an_unlisted_extra_file_is_rejected() {
    let mut harness = Harness::new();
    let (report, manifest) = setup(&mut harness);
    let output = tempfile::tempdir().expect("output");
    let published = publish(&harness, &report, &manifest, output.path(), None);
    std::fs::write(published.directory.join("extra.txt"), b"smuggled").expect("extra");
    let error = verify_package(&published.directory, None).expect_err("extra must fail");
    assert!(error.to_string().contains("unlisted file"), "{error}");
}

#[test]
fn inventory_paths_cannot_escape_or_collide() {
    let mut harness = Harness::new();
    let (report, manifest) = setup(&mut harness);
    let output = tempfile::tempdir().expect("output");
    let published = publish(&harness, &report, &manifest, output.path(), None);
    let inventory_path = published.directory.join("package.json");
    let original: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&inventory_path).expect("inventory"))
            .expect("json");

    let mut escaped = original.clone();
    escaped["files"][0]["path"] = "../escape.txt".into();
    std::fs::write(&inventory_path, escaped.to_string()).expect("escape inventory");
    let error = verify_package(&published.directory, None).expect_err("traversal must fail");
    assert!(error.to_string().contains("escapes"), "{error}");

    let mut duplicate = original.clone();
    let first = duplicate["files"][0].clone();
    duplicate["files"]
        .as_array_mut()
        .expect("files")
        .push(first);
    std::fs::write(&inventory_path, duplicate.to_string()).expect("duplicate inventory");
    let error = verify_package(&published.directory, None).expect_err("collision must fail");
    assert!(error.to_string().contains("twice"), "{error}");
}

#[test]
fn a_signed_package_separates_validity_from_trust() {
    let mut harness = Harness::new();
    let (report, manifest) = setup(&mut harness);
    let output = tempfile::tempdir().expect("output");
    let key_dir = tempfile::tempdir().expect("keys");
    let key_path = key_dir.path().join("key.pem");
    generate_key_file(&key_path, PASS).expect("key");
    let key = load_key_file(&key_path, PASS).expect("unlock");
    let published = publish(&harness, &report, &manifest, output.path(), Some(&key));
    assert!(published.signed);
    let fingerprint = published.key_fingerprint.clone().expect("fingerprint");

    let untrusted = verify_package(&published.directory, None).expect("verify");
    assert!(untrusted.is_accepted());
    assert_eq!(untrusted.signature, SignatureStatus::Valid);
    assert_eq!(untrusted.key_trust, KeyTrust::Untrusted);

    let trust = TrustedKeys::parse(&fingerprint).expect("trust");
    let trusted = verify_package(&published.directory, Some(&trust)).expect("verify");
    assert_eq!(trusted.key_trust, KeyTrust::Trusted);

    // Changing the inventory bytes invalidates the signature even though every
    // listed file still matches its digest.
    let inventory_path = published.directory.join("package.json");
    let mut text = std::fs::read_to_string(&inventory_path).expect("inventory");
    text.push('\n');
    std::fs::write(&inventory_path, text).expect("tamper inventory");
    let tampered = verify_package(&published.directory, Some(&trust)).expect("verify");
    assert!(!tampered.is_accepted());
    assert!(matches!(tampered.signature, SignatureStatus::Invalid(_)));
}

#[test]
fn object_paths_are_digests_only() {
    let root = std::path::Path::new("/tmp/case");
    assert!(object_path(root, "../escape").is_err());
    assert!(object_path(root, &"g".repeat(64)).is_err());
    let path = object_path(root, &"ab".repeat(32)).expect("digest");
    assert_eq!(path, root.join("objects/sha256/ab").join("ab".repeat(32)));
}

#[test]
fn a_redacted_package_records_the_ledger_without_values() {
    let mut harness = Harness::new();
    let (report, manifest) = setup(&mut harness);
    let (redacted, ledger) = redact_report(
        &report,
        &RedactionPolicy {
            timeline_summaries: true,
            ..RedactionPolicy::default()
        },
    );
    let output = tempfile::tempdir().expect("output");
    let published = publish_package(PackageRequest {
        case_root: &harness.case_root(),
        output: output.path(),
        report: &redacted,
        redaction: Some(&ledger),
        manifest_path: &manifest,
        manifest_signature: None,
        key: None,
        tool_version: env!("CARGO_PKG_VERSION"),
    })
    .expect("package");
    let ledger_text =
        std::fs::read_to_string(published.directory.join("redaction.json")).expect("ledger");
    let removed = &report.timeline[0].summary;
    assert!(!removed.is_empty());
    assert!(
        !ledger_text.contains(removed.as_str()),
        "the ledger leaked the removed summary"
    );
    let verification = verify_package(&published.directory, None).expect("verify");
    assert!(verification.inventory.redacted);
    assert!(verification.inventory.redaction.is_some());
}

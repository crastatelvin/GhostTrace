//! P9.1: signature validity and key trust are separate statuses. A valid
//! unknown key is "valid signature, untrusted key"; tampering is a rejection.

mod support;

use std::path::{Path, PathBuf};

use ghosttrace_core::integrity::keys::{generate_key_file, load_key_file};
use ghosttrace_core::integrity::signature::{
    KeyTrust, ManifestStatus, SIGNATURE_FORMAT, SignatureEnvelope, SignatureStatus, TrustedKeys,
    sidecar_path, verify_manifest,
};
use support::Harness;

const PASS: &[u8] = b"correct horse battery staple";

fn case() -> (Harness, PathBuf) {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("a.txt", b"alpha\n")]);
    let manifest = harness
        .root()
        .join("manifests")
        .join(format!("manifest-{acquisition}.json"));
    assert!(manifest.is_file(), "{manifest:?}");
    (harness, manifest)
}

fn sign(path: &Path, manifest: &Path, passphrase: &[u8]) -> SignatureEnvelope {
    generate_key_file(path, passphrase).expect("key");
    let key = load_key_file(path, passphrase).expect("unlock");
    let bytes = std::fs::read(manifest).expect("manifest");
    let envelope = SignatureEnvelope::sign(&bytes, &key);
    envelope
        .write_atomic(&sidecar_path(manifest))
        .expect("sidecar");
    envelope
}

#[test]
fn a_valid_signature_from_an_unknown_key_is_reported_as_untrusted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (harness, manifest) = case();
    let key = dir.path().join("key.pem");
    let envelope = sign(&key, &manifest, PASS);

    let report = verify_manifest(harness.root(), &manifest, None, None).expect("verify");
    assert!(report.is_accepted());
    assert_eq!(report.signature, SignatureStatus::Valid);
    assert_eq!(report.key_trust, KeyTrust::Untrusted);
    assert_eq!(
        report.key_fingerprint.as_deref(),
        Some(envelope.key_fingerprint.as_str())
    );
    assert_eq!(
        report.public_key.as_deref(),
        Some(envelope.public_key.as_str())
    );
    assert_eq!(report.capture_complete, Some(true));
    assert!(matches!(report.manifest, ManifestStatus::Verified(_)));
}

#[test]
fn an_explicit_trust_list_promotes_the_same_signature() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (harness, manifest) = case();
    let key = dir.path().join("key.pem");
    let envelope = sign(&key, &manifest, PASS);

    let trust_path = dir.path().join("trusted-keys.txt");
    std::fs::write(
        &trust_path,
        format!("# my keys\n{}\n", envelope.key_fingerprint),
    )
    .expect("trust file");
    let trusted = TrustedKeys::load(&trust_path).expect("trust");
    let report = verify_manifest(harness.root(), &manifest, None, Some(&trusted)).expect("verify");
    assert_eq!(report.key_trust, KeyTrust::Trusted);
    assert_eq!(report.signature, SignatureStatus::Valid);
    assert!(report.is_accepted());

    let unrelated =
        TrustedKeys::parse("0000000000000000000000000000000000000000000000000000000000000000")
            .expect("other fingerprint");
    let report =
        verify_manifest(harness.root(), &manifest, None, Some(&unrelated)).expect("verify");
    assert_eq!(report.key_trust, KeyTrust::Untrusted);
}

#[test]
fn a_whitespace_change_invalidates_the_signature() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (harness, manifest) = case();
    let key = dir.path().join("key.pem");
    sign(&key, &manifest, PASS);

    let text = std::fs::read_to_string(&manifest).expect("read");
    std::fs::write(&manifest, text.replacen("{\n", "{\n\n", 1)).expect("write");
    let report = verify_manifest(harness.root(), &manifest, None, None).expect("verify");
    assert!(!report.is_accepted());
    assert!(
        matches!(report.signature, SignatureStatus::Invalid(_)),
        "{:?}",
        report.signature
    );
    // The manifest still decodes: only the signature rejected these bytes.
    assert!(matches!(report.manifest, ManifestStatus::Verified(_)));
}

#[test]
fn tampered_objects_and_tampered_manifests_are_separate_statuses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (harness, manifest) = case();
    let key = dir.path().join("key.pem");
    sign(&key, &manifest, PASS);

    let object = std::fs::read_dir(harness.root().join("objects/sha256"))
        .expect("objects")
        .flatten()
        .flat_map(|bucket| std::fs::read_dir(bucket.path()).expect("bucket").flatten())
        .next()
        .expect("one object")
        .path();
    let mut bytes = std::fs::read(&object).expect("object");
    bytes[0] ^= 0xff;
    std::fs::write(&object, bytes).expect("write");

    let report = verify_manifest(harness.root(), &manifest, None, None).expect("verify");
    assert!(!report.is_accepted());
    assert_eq!(
        report.signature,
        SignatureStatus::Valid,
        "the manifest file itself was not changed"
    );
    match report.manifest {
        ManifestStatus::Rejected { code, .. } => assert_eq!(code, "integrity_mismatch"),
        other => panic!("expected a rejected manifest, got {other:?}"),
    }
    assert_eq!(report.capture_complete, None);
}

#[test]
fn unsupported_algorithm_and_version_are_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (harness, manifest) = case();
    let key = dir.path().join("key.pem");
    let envelope = sign(&key, &manifest, PASS);
    let sidecar = sidecar_path(&manifest);

    for mutate in [
        |value: &mut serde_json::Value| value["algorithm"] = "rsa-pss".into(),
        |value: &mut serde_json::Value| value["format"] = "ghosttrace-signature/2".into(),
    ] {
        let mut value = serde_json::to_value(&envelope).expect("json");
        mutate(&mut value);
        std::fs::write(&sidecar, serde_json::to_vec_pretty(&value).unwrap()).expect("write");
        let error = verify_manifest(harness.root(), &manifest, None, None).expect_err("refused");
        assert_eq!(error.code(), "unsupported_format", "{error}");
    }
}

#[test]
fn a_duplicate_sidecar_key_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (harness, manifest) = case();
    let key = dir.path().join("key.pem");
    sign(&key, &manifest, PASS);
    let sidecar = sidecar_path(&manifest);
    let text = std::fs::read_to_string(&sidecar).expect("read");
    std::fs::write(
        &sidecar,
        text.replacen(
            '{',
            &format!("{{\n  \"format\": \"{SIGNATURE_FORMAT}\","),
            1,
        ),
    )
    .expect("write");
    let error = verify_manifest(harness.root(), &manifest, None, None).expect_err("duplicate");
    assert_eq!(error.code(), "unsupported_format", "{error}");
}

#[test]
fn malformed_encodings_and_a_foreign_signature_are_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (harness, manifest) = case();
    let key = dir.path().join("key.pem");
    let envelope = sign(&key, &manifest, PASS);
    let sidecar = sidecar_path(&manifest);

    // Malformed signature hex.
    let mut value = serde_json::to_value(&envelope).expect("json");
    value["signature"] = "zz".into();
    std::fs::write(&sidecar, serde_json::to_vec_pretty(&value).unwrap()).expect("write");
    let error = verify_manifest(harness.root(), &manifest, None, None).expect_err("hex");
    assert_eq!(error.code(), "unsupported_format", "{error}");

    // Fingerprint that does not belong to the embedded key.
    let mut value = serde_json::to_value(&envelope).expect("json");
    value["key_fingerprint"] = "0".repeat(64).into();
    std::fs::write(&sidecar, serde_json::to_vec_pretty(&value).unwrap()).expect("write");
    let error = verify_manifest(harness.root(), &manifest, None, None).expect_err("fingerprint");
    assert!(error.to_string().contains("fingerprint"), "{error}");

    // A signature from a different key over the same bytes.
    let other = dir.path().join("other.pem");
    generate_key_file(&other, PASS).expect("other key");
    let other_key = load_key_file(&other, PASS).expect("unlock");
    let bytes = std::fs::read(&manifest).expect("manifest");
    let foreign = SignatureEnvelope::sign(&bytes, &other_key);
    let mut value = serde_json::to_value(&envelope).expect("json");
    value["signature"] = foreign.signature.into();
    std::fs::write(&sidecar, serde_json::to_vec_pretty(&value).unwrap()).expect("write");
    let report = verify_manifest(harness.root(), &manifest, None, None).expect("verify");
    assert!(!report.is_accepted());
    assert!(matches!(report.signature, SignatureStatus::Invalid(_)));
}

#[test]
fn signing_never_overwrites_an_existing_sidecar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_harness, manifest) = case();
    let key = dir.path().join("key.pem");
    let envelope = sign(&key, &manifest, PASS);
    let error = envelope
        .write_atomic(&sidecar_path(&manifest))
        .expect_err("exists");
    assert!(error.to_string().contains("already exists"), "{error}");
}

#[test]
fn the_trust_file_is_strict() {
    let error = TrustedKeys::parse("# comment\nnot-a-fingerprint\n").expect_err("strict");
    assert!(error.to_string().contains("line 2"), "{error}");
    let parsed = TrustedKeys::parse(
        "# comment\n\nABCDEF0000000000000000000000000000000000000000000000000000000000\n",
    )
    .expect("uppercase is accepted");
    assert!(parsed.contains("abcdef0000000000000000000000000000000000000000000000000000000000"));
    assert!(TrustedKeys::default().is_empty());
}

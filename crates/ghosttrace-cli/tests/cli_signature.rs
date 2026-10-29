//! P9.1 CLI contract: signatures are verified with explicit key trust, and a
//! passphrase is never accepted from a pipe or an argument.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ghosttrace_core::integrity::keys::{generate_key_file, load_key_file};
use ghosttrace_core::integrity::signature::{SignatureEnvelope, sidecar_path};

const PASS: &[u8] = b"correct horse battery staple";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ghosttrace")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().expect("cli runs")
}

fn setup(dir: &Path) -> (PathBuf, PathBuf) {
    let evidence = dir.join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("a.txt"), b"alpha\n").unwrap();
    let case = dir.join("case.ghosttrace-case");
    let output = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        "signature",
    ]);
    assert!(output.status.success(), "{output:?}");
    let output = run(&[
        "scan",
        "--case",
        case.to_str().unwrap(),
        "--source",
        evidence.to_str().unwrap(),
    ]);
    assert!(
        matches!(output.status.code(), Some(0) | Some(3)),
        "{output:?}"
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let acquisition = parsed["acquisition_id"].as_str().unwrap();
    let manifest = case
        .join("manifests")
        .join(format!("manifest-{acquisition}.json"));
    assert!(manifest.is_file(), "{manifest:?}");
    (case, manifest)
}

fn sign(manifest: &Path, key_path: &Path) -> SignatureEnvelope {
    generate_key_file(key_path, PASS).expect("key");
    let key = load_key_file(key_path, PASS).expect("unlock");
    let bytes = std::fs::read(manifest).expect("manifest");
    let envelope = SignatureEnvelope::sign(&bytes, &key);
    envelope
        .write_atomic(&sidecar_path(manifest))
        .expect("sidecar");
    envelope
}

fn verify(case: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["verify", "--case", case.to_str().unwrap()];
    args.extend_from_slice(extra);
    run(&args)
}

#[test]
fn verify_reports_valid_signature_and_untrusted_key() {
    let dir = tempfile::tempdir().unwrap();
    let (case, manifest) = setup(dir.path());
    let envelope = sign(&manifest, &dir.path().join("key.pem"));

    let output = verify(&case, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["verified"], true);
    assert_eq!(report["signed"], true);
    assert_eq!(report["signature"], "valid");
    assert_eq!(report["key_trust"], "untrusted");
    assert_eq!(report["key_fingerprint"], envelope.key_fingerprint);
    assert_eq!(report["public_key"], envelope.public_key);
    assert_eq!(report["capture_complete"], true);
    assert!(
        report["explanation"]
            .as_str()
            .unwrap()
            .contains("not that the key is yours"),
        "{report}"
    );
}

#[test]
fn verify_promotes_a_key_listed_in_the_trust_file() {
    let dir = tempfile::tempdir().unwrap();
    let (case, manifest) = setup(dir.path());
    let envelope = sign(&manifest, &dir.path().join("key.pem"));
    let trust = dir.path().join("trusted.txt");
    std::fs::write(&trust, format!("{}\n", envelope.key_fingerprint)).unwrap();

    let output = verify(&case, &["--trust", trust.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["key_trust"], "trusted");
    assert!(
        report["explanation"]
            .as_str()
            .unwrap()
            .contains("trusted-key list")
    );
}

#[test]
fn a_whitespace_change_fails_with_exit_4_and_names_the_signature() {
    let dir = tempfile::tempdir().unwrap();
    let (case, manifest) = setup(dir.path());
    sign(&manifest, &dir.path().join("key.pem"));

    let text = std::fs::read_to_string(&manifest).unwrap();
    std::fs::write(&manifest, text.replacen("{\n", "{\n\n", 1)).unwrap();

    let output = verify(&case, &[]);
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["verified"], false);
    assert_eq!(report["signature"], "invalid");
    let stderr = String::from_utf8(output.stderr).unwrap();
    let error: serde_json::Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(error["error"], "integrity_mismatch", "{error}");
}

#[test]
fn an_explicitly_named_missing_sidecar_is_an_error_not_absent() {
    let dir = tempfile::tempdir().unwrap();
    let (case, _) = setup(dir.path());
    let missing = dir.path().join("missing.sig.json");
    let output = verify(&case, &["--signature", missing.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("does not exist"), "{stderr}");
}

#[test]
fn passphrase_prompts_refuse_a_pipe() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key.pem");
    let output = run(&["key", "generate", "--out", key.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!key.exists(), "no key without a terminal passphrase");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("need a terminal"), "{stderr}");

    let (_, manifest) = setup(dir.path());
    let output = run(&[
        "sign",
        "--manifest",
        manifest.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!sidecar_path(&manifest).exists());
}

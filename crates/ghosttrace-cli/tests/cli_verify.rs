//! P3.2 verification contract: a stored manifest verifies by re-hashing the
//! case store, and every dishonest or broken variant fails closed with exit 4.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ghosttrace")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().expect("cli runs")
}

fn create_case(dir: &Path) -> PathBuf {
    let case = dir.join("case.ghosttrace-case");
    let output = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        "verify",
    ]);
    assert!(output.status.success(), "{output:?}");
    case
}

fn scan(case: &Path, source: &Path, extra: &[&str]) -> (String, serde_json::Value) {
    let mut args = vec![
        "scan",
        "--case",
        case.to_str().unwrap(),
        "--source",
        source.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let output = run(&args);
    // A recorded gap is a successful, honest capture: exit 3, never 0.
    assert!(
        matches!(output.status.code(), Some(0) | Some(3)),
        "{output:?}"
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    (
        parsed["acquisition_id"].as_str().unwrap().to_string(),
        parsed,
    )
}

/// Create a case with one captured file and return it with the manifest path.
fn setup(dir: &Path) -> (PathBuf, PathBuf) {
    let evidence = dir.join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("a.txt"), b"alpha\n").unwrap();
    let case = create_case(dir);
    let (acquisition, _) = scan(&case, &evidence, &[]);
    let manifest = case
        .join("manifests")
        .join(format!("manifest-{acquisition}.json"));
    assert!(manifest.is_file(), "{manifest:?}");
    (case, manifest)
}

fn verify(case: &Path) -> Output {
    run(&["verify", "--case", case.to_str().unwrap()])
}

fn verify_text(case: &Path) -> serde_json::Value {
    let output = verify(case);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_verify_failure(case: &Path, expected_code: &str) {
    let output = verify(case);
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(parsed["error"], expected_code, "{parsed}");
}

fn object_files(case: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for bucket in std::fs::read_dir(case.join("objects/sha256"))
        .unwrap()
        .flatten()
    {
        for file in std::fs::read_dir(bucket.path()).unwrap().flatten() {
            files.push(file.path());
        }
    }
    files
}

fn read_manifest(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn write_manifest(path: &Path, value: &serde_json::Value) {
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

#[test]
fn verify_accepts_an_untouched_acquisition() {
    let dir = tempfile::tempdir().unwrap();
    let (case, _) = setup(dir.path());
    let report = verify_text(&case);
    assert_eq!(report["verified"], true);
    assert_eq!(report["objects_verified"], 1);
    assert_eq!(report["total_bytes"], 6);
    assert_eq!(report["signed"], false);
    assert_eq!(report["captured"], 1);
    assert_eq!(report["gaps"], 0);
}

#[test]
fn verify_reports_recorded_coverage_gaps() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("big.bin"), b"larger than the cap").unwrap();
    let case = create_case(dir.path());
    let (_, scan) = scan(&case, &evidence, &["--max-file-bytes", "1"]);
    assert_eq!(scan["coverage"]["excluded"], 1);
    let report = verify_text(&case);
    assert_eq!(
        report["verified"], true,
        "recorded exclusions do not tamper"
    );
    assert_eq!(report["gaps"], 1);
}

#[test]
fn tampered_object_bytes_fail_verification() {
    let dir = tempfile::tempdir().unwrap();
    let (case, _) = setup(dir.path());
    let object = object_files(&case).pop().unwrap();
    let mut bytes = std::fs::read(&object).unwrap();
    bytes[0] ^= 0xff;
    std::fs::write(&object, bytes).unwrap();
    assert_verify_failure(&case, "integrity_mismatch");
}

#[test]
fn missing_object_fails_verification() {
    let dir = tempfile::tempdir().unwrap();
    let (case, _) = setup(dir.path());
    std::fs::remove_file(object_files(&case).pop().unwrap()).unwrap();
    assert_verify_failure(&case, "corrupt_evidence");
}

#[test]
fn malformed_manifest_fails_verification() {
    let dir = tempfile::tempdir().unwrap();
    let (case, manifest) = setup(dir.path());
    std::fs::write(&manifest, b"{not json").unwrap();
    assert_verify_failure(&case, "unsupported_format");
}

#[test]
fn duplicate_json_keys_fail_verification() {
    let dir = tempfile::tempdir().unwrap();
    let (case, manifest) = setup(dir.path());
    let text = std::fs::read_to_string(&manifest).unwrap();
    let duplicated = text.replacen('{', "{\n  \"format\": \"ghosttrace-manifest/1\",", 1);
    std::fs::write(&manifest, duplicated).unwrap();
    assert_verify_failure(&case, "unsupported_format");
}

#[test]
fn unsupported_manifest_version_fails_verification() {
    let dir = tempfile::tempdir().unwrap();
    let (case, manifest) = setup(dir.path());
    let mut value = read_manifest(&manifest);
    value["format"] = "ghosttrace-manifest/2".into();
    write_manifest(&manifest, &value);
    assert_verify_failure(&case, "unsupported_format");
}

#[test]
fn duplicate_object_references_fail_verification() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("a.txt"), b"alpha\n").unwrap();
    std::fs::write(evidence.join("b.txt"), b"bravo\n").unwrap();
    let case = create_case(dir.path());
    let (acquisition, _) = scan(&case, &evidence, &[]);
    let manifest = case
        .join("manifests")
        .join(format!("manifest-{acquisition}.json"));
    let mut value = read_manifest(&manifest);
    let first = value["objects"][0]["object_id"].clone();
    value["objects"][1]["object_id"] = first;
    write_manifest(&manifest, &value);
    assert_verify_failure(&case, "unsupported_format");
}

#[test]
fn store_path_traversal_fails_verification() {
    let dir = tempfile::tempdir().unwrap();
    let (case, manifest) = setup(dir.path());
    let mut value = read_manifest(&manifest);
    value["objects"][0]["store_subpath"] = "../../../etc/passwd".into();
    write_manifest(&manifest, &value);
    assert_verify_failure(&case, "unsupported_format");
}

//! P2.3 end-to-end CLI contract: scan a controlled folder, reopen the case,
//! verify stored bytes independently, and see every coverage status.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ghosttrace")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().expect("cli runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn create_case(dir: &Path) -> PathBuf {
    let case = dir.join("case.ghosttrace-case");
    let output = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        "cli scan",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    case
}

fn object_files(case: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let objects = case.join("objects/sha256");
    for bucket in std::fs::read_dir(objects).unwrap().flatten() {
        if bucket.path().is_dir() {
            for file in std::fs::read_dir(bucket.path()).unwrap().flatten() {
                files.push(file.path());
            }
        }
    }
    files
}

#[test]
fn scan_roundtrip_verifies_independent_bytes_and_status() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(evidence.join("nested")).unwrap();
    std::fs::write(evidence.join("a.txt"), b"alpha\n").unwrap();
    std::fs::write(evidence.join("nested/b.txt"), b"bravo\n").unwrap();
    std::os::unix::fs::symlink("a.txt", evidence.join("link.txt")).unwrap();
    let case = create_case(dir.path());

    let output = run(&[
        "scan",
        "--case",
        case.to_str().unwrap(),
        "--source",
        evidence.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(parsed["state"], "completed");
    assert_eq!(parsed["objects"], 2);
    assert_eq!(parsed["coverage"]["captured"], 3, "files plus link");
    assert!(parsed["manifest"].is_string());

    // Progress is stderr-only; stdout stays machine JSON.
    assert!(stderr(&output).contains("progress:"));
    assert!(!stdout(&output).contains("progress:"));

    // Independently verify: stored object bytes are the source bytes.
    let mut stored: Vec<Vec<u8>> = object_files(&case)
        .iter()
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    stored.sort();
    let mut expected = vec![
        std::fs::read(evidence.join("a.txt")).unwrap(),
        std::fs::read(evidence.join("nested/b.txt")).unwrap(),
    ];
    expected.sort();
    assert_eq!(stored, expected);

    // Reopen via status: coverage and recovery are inspectable.
    let status = run(&["status", "--case", case.to_str().unwrap()]);
    assert!(status.status.success());
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&status)).unwrap();
    assert_eq!(parsed["acquisitions"].as_array().unwrap().len(), 1);
    assert_eq!(parsed["coverage"]["captured"], 3);
    assert_eq!(parsed["recovery"]["orphan_objects"], 0);
    assert_eq!(parsed["recovery"]["abandoned_staging"], 0);
    assert!(parsed["recoverable_jobs"].as_array().unwrap().is_empty());

    // Source bytes are unchanged by capture.
    assert_eq!(std::fs::read(evidence.join("a.txt")).unwrap(), b"alpha\n");
    assert_eq!(
        std::fs::read(evidence.join("nested/b.txt")).unwrap(),
        b"bravo\n"
    );
}

#[test]
fn material_omission_exits_3_with_case_and_code() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("small.txt"), b"ok").unwrap();
    std::fs::write(evidence.join("large.bin"), b"0123456789").unwrap();
    let case = create_case(dir.path());

    let output = run(&[
        "scan",
        "--case",
        case.to_str().unwrap(),
        "--source",
        evidence.to_str().unwrap(),
        "--max-file-bytes",
        "4",
    ]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(parsed["state"], "partial");
    assert_eq!(parsed["objects"], 1);
    assert_eq!(parsed["coverage"]["excluded"], 1);
    let gaps = parsed["gaps"].as_array().unwrap();
    assert!(
        gaps.iter().any(|gap| {
            gap["code"] == "policy_excluded" && gap["path"].as_str().unwrap().contains("large.bin")
        }),
        "the omission is named with a stable code and encoded path"
    );
}

#[test]
fn material_omission_still_leaves_a_reopenable_case_with_no_orphans() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("large.bin"), vec![7u8; 8192]).unwrap();
    let case = create_case(dir.path());
    let output = run(&[
        "scan",
        "--case",
        case.to_str().unwrap(),
        "--source",
        evidence.to_str().unwrap(),
        "--max-file-bytes",
        "1024",
    ]);
    assert_eq!(output.status.code(), Some(3));
    let status = run(&["status", "--case", case.to_str().unwrap()]);
    assert!(status.status.success());
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&status)).unwrap();
    assert_eq!(parsed["acquisitions"][0]["state"], "partial");
    assert_eq!(parsed["recovery"]["orphan_objects"], 0);
    assert_eq!(parsed["acquisitions"][0]["objects"], 0);
}

#[test]
fn ctrl_c_cancels_the_scan_and_exits_3() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    // Enough hash/copy work to leave a window, and a start marker so the
    // signal is not sent before the handler exists or after the scan finished.
    let big = std::fs::File::create(evidence.join("big.bin")).unwrap();
    big.set_len(64 * 1024 * 1024).unwrap();
    drop(big);
    let case = create_case(dir.path());

    let stderr_path = dir.path().join("scan.stderr");
    let stderr_file = std::fs::File::create(&stderr_path).unwrap();
    let mut child = Command::new(bin())
        .args([
            "scan",
            "--case",
            case.to_str().unwrap(),
            "--source",
            evidence.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    loop {
        let text = std::fs::read_to_string(&stderr_path).unwrap_or_default();
        if text.contains("source method") {
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the scan never started: {text}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    kill(Pid::from_raw(child.id() as i32), Signal::SIGINT).unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = std::fs::read_to_string(&stderr_path).unwrap();

    assert_eq!(output.status.code(), Some(3), "{stderr}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(parsed["state"], "cancelled");
    assert!(
        stderr.contains("interrupt received"),
        "the cancellation is explained: {stderr}"
    );
    // Nothing half-published: no staging leftovers, no orphan objects.
    assert_eq!(std::fs::read_dir(case.join("staging")).unwrap().count(), 0);
    let status = run(&["status", "--case", case.to_str().unwrap()]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&status)).unwrap();
    assert_eq!(parsed["recovery"]["orphan_objects"], 0);
}

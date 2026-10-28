//! Minimal native prerelease packaging (plan P3.2).
//!
//! Builds a tar.gz from an already-built CLI plus licences, help text, sample
//! data, and a real build/target inventory, then writes a matching SHA-256.
//! Nothing is uploaded and no network is used.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Options {
    pub output: PathBuf,
    pub binary: Option<PathBuf>,
    pub version: String,
}

#[derive(Debug, Serialize)]
struct BuildInfo {
    package: String,
    version: String,
    target: String,
    rustc: String,
    commit: String,
    created_unix: u64,
    files: Vec<FileInfo>,
}

#[derive(Debug, Serialize)]
struct FileInfo {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    archive: String,
    checksum_file: String,
    sha256: String,
    package: String,
    files: usize,
}

pub fn run(options: &Options) -> Result<Summary, String> {
    let root = workspace_root();
    let binary = options
        .binary
        .clone()
        .unwrap_or_else(|| root.join("target/release/ghosttrace"));
    if !binary.is_file() {
        return Err(format!(
            "binary {} not found; build it first (cargo build -p ghosttrace-cli --release)",
            binary.display()
        ));
    }
    let target = command_output("rustc", &["-vV"])
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("host: ").map(str::to_string))
        })
        .unwrap_or_else(|| "unknown".to_string());
    let rustc = command_output("rustc", &["--version"]).unwrap_or_else(|| "unknown".to_string());
    let commit = command_output(
        "git",
        &["-C", root.to_str().unwrap_or("."), "rev-parse", "HEAD"],
    )
    .unwrap_or_else(|| "unknown".to_string());
    let package = format!("ghosttrace-{}-{target}", options.version);

    let archive = options.output.join(format!("{package}.tar.gz"));
    if archive.exists() {
        return Err(format!(
            "{} already exists; refusing to overwrite",
            archive.display()
        ));
    }
    fs::create_dir_all(&options.output).map_err(|error| format!("output dir: {error}"))?;
    // The archive's top-level directory is built in place, then archived.
    let staging = options.output.join(&package);
    if staging.exists() {
        return Err(format!(
            "{} already exists; remove it before packaging",
            staging.display()
        ));
    }

    let result = (|| -> Result<Summary, String> {
        fs::create_dir_all(staging.join("bin")).map_err(|e| format!("staging: {e}"))?;
        copy(&binary, &staging.join("bin/ghosttrace"))?;
        make_executable(&staging.join("bin/ghosttrace"))?;

        // Licences, docs, help, and sample data ship with every archive.
        for name in ["LICENSE-APACHE", "LICENSE-MIT", "README.md"] {
            copy(&root.join(name), &staging.join(name))?;
        }
        fs::create_dir_all(staging.join("docs")).map_err(|e| format!("staging: {e}"))?;
        for name in [
            "cli.md",
            "gui-guide.md",
            "reports.md",
            "walkthrough.md",
            "releases.md",
        ] {
            let source = root.join("docs").join(name);
            if source.is_file() {
                copy(&source, &staging.join("docs").join(name))?;
            }
        }
        let help = Command::new(&binary)
            .arg("--help")
            .output()
            .map_err(|error| format!("run binary --help: {error}"))?;
        if !help.status.success() {
            return Err("binary --help failed; the archive must describe itself".to_string());
        }
        fs::write(staging.join("help.txt"), &help.stdout).map_err(|e| format!("help: {e}"))?;

        fs::create_dir_all(staging.join("sample/notes")).map_err(|e| format!("sample: {e}"))?;
        fs::write(
            staging.join("sample/notes/readme.txt"),
            b"GhostTrace sample data. Copy this folder into a case to try the CLI.\n",
        )
        .map_err(|e| format!("sample: {e}"))?;
        fs::write(
            staging.join("sample/notes/log.txt"),
            b"2026-10-23T09:00:00Z boot\n2026-10-23T09:01:00Z login alice\n",
        )
        .map_err(|e| format!("sample: {e}"))?;

        let files = inventory(&staging)?;
        let info = BuildInfo {
            package: package.clone(),
            version: options.version.clone(),
            target: target.clone(),
            rustc: rustc.clone(),
            commit: commit.clone(),
            created_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0),
            files,
        };
        let text = serde_json::to_vec_pretty(&info).map_err(|e| format!("build info: {e}"))?;
        fs::write(staging.join("build-info.json"), text).map_err(|e| format!("build info: {e}"))?;
        let file_count = info.files.len();

        let status = Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&options.output)
            .arg(&package)
            .status()
            .map_err(|error| format!("tar: {error}"))?;
        if !status.success() {
            return Err("tar failed".to_string());
        }
        let digest = digest_file(&archive)?;
        let checksum_file = options.output.join(format!("{package}.tar.gz.sha256"));
        fs::write(&checksum_file, format!("{digest}  {package}.tar.gz\n"))
            .map_err(|error| format!("checksum: {error}"))?;

        Ok(Summary {
            archive: archive.display().to_string(),
            checksum_file: checksum_file.display().to_string(),
            sha256: digest,
            package: package.clone(),
            files: file_count,
        })
    })();

    if let Err(error) = result {
        let _ = fs::remove_dir_all(&staging);
        let _ = fs::remove_file(&archive);
        let _ = fs::remove_file(options.output.join(format!("{package}.tar.gz.sha256")));
        return Err(error);
    }
    fs::remove_dir_all(&staging).map_err(|error| format!("staging cleanup: {error}"))?;
    result
}

fn copy(source: &Path, target: &Path) -> Result<(), String> {
    fs::copy(source, target)
        .map(|_| ())
        .map_err(|error| format!("copy {}: {error}", source.display()))
}

fn make_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(path)
            .map_err(|error| format!("metadata: {error}"))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).map_err(|error| format!("chmod: {error}"))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn inventory(root: &Path) -> Result<Vec<FileInfo>, String> {
    let mut files = Vec::new();
    collect(root, root, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn collect(root: &Path, directory: &Path, files: &mut Vec<FileInfo>) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("read {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read entry: {error}"))?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|error| format!("relative path: {error}"))?;
        if path.is_dir() {
            collect(root, &path, files)?;
            continue;
        }
        files.push(FileInfo {
            path: relative.to_string_lossy().replace('\\', "/"),
            bytes: fs::metadata(&path)
                .map_err(|error| format!("metadata: {error}"))?
                .len(),
            sha256: digest_file(&path)?,
        });
    }
    Ok(())
}

fn digest_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_builds_checksummed_archive_and_smoke_runs_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = dir.path().join("fake-ghosttrace");
        fs::write(&binary, "#!/bin/sh\necho fake-ghosttrace-ok\n").expect("fake binary");
        make_executable(&binary).expect("chmod");
        let output = dir.path().join("dist");
        let summary = run(&Options {
            output: output.clone(),
            binary: Some(binary),
            version: "9.9.9-test".into(),
        })
        .expect("package");

        let archive = PathBuf::from(&summary.archive);
        assert!(archive.is_file());
        let checksum = fs::read_to_string(&summary.checksum_file).expect("checksum");
        let expected = digest_file(&archive).expect("digest");
        assert!(checksum.starts_with(&expected), "{checksum}");
        assert_eq!(summary.sha256, expected);

        let extracted = dir.path().join("extracted");
        fs::create_dir_all(&extracted).expect("extract dir");
        let status = Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&extracted)
            .status()
            .expect("tar");
        assert!(status.success());
        let package = extracted.join(&summary.package);
        let info: serde_json::Value =
            serde_json::from_slice(&fs::read(package.join("build-info.json")).expect("info"))
                .expect("info json");
        assert_eq!(info["package"], summary.package);
        assert!(!info["target"].as_str().unwrap().is_empty());
        assert!(
            info["files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|file| file["path"] == "bin/ghosttrace")
        );
        assert!(package.join("sample/notes/log.txt").is_file());
        assert!(package.join("help.txt").is_file());

        let smoke = Command::new(package.join("bin/ghosttrace"))
            .arg("--help")
            .output()
            .expect("smoke run");
        assert!(smoke.status.success());
        assert_eq!(
            String::from_utf8_lossy(&smoke.stdout),
            "fake-ghosttrace-ok\n"
        );

        // Re-packaging never overwrites the published archive.
        let again = run(&Options {
            output: output.clone(),
            binary: Some(package.join("bin/ghosttrace")),
            version: "9.9.9-test".into(),
        });
        assert!(again.is_err());
    }
}

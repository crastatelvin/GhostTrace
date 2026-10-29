//! Native release packaging (plan P3.2, extended by P6.4 and P11).
//!
//! Builds a tar.gz from an already-built CLI and desktop pair plus licences,
//! help text, shell completions, user guides, tracked samples, a CycloneDX
//! dependency inventory, platform support, and a real build/target inventory,
//! then writes a matching SHA-256. Nothing is uploaded and no network is used.

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
    /// Desktop binary; the P6.4 bundle ships the CLI/desktop pair.
    pub desktop: Option<PathBuf>,
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
    let desktop = options
        .desktop
        .clone()
        .unwrap_or_else(|| root.join("target/release/ghosttrace-desktop"));
    if !desktop.is_file() {
        return Err(format!(
            "desktop binary {} not found; build it first (cargo build -p ghosttrace-desktop --release)",
            desktop.display()
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
        copy(&desktop, &staging.join("bin/ghosttrace-desktop"))?;
        make_executable(&staging.join("bin/ghosttrace-desktop"))?;

        // Licences, docs, help, and tracked sample data ship with every archive.
        for name in [
            "LICENSE-APACHE",
            "LICENSE-MIT",
            "THIRD_PARTY_NOTICES.md",
            "README.md",
        ] {
            copy(&root.join(name), &staging.join(name))?;
        }
        fs::create_dir_all(staging.join("docs")).map_err(|e| format!("staging: {e}"))?;
        for name in [
            "architecture.md",
            "cli.md",
            "evidence-model.md",
            "formats.md",
            "gui-guide.md",
            "installation.md",
            "limitations.md",
            "performance.md",
            "quickstart.md",
            "reports.md",
            "storage.md",
            "testing.md",
            "threat-model.md",
            "timestamps.md",
            "troubleshooting.md",
            "walkthrough.md",
            "worker-protocol.md",
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

        // Completion scripts are generated by the packaged CLI itself, so the
        // archive cannot describe a different command surface than its binary.
        fs::create_dir_all(staging.join("completions")).map_err(|e| format!("completions: {e}"))?;
        for (shell, name) in [
            ("bash", "ghosttrace.bash"),
            ("zsh", "_ghosttrace"),
            ("fish", "ghosttrace.fish"),
            ("powershell", "_ghosttrace.ps1"),
            ("elvish", "ghosttrace.elv"),
        ] {
            let output = Command::new(&binary)
                .args(["completions", shell])
                .output()
                .map_err(|error| format!("run completions {shell}: {error}"))?;
            if !output.status.success() {
                return Err(format!("binary completions {shell} failed"));
            }
            fs::write(staging.join("completions").join(name), &output.stdout)
                .map_err(|error| format!("completion {name}: {error}"))?;
        }

        // The desktop must identify its build without a display server, so the
        // extracted bundle can be smoke-run on a headless host.
        let desktop_version = Command::new(&desktop)
            .arg("--version")
            .output()
            .map_err(|error| format!("run desktop --version: {error}"))?;
        if !desktop_version.status.success()
            || !String::from_utf8_lossy(&desktop_version.stdout).contains(&options.version)
        {
            return Err(
                "desktop --version failed or reported another version; refusing to package"
                    .to_string(),
            );
        }

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
        if root.join("samples").is_dir() {
            copy_tree(&root.join("samples"), &staging.join("samples"))?;
        }
        let notes = root
            .join("docs/releases")
            .join(format!("{}.md", options.version));
        if notes.is_file() {
            copy(&notes, &staging.join("RELEASE-NOTES.md"))?;
        }
        write_sbom(&root, &staging, &options.version)?;

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

fn copy_tree(source: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|error| format!("create {}: {error}", target.display()))?;
    let entries =
        fs::read_dir(source).map_err(|error| format!("read {}: {error}", source.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read entry: {error}"))?;
        let path = entry.path();
        let destination = target.join(entry.file_name());
        if path.is_dir() {
            copy_tree(&path, &destination)?;
        } else {
            copy(&path, &destination)?;
        }
    }
    Ok(())
}

/// Write a minimal CycloneDX 1.5 inventory from Cargo's own resolved metadata.
/// No network is used and no hand-maintained dependency list can drift.
fn write_sbom(root: &Path, staging: &Path, version: &str) -> Result<(), String> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err("cargo metadata failed; refusing to write a partial SBOM".to_string());
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cargo metadata json: {error}"))?;
    let mut components = Vec::new();
    if let Some(packages) = metadata["packages"].as_array() {
        for package in packages {
            let (Some(name), Some(package_version)) =
                (package["name"].as_str(), package["version"].as_str())
            else {
                continue;
            };
            let mut component = serde_json::json!({
                "type": "library",
                "name": name,
                "version": package_version,
                "purl": format!("pkg:cargo/{name}@{package_version}"),
            });
            if let Some(license) = package["license"].as_str() {
                component["licenses"] = serde_json::json!([{ "license": { "name": license } }]);
            }
            if let Some(checksum) = package["checksum"].as_str() {
                component["hashes"] =
                    serde_json::json!([{ "alg": "SHA-256", "content": checksum }]);
            }
            components.push(component);
        }
    }
    let bom = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "ghosttrace",
                "version": version,
            }
        },
        "components": components,
    });
    fs::write(
        staging.join("sbom.cdx.json"),
        serde_json::to_vec_pretty(&bom).map_err(|error| format!("sbom json: {error}"))?,
    )
    .map_err(|error| format!("sbom: {error}"))
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
        let desktop = dir.path().join("fake-ghosttrace-desktop");
        fs::write(&desktop, "#!/bin/sh\necho ghosttrace-desktop 9.9.9-test\n")
            .expect("fake desktop");
        make_executable(&desktop).expect("chmod");
        let output = dir.path().join("dist");
        let summary = run(&Options {
            output: output.clone(),
            binary: Some(binary),
            desktop: Some(desktop),
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
        assert!(
            info["files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|file| file["path"] == "bin/ghosttrace-desktop"),
            "the bundle carries the CLI/desktop pair"
        );
        assert!(package.join("sample/notes/log.txt").is_file());
        assert!(package.join("samples/README.md").is_file());
        assert!(package.join("sbom.cdx.json").is_file());
        assert!(package.join("completions/ghosttrace.bash").is_file());
        assert!(package.join("help.txt").is_file());
        assert!(package.join("THIRD_PARTY_NOTICES.md").is_file());
        assert!(package.join("docs/gui-guide.md").is_file());
        assert!(package.join("docs/installation.md").is_file());

        let smoke = Command::new(package.join("bin/ghosttrace"))
            .arg("--help")
            .output()
            .expect("smoke run");
        assert!(smoke.status.success());
        assert_eq!(
            String::from_utf8_lossy(&smoke.stdout),
            "fake-ghosttrace-ok\n"
        );
        let desktop_smoke = Command::new(package.join("bin/ghosttrace-desktop"))
            .arg("--version")
            .output()
            .expect("desktop smoke run");
        assert!(desktop_smoke.status.success());
        assert!(
            String::from_utf8_lossy(&desktop_smoke.stdout).contains("9.9.9-test"),
            "the extracted desktop identifies its build"
        );

        // Re-packaging never overwrites the published archive.
        let again = run(&Options {
            output: output.clone(),
            binary: Some(package.join("bin/ghosttrace")),
            desktop: Some(package.join("bin/ghosttrace-desktop")),
            version: "9.9.9-test".into(),
        });
        assert!(again.is_err());
    }
}

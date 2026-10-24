//! Deterministic fixture catalog verification (plan P0.2).
//!
//! `tests/fixtures/catalog.toml` is the authoritative inventory of the small,
//! legally redistributable fixtures tracked in Git. Verification must fail on:
//! unknown license, missing expected digest, digest mismatch, path escape,
//! or a private-key-looking file anywhere under the tracked fixture tree.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

/// Licenses allowed for tracked fixtures. Anything else is rejected wholesale
/// rather than silently accepted.
const ALLOWED_LICENSES: &[&str] = &["Apache-2.0", "MIT", "Apache-2.0 OR MIT"];

/// File suffixes that must never appear in tracked fixtures (private material).
const PRIVATE_KEY_SUFFIXES: &[&str] = &[".pem", ".key", ".p12", ".pfx"];

/// PEM markers of private key material, scanned for in every tracked file.
const PRIVATE_KEY_MARKERS: &[&str] = &[
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
];

#[derive(Debug, Deserialize)]
pub struct Catalog {
    #[serde(default)]
    pub fixture: Vec<FixtureEntry>,
}

#[derive(Debug, Deserialize)]
pub struct FixtureEntry {
    pub name: String,
    pub path: String,
    pub license: String,
    pub sha256: String,
}

pub fn verify(fixtures_root: &Path) -> Result<(), String> {
    let catalog_path = fixtures_root.join("catalog.toml");
    let catalog_text = std::fs::read_to_string(&catalog_path)
        .map_err(|e| format!("cannot read {}: {e}", catalog_path.display()))?;
    let catalog: Catalog =
        toml::from_str(&catalog_text).map_err(|e| format!("invalid catalog.toml: {e}"))?;

    let mut problems = Vec::new();

    for entry in &catalog.fixture {
        let rel = Path::new(&entry.path);
        if rel.is_absolute() || rel.components().any(|c| c.as_os_str() == "..") {
            problems.push(format!(
                "{}: path escapes fixture root: {}",
                entry.name, entry.path
            ));
            continue;
        }
        let full = fixtures_root.join(rel);
        let bytes = match std::fs::read(&full) {
            Ok(bytes) => bytes,
            Err(e) => {
                problems.push(format!(
                    "{}: cannot read {}: {e}",
                    entry.name,
                    full.display()
                ));
                continue;
            }
        };
        let actual = sha256_hex(&bytes);
        if !actual.eq_ignore_ascii_case(entry.sha256.trim()) {
            problems.push(format!(
                "{}: sha256 mismatch (expected {}, actual {actual})",
                entry.name, entry.sha256
            ));
        }
        if !ALLOWED_LICENSES.contains(&entry.license.as_str()) {
            problems.push(format!(
                "{}: unknown license {:?}; allowed: {}",
                entry.name,
                entry.license,
                ALLOWED_LICENSES.join(", ")
            ));
        }
    }

    problems.extend(scan_tracked_fixture_files(fixtures_root));

    if problems.is_empty() {
        println!(
            "fixtures: catalog verified ({} entries)",
            catalog.fixture.len()
        );
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

/// Walk every Git-tracked file under the fixture root and reject private-key
/// material by suffix or PEM marker.
fn scan_tracked_fixture_files(fixtures_root: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let Ok(output) = Command::new("git")
        .args(["ls-files", "-z"])
        .arg(fixtures_root)
        .output()
    else {
        return problems; // no git (e.g. source tarball); catalog checks still ran
    };
    if !output.status.success() {
        return problems;
    }
    for raw in output.stdout.split(|b| *b == 0) {
        if raw.is_empty() {
            continue;
        }
        let path = String::from_utf8_lossy(raw).to_string();
        let file_path = PathBuf::from(&path);
        if PRIVATE_KEY_SUFFIXES.iter().any(|s| {
            file_path
                .extension()
                .is_some_and(|e| s.trim_start_matches('.').eq(e))
        }) {
            problems.push(format!("tracked fixture has private-key suffix: {path}"));
            continue;
        }
        if let Ok(bytes) = std::fs::read(&file_path) {
            let text = String::from_utf8_lossy(&bytes);
            if PRIVATE_KEY_MARKERS.iter().any(|m| text.contains(m)) {
                problems.push(format!(
                    "tracked fixture contains private-key material: {path}"
                ));
            }
        }
    }
    problems
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn valid_catalog_passes() {
        let dir =
            std::env::temp_dir().join(format!("ghosttrace-fixtures-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let data = b"0123456789abcdef\n";
        write(&dir.join("hello.txt"), data);
        let digest = sha256_hex(data);
        write(
            &dir.join("catalog.toml"),
            format!(
                "[[fixture]]\nname = \"hello\"\npath = \"hello.txt\"\nlicense = \"Apache-2.0 OR MIT\"\nsha256 = \"{digest}\"\n"
            )
            .as_bytes(),
        );
        verify(&dir).expect("valid catalog must verify");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn digest_mismatch_fails() {
        let dir =
            std::env::temp_dir().join(format!("ghosttrace-fixtures-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write(&dir.join("hello.txt"), b"real contents\n");
        write(
            &dir.join("catalog.toml"),
            b"[[fixture]]\nname = \"hello\"\npath = \"hello.txt\"\nlicense = \"MIT\"\nsha256 = \"deadbeef\"\n",
        );
        let problem = verify(&dir).expect_err("mismatched digest must fail");
        assert!(problem.contains("sha256 mismatch"), "got: {problem}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_license_fails() {
        let dir =
            std::env::temp_dir().join(format!("ghosttrace-fixtures-lic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let data = b"contents\n";
        write(&dir.join("hello.txt"), data);
        let digest = sha256_hex(data);
        write(
            &dir.join("catalog.toml"),
            format!(
                "[[fixture]]\nname = \"hello\"\npath = \"hello.txt\"\nlicense = \"Proprietary-1.0\"\nsha256 = \"{digest}\"\n"
            )
            .as_bytes(),
        );
        let problem = verify(&dir).expect_err("unknown license must fail");
        assert!(problem.contains("unknown license"), "got: {problem}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn escaping_path_fails() {
        let dir =
            std::env::temp_dir().join(format!("ghosttrace-fixtures-esc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write(
            &dir.join("catalog.toml"),
            b"[[fixture]]\nname = \"escape\"\npath = \"../../secret.pem\"\nlicense = \"MIT\"\nsha256 = \"aa\"\n",
        );
        let problem = verify(&dir).expect_err("escaping path must fail");
        assert!(problem.contains("escapes fixture root"), "got: {problem}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

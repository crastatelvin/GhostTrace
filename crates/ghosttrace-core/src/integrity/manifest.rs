//! Acquisition manifest v1 (plan Sections 5, 8; P2.2, P9.2).
//!
//! The manifest records *what this acquisition claims*: method, tool version,
//! roots, coverage counts, and every published object with its exact byte
//! length and SHA-256. It is deliberately unsigned here; signing lands with
//! the integrity phase (P9). Formatting is stable (sorted keys as written,
//! two-space JSON, trailing newline) so diffs are reviewable.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::integrity::hash::{StreamDigest, digest_file, sha256_hex};

/// Format identity and version. Changing the shape requires a new version.
pub const MANIFEST_FORMAT: &str = "ghosttrace-manifest/1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestV1 {
    pub format: String,
    pub manifest_id: String,
    pub case_id: String,
    pub acquisition_id: String,
    /// `protected_copy` or `live_best_effort`.
    pub method: String,
    pub tool_version: String,
    /// RFC 3339 UTC instant, seconds precision.
    pub created_utc: String,
    pub link_policy: String,
    pub roots: Vec<ManifestRoot>,
    pub coverage: ManifestCoverage,
    pub objects: Vec<ManifestObject>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestRoot {
    pub label: String,
    /// Root-relative native paths below are anchored to this root.
    pub native_path_encoded: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestCoverage {
    pub captured: u64,
    pub excluded: u64,
    pub inaccessible: u64,
    pub unstable: u64,
    pub vanished: u64,
    pub unsupported: u64,
    pub unobserved: u64,
    pub hardlink_aliases: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestObject {
    pub object_id: String,
    pub root_label: String,
    /// Native relative path, encoded losslessly (`NativePath::encoded`).
    pub native_path_encoded: String,
    pub byte_length: u64,
    pub sha256: String,
    /// Case-relative store path, e.g. `objects/sha256/ab/<digest>`.
    pub store_subpath: String,
    pub hardlink_alias: bool,
}

impl ManifestV1 {
    /// Stable serialization: pretty JSON plus one trailing newline.
    pub fn to_json(&self) -> CoreResult<String> {
        let mut text = serde_json::to_string_pretty(self)
            .map_err(|error| CoreError::Internal(format!("manifest serialize: {error}")))?;
        text.push('\n');
        Ok(text)
    }

    /// Write atomically inside `directory`: private temp, sync, rename, then
    /// sync the directory. A reader never sees a half-written manifest.
    pub fn write_atomic(&self, directory: &Path) -> CoreResult<PathBuf> {
        std::fs::create_dir_all(directory)
            .map_err(|error| CoreError::Storage(format!("manifest dir: {error}")))?;
        let staging = directory.join(format!("{}.json.part", self.manifest_id));
        let final_path = directory.join(format!("{}.json", self.manifest_id));
        let text = self.to_json()?;
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&staging)
                .map_err(|error| CoreError::Storage(format!("manifest create: {error}")))?;
            file.write_all(text.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|error| {
                    let _ = std::fs::remove_file(&staging);
                    CoreError::Storage(format!("manifest write: {error}"))
                })?;
        }
        std::fs::rename(&staging, &final_path).map_err(|error| {
            let _ = std::fs::remove_file(&staging);
            CoreError::Storage(format!("manifest publish: {error}"))
        })?;
        sync_directory(directory)?;
        Ok(final_path)
    }

    /// Re-hash every stored copy and compare with this manifest. Verifies the
    /// *stored* bytes, never a later read of the source.
    pub fn verify_objects(&self, case_root: &Path) -> CoreResult<()> {
        for object in &self.objects {
            let path = case_root.join(&object.store_subpath);
            let actual = digest_file(&path)?;
            let expected = StreamDigest {
                byte_length: object.byte_length,
                sha256: parse_hex(&object.sha256)?,
            };
            if actual != expected {
                return Err(CoreError::IntegrityMismatch);
            }
        }
        Ok(())
    }
}

fn parse_hex(text: &str) -> CoreResult<[u8; 32]> {
    if text.len() != 64 {
        return Err(CoreError::CorruptEvidence);
    }
    let mut digest = [0u8; 32];
    let bytes = text.as_bytes();
    for index in 0..32 {
        let pair = std::str::from_utf8(&bytes[index * 2..index * 2 + 2])
            .map_err(|_| CoreError::CorruptEvidence)?;
        digest[index] = u8::from_str_radix(pair, 16).map_err(|_| CoreError::CorruptEvidence)?;
    }
    Ok(digest)
}

fn sync_directory(path: &Path) -> CoreResult<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(path)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| CoreError::Storage(format!("sync dir: {error}")))?;
    }
    Ok(())
}

/// Build a manifest object from a published copy.
pub fn manifest_object(
    object_id: String,
    root_label: String,
    native_path_encoded: String,
    digest: StreamDigest,
    store_subpath: String,
    hardlink_alias: bool,
) -> ManifestObject {
    ManifestObject {
        object_id,
        root_label,
        native_path_encoded,
        byte_length: digest.byte_length,
        sha256: sha256_hex(&digest.sha256),
        store_subpath,
        hardlink_alias,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ManifestV1 {
        ManifestV1 {
            format: MANIFEST_FORMAT.into(),
            manifest_id: "manifest-1".into(),
            case_id: "case-1".into(),
            acquisition_id: "acq-1".into(),
            method: "protected_copy".into(),
            tool_version: "0.1.0".into(),
            created_utc: "2026-10-27T10:00:00Z".into(),
            link_policy: "no_follow".into(),
            roots: vec![ManifestRoot {
                label: "evidence".into(),
                native_path_encoded: "/evidence".into(),
            }],
            coverage: ManifestCoverage {
                captured: 1,
                ..ManifestCoverage::default()
            },
            objects: Vec::new(),
        }
    }

    #[test]
    fn json_round_trips_and_ends_with_newline() {
        let text = manifest().to_json().unwrap();
        assert!(text.ends_with("}\n"));
        let parsed: ManifestV1 = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, manifest());
    }
}

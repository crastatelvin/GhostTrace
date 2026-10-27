//! Acquisition manifest v1 (plan Sections 5, 8; P2.2, P9.2).
//!
//! The manifest records *what this acquisition claims*: method, tool version,
//! roots, coverage counts, and every published object with its exact byte
//! length and SHA-256. It is deliberately unsigned here; signing lands with
//! the integrity phase (P9). Formatting is stable (sorted keys as written,
//! two-space JSON, trailing newline) so diffs are reviewable.

use std::path::{Path, PathBuf};

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

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
            if !path.exists() {
                return Err(CoreError::CorruptEvidence);
            }
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

/// Result of verifying one manifest file against the case store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestVerification {
    pub manifest_id: String,
    pub acquisition_id: String,
    pub format: String,
    pub objects_verified: usize,
    pub total_bytes: u64,
    pub captured: u64,
    pub gaps: u64,
}

/// Any JSON value, parsed only to reject duplicate object keys. Numbers are
/// not interpreted here; the real parse follows serde_json's normal rules.
#[derive(Debug)]
#[allow(dead_code)] // payloads are carried only to keep the visitor generic
enum AnyValue {
    Null,
    Bool,
    Number,
    String,
    Array(Vec<AnyValue>),
    Object(Vec<(String, AnyValue)>),
}

impl<'de> Deserialize<'de> for AnyValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = AnyValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("any JSON value")
            }

            fn visit_unit<E: de::Error>(self) -> Result<AnyValue, E> {
                Ok(AnyValue::Null)
            }

            fn visit_none<E: de::Error>(self) -> Result<AnyValue, E> {
                Ok(AnyValue::Null)
            }

            fn visit_some<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<AnyValue, D::Error> {
                AnyValue::deserialize(deserializer)
            }

            fn visit_bool<E: de::Error>(self, _value: bool) -> Result<AnyValue, E> {
                Ok(AnyValue::Bool)
            }

            fn visit_i64<E: de::Error>(self, _value: i64) -> Result<AnyValue, E> {
                Ok(AnyValue::Number)
            }

            fn visit_u64<E: de::Error>(self, _value: u64) -> Result<AnyValue, E> {
                Ok(AnyValue::Number)
            }

            fn visit_f64<E: de::Error>(self, _value: f64) -> Result<AnyValue, E> {
                Ok(AnyValue::Number)
            }

            fn visit_str<E: de::Error>(self, _value: &str) -> Result<AnyValue, E> {
                Ok(AnyValue::String)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<AnyValue, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(AnyValue::Array(values))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<AnyValue, A::Error> {
                let mut seen = std::collections::HashSet::new();
                let mut values = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom(format!("duplicate object key: {key}")));
                    }
                    values.push((key, map.next_value()?));
                }
                Ok(AnyValue::Object(values))
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}

impl ManifestV1 {
    /// Parse and verify a manifest file: duplicate keys, format version,
    /// object references, and the stored bytes themselves.
    pub fn verify_file(path: &Path, case_root: &Path) -> CoreResult<ManifestVerification> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| CoreError::Storage(format!("manifest read: {error}")))?;
        reject_duplicate_keys(&text)?;

        let header: serde_json::Value = serde_json::from_str(&text)
            .map_err(|error| CoreError::Unsupported(format!("manifest json: {error}")))?;
        match header.get("format").and_then(|value| value.as_str()) {
            Some(MANIFEST_FORMAT) => {}
            Some(other) => {
                return Err(CoreError::Unsupported(format!(
                    "manifest format {other} is not supported"
                )));
            }
            None => {
                return Err(CoreError::Unsupported(
                    "manifest has no format field".into(),
                ));
            }
        }
        let manifest: ManifestV1 = serde_json::from_value(header)
            .map_err(|error| CoreError::Unsupported(format!("manifest shape: {error}")))?;
        manifest.validate_references()?;
        manifest.verify_objects(case_root)?;

        Ok(ManifestVerification {
            manifest_id: manifest.manifest_id,
            acquisition_id: manifest.acquisition_id,
            format: manifest.format,
            objects_verified: manifest.objects.len(),
            total_bytes: manifest
                .objects
                .iter()
                .map(|object| object.byte_length)
                .sum(),
            captured: manifest.coverage.captured,
            gaps: manifest.coverage.excluded
                + manifest.coverage.inaccessible
                + manifest.coverage.unstable
                + manifest.coverage.vanished
                + manifest.coverage.unsupported
                + manifest.coverage.unobserved,
        })
    }

    /// Reject duplicate object identities and store paths that could escape
    /// the case's content-addressed store.
    pub fn validate_references(&self) -> CoreResult<()> {
        let mut ids = std::collections::HashSet::new();
        let mut subpaths = std::collections::HashSet::new();
        for object in &self.objects {
            if !ids.insert(object.object_id.as_str()) {
                return Err(CoreError::Unsupported(format!(
                    "duplicate object id {}",
                    object.object_id
                )));
            }
            if !subpaths.insert(object.store_subpath.as_str()) {
                return Err(CoreError::Unsupported(format!(
                    "duplicate object path {}",
                    object.store_subpath
                )));
            }
            if !safe_store_subpath(&object.store_subpath) {
                return Err(CoreError::Unsupported(format!(
                    "unsafe object path {}",
                    object.store_subpath
                )));
            }
        }
        Ok(())
    }
}

/// Only `objects/sha256/<bucket>/<hex>` with normal components may be read.
fn safe_store_subpath(subpath: &str) -> bool {
    let components: Vec<&str> = subpath.split('/').collect();
    components.len() == 4
        && components[0] == "objects"
        && components[1] == "sha256"
        && components[2].len() == 2
        && !components[2].is_empty()
        && components[3].len() == 64
        && components
            .iter()
            .all(|component| *component != "." && *component != ".." && !component.is_empty())
}

/// Reject duplicate object keys anywhere in the document. serde_json keeps
/// the last duplicate silently, which is exactly what an integrity check must
/// not do.
pub fn reject_duplicate_keys(text: &str) -> CoreResult<()> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    AnyValue::deserialize(&mut deserializer)
        .map_err(|error| CoreError::Unsupported(format!("manifest json: {error}")))?;
    deserializer
        .end()
        .map_err(|error| CoreError::Unsupported(format!("manifest json: {error}")))
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

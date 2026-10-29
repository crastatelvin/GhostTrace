//! Content inventories shared by portable packages and case backups (plan
//! Section 12; P9.2).
//!
//! An inventory is only trustworthy if it is checked strictly: relative paths
//! that cannot escape the directory, no duplicates, no symlinks, exact byte
//! lengths, and SHA-256 over the exact bytes. A file that exists but is not
//! listed is a rejection, not a harmless extra.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::integrity::hash::sha256_hex;

/// One file in a package or backup inventory. `path` is always relative and
/// uses `/` separators so an inventory is portable across platforms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryFile {
    pub path: String,
    pub role: String,
    pub sha256: String,
    pub byte_length: u64,
}

impl InventoryFile {
    pub fn of(root: &Path, relative: &str, role: &str) -> CoreResult<Self> {
        let path = root.join(relative);
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| CoreError::Storage(format!("inventory file {relative}: {error}")))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(CoreError::Permission(format!(
                "inventory path {relative} is not a regular file"
            )));
        }
        let digest = crate::integrity::hash::digest_file(&path)?;
        Ok(Self {
            path: relative.to_string(),
            role: role.to_string(),
            sha256: digest.hex(),
            byte_length: digest.byte_length,
        })
    }
}

/// Reject absolute paths, `..`, backslashes, empty components, and control
/// characters. The inventory never names anything outside its own directory.
pub fn check_relative_path(path: &str) -> CoreResult<()> {
    if path.is_empty() || path.len() > 1024 {
        return Err(CoreError::Unsupported(
            "inventory path is empty or too long".into(),
        ));
    }
    if path.contains('\\') || path.chars().any(|ch| ch.is_control()) {
        return Err(CoreError::Unsupported(format!(
            "inventory path {path:?} contains a backslash or control character"
        )));
    }
    if path.starts_with('/') {
        return Err(CoreError::Unsupported(format!(
            "inventory path {path:?} is absolute"
        )));
    }
    for component in Path::new(path).components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(CoreError::Unsupported(format!(
                    "inventory path {path:?} escapes its directory"
                )));
            }
        }
    }
    Ok(())
}

/// Verify every listed file: unique safe paths, regular files, exact length
/// and SHA-256.
pub fn verify_files(root: &Path, files: &[InventoryFile]) -> CoreResult<u64> {
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for file in files {
        check_relative_path(&file.path)?;
        if !seen.insert(file.path.as_str()) {
            return Err(CoreError::Unsupported(format!(
                "inventory lists {} twice",
                file.path
            )));
        }
        if file.sha256.len() != 64 || !file.sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(CoreError::Unsupported(format!(
                "inventory digest for {} is malformed",
                file.path
            )));
        }
        let path = root.join(&file.path);
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| CoreError::CorruptEvidence)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(CoreError::CorruptEvidence);
        }
        if metadata.len() != file.byte_length {
            return Err(CoreError::CorruptEvidence);
        }
        let digest = crate::integrity::hash::digest_file(&path)?;
        if !digest.hex().eq_ignore_ascii_case(&file.sha256) {
            return Err(CoreError::CorruptEvidence);
        }
        total += file.byte_length;
    }
    Ok(total)
}

/// Reject any regular file under `root` that is neither listed nor explicitly
/// allowed (the inventory itself and its detached signature).
pub fn ensure_no_unlisted(
    root: &Path,
    files: &[InventoryFile],
    allowed: &[&str],
) -> CoreResult<()> {
    let mut listed: BTreeSet<String> = files.iter().map(|file| file.path.clone()).collect();
    for path in allowed {
        listed.insert((*path).to_string());
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory)
            .map_err(|error| CoreError::Storage(format!("inventory walk: {error}")))?
        {
            let entry =
                entry.map_err(|error| CoreError::Storage(format!("inventory walk: {error}")))?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| CoreError::Storage(format!("inventory stat: {error}")))?;
            if metadata.file_type().is_symlink() {
                return Err(CoreError::Unsupported(format!(
                    "unexpected symlink {}",
                    path.display()
                )));
            }
            if metadata.is_dir() {
                stack.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| CoreError::Storage("inventory walk escaped root".into()))?;
            let relative = relative
                .components()
                .filter_map(|component| match component {
                    Component::Normal(name) => name.to_str(),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("/");
            if !listed.contains(&relative) {
                return Err(CoreError::Unsupported(format!(
                    "unlisted file {relative} in the inventory directory"
                )));
            }
        }
    }
    Ok(())
}

/// Lowercase hex digest of a byte slice (inventory helpers keep the exact-byte
/// rule in one place).
pub fn digest_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    sha256_hex(&hasher.finalize().into())
}

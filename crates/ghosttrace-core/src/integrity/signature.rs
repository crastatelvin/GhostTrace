//! Detached Ed25519 signatures over exact manifest bytes (plan Section 12;
//! P9.1).
//!
//! The signed message is the ASCII domain `GhostTrace manifest v1`, one NUL
//! byte, then the 32-byte SHA-256 digest of the complete manifest file. The
//! verifier hashes the bytes it actually holds and then strictly decodes the
//! manifest, so a whitespace or ordering change invalidates the old signature.
//!
//! A valid signature is a mathematical statement about a key, not about
//! custody: trust is a separate, explicit fingerprint list maintained outside
//! the case.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};
use crate::integrity::hash::sha256_hex;
use crate::integrity::keys::{UnlockedKey, fingerprint, hex, unhex};
use crate::integrity::manifest::{ManifestV1, ManifestVerification, reject_duplicate_keys};

/// Format identity of the detached sidecar. Changing it requires a new version.
pub const SIGNATURE_FORMAT: &str = "ghosttrace-signature/1";
/// The only accepted algorithm in this build.
pub const SIGNATURE_ALGORITHM: &str = "ed25519";
/// Domain separation for the signed message.
pub const SIGNED_DOMAIN: &[u8] = b"GhostTrace manifest v1";
/// Suffix appended to the manifest file name for the detached sidecar.
pub const SIGNATURE_SUFFIX: &str = ".sig.json";

const MAX_SIGNATURE_FILE_BYTES: u64 = 64 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

/// The exact byte sequence an Ed25519 signature covers.
pub fn signing_message(manifest_digest: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNED_DOMAIN.len() + 1 + 32);
    message.extend_from_slice(SIGNED_DOMAIN);
    message.push(0);
    message.extend_from_slice(manifest_digest);
    message
}

/// SHA-256 over the exact manifest bytes.
pub fn manifest_digest(manifest_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(manifest_bytes);
    hasher.finalize().into()
}

/// `manifest-….json` becomes `manifest-….json.sig.json`.
pub fn sidecar_path(manifest: &Path) -> PathBuf {
    let mut name = manifest
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    name.push(SIGNATURE_SUFFIX);
    manifest.with_file_name(name)
}

/// Detached signature sidecar. Carries everything a verifier needs; the
/// manifest bytes are never embedded or rewritten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub format: String,
    pub algorithm: String,
    /// Lowercase hex SHA-256 of the manifest bytes that were signed.
    pub manifest_sha256: String,
    /// Lowercase hex 32-byte Ed25519 public key.
    pub public_key: String,
    /// Lowercase hex SHA-256 of the public key bytes.
    pub key_fingerprint: String,
    /// Lowercase hex 64-byte Ed25519 signature.
    pub signature: String,
}

impl SignatureEnvelope {
    /// Sign exact manifest bytes with an unlocked key.
    pub fn sign(manifest_bytes: &[u8], key: &UnlockedKey) -> Self {
        let digest = manifest_digest(manifest_bytes);
        let signature = key.sign(&signing_message(&digest));
        let public = key.public_key_bytes();
        Self {
            format: SIGNATURE_FORMAT.into(),
            algorithm: SIGNATURE_ALGORITHM.into(),
            manifest_sha256: sha256_hex(&digest),
            public_key: hex(&public),
            key_fingerprint: fingerprint(&public),
            signature: hex(&signature),
        }
    }

    /// Stable serialization: pretty JSON plus one trailing newline.
    pub fn to_json(&self) -> CoreResult<String> {
        let mut text = serde_json::to_string_pretty(self)
            .map_err(|error| CoreError::Internal(format!("signature serialize: {error}")))?;
        text.push('\n');
        Ok(text)
    }

    /// Write atomically beside the manifest. Refuses to overwrite an existing
    /// sidecar: an old signature is never silently replaced.
    pub fn write_atomic(&self, path: &Path) -> CoreResult<PathBuf> {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        std::fs::create_dir_all(parent)
            .map_err(|error| CoreError::Storage(format!("signature dir: {error}")))?;
        let staging = parent.join(format!(
            ".{}.part",
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "signature".into())
        ));
        let text = self.to_json()?;
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging)
                .map_err(|error| {
                    CoreError::Storage(format!(
                        "signature staging create (remove {} if it is stale): {error}",
                        staging.display()
                    ))
                })?;
            file.write_all(text.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|error| {
                    let _ = std::fs::remove_file(&staging);
                    CoreError::Storage(format!("signature write: {error}"))
                })?;
        }
        if path.exists() {
            let _ = std::fs::remove_file(&staging);
            return Err(CoreError::InvalidInput(format!(
                "a signature already exists at {}; remove it before signing again",
                path.display()
            )));
        }
        std::fs::rename(&staging, path).map_err(|error| {
            let _ = std::fs::remove_file(&staging);
            CoreError::Storage(format!("signature publish: {error}"))
        })?;
        Ok(path.to_path_buf())
    }

    /// Read a sidecar with duplicate-key rejection, a size bound, and strict
    /// shape decoding.
    pub fn read(path: &Path) -> CoreResult<Self> {
        let metadata = std::fs::metadata(path)
            .map_err(|error| CoreError::Storage(format!("signature file: {error}")))?;
        if metadata.len() > MAX_SIGNATURE_FILE_BYTES {
            return Err(CoreError::Unsupported(format!(
                "the signature file is larger than {MAX_SIGNATURE_FILE_BYTES} bytes"
            )));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|error| CoreError::Storage(format!("signature read: {error}")))?;
        reject_duplicate_keys(&text)?;
        serde_json::from_str(&text)
            .map_err(|error| CoreError::Unsupported(format!("signature shape: {error}")))
    }

    /// Verify this envelope against exact manifest bytes.
    pub fn check(&self, manifest_bytes: &[u8]) -> CoreResult<SignatureCheck> {
        if self.format != SIGNATURE_FORMAT {
            return Err(CoreError::Unsupported(format!(
                "signature format {} is not supported",
                self.format
            )));
        }
        if self.algorithm != SIGNATURE_ALGORITHM {
            return Err(CoreError::Unsupported(format!(
                "signature algorithm {} is not supported",
                self.algorithm
            )));
        }
        let public: [u8; 32] = unhex(&self.public_key)?;
        let signature: [u8; 64] = unhex(&self.signature)?;
        let _signed_digest: [u8; 32] = unhex(&self.manifest_sha256)?;
        let expected_fingerprint = fingerprint(&public);
        if self.key_fingerprint != expected_fingerprint {
            return Err(CoreError::Unsupported(
                "the key fingerprint does not match the embedded public key".into(),
            ));
        }
        let verifying = VerifyingKey::from_bytes(&public).map_err(|_| {
            CoreError::Unsupported("the public key is not a valid Ed25519 key".into())
        })?;
        let computed = manifest_digest(manifest_bytes);
        let digest_matches = self.manifest_sha256 == sha256_hex(&computed);
        let signature_valid = verifying
            .verify_strict(
                &signing_message(&computed),
                &Signature::from_bytes(&signature),
            )
            .is_ok();
        Ok(SignatureCheck {
            signature_valid,
            manifest_digest_matches: digest_matches,
            key_fingerprint: expected_fingerprint,
            public_key: self.public_key.clone(),
        })
    }
}

/// Result of checking one envelope. Separate booleans: a digest mismatch and a
/// forged signature are different observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureCheck {
    pub signature_valid: bool,
    pub manifest_digest_matches: bool,
    pub key_fingerprint: String,
    pub public_key: String,
}

/// Explicit user-maintained trusted-key list. One lowercase/uppercase hex
/// fingerprint per line; `#` comments and blank lines are ignored. Anything
/// else is an error, never a silently skipped line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedKeys {
    fingerprints: HashSet<String>,
}

impl TrustedKeys {
    pub fn parse(text: &str) -> CoreResult<Self> {
        let mut fingerprints = HashSet::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let _: [u8; 32] = unhex(line).map_err(|_| {
                CoreError::Unsupported(format!(
                    "trusted-key line {} is not a 64-character key fingerprint",
                    index + 1
                ))
            })?;
            fingerprints.insert(line.to_ascii_lowercase());
        }
        Ok(Self { fingerprints })
    }

    pub fn load(path: &Path) -> CoreResult<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| CoreError::Storage(format!("trusted-key file: {error}")))?;
        Self::parse(&text)
    }

    pub fn contains(&self, fingerprint: &str) -> bool {
        self.fingerprints
            .contains(&fingerprint.to_ascii_lowercase())
    }

    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }
}

/// Signature state, kept separate from manifest and key-trust state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// No sidecar was present and none was requested.
    Absent,
    /// The signature covers these exact bytes.
    Valid,
    /// A sidecar was present but does not cover these bytes.
    Invalid(String),
}

/// Key-trust state. A valid signature from an unknown key is still valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyTrust {
    NotApplicable,
    Untrusted,
    Trusted,
}

/// Manifest decode/object state, kept separate from the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestStatus {
    Verified(ManifestVerification),
    Rejected { code: String, detail: String },
}

/// Complete verification report: no status is collapsed into another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedManifestVerification {
    pub manifest: ManifestStatus,
    pub signature: SignatureStatus,
    pub key_trust: KeyTrust,
    pub key_fingerprint: Option<String>,
    pub public_key: Option<String>,
    /// `None` when the manifest did not decode.
    pub capture_complete: Option<bool>,
}

impl SignedManifestVerification {
    /// Accepted means: the stored bytes verify and no signature was rejected.
    /// An untrusted-but-valid key does not fail verification; it is reported.
    pub fn is_accepted(&self) -> bool {
        matches!(self.manifest, ManifestStatus::Verified(_))
            && !matches!(self.signature, SignatureStatus::Invalid(_))
    }
}

/// Verify a manifest and, when present or explicitly requested, its detached
/// signature. Reads the manifest bytes once so the signature and the decode
/// cover the same bytes. The case root is explicit: it is never guessed from
/// the manifest path.
pub fn verify_manifest(
    case_root: &Path,
    manifest_path: &Path,
    signature_path: Option<&Path>,
    trust: Option<&TrustedKeys>,
) -> CoreResult<SignedManifestVerification> {
    let metadata = std::fs::metadata(manifest_path)
        .map_err(|error| CoreError::Storage(format!("manifest file: {error}")))?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(CoreError::Unsupported(format!(
            "the manifest is larger than {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let bytes = std::fs::read(manifest_path)
        .map_err(|error| CoreError::Storage(format!("manifest read: {error}")))?;
    verify_loaded_bytes(case_root, manifest_path, signature_path, trust, &bytes)
}

fn verify_loaded_bytes(
    case_root: &Path,
    manifest_path: &Path,
    signature_path: Option<&Path>,
    trust: Option<&TrustedKeys>,
    bytes: &[u8],
) -> CoreResult<SignedManifestVerification> {
    let explicit = signature_path.is_some();
    let sidecar = signature_path
        .map(|path| path.to_path_buf())
        .unwrap_or_else(|| sidecar_path(manifest_path));
    let (signature, key_fingerprint, public_key) = if sidecar.exists() {
        let envelope = SignatureEnvelope::read(&sidecar)?;
        let check = envelope.check(bytes)?;
        let status = if check.signature_valid {
            SignatureStatus::Valid
        } else if check.manifest_digest_matches {
            SignatureStatus::Invalid(
                "the signature does not verify for these exact manifest bytes".into(),
            )
        } else {
            SignatureStatus::Invalid(
                "the manifest digest differs from the signed digest (the bytes changed)".into(),
            )
        };
        (status, Some(check.key_fingerprint), Some(check.public_key))
    } else if explicit {
        return Err(CoreError::Storage(format!(
            "signature file {} does not exist",
            sidecar.display()
        )));
    } else {
        (SignatureStatus::Absent, None, None)
    };
    let key_trust = match (&signature, &key_fingerprint) {
        (SignatureStatus::Absent, _) => KeyTrust::NotApplicable,
        (_, Some(fingerprint)) => match trust {
            Some(trusted) if trusted.contains(fingerprint) => KeyTrust::Trusted,
            _ => KeyTrust::Untrusted,
        },
        (_, None) => KeyTrust::NotApplicable,
    };
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CoreError::Unsupported("the manifest is not UTF-8".into()))?;
    let (manifest, capture_complete) = match ManifestV1::verify_bytes(text, case_root) {
        Ok(verification) => {
            let gaps = verification.gaps;
            (ManifestStatus::Verified(verification), Some(gaps == 0))
        }
        Err(error) => (
            ManifestStatus::Rejected {
                code: error.code().to_string(),
                detail: error.to_string(),
            },
            None,
        ),
    };
    Ok(SignedManifestVerification {
        manifest,
        signature,
        key_trust,
        key_fingerprint,
        public_key,
        capture_complete,
    })
}

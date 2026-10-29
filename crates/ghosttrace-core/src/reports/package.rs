//! Portable evidence packages (plan Section 12; P9.2).
//!
//! A package is a directory a second person can verify without this case or
//! this machine: the acquisition manifest, the stored objects the report
//! cites, the report itself (optionally redacted), a verifier README, and a
//! digest inventory over every file. The inventory can carry the same detached
//! Ed25519 signature as a manifest (P9.1).
//!
//! Publication is atomic: a failure leaves no directory that looks like a
//! complete package, and an existing package is never overwritten.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::integrity::inventory::{
    InventoryFile, check_relative_path, ensure_no_unlisted, verify_files,
};
use crate::integrity::keys::UnlockedKey;
use crate::integrity::manifest::{ManifestV1, reject_duplicate_keys};
use crate::integrity::signature::{KeyTrust, SignatureEnvelope, SignatureStatus, TrustedKeys};
use crate::reports::csv;
use crate::reports::redact::RedactionLedger;
use crate::reports::{ReportV1, html, json};

/// Package format identity.
pub const PACKAGE_FORMAT: &str = "ghosttrace-package/1";
/// Inventory file name (signed document when a key is supplied).
pub const INVENTORY_NAME: &str = "package.json";
/// The inventory's detached signature, when signed.
pub const INVENTORY_SIGNATURE_NAME: &str = "package.json.sig.json";
/// Upper bound for an inventory this build will read.
pub const MAX_INVENTORY_BYTES: u64 = 4 * 1024 * 1024;

/// One published package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPackage {
    pub package_id: String,
    pub directory: PathBuf,
    pub inventory_path: PathBuf,
    pub files: Vec<InventoryFile>,
    pub total_bytes: u64,
    pub signed: bool,
    pub public_key: Option<String>,
    pub key_fingerprint: Option<String>,
}

/// The versioned inventory. No evidence values beyond file names and digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageInventoryV1 {
    pub format: String,
    pub package_id: String,
    pub created_utc: String,
    pub tool_version: String,
    pub case_id: String,
    pub case_label: String,
    pub acquisition_id: String,
    pub revision: String,
    pub redacted: bool,
    pub redaction: Option<RedactionLedger>,
    /// `signed` or `unsigned`.
    pub signature: String,
    pub files: Vec<InventoryFile>,
    pub limitations: Vec<String>,
}

/// Everything needed to publish one package.
pub struct PackageRequest<'a> {
    pub case_root: &'a Path,
    pub output: &'a Path,
    pub report: &'a ReportV1,
    pub redaction: Option<&'a RedactionLedger>,
    pub manifest_path: &'a Path,
    /// Existing manifest sidecar to include, if any.
    pub manifest_signature: Option<&'a Path>,
    /// Sign the package inventory with this key.
    pub key: Option<&'a UnlockedKey>,
    pub tool_version: &'a str,
}

/// Result of verifying a package independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageVerification {
    pub inventory: PackageInventoryV1,
    pub files_verified: usize,
    pub total_bytes: u64,
    pub signature: SignatureStatus,
    pub key_trust: KeyTrust,
    pub key_fingerprint: Option<String>,
}

impl PackageVerification {
    /// Accepted means every listed file matches and no signature was rejected.
    /// A valid signature from an untrusted key is reported, not rejected.
    pub fn is_accepted(&self) -> bool {
        !matches!(self.signature, SignatureStatus::Invalid(_))
    }
}

/// Publish one package atomically.
pub fn publish_package(request: PackageRequest<'_>) -> CoreResult<PublishedPackage> {
    let report = request.report;
    let created = chrono::Utc::now();
    let package_id = format!("package-{}-{}", report.acquisition.id, created.timestamp());
    std::fs::create_dir_all(request.output)
        .map_err(|error| CoreError::Storage(format!("package output dir: {error}")))?;
    let target = request.output.join(&package_id);
    if target.exists() {
        return Err(CoreError::Storage(format!(
            "package {package_id} already exists; refusing to overwrite"
        )));
    }
    let staging = request.output.join(format!(".{package_id}.part"));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .map_err(|error| CoreError::Storage(format!("package staging cleanup: {error}")))?;
    }

    let mut files: Vec<InventoryFile> = Vec::new();
    let result = (|| -> CoreResult<()> {
        crate::reports::create_private_dir(&staging)?;

        // Report projections.
        crate::reports::write_synced(
            &staging.join("report.json"),
            json::render(report)?.as_bytes(),
        )?;
        crate::reports::write_synced(
            &staging.join("report.html"),
            html::render(report).as_bytes(),
        )?;
        crate::reports::write_synced(
            &staging.join("report.csv"),
            csv::timeline_csv(report).as_bytes(),
        )?;
        crate::reports::write_synced(
            &staging.join("objects.csv"),
            csv::objects_csv(report).as_bytes(),
        )?;
        if let Some(ledger) = request.redaction {
            crate::reports::write_synced(
                &staging.join("redaction.json"),
                ledger.to_json()?.as_bytes(),
            )?;
        }

        // Manifest bytes and its existing signature. The manifest is re-read
        // and verified against the case before it is copied, so a package can
        // never contain a manifest that does not describe the copied objects.
        let manifest_bytes = std::fs::read(request.manifest_path)
            .map_err(|error| CoreError::Storage(format!("manifest read: {error}")))?;
        let manifest_text = std::str::from_utf8(&manifest_bytes)
            .map_err(|_| CoreError::Unsupported("the manifest is not UTF-8".into()))?;
        ManifestV1::verify_bytes(manifest_text, request.case_root)?;
        crate::reports::write_synced(&staging.join("manifest.json"), &manifest_bytes)?;
        if let Some(signature) = request.manifest_signature.filter(|path| path.exists()) {
            let bytes = std::fs::read(signature)
                .map_err(|error| CoreError::Storage(format!("signature read: {error}")))?;
            crate::reports::write_synced(&staging.join("manifest.json.sig.json"), &bytes)?;
        }

        // Referenced objects, named by digest so no path can escape.
        crate::reports::create_private_dir(&staging.join("objects"))?;
        for object in &report.objects {
            let source = object_path(request.case_root, &object.sha256)?;
            let bytes = std::fs::read(&source).map_err(|_| CoreError::CorruptEvidence)?;
            if crate::integrity::inventory::digest_hex(&bytes) != object.sha256.to_ascii_lowercase()
                || bytes.len() as u64 != object.byte_length
            {
                return Err(CoreError::CorruptEvidence);
            }
            crate::reports::write_synced(&staging.join("objects").join(&object.sha256), &bytes)?;
        }

        crate::reports::write_synced(
            &staging.join("README.txt"),
            readme(&package_id, request.key.is_some()).as_bytes(),
        )?;

        // Inventory over every file written so far, then its signature.
        for relative in [
            "README.txt",
            "report.json",
            "report.html",
            "report.csv",
            "objects.csv",
            "manifest.json",
            "manifest.json.sig.json",
            "redaction.json",
        ] {
            if staging.join(relative).is_file() {
                files.push(InventoryFile::of(&staging, relative, role_for(relative))?);
            }
        }
        let mut object_digests: BTreeSet<&str> = BTreeSet::new();
        for object in &report.objects {
            if object_digests.insert(object.sha256.as_str()) {
                files.push(InventoryFile::of(
                    &staging,
                    &format!("objects/{}", object.sha256),
                    "object",
                )?);
            }
        }

        let mut limitations = report.limitations.clone();
        limitations.push(
            "A package proves what this case recorded; it cannot prove that collection was \
             complete or that the host was truthful."
                .into(),
        );
        if request.redaction.is_some() {
            limitations.push(
                "This package is redacted: the ledger lists replaced fields and counts, not the \
                 removed values. The original case is unchanged."
                    .into(),
            );
        }
        let signature = if request.key.is_some() {
            "signed".to_string()
        } else {
            "unsigned".to_string()
        };
        let inventory = PackageInventoryV1 {
            format: PACKAGE_FORMAT.into(),
            package_id: package_id.clone(),
            created_utc: created.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            tool_version: request.tool_version.into(),
            case_id: report.case.case_id.clone(),
            case_label: report.case.label.clone(),
            acquisition_id: report.acquisition.id.clone(),
            revision: report.revision.clone(),
            redacted: request.redaction.is_some(),
            redaction: request.redaction.cloned(),
            signature,
            files: files.clone(),
            limitations,
        };
        let inventory_bytes = inventory_json(&inventory)?;
        crate::reports::write_synced(&staging.join(INVENTORY_NAME), inventory_bytes.as_bytes())?;
        if let Some(key) = request.key {
            let envelope = SignatureEnvelope::sign(inventory_bytes.as_bytes(), key);
            envelope.write_atomic(&staging.join(INVENTORY_SIGNATURE_NAME))?;
        }

        crate::reports::sync_directory(&staging)?;
        std::fs::rename(&staging, &target)
            .map_err(|error| CoreError::Storage(format!("package publish: {error}")))?;
        crate::reports::sync_directory(request.output)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(error);
    }
    let total_bytes = files.iter().map(|file| file.byte_length).sum();
    let identity = request.key.map(|key| key.identity());
    Ok(PublishedPackage {
        package_id,
        directory: target.clone(),
        inventory_path: target.join(INVENTORY_NAME),
        files,
        total_bytes,
        signed: identity.is_some(),
        public_key: identity
            .as_ref()
            .map(|identity| identity.public_key.clone()),
        key_fingerprint: identity.map(|identity| identity.key_fingerprint),
    })
}

/// Verify a package directory without trusting anything inside it.
pub fn verify_package(
    directory: &Path,
    trust: Option<&TrustedKeys>,
) -> CoreResult<PackageVerification> {
    let inventory_path = directory.join(INVENTORY_NAME);
    let metadata = std::fs::metadata(&inventory_path)
        .map_err(|error| CoreError::Storage(format!("package inventory: {error}")))?;
    if metadata.len() > MAX_INVENTORY_BYTES {
        return Err(CoreError::Unsupported(
            "the package inventory is implausibly large".into(),
        ));
    }
    let text = std::fs::read_to_string(&inventory_path)
        .map_err(|error| CoreError::Storage(format!("package inventory: {error}")))?;
    reject_duplicate_keys(&text)?;
    let inventory: PackageInventoryV1 = serde_json::from_str(&text)
        .map_err(|error| CoreError::Unsupported(format!("package inventory: {error}")))?;
    if inventory.format != PACKAGE_FORMAT {
        return Err(CoreError::Unsupported(format!(
            "package format {} is not supported",
            inventory.format
        )));
    }
    for file in &inventory.files {
        check_relative_path(&file.path)?;
    }
    let total_bytes = verify_files(directory, &inventory.files)?;
    ensure_no_unlisted(
        directory,
        &inventory.files,
        &[INVENTORY_NAME, INVENTORY_SIGNATURE_NAME],
    )?;

    let sidecar = directory.join(INVENTORY_SIGNATURE_NAME);
    let (signature, key_fingerprint) = if sidecar.exists() {
        let envelope = SignatureEnvelope::read(&sidecar)?;
        let check = envelope.check(text.as_bytes())?;
        let status = if check.signature_valid {
            SignatureStatus::Valid
        } else if check.manifest_digest_matches {
            SignatureStatus::Invalid(
                "the signature does not verify for these exact inventory bytes".into(),
            )
        } else {
            SignatureStatus::Invalid(
                "the inventory digest differs from the signed digest (the bytes changed)".into(),
            )
        };
        (status, Some(check.key_fingerprint))
    } else {
        (SignatureStatus::Absent, None)
    };
    let key_trust = match (&signature, trust, &key_fingerprint) {
        (SignatureStatus::Absent, _, _) => KeyTrust::NotApplicable,
        (_, Some(trust), Some(fingerprint)) if trust.contains(fingerprint) => KeyTrust::Trusted,
        (_, _, _) => KeyTrust::Untrusted,
    };
    let files_verified = inventory.files.len();
    Ok(PackageVerification {
        inventory,
        files_verified,
        total_bytes,
        signature,
        key_trust,
        key_fingerprint,
    })
}

/// The store path for one digest, with no user-controlled component.
pub fn object_path(case_root: &Path, sha256: &str) -> CoreResult<PathBuf> {
    if sha256.len() != 64 || !sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(CoreError::Unsupported("object digest is malformed".into()));
    }
    let sha256 = sha256.to_ascii_lowercase();
    Ok(case_root
        .join("objects")
        .join("sha256")
        .join(&sha256[..2])
        .join(&sha256))
}

fn inventory_json(inventory: &PackageInventoryV1) -> CoreResult<String> {
    let mut text = serde_json::to_string_pretty(inventory)
        .map_err(|error| CoreError::Storage(format!("package inventory: {error}")))?;
    text.push('\n');
    Ok(text)
}

fn role_for(relative: &str) -> &'static str {
    match relative {
        "manifest.json" | "manifest.json.sig.json" => "manifest",
        "README.txt" => "instructions",
        "redaction.json" => "redaction",
        _ => "report",
    }
}

fn readme(package_id: &str, signed: bool) -> String {
    let signature = if signed {
        "package.json.sig.json is a detached Ed25519 signature over the exact bytes of \
         package.json. Check it with the signer's public key and compare the key fingerprint \
         with a fingerprint you obtained out of band."
    } else {
        "This package is unsigned. The inventory proves the files match their digests, not who \
         produced them."
    };
    format!(
        "GhostTrace evidence package {package_id}\n\
         \n\
         Contents\n\
         --------\n\
         package.json        digest inventory over every file in this directory\n\
         report.json         the recorded report (exact values)\n\
         report.html         self-contained reading view\n\
         report.csv          spreadsheet-safe timeline projection\n\
         objects.csv         spreadsheet-safe object list\n\
         manifest.json       the acquisition manifest (and .sig.json when present)\n\
         objects/<sha256>    stored objects cited by the report\n\
         \n\
         Verify\n\
         ------\n\
         1. Read package.json and confirm every listed file exists, has the listed byte length,\n\
            and hashes to the listed SHA-256. Reject a file that is missing, changed, or unlisted.\n\
         2. {signature}\n\
         3. Check manifest.json against objects/<sha256> using the recorded digests. An object\n\
            digest mismatch is a failure, never a warning.\n\
         4. A valid signature from an unknown key is valid but untrusted: it proves those bytes\n\
            were signed by that key, not that the key belongs to the person you expect.\n\
         \n\
         Limits\n\
         ------\n\
         A package proves what the case recorded. It does not prove that collection was complete,\n\
         that the host was truthful, or that custody was legally sufficient. No step here needs\n\
         network access.\n"
    )
}

//! Evidence objects and filesystem observations (plan Sections 5–6, P1.1).
//!
//! A `Complete` digest status is only constructible together with a digest:
//! unreadable, partial, or unstable captures can never present a successful
//! full-content digest (plan Section 19 evidence correctness).

use serde::{Deserialize, Serialize};

use super::case::AcquisitionId;
use super::path::NativePath;
use super::time::EventTime;
use crate::error::{CoreError, CoreResult};

/// Completion state of full-content hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DigestStatus {
    /// Not hashed yet (e.g. a non-file observation).
    NotApplicable,
    /// A full-content digest exists and matched the captured bytes.
    Complete,
    /// A digest was computed over incomplete bytes; never a verification.
    Partial,
    /// Hashing failed or the bytes changed during capture.
    Failed,
}

impl DigestStatus {
    /// True only when a full capture succeeded. Never true for
    /// `Partial`/`Failed`.
    pub fn is_complete(self) -> bool {
        matches!(self, DigestStatus::Complete)
    }
}

/// Where the bytes live in the case's content-addressed store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectLocation {
    /// Content-addressed store subpath (e.g. `objects/sha256/ab/<digest>`).
    pub store_subpath: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceObject {
    pub id: String,
    pub acquisition_id: AcquisitionId,
    /// The raw native path as observed, never canonicalized.
    pub native_path: NativePath,
    pub kind: EvidenceObjectKind,
    pub byte_length: Option<u64>,
    pub digest_status: DigestStatus,
    /// Full-content SHA-256, present exactly when status is `Complete`.
    pub sha256: Option<[u8; 32]>,
    pub location: Option<ObjectLocation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceObjectKind {
    /// Captured file content (immutable once published).
    FileContent,
    /// Captured non-file observation (e.g. symlink target, device note).
    NonFileObservation,
}

impl EvidenceObject {
    /// Construct a verified captured object. `sha256` is mandatory: this is
    /// the only way to obtain `DigestStatus::Complete`.
    pub fn captured(
        id: impl Into<String>,
        acquisition_id: AcquisitionId,
        native_path: NativePath,
        byte_length: u64,
        sha256: [u8; 32],
        location: ObjectLocation,
    ) -> Self {
        Self {
            id: id.into(),
            acquisition_id,
            native_path,
            kind: EvidenceObjectKind::FileContent,
            byte_length: Some(byte_length),
            digest_status: DigestStatus::Complete,
            sha256: Some(sha256),
            location: Some(location),
        }
    }

    /// Construct an object that is present but not successfully hashed.
    pub fn incomplete(
        id: impl Into<String>,
        acquisition_id: AcquisitionId,
        native_path: NativePath,
        status: DigestStatus,
    ) -> CoreResult<Self> {
        if status.is_complete() {
            return Err(CoreError::InvalidInput(
                "evidence: Complete requires EvidenceObject::captured with a digest".into(),
            ));
        }
        Ok(Self {
            id: id.into(),
            acquisition_id,
            native_path,
            kind: EvidenceObjectKind::FileContent,
            byte_length: None,
            digest_status: status,
            sha256: None,
            location: None,
        })
    }

    /// The digest as lowercase hex, when a full capture exists.
    pub fn sha256_hex(&self) -> Option<String> {
        self.sha256
            .as_ref()
            .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect())
    }
}

/// A filesystem fact observed during acquisition (plan Section 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeIdentity {
    /// Scoped device/inode or file ID (e.g. `dev:ino`, `volume:file_index`).
    pub scoped_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileObservation {
    pub id: String,
    pub evidence_id: Option<String>,
    /// Native identity is scoped by acquisition volume/host, never global.
    pub native_identity: Option<NativeIdentity>,
    pub size: Option<u64>,
    /// Raw timestamp values with their exact semantics preserved.
    pub times: Vec<NamedEventTime>,
    pub link_target: Option<NativePath>,
    pub observed_at: EventTime,
}

/// A named time value: the field name carries its semantic meaning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedEventTime {
    pub field: String,
    pub value: EventTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acquisition() -> AcquisitionId {
        AcquisitionId::new("acq-1")
    }

    #[test]
    fn complete_status_requires_a_digest() {
        let object = EvidenceObject::captured(
            "obj-1",
            acquisition(),
            NativePath::unix("docs/report.txt"),
            4096,
            [0xab; 32],
            ObjectLocation {
                store_subpath: "objects/sha256/ab/".into(),
            },
        );
        assert!(object.digest_status.is_complete());
        assert!(object.sha256_hex().is_some());
        assert_eq!(object.byte_length, Some(4096));
    }

    #[test]
    fn partial_or_failed_never_claim_success() {
        let partial = EvidenceObject::incomplete(
            "obj-2",
            acquisition(),
            NativePath::unix("docs/large.bin"),
            DigestStatus::Partial,
        )
        .unwrap();
        assert!(!partial.digest_status.is_complete());
        assert!(partial.sha256.is_none());

        let failed = EvidenceObject::incomplete(
            "obj-3",
            acquisition(),
            NativePath::unix("mnt/locked.bin"),
            DigestStatus::Failed,
        )
        .unwrap();
        assert!(!failed.digest_status.is_complete());
    }

    #[test]
    fn complete_without_digest_is_rejected() {
        let error = EvidenceObject::incomplete(
            "obj-4",
            acquisition(),
            NativePath::unix("x"),
            DigestStatus::Complete,
        )
        .unwrap_err();
        assert_eq!(error.code(), "invalid_request");
    }
}

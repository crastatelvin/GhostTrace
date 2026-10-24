//! Raw observations and normalized events (plan Sections 5, 7, P1.1).
//!
//! A raw observation is what a parser actually extracted, with the strongest
//! supported locator. An event is the normalized interpretation; it always
//! points back at observations so provenance stays retrievable.

use serde::{Deserialize, Serialize};

use super::case::AcquisitionId;
use super::evidence::EvidenceObject;
use super::path::NativePath;
use super::time::{EventTime, TimeSemantic};

/// The strongest locator a parser can support for one record.
/// Never invented: when a byte range does not exist, the logical locator is
/// used and its limitation is disclosed (plan Section 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordLocator {
    /// Byte range inside a text/JSONL object.
    ByteRange {
        object_id: String,
        offset: u64,
        length: u64,
        line: Option<u64>,
    },
    /// Logical row reference inside a captured SQLite database.
    LogicalRow {
        object_id: String,
        table: String,
        primary_key: String,
    },
    /// Structured binary record location (chunk/record where available).
    BinaryRecord {
        object_id: String,
        chunk: Option<String>,
        record_id: Option<String>,
    },
    /// Filesystem entry with its acquisition scope.
    FilesystemEntry {
        acquisition_id: AcquisitionId,
        native_path: NativePath,
    },
}

/// One extracted record before interpretation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawObservation {
    pub id: String,
    pub acquisition_id: AcquisitionId,
    pub evidence: EvidenceObject,
    pub locator: RecordLocator,
    /// Field values exactly as parsed, keyed by source field name.
    pub raw_fields: Vec<(String, serde_json::Value)>,
    pub recorded_at: EventTime,
}

/// Normalized interpretation of one or more raw observations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub kind: String,
    pub summary: String,
    pub observations: Vec<String>,
    pub times: Vec<NamedEventTimeRef>,
    /// Host or domain the event *claims*; never silently cross-host joined.
    pub host_claim: Option<String>,
    /// Active parse-run/revision this normalized event belongs to.
    pub revision: String,
}

/// A time value attached to a normalized event, keyed by its semantic name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NamedEventTimeRef {
    pub name: String,
    pub semantic: TimeSemantic,
    pub value: EventTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_locator_is_exact_when_supported() {
        let observation = RawObservation {
            id: "obs-1".into(),
            acquisition_id: AcquisitionId::new("acq-1"),
            evidence: EvidenceObject::captured(
                "obj-1",
                AcquisitionId::new("acq-1"),
                NativePath::unix("logs/app.jsonl"),
                12,
                [0x01; 32],
                crate::domain::evidence::ObjectLocation {
                    store_subpath: "objects/sha256/01/".into(),
                },
            ),
            locator: RecordLocator::ByteRange {
                object_id: "obj-1".into(),
                offset: 6,
                length: 6,
                line: Some(1),
            },
            raw_fields: vec![("msg".into(), serde_json::json!("hello"))],
            recorded_at: EventTime::from_unix_seconds(0, TimeSemantic::LoggedTime),
        };
        match &observation.locator {
            RecordLocator::ByteRange { offset, length, .. } => {
                assert_eq!((*offset, *length), (6, 6));
            }
            other => panic!("unexpected locator: {other:?}"),
        }
        assert!(observation.evidence.digest_status.is_complete());
    }
}

//! Provenance detail for one event and bounded time aggregates (plan P6.2).
//!
//! The inspector must be able to show exactly what an event rests on: the raw
//! record, its locator, the evidence object, every recorded time with its
//! assumptions, the scoped entities, and the parse run's own diagnostics. The
//! types here carry recorded values; they never invent a missing link. An
//! event imported before the source link existed reports `source_linked:
//! false` instead of pointing at a guessed record.

use serde::{Deserialize, Serialize};

use crate::domain::query::EventRow;

/// Everything the inspector can show for one event, read in one call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventDetail {
    pub event: EventRow,
    pub parse_run_id: String,
    pub parser_id: String,
    pub parser_version: String,
    /// True when the event stores the evidence/locator link recorded by the
    /// importer. False means the link was never recorded (older case) and the
    /// raw record cannot be re-read without guessing.
    pub source_linked: bool,
    pub observations: Vec<ObservationDetail>,
    pub times: Vec<EventTimeDetail>,
    pub entities: Vec<EntityRef>,
    /// Diagnostics of the parse run that produced this event, not per-record
    /// guesses. Bounded by the run's own recorded list.
    pub run_diagnostics: Vec<RunDiagnostic>,
    /// The parse run's recorded assumptions as stored JSON text.
    pub run_assumptions_json: String,
}

/// One raw observation behind the event, with its exact locator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationDetail {
    pub evidence_id: String,
    pub acquisition_id: String,
    /// Reversible encoded native path; never a lossy display string.
    pub evidence_path: String,
    pub locator_kind: String,
    pub locator_identity: String,
    /// Recorded raw fields exactly as stored (JSON text).
    pub raw_fields_json: String,
}

/// One recorded time value with its resolution and assumptions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventTimeDetail {
    pub name: String,
    pub semantic: String,
    pub status: String,
    /// Candidates as stored JSON: exact seconds + nanos pairs.
    pub candidates_json: String,
    pub raw_field: Option<String>,
    pub raw_value_kind: Option<String>,
    /// Exact raw integer (decimal text) or raw text, whichever was recorded.
    pub raw_value: Option<String>,
    pub epoch: String,
    pub unit: String,
    pub declared_precision: String,
    pub clock_domain: String,
    pub assumptions_json: String,
}

/// A scoped entity the event mentions, with the role it played.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRef {
    pub entity_id: String,
    pub kind: String,
    pub display_form: String,
    pub role: String,
}

/// One parse-run diagnostic. Operational detail only; never record content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDiagnostic {
    pub code: String,
    pub locator: String,
    pub detail: String,
}

/// A bounded histogram over one filtered revision.
///
/// Bins are uniform intervals in Unix seconds. The caller declares the bin
/// width (`bin_seconds`) and the interval, so a chart can never imply more
/// precision than the aggregate has. Events with no chosen time cannot be
/// binned and are counted separately — they are never dropped silently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Histogram {
    pub bin_seconds: i64,
    /// Inclusive start of the first bin.
    pub from_seconds: i64,
    /// Exclusive end of the last bin.
    pub to_seconds: i64,
    pub bins: Vec<HistogramBin>,
    /// Matching events with no chosen time. They cannot be placed in a window,
    /// so they are reported beside the bins instead of being dropped.
    pub unresolved_count: u64,
    /// Matching events in the aggregate's filter scope: binned plus
    /// unresolved. With an explicit time window, only the bins are inside it.
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistogramBin {
    pub start_seconds: i64,
    pub end_seconds: i64,
    pub count: u64,
}

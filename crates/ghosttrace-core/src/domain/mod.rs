//! Domain records and lossless value types (plan Section 5).
//!
//! Everything here is pure data with no storage or I/O. Raw observations,
//! normalized events, analyst annotations, and rule outputs are deliberately
//! separate types so interpretations never overwrite facts.

pub mod case;
pub mod event;
pub mod evidence;
pub mod path;
pub mod time;

pub use case::{Acquisition, AcquisitionId, AcquisitionMethod, AcquisitionState, Case, CaseId};
pub use event::{Event, NamedEventTimeRef, RawObservation, RecordLocator};
pub use evidence::{
    DigestStatus, EvidenceObject, EvidenceObjectKind, FileObservation, NamedEventTime,
    NativeIdentity, ObjectLocation,
};
pub use path::{NativePath, NativePathDecodeError};
pub use time::{
    ClockDomain, Epoch, EventTime, RawTimeValue, TimeAssumption, TimePrecision, TimeSemantic,
    TimeStatus, TimeUnit, UnixTime,
};

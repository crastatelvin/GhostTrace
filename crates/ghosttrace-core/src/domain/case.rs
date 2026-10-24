//! Case and acquisition records (plan Section 5, P1.1).
//!
//! IDs are application-generated and opaque. A case is an investigator
//! workspace, not proof of source identity.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::time::UnixTime;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CaseId(String);

impl CaseId {
    pub fn new(value: impl Into<String>) -> Self {
        CaseId(value.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AcquisitionId(String);

impl AcquisitionId {
    pub fn new(value: impl Into<String>) -> Self {
        AcquisitionId(value.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AcquisitionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Case {
    pub id: CaseId,
    pub label: String,
    pub schema_version: u32,
    /// UTC instant this record was created by the application.
    pub created: UnixTime,
    /// IANA zone name the investigator selected for display, or "UTC".
    /// Display-only; never applied to source-time interpretation.
    pub display_timezone: String,
    pub description: String,
}

/// What an acquisition attempted, and how it completed (plan Section 8 job
/// states). An interrupted `running` acquisition is never auto-completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcquisitionState {
    Queued,
    Running,
    Completed,
    Partial,
    Cancelled,
    Failed,
}

impl AcquisitionState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            AcquisitionState::Completed
                | AcquisitionState::Partial
                | AcquisitionState::Cancelled
                | AcquisitionState::Failed
        )
    }
}

/// How the source was reached. Protected copies are the recommended path;
/// live acquisition is explicitly best effort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcquisitionMethod {
    ProtectedCopy,
    LiveBestEffort,
}

impl AcquisitionMethod {
    pub fn is_best_effort(self) -> bool {
        matches!(self, AcquisitionMethod::LiveBestEffort)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acquisition {
    pub id: AcquisitionId,
    pub case_id: CaseId,
    pub method: AcquisitionMethod,
    /// Claimed host/volume identity as recorded by the investigator.
    pub claimed_source: String,
    pub state: AcquisitionState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_opaque_strings_with_stable_display() {
        let id = CaseId::new("01J9ZQ");
        assert_eq!(id.to_string(), "01J9ZQ");
        assert_eq!(id.as_str(), "01J9ZQ");
    }

    #[test]
    fn only_terminal_states_end_a_job() {
        assert!(!AcquisitionState::Running.is_terminal());
        assert!(!AcquisitionState::Queued.is_terminal());
        assert!(AcquisitionState::Partial.is_terminal());
        assert!(AcquisitionMethod::LiveBestEffort.is_best_effort());
        assert!(!AcquisitionMethod::ProtectedCopy.is_best_effort());
    }
}

//! Job state, checkpoints, and recovery (plan Sections 8, 9, P1.2).
//!
//! States: queued, running, completed, partial, cancelled, failed. An
//! interrupted `running` job becomes *recoverable* on reopen; it is never
//! auto-marked completed. Resume requires matching input identity.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobState {
    Queued,
    Running,
    Completed,
    Partial,
    Cancelled,
    Failed,
}

impl JobState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            JobState::Completed | JobState::Partial | JobState::Cancelled | JobState::Failed
        )
    }

    /// A job that was mid-flight when the case was last closed: still
    /// recoverable, never silently completed.
    pub fn is_recoverable_interruption(self) -> bool {
        matches!(self, JobState::Running)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobKind {
    Acquisition,
    Parse,
    Analysis,
    Export,
}

impl JobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            JobKind::Acquisition => "acquisition",
            JobKind::Parse => "parse",
            JobKind::Analysis => "analysis",
            JobKind::Export => "export",
        }
    }
}

/// A checkpoint records enough identity to resume safely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobCheckpoint {
    pub job_id: String,
    pub kind: JobKind,
    pub state: JobState,
    /// Stable identity of the job's inputs (e.g. root + exclusions hash).
    pub input_identity: String,
    /// Digest of the input identity.
    pub input_digest: String,
    pub adapter_version: String,
    pub config_digest: String,
    /// Committed locator: resume strictly after this record only.
    pub committed_locator: Option<String>,
    /// Counters (objects, events, bytes) as exact integers.
    pub counters_json: String,
    pub updated_seconds: i64,
}

impl JobCheckpoint {
    /// Empty initial checkpoint for a queued job.
    pub fn queued(
        job_id: impl Into<String>,
        kind: JobKind,
        input_identity: impl Into<String>,
        input_digest: impl Into<String>,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            kind,
            state: JobState::Queued,
            input_identity: input_identity.into(),
            input_digest: input_digest.into(),
            adapter_version: String::new(),
            config_digest: String::new(),
            committed_locator: None,
            counters_json: "{}".to_string(),
            updated_seconds: 0,
        }
    }

    /// Resume is only safe when inputs match the checkpoint exactly.
    pub fn can_resume(&self, input_identity: &str, input_digest: &str) -> bool {
        self.input_identity == input_identity && self.input_digest == input_digest
    }
}

/// One interrupted job as seen at case open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverableJob {
    pub job_id: String,
    pub kind: JobKind,
    /// The state found in storage (always `running` for interruptions).
    pub found_state: JobState,
    pub committed_locator: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_is_never_terminal() {
        assert!(!JobState::Running.is_terminal());
        assert!(JobState::Running.is_recoverable_interruption());
        assert!(JobState::Completed.is_terminal());
    }

    #[test]
    fn resume_requires_identical_inputs() {
        let checkpoint = JobCheckpoint::queued("job-1", JobKind::Acquisition, "root:x", "digest-x");
        assert!(checkpoint.can_resume("root:x", "digest-x"));
        assert!(!checkpoint.can_resume("root:y", "digest-x"));
        assert!(!checkpoint.can_resume("root:x", "digest-y"));
    }
}

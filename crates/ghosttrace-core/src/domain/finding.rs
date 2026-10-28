//! Versioned findings and analyst dispositions (plan Section 11, P5.2).
//!
//! A finding is an interpretation with an explanation: which rule version ran,
//! which recorded events it used, which predicates held, which alternatives
//! remain, and how strong the evidence is. Severity is a handling priority, not
//! a probability, and no field here can express a "maliciousness percentage".

use serde::{Deserialize, Serialize};

/// Handling priority, deliberately separate from evidence strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            _ => None,
        }
    }
}

/// Analyst state attached to a finding. Stored in annotation history so a new
/// analysis run never destroys it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Undismissed,
    Confirmed,
    Dismissed,
    Commented,
}

impl Disposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Disposition::Undismissed => "undismissed",
            Disposition::Confirmed => "confirmed",
            Disposition::Dismissed => "dismissed",
            Disposition::Commented => "commented",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "undismissed" => Some(Disposition::Undismissed),
            "confirmed" => Some(Disposition::Confirmed),
            "dismissed" => Some(Disposition::Dismissed),
            "commented" => Some(Disposition::Commented),
            _ => None,
        }
    }
}

/// One reproducible finding row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub analysis_run_id: String,
    pub rule_id: String,
    pub rule_version: String,
    /// Recorded events this finding rests on, sorted and deduplicated.
    pub event_ids: Vec<String>,
    /// The exact predicates that held, as recorded values.
    pub predicates: serde_json::Value,
    pub severity: Severity,
    pub rationale: String,
    /// Explanations that remain plausible; never a certainty claim.
    pub alternatives: Vec<String>,
    pub disposition: Disposition,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_round_trips_and_rejects_unknown_text() {
        for disposition in [
            Disposition::Undismissed,
            Disposition::Confirmed,
            Disposition::Dismissed,
            Disposition::Commented,
        ] {
            assert_eq!(Disposition::parse(disposition.as_str()), Some(disposition));
        }
        assert_eq!(Disposition::parse("probably_bad"), None);
    }

    #[test]
    fn severity_text_is_stable() {
        assert_eq!(Severity::Medium.as_str(), "medium");
        assert_eq!(Severity::parse("high"), None, "no invented severity level");
    }
}

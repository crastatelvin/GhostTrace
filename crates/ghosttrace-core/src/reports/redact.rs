//! Redaction is a projection over a report, never a mutation of the case
//! (plan Section 12; P9.2).
//!
//! Selected values are replaced with [`REDACTED`] in the exported copy. The
//! ledger records only field names, categories, and counts: it never contains
//! the text it removed, so publishing the ledger cannot undo the redaction.

use serde::{Deserialize, Serialize};

use crate::error::CoreResult;
use crate::reports::ReportV1;

/// Ledger format identity.
pub const REDACTION_FORMAT: &str = "ghosttrace-redaction/1";
/// The replacement marker. Fixed so a reader can search for it.
pub const REDACTED: &str = "[redacted]";

/// Which fields a redacted projection removes. Every flag is explicit; there
/// is no implicit "redact everything".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionPolicy {
    pub case_label: bool,
    pub source_paths: bool,
    pub object_paths: bool,
    pub timeline_summaries: bool,
    pub timeline_hosts: bool,
}

impl RedactionPolicy {
    pub fn any(&self) -> bool {
        self.case_label
            || self.source_paths
            || self.object_paths
            || self.timeline_summaries
            || self.timeline_hosts
    }

    /// Stable category names used by the CLI and the ledger.
    pub fn selected(&self) -> Vec<&'static str> {
        let mut selected = Vec::new();
        if self.case_label {
            selected.push("case-label");
        }
        if self.source_paths {
            selected.push("source-paths");
        }
        if self.object_paths {
            selected.push("object-paths");
        }
        if self.timeline_summaries {
            selected.push("timeline-summaries");
        }
        if self.timeline_hosts {
            selected.push("timeline-hosts");
        }
        selected
    }
}

/// One applied redaction: field path, category, and how many values changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionAction {
    pub field: String,
    pub category: String,
    pub count: u64,
}

/// The published ledger. Contains no removed values by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionLedger {
    pub format: String,
    pub selected: Vec<String>,
    pub actions: Vec<RedactionAction>,
    pub note: String,
}

impl RedactionLedger {
    pub fn to_json(&self) -> CoreResult<String> {
        let mut text = serde_json::to_string_pretty(self)
            .map_err(|error| crate::error::CoreError::Internal(format!("ledger: {error}")))?;
        text.push('\n');
        Ok(text)
    }

    /// A one-line summary for the CLI/GUI: fields and counts only.
    pub fn summary(&self) -> String {
        if self.actions.is_empty() {
            return "no values matched the selected redaction categories".into();
        }
        self.actions
            .iter()
            .map(|action| format!("{} {} value(s)", action.count, action.field))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Build a redacted copy of a report plus its ledger. The input report is not
/// modified, and no case row or stored byte is touched.
pub fn redact_report(report: &ReportV1, policy: &RedactionPolicy) -> (ReportV1, RedactionLedger) {
    let mut redacted = report.clone();
    let mut actions = Vec::new();
    let mut action = |field: &str, category: &str, count: u64| {
        if count > 0 {
            actions.push(RedactionAction {
                field: field.into(),
                category: category.into(),
                count,
            });
        }
    };

    if policy.case_label && !redacted.case.label.is_empty() {
        redacted.case.label = REDACTED.into();
        action("case.label", "case-label", 1);
    }
    if policy.source_paths {
        let mut count = 0;
        if !redacted.acquisition.claimed_source.is_empty() {
            redacted.acquisition.claimed_source = REDACTED.into();
            count += 1;
        }
        count += redacted.acquisition.roots.len() as u64;
        redacted.acquisition.roots = redacted
            .acquisition
            .roots
            .iter()
            .map(|_| REDACTED.to_string())
            .collect();
        count += redacted.coverage.gaps.len() as u64;
        for gap in &mut redacted.coverage.gaps {
            gap.path = REDACTED.into();
        }
        if !redacted.provenance.claimed_source.is_empty() {
            redacted.provenance.claimed_source = REDACTED.into();
            count += 1;
        }
        count += redacted.provenance.roots.len() as u64;
        redacted.provenance.roots = redacted
            .provenance
            .roots
            .iter()
            .map(|_| REDACTED.to_string())
            .collect();
        action(
            "acquisition.claimed_source/roots, coverage.gaps.path, provenance",
            "source-paths",
            count,
        );
    }
    if policy.object_paths {
        let count = redacted.objects.len() as u64;
        for object in &mut redacted.objects {
            object.path = REDACTED.into();
        }
        action("objects.path", "object-paths", count);
    }
    if policy.timeline_summaries {
        let count = redacted.timeline.len() as u64;
        for row in &mut redacted.timeline {
            row.summary = REDACTED.into();
        }
        action("timeline.summary", "timeline-summaries", count);
    }
    if policy.timeline_hosts {
        let count = redacted
            .timeline
            .iter()
            .filter(|row| row.host_claim.is_some())
            .count() as u64;
        for row in &mut redacted.timeline {
            if row.host_claim.is_some() {
                row.host_claim = Some(REDACTED.into());
            }
        }
        action("timeline.host_claim", "timeline-hosts", count);
    }

    if policy.any() {
        redacted.limitations.push(format!(
            "This export is redacted ({}). Selected values were replaced with {REDACTED}; the \
             ledger lists fields and counts only. The case itself is unchanged.",
            policy.selected().join(", ")
        ));
    }

    let ledger = RedactionLedger {
        format: REDACTION_FORMAT.into(),
        selected: policy.selected().into_iter().map(String::from).collect(),
        actions,
        note: "Counts describe replaced values. Removed text is never recorded here.".into(),
    };
    (redacted, ledger)
}

/// The counts a preview needs, without publishing anything.
pub fn preview_counts(report: &ReportV1, policy: &RedactionPolicy) -> Vec<(String, u64)> {
    let (_, ledger) = redact_report(report, policy);
    ledger
        .actions
        .into_iter()
        .map(|action| (action.field, action.count))
        .collect()
}

/// A compact redaction summary used in report limitations and UI status lines.
pub fn describe(policy: &RedactionPolicy) -> String {
    if !policy.any() {
        return "no redaction".into();
    }
    format!("redacted: {}", policy.selected().join(", "))
}

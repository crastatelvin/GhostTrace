//! Query contracts shared by every front end (plan Sections 6, 9).
//!
//! These are storage-agnostic requests/pages; the storage layer implements
//! the keyset ordering guarantees checked in `writer_concurrency.rs`.

use serde::{Deserialize, Serialize};

/// Filters for a timeline query. Structured fields only — arbitrary SQL is
/// never exposed (plan Section 13).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventQuery {
    /// Active parse-run/revision to read.
    pub revision: String,
    pub kind: Option<String>,
    pub host: Option<String>,
    /// Parser/adapter identity that produced the event (`parse_runs.parser_id`).
    pub source: Option<String>,
    /// Inclusive lower bound on chosen time (Unix seconds).
    pub after_seconds: Option<i64>,
    /// Exclusive upper bound on chosen time (Unix seconds).
    pub before_seconds: Option<i64>,
    /// Only events whose chosen time is unresolved (the explicit view).
    pub unresolved_only: bool,
    pub limit: u32,
    /// Keyset cursor: resume strictly after (seconds, nanos, event id).
    pub after: Option<TimeCursor>,
}

/// A total order over events: chosen time, then event ID (Section 6).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TimeCursor {
    pub seconds: i64,
    pub nanos: u32,
    pub event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRow {
    pub event_id: String,
    pub revision: String,
    pub kind: String,
    pub summary: String,
    pub host_claim: Option<String>,
    pub chosen_seconds: Option<i64>,
    pub chosen_nanos: u32,
    pub time_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPage {
    pub rows: Vec<EventRow>,
    /// Present when more rows match beyond this page.
    pub next_cursor: Option<TimeCursor>,
    /// The chosen case display zone this page was produced in.
    pub display_timezone: String,
}

/// One recorded parse run of an acquisition, for the revision review list.
/// A re-import with different assumptions is a separate revision, and both
/// stay listed and readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionSummary {
    pub run_id: String,
    pub parser_id: String,
    pub parser_version: String,
    pub config_digest: String,
    pub state: String,
    /// Events recorded under this revision.
    pub events: u64,
}

impl EventQuery {
    pub const MAX_LIMIT: u32 = 1_000;
    pub const DEFAULT_LIMIT: u32 = 200;

    pub fn with_revision(revision: impl Into<String>) -> Self {
        Self {
            revision: revision.into(),
            limit: Self::DEFAULT_LIMIT,
            ..Self::default()
        }
    }

    /// Clamp the requested page size to the documented maximum.
    pub fn effective_limit(&self) -> u32 {
        self.limit.clamp(1, Self::MAX_LIMIT).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_is_bounded() {
        let mut query = EventQuery::with_revision("r1");
        query.limit = 10_000;
        assert_eq!(query.effective_limit(), EventQuery::MAX_LIMIT);
        query.limit = 0;
        assert_eq!(query.effective_limit(), 1);
    }

    #[test]
    fn cursor_orders_all_fields() {
        let early = TimeCursor {
            seconds: 5,
            nanos: 0,
            event_id: "a".into(),
        };
        let late = TimeCursor {
            seconds: 5,
            nanos: 1,
            event_id: "a".into(),
        };
        assert!(early < late, "nanos must break second ties");
        let nanos_same = TimeCursor {
            seconds: 5,
            nanos: 1,
            event_id: "b".into(),
        };
        assert!(late < nanos_same, "event id must break full ties");
    }
}

//! Read-side connections and the shared query contract (plan Sections 8, 9).
//!
//! Readers get their own connection with short, read-only transactions and
//! never write. Keyset pagination gives a total order — identical-time events
//! paginate without skips or duplicates — and unknown times stay reachable in
//! an explicit unresolved view instead of being silently dropped.

use std::path::Path;

use rusqlite::Connection;

use crate::domain::query::{EventPage, EventQuery, EventRow, TimeCursor};
use crate::error::{CoreError, CoreResult};
use crate::jobs::{JobKind, JobState, RecoverableJob};

/// A short-lived read-only connection to a case database.
pub struct CaseReader {
    connection: Connection,
}

impl CaseReader {
    /// Open read-only. Fails (rather than creating) when the case is absent.
    pub fn open(database_path: &Path) -> CoreResult<Self> {
        if !database_path.exists() {
            return Err(CoreError::Storage(format!(
                "case database not found: {}",
                database_path.display()
            )));
        }
        let connection =
            Connection::open_with_flags(database_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| CoreError::Storage(format!("open read-only: {e}")))?;
        connection
            .busy_timeout(std::time::Duration::from_millis(5_000))
            .map_err(|e| CoreError::Storage(format!("busy_timeout: {e}")))?;
        Ok(Self { connection })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Diagnose interruptions left in this case. A running job found at open
    /// is recoverable, never auto-completed.
    pub fn recoverable_jobs(&self) -> CoreResult<Vec<RecoverableJob>> {
        let has_table = self.table_exists("job_checkpoints")?;
        if !has_table {
            return Ok(Vec::new());
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT job_id, kind, committed_locator FROM job_checkpoints WHERE state = 'running' ORDER BY job_id",
            )
            .map_err(|e| CoreError::Storage(format!("recovery probe: {e}")))?;
        let rows = statement
            .query_map([], |row| {
                Ok(RecoverableJob {
                    job_id: row.get(0)?,
                    kind: parse_job_kind(&row.get::<_, String>(1)?),
                    found_state: JobState::Running,
                    committed_locator: row.get(2)?,
                })
            })
            .map_err(|e| CoreError::Storage(format!("recovery probe: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CoreError::Storage(format!("recovery probe: {e}")))?;
        Ok(rows)
    }

    fn table_exists(&self, name: &str) -> CoreResult<bool> {
        self.connection
            .query_row(
                "SELECT count(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .map_err(|e| CoreError::Storage(format!("table probe {name}: {e}")))
    }

    /// Newest chosen instant in the case, used as the anchor for relative
    /// ranges such as `--last 24h`. `None` when the case has no resolved time.
    pub fn latest_chosen_seconds(&self) -> CoreResult<Option<i64>> {
        self.connection
            .query_row(
                "SELECT max(chosen_seconds) FROM events WHERE chosen_seconds IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .map_err(|e| CoreError::Storage(format!("latest time: {e}")))
    }

    /// Execute one timeline query. Both views use keyset pagination with the
    /// same total order (chosen time, then nanos, then event id); the
    /// unresolved view orders by event id alone because its times are unknown.
    pub fn query_events(
        &self,
        display_timezone: &str,
        query: &EventQuery,
    ) -> CoreResult<EventPage> {
        let limit = i64::from(query.effective_limit());
        let mut rows = if query.unresolved_only {
            let mut statement = self
                .connection
                .prepare_cached(
                    "SELECT id, revision, kind, summary, host_claim, chosen_seconds, chosen_nanos, time_status
                     FROM events
                     WHERE revision = ?1 AND chosen_seconds IS NULL
                       AND (?2 IS NULL OR kind = ?2)
                       AND (?3 IS NULL OR host_claim = ?3)
                       AND (?4 IS NULL OR EXISTS (
                             SELECT 1 FROM parse_runs p
                             WHERE p.id = events.parse_run_id AND p.parser_id = ?4))
                       AND (?5 = 0 OR id > ?6)
                     ORDER BY id
                     LIMIT ?7",
                )
                .map_err(|e| CoreError::Storage(format!("prepare: {e}")))?;
            let mapped = statement
                .query_map(
                    rusqlite::params![
                        query.revision,
                        query.kind,
                        query.host,
                        query.source,
                        query.after.is_some() as i32,
                        query
                            .after
                            .as_ref()
                            .map_or(String::new(), |c| c.event_id.clone()),
                        limit + 1,
                    ],
                    row_to_event,
                )
                .map_err(|e| CoreError::Storage(format!("prepare: {e}")))?;
            collect_rows(mapped)?
        } else {
            let mut statement = self
                .connection
                .prepare_cached(
                    "SELECT id, revision, kind, summary, host_claim, chosen_seconds, chosen_nanos, time_status
                     FROM events
                     WHERE revision = ?1 AND chosen_seconds IS NOT NULL
                       AND (?2 IS NULL OR kind = ?2)
                       AND (?3 IS NULL OR host_claim = ?3)
                       AND (?4 IS NULL OR chosen_seconds >= ?4)
                       AND (?5 IS NULL OR chosen_seconds < ?5)
                       AND (?10 IS NULL OR EXISTS (
                             SELECT 1 FROM parse_runs p
                             WHERE p.id = events.parse_run_id AND p.parser_id = ?10))
                       AND (chosen_seconds > ?6
                            OR (chosen_seconds = ?6 AND (chosen_nanos > ?7
                                                        OR (chosen_nanos = ?7 AND id > ?8))))
                     ORDER BY chosen_seconds, chosen_nanos, id
                     LIMIT ?9",
                )
                .map_err(|e| CoreError::Storage(format!("prepare: {e}")))?;
            let cursor = query.after.clone().unwrap_or(TimeCursor {
                seconds: 0,
                nanos: 0,
                event_id: String::new(),
            });
            let mapped = statement
                .query_map(
                    rusqlite::params![
                        query.revision,
                        query.kind,
                        query.host,
                        query.after_seconds,
                        query.before_seconds,
                        cursor.seconds,
                        cursor.nanos,
                        cursor.event_id,
                        limit + 1,
                        query.source,
                    ],
                    row_to_event,
                )
                .map_err(|e| CoreError::Storage(format!("prepare: {e}")))?;
            collect_rows(mapped)?
        };

        let has_more = rows.len() as i64 > limit;
        if has_more {
            rows.pop();
        }
        let next_cursor = rows
            .last()
            .map(|row| TimeCursor {
                seconds: row.chosen_seconds.unwrap_or(0),
                nanos: row.chosen_nanos,
                event_id: row.event_id.clone(),
            })
            .filter(|_| has_more);
        Ok(EventPage {
            rows,
            next_cursor,
            display_timezone: display_timezone.to_string(),
        })
    }
}

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<EventRow> {
    Ok(EventRow {
        event_id: row.get(0)?,
        revision: row.get(1)?,
        kind: row.get(2)?,
        summary: row.get(3)?,
        host_claim: row.get(4)?,
        chosen_seconds: row.get(5)?,
        chosen_nanos: row.get(6)?,
        time_status: row.get(7)?,
    })
}

fn collect_rows<'stmt, F>(mapped: rusqlite::MappedRows<'stmt, F>) -> CoreResult<Vec<EventRow>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<EventRow>,
{
    mapped
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CoreError::Storage(format!("query: {e}")))
}

fn parse_job_kind(name: &str) -> JobKind {
    match name {
        "acquisition" => JobKind::Acquisition,
        "parse" => JobKind::Parse,
        "analysis" => JobKind::Analysis,
        "export" => JobKind::Export,
        _ => JobKind::Parse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_kind_parses_round_trip() {
        for kind in [
            JobKind::Acquisition,
            JobKind::Parse,
            JobKind::Analysis,
            JobKind::Export,
        ] {
            assert_eq!(parse_job_kind(kind.as_str()), kind);
        }
    }
}

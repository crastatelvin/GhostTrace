//! Read-side connections and the shared query contract (plan Sections 8, 9).
//!
//! Readers get their own connection with short, read-only transactions and
//! never write. Keyset pagination gives a total order — identical-time events
//! paginate without skips or duplicates — and unknown times stay reachable in
//! an explicit unresolved view instead of being silently dropped.

use std::path::Path;

use rusqlite::Connection;
use rusqlite::OptionalExtension;

use crate::domain::detail::{
    EntityRef, EventDetail, EventTimeDetail, Histogram, HistogramBin, ObservationDetail,
    RunDiagnostic,
};
use crate::domain::query::{EventPage, EventQuery, EventRow, TimeCursor};
use crate::error::{CoreError, CoreResult};
use crate::jobs::{JobKind, JobState, RecoverableJob};
use crate::storage::search::FtsQuery;

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

    /// Newest chosen instant, used as the anchor for relative ranges such as
    /// `--last 24h`. Scoped to one revision when given, so the window ends at
    /// the newest event the same view can see; `None` when there is no
    /// resolved time.
    pub fn latest_chosen_seconds(&self, revision: Option<&str>) -> CoreResult<Option<i64>> {
        self.connection
            .query_row(
                "SELECT max(chosen_seconds) FROM events
                 WHERE chosen_seconds IS NOT NULL
                   AND (?1 IS NULL OR revision = ?1)",
                [revision],
                |row| row.get(0),
            )
            .map_err(|e| CoreError::Storage(format!("latest time: {e}")))
    }

    /// The newest parse run (revision) of one acquisition, or of the latest
    /// acquisition when `acquisition_id` is `None`. `None` when the case has
    /// no parse run at all.
    ///
    /// Each import records its own revision, so "the newest one" is what a
    /// timeline or report should show by default; earlier revisions stay
    /// selectable by id so an old result can be reproduced exactly.
    pub fn latest_revision(&self, acquisition_id: Option<&str>) -> CoreResult<Option<String>> {
        let connection = self.connection();
        let revision = connection
            .query_row(
                "SELECT p.id FROM parse_runs p
                 WHERE (?1 IS NULL OR p.acquisition_id = ?1)
                   AND (?1 IS NOT NULL OR p.acquisition_id = (
                        SELECT id FROM acquisitions
                        ORDER BY started_seconds DESC, id DESC LIMIT 1))
                 ORDER BY p.rowid DESC
                 LIMIT 1",
                [acquisition_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| CoreError::Storage(format!("latest revision: {e}")))?;
        Ok(revision)
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

    /// One event with everything the inspector shows: raw observations and
    /// their locators, every recorded time with assumptions, scoped entities,
    /// and the producing parse run. A missing source link is reported, never
    /// guessed.
    pub fn event_detail(&self, revision: &str, event_id: &str) -> CoreResult<EventDetail> {
        let (event, parse_run_id, evidence_id, locator_identity) = self
            .connection
            .query_row(
                "SELECT id, revision, kind, summary, host_claim, chosen_seconds,
                        chosen_nanos, time_status, parse_run_id, evidence_id,
                        locator_identity
                 FROM events
                 WHERE revision = ?1 AND id = ?2",
                rusqlite::params![revision, event_id],
                |row| {
                    Ok((
                        row_to_event(row)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Option<String>>(10)?,
                    ))
                },
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => {
                    CoreError::InvalidInput(format!("no event {event_id} in revision {revision}"))
                }
                other => CoreError::Storage(format!("read event: {other}")),
            })?;

        let (parser_id, parser_version, diagnostics_json, assumptions_json) = self
            .connection
            .query_row(
                "SELECT parser_id, parser_version, diagnostics_json, assumptions_json
                 FROM parse_runs WHERE id = ?1",
                [&parse_run_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .map_err(|error| CoreError::Storage(format!("read parse run: {error}")))?;
        let run_diagnostics: Vec<RunDiagnostic> =
            serde_json::from_str(&diagnostics_json).map_err(|error| {
                CoreError::Storage(format!(
                    "recorded parse diagnostics are unreadable: {error}"
                ))
            })?;

        let source_linked = evidence_id.is_some() && locator_identity.is_some();
        let mut observations = Vec::new();
        if let (Some(evidence_id), Some(locator_identity)) = (&evidence_id, &locator_identity) {
            let mut statement = self
                .connection
                .prepare_cached(
                    "SELECT r.evidence_id, r.acquisition_id, o.native_path_encoded,
                            r.locator_kind, r.locator_identity, r.raw_fields_json
                     FROM raw_observations r
                     JOIN evidence_objects o ON o.id = r.evidence_id
                     WHERE r.parse_run_id = ?1 AND r.evidence_id = ?2
                       AND r.locator_identity = ?3
                     ORDER BY r.id",
                )
                .map_err(|error| CoreError::Storage(format!("prepare observations: {error}")))?;
            let rows = statement
                .query_map(
                    rusqlite::params![parse_run_id, evidence_id, locator_identity],
                    |row| {
                        Ok(ObservationDetail {
                            evidence_id: row.get(0)?,
                            acquisition_id: row.get(1)?,
                            evidence_path: row.get(2)?,
                            locator_kind: row.get(3)?,
                            locator_identity: row.get(4)?,
                            raw_fields_json: row.get(5)?,
                        })
                    },
                )
                .map_err(|error| CoreError::Storage(format!("read observations: {error}")))?;
            observations = rows
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| CoreError::Storage(format!("read observations: {error}")))?;
        }

        let mut statement = self
            .connection
            .prepare_cached(
                "SELECT name, semantic, status, candidates_json, raw_field,
                        raw_value_kind, raw_value_text, raw_text, epoch, unit,
                        declared_precision, clock_domain, assumptions_json
                 FROM event_times WHERE event_id = ?1 ORDER BY id",
            )
            .map_err(|error| CoreError::Storage(format!("prepare times: {error}")))?;
        let rows = statement
            .query_map([event_id], |row| {
                let raw_value_kind: Option<String> = row.get(5)?;
                let raw_value = if raw_value_kind.as_deref() == Some("integer") {
                    row.get::<_, Option<String>>(6)?
                } else {
                    row.get::<_, Option<String>>(7)?
                };
                Ok(EventTimeDetail {
                    name: row.get(0)?,
                    semantic: row.get(1)?,
                    status: row.get(2)?,
                    candidates_json: row.get(3)?,
                    raw_field: row.get(4)?,
                    raw_value_kind,
                    raw_value,
                    epoch: row.get(8)?,
                    unit: row.get(9)?,
                    declared_precision: row.get(10)?,
                    clock_domain: row.get(11)?,
                    assumptions_json: row.get(12)?,
                })
            })
            .map_err(|error| CoreError::Storage(format!("read times: {error}")))?;
        let times = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| CoreError::Storage(format!("read times: {error}")))?;

        let mut statement = self
            .connection
            .prepare_cached(
                "SELECT en.id, en.kind, en.display_form, ee.role
                 FROM event_entities ee
                 JOIN entities en ON en.id = ee.entity_id
                 WHERE ee.event_id = ?1
                 ORDER BY en.kind, en.display_form, ee.role",
            )
            .map_err(|error| CoreError::Storage(format!("prepare entities: {error}")))?;
        let rows = statement
            .query_map([event_id], |row| {
                Ok(EntityRef {
                    entity_id: row.get(0)?,
                    kind: row.get(1)?,
                    display_form: row.get(2)?,
                    role: row.get(3)?,
                })
            })
            .map_err(|error| CoreError::Storage(format!("read entities: {error}")))?;
        let entities = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| CoreError::Storage(format!("read entities: {error}")))?;

        Ok(EventDetail {
            event,
            parse_run_id,
            parser_id,
            parser_version,
            source_linked,
            observations,
            times,
            entities,
            run_diagnostics,
            run_assumptions_json: assumptions_json,
        })
    }

    /// Bounded time histogram over the same filters as [`Self::query_events`],
    /// optionally restricted to FTS matches. Events without a chosen time
    /// cannot be binned and are counted separately.
    pub fn event_histogram(
        &self,
        query: &EventQuery,
        text: Option<&FtsQuery>,
        bins: u32,
    ) -> CoreResult<Histogram> {
        let bins = bins.clamp(4, 120);
        // The FTS subquery drives the join. A plain `JOIN events_fts ON ...`
        // lets SQLite pick the timeline index and evaluate MATCH once per
        // event, which turns a rare-term search into a full revision scan.
        // CROSS JOIN is SQLite's documented way to pin that join order.
        let (source, link) = if text.is_some() {
            (
                "(SELECT rowid FROM events_fts WHERE events_fts MATCH :match_text) AS m
                 CROSS JOIN events AS e",
                "e.rowid = m.rowid",
            )
        } else {
            ("events AS e", "1 = 1")
        };
        let filters = "e.revision = :revision
            AND (:kind IS NULL OR e.kind = :kind)
            AND (:host IS NULL OR e.host_claim = :host)
            AND (:source IS NULL OR EXISTS (
                  SELECT 1 FROM parse_runs p
                  WHERE p.id = e.parse_run_id AND p.parser_id = :source))";

        let base_params = || -> Vec<(&'static str, Box<dyn rusqlite::ToSql>)> {
            let mut params: Vec<(&'static str, Box<dyn rusqlite::ToSql>)> = vec![
                (":revision", Box::new(query.revision.clone())),
                (":kind", Box::new(query.kind.clone())),
                (":host", Box::new(query.host.clone())),
                (":source", Box::new(query.source.clone())),
            ];
            if let Some(text) = text {
                params.push((":match_text", Box::new(text.expression.clone())));
            }
            params
        };

        let unresolved_sql = format!(
            "SELECT count(*) FROM {source}
             WHERE {link} AND {filters} AND e.chosen_seconds IS NULL"
        );
        let unresolved: i64 =
            self.histogram_row(&unresolved_sql, &base_params(), |row| row.get(0))?;
        let unresolved_count = u64::try_from(unresolved).unwrap_or(0);

        if query.unresolved_only {
            return Ok(Histogram {
                bin_seconds: 1,
                from_seconds: query.after_seconds.unwrap_or(0),
                to_seconds: query.before_seconds.unwrap_or(0),
                bins: Vec::new(),
                unresolved_count,
                total: unresolved_count,
            });
        }

        let bounds_sql = format!(
            "SELECT min(e.chosen_seconds), max(e.chosen_seconds)
             FROM {source}
             WHERE {link} AND {filters}
               AND e.chosen_seconds IS NOT NULL
               AND (:after_seconds IS NULL OR e.chosen_seconds >= :after_seconds)
               AND (:before_seconds IS NULL OR e.chosen_seconds < :before_seconds)"
        );
        let mut bounds_params = base_params();
        bounds_params.push((":after_seconds", Box::new(query.after_seconds)));
        bounds_params.push((":before_seconds", Box::new(query.before_seconds)));
        let (min, max): (Option<i64>, Option<i64>) =
            self.histogram_row(&bounds_sql, &bounds_params, |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;

        let from = query.after_seconds.or(min);
        let to = query
            .before_seconds
            .or(max.map(|max| max.saturating_add(1)));
        let (Some(from), Some(to)) = (from, to) else {
            return Ok(Histogram {
                bin_seconds: 1,
                from_seconds: 0,
                to_seconds: 0,
                bins: Vec::new(),
                unresolved_count,
                total: unresolved_count,
            });
        };
        if to <= from {
            return Ok(Histogram {
                bin_seconds: 1,
                from_seconds: from,
                to_seconds: to.max(from),
                bins: Vec::new(),
                unresolved_count,
                total: unresolved_count,
            });
        }

        let span = to - from;
        let bin_seconds = (span + i64::from(bins) - 1) / i64::from(bins);
        let bin_seconds = bin_seconds.max(1);
        let bin_count = (span + bin_seconds - 1) / bin_seconds;
        let counts_sql = format!(
            "SELECT ((e.chosen_seconds - :from_seconds) / :bin_seconds) AS bin,
                    count(*)
             FROM {source}
             WHERE {link} AND {filters}
               AND e.chosen_seconds >= :from_seconds
               AND e.chosen_seconds < :to_seconds
             GROUP BY bin ORDER BY bin"
        );
        let mut counts_params = base_params();
        counts_params.push((":from_seconds", Box::new(from)));
        counts_params.push((":to_seconds", Box::new(to)));
        counts_params.push((":bin_seconds", Box::new(bin_seconds)));
        let counts = self.histogram_counts(&counts_sql, &counts_params)?;

        let bins_out: Vec<HistogramBin> = (0..bin_count)
            .map(|index| {
                let start = from + bin_seconds * index;
                HistogramBin {
                    start_seconds: start,
                    end_seconds: start + bin_seconds,
                    count: counts
                        .iter()
                        .find(|(bin, _)| *bin == index)
                        .map_or(0, |(_, count)| *count),
                }
            })
            .collect();
        let binned: u64 = bins_out.iter().map(|bin| bin.count).sum();
        Ok(Histogram {
            bin_seconds,
            from_seconds: from,
            to_seconds: to,
            bins: bins_out,
            unresolved_count,
            total: binned + unresolved_count,
        })
    }

    fn histogram_row<T>(
        &self,
        sql: &str,
        params: &[(&'static str, Box<dyn rusqlite::ToSql>)],
        map: impl FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    ) -> CoreResult<T> {
        let refs: Vec<(&str, &dyn rusqlite::ToSql)> = params
            .iter()
            .map(|(name, value)| (*name, value.as_ref()))
            .collect();
        self.connection
            .query_row(sql, &refs[..], map)
            .map_err(|error| CoreError::Storage(format!("histogram: {error}")))
    }

    fn histogram_counts(
        &self,
        sql: &str,
        params: &[(&'static str, Box<dyn rusqlite::ToSql>)],
    ) -> CoreResult<Vec<(i64, u64)>> {
        let refs: Vec<(&str, &dyn rusqlite::ToSql)> = params
            .iter()
            .map(|(name, value)| (*name, value.as_ref()))
            .collect();
        let mut statement = self
            .connection
            .prepare_cached(sql)
            .map_err(|error| CoreError::Storage(format!("prepare histogram: {error}")))?;
        let rows = statement
            .query_map(&refs[..], |row| {
                let count: i64 = row.get(1)?;
                Ok((row.get::<_, i64>(0)?, u64::try_from(count).unwrap_or(0)))
            })
            .map_err(|error| CoreError::Storage(format!("read histogram: {error}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| CoreError::Storage(format!("read histogram: {error}")))
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

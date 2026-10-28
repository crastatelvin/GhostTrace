//! Full-text search and reviewed time normalization (plan Sections 6, 13; P4.4).
//!
//! Search runs over an FTS5 external-content index whose text is read from the
//! `events` table at query time. The index is a projection, so a rebuild cannot
//! change or lose a recorded fact; it only re-derives what to search.
//!
//! Rules embodied here:
//! - The search text is validated against a small, documented grammar and
//!   then passed to FTS5 as a **bound parameter**. No user text is ever
//!   concatenated into SQL, and no structured filter accepts free-form
//!   operators (plan Section 13: no arbitrary SQL).
//! - Structured filters (`kind`, `host`, `source`, `after`, `before`,
//!   `revision`) are exact matches bound as parameters.
//! - Results use the same keyset order as the timeline — chosen time, then
//!   nanos, then event id — so pagination never skips or repeats across pages.
//! - Search answers only indexable event text (`summary`, `kind`, `host`);
//!   raw field values are reached through the timeline and event detail, not
//!   through this index.

use rusqlite::Connection;

use crate::domain::query::{EventPage, EventQuery, TimeCursor};
use crate::error::{CoreError, CoreResult};
use crate::storage::read::CaseReader;

/// Hard bound on search text length (plan Section 13: search input ≤ 4 KiB).
pub const MAX_SEARCH_INPUT_BYTES: usize = 4 << 10;

/// The validated query as passed to FTS5 `MATCH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtsQuery {
    /// The original operator text, kept for honest echo in results.
    pub input: String,
    /// The validated FTS5 expression, always bound as a parameter.
    pub expression: String,
}

/// Clear and rebuild the FTS5 external-content index from the recorded events.
/// Deleting the index rows first makes a stale entry impossible to resurrect:
/// `rebuild` truncates and re-reads `events` in one statement.
pub fn rebuild_index(connection: &Connection) -> CoreResult<()> {
    connection
        .execute_batch("INSERT INTO events_fts(events_fts) VALUES('delete-all');")
        .map_err(|e| CoreError::Storage(format!("search index clear: {e}")))?;
    connection
        .execute_batch("INSERT INTO events_fts(events_fts) VALUES('rebuild');")
        .map_err(|e| CoreError::Storage(format!("search index rebuild: {e}")))?;
    Ok(())
}

/// Validate operator search text into a safe FTS5 expression.
///
/// Grammar (documented, deliberately tiny): bare words, quoted phrases, and
/// `-` immediately before a word or phrase to exclude it. Everything else is
/// rejected rather than guessed at. A quoted phrase is passed through verbatim
/// with internal quotes doubled, which is the FTS5 escape rule, so an operator
/// can never break out of the string.
///
/// The result never contains an operator FTS5 would accept as SQL or as a
/// column filter: `:` is rejected, so `col:term` syntax cannot appear, and
/// `NEAR`/`*`/`^` are rejected too.
pub fn validate_search_text(input: &str) -> CoreResult<FtsQuery> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidInput(
            "search text must not be empty".to_string(),
        ));
    }
    if trimmed.len() > MAX_SEARCH_INPUT_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "search text must be at most {MAX_SEARCH_INPUT_BYTES} bytes"
        )));
    }

    let mut expression = String::new();
    let mut chars = trimmed.chars().peekable();
    while let Some(&char) = chars.peek() {
        if char.is_whitespace() {
            chars.next();
            continue;
        }
        let negated = if char == '-' {
            // Only a leading `-` on a term excludes it; elsewhere it is part
            // of a word (host names, domains, hyphenated tokens).
            chars.next();
            true
        } else {
            false
        };
        if negated && expression.is_empty() {
            return Err(CoreError::InvalidInput(
                "search text may not start with an exclusion".to_string(),
            ));
        }
        let term = if chars.peek() == Some(&'"') {
            read_quoted_phrase(&mut chars)?
        } else {
            read_bare_word(&mut chars)?
        };
        if term.text.is_empty() {
            return Err(CoreError::InvalidInput(
                "search text contains an empty term".to_string(),
            ));
        }
        if negated {
            if !expression.is_empty() {
                expression.push(' ');
            }
            expression.push_str("NOT ");
        } else if !expression.is_empty() {
            expression.push(' ');
        }
        // A quoted FTS5 string: internal quotes doubled. An unquoted word
        // needs no escaping because the grammar allowed no FTS5 specials.
        if term.is_quoted {
            expression.push('"');
            // FTS5 string escaping: an internal quote is doubled. The phrase
            // text holds one quote per literal quote, so doubling here is the
            // complete escape — nothing else about the phrase is reinterpreted.
            for char in term.text.chars() {
                expression.push(char);
                if char == '"' {
                    expression.push('"');
                }
            }
            expression.push('"');
        } else {
            expression.push_str(&term.text);
        }
    }

    if expression.is_empty() {
        return Err(CoreError::InvalidInput(
            "search text has no searchable terms".to_string(),
        ));
    }
    Ok(FtsQuery {
        input: trimmed.to_string(),
        expression,
    })
}

struct FtsTerm {
    text: String,
    is_quoted: bool,
}

fn read_bare_word(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> CoreResult<FtsTerm> {
    let mut word = String::new();
    while let Some(&char) = chars.peek() {
        if char.is_whitespace() {
            break;
        }
        match char {
            // FTS5 specials that would change the parse; rejected, never
            // escaped-and-hoped-for.
            '"' | ':' | '*' | '^' | '(' | ')' | '{' | '}' | '[' | ']' | '\\' => {
                return Err(CoreError::InvalidInput(format!(
                    "search text may not contain `{char}`; use a quoted phrase to search for it"
                )));
            }
            _ => word.push(char),
        }
        chars.next();
    }
    if word.eq_ignore_ascii_case("AND")
        || word.eq_ignore_ascii_case("OR")
        || word.eq_ignore_ascii_case("NOT")
        || word.eq_ignore_ascii_case("NEAR")
    {
        return Err(CoreError::InvalidInput(format!(
            "`{word}` is an FTS5 operator and is not accepted as search text"
        )));
    }
    Ok(FtsTerm {
        text: word,
        is_quoted: false,
    })
}

fn read_quoted_phrase(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> CoreResult<FtsTerm> {
    // Consume the opening quote.
    chars.next();
    let mut phrase = String::new();
    loop {
        match chars.next() {
            None => {
                return Err(CoreError::InvalidInput(
                    "search text has an unterminated quote".to_string(),
                ));
            }
            Some('"') => {
                // A doubled quote is a literal quote inside the phrase.
                if chars.peek() == Some(&'"') {
                    phrase.push('"');
                    chars.next();
                } else {
                    break;
                }
            }
            Some(other) => {
                if other.is_control() {
                    return Err(CoreError::InvalidInput(
                        "search text may not contain control characters".to_string(),
                    ));
                }
                phrase.push(other);
            }
        }
    }
    Ok(FtsTerm {
        text: phrase,
        is_quoted: true,
    })
}

/// Search over the indexed event text with the timeline's structured filters.
///
/// The full-text condition is combined with the parameterized filters of
/// `EventQuery`; the statements are fixed and every value — including the
/// validated FTS5 expression — is bound. Page order is the timeline's total
/// order (chosen time, nanos, event id), so results never skip or repeat.
pub fn search_events(
    reader: &CaseReader,
    display_timezone: &str,
    query: &EventQuery,
    text: &FtsQuery,
) -> CoreResult<EventPage> {
    let limit = i64::from(query.effective_limit());
    let cursor = query.after.clone().unwrap_or(TimeCursor {
        seconds: 0,
        nanos: 0,
        event_id: String::new(),
    });
    let mut rows = if query.unresolved_only {
        let mut statement = reader
            .connection()
            .prepare_cached(
                "SELECT e.id, e.revision, e.kind, e.summary, e.host_claim,
                        e.chosen_seconds, e.chosen_nanos, e.time_status
                 FROM events AS e
                 JOIN events_fts ON events_fts.rowid = e.rowid
                 WHERE events_fts MATCH ?1
                   AND e.revision = ?2 AND e.chosen_seconds IS NULL
                   AND (?3 IS NULL OR e.kind = ?3)
                   AND (?4 IS NULL OR e.host_claim = ?4)
                   AND (?5 IS NULL OR EXISTS (
                         SELECT 1 FROM parse_runs p
                         WHERE p.id = e.parse_run_id AND p.parser_id = ?5))
                   AND e.id > ?6
                 ORDER BY e.id
                 LIMIT ?7",
            )
            .map_err(|e| CoreError::Storage(format!("search prepare: {e}")))?;
        let mapped = statement
            .query_map(
                rusqlite::params![
                    text.expression,
                    query.revision,
                    query.kind,
                    query.host,
                    query.source,
                    cursor.event_id,
                    limit + 1,
                ],
                search_row,
            )
            .map_err(|e| CoreError::Storage(format!("search: {e}")))?;
        mapped
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CoreError::Storage(format!("search: {e}")))?
    } else {
        let mut statement = reader
            .connection()
            .prepare_cached(
                "SELECT e.id, e.revision, e.kind, e.summary, e.host_claim,
                        e.chosen_seconds, e.chosen_nanos, e.time_status
                 FROM events AS e
                 JOIN events_fts ON events_fts.rowid = e.rowid
                 WHERE events_fts MATCH ?1
                   AND e.revision = ?2 AND e.chosen_seconds IS NOT NULL
                   AND (?3 IS NULL OR e.kind = ?3)
                   AND (?4 IS NULL OR e.host_claim = ?4)
                   AND (?5 IS NULL OR e.chosen_seconds >= ?5)
                   AND (?6 IS NULL OR e.chosen_seconds < ?6)
                   AND (?7 IS NULL OR EXISTS (
                         SELECT 1 FROM parse_runs p
                         WHERE p.id = e.parse_run_id AND p.parser_id = ?7))
                   AND (e.chosen_seconds > ?8
                        OR (e.chosen_seconds = ?8 AND (e.chosen_nanos > ?9
                                                       OR (e.chosen_nanos = ?9
                                                           AND e.id > ?10))))
                 ORDER BY e.chosen_seconds, e.chosen_nanos, e.id
                 LIMIT ?11",
            )
            .map_err(|e| CoreError::Storage(format!("search prepare: {e}")))?;
        let mapped = statement
            .query_map(
                rusqlite::params![
                    text.expression,
                    query.revision,
                    query.kind,
                    query.host,
                    query.after_seconds,
                    query.before_seconds,
                    query.source,
                    cursor.seconds,
                    cursor.nanos,
                    cursor.event_id,
                    limit + 1,
                ],
                search_row,
            )
            .map_err(|e| CoreError::Storage(format!("search: {e}")))?;
        mapped
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CoreError::Storage(format!("search: {e}")))?
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

fn search_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<crate::domain::query::EventRow> {
    Ok(crate::domain::query::EventRow {
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

/// The recorded time assumptions of one revision, for the review view.
pub fn recorded_assumptions(
    reader: &CaseReader,
    revision: &str,
) -> CoreResult<Vec<crate::domain::time::TimeAssumption>> {
    let connection = reader.connection();
    let text: String = connection
        .query_row(
            "SELECT assumptions_json FROM parse_runs WHERE id = ?1",
            [revision],
            |row| row.get(0),
        )
        .map_err(|e| CoreError::Storage(format!("parse run assumptions: {e}")))?;
    serde_json::from_str(&text).map_err(|e| CoreError::Storage(format!("assumptions json: {e}")))
}

/// Revisions of one acquisition, newest first (insertion order, not id order),
/// with their event counts. This is what makes a re-import explicit: the
/// operator sees every recorded revision and the assumptions each one
/// carries, and the newest one is the default report/timeline revision.
pub fn list_revisions(
    reader: &CaseReader,
    acquisition_id: &str,
) -> CoreResult<Vec<crate::domain::query::RevisionSummary>> {
    let mut statement = reader
        .connection()
        .prepare_cached(
            "SELECT id, parser_id, parser_version, config_digest, state,
                    (SELECT count(*) FROM events WHERE revision = parse_runs.id)
             FROM parse_runs WHERE acquisition_id = ?1
             ORDER BY rowid DESC",
        )
        .map_err(|e| CoreError::Storage(format!("revisions: {e}")))?;
    let rows = statement
        .query_map([acquisition_id], |row| {
            Ok(crate::domain::query::RevisionSummary {
                run_id: row.get(0)?,
                parser_id: row.get(1)?,
                parser_version: row.get(2)?,
                config_digest: row.get(3)?,
                state: row.get(4)?,
                events: row.get::<_, i64>(5)?.max(0) as u64,
            })
        })
        .map_err(|e| CoreError::Storage(format!("revisions: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CoreError::Storage(format!("revisions: {e}")))?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_words_bind_as_one_expression() {
        let query = validate_search_text("  browser visit  ").unwrap();
        assert_eq!(query.expression, "browser visit");
    }

    #[test]
    fn quoted_phrases_and_exclusions_are_expressed_not_injected() {
        let query = validate_search_text("visit -\"acme login\"").unwrap();
        assert_eq!(query.expression, "visit NOT \"acme login\"");
    }

    #[test]
    fn internal_quotes_are_doubled_in_a_phrase() {
        let query = validate_search_text("\"say \"\"hi\"\"\"").unwrap();
        assert_eq!(query.expression, "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn a_hyphen_inside_a_word_is_not_an_exclusion() {
        let query = validate_search_text("host-a").unwrap();
        assert_eq!(query.expression, "host-a");
    }

    #[test]
    fn operators_and_column_syntax_are_rejected() {
        for bad in [
            "",
            "   ",
            "\"unterminated",
            "col:term",
            "prefix*",
            "a AND b",
            "NEAR",
            "a b\\c",
        ] {
            let error = validate_search_text(bad).unwrap_err();
            assert!(
                matches!(error, CoreError::InvalidInput(_)),
                "{bad} should be rejected, got {error:?}"
            );
        }
    }

    #[test]
    fn search_text_is_bounded() {
        let long = "word ".repeat(2_000);
        let error = validate_search_text(&long).unwrap_err();
        assert!(matches!(error, CoreError::InvalidInput(_)));
    }
}

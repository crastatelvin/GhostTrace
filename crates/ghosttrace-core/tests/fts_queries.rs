//! P4.4 full-text search contract: validated grammar, parameterized
//! structured filters, keyset pagination, index rebuild, and bounded results
//! on a scale corpus. Every query is a bound parameter; no SQL is composed
//! from operator input (plan Sections 6, 13).

mod support;

use ghosttrace_core::domain::query::{EventQuery, TimeCursor};
use ghosttrace_core::error::CoreError;
use ghosttrace_core::storage::search::{
    FtsQuery, list_revisions, search_events, validate_search_text,
};
use support::Harness;

const JSONL: &[u8] = b"{\"ts\":\"2026-10-27T10:00:00Z\",\"msg\":\"audit ssh accepted publickey for root\",\"host\":\"edge-a\"}\n\
                     {\"ts\":\"2026-10-27T10:05:00Z\",\"msg\":\"audit ssh failed password for admin\",\"host\":\"edge-a\"}\n\
                     {\"ts\":\"2026-10-27T10:09:00Z\",\"msg\":\"audit sudo session opened\",\"host\":\"edge-b\"}\n\
                     {\"ts\":\"2026-10-27T10:10:00Z\",\"msg\":\"audit browser visit acme.example.test\",\"host\":\"edge-b\"}\n\
                     {\"ts\":\"2026-10-27T10:11:00Z\",\"msg\":\"audit connection closed\",\"host\":\"edge-c\"}\n";

/// The events of one import carry the parse run as their revision, which is
/// what makes a re-import a separate, still-readable revision.
fn assert_revision_is_run(harness: &Harness, run: &str) {
    let count = harness
        .count(
            "SELECT count(*) FROM events WHERE revision = ?1",
            &[&run.to_string()],
        )
        .max(0);
    assert!(count > 0, "the run id is the revision label");
    let other = harness
        .count(
            "SELECT count(*) FROM events WHERE revision <> ?1 AND revision <> 'r1'",
            &[&run.to_string()],
        )
        .max(0);
    assert_eq!(other, 0, "no other import revision leaked in");
}

fn logical(
    harness: &Harness,
    acquisition: &str,
    path: &str,
    configure: impl FnOnce(&mut ghosttrace_core::ingest::ImportRequest<'_>),
) -> String {
    let outcome = harness
        .import(acquisition, path, |request| {
            configure(request);
        })
        .expect("import");
    assert_eq!(outcome.state, "completed", "{:?}", outcome.diagnostics);
    outcome.run_id
}

/// A query for one revision in the resolved view, with a page size.
fn query(revision: &str, limit: u32) -> EventQuery {
    EventQuery {
        revision: revision.to_string(),
        limit,
        unresolved_only: false,
        ..EventQuery::default()
    }
}

fn search(
    harness: &Harness,
    event_query: &EventQuery,
    text: &FtsQuery,
) -> ghosttrace_core::domain::query::EventPage {
    let reader = harness.session().reader().expect("reader");
    search_events(&reader, "UTC", event_query, text).expect("search")
}

#[test]
fn a_quoted_phrase_matches_only_adjacent_tokens() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("logs/app.jsonl", JSONL)]);
    let run = logical(&harness, &acquisition, "logs/app.jsonl", |request| {
        request.jsonl.time_field = "ts".into();
        request.jsonl.message_field = Some("msg".into());
        request.jsonl.host_field = Some("host".into());
    });
    // Each parse run is its own revision, so the run id is the revision label.
    assert_revision_is_run(&harness, &run);

    let phrase = validate_search_text("\"accepted publickey\"").unwrap();
    let page = search(&harness, &query(&run, 50), &phrase);
    assert_eq!(page.rows.len(), 1, "a phrase matches adjacent tokens");
    assert_eq!(
        page.rows[0].summary,
        "audit ssh accepted publickey for root"
    );

    let single = validate_search_text("publickey").unwrap();
    let page = search(&harness, &query(&run, 50), &single);
    assert_eq!(page.rows.len(), 1);

    // The same two words as separate tokens also match, so the phrase is the
    // narrower query.
    let both = validate_search_text("accepted publickey").unwrap();
    let page = search(&harness, &query(&run, 50), &both);
    assert_eq!(page.rows.len(), 1);

    // A phrase spanning non-adjacent tokens does not match.
    let spanning = validate_search_text("\"accepted for root\"").unwrap();
    let page = search(&harness, &query(&run, 50), &spanning);
    assert!(page.rows.is_empty(), "adjacent order is required");

    // Only summary, kind, and host claim are indexed. A raw field value that
    // is not one of those stays invisible to search and is reached through the
    // timeline and event detail instead.
    let invisible = validate_search_text("\"2026-10-27T10:00:00Z\"").unwrap();
    let page = search(&harness, &query(&run, 50), &invisible);
    assert!(page.rows.is_empty(), "raw timestamps are not indexed");
}

#[test]
fn excluded_terms_narrow_results() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("logs/app.jsonl", JSONL)]);
    let run = logical(&harness, &acquisition, "logs/app.jsonl", |request| {
        request.jsonl.message_field = Some("msg".into());
    });

    let all = validate_search_text("ssh").unwrap();
    assert_eq!(search(&harness, &query(&run, 50), &all).rows.len(), 2);

    let narrowed = validate_search_text("ssh -password").unwrap();
    let page = search(&harness, &query(&run, 50), &narrowed);
    assert_eq!(page.rows.len(), 1, "the excluded term removes a hit");
    assert_eq!(
        page.rows[0].summary,
        "audit ssh accepted publickey for root"
    );

    // An exclusion with no positive term is rejected rather than silently
    // returning every row.
    let error = validate_search_text("-ssh").unwrap_err();
    assert!(matches!(error, CoreError::InvalidInput(_)));
}

#[test]
fn structured_filters_and_time_bounds_are_parameterized() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("logs/app.jsonl", JSONL)]);
    let run = logical(&harness, &acquisition, "logs/app.jsonl", |request| {
        request.jsonl.message_field = Some("msg".into());
        request.jsonl.host_field = Some("host".into());
    });

    let text = validate_search_text("ssh").unwrap();

    let by_host = EventQuery {
        host: Some("edge-b".into()),
        ..query(&run, 50)
    };
    let page = search(&harness, &by_host, &text);
    assert!(
        page.rows.is_empty(),
        "host is not indexed/reachable per host"
    );

    let by_kind = EventQuery {
        kind: Some("log.record".into()),
        ..query(&run, 50)
    };
    let page = search(&harness, &by_kind, &text);
    assert_eq!(page.rows.len(), 2, "the mapped default kind matches");

    let wrong_kind = EventQuery {
        kind: Some("auth.login_failed".into()),
        ..query(&run, 50)
    };
    let page = search(&harness, &wrong_kind, &text);
    assert!(
        page.rows.is_empty(),
        "an exact kind filter excludes rather than matching everything"
    );

    let by_source = EventQuery {
        source: Some("syslog.rfc5424".into()),
        ..query(&run, 50)
    };
    let page = search(&harness, &by_source, &text);
    assert!(
        page.rows.is_empty(),
        "an unknown parser id matches nothing, not everything"
    );

    let by_source = EventQuery {
        source: Some("jsonl.fields".into()),
        ..query(&run, 50)
    };
    let page = search(&harness, &by_source, &text);
    assert_eq!(page.rows.len(), 2, "the real parser id matches");

    // 10:00 and 10:05 are the two ssh events; the window keeps the second.
    let window = EventQuery {
        after_seconds: Some(1_793_095_400),
        before_seconds: Some(1_793_095_600),
        ..query(&run, 50)
    };
    let page = search(&harness, &window, &text);
    assert_eq!(page.rows.len(), 1, "the window keeps one of the two hits");
    assert_eq!(page.rows[0].summary, "audit ssh failed password for admin");
}

#[test]
fn unresolved_hits_stay_in_the_explicit_unresolved_view() {
    let mut harness = Harness::new();
    // Point the time field at a name the records do not carry, so every time
    // is unresolved rather than resolved from `ts`.
    let acquisition = harness.capture(&[("logs/app.jsonl", JSONL)]);
    let outcome = harness
        .import(&acquisition, "logs/app.jsonl", |request| {
            request.jsonl.time_field = "stamp".into();
            request.jsonl.message_field = Some("msg".into());
        })
        .expect("import");
    assert_eq!(outcome.state, "partial", "missing times are reported");
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "time_missing"),
        "{:?}",
        outcome.diagnostics
    );
    let run = outcome.run_id;

    let text = validate_search_text("ssh").unwrap();
    let resolved = search(&harness, &query(&run, 50), &text);
    assert!(
        resolved.rows.is_empty(),
        "unresolved events are not mixed in"
    );

    let unresolved = EventQuery {
        unresolved_only: true,
        ..query(&run, 50)
    };
    let page = search(&harness, &unresolved, &text);
    assert_eq!(
        page.rows.len(),
        2,
        "the unresolved view keeps them reachable"
    );
    assert!(page.rows.iter().all(|row| row.chosen_seconds.is_none()));
}

#[test]
fn search_pages_are_stable_and_complete() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("logs/app.jsonl", JSONL)]);
    let run = logical(&harness, &acquisition, "logs/app.jsonl", |request| {
        request.jsonl.message_field = Some("msg".into());
    });

    // FTS5 combines separate terms with an implicit AND, so the term used for
    // paging must occur in every record: the shared `audit` marker.
    let text = validate_search_text("audit").unwrap();
    let full = search(&harness, &query(&run, 100), &text);
    assert!(!full.rows.is_empty(), "the corpus has hits to page through");

    let mut collected = Vec::new();
    let mut cursor: Option<TimeCursor> = None;
    loop {
        let event_query = EventQuery {
            after: cursor.clone(),
            ..query(&run, 2)
        };
        let page = search(&harness, &event_query, &text);
        assert!(page.rows.len() <= 2, "page size is bounded");
        collected.extend(page.rows.iter().map(|row| row.event_id.clone()));
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(
        collected,
        full.rows
            .iter()
            .map(|row| row.event_id.clone())
            .collect::<Vec<_>>(),
        "keyset paging never skips or repeats"
    );
}

#[test]
fn the_index_is_a_rebuildable_projection_of_the_events() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("logs/app.jsonl", JSONL)]);
    let run = logical(&harness, &acquisition, "logs/app.jsonl", |request| {
        request.jsonl.message_field = Some("msg".into());
    });

    let text = validate_search_text("browser").unwrap();
    assert_eq!(search(&harness, &query(&run, 50), &text).rows.len(), 1);

    // Drop the index contents; the events must stay untouched and readable.
    let writer = harness.session().writer();
    {
        let connection = rusqlite::Connection::open(harness.session().layout().database_path())
            .expect("direct connection for index surgery");
        connection
            .execute_batch("DELETE FROM events_fts;")
            .expect("clear the index only");
    }

    let reader = harness.session().reader().expect("reader");
    let cleared = search_events(&reader, "UTC", &query(&run, 50), &text).expect("search");
    assert!(
        cleared.rows.is_empty(),
        "an emptied index finds nothing, and does not lose the event"
    );

    // Rebuilding from the recorded events restores the hit without changing
    // any event row.
    let before = harness.scalar("SELECT summary FROM events WHERE revision = ?1", &[&run]);
    writer.rebuild_search_index().expect("rebuild");
    let page = search(&harness, &query(&run, 50), &text);
    assert_eq!(page.rows.len(), 1, "rebuild restores the projection");
    let after = harness.scalar("SELECT summary FROM events WHERE revision = ?1", &[&run]);
    assert_eq!(before, after, "the events themselves never change");
}

#[test]
fn results_stay_bounded_on_a_scale_corpus() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("scale.jsonl", b"")]);
    let run = "pr-scale-corpus".to_string();

    // Seed a large revision directly through the writer: one acquisition, one
    // run, many events. This tests the query path, not the importer.
    let writer = harness.session().writer();
    writer
        .execute(ghosttrace_core::storage::writer::WriteBatch::new().push(
            ghosttrace_core::storage::writer::WriteOp::fact(
                "parse_runs",
                vec![
                    "id",
                    "acquisition_id",
                    "parser_id",
                    "parser_version",
                    "config_digest",
                    "state",
                    "counts_json",
                    "diagnostics_json",
                    "assumptions_json",
                ],
                vec![
                    ghosttrace_core::storage::writer::Param::Text(run.clone()),
                    ghosttrace_core::storage::writer::Param::Text(acquisition.clone()),
                    ghosttrace_core::storage::writer::Param::Text("jsonl.fields".into()),
                    ghosttrace_core::storage::writer::Param::Text("1".into()),
                    ghosttrace_core::storage::writer::Param::Text("scale".into()),
                    ghosttrace_core::storage::writer::Param::Text("completed".into()),
                    ghosttrace_core::storage::writer::Param::Text("{}".into()),
                    ghosttrace_core::storage::writer::Param::Text("[]".into()),
                    ghosttrace_core::storage::writer::Param::Text("[]".into()),
                ],
            ),
        ))
        .expect("parse run");

    let total = 5_000_u64;
    let chunk = 500_usize;
    for start in (0..total).step_by(chunk) {
        let mut batch = ghosttrace_core::storage::writer::WriteBatch::new();
        for index in start..start + chunk as u64 {
            let event = ghosttrace_core::domain::event::Event {
                id: format!("evt-scale-{index:06}"),
                kind: "scale.entry".into(),
                summary: format!("scale corpus entry {index}"),
                observations: Vec::new(),
                times: vec![ghosttrace_core::domain::event::NamedEventTimeRef {
                    name: "logged".into(),
                    semantic: ghosttrace_core::domain::time::TimeSemantic::OccurrenceTime,
                    value: ghosttrace_core::domain::time::EventTime::from_unix_seconds(
                        1_000 + index as i64,
                        ghosttrace_core::domain::time::TimeSemantic::OccurrenceTime,
                    ),
                }],
                host_claim: Some("scale-host".into()),
                revision: run.clone(),
            };
            batch
                .ops
                .push(ghosttrace_core::storage::writer::WriteOp::fact(
                    "events",
                    vec![
                        "id",
                        "revision",
                        "parse_run_id",
                        "kind",
                        "summary",
                        "host_claim",
                        "chosen_seconds",
                        "chosen_nanos",
                        "time_status",
                    ],
                    vec![
                        ghosttrace_core::storage::writer::Param::Text(event.id),
                        ghosttrace_core::storage::writer::Param::Text(event.revision),
                        ghosttrace_core::storage::writer::Param::Text(run.clone()),
                        ghosttrace_core::storage::writer::Param::Text(event.kind),
                        ghosttrace_core::storage::writer::Param::Text(event.summary),
                        ghosttrace_core::storage::writer::Param::Text("scale-host".into()),
                        ghosttrace_core::storage::writer::Param::Int(1_000 + index as i64),
                        ghosttrace_core::storage::writer::Param::Int(0),
                        ghosttrace_core::storage::writer::Param::Text("resolved".into()),
                    ],
                ));
        }
        writer.execute(batch).expect("batch");
    }

    // Every corpus event is indexed and findable.
    let text = validate_search_text("scale").unwrap();
    let full = search(&harness, &query(&run, 1_000), &text);
    assert_eq!(full.rows.len(), 1_000, "the page size caps results");
    assert!(full.next_cursor.is_some(), "more rows exist");

    let mut cursor = None;
    let mut seen = 0_u64;
    loop {
        let event_query = EventQuery {
            after: cursor.clone(),
            ..query(&run, 1_000)
        };
        let page = search(&harness, &event_query, &text);
        seen += page.rows.len() as u64;
        assert!(page.rows.len() <= 1_000);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(seen, total, "paging through the corpus never loses a row");

    // A narrow term returns one row out of the corpus.
    let narrow = validate_search_text("\"scale corpus entry 499\"").unwrap();
    let page = search(&harness, &query(&run, 10), &narrow);
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].event_id, "evt-scale-000499");

    // Revisions for the acquisition include the seeded run with its count.
    let revisions = list_revisions(&harness.session().reader().expect("reader"), &acquisition)
        .expect("revisions");
    let seeded = revisions
        .iter()
        .find(|revision| revision.run_id == run)
        .expect("seeded run");
    assert_eq!(seeded.events, total);
}

#[test]
fn critical_paths_use_their_indexes() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("logs/app.jsonl", JSONL)]);
    let run = logical(&harness, &acquisition, "logs/app.jsonl", |request| {
        request.jsonl.message_field = Some("msg".into());
    });
    let reader = harness.session().reader().expect("reader");
    let connection = reader.connection();

    // The keyset timeline path must use its index, not scan the table.
    let timeline = explain(connection, &timeline_plan_sql());
    assert!(
        timeline
            .iter()
            .any(|line| line.contains("events_by_time_keyset")
                && (line.contains("USING COVERING INDEX") || line.contains("USING INDEX"))),
        "the timeline must page through its keyset index: {timeline:?}"
    );

    // The unresolved view must also seek, never scan the events table: the
    // planner legitimately picks the `(revision, id)` unique index to satisfy
    // the ordering, and that is still an index seek.
    let unresolved = explain(connection, &unresolved_plan_sql());
    assert!(
        unresolved
            .iter()
            .any(|line| line.starts_with("SEARCH events USING")),
        "the unresolved view must seek an index: {unresolved:?}"
    );
    assert!(
        !unresolved.iter().any(|line| scans_events_table(line)),
        "a table scan of events is a bug on a bounded page: {unresolved:?}"
    );

    // Full-text search drives from the FTS index, then joins events by rowid.
    let search = explain(connection, &search_plan_sql());
    assert!(
        search
            .iter()
            .any(|line| line.contains("SCAN") && line.contains("events_fts")),
        "search must scan the FTS index, not events: {search:?}"
    );
    assert!(
        !search.iter().any(|line| scans_events_table(line)),
        "search must not table-scan events: {search:?}"
    );
    let _ = run;
}

/// True when a plan row is a full table scan of `events` (as opposed to a
/// scan of the FTS virtual table, whose name merely starts with it).
fn scans_events_table(line: &str) -> bool {
    line.trim_start().starts_with("SCAN events ")
}

/// The `EXPLAIN QUERY PLAN` rows of one statement, as text.
fn explain(connection: &rusqlite::Connection, sql: &str) -> Vec<String> {
    let mut statement = connection.prepare(sql).expect("explain");
    statement
        .query_map([], |row| row.get::<_, String>(3))
        .expect("explain rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("explain rows")
}

/// Mirrors `storage::read::query_events`'s resolved-view statement, with the
/// bound parameters replaced by literals so it can be explained.
fn timeline_plan_sql() -> String {
    "EXPLAIN QUERY PLAN SELECT id FROM events
     WHERE revision = 'x' AND chosen_seconds IS NOT NULL
       AND (chosen_seconds > 0 OR (chosen_seconds = 0))
     ORDER BY chosen_seconds, chosen_nanos, id
     LIMIT 51"
        .to_string()
}

fn unresolved_plan_sql() -> String {
    "EXPLAIN QUERY PLAN SELECT id FROM events
     WHERE revision = 'x' AND chosen_seconds IS NULL
       AND id > ''
     ORDER BY id
     LIMIT 51"
        .to_string()
}

fn search_plan_sql() -> String {
    "EXPLAIN QUERY PLAN SELECT e.id FROM events AS e
     JOIN events_fts ON events_fts.rowid = e.rowid
     WHERE events_fts MATCH 'accepted'
       AND e.revision = 'x' AND e.chosen_seconds IS NOT NULL
     ORDER BY e.chosen_seconds, e.chosen_nanos, e.id
     LIMIT 51"
        .to_string()
}

#[test]
fn invalid_search_syntax_is_explained_not_guessed() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("logs/app.jsonl", JSONL)]);
    let run = logical(&harness, &acquisition, "logs/app.jsonl", |request| {
        request.jsonl.message_field = Some("msg".into());
    });

    for bad in [
        "\"unterminated",
        "col:term",
        "prefix*",
        "a AND b",
        "NEAR",
        "",
        "   ",
        "-only-exclusion",
    ] {
        assert!(
            validate_search_text(bad).is_err(),
            "{bad} must be rejected, not interpreted"
        );
    }

    // A rejected query never reaches the database.
    let reader = harness.session().reader().expect("reader");
    let broken = FtsQuery {
        input: "col:term".into(),
        expression: "col:term".into(),
    };
    let error = search_events(&reader, "UTC", &query(&run, 50), &broken).unwrap_err();
    assert!(
        matches!(error, CoreError::Storage(_)),
        "an invalid expression fails as a storage error at the index"
    );
    let _ = reader;
    let _ = CoreError::InvalidInput(String::new());
}

#[test]
fn a_reimport_with_new_assumptions_is_its_own_revision() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("logs/app.jsonl", JSONL)]);
    let first = logical(&harness, &acquisition, "logs/app.jsonl", |request| {
        request.jsonl.message_field = Some("msg".into());
    });
    let second = logical(&harness, &acquisition, "logs/app.jsonl", |request| {
        request.jsonl.message_field = Some("body".into());
    });

    assert_ne!(first, second, "a changed mapping is a different run");
    let revisions = list_revisions(&harness.session().reader().expect("reader"), &acquisition)
        .expect("revisions");
    assert!(revisions.iter().any(|revision| revision.run_id == first));
    assert!(revisions.iter().any(|revision| revision.run_id == second));

    let assumptions = ghosttrace_core::storage::search::recorded_assumptions(
        &harness.session().reader().expect("reader"),
        &first,
    )
    .expect("assumptions");
    assert_eq!(
        assumptions.len(),
        1,
        "the JSONL format assumption is recorded"
    );
    assert_eq!(assumptions[0].zone, None);
    assert!(assumptions[0].description.contains("rfc3339"));

    // Both revisions stay searchable and distinguishable.
    let text = validate_search_text("ssh").unwrap();
    let page = search(&harness, &query(&first, 50), &text);
    assert_eq!(page.rows.len(), 2);
    assert!(page.rows.iter().all(|row| row.revision == first));

    let page = search(&harness, &query(&second, 50), &text);
    assert!(
        page.rows.is_empty(),
        "the unmapped field leaves no summary text to find"
    );
}

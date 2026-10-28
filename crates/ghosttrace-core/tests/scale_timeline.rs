//! P6.2 responsiveness measurement against a real large case.
//!
//! Ignored by default: it needs a generated corpus. Point it at a case built
//! from the 1-million-event corpus and run with
//!
//! ```text
//! GHOSTTRACE_SCALE_CASE=/tmp/scale/case.ghosttrace-case \
//!   cargo test --release -p ghosttrace-core --test scale_timeline -- --ignored --nocapture
//! ```
//!
//! The bounds are deliberately loose (a slow CI disk is not a bug), but they
//! catch the regression that matters: a query that scans the whole revision
//! instead of using the recorded index or keyset cursor.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ghosttrace_core::domain::query::EventQuery;
use ghosttrace_core::service::CaseSession;

#[test]
#[ignore = "requires GHOSTTRACE_SCALE_CASE pointing at a generated large case"]
fn timeline_queries_stay_bounded_on_a_million_events() {
    let case = PathBuf::from(
        std::env::var("GHOSTTRACE_SCALE_CASE")
            .expect("set GHOSTTRACE_SCALE_CASE to a case directory"),
    );
    let (session, _report) = CaseSession::open(case).expect("open scale case");
    let revision = session
        .reader()
        .expect("reader")
        .latest_revision(None)
        .expect("revision")
        .expect("a parse run");
    let query = EventQuery {
        revision: revision.clone(),
        limit: 200,
        ..EventQuery::default()
    };

    let started = Instant::now();
    let first = session.query_events(&query).expect("first page");
    let first_page = started.elapsed();
    assert_eq!(first.rows.len(), 200);

    let started = Instant::now();
    let second = session
        .query_events(&EventQuery {
            after: first.next_cursor.clone(),
            ..query.clone()
        })
        .expect("second page");
    let second_page = started.elapsed();
    assert!(
        !second.rows.is_empty(),
        "keyset paging returns the next rows"
    );
    assert_ne!(
        first.rows[0].event_id, second.rows[0].event_id,
        "keyset paging does not repeat rows"
    );

    let started = Instant::now();
    let histogram = session
        .event_histogram(&query, None, 24)
        .expect("histogram");
    let histogram_time = started.elapsed();
    assert!(histogram.total > 0);

    let started = Instant::now();
    let detail = session
        .event_detail(&revision, &first.rows[0].event_id)
        .expect("detail");
    let detail_time = started.elapsed();
    assert!(detail.source_linked);
    assert_eq!(detail.observations.len(), 1);

    let started = Instant::now();
    let search = session
        .search_events(&query, "\"needle-rare\"")
        .expect("search");
    let search_time = started.elapsed();
    assert_eq!(search.rows.len(), 100, "one match per 10,000 records");

    println!(
        "page1={first_page:?} page2={second_page:?} histogram={histogram_time:?} \
         detail={detail_time:?} search={search_time:?}"
    );
    for (name, elapsed) in [
        ("first page", first_page),
        ("second page", second_page),
        ("histogram", histogram_time),
        ("detail", detail_time),
        ("search", search_time),
    ] {
        assert!(
            elapsed < Duration::from_secs(2),
            "{name} took {elapsed:?}; the query path is no longer bounded"
        );
    }
}

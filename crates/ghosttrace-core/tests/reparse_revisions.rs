//! P4.4 re-parse revisions: re-importing with changed time assumptions records
//! a new revision instead of replacing the old one, and an already-published
//! report stays byte-reproducible (plan Sections 6, 12, P3.2 + P4.4).

mod support;

use ghosttrace_core::domain::query::EventQuery;
use ghosttrace_core::reports::{ReportContext, ReportSelection, build_report, publish};
use ghosttrace_core::storage::search::{
    list_revisions, recorded_assumptions, search_events, validate_search_text,
};
use support::Harness;

/// An RFC 3164 log with no year and no zone in the record itself.
const SYSLOG: &[u8] = b"<38>Oct 27 10:00:00 edge-a sshd[1]: Accepted publickey for root from 10.0.0.5 port 22 ssh2\n\
                       <38>Oct 27 10:05:00 edge-a sshd[2]: Failed password for admin from 10.0.0.9 port 22 ssh2\n\
                       <38>Oct 27 11:30:00 edge-a sshd[3]: Accepted publickey for ops from 10.0.0.7 port 22 ssh2\n";

/// A query pinned to one revision with an explicit page size. `EventQuery`'s
/// `Default` leaves the limit at 0, which the service clamps to one row.
fn revision_query(run: &str, kind: Option<&str>, limit: u32) -> EventQuery {
    EventQuery {
        revision: run.to_string(),
        kind: kind.map(str::to_string),
        limit,
        ..EventQuery::default()
    }
}

fn import(harness: &Harness, acquisition: &str, year: i32, zone: &str) -> String {
    let outcome = harness
        .import(acquisition, "logs/auth.log", |request| {
            request.format = Some(ghosttrace_core::ingest::LogFormat::Syslog3164);
            request.syslog.year = Some(year);
            request.syslog.timezone = Some(zone.to_string());
        })
        .expect("import");
    assert_eq!(outcome.state, "completed", "{:?}", outcome.diagnostics);
    outcome.run_id
}

#[test]
fn a_changed_zone_or_year_records_a_new_revision_and_keeps_the_old_one() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("logs/auth.log", SYSLOG)]);

    let first = import(&harness, &acquisition, 2026, "UTC");
    let second = import(&harness, &acquisition, 2026, "Asia/Kolkata");
    let third = import(&harness, &acquisition, 2025, "UTC");

    assert_ne!(first, second, "a new zone is a new parse run");
    assert_ne!(first, third, "a new year is a new parse run");
    assert_ne!(second, third);

    let reader = harness.session().reader().expect("reader");
    let revisions = list_revisions(&reader, &acquisition).expect("revisions");
    let by_id: Vec<&str> = revisions
        .iter()
        .map(|revision| revision.run_id.as_str())
        .collect();
    for run in [&first, &second, &third] {
        assert!(by_id.contains(&run.as_str()), "{run} is listed");
    }
    // The capture's own metadata run is a revision of this acquisition too;
    // what matters is that all three imports are still listed alongside it.
    assert_eq!(
        revisions.len(),
        4,
        "the earlier revisions are not overwritten or hidden"
    );
    assert!(
        revisions
            .iter()
            .any(|revision| revision.parser_id == "capture.metadata.v1"),
        "the capture run is listed as well"
    );

    // Every revision carries its own recorded assumptions, so a reviewer can
    // tell them apart without re-reading the source.
    let utc = recorded_assumptions(&reader, &first).expect("assumptions");
    assert_eq!(utc.len(), 1);
    assert_eq!(utc[0].zone.as_deref(), Some("UTC"));
    assert_eq!(utc[0].year_assumed, Some(2026));

    let ist = recorded_assumptions(&reader, &second).expect("assumptions");
    assert_eq!(ist[0].zone.as_deref(), Some("Asia/Kolkata"));

    let old_year = recorded_assumptions(&reader, &third).expect("assumptions");
    assert_eq!(old_year[0].year_assumed, Some(2025));

    // Both instants differ exactly by the offset, and both stay readable.
    let chosen = |run: &str| -> Option<i64> {
        let page = harness
            .session()
            .query_events(&revision_query(run, Some("auth.login_succeeded"), 10))
            .expect("query");
        page.rows.first().and_then(|row| row.chosen_seconds)
    };
    let utc_seconds = chosen(&first).expect("resolved in UTC");
    let ist_seconds = chosen(&second).expect("resolved in IST");
    assert_eq!(
        utc_seconds - ist_seconds,
        5 * 3_600 + 30 * 60,
        "Asia/Kolkata was UTC+05:30 on that date, so its UTC instant is earlier"
    );

    // The old revision still resolves its own events; nothing was rewritten.
    let utc_page = harness
        .session()
        .query_events(&revision_query(&first, None, 50))
        .expect("query");
    assert_eq!(
        utc_page.rows.len(),
        3,
        "the first revision keeps its events"
    );

    // Search is per revision too, so a reviewer cannot accidentally read the
    // wrong normalization.
    let text = validate_search_text("accepted").unwrap();
    let in_utc =
        search_events(&reader, "UTC", &revision_query(&first, None, 50), &text).expect("search");
    assert_eq!(in_utc.rows.len(), 2);
    assert!(in_utc.rows.iter().all(|row| row.revision == first));

    // The 2025 revision keeps the same wall clock but a different instant.
    let old = chosen(&third).expect("resolved in the old year");
    assert_ne!(old, utc_seconds, "a different year is a different instant");
}

#[test]
fn a_published_report_stays_reproducible_after_a_reparse() {
    let mut harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let acquisition = harness.capture(&[("logs/auth.log", SYSLOG)]);
    let first = import(&harness, &acquisition, 2026, "UTC");

    let context = ReportContext {
        case_id: harness.session().case_id().to_string(),
        label: "reparse".into(),
        display_timezone: "UTC".into(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let selection = ReportSelection {
        acquisition_id: Some(acquisition.clone()),
        revision: Some(first.clone()),
        event_limit: 50,
    };
    let report = build_report(
        &harness.session().reader().expect("reader"),
        &context,
        &selection,
    )
    .expect("report");
    let first_json = ghosttrace_core::reports::json::render(&report).expect("json");
    let published = publish(&report, dir.path()).expect("publish");
    let on_disk = std::fs::read_to_string(published.json_path).expect("read");

    // Re-import with different assumptions, then rebuild the same selection:
    // the pinned revision produces the identical timeline.
    let second = import(&harness, &acquisition, 2026, "Asia/Kolkata");
    let again = build_report(
        &harness.session().reader().expect("reader"),
        &context,
        &selection,
    )
    .expect("report again");
    let again_json = ghosttrace_core::reports::json::render(&again).expect("json");
    assert_eq!(
        first_json, again_json,
        "the recorded facts did not change, so the pinned report is identical"
    );
    assert_eq!(on_disk, first_json, "the published report is unchanged");

    // Publication is never overwritten: the same report id refuses.
    let error = publish(&again, dir.path()).expect_err("overwrite");
    assert!(
        error.to_string().contains("refusing to overwrite"),
        "{error}"
    );

    // The new revision is present and distinct, so a reviewer can choose it.
    // Newest first: the capture run plus both imports, with the re-import last.
    let revisions =
        list_revisions(&harness.session().reader().expect("reader"), &acquisition).expect("list");
    assert_eq!(revisions.len(), 3, "the capture run plus both imports");
    assert_eq!(
        revisions[0].run_id, second,
        "the newest revision is listed first"
    );
    let reader = harness.session().reader().expect("reader");
    let ist_seconds = harness
        .session()
        .query_events(&revision_query(&second, Some("auth.login_succeeded"), 10))
        .expect("query")
        .rows
        .first()
        .and_then(|row| row.chosen_seconds);
    let utc_seconds = harness
        .session()
        .query_events(&revision_query(&first, Some("auth.login_succeeded"), 10))
        .expect("query")
        .rows
        .first()
        .and_then(|row| row.chosen_seconds);
    assert_eq!(
        utc_seconds.unwrap() - ist_seconds.unwrap(),
        5 * 3_600 + 30 * 60
    );
    let _ = reader;
}

//! P4 gate: a case holding every supported source keeps counts and provenance
//! matching ground truth, raw values survive re-parsing, and schema drift plus
//! ambiguous time stay visible (plan P4 gate, Sections 6-7).

mod support;

use ghosttrace_core::domain::query::EventQuery;
use ghosttrace_core::ingest::LogFormat;
use ghosttrace_core::storage::search::list_revisions;
use support::Harness;

const CHROMIUM_VISITS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/browser/chromium-visits.sql"
));

/// Two records, one with no time at all: an unresolved event must survive.
const JSONL: &[u8] =
    b"{\"ts\":\"2026-10-27T10:00:00Z\",\"msg\":\"login ok\",\"host\":\"edge-a\"}\n\
                       {\"msg\":\"no timestamp here\",\"host\":\"edge-a\"}\n";

/// RFC 3164 has neither a year nor a zone in the record.
const SYSLOG: &[u8] = b"<34>Oct 27 10:00:00 host sshd[1]: Accepted password for bob from 10.0.0.6 port 22 ssh2\n\
                       <34>Oct 27 10:05:00 host sshd[2]: Failed password for root from 10.0.0.9 port 22 ssh2\n";

const JOURNAL: &[u8] = b"__CURSOR=s=1;i=1;b=6c7c6013a26343b29e964691ff25d04c\n\
                        __REALTIME_TIMESTAMP=1793095200000000\n\
                        _BOOT_ID=6c7c6013a26343b29e964691ff25d04c\n\
                        _HOSTNAME=host-a\n\
                        MESSAGE=unit started\n\n";

fn import(
    harness: &Harness,
    acquisition: &str,
    path: &str,
    configure: impl FnOnce(&mut ghosttrace_core::ingest::ImportRequest<'_>),
) -> ghosttrace_core::ingest::ImportOutcome {
    let outcome = harness
        .import(acquisition, path, configure)
        .expect("import");
    assert!(
        outcome.state == "completed" || outcome.state == "partial",
        "{}: {:?}",
        outcome.state,
        outcome.diagnostics
    );
    outcome
}

#[test]
fn mixed_sources_match_ground_truth_and_keep_uncertainty_visible() {
    let mut harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let chromium = support::sqlite_bytes(
        dir.path(),
        "History",
        CHROMIUM_VISITS,
        &[
            "INSERT INTO urls VALUES (1,'https://example.test/start','Start',1,13437532800000000,0)",
            "INSERT INTO visits VALUES (1,1,13437532800000000,0,805306368,1000000,'',0)",
        ],
    );
    let acquisition = harness.capture(&[
        ("logs/app.jsonl", JSONL),
        ("logs/auth.log", SYSLOG),
        ("logs/system.journal", JOURNAL),
        ("History", &chromium),
    ]);

    let jsonl = import(&harness, &acquisition, "logs/app.jsonl", |request| {
        request.format = Some(LogFormat::Jsonl);
        request.jsonl.message_field = Some("msg".into());
        request.jsonl.host_field = Some("host".into());
    });
    assert_eq!((jsonl.records, jsonl.observations, jsonl.events), (2, 2, 2));
    assert_eq!(jsonl.state, "partial", "the second record has no time");

    let syslog = import(&harness, &acquisition, "logs/auth.log", |request| {
        request.format = Some(LogFormat::Syslog3164);
        request.syslog.year = Some(2026);
        request.syslog.timezone = Some("Europe/Berlin".into());
    });
    assert_eq!(
        (syslog.records, syslog.observations, syslog.events),
        (2, 2, 2)
    );

    let journal = import(&harness, &acquisition, "logs/system.journal", |request| {
        request.format = Some(LogFormat::JournalExport);
    });
    assert_eq!(
        (journal.records, journal.observations, journal.events),
        (1, 1, 1)
    );

    let browser = import(&harness, &acquisition, "History", |_| {});
    assert_eq!(
        (browser.records, browser.observations, browser.events),
        (1, 1, 1)
    );
    assert_eq!(browser.parser_id, "browser.chromium");

    // Counts match ground truth per adapter, not merely in total.
    let per_parser = |parser: &str| {
        harness.count(
            "SELECT count(*) FROM events e JOIN parse_runs p ON p.id = e.parse_run_id
             WHERE p.acquisition_id = ?1 AND p.parser_id = ?2",
            &[&acquisition, &parser],
        )
    };
    assert_eq!(per_parser("jsonl.fields"), 2);
    assert_eq!(per_parser("syslog.rfc3164"), 2);
    assert_eq!(per_parser("journal.export"), 1);
    assert_eq!(per_parser("browser.chromium"), 1);
    let total: i64 = harness.count(
        "SELECT count(*) FROM events e JOIN parse_runs p ON p.id = e.parse_run_id
         WHERE p.acquisition_id = ?1 AND p.parser_id <> 'capture.metadata.v1'",
        &[&acquisition],
    );
    assert_eq!(total, 6, "six parsed events, plus capture metadata");

    // Every recorded record kept its raw fields and an exact locator.
    let raw: i64 = harness.count(
        "SELECT count(*) FROM raw_observations r JOIN parse_runs p ON p.id = r.parse_run_id
         WHERE p.acquisition_id = ?1 AND p.parser_id <> 'capture.metadata.v1'",
        &[&acquisition],
    );
    assert_eq!(raw, 6, "one raw observation per record, none dropped");
    let empty_raw: i64 = harness.count(
        "SELECT count(*) FROM raw_observations WHERE raw_fields_json = '' OR locator_identity = ''",
        &[],
    );
    assert_eq!(empty_raw, 0, "no record lost its fields or locator");

    // The record without a time is unresolved, never silently resolved.
    let unresolved = harness
        .session()
        .query_events(&EventQuery {
            revision: jsonl.run_id.clone(),
            unresolved_only: true,
            limit: 50,
            ..EventQuery::default()
        })
        .expect("unresolved view");
    assert_eq!(unresolved.rows.len(), 1);
    assert_eq!(unresolved.rows[0].time_status, "unresolved");
    let resolved = harness
        .session()
        .query_events(&EventQuery {
            revision: jsonl.run_id.clone(),
            limit: 50,
            ..EventQuery::default()
        })
        .expect("resolved view");
    assert_eq!(resolved.rows.len(), 1, "the ordered view stays separate");

    // Re-parsing with the same configuration is a replay, not new facts.
    let replay = import(&harness, &acquisition, "logs/auth.log", |request| {
        request.format = Some(LogFormat::Syslog3164);
        request.syslog.year = Some(2026);
        request.syslog.timezone = Some("Europe/Berlin".into());
    });
    assert_eq!(
        replay.run_id, syslog.run_id,
        "the same config is the same run"
    );
    assert_eq!(per_parser("syslog.rfc3164"), 2, "the replay added nothing");
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM raw_observations WHERE parse_run_id = ?1",
            &[&syslog.run_id],
        ),
        2
    );

    // A different assumption is a new revision; the old one is untouched.
    let reparsed = import(&harness, &acquisition, "logs/auth.log", |request| {
        request.format = Some(LogFormat::Syslog3164);
        request.syslog.year = Some(2025);
        request.syslog.timezone = Some("Europe/Berlin".into());
    });
    assert_ne!(reparsed.run_id, syslog.run_id);
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM events WHERE revision = ?1",
            &[&syslog.run_id],
        ),
        2,
        "the earlier revision keeps its own events"
    );
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM events WHERE revision = ?1",
            &[&reparsed.run_id],
        ),
        2
    );

    // Browser schema drift is visible: the fingerprint is part of the run's
    // configuration, so a different schema cannot reuse the earlier run.
    let drifted = support::sqlite_bytes(
        dir.path(),
        "History-drifted",
        &format!("{CHROMIUM_VISITS}\nALTER TABLE urls ADD COLUMN extra_note TEXT;"),
        &[
            "INSERT INTO urls VALUES (1,'https://example.test/start','Start',1,13437532800000000,0,'drift')",
            "INSERT INTO visits VALUES (1,1,13437532800000000,0,805306368,1000000,'',0)",
        ],
    );
    let second = harness.capture(&[("History", &drifted)]);
    let drifted_outcome = import(&harness, &second, "History", |_| {});
    assert_eq!(drifted_outcome.parser_id, "browser.chromium");
    let first_digest: String = harness
        .scalar(
            "SELECT config_digest FROM parse_runs WHERE id = ?1",
            &[&browser.run_id],
        )
        .expect("first digest");
    let second_digest: String = harness
        .scalar(
            "SELECT config_digest FROM parse_runs WHERE id = ?1",
            &[&drifted_outcome.run_id],
        )
        .expect("second digest");
    assert_ne!(
        first_digest, second_digest,
        "a different schema must not share a run identity"
    );

    // Both acquisitions' revisions stay listed with their own counts.
    let reader = harness.session().reader().expect("reader");
    let revisions = list_revisions(&reader, &acquisition).expect("revisions");
    let jsonl_revision = revisions
        .iter()
        .find(|revision| revision.run_id == jsonl.run_id)
        .expect("jsonl revision");
    assert_eq!(jsonl_revision.parser_id, "jsonl.fields");
    assert_eq!(jsonl_revision.events, 2);
    let browser_revision = revisions
        .iter()
        .find(|revision| revision.run_id == browser.run_id)
        .expect("browser revision");
    assert_eq!(browser_revision.events, 1);
}

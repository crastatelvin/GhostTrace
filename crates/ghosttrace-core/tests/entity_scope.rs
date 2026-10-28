//! P5.1 entity scope contract: identity is scoped before it is compared, and
//! missing evidence stays visible instead of becoming a silent match.

mod support;

use ghosttrace_core::analysis::correlate::{CorrelateConfig, RelationshipQuery};
use ghosttrace_core::ingest::LogFormat;
use support::Harness;

/// Four records: the same PID on two hosts and two boots, with one shared IP
/// and one shared username. Only the IP is allowed to become an edge, and only
/// as a candidate.
const RECORDS: &[u8] = b"{\"ts\":\"2026-10-27T10:00:00Z\",\"host\":\"edge-a\",\"user\":\"alice\",\"src_ip\":\"10.0.0.6\",\"pid\":42,\"_BOOT_ID\":\"boot-1\",\"path\":\"/srv/app/config.json\",\"msg\":\"a\"}\n\
{\"ts\":\"2026-10-27T10:01:00Z\",\"host\":\"edge-b\",\"user\":\"alice\",\"src_ip\":\"10.0.0.6\",\"pid\":42,\"_BOOT_ID\":\"boot-1\",\"path\":\"/srv/app/config.json\",\"msg\":\"b\"}\n\
{\"ts\":\"2026-10-27T10:02:00Z\",\"host\":\"edge-a\",\"user\":\"alice\",\"src_ip\":\"10.0.0.6\",\"pid\":42,\"_BOOT_ID\":\"boot-2\",\"path\":\"/srv/app/config.json\",\"msg\":\"c\"}\n\
{\"ts\":\"2026-10-27T10:03:00Z\",\"host\":\"edge-a\",\"user\":\"alice\",\"src_ip\":\"10.0.0.7\",\"pid\":43,\"_BOOT_ID\":\"boot-1\",\"path\":\"/srv/app/other.json\",\"msg\":\"d\"}\n";

fn import(harness: &Harness, acquisition: &str) -> ghosttrace_core::ingest::ImportOutcome {
    harness
        .import(acquisition, "logs/app.jsonl", |request| {
            request.format = Some(LogFormat::Jsonl);
            request.jsonl.message_field = Some("msg".into());
            request.jsonl.host_field = Some("host".into());
        })
        .expect("import")
}

#[test]
fn process_identity_is_scoped_by_host_and_boot() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("logs/app.jsonl", RECORDS)]);
    let outcome = import(&harness, &acquisition);
    assert_eq!(outcome.events, 4);

    let report = harness
        .session()
        .build_entities(&outcome.run_id)
        .expect("entities");
    assert_eq!(report.events, 4);
    assert_eq!(
        report.events_without_source, 0,
        "every imported event recorded its locator"
    );
    let count = |sql: &str| harness.count(sql, &[]);
    assert_eq!(
        count("SELECT count(*) FROM entities WHERE kind = 'process'"),
        4
    );
    assert_eq!(
        count("SELECT count(*) FROM entities WHERE kind = 'user'"),
        2,
        "the same username on two hosts is two scoped entities, never one"
    );
    assert_eq!(
        count("SELECT count(*) FROM entities WHERE kind = 'ip'"),
        3,
        "the IP is scoped by the host that claimed it"
    );

    let report = harness
        .session()
        .correlate(&CorrelateConfig::default())
        .expect("correlate");
    assert_eq!(
        report.derived, 1,
        "only the shared IP becomes an edge; no PID or username join"
    );
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM relationships WHERE kind = 'observed'",
            &[],
        ),
        0,
        "no asserted join may rest on a PID or a username"
    );

    let process: String = harness
        .scalar(
            "SELECT id FROM entities WHERE kind = 'process' ORDER BY id LIMIT 1",
            &[],
        )
        .expect("process entity");
    let page = harness
        .session()
        .query_relationships(&RelationshipQuery {
            entity_id: Some(process),
            ..RelationshipQuery::default()
        })
        .expect("relationships");
    assert!(
        page.rows.is_empty(),
        "a process entity participates in no relationship: {:?}",
        page.rows
    );

    let page = harness
        .session()
        .query_relationships(&RelationshipQuery::default())
        .expect("relationships");
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].kind, "candidate");
    assert_eq!(page.rows[0].rule_id, "correlate.shared_ip");
    assert!(page.rows[0].strength_basis.contains("candidate only"));
    let scopes = format!(
        "{} {}",
        page.rows[0].source.scoped_identity, page.rows[0].target.scoped_identity
    );
    assert!(scopes.contains("edge-a") && scopes.contains("edge-b"));
}

#[test]
fn missing_time_is_reported_rather_than_treated_as_a_window_match() {
    let mut harness = Harness::new();
    let records: &[u8] = b"{\"msg\":\"no timestamp\",\"host\":\"edge-a\",\"src_ip\":\"10.0.0.9\",\"pid\":7,\"_BOOT_ID\":\"boot-1\"}\n\
{\"ts\":\"2026-10-27T10:05:00Z\",\"msg\":\"timed\",\"host\":\"edge-b\",\"src_ip\":\"10.0.0.9\",\"pid\":7,\"_BOOT_ID\":\"boot-1\"}\n";
    let acquisition = harness.capture(&[("logs/app.jsonl", records)]);
    let outcome = import(&harness, &acquisition);
    assert_eq!(outcome.events, 2);
    assert_eq!(outcome.state, "partial", "the missing time is not hidden");

    let report = harness
        .session()
        .build_entities(&outcome.run_id)
        .expect("entities");
    assert_eq!(report.events, 2);
    let report = harness
        .session()
        .correlate(&CorrelateConfig::default())
        .expect("correlate");
    assert_eq!(report.derived, 0);
    assert_eq!(
        report.unsupported_time, 1,
        "an untimed entity cannot be placed inside a window"
    );
    assert!(!report.truncated, "nothing was dropped for lack of budget");
}

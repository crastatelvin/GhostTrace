//! P5.1 relationship contract: hashes prove equal bytes only, weak matches stay
//! candidates, and correlation work is bounded no matter how common a name is.

mod support;

use ghosttrace_core::analysis::correlate::{CorrelateConfig, RelationshipQuery, RelationshipRow};
use ghosttrace_core::ingest::LogFormat;
use support::Harness;

fn capture_run(harness: &Harness, acquisition: &str) -> String {
    harness
        .scalar(
            "SELECT id FROM parse_runs
             WHERE acquisition_id = ?1 AND parser_id = 'capture.metadata.v1'",
            &[&acquisition],
        )
        .expect("capture run")
}

fn build(
    harness: &Harness,
    acquisition: &str,
) -> ghosttrace_core::analysis::entities::EntityBuildReport {
    let run = capture_run(harness, acquisition);
    harness.session().build_entities(&run).expect("entities")
}

fn one_edge(harness: &Harness) -> RelationshipRow {
    let page = harness
        .session()
        .query_relationships(&RelationshipQuery::default())
        .expect("relationships");
    assert_eq!(page.rows.len(), 1, "{:?}", page.rows);
    page.rows.into_iter().next().expect("one edge")
}

#[test]
fn equal_hashes_link_content_without_merging_acquisitions() {
    let mut harness = Harness::new();
    let first = harness.capture(&[("docs/a.txt", b"identical bytes")]);
    let second = harness.capture(&[("backup/b.txt", b"identical bytes")]);
    let first_report = build(&harness, &first);
    let second_report = build(&harness, &second);
    assert_eq!(first_report.entities, 2, "one path entity and one digest");
    assert_eq!(second_report.entities, 2);

    let report = harness
        .session()
        .correlate(&CorrelateConfig::default())
        .expect("correlate");
    assert_eq!(report.derived, 1);
    assert_eq!(report.inserted, 1);
    assert_eq!(
        harness.count("SELECT count(*) FROM acquisitions", &[]),
        2,
        "an edge never merges acquisitions"
    );
    assert_eq!(
        harness.count("SELECT count(*) FROM entities WHERE kind = 'path'", &[]),
        2,
        "each acquisition keeps its own path identity"
    );

    let edge = one_edge(&harness);
    assert_eq!(edge.kind, "observed");
    assert_eq!(edge.rule_id, "correlate.digest_equal");
    assert_eq!(edge.rule_version, "1");
    assert!(
        edge.strength_basis.contains("does not prove a copy"),
        "{}",
        edge.strength_basis
    );
    let scopes = format!(
        "{} {}",
        edge.source.scoped_identity, edge.target.scoped_identity
    );
    assert!(
        scopes.contains(&first) && scopes.contains(&second),
        "both acquisitions are named in the edge scope: {scopes}"
    );

    let support: serde_json::Value =
        serde_json::from_str(&edge.support_json).expect("support json");
    assert_eq!(support["matching_fields"][0].as_str().unwrap(), {
        let digest = harness
            .scalar("SELECT raw_form FROM entities WHERE kind = 'digest'", &[])
            .expect("digest");
        format!("sha256:{digest}")
    });
    let events = support["events"].as_array().expect("support events");
    assert_eq!(events.len(), 2, "both file events support the edge");
    for event in events {
        let id = event.as_str().expect("event id");
        assert_eq!(
            harness.count("SELECT count(*) FROM events WHERE id = ?1", &[&id]),
            1,
            "support points at a recorded event"
        );
    }

    // Replaying the same facts adds nothing and explains the same edge.
    let replay = harness
        .session()
        .correlate(&CorrelateConfig::default())
        .expect("replay");
    assert_eq!(replay.derived, 1);
    assert_eq!(replay.inserted, 0, "the edge already exists");
    assert_eq!(harness.count("SELECT count(*) FROM relationships", &[]), 1);
}

#[test]
fn basename_matches_are_candidates_inside_the_time_window() {
    let mut harness = Harness::new();
    let records: &[u8] = b"{\"ts\":\"2026-10-27T10:00:00Z\",\"host\":\"edge-a\",\"msg\":\"one\",\"path\":\"/srv/a/config.json\"}\n\
{\"ts\":\"2026-10-27T12:00:00Z\",\"host\":\"edge-a\",\"msg\":\"two\",\"path\":\"/srv/b/config.json\"}\n";
    let acquisition = harness.capture(&[("logs/app.jsonl", records)]);
    let outcome = harness
        .import(&acquisition, "logs/app.jsonl", |request| {
            request.format = Some(LogFormat::Jsonl);
            request.jsonl.message_field = Some("msg".into());
            request.jsonl.host_field = Some("host".into());
        })
        .expect("import");
    harness
        .session()
        .build_entities(&outcome.run_id)
        .expect("entities");

    let close = harness
        .session()
        .correlate(&CorrelateConfig {
            window_seconds: 3_600,
            ..CorrelateConfig::default()
        })
        .expect("close window");
    assert_eq!(close.derived, 0, "two hours apart is outside one hour");

    let wide = harness
        .session()
        .correlate(&CorrelateConfig {
            window_seconds: 7_200,
            ..CorrelateConfig::default()
        })
        .expect("wide window");
    assert_eq!(wide.derived, 1);
    let edge = one_edge(&harness);
    assert_eq!(edge.kind, "candidate");
    assert_eq!(edge.rule_id, "correlate.shared_basename");
    assert!(edge.strength_basis.contains("may differ"));
    let support: serde_json::Value =
        serde_json::from_str(&edge.support_json).expect("support json");
    assert_eq!(
        support["matching_fields"][0].as_str(),
        Some("basename:config.json")
    );
}

#[test]
fn shared_ips_across_hosts_are_only_candidates() {
    let mut harness = Harness::new();
    let records: &[u8] = b"{\"ts\":\"2026-10-27T10:00:00Z\",\"host\":\"edge-a\",\"msg\":\"one\",\"src_ip\":\"10.0.0.6\"}\n\
{\"ts\":\"2026-10-27T10:05:00Z\",\"host\":\"edge-b\",\"msg\":\"two\",\"src_ip\":\"10.0.0.6\"}\n";
    let acquisition = harness.capture(&[("logs/app.jsonl", records)]);
    let outcome = harness
        .import(&acquisition, "logs/app.jsonl", |request| {
            request.format = Some(LogFormat::Jsonl);
            request.jsonl.message_field = Some("msg".into());
            request.jsonl.host_field = Some("host".into());
        })
        .expect("import");
    harness
        .session()
        .build_entities(&outcome.run_id)
        .expect("entities");
    harness
        .session()
        .correlate(&CorrelateConfig::default())
        .expect("correlate");

    let edge = one_edge(&harness);
    assert_eq!(edge.kind, "candidate");
    assert_eq!(edge.rule_id, "correlate.shared_ip");
    assert!(edge.strength_basis.contains("candidate only"));
    assert_eq!(edge.source.kind, "ip");
    assert_eq!(edge.target.kind, "ip");
}

#[test]
fn common_basenames_cannot_exceed_the_correlation_limits() {
    let mut harness = Harness::new();
    let names: Vec<String> = (0..40)
        .map(|index| format!("d{index}/config.json"))
        .collect();
    let bodies: Vec<Vec<u8>> = (0..40)
        .map(|index| format!("body-{index}").into_bytes())
        .collect();
    let files: Vec<(&str, &[u8])> = names
        .iter()
        .map(String::as_str)
        .zip(bodies.iter().map(Vec::as_slice))
        .collect();
    let acquisition = harness.capture(&files);
    build(&harness, &acquisition);

    // A bucket of 40 is over the default cap of 32: skipped and counted.
    let skipped = harness
        .session()
        .correlate(&CorrelateConfig::default())
        .expect("correlate");
    assert_eq!(skipped.derived, 0);
    assert_eq!(skipped.buckets_skipped, 1);
    assert_eq!(
        skipped.pairs_examined, 0,
        "no pair work for a skipped bucket"
    );

    // Raising the cap admits the bucket, and the pair budget still bounds it.
    let all = harness
        .session()
        .correlate(&CorrelateConfig {
            max_bucket_entities: 64,
            ..CorrelateConfig::default()
        })
        .expect("wide bucket");
    assert_eq!(all.derived, 40 * 39 / 2);
    assert_eq!(all.buckets_skipped, 0);

    let bounded = harness
        .session()
        .correlate(&CorrelateConfig {
            max_bucket_entities: 64,
            max_pairs: 10,
            max_edges: 4,
            ..CorrelateConfig::default()
        })
        .expect("bounded");
    assert!(bounded.truncated);
    assert!(bounded.derived <= 4, "{}", bounded.derived);
    assert!(bounded.pairs_examined <= 10, "{}", bounded.pairs_examined);
}

#[test]
fn relationship_pages_are_bounded_and_filterable() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[
        ("a.txt", b"same bytes"),
        ("b.txt", b"same bytes"),
        ("c.txt", b"same bytes"),
    ]);
    build(&harness, &acquisition);
    let report = harness
        .session()
        .correlate(&CorrelateConfig::default())
        .expect("correlate");
    assert_eq!(report.derived, 3, "three files sharing one digest");

    let first = harness
        .session()
        .query_relationships(&RelationshipQuery {
            limit: 2,
            ..RelationshipQuery::default()
        })
        .expect("first page");
    assert_eq!(first.rows.len(), 2);
    let cursor = first.next_cursor.expect("more rows");
    let second = harness
        .session()
        .query_relationships(&RelationshipQuery {
            limit: 2,
            after_id: Some(cursor),
            ..RelationshipQuery::default()
        })
        .expect("second page");
    assert_eq!(second.rows.len(), 1);
    assert_eq!(second.next_cursor, None);

    let endpoint = first.rows[0].source.id.clone();
    let by_entity = harness
        .session()
        .query_relationships(&RelationshipQuery {
            entity_id: Some(endpoint),
            ..RelationshipQuery::default()
        })
        .expect("by entity");
    assert_eq!(by_entity.rows.len(), 2, "the endpoint appears in two edges");

    let by_rule = harness
        .session()
        .query_relationships(&RelationshipQuery {
            rule_id: Some("correlate.digest_equal".into()),
            kind: Some("observed".into()),
            ..RelationshipQuery::default()
        })
        .expect("by rule");
    assert_eq!(by_rule.rows.len(), 3);
}

#[test]
fn entity_bucket_reads_use_their_indexes() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("a.txt", b"same bytes"), ("b.txt", b"same bytes")]);
    build(&harness, &acquisition);
    harness
        .session()
        .correlate(&CorrelateConfig::default())
        .unwrap();
    let reader = harness.session().reader().expect("reader");

    let plan = |sql: &str| -> Vec<String> {
        let mut statement = reader
            .connection()
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap();
        let mut rows = statement.query([]).unwrap();
        let mut lines = Vec::new();
        while let Some(row) = rows.next().unwrap() {
            lines.push(row.get::<_, String>(3).unwrap());
        }
        lines
    };

    let facts = plan(
        "SELECT n.id, n.kind, n.raw_form, MIN(e.chosen_seconds), MAX(e.chosen_seconds)
         FROM entities n
         LEFT JOIN event_entities ee ON ee.entity_id = n.id
         LEFT JOIN events e ON e.id = ee.event_id
         WHERE n.kind IN ('path', 'ip')
         GROUP BY n.id
         ORDER BY n.id
         LIMIT 10",
    );
    assert!(
        facts
            .iter()
            .any(|line| line.contains("event_entities_by_entity")),
        "{facts:?}"
    );

    let digest = plan(
        "SELECT DISTINCT p.id, d.raw_form
         FROM event_entities pd
         JOIN event_entities dd ON dd.event_id = pd.event_id
         JOIN entities p ON p.id = pd.entity_id AND p.kind = 'path'
         JOIN entities d ON d.id = dd.entity_id AND d.kind = 'digest'
         ORDER BY d.raw_form, p.id
         LIMIT 10",
    );
    assert!(
        digest.iter().any(|line| line.contains("event_entities")),
        "{digest:?}"
    );
    assert!(
        !digest.iter().any(|line| line.contains("SCAN events")),
        "the digest bucket never scans the event table: {digest:?}"
    );
}

//! P4.3 Chromium/Firefox history contract: exact epochs, referrers,
//! transitions, sync labels, profile identity, downloads, and unavailable
//! download fields.

mod support;

use support::Harness;

const CHROMIUM_VISITS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/browser/chromium-visits.sql"
));
const CHROMIUM_DOWNLOADS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/browser/chromium-downloads.sql"
));
const CHROMIUM_DOWNLOADS_PARTIAL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/browser/chromium-downloads-partial.sql"
));
const FIREFOX: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/browser/firefox.sql"
));

/// 2026-10-27T00:00:00Z as microseconds since 1601-01-01 (Chromium) and as
/// PRTime microseconds since 1970-01-01 (Firefox).
const UNIX_2026: i64 = 1_793_059_200;
const PRTIME_2026: i64 = UNIX_2026 * 1_000_000;

fn raw_fields(harness: &Harness, run_id: &str, locator: &str) -> serde_json::Value {
    let raw = harness
        .scalar(
            "SELECT raw_fields_json FROM raw_observations
             WHERE parse_run_id = ?1 AND locator_identity = ?2",
            &[&run_id, &locator],
        )
        .expect("raw observation");
    serde_json::from_str(&raw).expect("raw JSON")
}

#[test]
fn chromium_visits_keep_epoch_referrers_transitions_and_sync_labels() {
    let mut harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let bytes = support::sqlite_bytes(
        dir.path(),
        "History",
        CHROMIUM_VISITS,
        &[
            "INSERT INTO urls VALUES (1,'https://example.test/start','Start',3,13437532800000000,0)",
            "INSERT INTO urls VALUES (2,'https://example.test/next','Next page',1,13437532850000000,0)",
            "INSERT INTO visits VALUES (1,1,13437532800000000,0,805306368,1000000,'',0)",
            "INSERT INTO visits VALUES (2,2,13437532805000000,1,1,0,'imported-cache-guid',1)",
            "INSERT INTO visits VALUES (3,1,13437532810000000,0,2,0,'',1)",
        ],
    );
    let acquisition = harness.capture(&[("History", &bytes)]);
    let outcome = harness
        .import(&acquisition, "History", |_| {})
        .expect("import");

    assert_eq!(outcome.detected_format.as_deref(), Some("browser"));
    assert_eq!(outcome.parser_id, "browser.chromium");
    assert_eq!(outcome.state, "completed");
    assert_eq!(outcome.records, 3);
    assert_eq!(outcome.observations, 3);
    assert_eq!(outcome.events, 3);
    assert_eq!(outcome.diagnostics_total, 0);

    let second = raw_fields(&harness, &outcome.run_id, "table:visits:rowid:2");
    assert_eq!(second["transition"], 1);
    assert_eq!(second["referrer_url"], "https://example.test/start");
    assert_eq!(second["url"], "https://example.test/next");
    assert_eq!(second["title"], "Next page");
    assert_eq!(second["visit_time"], 13_437_532_805_000_000_i64);
    assert_eq!(second["sync_status"], "imported");
    assert_eq!(second["originator_cache_guid"], "imported-cache-guid");

    let first = raw_fields(&harness, &outcome.run_id, "table:visits:rowid:1");
    assert_eq!(first["transition"], 805_306_368_i64);
    assert_eq!(first["sync_status"], "local");
    assert_eq!(first["referrer_url"], serde_json::Value::Null);

    let third = raw_fields(&harness, &outcome.run_id, "table:visits:rowid:3");
    assert_eq!(third["sync_status"], "sync_known");

    assert_eq!(
        harness
            .scalar(
                "SELECT locator_kind FROM raw_observations
                 WHERE parse_run_id = ?1 AND locator_identity = 'table:visits:rowid:2'",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("logical_row")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT chosen_seconds FROM events
                 WHERE parse_run_id = ?1 AND summary = 'Start'
                 ORDER BY chosen_seconds LIMIT 1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("1793059200")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT epoch FROM event_times
                 WHERE event_id = (SELECT id FROM events
                                   WHERE parse_run_id = ?1 AND summary = 'Next page')
                   AND name = 'visit'",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("chrome_1601")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT unit FROM event_times
                 WHERE event_id = (SELECT id FROM events
                                   WHERE parse_run_id = ?1 AND summary = 'Next page')
                   AND name = 'visit'",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("micros")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT chosen_seconds FROM events WHERE parse_run_id = ?1
                 AND summary = 'Next page'",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("1793059205")
    );
}

#[test]
fn chromium_downloads_preserve_paths_times_url_chain_and_rule_fields() {
    let mut harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let bytes = support::sqlite_bytes(
        dir.path(),
        "History",
        CHROMIUM_DOWNLOADS,
        &[
            "INSERT INTO downloads VALUES (
                7,'guid-7','/home/u/Downloads/a.bin','/home/u/a.bin',
                13437532800000000,1024,2048,1,0,0,X'00ff',13437532805000000,
                1,1343753290000000,0,'https://example.test/','https://example.test/',
                'https://example.test/file','https://example.test/','GET','ext-id','ext-name',
                'etag-value','Wed, 21 Oct 2015 07:28:00 GMT','application/octet-stream',
                'application/octet-stream')",
            "INSERT INTO downloads_url_chains VALUES (7,0,'https://example.test/file')",
            "INSERT INTO downloads_url_chains VALUES (7,1,'https://cdn.example.test/file')",
        ],
    );
    let acquisition = harness.capture(&[("History", &bytes)]);
    let outcome = harness
        .import(&acquisition, "History", |_| {})
        .expect("import");

    assert_eq!(outcome.parser_id, "browser.chromium");
    assert_eq!(outcome.state, "completed");
    assert_eq!(outcome.records, 1);
    assert_eq!(outcome.events, 1);
    assert_eq!(outcome.diagnostics_total, 0);

    let raw = raw_fields(&harness, &outcome.run_id, "table:downloads:rowid:7");
    assert_eq!(raw["current_path"], "/home/u/Downloads/a.bin");
    assert_eq!(raw["target_path"], "/home/u/a.bin");
    assert_eq!(
        raw["start_time"], 13_437_532_800_000_000_i64,
        "raw Chrome micros are preserved"
    );
    assert_eq!(raw["end_time"], 13_437_532_805_000_000_i64);
    assert_eq!(raw["opened"], 1);
    assert_eq!(raw["state"], 1);
    assert_eq!(raw["mime_type"], "application/octet-stream");
    assert_eq!(
        raw["url_chain"],
        serde_json::json!(["https://example.test/file", "https://cdn.example.test/file"])
    );

    assert_eq!(
        harness
            .scalar(
                "SELECT kind FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("browser.download")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT chosen_seconds FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("1793059200")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT candidates_json FROM event_times
                 WHERE event_id = (SELECT id FROM events WHERE parse_run_id = ?1)
                   AND name = 'end'",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some(r#"[{"seconds":1793059205,"nanos":0}]"#)
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT raw_value_text FROM event_times
                 WHERE event_id = (SELECT id FROM events WHERE parse_run_id = ?1)
                   AND name = 'start'",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("13437532800000000")
    );
}

#[test]
fn unavailable_download_fields_are_reported_without_invented_values() {
    let mut harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let bytes = support::sqlite_bytes(
        dir.path(),
        "History",
        CHROMIUM_DOWNLOADS_PARTIAL,
        &["INSERT INTO downloads VALUES (8,'/tmp/current','/tmp/target',13437532800000000,1)"],
    );
    let acquisition = harness.capture(&[("History", &bytes)]);
    let outcome = harness
        .import(&acquisition, "History", |_| {})
        .expect("import");

    assert_eq!(outcome.state, "partial");
    assert!(
        outcome.diagnostics.iter().any(|diagnostic| diagnostic.code
            == "download_fields_unavailable"
            && diagnostic.detail.contains("tab_url")),
        "{:?}",
        outcome.diagnostics
    );
    let raw = raw_fields(&harness, &outcome.run_id, "table:downloads:rowid:8");
    assert!(raw.get("tab_url").is_none(), "no fabricated field: {raw}");
    assert!(raw.get("url_chain").is_none(), "no fabricated chain: {raw}");
    assert_eq!(raw["opened"], 1);
    assert_eq!(raw["target_path"], "/tmp/target");
}

#[test]
fn firefox_visits_keep_prtime_referrers_and_sync_source() {
    let mut harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let bytes = support::sqlite_bytes(
        dir.path(),
        "places.sqlite",
        FIREFOX,
        &[
            "INSERT INTO moz_places VALUES (
                10,'https://mozilla.test/a','A','test.',2,0,0,100,
                1793059200000000,'guid-a',0,123,NULL,NULL,NULL,NULL,0,NULL,0)",
            "INSERT INTO moz_places VALUES (
                11,'https://mozilla.test/b','B','test.',1,0,0,100,
                1793059260000000,'guid-b',0,124,NULL,NULL,NULL,NULL,0,NULL,0)",
            "INSERT INTO moz_historyvisits VALUES (1,0,10,1793059200000000,2,0,0)",
            "INSERT INTO moz_historyvisits VALUES (2,1,11,1793059260000000,1,0,1)",
        ],
    );
    let acquisition = harness.capture(&[("places.sqlite", &bytes)]);
    let outcome = harness
        .import(&acquisition, "places.sqlite", |_| {})
        .expect("import");

    assert_eq!(outcome.parser_id, "browser.firefox");
    assert_eq!(outcome.state, "completed");
    assert_eq!(outcome.events, 2);
    assert_eq!(outcome.diagnostics_total, 0);

    let second = raw_fields(&harness, &outcome.run_id, "table:moz_historyvisits:rowid:2");
    assert_eq!(second["visit_date"], PRTIME_2026 + 60_000_000);
    assert_eq!(second["visit_type"], 1);
    assert_eq!(second["referrer_url"], "https://mozilla.test/a");
    assert_eq!(second["history_source"], "synced");
    assert_eq!(second["url_visit_count"], 1);

    let first = raw_fields(&harness, &outcome.run_id, "table:moz_historyvisits:rowid:1");
    assert_eq!(first["history_source"], "local");
    assert_eq!(
        harness
            .scalar(
                "SELECT epoch FROM event_times
                 WHERE event_id = (SELECT id FROM events WHERE parse_run_id = ?1
                                   ORDER BY chosen_seconds LIMIT 1)",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("unix")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT chosen_seconds FROM events
                 WHERE parse_run_id = ?1 ORDER BY chosen_seconds LIMIT 1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("1793059200")
    );
}

#[test]
fn two_profiles_keep_distinct_run_and_event_identities() {
    let mut harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let bytes_a = support::sqlite_bytes(
        dir.path().join("a").as_path(),
        "History",
        CHROMIUM_VISITS,
        &[
            "INSERT INTO urls VALUES (1,'https://example.test/start','Start',1,13437532800000000,0)",
            "INSERT INTO visits VALUES (1,1,13437532800000000,0,1,0,'',0)",
        ],
    );
    let bytes_b = bytes_a.clone();
    let acquisition_a = harness.capture(&[("profile-a/History", &bytes_a)]);
    let acquisition_b = harness.capture(&[("profile-b/History", &bytes_b)]);

    let outcome_a = harness
        .import(&acquisition_a, "profile-a/History", |_| {})
        .expect("import a");
    let outcome_b = harness
        .import(&acquisition_b, "profile-b/History", |_| {})
        .expect("import b");

    assert_ne!(outcome_a.run_id, outcome_b.run_id);
    assert_ne!(outcome_a.evidence_id, outcome_b.evidence_id);
    assert_ne!(outcome_a.acquisition_id, outcome_b.acquisition_id);
    assert_eq!(outcome_a.path, "profile-a/History");
    assert_eq!(outcome_b.path, "profile-b/History");
    assert_eq!(
        harness.count(
            "SELECT count(DISTINCT id) FROM events WHERE parse_run_id IN (?1, ?2)",
            &[&outcome_a.run_id, &outcome_b.run_id],
        ),
        2
    );
    assert_eq!(
        harness.count(
            "SELECT count(DISTINCT parse_run_id) FROM events
                 WHERE parse_run_id IN (?1, ?2)",
            &[&outcome_a.run_id, &outcome_b.run_id],
        ),
        2
    );
}

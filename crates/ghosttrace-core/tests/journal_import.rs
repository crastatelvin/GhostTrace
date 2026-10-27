//! P4.2 journal export contract: binary safe fields, repeated fields preserved
//! in order, length-prefixed values, truncated lengths, cursors, and
//! boot-scoped monotonic clocks.

mod support;

use std::cmp::Ordering;

use ghosttrace_core::domain::time::{
    ClockDomain, Epoch, EventTime, TimePrecision, TimeSemantic, TimeStatus, TimeUnit, UnixTime,
};
use ghosttrace_core::ingest::LogFormat;
use ghosttrace_core::ingest::journal::compare_boot_times;
use support::Harness;

const BOOT_A: &str = "6c7c6013a26343b29e964691ff25d04c";
const BOOT_B: &str = "ec25d6795f0645619ddac9afdef453ee";

fn text(name: &str, value: &str) -> Vec<u8> {
    format!("{name}={value}\n").into_bytes()
}

fn binary(name: &str, value: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{name}\n").into_bytes();
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value);
    bytes.push(b'\n');
    bytes
}

fn entry(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for field in fields {
        bytes.extend_from_slice(field);
    }
    bytes.push(b'\n');
    bytes
}

fn journal(
    harness: &Harness,
    acquisition: &str,
    path: &str,
) -> ghosttrace_core::ingest::ImportOutcome {
    harness
        .import(acquisition, path, |request| {
            request.format = Some(LogFormat::JournalExport);
        })
        .expect("import")
}

#[test]
fn binary_repeated_and_length_prefixed_fields_survive_exactly() {
    let mut harness = Harness::new();
    let cursor = "s=739ad463348b4ceca5a9e69c95a3c93f;i=4ece7;b=6c7c6013a26343b29e964691ff25d04c";
    let bytes = entry(&[
        text("__CURSOR", cursor),
        text("__REALTIME_TIMESTAMP", "1342540861416409"),
        text("__MONOTONIC_TIMESTAMP", "21415215982"),
        text("_BOOT_ID", BOOT_A),
        text("_HOSTNAME", "host-a"),
        text("MESSAGE", "first message"),
        text("MESSAGE", "second message"),
        binary("BINARY", b"foo\nbar\0\x07"),
        text("TAB_VALUE", "a\tb"),
    ]);
    let acquisition = harness.capture(&[("journal.export", &bytes)]);

    // No --format: the __CURSOR signature must detect the adapter.
    let outcome = harness
        .import(&acquisition, "journal.export", |_| {})
        .expect("import");
    assert_eq!(outcome.detected_format.as_deref(), Some("journal-export"));
    assert_eq!(outcome.declared_format, None);
    assert_eq!(outcome.parser_id, "journal.export");
    assert_eq!(outcome.state, "completed");
    assert_eq!(outcome.records, 1);
    assert_eq!(outcome.observations, 1);
    assert_eq!(outcome.events, 1);

    let raw = harness
        .scalar(
            "SELECT raw_fields_json FROM raw_observations WHERE parse_run_id = ?1",
            &[&outcome.run_id],
        )
        .expect("raw fields");
    let pairs: serde_json::Value = serde_json::from_str(&raw).expect("pairs");
    let pairs = pairs.as_array().expect("array of pairs");
    let messages: Vec<&str> = pairs
        .iter()
        .filter(|pair| pair[0] == "MESSAGE")
        .map(|pair| pair[1].as_str().expect("text"))
        .collect();
    assert_eq!(messages, ["first message", "second message"], "no collapse");
    let cursor_value = pairs
        .iter()
        .find(|pair| pair[0] == "__CURSOR")
        .map(|pair| pair[1].as_str().unwrap())
        .expect("cursor");
    assert_eq!(cursor_value, cursor, "cursor preserved verbatim");
    let binary_value = pairs
        .iter()
        .find(|pair| pair[0] == "BINARY")
        .map(|pair| pair[1].clone())
        .expect("binary field");
    assert_eq!(binary_value["binary_hex"], "666f6f0a6261720007");
    let tab = pairs
        .iter()
        .find(|pair| pair[0] == "TAB_VALUE")
        .map(|pair| pair[1].as_str().unwrap())
        .expect("tab field");
    assert_eq!(tab, "a\tb", "TAB is legal text");

    assert_eq!(
        harness
            .scalar(
                "SELECT summary FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("first message")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT host_claim FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("host-a")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT chosen_seconds FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("1342540861")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT chosen_nanos FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("416409000")
    );
    let expected_domain = format!("boot:{BOOT_A}");
    assert_eq!(
        harness
            .scalar(
                "SELECT clock_domain FROM event_times WHERE event_id = (
                     SELECT id FROM events WHERE parse_run_id = ?1
                 ) AND name = 'monotonic'",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some(expected_domain.as_str())
    );
}

#[test]
fn monotonic_times_are_only_orderable_within_one_boot() {
    let mut harness = Harness::new();
    let mut bytes = entry(&[
        text("__REALTIME_TIMESTAMP", "2000000"),
        text("__MONOTONIC_TIMESTAMP", "900"),
        text("_BOOT_ID", BOOT_A),
        text("MESSAGE", "later realtime, larger monotonic"),
    ]);
    bytes.extend(entry(&[
        text("__REALTIME_TIMESTAMP", "1000000"),
        text("__MONOTONIC_TIMESTAMP", "100"),
        text("_BOOT_ID", BOOT_A),
        text("MESSAGE", "earlier realtime, smaller monotonic"),
    ]));
    bytes.extend(entry(&[
        text("__REALTIME_TIMESTAMP", "3000000"),
        text("__MONOTONIC_TIMESTAMP", "5"),
        text("_BOOT_ID", BOOT_B),
        text("MESSAGE", "other boot"),
    ]));
    let acquisition = harness.capture(&[("journal.export", &bytes)]);
    let outcome = journal(&harness, &acquisition, "journal.export");
    assert_eq!(outcome.events, 3);

    // The timeline position comes from realtime only; monotonic values never
    // decide ordering, so boot B's tiny value cannot jump the queue.
    let chosen = harness
        .scalar(
            "SELECT group_concat(chosen_seconds, ',') FROM (
                 SELECT chosen_seconds FROM events
                 WHERE parse_run_id = ?1 ORDER BY chosen_seconds
             )",
            &[&outcome.run_id],
        )
        .expect("chosen");
    assert_eq!(chosen, "1,2,3");

    let domains = harness
        .scalar(
            "SELECT group_concat(clock_domain, ',') FROM (
                 SELECT DISTINCT clock_domain FROM event_times
                 WHERE event_id IN (SELECT id FROM events WHERE parse_run_id = ?1)
                   AND name = 'monotonic'
                 ORDER BY clock_domain
             )",
            &[&outcome.run_id],
        )
        .expect("domains");
    assert!(domains.contains(&format!("boot:{BOOT_A}")), "{domains}");
    assert!(domains.contains(&format!("boot:{BOOT_B}")), "{domains}");

    let time = |value: i128, boot: &str| EventTime {
        status: TimeStatus::Resolved,
        candidates: vec![UnixTime::from_parts(value, Epoch::Unix, TimeUnit::Micros).unwrap()],
        raw: None,
        semantic: TimeSemantic::Monotonic,
        clock_domain: ClockDomain::Boot(boot.to_string()),
        declared_precision: TimePrecision::Micros,
        assumptions: Vec::new(),
    };
    assert_eq!(
        compare_boot_times(&time(900, BOOT_A), &time(100, BOOT_A)),
        Some(Ordering::Greater)
    );
    assert_eq!(
        compare_boot_times(&time(1, BOOT_A), &time(2, BOOT_B)),
        None,
        "different boots are never ordered"
    );
    assert_eq!(
        compare_boot_times(
            &time(1, BOOT_A),
            &EventTime {
                clock_domain: ClockDomain::Unknown,
                ..time(2, BOOT_A)
            }
        ),
        None
    );
}

#[test]
fn truncated_lengths_are_diagnosed_and_earlier_entries_kept() {
    let mut harness = Harness::new();
    let mut bytes = entry(&[
        text("__REALTIME_TIMESTAMP", "1000000"),
        text("_BOOT_ID", BOOT_A),
        text("MESSAGE", "complete entry"),
    ]);
    // A binary field header declaring 100 bytes, then EOF after 3 bytes.
    bytes.extend_from_slice(b"BROKEN\n");
    bytes.extend(100_u64.to_le_bytes());
    bytes.extend(b"abc");
    let acquisition = harness.capture(&[("journal.export", &bytes)]);
    let outcome = journal(&harness, &acquisition, "journal.export");

    assert_eq!(outcome.records, 2);
    assert_eq!(outcome.observations, 1, "the complete entry is kept");
    assert_eq!(outcome.events, 1);
    assert_eq!(outcome.state, "partial");
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "truncated_field"),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn an_oversized_entry_is_reported_not_partially_parsed() {
    let mut harness = Harness::new();
    let mut bytes = entry(&[
        text("__REALTIME_TIMESTAMP", "1000000"),
        text("_BOOT_ID", BOOT_A),
        text("MESSAGE", "small entry"),
    ]);
    bytes.extend(entry(&[
        text("__REALTIME_TIMESTAMP", "2000000"),
        text("MESSAGE", &"x".repeat(200)),
    ]));
    let acquisition = harness.capture(&[("journal.export", &bytes)]);
    let outcome = harness
        .import(&acquisition, "journal.export", |request| {
            request.format = Some(LogFormat::JournalExport);
            request.max_record_bytes = 128;
        })
        .expect("import");

    assert_eq!(outcome.records, 2);
    assert_eq!(outcome.observations, 1);
    assert_eq!(outcome.events, 1);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "record_too_large"),
        "{:?}",
        outcome.diagnostics
    );
}

#[test]
fn a_monotonic_value_without_realtime_stays_off_the_timeline() {
    let mut harness = Harness::new();
    let bytes = entry(&[
        text("__MONOTONIC_TIMESTAMP", "21415215982"),
        text("_BOOT_ID", BOOT_A),
        text("MESSAGE", "no realtime"),
    ]);
    let acquisition = harness.capture(&[("journal.export", &bytes)]);
    let outcome = journal(&harness, &acquisition, "journal.export");
    assert_eq!(outcome.events, 1);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "time_missing"),
        "{:?}",
        outcome.diagnostics
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT time_status FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("unresolved")
    );
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM events
             WHERE parse_run_id = ?1 AND chosen_seconds IS NULL",
            &[&outcome.run_id],
        ),
        1,
        "a boot-relative value never becomes a wall-clock position"
    );
    let expected_domain = format!("boot:{BOOT_A}");
    assert_eq!(
        harness
            .scalar(
                "SELECT clock_domain FROM event_times WHERE event_id = (
                     SELECT id FROM events WHERE parse_run_id = ?1
                 ) AND name = 'monotonic'",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some(expected_domain.as_str())
    );
}

#[test]
fn a_monotonic_value_without_a_boot_id_is_unresolved() {
    let mut harness = Harness::new();
    let bytes = entry(&[
        text("__REALTIME_TIMESTAMP", "1000000"),
        text("__MONOTONIC_TIMESTAMP", "5"),
        text("MESSAGE", "no boot id"),
    ]);
    let acquisition = harness.capture(&[("journal.export", &bytes)]);
    let outcome = journal(&harness, &acquisition, "journal.export");
    assert_eq!(
        harness
            .scalar(
                "SELECT status FROM event_times WHERE event_id = (
                     SELECT id FROM events WHERE parse_run_id = ?1
                 ) AND name = 'monotonic'",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("unresolved")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT clock_domain FROM event_times WHERE event_id = (
                     SELECT id FROM events WHERE parse_run_id = ?1
                 ) AND name = 'monotonic'",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("unknown")
    );
}

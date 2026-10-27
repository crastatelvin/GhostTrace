//! P4.1 syslog contract: RFC 5424 headers, selected RFC 3164 headers, missing
//! year/zone, DST overlap, New Year rotation, malformed records, and the small
//! set of tested authentication mappings.

mod support;

use ghosttrace_core::ingest::LogFormat;
use support::Harness;

fn syslog(
    harness: &Harness,
    acquisition: &str,
    timezone: Option<&str>,
    year: Option<i32>,
) -> ghosttrace_core::ingest::ImportOutcome {
    harness
        .import(acquisition, "syslog.log", |request| {
            request.format = Some(LogFormat::Syslog3164);
            request.syslog.timezone = timezone.map(str::to_string);
            request.syslog.year = year;
        })
        .expect("import")
}

#[test]
fn rfc5424_resolves_offsets_and_maps_tested_auth() {
    let mut harness = Harness::new();
    let line = b"<34>1 2026-10-27T10:00:00.123Z host sshd 1234 ID47 [exampleSDID@32473 iut=\"3\"] Accepted publickey for alice from 10.0.0.5 port 2222 ssh2\n";
    let acquisition = harness.capture(&[("syslog.log", line)]);
    let outcome = harness
        .import(&acquisition, "syslog.log", |request| {
            request.format = Some(LogFormat::Syslog5424);
        })
        .expect("import");
    assert_eq!(outcome.state, "completed");
    assert_eq!(outcome.events, 1);
    assert_eq!(outcome.observations, 1);
    assert_eq!(
        harness
            .scalar(
                "SELECT kind FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("auth.login_succeeded")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT summary FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("sshd accepted publickey for alice from 10.0.0.5")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT host_claim FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("host")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT chosen_seconds FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("1793095200")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT chosen_nanos FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("123000000")
    );
    let raw = harness
        .scalar(
            "SELECT raw_fields_json FROM raw_observations WHERE parse_run_id = ?1",
            &[&outcome.run_id],
        )
        .expect("raw");
    assert!(raw.contains("exampleSDID@32473"), "{raw}");
    assert!(raw.contains("\"facility\":4"), "{raw}");
}

#[test]
fn nil_timestamp_stays_unresolved() {
    let mut harness = Harness::new();
    let line = b"<34>1 - host sshd - - - Failed password for root from 10.0.0.9 port 22 ssh2\n";
    let acquisition = harness.capture(&[("syslog.log", line)]);
    let outcome = harness
        .import(&acquisition, "syslog.log", |request| {
            request.format = Some(LogFormat::Syslog5424);
        })
        .expect("import");
    assert_eq!(outcome.events, 1);
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
        harness
            .scalar(
                "SELECT kind FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("auth.login_failed")
    );
}

#[test]
fn rfc3164_without_year_or_zone_keeps_the_time_unknown() {
    let mut harness = Harness::new();
    let line = b"<34>Oct 27 10:00:00 host sshd[123]: Accepted password for bob from 10.0.0.6 port 22 ssh2\n";
    let acquisition = harness.capture(&[("syslog.log", line)]);
    let outcome = syslog(&harness, &acquisition, None, None);
    assert_eq!(outcome.events, 1);
    assert_eq!(
        harness
            .scalar(
                "SELECT time_status FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("unresolved")
    );
    let assumptions = harness
        .scalar(
            "SELECT assumptions_json FROM event_times WHERE event_id = (
                 SELECT id FROM events WHERE parse_run_id = ?1
             )",
            &[&outcome.run_id],
        )
        .expect("assumptions");
    assert!(assumptions.contains("no year"), "{assumptions}");
}

#[test]
fn declared_year_and_zone_resolve_the_wall_clock() {
    let mut harness = Harness::new();
    let line = b"<34>Oct 27 10:00:00 host sshd[123]: Accepted password for bob from 10.0.0.6 port 22 ssh2\n";
    let acquisition = harness.capture(&[("syslog.log", line)]);
    let outcome = syslog(&harness, &acquisition, Some("Europe/Berlin"), Some(2026));
    assert_eq!(outcome.events, 1);
    assert_eq!(
        harness
            .scalar(
                "SELECT chosen_seconds FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("1793091600"),
        "10:00 CET (DST ended Oct 25) is 09:00Z"
    );
    let assumptions = harness
        .scalar(
            "SELECT assumptions_json FROM event_times WHERE event_id = (
                 SELECT id FROM events WHERE parse_run_id = ?1
             )",
            &[&outcome.run_id],
        )
        .expect("assumptions");
    assert!(assumptions.contains("2026"), "{assumptions}");
    assert!(assumptions.contains("Europe/Berlin"), "{assumptions}");
}

#[test]
fn dst_overlap_produces_two_genuine_candidates() {
    let mut harness = Harness::new();
    let line =
        b"<34>Oct 25 02:30:00 host sshd[1]: Accepted password for bob from 10.0.0.6 port 22 ssh2\n";
    let acquisition = harness.capture(&[("syslog.log", line)]);
    let outcome = syslog(&harness, &acquisition, Some("Europe/Berlin"), Some(2026));
    assert_eq!(
        harness
            .scalar(
                "SELECT time_status FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("ambiguous")
    );
    let candidates = harness
        .scalar(
            "SELECT candidates_json FROM event_times WHERE event_id = (
                 SELECT id FROM events WHERE parse_run_id = ?1
             )",
            &[&outcome.run_id],
        )
        .expect("candidates");
    assert!(candidates.contains("1792888200"), "{candidates}");
    assert!(candidates.contains("1792891800"), "{candidates}");
    assert!(
        harness
            .scalar(
                "SELECT chosen_seconds FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref()
            == Some("1792888200"),
        "the earliest candidate is the display instant"
    );
}

#[test]
fn a_new_year_rotation_is_ambiguous_not_guessed() {
    let mut harness = Harness::new();
    let lines =
        b"<34>Dec 31 23:59:58 host sshd[1]: Accepted password for bob from 10.0.0.6 port 22 ssh2\n\
<34>Jan  1 00:00:02 host sshd[1]: Accepted password for bob from 10.0.0.6 port 22 ssh2\n";
    let acquisition = harness.capture(&[("syslog.log", lines)]);
    let outcome = syslog(&harness, &acquisition, Some("UTC"), Some(2025));
    assert_eq!(outcome.events, 2);
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM events WHERE parse_run_id = ?1 AND time_status = 'resolved'",
            &[&outcome.run_id],
        ),
        1
    );
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM events WHERE parse_run_id = ?1 AND time_status = 'ambiguous'",
            &[&outcome.run_id],
        ),
        1
    );
    let candidates = harness
        .scalar(
            "SELECT candidates_json FROM event_times WHERE event_id = (
                 SELECT id FROM events WHERE parse_run_id = ?1 AND time_status = 'ambiguous'
             )",
            &[&outcome.run_id],
        )
        .expect("candidates");
    assert!(candidates.contains("1735689602"), "{candidates}");
    assert!(candidates.contains("1767225602"), "{candidates}");
}

#[test]
fn malformed_records_are_diagnosed_not_stored() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("syslog.log", b"this is not a syslog line\n")]);
    let outcome = syslog(&harness, &acquisition, None, None);
    assert_eq!(outcome.records, 1);
    assert_eq!(outcome.observations, 0);
    assert_eq!(outcome.events, 0);
    assert_eq!(outcome.state, "partial");
    assert_eq!(outcome.diagnostics[0].code, "malformed_record");
}

#[test]
fn unmatched_messages_stay_raw_without_an_event() {
    let mut harness = Harness::new();
    let line = b"<34>Oct 27 10:00:00 host myapp[1]: service started\n";
    let acquisition = harness.capture(&[("syslog.log", line)]);
    let outcome = syslog(&harness, &acquisition, Some("UTC"), Some(2026));
    assert_eq!(outcome.observations, 1);
    assert_eq!(outcome.events, 0);
    assert_eq!(
        outcome.state, "completed",
        "no invented event or diagnostic"
    );
}

#[test]
fn tested_sudo_mapping_is_supported() {
    let mut harness = Harness::new();
    let line =
        b"<34>Oct 27 10:00:00 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id\n";
    let acquisition = harness.capture(&[("syslog.log", line)]);
    let outcome = syslog(&harness, &acquisition, Some("UTC"), Some(2026));
    assert_eq!(
        harness
            .scalar(
                "SELECT kind FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("auth.sudo_command")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT summary FROM events WHERE parse_run_id = ?1",
                &[&outcome.run_id],
            )
            .as_deref(),
        Some("sudo command by alice")
    );
}

#[test]
fn an_unknown_timezone_is_a_usage_error_before_any_run() {
    let mut harness = Harness::new();
    let acquisition =
        harness.capture(&[("syslog.log", b"<34>Oct 27 10:00:00 host myapp[1]: ok\n")]);
    let error = harness
        .import(&acquisition, "syslog.log", |request| {
            request.format = Some(LogFormat::Syslog3164);
            request.syslog.timezone = Some("Mars/Olympus".into());
        })
        .expect_err("must refuse");
    assert_eq!(error.code(), "invalid_request");
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM parse_runs WHERE acquisition_id = ?1 AND parser_id LIKE 'syslog%'",
            &[&acquisition],
        ),
        0,
        "no run row is recorded for a rejected configuration"
    );
}

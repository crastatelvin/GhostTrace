//! P5.2 rule contract: every rule explains itself, missing prerequisites stay
//! visible, and no output claims a probability of maliciousness.

mod support;

use ghosttrace_core::analysis::rules::{AnalysisReport, AnalysisRequest, RuleConfig, RuleOutcome};
use ghosttrace_core::domain::finding::Severity;
use ghosttrace_core::ingest::{ImportOutcome, LogFormat};
use support::Harness;

const AUTH: &str = "auth.fail_then_success";
const DOWNLOAD: &str = "process.download_then_execute";
const HASH_CHANGED: &str = "file.hash_changed_metadata_equal";
const CLOCK: &str = "time.clock_discontinuity";
const HOURS: &str = "activity.outside_declared_hours";

fn import_jsonl(harness: &mut Harness, records: &[u8]) -> ImportOutcome {
    let acquisition = harness.capture(&[("logs/events.jsonl", records)]);
    harness
        .import(&acquisition, "logs/events.jsonl", |request| {
            request.format = Some(LogFormat::Jsonl);
            request.jsonl.message_field = Some("msg".into());
            request.jsonl.host_field = Some("host".into());
            request.jsonl.kind_field = Some("kind".into());
        })
        .expect("import")
}

fn analyze(harness: &Harness, outcome: &ImportOutcome, config: RuleConfig) -> AnalysisReport {
    harness
        .session()
        .analyze(&AnalysisRequest {
            revision: outcome.run_id.clone(),
            config,
        })
        .expect("analyze")
}

fn outcome<'a>(report: &'a AnalysisReport, id: &str) -> &'a RuleOutcome {
    report
        .outcomes
        .iter()
        .find(|outcome| outcome.rule_id == id)
        .expect("a rule outcome per built-in rule")
}

#[test]
fn authentication_rule_counts_a_window_and_explains_alternatives() {
    let mut harness = Harness::new();
    let records: &[u8] = b"\
{\"ts\":\"2026-10-27T10:00:00Z\",\"kind\":\"auth.login_failed\",\"host\":\"edge-a\",\"user\":\"bob\",\"service\":\"sshd\",\"msg\":\"fail 1\"}
{\"ts\":\"2026-10-27T10:00:30Z\",\"kind\":\"auth.login_failed\",\"host\":\"edge-a\",\"user\":\"bob\",\"service\":\"sshd\",\"msg\":\"fail 2\"}
{\"ts\":\"2026-10-27T10:01:00Z\",\"kind\":\"auth.login_failed\",\"host\":\"edge-a\",\"user\":\"bob\",\"service\":\"sshd\",\"msg\":\"fail 3\"}
{\"ts\":\"2026-10-27T10:01:30Z\",\"kind\":\"auth.login_failed\",\"host\":\"edge-a\",\"user\":\"bob\",\"service\":\"sshd\",\"msg\":\"fail 4\"}
{\"ts\":\"2026-10-27T10:02:00Z\",\"kind\":\"auth.login_failed\",\"host\":\"edge-a\",\"user\":\"bob\",\"service\":\"sshd\",\"msg\":\"fail 5\"}
{\"ts\":\"2026-10-27T10:04:00Z\",\"kind\":\"auth.login_succeeded\",\"host\":\"edge-a\",\"user\":\"bob\",\"service\":\"sshd\",\"msg\":\"ok\"}
{\"ts\":\"2026-10-27T10:00:00Z\",\"kind\":\"auth.login_failed\",\"host\":\"edge-a\",\"user\":\"alice\",\"service\":\"sshd\",\"msg\":\"fail 1\"}
{\"ts\":\"2026-10-27T10:00:30Z\",\"kind\":\"auth.login_failed\",\"host\":\"edge-a\",\"user\":\"alice\",\"service\":\"sshd\",\"msg\":\"fail 2\"}
{\"ts\":\"2026-10-27T10:01:00Z\",\"kind\":\"auth.login_failed\",\"host\":\"edge-a\",\"user\":\"alice\",\"service\":\"sshd\",\"msg\":\"fail 3\"}
{\"ts\":\"2026-10-27T10:01:30Z\",\"kind\":\"auth.login_failed\",\"host\":\"edge-a\",\"user\":\"alice\",\"service\":\"sshd\",\"msg\":\"fail 4\"}
{\"ts\":\"2026-10-27T10:09:00Z\",\"kind\":\"auth.login_succeeded\",\"host\":\"edge-a\",\"user\":\"alice\",\"service\":\"sshd\",\"msg\":\"ok\"}
";
    let imported = import_jsonl(&mut harness, records);
    let report = analyze(&harness, &imported, RuleConfig::default());
    assert_eq!(report.state, "completed");
    assert_eq!(report.outcomes.len(), 5, "all five rules report an outcome");

    let auth = outcome(&report, AUTH);
    assert_eq!(auth.status, "evaluated");
    assert_eq!(auth.findings, 1, "bob's 5 failures; alice only had 4");
    let finding = &report.findings[0];
    assert_eq!(finding.rule_id, AUTH);
    assert_eq!(finding.rule_version, "1");
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.event_ids.len(), 6, "five failures and the success");
    assert_eq!(finding.predicates["user"], "bob");
    assert_eq!(finding.predicates["failures"], 5);
    assert_eq!(finding.predicates["interval_seconds"], 240);
    assert_eq!(finding.alternatives.len(), 4);
    assert!(finding.rationale.contains("credential guessing"));
    assert!(
        !finding.rationale.contains('%')
            && !finding.rationale.to_lowercase().contains("probability"),
        "no uncalibrated score: {}",
        finding.rationale
    );
    for outcome in &report.outcomes {
        assert!(
            !outcome.reason.as_deref().unwrap_or("").contains('%'),
            "no percentage in an explanation"
        );
    }

    let stored = harness
        .session()
        .findings(&report.run_id)
        .expect("stored findings");
    assert_eq!(stored, report.findings);
}

#[test]
fn authentication_window_boundary_is_exact() {
    let mut harness = Harness::new();
    let mut records = String::new();
    for (user, success) in [("exact", "11:10:00"), ("over", "12:10:01")] {
        let hour = if user == "exact" { 11 } else { 12 };
        for index in 0..5 {
            records.push_str(&format!(
                "{{\"ts\":\"2026-10-27T{hour}:00:0{index}Z\",\"kind\":\"auth.login_failed\",\"host\":\"edge-a\",\"user\":\"{user}\",\"service\":\"sshd\",\"msg\":\"fail\"}}\n"
            ));
        }
        records.push_str(&format!(
            "{{\"ts\":\"2026-10-27T{success}Z\",\"kind\":\"auth.login_succeeded\",\"host\":\"edge-a\",\"user\":\"{user}\",\"service\":\"sshd\",\"msg\":\"ok\"}}\n"
        ));
    }
    let imported = import_jsonl(&mut harness, records.as_bytes());
    let report = analyze(&harness, &imported, RuleConfig::default());
    let auth = outcome(&report, AUTH);
    assert_eq!(auth.findings, 1, "600 s is inside the window; 601 s is not");
    assert_eq!(report.findings[0].predicates["user"], "exact");
}

#[test]
fn authentication_rule_reports_missing_account_and_unresolved_time() {
    let mut harness = Harness::new();
    // No `user` field: the rule must not guess an account from the message.
    let records: &[u8] = b"\
{\"ts\":\"2026-10-27T10:00:00Z\",\"kind\":\"auth.login_failed\",\"host\":\"edge-a\",\"msg\":\"fail for bob\"}
{\"ts\":\"2026-10-27T10:01:00Z\",\"kind\":\"auth.login_succeeded\",\"host\":\"edge-a\",\"msg\":\"accepted bob\"}
";
    let imported = import_jsonl(&mut harness, records);
    let report = analyze(&harness, &imported, RuleConfig::default());
    let auth = outcome(&report, AUTH);
    assert_eq!(auth.status, "not_evaluated");
    assert!(
        auth.reason
            .as_deref()
            .unwrap_or("")
            .contains("mapped account"),
        "{:?}",
        auth.reason
    );
    assert_eq!(auth.findings, 0);

    // Unresolved times are excluded and counted, not ordered.
    let mut harness = Harness::new();
    let records: &[u8] = b"\
{\"ts\":\"not-a-time\",\"kind\":\"auth.login_failed\",\"host\":\"edge-a\",\"user\":\"bob\",\"service\":\"sshd\",\"msg\":\"fail\"}
{\"ts\":\"also-not-a-time\",\"kind\":\"auth.login_succeeded\",\"host\":\"edge-a\",\"user\":\"bob\",\"service\":\"sshd\",\"msg\":\"ok\"}
";
    let imported = import_jsonl(&mut harness, records);
    assert_eq!(imported.state, "partial");
    let report = analyze(&harness, &imported, RuleConfig::default());
    let auth = outcome(&report, AUTH);
    assert_eq!(auth.status, "not_evaluated");
    assert_eq!(auth.events_considered, 2);
    assert_eq!(
        auth.excluded, 2,
        "both auth events with unusable time are counted as excluded"
    );
    assert!(
        auth.reason
            .as_deref()
            .unwrap_or("")
            .contains("resolved time")
    );
}

#[test]
fn download_rule_needs_supported_identifiers_and_obeys_the_window() {
    let mut harness = Harness::new();
    let records: &[u8] = b"\
{\"ts\":\"2026-10-27T10:00:00Z\",\"kind\":\"browser.download\",\"host\":\"edge-a\",\"msg\":\"download\",\"path\":\"/tmp/payload\"}
{\"ts\":\"2026-10-27T10:05:00Z\",\"kind\":\"process.execute\",\"host\":\"edge-a\",\"msg\":\"run\",\"path\":\"/tmp/payload\"}
{\"ts\":\"2026-10-27T10:10:00Z\",\"kind\":\"browser.download\",\"host\":\"edge-a\",\"msg\":\"download 2\",\"path\":\"/tmp/late\"}
{\"ts\":\"2026-10-27T10:26:00Z\",\"kind\":\"process.execute\",\"host\":\"edge-a\",\"msg\":\"run 2\",\"path\":\"/tmp/late\"}
";
    let imported = import_jsonl(&mut harness, records);
    let report = analyze(&harness, &imported, RuleConfig::default());
    let download = outcome(&report, DOWNLOAD);
    assert_eq!(download.status, "evaluated");
    assert_eq!(download.findings, 1, "16 minutes apart is outside 15");
    let finding = &report.findings[0];
    assert_eq!(finding.rule_id, DOWNLOAD);
    assert_eq!(finding.predicates["path"], "/tmp/payload");
    assert_eq!(finding.predicates["gap_seconds"], 300);
    assert!(finding.rationale.contains("candidate causal sequence"));
    assert!(
        finding
            .alternatives
            .iter()
            .any(|line| line.contains("already existed"))
    );

    // No execution events at all: clearly reported, never an empty success.
    let mut harness = Harness::new();
    let records: &[u8] = b"\
{\"ts\":\"2026-10-27T10:00:00Z\",\"kind\":\"browser.download\",\"host\":\"edge-a\",\"msg\":\"download\",\"path\":\"/tmp/payload\"}
";
    let imported = import_jsonl(&mut harness, records);
    let report = analyze(&harness, &imported, RuleConfig::default());
    assert_eq!(outcome(&report, DOWNLOAD).status, "not_evaluated");

    // Executions that carry no path or digest are not guessed from a message.
    let mut harness = Harness::new();
    let records: &[u8] = b"\
{\"ts\":\"2026-10-27T10:00:00Z\",\"kind\":\"browser.download\",\"host\":\"edge-a\",\"msg\":\"download\",\"path\":\"/tmp/payload\"}
{\"ts\":\"2026-10-27T10:01:00Z\",\"kind\":\"process.execute\",\"host\":\"edge-a\",\"msg\":\"executed /tmp/payload\"}
";
    let imported = import_jsonl(&mut harness, records);
    let report = analyze(&harness, &imported, RuleConfig::default());
    let download = outcome(&report, DOWNLOAD);
    assert_eq!(download.status, "not_evaluated");
    assert!(
        download
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("no supported path or digest")
    );
}

#[test]
fn hash_change_rule_requires_equal_size_and_source_mtime() {
    let mut harness = Harness::new();
    let first = harness.capture_at(&[("etc/app.conf", b"AAAA")], 1_700_000_000);
    let second = harness.capture_at(&[("etc/app.conf", b"BBBB")], 1_700_000_000);
    let runs: Vec<String> = [first, second]
        .iter()
        .map(|acquisition| {
            harness
                .scalar(
                    "SELECT id FROM parse_runs
                     WHERE acquisition_id = ?1 AND parser_id = 'capture.metadata.v1'",
                    &[acquisition],
                )
                .expect("capture run")
        })
        .collect();
    let report = harness
        .session()
        .analyze(&AnalysisRequest {
            revision: runs[0].clone(),
            config: RuleConfig::default(),
        })
        .expect("analyze");
    let hash = outcome(&report, HASH_CHANGED);
    assert_eq!(hash.status, "evaluated");
    assert_eq!(hash.findings, 1);
    let finding = &report.findings[0];
    assert_eq!(finding.event_ids.len(), 2, "both capture events support it");
    assert_eq!(finding.predicates["path"], "etc/app.conf");
    assert_eq!(finding.predicates["size"], 4);
    assert_ne!(
        finding.predicates["sha256"][0], finding.predicates["sha256"][1],
        "the hashes differ"
    );
    assert_eq!(finding.severity, Severity::Low);

    // The same bytes with a different mtime is not this rule's case.
    let mut harness = Harness::new();
    let first = harness.capture_at(&[("etc/app.conf", b"AAAA")], 1_700_000_000);
    let second = harness.capture_at(&[("etc/app.conf", b"BBBB")], 1_700_000_100);
    let run = harness
        .scalar(
            "SELECT id FROM parse_runs
             WHERE acquisition_id = ?1 AND parser_id = 'capture.metadata.v1'",
            &[&first],
        )
        .expect("capture run");
    let _ = second;
    let report = harness
        .session()
        .analyze(&AnalysisRequest {
            revision: run,
            config: RuleConfig::default(),
        })
        .expect("analyze");
    assert_eq!(outcome(&report, HASH_CHANGED).findings, 0);
}

fn text(name: &str, value: &str) -> Vec<u8> {
    format!("{name}={value}\n").into_bytes()
}

fn entry(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for field in fields {
        bytes.extend_from_slice(field);
    }
    bytes.push(b'\n');
    bytes
}

#[test]
fn clock_rule_compares_realtime_against_boot_monotonic_time() {
    let mut harness = Harness::new();
    let boot = "6c7c6013a26343b29e964691ff25d04c";
    let mut bytes = entry(&[
        text("__CURSOR", "s=1;i=1"),
        text("__REALTIME_TIMESTAMP", "1700000000000000"),
        text("__MONOTONIC_TIMESTAMP", "1000000000"),
        text("_BOOT_ID", boot),
        text("MESSAGE", "first"),
    ]);
    bytes.extend_from_slice(&entry(&[
        text("__CURSOR", "s=1;i=2"),
        text("__REALTIME_TIMESTAMP", "1700000030000000"),
        text("__MONOTONIC_TIMESTAMP", "1010000000"),
        text("_BOOT_ID", boot),
        text("MESSAGE", "second"),
    ]));
    let acquisition = harness.capture(&[("journal.export", &bytes)]);
    let imported = harness
        .import(&acquisition, "journal.export", |request| {
            request.format = Some(LogFormat::JournalExport);
        })
        .expect("import");
    let report = analyze(&harness, &imported, RuleConfig::default());
    let clock = outcome(&report, CLOCK);
    assert_eq!(clock.status, "evaluated");
    assert_eq!(clock.findings, 1);
    let finding = &report.findings[0];
    assert_eq!(finding.predicates["divergence_millis"], 20_000);
    assert_eq!(finding.event_ids.len(), 2);
    assert_eq!(finding.severity, Severity::Info);

    // One sample cannot establish a discontinuity.
    let mut harness = Harness::new();
    let bytes = entry(&[
        text("__CURSOR", "s=1;i=1"),
        text("__REALTIME_TIMESTAMP", "1700000000000000"),
        text("__MONOTONIC_TIMESTAMP", "1000000000"),
        text("_BOOT_ID", boot),
        text("MESSAGE", "only"),
    ]);
    let acquisition = harness.capture(&[("journal.export", &bytes)]);
    let imported = harness
        .import(&acquisition, "journal.export", |request| {
            request.format = Some(LogFormat::JournalExport);
        })
        .expect("import");
    let report = analyze(&harness, &imported, RuleConfig::default());
    assert_eq!(outcome(&report, CLOCK).status, "not_evaluated");
}

#[test]
fn outside_hours_rule_is_disabled_without_a_declared_baseline() {
    let mut harness = Harness::new();
    let records: &[u8] = b"\
{\"ts\":\"2026-10-27T02:00:00Z\",\"kind\":\"activity\",\"host\":\"edge-a\",\"msg\":\"late\"}
{\"ts\":\"2026-10-27T10:00:00Z\",\"kind\":\"activity\",\"host\":\"edge-a\",\"msg\":\"work\"}
";
    let imported = import_jsonl(&mut harness, records);

    let disabled = analyze(&harness, &imported, RuleConfig::default());
    let hours = outcome(&disabled, HOURS);
    assert_eq!(hours.status, "not_evaluated");
    assert!(
        hours
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("no declared schedule baseline")
    );

    let config = RuleConfig::from_toml(
        "[activity.outside_declared_hours]\n\
         timezone = \"Europe/Berlin\"\n\
         weekdays = [\"Mon\", \"Tue\", \"Wed\", \"Thu\", \"Fri\"]\n\
         start = \"09:00\"\n\
         end = \"17:00\"\n",
    )
    .expect("schedule");
    let report = analyze(&harness, &imported, config);
    let hours = outcome(&report, HOURS);
    assert_eq!(hours.status, "evaluated");
    assert_eq!(hours.findings, 1, "04:00 local is outside 09:00..17:00");
    let finding = &report.findings[0];
    assert_eq!(finding.predicates["timezone"], "Europe/Berlin");
    assert_eq!(finding.predicates["local_time"], "2026-10-27 03:00:00");
    assert_eq!(finding.severity, Severity::Info);
    assert!(finding.rationale.contains("policy deviation"));

    // A declared holiday turns an inside-hours event into an outside one.
    let config = RuleConfig::from_toml(
        "[activity.outside_declared_hours]\n\
         timezone = \"Europe/Berlin\"\n\
         weekdays = [\"Mon\", \"Tue\", \"Wed\", \"Thu\", \"Fri\"]\n\
         start = \"09:00\"\n\
         end = \"17:00\"\n\
         holidays = [\"2026-10-27\"]\n",
    )
    .expect("schedule");
    let report = analyze(&harness, &imported, config);
    assert_eq!(
        outcome(&report, HOURS).findings,
        2,
        "both events fall on the declared holiday"
    );
}

#[test]
fn analysis_run_is_reproducible_and_replays_without_duplicates() {
    let mut harness = Harness::new();
    let records: &[u8] = b"\
{\"ts\":\"2026-10-27T10:00:00Z\",\"kind\":\"activity\",\"host\":\"edge-a\",\"msg\":\"one\"}
";
    let imported = import_jsonl(&mut harness, records);
    let first = analyze(&harness, &imported, RuleConfig::default());
    let second = analyze(&harness, &imported, RuleConfig::default());
    assert_eq!(first.run_id, second.run_id, "same input, same run identity");
    assert_eq!(
        harness.count("SELECT count(*) FROM analysis_runs", &[]),
        1,
        "replay rewrites the same run row"
    );
    assert_eq!(
        harness.count("SELECT count(*) FROM findings", &[]),
        first.findings.len() as i64
    );
}

//! P5.2 rule parameter contract: unknown keys and out-of-range values are
//! rejected, the config digest is stable, and every run records what it did.

mod support;

use ghosttrace_core::analysis::rules::{AnalysisRequest, RULES_ID, RULES_VERSION, RuleConfig};
use ghosttrace_core::ingest::LogFormat;
use support::Harness;

fn parse(text: &str) -> Result<RuleConfig, ghosttrace_core::error::CoreError> {
    RuleConfig::from_toml(text)
}

#[test]
fn unknown_sections_and_fields_are_rejected() {
    for text in [
        // A misspelled parameter must not silently fall back to the default.
        "[auth.fail_then_success]\nfailure = 3\n",
        // A misspelled section must not be ignored.
        "[auth.fail_then_sucsess]\nfailures = 3\n",
        // Top-level freedom is not offered either.
        "[anything]\nenabled = true\n",
        // The schedule baseline is a fixed value set, not free text.
        "[activity.outside_declared_hours]\ntimezone = \"UTC\"\ncommand = \"sudo\"\n",
    ] {
        let error = parse(text).expect_err(text);
        assert_eq!(error.code(), "invalid_request", "for {text:?}");
    }
}

/// A complete, valid schedule baseline; probes below change one line of it.
fn baseline(weekdays: &str, start: &str, end: &str, timezone: &str) -> String {
    format!(
        "[activity.outside_declared_hours]\n\
         timezone = \"{timezone}\"\n\
         weekdays = [{weekdays}]\n\
         start = \"{start}\"\n\
         end = \"{end}\"\n"
    )
}

#[test]
fn parameters_are_range_and_syntax_checked() {
    let schedule = [
        baseline("\"Mon\"", "09:00", "17:00", "Mars/Olympus"),
        baseline("", "09:00", "17:00", "UTC"),
        baseline("\"Funday\"", "09:00", "17:00", "UTC"),
        baseline("\"Mon\", \"Mon\"", "09:00", "17:00", "UTC"),
        baseline("\"Mon\"", "17:00", "09:00", "UTC"),
        format!(
            "{}holidays = [\"2026-13-01\"]\n",
            baseline("\"Mon\"", "09:00", "17:00", "UTC")
        ),
    ];
    for text in [
        "[auth.fail_then_success]\nfailures = 0\n".to_string(),
        "[auth.fail_then_success]\nfailures = 101\n".to_string(),
        "[auth.fail_then_success]\nwindow_seconds = 0\n".to_string(),
        "[process.download_then_execute]\nwindow_seconds = 86_401\n".to_string(),
        "[time.clock_discontinuity]\nthreshold_seconds = 86_401\n".to_string(),
    ]
    .into_iter()
    .chain(schedule)
    {
        let error = parse(&text).expect_err(&text);
        assert_eq!(error.code(), "invalid_request", "for {text:?}");
    }

    // The documented shape parses exactly.
    let config = parse(
        "[auth.fail_then_success]\n\
         failures = 3\n\
         window_seconds = 120\n\
         [process.download_then_execute]\n\
         window_seconds = 60\n\
         [time.clock_discontinuity]\n\
         threshold_seconds = 5\n\
         [activity.outside_declared_hours]\n\
         timezone = \"Europe/Berlin\"\n\
         weekdays = [\"Mon\", \"Tue\"]\n\
         start = \"09:00\"\n\
         end = \"17:00\"\n\
         holidays = [\"2026-12-24\"]\n",
    )
    .expect("valid config");
    assert_eq!(config.auth().failures, 3);
    assert_eq!(config.download().window_seconds, 60);
    assert_eq!(config.clock().threshold_seconds, 5);
    assert!(config.hours().is_some());
}

#[test]
fn config_digest_is_stable_and_parameter_sensitive() {
    let text = "[auth.fail_then_success]\nfailures = 4\n";
    assert_eq!(
        parse(text).expect("a").digest(),
        parse(text).expect("b").digest(),
        "identical parameters produce one digest"
    );
    assert_eq!(
        RuleConfig::default().digest(),
        RuleConfig::default().digest()
    );
    assert_ne!(
        parse(text).expect("custom").digest(),
        RuleConfig::default().digest(),
        "a parameter change must change the run identity"
    );
    assert_ne!(
        parse(&baseline("\"Mon\"", "09:00", "17:00", "UTC"))
            .expect("utc")
            .digest(),
        parse(&baseline("\"Mon\"", "09:00", "17:00", "Europe/Berlin"))
            .expect("berlin")
            .digest()
    );

    // Serialization round-trips without changing the digest.
    let config = parse(text).expect("config");
    let json = serde_json::to_string(&config).expect("json");
    let back: RuleConfig = serde_json::from_str(&json).expect("back");
    assert_eq!(config.digest(), back.digest());
}

#[test]
fn each_combination_of_parameters_records_its_own_bounded_run() {
    let mut harness = Harness::new();
    let records: &[u8] = b"\
{\"ts\":\"2026-10-27T10:00:00Z\",\"kind\":\"activity\",\"host\":\"edge-a\",\"msg\":\"one\"}
";
    let acquisition = harness.capture(&[("logs/events.jsonl", records)]);
    let imported = harness
        .import(&acquisition, "logs/events.jsonl", |request| {
            request.format = Some(LogFormat::Jsonl);
            request.jsonl.message_field = Some("msg".into());
            request.jsonl.host_field = Some("host".into());
            request.jsonl.kind_field = Some("kind".into());
        })
        .expect("import");

    let default_run = harness
        .session()
        .analyze(&AnalysisRequest {
            revision: imported.run_id.clone(),
            config: RuleConfig::default(),
        })
        .expect("default");
    let tuned = parse("[auth.fail_then_success]\nfailures = 2\n").expect("tuned");
    let tuned_run = harness
        .session()
        .analyze(&AnalysisRequest {
            revision: imported.run_id.clone(),
            config: tuned,
        })
        .expect("tuned");
    assert_ne!(default_run.run_id, tuned_run.run_id);
    assert_eq!(
        harness.count("SELECT count(*) FROM analysis_runs", &[]),
        2,
        "both parameter sets keep their run"
    );

    // The recorded counts explain every rule, including the ones that could
    // not decide anything for this revision.
    let counts = harness
        .scalar(
            "SELECT counts_json FROM analysis_runs WHERE id = ?1",
            &[&tuned_run.run_id],
        )
        .expect("counts");
    let counts: serde_json::Value = serde_json::from_str(&counts).expect("counts json");
    let array = counts.as_array().expect("array");
    assert_eq!(array.len(), 5);
    for outcome in array {
        assert!(outcome["rule_id"].is_string());
        assert!(outcome["status"].is_string());
        assert!(outcome["events_considered"].is_u64());
        assert!(outcome["truncated"].is_boolean());
    }
    let auth = array
        .iter()
        .find(|outcome| outcome["rule_id"] == "auth.fail_then_success")
        .expect("auth outcome");
    assert_eq!(auth["status"], "not_evaluated");
    assert!(auth["reason"].is_string(), "the reason is recorded");

    let (rules_id, rules_version): (String, String) = {
        let reader = harness.session().reader().expect("reader");
        reader
            .connection()
            .query_row(
                "SELECT rules_id, rules_version FROM analysis_runs WHERE id = ?1",
                [&tuned_run.run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("run row")
    };
    assert_eq!(rules_id, RULES_ID);
    assert_eq!(rules_version, RULES_VERSION);
}

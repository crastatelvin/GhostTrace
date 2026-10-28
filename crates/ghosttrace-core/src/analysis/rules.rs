//! Five compiled, explainable rules (plan Section 11, P5.2).
//!
//! Rules are deterministic Rust evaluators with fixed metadata and bounded
//! TOML parameters. There is no script engine, no regex DSL, no arbitrary SQL,
//! and no remote rule download. Every finding names the rule version, the exact
//! recorded events, the predicates that held, the counts behind the decision,
//! and the alternatives that remain plausible.
//!
//! Missing prerequisites produce `not_evaluated` with a reason. Ambiguous or
//! unresolved times are excluded from definite-order rules and counted, never
//! silently treated as ordered. Severity is a handling priority; nothing here
//! computes or implies a probability of maliciousness.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use chrono::{Datelike, NaiveDate, NaiveTime, TimeZone, Timelike, Weekday};
use chrono_tz::Tz;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::domain::finding::{Disposition, Finding, Severity};
use crate::domain::time::UnixTime;
use crate::error::{CoreError, CoreResult};
use crate::integrity::hash::identity_hex;
use crate::storage::read::CaseReader;
use crate::storage::writer::{CaseWriter, Param, WriteBatch, WriteOp};

/// Rule set identity recorded with every analysis run.
pub const RULES_ID: &str = "builtin";
pub const RULES_VERSION: &str = "1";

/// Hard bounds for one run. Exceeding a bound is reported as truncation.
pub const MAX_EVENTS: usize = 200_000;
pub const MAX_FINDINGS_PER_RULE: usize = 200;

const AUTH_FAILURE: &str = "auth.login_failed";
const AUTH_SUCCESS: &str = "auth.login_succeeded";
const DOWNLOAD: &str = "browser.download";
const PROCESS_EXECUTE: &str = "process.execute";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleMetadata {
    pub id: &'static str,
    pub version: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub requires: &'static str,
}

pub const BUILTIN_RULES: &[RuleMetadata] = &[
    RuleMetadata {
        id: "auth.fail_then_success",
        version: "1",
        title: "Authentication failures followed by a success",
        severity: Severity::Medium,
        requires: "mapped account, service, host, and resolved times",
    },
    RuleMetadata {
        id: "process.download_then_execute",
        version: "1",
        title: "Download followed by an execution referencing the same path or digest",
        severity: Severity::Low,
        requires: "browser download and recorded process execution path or digest",
    },
    RuleMetadata {
        id: "file.hash_changed_metadata_equal",
        version: "1",
        title: "Full hash changed while size and source mtime stayed equal",
        severity: Severity::Low,
        requires: "two complete captures with recorded size and source mtime",
    },
    RuleMetadata {
        id: "time.clock_discontinuity",
        version: "1",
        title: "Realtime clock jumped against boot-scoped monotonic progression",
        severity: Severity::Info,
        requires: "two journal samples with realtime and monotonic times on one boot",
    },
    RuleMetadata {
        id: "activity.outside_declared_hours",
        version: "1",
        title: "Activity outside the declared schedule",
        severity: Severity::Info,
        requires: "an explicit investigator-declared schedule baseline",
    },
];

fn metadata(id: &str) -> &'static RuleMetadata {
    BUILTIN_RULES
        .iter()
        .find(|rule| rule.id == id)
        .expect("built-in rule metadata is complete")
}

/// Validated, bounded rule parameters. Every section is optional; a rule with
/// no parameters uses its documented default, except the schedule rule, which
/// is disabled without an explicit baseline.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RuleConfig {
    pub auth: AuthSection,
    pub process: ProcessSection,
    pub time: TimeSection,
    pub activity: ActivitySection,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuthSection {
    pub fail_then_success: Option<AuthConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProcessSection {
    pub download_then_execute: Option<DownloadConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TimeSection {
    pub clock_discontinuity: Option<ClockConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ActivitySection {
    pub outside_declared_hours: Option<HoursConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuthConfig {
    /// Supported failures required before the success.
    pub failures: usize,
    /// Maximum interval between the first counted failure and the success.
    pub window_seconds: i64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            failures: 5,
            window_seconds: 600,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DownloadConfig {
    pub window_seconds: i64,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            window_seconds: 900,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ClockConfig {
    /// Absolute realtime/monotonic divergence above this is a discontinuity.
    pub threshold_seconds: i64,
}

impl Default for ClockConfig {
    fn default() -> Self {
        Self {
            threshold_seconds: 2,
        }
    }
}

/// The schedule baseline. All four fields are required: a partial schedule
/// would silently invent the missing part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoursConfig {
    pub timezone: String,
    /// Short or long weekday names (`Mon`, `Monday`), at least one.
    pub weekdays: Vec<String>,
    /// `HH:MM`, inclusive start.
    pub start: String,
    /// `HH:MM`, exclusive end.
    pub end: String,
    /// `YYYY-MM-DD`, treated as outside the schedule entirely.
    #[serde(default)]
    pub holidays: Vec<String>,
}

impl RuleConfig {
    /// Effective authentication parameters (documented defaults when absent).
    pub fn auth(&self) -> AuthConfig {
        self.auth.fail_then_success.clone().unwrap_or_default()
    }

    /// Effective download/execute parameters.
    pub fn download(&self) -> DownloadConfig {
        self.process
            .download_then_execute
            .clone()
            .unwrap_or_default()
    }

    /// Effective clock parameters.
    pub fn clock(&self) -> ClockConfig {
        self.time.clock_discontinuity.clone().unwrap_or_default()
    }

    /// The declared schedule, if any. `None` disables the rule.
    pub fn hours(&self) -> Option<&HoursConfig> {
        self.activity.outside_declared_hours.as_ref()
    }

    pub fn from_toml(text: &str) -> CoreResult<Self> {
        let config: Self = toml::from_str(text)
            .map_err(|error| CoreError::InvalidInput(format!("rule config: {error}")))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> CoreResult<()> {
        if let Some(auth) = &self.auth.fail_then_success {
            if !(1..=100).contains(&auth.failures) {
                return Err(CoreError::InvalidInput(
                    "auth.fail_then_success.failures must be 1..=100".into(),
                ));
            }
            if !(1..=86_400).contains(&auth.window_seconds) {
                return Err(CoreError::InvalidInput(
                    "auth.fail_then_success.window_seconds must be 1..=86400".into(),
                ));
            }
        }
        if let Some(download) = &self.process.download_then_execute
            && !(1..=86_400).contains(&download.window_seconds)
        {
            return Err(CoreError::InvalidInput(
                "process.download_then_execute.window_seconds must be 1..=86400".into(),
            ));
        }
        if let Some(clock) = &self.time.clock_discontinuity
            && !(0..=86_400).contains(&clock.threshold_seconds)
        {
            return Err(CoreError::InvalidInput(
                "time.clock_discontinuity.threshold_seconds must be 0..=86400".into(),
            ));
        }
        if let Some(hours) = self.hours() {
            if hours.timezone.trim().is_empty() {
                return Err(CoreError::InvalidInput(
                    "activity.outside_declared_hours.timezone is required".into(),
                ));
            }
            Tz::from_str(&hours.timezone).map_err(|_| {
                CoreError::InvalidInput(format!(
                    "activity.outside_declared_hours.timezone is not a known zone: {}",
                    hours.timezone
                ))
            })?;
            if hours.weekdays.is_empty() || hours.weekdays.len() > 7 {
                return Err(CoreError::InvalidInput(
                    "activity.outside_declared_hours.weekdays must list 1..=7 days".into(),
                ));
            }
            let mut seen: Vec<Weekday> = Vec::new();
            for day in &hours.weekdays {
                let weekday = Weekday::from_str(day).map_err(|_| {
                    CoreError::InvalidInput(format!(
                        "activity.outside_declared_hours.weekdays has an unknown day: {day}"
                    ))
                })?;
                if seen.contains(&weekday) {
                    return Err(CoreError::InvalidInput(
                        "activity.outside_declared_hours.weekdays repeats a day".into(),
                    ));
                }
                seen.push(weekday);
            }
            let start = parse_clock(&hours.start)?;
            let end = parse_clock(&hours.end)?;
            if start >= end {
                return Err(CoreError::InvalidInput(
                    "activity.outside_declared_hours.start must be before end".into(),
                ));
            }
            if hours.holidays.len() > 366 {
                return Err(CoreError::InvalidInput(
                    "activity.outside_declared_hours.holidays is limited to 366 dates".into(),
                ));
            }
            for holiday in &hours.holidays {
                NaiveDate::parse_from_str(holiday, "%Y-%m-%d").map_err(|_| {
                    CoreError::InvalidInput(format!(
                        "activity.outside_declared_hours.holidays has an invalid date: {holiday}"
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// Content digest of the effective parameters, recorded on the run.
    pub fn digest(&self) -> String {
        let text = serde_json::to_string(self).expect("rule config always serializes");
        identity_hex(&text, 64)
    }
}

fn parse_clock(text: &str) -> CoreResult<NaiveTime> {
    NaiveTime::parse_from_str(text, "%H:%M").map_err(|_| {
        CoreError::InvalidInput(format!(
            "activity.outside_declared_hours time is not HH:MM: {text}"
        ))
    })
}

/// One analysis request. The revision is a parse run id; rules never mix runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisRequest {
    pub revision: String,
    pub config: RuleConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleOutcome {
    pub rule_id: String,
    pub rule_version: String,
    /// `evaluated` or `not_evaluated`.
    pub status: String,
    pub reason: Option<String>,
    pub findings: u64,
    /// Events the rule looked at.
    pub events_considered: u64,
    /// Events or records excluded for missing identifiers or uncertain time.
    pub excluded: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub run_id: String,
    pub input_revision: String,
    pub rules_id: String,
    pub rules_version: String,
    pub config_digest: String,
    /// `completed`, or `partial` when a bound truncated the pass.
    pub state: String,
    pub findings: Vec<Finding>,
    pub outcomes: Vec<RuleOutcome>,
}

/// Evaluate all five rules against one parse run and record a reproducible run.
pub fn run_analysis(
    writer: &CaseWriter,
    reader: &CaseReader,
    request: &AnalysisRequest,
) -> CoreResult<AnalysisReport> {
    request.config.validate()?;
    let events = load_events(reader, &request.revision)?;
    let digest = request.config.digest();
    let mut drafts = Vec::new();
    let mut outcomes = Vec::new();

    let results = [
        evaluate_auth(
            &events,
            &request.config.auth(),
            metadata("auth.fail_then_success"),
        ),
        evaluate_download(
            &events,
            &request.config.download(),
            metadata("process.download_then_execute"),
        ),
        evaluate_hash_changed(reader, metadata("file.hash_changed_metadata_equal"))?,
        evaluate_clock(
            reader,
            &request.revision,
            &request.config.clock(),
            metadata("time.clock_discontinuity"),
        )?,
        evaluate_hours(
            &events,
            request.config.hours(),
            metadata("activity.outside_declared_hours"),
        ),
    ];
    for result in results {
        outcomes.push(result.outcome);
        drafts.extend(result.drafts);
    }

    let truncated = outcomes.iter().any(|outcome| outcome.truncated);
    let state = if truncated { "partial" } else { "completed" };
    let config_digest = digest;
    let run_id = format!(
        "arun-{}",
        identity_hex(
            &format!(
                "{}|{}|{}|{}",
                request.revision, RULES_ID, RULES_VERSION, config_digest
            ),
            24
        )
    );
    let counts = serde_json::to_string(&outcomes)
        .map_err(|error| CoreError::Storage(format!("serialize rule counts: {error}")))?;
    writer.execute(WriteBatch::new().push(WriteOp::upsert(
        "analysis_runs",
        vec![
            "id",
            "input_revision",
            "rules_id",
            "rules_version",
            "config_digest",
            "state",
            "time_adjustments_json",
            "counts_json",
        ],
        vec![
            Param::Text(run_id.clone()),
            Param::Text(request.revision.clone()),
            Param::Text(RULES_ID.to_string()),
            Param::Text(RULES_VERSION.to_string()),
            Param::Text(config_digest.clone()),
            Param::Text(state.to_string()),
            Param::Text("[]".to_string()),
            Param::Text(counts),
        ],
    )))?;

    if !drafts.is_empty() {
        let mut finding_ids = BTreeSet::new();
        let mut batch = WriteBatch::new();
        for draft in &drafts {
            let id = draft.id(&request.revision, &config_digest);
            if !finding_ids.insert(id.clone()) {
                continue;
            }
            let predicates = serde_json::to_string(&draft.predicates)
                .map_err(|error| CoreError::Storage(format!("serialize predicates: {error}")))?;
            let alternatives = serde_json::to_string(&draft.alternatives)
                .map_err(|error| CoreError::Storage(format!("serialize alternatives: {error}")))?;
            batch = batch.push(WriteOp::fact(
                "findings",
                vec![
                    "id",
                    "analysis_run_id",
                    "rule_id",
                    "rule_version",
                    "event_ids_json",
                    "predicates_json",
                    "severity",
                    "rationale",
                    "alternatives_json",
                    "disposition",
                ],
                vec![
                    Param::Text(id),
                    Param::Text(run_id.clone()),
                    Param::Text(draft.rule.id.to_string()),
                    Param::Text(draft.rule.version.to_string()),
                    Param::Text(
                        serde_json::to_string(&draft.event_ids)
                            .expect("event ids always serialize"),
                    ),
                    Param::Text(predicates),
                    Param::Text(draft.rule.severity.as_str().to_string()),
                    Param::Text(draft.rationale.clone()),
                    Param::Text(alternatives),
                    Param::Text(Disposition::Undismissed.as_str().to_string()),
                ],
            ));
        }
        writer.execute(batch)?;
    }

    let findings = load_findings(reader, &run_id)?;
    Ok(AnalysisReport {
        run_id,
        input_revision: request.revision.clone(),
        rules_id: RULES_ID.to_string(),
        rules_version: RULES_VERSION.to_string(),
        config_digest,
        state: state.to_string(),
        findings,
        outcomes,
    })
}

struct Draft {
    rule: &'static RuleMetadata,
    event_ids: Vec<String>,
    predicates: Value,
    rationale: String,
    alternatives: Vec<String>,
}

impl Draft {
    fn id(&self, revision: &str, config_digest: &str) -> String {
        let mut event_ids = self.event_ids.clone();
        event_ids.sort();
        event_ids.dedup();
        let predicates = self.predicates.to_string();
        format!(
            "fnd-{}",
            identity_hex(
                &format!(
                    "{}|{}|{}|{}|{}|{}",
                    self.rule.id,
                    self.rule.version,
                    revision,
                    config_digest,
                    event_ids.join(","),
                    predicates
                ),
                24
            )
        )
    }
}

struct RuleResult {
    drafts: Vec<Draft>,
    outcome: RuleOutcome,
}

fn not_evaluated(rule: &'static RuleMetadata, reason: impl Into<String>) -> RuleResult {
    not_evaluated_with(rule, reason, 0, 0)
}

/// A rule that could not reach a decision still reports how much it looked at
/// and how much it had to leave out.
fn not_evaluated_with(
    rule: &'static RuleMetadata,
    reason: impl Into<String>,
    events_considered: u64,
    excluded: u64,
) -> RuleResult {
    RuleResult {
        drafts: Vec::new(),
        outcome: RuleOutcome {
            rule_id: rule.id.to_string(),
            rule_version: rule.version.to_string(),
            status: "not_evaluated".into(),
            reason: Some(reason.into()),
            findings: 0,
            events_considered,
            excluded,
            truncated: false,
        },
    }
}

fn evaluated(
    rule: &'static RuleMetadata,
    drafts: Vec<Draft>,
    events_considered: u64,
    excluded: u64,
    truncated: bool,
) -> RuleResult {
    RuleResult {
        outcome: RuleOutcome {
            rule_id: rule.id.to_string(),
            rule_version: rule.version.to_string(),
            status: "evaluated".into(),
            reason: None,
            findings: drafts.len() as u64,
            events_considered,
            excluded,
            truncated,
        },
        drafts,
    }
}

// ---------------------------------------------------------------- event input

struct EventFact {
    id: String,
    kind: String,
    host: Option<String>,
    millis: i64,
    status: String,
    raw: Option<Value>,
    mapped: Option<Value>,
}

impl EventFact {
    fn resolved(&self) -> bool {
        self.status == "resolved"
    }

    fn field(&self, names: &[&str]) -> Option<String> {
        self.mapped
            .as_ref()
            .and_then(|fields| field_text(fields, names))
            .or_else(|| {
                self.raw
                    .as_ref()
                    .and_then(|fields| field_text(fields, names))
            })
    }
}

fn load_events(reader: &CaseReader, revision: &str) -> CoreResult<Vec<EventFact>> {
    let mut statement = reader
        .connection()
        .prepare(
            "SELECT e.id, e.kind, e.host_claim, e.chosen_seconds, e.chosen_nanos,
                    e.time_status, r.raw_fields_json, r.mapped_fields_json
             FROM events e
             LEFT JOIN raw_observations r
               ON r.parse_run_id = e.parse_run_id
              AND r.evidence_id = e.evidence_id
              AND r.locator_identity = e.locator_identity
             WHERE e.parse_run_id = ?1
             ORDER BY e.chosen_seconds IS NULL, e.chosen_seconds, e.id
             LIMIT ?2",
        )
        .map_err(|error| CoreError::Storage(format!("prepare rule events: {error}")))?;
    let mut rows = statement
        .query(params![revision, (MAX_EVENTS + 1) as i64])
        .map_err(|error| CoreError::Storage(format!("read rule events: {error}")))?;
    let mut events = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| CoreError::Storage(format!("read rule event: {error}")))?
    {
        if events.len() == MAX_EVENTS {
            break;
        }
        let seconds: Option<i64> = row.get(3).map_err(storage_error)?;
        let nanos: i64 = row.get(4).map_err(storage_error)?;
        events.push(EventFact {
            id: row.get(0).map_err(storage_error)?,
            kind: row.get(1).map_err(storage_error)?,
            host: row.get(2).map_err(storage_error)?,
            millis: seconds.map_or(0, |seconds| seconds * 1_000 + nanos / 1_000_000),
            status: row.get(5).map_err(storage_error)?,
            raw: row
                .get::<_, Option<String>>(6)
                .map_err(storage_error)?
                .and_then(|text| serde_json::from_str(&text).ok()),
            mapped: row
                .get::<_, Option<String>>(7)
                .map_err(storage_error)?
                .and_then(|text| serde_json::from_str(&text).ok()),
        });
    }
    Ok(events)
}

fn field_text(fields: &Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        field(fields, name).and_then(|value| match value {
            Value::String(text) => Some(text.clone()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
    })
}

fn field<'a>(fields: &'a Value, name: &str) -> Option<&'a Value> {
    match fields {
        Value::Object(map) => map.get(name),
        Value::Array(pairs) => pairs.iter().find_map(|pair| {
            let pair = pair.as_array()?;
            (pair.len() == 2 && pair[0].as_str() == Some(name)).then(|| &pair[1])
        }),
        _ => None,
    }
}

// ------------------------------------------------------------------ rule: auth

fn evaluate_auth(
    events: &[EventFact],
    config: &AuthConfig,
    rule: &'static RuleMetadata,
) -> RuleResult {
    let auth: Vec<&EventFact> = events
        .iter()
        .filter(|event| event.kind == AUTH_FAILURE || event.kind == AUTH_SUCCESS)
        .collect();
    let considered = auth.len() as u64;
    if auth.is_empty() {
        return not_evaluated(rule, "no supported authentication events in this revision");
    }
    let mut excluded = 0_u64;
    type AuthGroup<'a> = (Vec<(i64, &'a EventFact)>, Vec<(i64, &'a EventFact)>);
    let mut groups: BTreeMap<(String, String, String), AuthGroup<'_>> = BTreeMap::new();
    for event in &auth {
        let Some(user) = event.field(&["user", "account", "username"]) else {
            excluded += 1;
            continue;
        };
        let Some(service) = event.field(&["service", "app", "app_name", "tag"]) else {
            excluded += 1;
            continue;
        };
        if !event.resolved() {
            excluded += 1;
            continue;
        }
        let host = event.host.clone().unwrap_or_else(|| "no-host".to_string());
        let entry = groups.entry((host, user, service)).or_default();
        if event.kind == AUTH_FAILURE {
            entry.0.push((event.millis, event));
        } else {
            entry.1.push((event.millis, event));
        }
    }
    if groups.is_empty() {
        return not_evaluated_with(
            rule,
            "authentication events carry no mapped account, service, and resolved time",
            considered,
            excluded,
        );
    }

    let window_ms = config.window_seconds * 1_000;
    let mut drafts = Vec::new();
    let mut truncated = false;
    'groups: for ((host, user, service), (mut failures, mut successes)) in groups {
        failures.sort_by_key(|(millis, _)| *millis);
        successes.sort_by_key(|(millis, _)| *millis);
        for (success_ms, success) in successes {
            let recent: Vec<&(i64, &EventFact)> = failures
                .iter()
                .filter(|(millis, _)| *millis < success_ms && success_ms - *millis <= window_ms)
                .collect();
            if recent.len() < config.failures {
                continue;
            }
            let counted = &recent[recent.len() - config.failures..];
            let first = counted[0].0;
            let mut event_ids: Vec<String> =
                counted.iter().map(|(_, event)| event.id.clone()).collect();
            event_ids.push(success.id.clone());
            let rationale = format!(
                "{} supported authentication failure(s) were followed by a success for \
                     {user} via {service} on {host} within {} s. This can be a mistyped \
                     password, a legitimate retry, or credential guessing; the recorded \
                     events are the basis, not a conclusion.",
                config.failures, config.window_seconds
            );
            drafts.push(Draft {
                rule,
                event_ids,
                predicates: json!({
                    "host": host,
                    "user": user,
                    "service": service,
                    "failures": config.failures,
                    "window_seconds": config.window_seconds,
                    "interval_seconds": (success_ms - first) / 1_000,
                }),
                rationale,
                alternatives: vec![
                    "mistyped or expired password".into(),
                    "legitimate retry by the same person".into(),
                    "automated service-account re-authentication".into(),
                    "password guessing or credential stuffing".into(),
                ],
            });
            if drafts.len() >= MAX_FINDINGS_PER_RULE {
                truncated = true;
                break 'groups;
            }
        }
    }
    evaluated(rule, drafts, considered, excluded, truncated)
}

// -------------------------------------------------------------- rule: download

fn evaluate_download(
    events: &[EventFact],
    config: &DownloadConfig,
    rule: &'static RuleMetadata,
) -> RuleResult {
    let executions: Vec<&EventFact> = events
        .iter()
        .filter(|event| event.kind == PROCESS_EXECUTE)
        .collect();
    if executions.is_empty() {
        return not_evaluated(
            rule,
            "no supported process execution events; the rule needs a recorded executable \
             path or digest",
        );
    }
    let downloads: Vec<&EventFact> = events
        .iter()
        .filter(|event| event.kind == DOWNLOAD)
        .collect();
    if downloads.is_empty() {
        return not_evaluated(rule, "no browser download observations in this revision");
    }
    let execution_ids = |event: &EventFact| {
        (
            event.field(&["path", "executable", "_EXE", "exe"]),
            event.field(&["sha256", "sha256_hex", "hash"]),
        )
    };
    if !executions
        .iter()
        .any(|event| execution_ids(event).0.is_some() || execution_ids(event).1.is_some())
    {
        return not_evaluated(
            rule,
            "process execution events carry no supported path or digest",
        );
    }

    let window_ms = config.window_seconds * 1_000;
    let mut drafts = Vec::new();
    let mut excluded = 0_u64;
    let mut truncated = false;
    for download in &downloads {
        let path = download.field(&["target_path", "current_path", "path"]);
        let digest = download.field(&["sha256", "sha256_hex", "hash"]);
        if !download.resolved() || (path.is_none() && digest.is_none()) {
            excluded += 1;
            continue;
        }
        for execution in &executions {
            if !execution.resolved() {
                excluded += 1;
                continue;
            }
            let (exec_path, exec_digest) = execution_ids(execution);
            let matched_path = path
                .as_ref()
                .zip(exec_path.as_ref())
                .filter(|(left, right)| left == right)
                .map(|(left, _)| left.clone());
            let matched_digest = digest
                .as_ref()
                .zip(exec_digest.as_ref())
                .filter(|(left, right)| left == right)
                .map(|(left, _)| left.clone());
            if matched_path.is_none() && matched_digest.is_none() {
                continue;
            }
            let gap = execution.millis - download.millis;
            if gap < 0 || gap > window_ms {
                continue;
            }
            drafts.push(Draft {
                rule,
                event_ids: vec![download.id.clone(), execution.id.clone()],
                predicates: json!({
                    "path": matched_path,
                    "sha256": matched_digest,
                    "window_seconds": config.window_seconds,
                    "gap_seconds": gap / 1_000,
                }),
                rationale: format!(
                    "A browser download and a process execution referenced the same recorded \
                     path or digest within {} s. This is a candidate causal sequence only: the \
                     file may have existed before the download, and an execution may be \
                     unrelated despite the match.",
                    config.window_seconds
                ),
                alternatives: vec![
                    "the executable already existed and was unrelated to the download".into(),
                    "the same path was reused by another file".into(),
                    "a browser-triggered helper process".into(),
                ],
            });
            if drafts.len() >= MAX_FINDINGS_PER_RULE {
                truncated = true;
                break;
            }
        }
        if truncated {
            break;
        }
    }
    evaluated(
        rule,
        drafts,
        (downloads.len() + executions.len()) as u64,
        excluded,
        truncated,
    )
}

// ----------------------------------------------------------- rule: hash changed

struct CapturedFile {
    object_id: String,
    acquisition_id: String,
    path: String,
    size: Option<i64>,
    mtime_seconds: i64,
    mtime_nanos: i64,
    digest: String,
}

fn evaluate_hash_changed(
    reader: &CaseReader,
    rule: &'static RuleMetadata,
) -> CoreResult<RuleResult> {
    let mut statement = reader
        .connection()
        .prepare(
            "SELECT o.id, o.acquisition_id, o.native_path_encoded, o.byte_length,
                    f.source_mtime_seconds, f.source_mtime_nanos, o.sha256
             FROM file_observations f
             JOIN evidence_objects o ON o.id = f.evidence_id
             WHERE o.kind = 'file_content' AND o.digest_status = 'complete'
               AND o.sha256 IS NOT NULL
               AND f.source_mtime_seconds IS NOT NULL AND f.source_mtime_nanos IS NOT NULL
             ORDER BY o.native_path_encoded, o.acquisition_id
             LIMIT ?1",
        )
        .map_err(|error| CoreError::Storage(format!("prepare hash comparison: {error}")))?;
    let mut rows = statement
        .query(params![(MAX_EVENTS + 1) as i64])
        .map_err(|error| CoreError::Storage(format!("read hash comparison: {error}")))?;
    let mut files: BTreeMap<String, Vec<CapturedFile>> = BTreeMap::new();
    let mut total = 0_u64;
    while let Some(row) = rows
        .next()
        .map_err(|error| CoreError::Storage(format!("read captured file: {error}")))?
    {
        let digest: Vec<u8> = row.get(6).map_err(storage_error)?;
        if digest.len() != 32 {
            continue;
        }
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        let file = CapturedFile {
            object_id: row.get(0).map_err(storage_error)?,
            acquisition_id: row.get(1).map_err(storage_error)?,
            path: row.get(2).map_err(storage_error)?,
            size: row.get(3).map_err(storage_error)?,
            mtime_seconds: row.get(4).map_err(storage_error)?,
            mtime_nanos: row.get(5).map_err(storage_error)?,
            digest: crate::integrity::hash::sha256_hex(&bytes),
        };
        total += 1;
        files.entry(file.path.clone()).or_default().push(file);
    }
    let comparable: usize = files.values().filter(|group| group.len() >= 2).count();
    if comparable == 0 {
        return Ok(not_evaluated(
            rule,
            "fewer than two comparable captures with complete digests and recorded size/mtime",
        ));
    }

    let mut drafts = Vec::new();
    let mut truncated = false;
    'paths: for group in files.values() {
        for left in 0..group.len() {
            for right in (left + 1)..group.len() {
                let a = &group[left];
                let b = &group[right];
                if a.acquisition_id == b.acquisition_id
                    || a.size != b.size
                    || a.size.is_none()
                    || a.mtime_seconds != b.mtime_seconds
                    || a.mtime_nanos != b.mtime_nanos
                    || a.digest == b.digest
                {
                    continue;
                }
                let mut event_ids = Vec::new();
                for object in [&a.object_id, &b.object_id] {
                    let mut statement = reader
                        .connection()
                        .prepare(
                            "SELECT id FROM events
                             WHERE evidence_id = ?1 AND kind = 'file.observed'
                             ORDER BY id LIMIT 4",
                        )
                        .map_err(|error| {
                            CoreError::Storage(format!("prepare capture event: {error}"))
                        })?;
                    let mut rows = statement.query(params![object]).map_err(|error| {
                        CoreError::Storage(format!("read capture event: {error}"))
                    })?;
                    while let Some(row) = rows.next().map_err(|error| {
                        CoreError::Storage(format!("read capture event row: {error}"))
                    })? {
                        event_ids.push(row.get::<_, String>(0).map_err(storage_error)?);
                    }
                }
                event_ids.sort();
                event_ids.dedup();
                drafts.push(Draft {
                    rule,
                    event_ids,
                    predicates: json!({
                        "path": a.path.clone(),
                        "size": a.size,
                        "mtime_seconds": a.mtime_seconds,
                        "mtime_nanos": a.mtime_nanos,
                        "acquisitions": [a.acquisition_id.clone(), b.acquisition_id.clone()],
                        "sha256": [a.digest.clone(), b.digest.clone()],
                    }),
                    rationale: "Two captures recorded the same path and size with an equal \
                                source mtime but different full SHA-256 digests. This can be \
                                normal tooling that preserves timestamps, or deliberate \
                                timestamp retention; the captures are named in the predicates."
                        .into(),
                    alternatives: vec![
                        "a tool rewrote the file while preserving its mtime".into(),
                        "the file legitimately changed between captures".into(),
                        "deliberate timestamp retention".into(),
                    ],
                });
                if drafts.len() >= MAX_FINDINGS_PER_RULE {
                    truncated = true;
                    break 'paths;
                }
            }
        }
    }
    Ok(evaluated(rule, drafts, total, 0, truncated))
}

// --------------------------------------------------------- rule: clock jump

struct ClockSample {
    event_id: String,
    domain: String,
    realtime: Option<i64>,
    monotonic: Option<i64>,
}

fn evaluate_clock(
    reader: &CaseReader,
    revision: &str,
    config: &ClockConfig,
    rule: &'static RuleMetadata,
) -> CoreResult<RuleResult> {
    let mut statement = reader
        .connection()
        .prepare(
            "SELECT t.event_id, t.semantic, t.candidates_json, t.clock_domain
             FROM event_times t
             JOIN events e ON e.id = t.event_id
             WHERE e.parse_run_id = ?1 AND t.status = 'resolved'
             ORDER BY t.event_id, t.semantic",
        )
        .map_err(|error| CoreError::Storage(format!("prepare clock samples: {error}")))?;
    let mut rows = statement
        .query(params![revision])
        .map_err(|error| CoreError::Storage(format!("read clock samples: {error}")))?;
    let mut samples: BTreeMap<String, ClockSample> = BTreeMap::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| CoreError::Storage(format!("read clock sample: {error}")))?
    {
        let event_id: String = row.get(0).map_err(storage_error)?;
        let semantic: String = row.get(1).map_err(storage_error)?;
        let candidates: String = row.get(2).map_err(storage_error)?;
        let domain: String = row.get(3).map_err(storage_error)?;
        let first = serde_json::from_str::<Vec<UnixTime>>(&candidates)
            .ok()
            .and_then(|candidates| candidates.first().copied())
            .map(|instant| i128::from(instant.seconds) * 1_000_000_000 + i128::from(instant.nanos));
        let sample = samples.entry(event_id.clone()).or_insert(ClockSample {
            event_id,
            domain,
            realtime: None,
            monotonic: None,
        });
        match semantic.as_str() {
            "realtime" => sample.realtime = first.map(|value| value as i64),
            "monotonic" => sample.monotonic = first.map(|value| value as i64),
            _ => {}
        }
    }
    let mut booted: BTreeMap<String, Vec<&ClockSample>> = BTreeMap::new();
    for sample in samples.values() {
        if sample.monotonic.is_some()
            && sample.realtime.is_some()
            && sample.domain.starts_with("boot:")
        {
            booted
                .entry(sample.domain.clone())
                .or_default()
                .push(sample);
        }
    }
    let pairs: usize = booted
        .values()
        .map(|group| group.len().saturating_sub(1))
        .sum();
    if pairs == 0 {
        return Ok(not_evaluated(
            rule,
            "fewer than two boot-scoped samples carrying both realtime and monotonic times",
        ));
    }

    let threshold = i128::from(config.threshold_seconds) * 1_000_000_000;
    let mut drafts = Vec::new();
    let mut truncated = false;
    'boots: for (domain, mut group) in booted {
        group.sort_by_key(|sample| sample.monotonic);
        for window in group.windows(2) {
            let (previous, current) = (window[0], window[1]);
            let Some(previous_mono) = previous.monotonic else {
                continue;
            };
            let Some(current_mono) = current.monotonic else {
                continue;
            };
            let Some(previous_real) = previous.realtime else {
                continue;
            };
            let Some(current_real) = current.realtime else {
                continue;
            };
            let real_delta = i128::from(current_real) - i128::from(previous_real);
            let mono_delta = i128::from(current_mono) - i128::from(previous_mono);
            let divergence = real_delta - mono_delta;
            if divergence.abs() <= threshold {
                continue;
            }
            let rationale = format!(
                "Realtime advanced {} ms more or less than monotonic time across two \
                 samples in {domain}. A clock correction, suspend/resume accounting \
                 difference, or a mixed clock source is a possible explanation.",
                divergence / 1_000_000
            );
            drafts.push(Draft {
                rule,
                event_ids: vec![previous.event_id.clone(), current.event_id.clone()],
                predicates: json!({
                    "clock_domain": domain,
                    "realtime_delta_millis": real_delta / 1_000_000,
                    "monotonic_delta_millis": mono_delta / 1_000_000,
                    "divergence_millis": divergence / 1_000_000,
                    "threshold_seconds": config.threshold_seconds,
                }),
                rationale,
                alternatives: vec![
                    "NTP or manual clock correction".into(),
                    "suspend/resume accounting difference".into(),
                    "the two fields came from different clock sources".into(),
                ],
            });
            if drafts.len() >= MAX_FINDINGS_PER_RULE {
                truncated = true;
                break 'boots;
            }
        }
    }
    Ok(evaluated(rule, drafts, pairs as u64, 0, truncated))
}

// ------------------------------------------------------ rule: outside hours

fn evaluate_hours(
    events: &[EventFact],
    config: Option<&HoursConfig>,
    rule: &'static RuleMetadata,
) -> RuleResult {
    let Some(config) = config else {
        return not_evaluated(rule, "disabled: no declared schedule baseline");
    };
    let Ok(zone) = Tz::from_str(&config.timezone) else {
        return not_evaluated(rule, "declared schedule has an unknown timezone");
    };
    let (Ok(start), Ok(end)) = (parse_clock(&config.start), parse_clock(&config.end)) else {
        return not_evaluated(rule, "declared schedule has an invalid time");
    };
    let weekdays: Vec<Weekday> = config
        .weekdays
        .iter()
        .filter_map(|day| Weekday::from_str(day).ok())
        .collect();
    let holidays: BTreeSet<&str> = config.holidays.iter().map(String::as_str).collect();

    let mut drafts = Vec::new();
    let mut excluded = 0_u64;
    let mut truncated = false;
    for event in events {
        if !event.resolved() {
            excluded += 1;
            continue;
        }
        let local = zone
            .timestamp_opt(event.millis.div_euclid(1_000), 0)
            .single();
        let Some(local) = local else {
            excluded += 1;
            continue;
        };
        let clock = NaiveTime::from_hms_opt(local.hour(), local.minute(), local.second())
            .expect("hour/minute/second are always valid");
        let date = format!(
            "{:04}-{:02}-{:02}",
            local.year(),
            local.month(),
            local.day()
        );
        let outside = !weekdays.contains(&local.weekday())
            || clock < start
            || clock >= end
            || holidays.contains(date.as_str());
        if !outside {
            continue;
        }
        let rationale = format!(
            "Recorded activity fell outside the declared schedule ({} {}..{}, {}). \
             This is a policy deviation, not evidence of intent; the schedule itself is \
             an investigator-provided baseline ({}).",
            config.weekdays.join(","),
            config.start,
            config.end,
            config.timezone,
            if holidays.is_empty() {
                "no holidays".to_string()
            } else {
                format!("{} declared holiday(s)", holidays.len())
            }
        );
        drafts.push(Draft {
            rule,
            event_ids: vec![event.id.clone()],
            predicates: json!({
                "local_time": format!("{date} {}", clock.format("%H:%M:%S")),
                "timezone": config.timezone,
                "weekdays": config.weekdays,
                "start": config.start,
                "end": config.end,
            }),
            rationale,
            alternatives: vec![
                "on-call or overtime work".into(),
                "an automated job outside working hours".into(),
                "the declared schedule is stale".into(),
            ],
        });
        if drafts.len() >= MAX_FINDINGS_PER_RULE {
            truncated = true;
            break;
        }
    }
    evaluated(rule, drafts, events.len() as u64, excluded, truncated)
}

// ------------------------------------------------------------------- storage

fn load_findings(reader: &CaseReader, run_id: &str) -> CoreResult<Vec<Finding>> {
    let mut statement = reader
        .connection()
        .prepare(
            "SELECT f.id, f.analysis_run_id, f.rule_id, f.rule_version, f.event_ids_json,
                    f.predicates_json, f.severity, f.rationale, f.alternatives_json,
                    COALESCE(
                        (SELECT a.disposition FROM annotation_revisions a
                         WHERE a.target_id = f.id AND a.disposition IS NOT NULL
                         ORDER BY a.id DESC LIMIT 1),
                        f.disposition
                    )
             FROM findings f
             WHERE f.analysis_run_id = ?1
             ORDER BY f.rule_id, f.id",
        )
        .map_err(|error| CoreError::Storage(format!("prepare findings: {error}")))?;
    let mut rows = statement
        .query(params![run_id])
        .map_err(|error| CoreError::Storage(format!("read findings: {error}")))?;
    let mut findings = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| CoreError::Storage(format!("read finding: {error}")))?
    {
        let severity: String = row.get(6).map_err(storage_error)?;
        let disposition: String = row.get(9).map_err(storage_error)?;
        findings.push(Finding {
            id: row.get(0).map_err(storage_error)?,
            analysis_run_id: row.get(1).map_err(storage_error)?,
            rule_id: row.get(2).map_err(storage_error)?,
            rule_version: row.get(3).map_err(storage_error)?,
            event_ids: serde_json::from_str(&row.get::<_, String>(4).map_err(storage_error)?)
                .unwrap_or_default(),
            predicates: serde_json::from_str(&row.get::<_, String>(5).map_err(storage_error)?)
                .unwrap_or(Value::Null),
            severity: Severity::parse(&severity).ok_or_else(|| {
                CoreError::Storage(format!("unknown severity in findings: {severity}"))
            })?,
            rationale: row.get(7).map_err(storage_error)?,
            alternatives: serde_json::from_str(&row.get::<_, String>(8).map_err(storage_error)?)
                .unwrap_or_default(),
            disposition: Disposition::parse(&disposition).ok_or_else(|| {
                CoreError::Storage(format!("unknown disposition in findings: {disposition}"))
            })?,
        });
    }
    Ok(findings)
}

pub fn findings_for_run(reader: &CaseReader, run_id: &str) -> CoreResult<Vec<Finding>> {
    load_findings(reader, run_id)
}

fn storage_error(error: rusqlite::Error) -> CoreError {
    CoreError::Storage(format!("read rule field: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_rule_sections_and_fields_are_rejected() {
        assert!(RuleConfig::from_toml("[unknown]\nvalue = 1\n").is_err());
        assert!(
            RuleConfig::from_toml("[auth.fail_then_success]\nfailures = 5\nextra = 1\n").is_err()
        );
    }

    #[test]
    fn out_of_range_parameters_are_rejected() {
        assert!(RuleConfig::from_toml("[auth.fail_then_success]\nfailures = 0\n").is_err());
        assert!(RuleConfig::from_toml("[auth.fail_then_success]\nwindow_seconds = 0\n").is_err());
        assert!(
            RuleConfig::from_toml(
                "[activity.outside_declared_hours]\ntimezone = \"Europe/Berlin\"\n\
                 weekdays = [\"Mon\"]\nstart = \"17:00\"\nend = \"09:00\"\n"
            )
            .is_err()
        );
        assert!(
            RuleConfig::from_toml(
                "[activity.outside_declared_hours]\ntimezone = \"Mars/Olympus\"\n\
                 weekdays = [\"Mon\"]\nstart = \"09:00\"\nend = \"17:00\"\n"
            )
            .is_err()
        );
    }

    #[test]
    fn defaults_are_the_documented_thresholds() {
        let config = RuleConfig::default();
        let auth = config.auth();
        assert_eq!(auth.failures, 5);
        assert_eq!(auth.window_seconds, 600);
        assert_eq!(config.download().window_seconds, 900);
        assert_eq!(config.clock().threshold_seconds, 2);
        assert!(
            config.hours().is_none(),
            "the schedule rule starts disabled"
        );
    }

    #[test]
    fn config_digest_changes_with_parameters() {
        let a = RuleConfig::from_toml("[auth.fail_then_success]\nfailures = 5\n").unwrap();
        let b = RuleConfig::from_toml("[auth.fail_then_success]\nfailures = 6\n").unwrap();
        assert_ne!(a.digest(), b.digest());
        assert_eq!(a.digest(), a.clone().digest());
    }
}

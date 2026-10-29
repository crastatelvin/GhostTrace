//! Windows Event Log (EVTX) structured ingestion (plan P8.1).
//!
//! Container and BinXml decoding is done by the `evtx` crate. This adapter is
//! the interpretation layer: it maps a small, tested, versioned set of provider
//! events onto the kinds the built-in rules consume, and keeps every other
//! record as a generic `windows.event_log` event. No meaning is inferred from an
//! Event ID alone, and a provider with no known mapping stays a structured
//! observation with its provider, channel, event id, and record id.
//!
//! Provider message resources are never loaded: the crate returns the record's
//! structured fields, not rendered provider text, so a missing message table
//! cannot change an event's meaning. The decoder does not resolve DTDs or
//! external entities, and this adapter never executes or fetches anything named
//! by a record; payload strings are preserved as text.
//!
//! Mapping table (version 1):
//!
//! | Provider | Event | Kind | Mapped fields |
//! |---|---|---|---|
//! | `Microsoft-Windows-Security-Auditing` | 4625 | `auth.login_failed` | `user`, `domain`, `service` = `logon_type:<n>`, `logon_type`, `ip`, `workstation`, `auth_package` |
//! | `Microsoft-Windows-Security-Auditing` | 4624 | `auth.login_succeeded` | same as 4625 |
//! | `Microsoft-Windows-Sysmon` | 1 | `process.execute` | `path` (`Image`), `sha256` (from `Hashes`), `user`, `parent_path`, `command_line`, `process_id` |
//! | `Microsoft-Windows-Security-Auditing` | 4688 | `process.execute` | `path` (`NewProcessName`), `sha256` (from `Hashes`), `creator_user`, `parent_path`, `command_line`, `process_id` |
//! | anything else | any | `windows.event_log` | `provider`, `channel`, `event_id`, `record_id`, `computer`, `version` |
//!
//! A mapped field is only written when the record actually carries it; a
//! missing account or hash stays missing instead of being guessed.

use std::io::Read;
use std::path::Path;
use std::sync::atomic::Ordering;

use serde_json::{Map, Value, json};

use crate::analysis::rules::{AUTH_FAILURE, AUTH_SUCCESS, PROCESS_EXECUTE};
use crate::domain::event::NamedEventTimeRef;
use crate::domain::time::{
    ClockDomain, Epoch, EventTime, RawTimeValue, TimeAssumption, TimePrecision, TimeSemantic,
    TimeStatus, TimeUnit, UnixTime,
};
use crate::error::{CoreError, CoreResult};

use super::{EventDraft, ImportDiagnostic, ImportRequest, ParsedRecord, RecordSink, truncate_text};

/// Every EVTX chunk is 64 KiB, including the last one in a complete file.
const CHUNK_SIZE: u64 = 65_536;
/// The file header block is 4 KiB in every supported version.
const HEADER_BLOCK: u64 = 4_096;
const SUMMARY_LIMIT: usize = 512;

const SECURITY: &str = "Microsoft-Windows-Security-Auditing";
const SYSMON: &str = "Microsoft-Windows-Sysmon";
const GENERIC_KIND: &str = "windows.event_log";

/// Read one captured EVTX object into the shared committer.
///
/// A file shorter than its own header declares is reported as truncated even
/// when the parser happily returns fewer chunks: an incomplete traversal is
/// never a completed run. Records the decoder cannot read become diagnostics
/// with the most precise locator it exposes (chunk or record id).
pub(super) fn import(
    sink: &mut dyn RecordSink,
    path: &Path,
    request: &ImportRequest<'_>,
    cancelled: &mut bool,
) -> CoreResult<()> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| CoreError::Storage(format!("open captured object: {error}")))?;
    let mut header_bytes = [0_u8; 128];
    file.read_exact(&mut header_bytes).map_err(|error| {
        CoreError::Unsupported(format!(
            "EVTX file is shorter than its 128 byte header ({error}); it is not an empty log"
        ))
    })?;
    let header = evtx::EvtxFileHeader::from_bytes(&header_bytes).map_err(|error| {
        CoreError::Unsupported(format!("EVTX file header is not valid: {error}"))
    })?;
    let actual = file
        .metadata()
        .map_err(|error| CoreError::Storage(format!("stat captured object: {error}")))?
        .len();
    // The header's chunk counter is stale on logs that were not cleanly closed
    // (both fixtures say "1 chunk" while holding 17 and 33), so completeness is
    // judged from the container layout: every chunk is 64 KiB and the chunk area
    // must therefore be a whole number of chunks. A trailing partial chunk is
    // truncation and is reported even though the parser happily returns the
    // chunks it can read.
    let header_block = u64::from(header.header_block_size).max(HEADER_BLOCK);
    if actual < header_block {
        sink.diagnostic(
            "truncated_evidence",
            "evtx-file",
            &format!(
                "file is {actual} bytes, shorter than the {header_block} byte EVTX header block; no record can be read"
            ),
        )?;
        return Ok(());
    }
    let chunk_area = actual - header_block;
    if chunk_area % CHUNK_SIZE != 0 {
        sink.diagnostic(
            "truncated_evidence",
            "evtx-file",
            &format!(
                "file is {actual} bytes; its {chunk_area} byte chunk area is not a whole number of {CHUNK_SIZE} byte chunks, so the trailing chunk is truncated; readable records are imported and the run is partial"
            ),
        )?;
    }

    let mut parser = evtx::EvtxParser::from_path(path).map_err(|error| {
        CoreError::Unsupported(format!(
            "EVTX file could not be opened as a Windows event log: {error}"
        ))
    })?;
    let records = parser.records_json_value();
    let mut ordinal = 0_u64;
    let mut seen = 0_u64;
    for item in records {
        if request.cancelled.load(Ordering::Relaxed) {
            *cancelled = true;
            break;
        }
        if seen >= request.max_records {
            sink.diagnostic(
                "record_limit",
                "evtx-file",
                &format!(
                    "import stopped at the configured limit of {} records",
                    request.max_records
                ),
            )?;
            break;
        }
        match item {
            Ok(record) => {
                ordinal += 1;
                let header_time = record.timestamp.to_string();
                let parsed = parse_record(
                    &record.data,
                    record.event_record_id,
                    ordinal,
                    &header_time,
                    record.recovered,
                    request.max_record_bytes,
                );
                seen += 1;
                sink.record(parsed)?;
                sink.progress(seen)?;
            }
            Err(error) => {
                let (locator, detail) = describe_error(&error);
                sink.diagnostic("evtx_parse_error", &locator, &detail)?;
            }
        }
    }
    Ok(())
}

/// Map one decoded record. Pure, so the mapping table is tested without a
/// binary fixture; the integration test runs the same code over real files.
///
/// `chunk_record_id` is the id from the record header, which is chunk-local on
/// exported logs (the Security fixture renumbers it from 1 while the payload
/// keeps its log-wide `EventRecordID`). The locator therefore uses
/// `System/EventRecordID`; only a record that lacks it falls back to the
/// traversal ordinal, and that weaker locator is disclosed.
pub(crate) fn parse_record(
    data: &Value,
    chunk_record_id: u64,
    ordinal: u64,
    header_timestamp: &str,
    recovered: bool,
    max_record_bytes: usize,
) -> ParsedRecord {
    let system = data
        .get("Event")
        .and_then(|event| event.get("System"))
        .cloned()
        .unwrap_or(Value::Null);
    let system_record = system.get("EventRecordID").and_then(Value::as_u64);
    let (locator, missing_id) = match system_record {
        Some(record_id) => (format!("evtx-record:{record_id}"), false),
        None => (format!("evtx-record-ordinal:{ordinal}"), true),
    };
    let raw_json = match serde_json::to_string(data) {
        Ok(raw) => raw,
        Err(error) => {
            return diagnostic(
                &locator,
                "serialization_failed",
                format!("record could not be serialized: {error}"),
            );
        }
    };
    if raw_json.len() > max_record_bytes {
        return diagnostic(
            &locator,
            "record_too_large",
            format!(
                "record is {} bytes; the configured limit is {max_record_bytes} bytes",
                raw_json.len()
            ),
        );
    }
    let Some(event) = data.get("Event").filter(|value| value.is_object()) else {
        return ParsedRecord {
            locator: locator.clone(),
            locator_kind: "binary_record",
            raw_json: Some(raw_json),
            mapped_json: None,
            event: None,
            diagnostics: vec![ImportDiagnostic {
                code: "schema_mismatch".to_string(),
                locator,
                detail: "decoded record has no Event object".to_string(),
            }],
        };
    };
    let provider = system
        .get("Provider")
        .and_then(|value| value.get("#attributes"))
        .and_then(|value| value.get("Name"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let channel = system.get("Channel").and_then(Value::as_str);
    let computer = system
        .get("Computer")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let event_id = numeric_field(&system, "EventID");
    let version = system.get("Version").and_then(Value::as_u64);
    let payload = event
        .get("EventData")
        .or_else(|| event.get("UserData"))
        .cloned()
        .unwrap_or(Value::Null);

    let mut mapped = Map::new();
    if let Some(provider) = provider {
        mapped.insert("provider".into(), json!(provider));
    }
    if let Some(channel) = channel {
        mapped.insert("channel".into(), json!(channel));
    }
    if let Some(event_id) = event_id {
        mapped.insert("event_id".into(), json!(event_id));
    }
    if let Some(version) = version {
        mapped.insert("version".into(), json!(version));
    }
    if let Some(system_record) = system_record {
        mapped.insert("record_id".into(), json!(system_record));
    }
    mapped.insert("chunk_record_id".into(), json!(chunk_record_id));
    mapped.insert("record_ordinal".into(), json!(ordinal));
    if let Some(computer) = computer {
        mapped.insert("computer".into(), json!(computer));
    }
    mapped.insert("record_header_time".into(), json!(header_timestamp));

    let (kind, summary) = match (provider, event_id) {
        (Some(SECURITY), Some(4625)) => map_auth(&payload, &mut mapped, "failed"),
        (Some(SECURITY), Some(4624)) => map_auth(&payload, &mut mapped, "succeeded"),
        (Some(SYSMON), Some(1)) => map_process(&payload, &mut mapped, true),
        (Some(SECURITY), Some(4688)) => map_process(&payload, &mut mapped, false),
        _ => map_generic(provider, channel, event_id),
    };

    let mut times = vec![NamedEventTimeRef {
        name: "logged".to_string(),
        semantic: TimeSemantic::LoggedTime,
        value: logged_time(&system, header_timestamp),
    }];
    if provider == Some(SYSMON)
        && event_id == Some(1)
        && let Some(value) = occurrence_time(&payload)
    {
        times.push(NamedEventTimeRef {
            name: "occurred".to_string(),
            semantic: TimeSemantic::OccurrenceTime,
            value,
        });
    }

    let mut diagnostics = Vec::new();
    if missing_id {
        diagnostics.push(ImportDiagnostic {
            code: "evtx_missing_record_id".to_string(),
            locator: locator.clone(),
            detail: format!(
                "record has no System/EventRecordID; the traversal ordinal {ordinal} is the locator"
            ),
        });
    }
    if recovered {
        diagnostics.push(ImportDiagnostic {
            code: "evtx_recovered_record".to_string(),
            locator: locator.clone(),
            detail: "record was carved from unallocated chunk space and is marked as recovered"
                .to_string(),
        });
    }

    ParsedRecord {
        locator,
        locator_kind: "binary_record",
        raw_json: Some(raw_json),
        mapped_json: Some(Value::Object(mapped).to_string()),
        event: Some(EventDraft {
            kind: kind.to_string(),
            summary: truncate_text(&summary, SUMMARY_LIMIT),
            host: computer.map(str::to_string),
            times,
        }),
        diagnostics,
    }
}

fn map_auth(
    payload: &Value,
    mapped: &mut Map<String, Value>,
    outcome: &str,
) -> (&'static str, String) {
    let user = payload_text(payload, "TargetUserName").filter(|value| value != "-");
    let domain = payload_text(payload, "TargetDomainName").filter(|value| value != "-");
    let logon_type = payload_text(payload, "LogonType");
    let auth_package =
        payload_text(payload, "AuthenticationPackageName").filter(|value| value != "-");
    let ip = payload_text(payload, "IpAddress").filter(|value| value != "-");
    let workstation = payload_text(payload, "WorkstationName").filter(|value| value != "-");
    let logon_process = payload_text(payload, "LogonProcessName").filter(|value| value != "-");
    if let Some(user) = &user {
        mapped.insert("user".into(), json!(user));
    }
    if let Some(domain) = &domain {
        mapped.insert("domain".into(), json!(domain));
    }
    if let Some(logon_type) = &logon_type {
        mapped.insert("logon_type".into(), json!(logon_type));
        // The rules group failures and successes by `service`; the logon type is
        // the always-present, recorded discriminator for how the logon happened.
        mapped.insert("service".into(), json!(format!("logon_type:{logon_type}")));
    }
    for (name, value) in [
        ("auth_package", &auth_package),
        ("ip", &ip),
        ("workstation", &workstation),
        ("logon_process", &logon_process),
    ] {
        if let Some(value) = value {
            mapped.insert(name.into(), json!(value));
        }
    }
    let account = match (&domain, &user) {
        (Some(domain), Some(user)) => format!("{domain}\\{user}"),
        (None, Some(user)) => user.clone(),
        _ => "an unnamed account".to_string(),
    };
    let summary = match &logon_type {
        Some(logon_type) => {
            format!("authentication {outcome} for {account} via logon type {logon_type}")
        }
        None => format!("authentication {outcome} for {account} (no logon type recorded)"),
    };
    let kind = if outcome == "failed" {
        AUTH_FAILURE
    } else {
        AUTH_SUCCESS
    };
    (kind, summary)
}

fn map_process(
    payload: &Value,
    mapped: &mut Map<String, Value>,
    sysmon: bool,
) -> (&'static str, String) {
    let path = payload_text(payload, if sysmon { "Image" } else { "NewProcessName" });
    let parent = payload_text(
        payload,
        if sysmon {
            "ParentImage"
        } else {
            "ParentProcessName"
        },
    );
    let command_line = payload_text(payload, "CommandLine");
    let process_id = payload_text(payload, if sysmon { "ProcessId" } else { "NewProcessId" });
    let sha256 = payload_text(payload, "Hashes")
        .as_deref()
        .and_then(sha256_from_hashes);
    let user = if sysmon {
        payload_text(payload, "User")
    } else {
        None
    };
    let creator = if sysmon {
        None
    } else {
        payload_text(payload, "SubjectUserName").filter(|value| value != "-")
    };
    for (name, value) in [
        ("path", &path),
        ("sha256", &sha256),
        ("parent_path", &parent),
        ("command_line", &command_line),
        ("process_id", &process_id),
        ("user", &user),
        ("creator_user", &creator),
    ] {
        if let Some(value) = value {
            mapped.insert(name.into(), json!(value));
        }
    }
    let summary = match &path {
        Some(path) => format!("process executed: {}", truncate_text(path, 200)),
        None => "process executed (path not recorded)".to_string(),
    };
    (PROCESS_EXECUTE, summary)
}

fn map_generic(
    provider: Option<&str>,
    channel: Option<&str>,
    event_id: Option<u64>,
) -> (&'static str, String) {
    let provider = provider.unwrap_or("unknown-provider");
    let summary = match (event_id, channel) {
        (Some(id), Some(channel)) => format!("{provider} event {id} on {channel}"),
        (Some(id), None) => format!("{provider} event {id}"),
        (None, Some(channel)) => format!("{provider} record on {channel}"),
        (None, None) => format!("{provider} record"),
    };
    (GENERIC_KIND, summary)
}

/// The record's logging time. `System/TimeCreated` is the logging time by the
/// event schema; the record header timestamp is only used when the payload has
/// no such field, and that substitution is recorded as an assumption.
fn logged_time(system: &Value, header_timestamp: &str) -> EventTime {
    let text = system
        .get("TimeCreated")
        .and_then(|value| value.get("#attributes"))
        .and_then(|value| value.get("SystemTime"))
        .and_then(Value::as_str);
    if let Some(text) = text {
        return match chrono::DateTime::parse_from_rfc3339(text) {
            Ok(instant) => EventTime {
                status: TimeStatus::Resolved,
                candidates: vec![UnixTime::from_datetime_utc(
                    instant.with_timezone(&chrono::Utc),
                )],
                raw: Some(raw_text("System/TimeCreated", text, TimePrecision::Micros)),
                semantic: TimeSemantic::LoggedTime,
                clock_domain: ClockDomain::Host,
                declared_precision: TimePrecision::Micros,
                assumptions: vec![TimeAssumption {
                    description:
                        "EVTX System/TimeCreated is UTC; the source FILETIME has 100 ns ticks"
                            .to_string(),
                    zone: Some("UTC".to_string()),
                    year_assumed: None,
                }],
            },
            Err(_) => {
                let mut time = super::invalid_time(
                    "System/TimeCreated",
                    text,
                    "System/TimeCreated is not an RFC 3339 instant; the header time is preserved in mapped fields but not substituted",
                );
                time.semantic = TimeSemantic::LoggedTime;
                time
            }
        };
    }
    match chrono::DateTime::parse_from_rfc3339(header_timestamp) {
        Ok(instant) => EventTime {
            status: TimeStatus::Resolved,
            candidates: vec![UnixTime::from_datetime_utc(
                instant.with_timezone(&chrono::Utc),
            )],
            raw: Some(raw_text("record-header", header_timestamp, TimePrecision::Micros)),
            semantic: TimeSemantic::LoggedTime,
            clock_domain: ClockDomain::Host,
            declared_precision: TimePrecision::Micros,
            assumptions: vec![TimeAssumption {
                description: "the payload has no System/TimeCreated; the record header timestamp is used as the logging time"
                    .to_string(),
                zone: Some("UTC".to_string()),
                year_assumed: None,
            }],
        },
        Err(_) => super::unresolved_time(
            "record-header",
            Some(header_timestamp),
            "neither the payload nor the record header carries a readable logging time",
        ),
    }
}

/// The payload occurrence time. Only Sysmon 1 declares one (`UtcTime`), and its
/// zone is not in the value: the field contract says UTC, which is recorded as
/// an explicit assumption rather than applied silently.
fn occurrence_time(payload: &Value) -> Option<EventTime> {
    let text = payload_text(payload, "UtcTime")?;
    let parsed = chrono::NaiveDateTime::parse_from_str(&text, "%Y-%m-%d %H:%M:%S%.f");
    match parsed {
        Ok(naive) => Some(EventTime {
            status: TimeStatus::Resolved,
            candidates: vec![UnixTime::from_datetime_utc(
                chrono::DateTime::from_naive_utc_and_offset(naive, chrono::Utc),
            )],
            raw: Some(raw_text("EventData/UtcTime", &text, TimePrecision::Millis)),
            semantic: TimeSemantic::OccurrenceTime,
            clock_domain: ClockDomain::Host,
            declared_precision: TimePrecision::Millis,
            assumptions: vec![TimeAssumption {
                description:
                    "Sysmon UtcTime has no zone marker; read as UTC per the Sysmon field contract"
                        .to_string(),
                zone: Some("UTC".to_string()),
                year_assumed: None,
            }],
        }),
        Err(_) => Some(EventTime {
            status: TimeStatus::Invalid,
            candidates: Vec::new(),
            raw: Some(raw_text("EventData/UtcTime", &text, TimePrecision::Unknown)),
            semantic: TimeSemantic::OccurrenceTime,
            clock_domain: ClockDomain::Host,
            declared_precision: TimePrecision::Unknown,
            assumptions: vec![TimeAssumption {
                description: "Sysmon UtcTime could not be read as a wall-clock time".to_string(),
                zone: None,
                year_assumed: None,
            }],
        }),
    }
}

fn raw_text(field: &str, text: &str, precision: TimePrecision) -> RawTimeValue {
    RawTimeValue {
        field: field.to_string(),
        integer: None,
        text: Some(text.to_string()),
        epoch: Epoch::Unix,
        unit: TimeUnit::Seconds,
        declared_precision: precision,
    }
}

fn diagnostic(locator: &str, code: &str, detail: String) -> ParsedRecord {
    ParsedRecord {
        locator: locator.to_string(),
        locator_kind: "binary_record",
        raw_json: None,
        mapped_json: None,
        event: None,
        diagnostics: vec![ImportDiagnostic {
            code: code.to_string(),
            locator: locator.to_string(),
            detail,
        }],
    }
}

fn describe_error(error: &evtx::err::EvtxError) -> (String, String) {
    match error {
        evtx::err::EvtxError::FailedToParseChunk { chunk_id, source } => (
            format!("chunk:{chunk_id}"),
            format!("chunk {chunk_id} could not be parsed: {source}"),
        ),
        evtx::err::EvtxError::FailedToParseRecord { record_id, source } => (
            format!("evtx-record:{record_id}"),
            format!("record {record_id} could not be parsed: {source}"),
        ),
        other => (
            "evtx-file".to_string(),
            format!("record could not be parsed: {other}"),
        ),
    }
}

/// A named payload field as text. Named `EventData` fields are scalars; the
/// `#text` form appears when the record carries attributes.
fn payload_text(payload: &Value, name: &str) -> Option<String> {
    let value = payload.get(name)?;
    let text = match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Object(map) => match map.get("#text")? {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            _ => return None,
        },
        _ => return None,
    };
    (!text.is_empty()).then_some(text)
}

fn numeric_field(fields: &Value, name: &str) -> Option<u64> {
    match fields.get(name)? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.parse().ok(),
        Value::Object(map) => match map.get("#text")? {
            Value::Number(number) => number.as_u64(),
            Value::String(text) => text.parse().ok(),
            _ => None,
        },
        _ => None,
    }
}

/// Extract `SHA256=` from a Sysmon/4688 `Hashes` list. A malformed or absent
/// digest stays absent instead of being normalized into a guess.
fn sha256_from_hashes(text: &str) -> Option<String> {
    text.split(',').find_map(|part| {
        let (algorithm, value) = part.trim().split_once('=')?;
        (algorithm.eq_ignore_ascii_case("SHA256")
            && value.len() == 64
            && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(event: Value) -> Value {
        json!({ "Event": event })
    }

    fn security(event_id: u64, data: Value) -> Value {
        record(json!({
            "System": {
                "Provider": { "#attributes": { "Name": SECURITY } },
                "EventID": event_id,
                "Version": 0,
                "TimeCreated": { "#attributes": { "SystemTime": "2016-06-29T15:24:34.346000Z" } },
                "EventRecordID": 42,
                "Channel": "Security",
                "Computer": "HOST1"
            },
            "EventData": data
        }))
    }

    fn parse(data: &Value) -> ParsedRecord {
        parse_record(data, 42, 1, "2016-06-29T15:24:34.346000Z", false, 1 << 20)
    }

    fn mapped(parsed: &ParsedRecord) -> Value {
        serde_json::from_str(parsed.mapped_json.as_deref().expect("mapped")).expect("json")
    }

    #[test]
    fn a_security_failure_maps_the_account_and_logon_type() {
        let data = security(
            4625,
            json!({
                "TargetUserName": "alice",
                "TargetDomainName": "CORP",
                "LogonType": 3,
                "AuthenticationPackageName": "NTLM",
                "IpAddress": "10.0.0.5",
                "WorkstationName": "WS1"
            }),
        );
        let parsed = parse(&data);
        let fields = mapped(&parsed);
        let draft = parsed.event.expect("event");
        assert_eq!(draft.kind, AUTH_FAILURE);
        assert_eq!(draft.host.as_deref(), Some("HOST1"));
        assert_eq!(fields["user"], "alice");
        assert_eq!(fields["domain"], "CORP");
        assert_eq!(fields["service"], "logon_type:3");
        assert_eq!(fields["auth_package"], "NTLM");
        assert_eq!(fields["ip"], "10.0.0.5");
        assert_eq!(fields["record_id"], 42);
        assert_eq!(parsed.locator, "evtx-record:42");
        assert_eq!(parsed.locator_kind, "binary_record");
        assert!(parsed.diagnostics.is_empty());
        assert_eq!(draft.times[0].name, "logged");
        assert_eq!(draft.times[0].value.status, TimeStatus::Resolved);
        assert_eq!(draft.times.len(), 1, "4625 has no payload occurrence time");
    }

    #[test]
    fn a_security_success_maps_the_success_kind() {
        let data = security(
            4624,
            json!({ "TargetUserName": "bob", "TargetDomainName": "CORP", "LogonType": 2 }),
        );
        let draft = parse(&data).event.expect("event");
        assert_eq!(draft.kind, AUTH_SUCCESS);
        assert_eq!(
            draft.summary,
            "authentication succeeded for CORP\\bob via logon type 2"
        );
    }

    #[test]
    fn a_missing_account_is_absent_instead_of_invented() {
        let data = security(4625, json!({ "TargetUserName": "-", "LogonType": 3 }));
        let parsed = parse(&data);
        let fields = mapped(&parsed);
        assert!(fields.get("user").is_none());
        assert_eq!(fields["service"], "logon_type:3");
        assert_eq!(parsed.event.expect("event").kind, AUTH_FAILURE);
    }

    #[test]
    fn sysmon_process_creation_maps_path_hash_user_and_occurrence_time() {
        let data = record(json!({
            "System": {
                "Provider": { "#attributes": { "Name": SYSMON } },
                "EventID": 1,
                "Version": 5,
                "TimeCreated": { "#attributes": { "SystemTime": "2017-12-26T13:10:29.136879Z" } },
                "EventRecordID": 1742,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Computer": "DESKTOP-1"
            },
            "EventData": {
                "UtcTime": "2017-12-26 13:10:29.134",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd /c whoami",
                "User": "CORP\\alice",
                "ProcessId": 9112,
                "ParentImage": "C:\\Windows\\explorer.exe",
                "Hashes": "SHA1=00,MD5=11,SHA256=8F16A431C919A0AA7C9466EC1CDC1E721F30EB5C8182835585A1B74ABECB1920"
            }
        }));
        let parsed = parse(&data);
        let fields = mapped(&parsed);
        let draft = parsed.event.expect("event");
        assert_eq!(draft.kind, PROCESS_EXECUTE);
        assert_eq!(fields["path"], "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(
            fields["sha256"],
            "8f16a431c919a0aa7c9466ec1cdc1e721f30eb5c8182835585a1b74abecb1920"
        );
        assert_eq!(fields["user"], "CORP\\alice");
        assert_eq!(fields["parent_path"], "C:\\Windows\\explorer.exe");
        assert_eq!(draft.times.len(), 2);
        let occurred = &draft.times[1];
        assert_eq!(occurred.name, "occurred");
        assert_eq!(occurred.value.semantic, TimeSemantic::OccurrenceTime);
        assert_eq!(occurred.value.status, TimeStatus::Resolved);
        assert_eq!(
            occurred.value.candidates[0].seconds, 1_514_293_829,
            "the payload time is the occurrence instant"
        );
        assert_eq!(
            occurred.value.assumptions[0].zone.as_deref(),
            Some("UTC"),
            "the zone assumption is explicit"
        );
    }

    #[test]
    fn a_security_4688_creation_maps_the_new_process_name() {
        let data = security(
            4688,
            json!({
                "NewProcessName": "C:\\Windows\\notepad.exe",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
                "SubjectUserName": "alice",
                "NewProcessId": "0x1a2b",
                "CommandLine": "notepad.exe"
            }),
        );
        let parsed = parse(&data);
        let fields = mapped(&parsed);
        let draft = parsed.event.expect("event");
        assert_eq!(draft.kind, PROCESS_EXECUTE);
        assert_eq!(fields["path"], "C:\\Windows\\notepad.exe");
        assert_eq!(fields["creator_user"], "alice");
        assert!(
            fields.get("user").is_none(),
            "the creator is not the process user"
        );
    }

    #[test]
    fn a_malformed_hash_stays_absent() {
        assert_eq!(sha256_from_hashes("SHA256=not-a-hash"), None);
        assert_eq!(sha256_from_hashes("SHA1=00"), None);
        assert_eq!(
            sha256_from_hashes(&format!("SHA256={}", "a".repeat(64))),
            Some("a".repeat(64))
        );
    }

    #[test]
    fn an_unknown_provider_is_a_structured_generic_event() {
        let data = record(json!({
            "System": {
                "Provider": { "#attributes": { "Name": "Contoso-Provider" } },
                "EventID": 7,
                "Version": 2,
                "TimeCreated": { "#attributes": { "SystemTime": "2026-10-27T10:00:00Z" } },
                "EventRecordID": 9,
                "Channel": "Contoso/Operational",
                "Computer": "HOST2"
            },
            "EventData": { "Whatever": "value" }
        }));
        let parsed = parse(&data);
        let fields = mapped(&parsed);
        let draft = parsed.event.expect("event");
        assert_eq!(draft.kind, GENERIC_KIND);
        assert_eq!(
            draft.summary,
            "Contoso-Provider event 7 on Contoso/Operational"
        );
        assert_eq!(fields["provider"], "Contoso-Provider");
        assert_eq!(fields["event_id"], 7);
        assert_eq!(fields["version"], 2);
        assert!(fields.get("user").is_none(), "no rule interpretation");
    }

    #[test]
    fn hostile_payload_text_is_preserved_verbatim() {
        let hostile = "<!DOCTYPE foo SYSTEM \"http://example.invalid/x\">&xxe;\u{1b}]0;pwned\u{7}";
        let data = record(json!({
            "System": {
                "Provider": { "#attributes": { "Name": "Contoso-Provider" } },
                "EventID": 1,
                "TimeCreated": { "#attributes": { "SystemTime": "2026-10-27T10:00:00Z" } },
                "EventRecordID": 3,
                "Channel": "Contoso"
            },
            "EventData": { "Payload": hostile }
        }));
        let parsed = parse(&data);
        let raw = parsed.raw_json.expect("raw");
        let value: Value = serde_json::from_str(&raw).expect("raw json");
        assert_eq!(value["Event"]["EventData"]["Payload"], hostile);
        assert!(
            raw.contains("&xxe;"),
            "the entity is preserved as text, never resolved"
        );
        assert!(raw.contains("example.invalid"));
        assert_eq!(parsed.event.expect("event").kind, GENERIC_KIND);
    }

    #[test]
    fn an_invalid_logging_time_is_invalid_not_zero() {
        let data = record(json!({
            "System": {
                "Provider": { "#attributes": { "Name": "Contoso-Provider" } },
                "EventID": 1,
                "TimeCreated": { "#attributes": { "SystemTime": "not-a-time" } },
                "EventRecordID": 5,
                "Channel": "Contoso"
            }
        }));
        let draft = parse(&data).event.expect("event");
        assert_eq!(draft.times[0].value.status, TimeStatus::Invalid);
        assert!(draft.times[0].value.candidates.is_empty());
    }

    #[test]
    fn a_missing_payload_time_falls_back_to_the_header_with_an_assumption() {
        let data = record(json!({
            "System": {
                "Provider": { "#attributes": { "Name": "Contoso-Provider" } },
                "EventID": 1,
                "EventRecordID": 5,
                "Channel": "Contoso"
            }
        }));
        let draft = parse(&data).event.expect("event");
        let time = &draft.times[0].value;
        assert_eq!(time.status, TimeStatus::Resolved);
        assert_eq!(
            time.raw.as_ref().map(|raw| raw.field.as_str()),
            Some("record-header")
        );
        assert!(time.assumptions[0].description.contains("record header"));
    }

    #[test]
    fn an_oversized_record_is_a_diagnostic_without_an_event() {
        let data = security(4625, json!({ "TargetUserName": "alice", "LogonType": 3 }));
        let parsed = parse_record(&data, 42, 1, "2016-06-29T15:24:34.346000Z", false, 32);
        assert!(parsed.event.is_none());
        assert!(parsed.raw_json.is_none());
        assert_eq!(parsed.diagnostics[0].code, "record_too_large");
    }

    #[test]
    fn the_payload_record_id_is_the_locator() {
        // The record header id is chunk-local on exported logs; the payload's
        // EventRecordID is the log-wide identifier the locator uses.
        let data = security(4625, json!({ "TargetUserName": "alice", "LogonType": 3 }));
        let parsed = parse_record(&data, 1, 7, "2016-06-29T15:24:34.346000Z", false, 1 << 20);
        assert_eq!(parsed.locator, "evtx-record:42");
        let fields = mapped(&parsed);
        assert_eq!(fields["record_id"], 42);
        assert_eq!(fields["chunk_record_id"], 1);
        assert_eq!(fields["record_ordinal"], 7);
        assert!(parsed.diagnostics.is_empty());
    }

    #[test]
    fn a_record_without_an_event_record_id_uses_the_disclosed_ordinal() {
        let data = record(json!({
            "System": {
                "Provider": { "#attributes": { "Name": "Contoso-Provider" } },
                "EventID": 1,
                "TimeCreated": { "#attributes": { "SystemTime": "2026-10-27T10:00:00Z" } },
                "Channel": "Contoso"
            }
        }));
        let parsed = parse_record(&data, 3, 9, "2026-10-27T10:00:00Z", false, 1 << 20);
        assert_eq!(parsed.locator, "evtx-record-ordinal:9");
        assert_eq!(parsed.diagnostics[0].code, "evtx_missing_record_id");
    }

    #[test]
    fn a_carved_record_is_disclosed() {
        let data = security(4625, json!({ "TargetUserName": "alice", "LogonType": 3 }));
        let parsed = parse_record(&data, 42, 1, "2016-06-29T15:24:34.346000Z", true, 1 << 20);
        assert_eq!(parsed.diagnostics[0].code, "evtx_recovered_record");
    }
}

//! Log and record ingestion (plan Section 7, P4.1).
//!
//! Adapters never invent an event type or a timestamp. Every adapter:
//!
//! - detects the format from a bounded prefix and records whether the choice
//!   was automatic or declared by the operator (`parse_runs.parser_id` plus the
//!   format in the run's config digest);
//! - stores the raw fields of each parsed record with its exact byte locator;
//! - reports malformed, oversized, or non-UTF-8 records as structured
//!   diagnostics instead of skipping silently;
//! - turns a record into a normalized event only through a rule that was
//!   actually tested. Anything else stays a raw observation with no invented
//!   type or time.

pub mod jsonl;
pub mod syslog;

use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use serde_json::Value;

use crate::domain::event::{Event, NamedEventTimeRef};
use crate::domain::time::{Epoch, EventTime, RawTimeValue, TimeSemantic, TimeStatus, TimeUnit};
use crate::error::{CoreError, CoreResult};
use crate::integrity::hash::{digest_file, sha256_hex};
use crate::storage::read::CaseReader;
use crate::storage::writer::{CaseWriter, ObservationRecord, ParseRunRecord};

/// Adapter contract version. Bump when the mapping changes; the run identity
/// includes it, so old runs stay reproducible.
pub const ADAPTER_VERSION: &str = "1";
/// Default per-record bound (bytes). Keeps one hostile line from exhausting
/// memory; larger records are reported, not parsed.
pub const DEFAULT_MAX_RECORD_BYTES: usize = 1 << 20;
pub const MAX_RECORD_BYTES_LIMIT: usize = 16 << 20;
/// Default record-count bound for one import.
pub const DEFAULT_MAX_RECORDS: u64 = 1_000_000;
/// Diagnostics kept on the run row. The full count is always recorded.
pub const MAX_DIAGNOSTICS: usize = 100;
/// Records per committed batch.
const BATCH_RECORDS: usize = 500;
/// The active revision label shared by all import adapters.
pub const ACTIVE_REVISION: &str = "r1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Jsonl,
    Syslog5424,
    Syslog3164,
}

impl LogFormat {
    pub const ALL: [LogFormat; 3] = [
        LogFormat::Jsonl,
        LogFormat::Syslog5424,
        LogFormat::Syslog3164,
    ];

    pub fn id(self) -> &'static str {
        match self {
            LogFormat::Jsonl => "jsonl",
            LogFormat::Syslog5424 => "syslog-5424",
            LogFormat::Syslog3164 => "syslog-3164",
        }
    }

    pub fn parser_id(self) -> &'static str {
        match self {
            LogFormat::Jsonl => "jsonl.fields",
            LogFormat::Syslog5424 => "syslog.rfc5424",
            LogFormat::Syslog3164 => "syslog.rfc3164",
        }
    }

    pub fn from_id(text: &str) -> Option<Self> {
        match text {
            "jsonl" => Some(LogFormat::Jsonl),
            "syslog-5424" => Some(LogFormat::Syslog5424),
            "syslog-3164" => Some(LogFormat::Syslog3164),
            _ => None,
        }
    }

    /// Signature detection over a bounded prefix. Ambiguous input returns
    /// `None` and requires an explicit format.
    pub fn detect(prefix: &[u8]) -> Option<Self> {
        let start = prefix.iter().position(|byte| !byte.is_ascii_whitespace())?;
        let rest = &prefix[start..];
        if matches!(rest.first(), Some(b'{') | Some(b'[')) {
            return Some(LogFormat::Jsonl);
        }
        if rest.first() != Some(&b'<') {
            return None;
        }
        let end = rest.iter().position(|byte| *byte == b'>')?;
        let pri = std::str::from_utf8(&rest[1..end]).ok()?;
        if pri.is_empty() || !pri.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let mut after = &rest[end + 1..];
        while after.first() == Some(&b' ') {
            after = &after[1..];
        }
        if after.starts_with(b"1 ") {
            Some(LogFormat::Syslog5424)
        } else {
            Some(LogFormat::Syslog3164)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TimeFormat {
    Rfc3339,
    UnixSeconds,
    UnixMillis,
    UnixMicros,
    UnixNanos,
}

impl TimeFormat {
    pub const ALL: [TimeFormat; 5] = [
        TimeFormat::Rfc3339,
        TimeFormat::UnixSeconds,
        TimeFormat::UnixMillis,
        TimeFormat::UnixMicros,
        TimeFormat::UnixNanos,
    ];

    pub fn id(self) -> &'static str {
        match self {
            TimeFormat::Rfc3339 => "rfc3339",
            TimeFormat::UnixSeconds => "unix-seconds",
            TimeFormat::UnixMillis => "unix-millis",
            TimeFormat::UnixMicros => "unix-micros",
            TimeFormat::UnixNanos => "unix-nanos",
        }
    }

    pub fn from_id(text: &str) -> Option<Self> {
        match text {
            "rfc3339" => Some(TimeFormat::Rfc3339),
            "unix-seconds" => Some(TimeFormat::UnixSeconds),
            "unix-millis" => Some(TimeFormat::UnixMillis),
            "unix-micros" => Some(TimeFormat::UnixMicros),
            "unix-nanos" => Some(TimeFormat::UnixNanos),
            _ => None,
        }
    }

    fn unit(self) -> TimeUnit {
        match self {
            TimeFormat::Rfc3339 | TimeFormat::UnixSeconds => TimeUnit::Seconds,
            TimeFormat::UnixMillis => TimeUnit::Millis,
            TimeFormat::UnixMicros => TimeUnit::Micros,
            TimeFormat::UnixNanos => TimeUnit::Nanos,
        }
    }
}

/// Bounded JSONL field mapping. No expressions, paths, or regular expressions:
/// the operator may only name fields and pick a fixed time format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonlConfig {
    pub time_field: String,
    pub time_format: TimeFormat,
    pub message_field: Option<String>,
    pub host_field: Option<String>,
    pub kind_field: Option<String>,
    pub default_kind: String,
}

impl Default for JsonlConfig {
    fn default() -> Self {
        Self {
            time_field: "ts".to_string(),
            time_format: TimeFormat::Rfc3339,
            message_field: None,
            host_field: None,
            kind_field: None,
            default_kind: "log.record".to_string(),
        }
    }
}

/// Syslog has no year (RFC 3164) and no zone (both legacy and some 5424
/// senders). Neither is defaulted; absent values leave the time unresolved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyslogConfig {
    /// IANA zone name applied to RFC 3164 wall-clock headers.
    pub timezone: Option<String>,
    /// Year applied to RFC 3164 headers. Never inferred from file mtime.
    pub year: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct ImportRequest<'a> {
    /// Captured relative path (or `--object` identity) of the evidence object.
    pub path: Option<String>,
    pub evidence_id: Option<String>,
    pub acquisition_id: Option<String>,
    /// Declared format; `None` means detect from the signature.
    pub format: Option<LogFormat>,
    pub jsonl: JsonlConfig,
    pub syslog: SyslogConfig,
    pub max_record_bytes: usize,
    pub max_records: u64,
    pub cancelled: &'a AtomicBool,
}

impl<'a> ImportRequest<'a> {
    pub fn new(cancelled: &'a AtomicBool) -> Self {
        Self {
            path: None,
            evidence_id: None,
            acquisition_id: None,
            format: None,
            jsonl: JsonlConfig::default(),
            syslog: SyslogConfig::default(),
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            max_records: DEFAULT_MAX_RECORDS,
            cancelled,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportDiagnostic {
    /// Stable machine code; never carries record content.
    pub code: String,
    /// Exact record location: `offset:O:len:L` and/or `line:N`.
    pub locator: String,
    /// Operational detail only (sizes, line numbers, expected types).
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportOutcome {
    pub run_id: String,
    pub acquisition_id: String,
    pub evidence_id: String,
    pub path: String,
    pub parser_id: String,
    pub parser_version: String,
    pub detected_format: Option<String>,
    pub declared_format: Option<String>,
    pub state: String,
    pub records: u64,
    pub observations: u64,
    pub events: u64,
    pub diagnostics: Vec<ImportDiagnostic>,
    pub diagnostics_total: u64,
    pub diagnostics_truncated: bool,
}

/// A captured object resolved by path or identity, with its store location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRef {
    pub id: String,
    pub acquisition_id: String,
    pub native_path: String,
    pub store_subpath: String,
    pub byte_length: u64,
    pub sha256: [u8; 32],
}

pub fn resolve_evidence(
    reader: &CaseReader,
    acquisition_id: Option<&str>,
    path: Option<&str>,
    evidence_id: Option<&str>,
) -> CoreResult<EvidenceRef> {
    let connection = reader.connection();
    let acquisition = match acquisition_id {
        Some(id) => id.to_string(),
        None => connection
            .query_row(
                "SELECT id FROM acquisitions ORDER BY started_seconds DESC, id DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| {
                CoreError::InvalidInput(format!("no acquisition in this case: {error}"))
            })?,
    };
    let mut statement = connection
        .prepare(
            "SELECT id, acquisition_id, native_path_encoded, object_location,
                    byte_length, sha256
             FROM evidence_objects
             WHERE acquisition_id = ?1
               AND kind = 'file_content'
               AND object_location IS NOT NULL
               AND digest_status = 'complete'
               AND (?2 IS NOT NULL AND id = ?2
                    OR ?2 IS NULL AND (native_path_encoded = ?3 OR native_path_encoded = ?4))
             ORDER BY native_path_encoded",
        )
        .map_err(|error| CoreError::Storage(format!("evidence lookup: {error}")))?;
    let encoded = path.map(encode_path_text).unwrap_or_default();
    let path_text = path.unwrap_or_default();
    let rows = statement
        .query_map(
            rusqlite::params![acquisition, evidence_id, encoded, path_text],
            |row| {
                let sha256: Option<Vec<u8>> = row.get(5)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    sha256,
                ))
            },
        )
        .map_err(|error| CoreError::Storage(format!("evidence lookup: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| CoreError::Storage(format!("evidence lookup: {error}")))?;
    if rows.is_empty() {
        return Err(CoreError::InvalidInput(match (path, evidence_id) {
            (_, Some(id)) => format!("no captured object with id {id}"),
            (Some(path), None) => format!("no captured object at path {path}"),
            (None, None) => "pass --path or --object".to_string(),
        }));
    }
    if rows.len() > 1 {
        return Err(CoreError::InvalidInput(
            "multiple captured objects match; pass --object".to_string(),
        ));
    }
    let (id, acquisition_id, native_path, store_subpath, byte_length, sha256) = rows[0].clone();
    let sha256: [u8; 32] = sha256
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(CoreError::CorruptEvidence)?;
    Ok(EvidenceRef {
        id,
        acquisition_id,
        native_path,
        store_subpath,
        byte_length: byte_length.max(0) as u64,
        sha256,
    })
}

/// Import one captured object. Returns the recorded run state; a cancellation
/// is a recorded `cancelled` run, never a silent success.
pub fn run_import(
    reader: &CaseReader,
    writer: &CaseWriter,
    case_root: &Path,
    request: &ImportRequest<'_>,
) -> CoreResult<ImportOutcome> {
    let evidence = resolve_evidence(
        reader,
        request.acquisition_id.as_deref(),
        request.path.as_deref(),
        request.evidence_id.as_deref(),
    )?;
    let store_path = case_root.join(&evidence.store_subpath);
    let actual = digest_file(&store_path)?;
    if actual.sha256 != evidence.sha256 {
        return Err(CoreError::IntegrityMismatch);
    }

    let detected = detect_format(&store_path)?;
    let format = request.format.or(detected).ok_or_else(|| {
        CoreError::Unsupported(format!(
            "{} does not match a supported signature; pass --format",
            evidence.native_path
        ))
    })?;
    if matches!(format, LogFormat::Syslog5424 | LogFormat::Syslog3164) {
        syslog::validate(&request.syslog)?;
    }
    let config_digest = config_digest(format, request)?;
    let identity = format!(
        "{}|{}|{}|{}",
        evidence.id,
        format.parser_id(),
        ADAPTER_VERSION,
        config_digest
    );
    let run_id = format!(
        "pr-{}",
        &sha256_hex(&sha256_bytes(identity.as_bytes()))[..16]
    );

    let mut counts = Counts::default();
    let mut diagnostics = Diagnostics::default();
    let mut run = ParseRunRecord {
        id: run_id.clone(),
        acquisition_id: evidence.acquisition_id.clone(),
        parser_id: format.parser_id().to_string(),
        parser_version: ADAPTER_VERSION.to_string(),
        config_digest,
        state: "running".to_string(),
        counts_json: counts.to_json(),
        diagnostics_json: "[]".to_string(),
    };
    writer.queue_parse_run(&run)?;

    let file = std::fs::File::open(&store_path)
        .map_err(|error| CoreError::Storage(format!("open captured object: {error}")))?;
    let mut records = BufReader::new(file);
    let mut syslog = syslog::Adapter::new(&request.syslog)?;
    let mut pending_observations: Vec<ObservationRecord> = Vec::new();
    let mut pending_events: Vec<Event> = Vec::new();
    let mut cancelled = false;
    let mut offset = 0_u64;
    let mut line_number = 0_u64;

    loop {
        if request.cancelled.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }
        if counts.records >= request.max_records {
            diagnostics.push(
                "record_limit",
                &format!("offset:{offset}"),
                &format!(
                    "import stopped at the configured limit of {} records",
                    request.max_records
                ),
            );
            break;
        }
        let Some(line) = read_record(&mut records, &mut offset, request.max_record_bytes)? else {
            break;
        };
        line_number += 1;
        counts.records += 1;
        let locator = format!(
            "line:{line_number}:offset:{}:len:{}",
            line.offset, line.length
        );
        if line.truncated {
            diagnostics.push(
                "record_too_large",
                &locator,
                &format!(
                    "record exceeds the configured {} byte limit; not parsed",
                    request.max_record_bytes
                ),
            );
            continue;
        }
        let text = match std::str::from_utf8(&line.bytes) {
            Ok(text) => text,
            Err(error) => {
                diagnostics.push(
                    "invalid_encoding",
                    &locator,
                    &format!(
                        "record is not UTF-8 (valid prefix {} bytes)",
                        error.valid_up_to()
                    ),
                );
                continue;
            }
        };
        let parsed = match format {
            LogFormat::Jsonl => jsonl::parse_line(text, &request.jsonl),
            LogFormat::Syslog5424 => syslog.parse_line(text, true),
            LogFormat::Syslog3164 => syslog.parse_line(text, false),
        };
        if let Some(fields) = parsed.raw_fields {
            counts.observations += 1;
            pending_observations.push(ObservationRecord {
                id: format!(
                    "ro-{}",
                    &sha256_hex(&sha256_bytes(format!("{run_id}|{locator}").as_bytes()))[..16]
                ),
                parse_run_id: run_id.clone(),
                acquisition_id: evidence.acquisition_id.clone(),
                evidence_id: evidence.id.clone(),
                locator_kind: "byte_range",
                locator_identity: locator.clone(),
                raw_fields_json: Value::Object(fields).to_string(),
            });
        }
        for diagnostic in parsed.diagnostics {
            diagnostics.push(&diagnostic.code, &locator, &diagnostic.detail);
        }
        if let Some(draft) = parsed.event {
            counts.events += 1;
            pending_events.push(Event {
                id: format!(
                    "ev-{}",
                    &sha256_hex(&sha256_bytes(
                        format!("{run_id}|{locator}|{}", draft.kind).as_bytes()
                    ))[..16]
                ),
                kind: draft.kind,
                summary: draft.summary,
                observations: Vec::new(),
                times: vec![NamedEventTimeRef {
                    name: "logged".to_string(),
                    semantic: TimeSemantic::LoggedTime,
                    value: draft.time,
                }],
                host_claim: draft.host,
                revision: run_id.clone(),
            });
        }
        if pending_observations.len() + pending_events.len() >= BATCH_RECORDS {
            run.counts_json = counts.to_json();
            run.diagnostics_json = diagnostics.to_json();
            writer.queue_import_batch(
                &run,
                &pending_observations,
                &pending_events,
                ACTIVE_REVISION,
            )?;
            pending_observations.clear();
            pending_events.clear();
        }
    }

    let (entries, total, truncated) = diagnostics.finish();
    run.state = if cancelled {
        "cancelled".to_string()
    } else if total > 0 {
        "partial".to_string()
    } else {
        "completed".to_string()
    };
    run.counts_json = counts.to_json();
    run.diagnostics_json = serde_json::to_string(&entries)
        .map_err(|error| CoreError::Storage(format!("diagnostics json: {error}")))?;
    writer.queue_import_batch(
        &run,
        &pending_observations,
        &pending_events,
        ACTIVE_REVISION,
    )?;

    Ok(ImportOutcome {
        run_id,
        acquisition_id: evidence.acquisition_id,
        evidence_id: evidence.id,
        path: evidence.native_path,
        parser_id: format.parser_id().to_string(),
        parser_version: ADAPTER_VERSION.to_string(),
        detected_format: detected.map(|format| format.id().to_string()),
        declared_format: request.format.map(|format| format.id().to_string()),
        state: run.state,
        records: counts.records,
        observations: counts.observations,
        events: counts.events,
        diagnostics: entries,
        diagnostics_total: total,
        diagnostics_truncated: truncated,
    })
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub(crate) struct Counts {
    pub records: u64,
    pub observations: u64,
    pub events: u64,
}

impl Counts {
    fn to_json(self) -> String {
        serde_json::to_string(&self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[derive(Debug, Default)]
pub(crate) struct Diagnostics {
    entries: Vec<ImportDiagnostic>,
    total: u64,
}

impl Diagnostics {
    pub(crate) fn push(&mut self, code: &str, locator: &str, detail: &str) {
        self.total += 1;
        if self.entries.len() < MAX_DIAGNOSTICS {
            self.entries.push(ImportDiagnostic {
                code: code.to_string(),
                locator: locator.to_string(),
                detail: detail.to_string(),
            });
        }
    }

    fn to_json(&self) -> String {
        serde_json::to_string(&self.entries).unwrap_or_else(|_| "[]".to_string())
    }

    fn finish(mut self) -> (Vec<ImportDiagnostic>, u64, bool) {
        let truncated = self.total > self.entries.len() as u64;
        if truncated {
            let total = self.total;
            self.entries.push(ImportDiagnostic {
                code: "diagnostics_truncated".to_string(),
                locator: String::new(),
                detail: format!(
                    "{total} diagnostics recorded; only the first {MAX_DIAGNOSTICS} are stored"
                ),
            });
        }
        (self.entries, self.total, truncated)
    }
}

/// What one parsed record produced. `raw_fields` is `None` only when the
/// record could not be parsed at all.
pub(crate) struct ParsedRecord {
    pub raw_fields: Option<serde_json::Map<String, Value>>,
    pub event: Option<EventDraft>,
    pub diagnostics: Vec<ImportDiagnostic>,
}

pub(crate) struct EventDraft {
    pub kind: String,
    pub summary: String,
    pub host: Option<String>,
    pub time: EventTime,
}

impl ParsedRecord {
    pub(crate) fn with_diagnostic(code: &str, detail: impl Into<String>) -> Self {
        Self {
            raw_fields: None,
            event: None,
            diagnostics: vec![ImportDiagnostic {
                code: code.to_string(),
                locator: String::new(),
                detail: detail.into(),
            }],
        }
    }

    pub(crate) fn diagnostic(&mut self, code: &str, detail: impl Into<String>) {
        self.diagnostics.push(ImportDiagnostic {
            code: code.to_string(),
            locator: String::new(),
            detail: detail.into(),
        });
    }
}

struct Line {
    bytes: Vec<u8>,
    truncated: bool,
    offset: u64,
    length: u64,
}

/// Read one bounded record. Oversized records are consumed to the next
/// newline and reported, never buffered whole.
fn read_record<R: BufRead>(
    reader: &mut R,
    offset: &mut u64,
    limit: usize,
) -> CoreResult<Option<Line>> {
    let start = *offset;
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut consumed_total = 0_u64;
    loop {
        let mut consumed = 0;
        let mut done = false;
        {
            let available = reader
                .fill_buf()
                .map_err(|error| CoreError::Storage(format!("read captured object: {error}")))?;
            if available.is_empty() {
                if bytes.is_empty() && !truncated && consumed_total == 0 {
                    return Ok(None);
                }
                done = true;
            } else if let Some(position) = available.iter().position(|byte| *byte == b'\n') {
                let chunk = &available[..position];
                if bytes.len() + chunk.len() > limit {
                    truncated = true;
                } else {
                    bytes.extend_from_slice(chunk);
                }
                consumed = position + 1;
                done = true;
            } else if bytes.len() + available.len() > limit {
                truncated = true;
                consumed = available.len();
            } else {
                consumed = available.len();
                bytes.extend_from_slice(available);
            }
        }
        consumed_total += consumed as u64;
        reader.consume(consumed);
        if done {
            break;
        }
    }
    *offset += consumed_total;
    Ok(Some(Line {
        bytes,
        truncated,
        offset: start,
        length: consumed_total,
    }))
}

fn detect_format(path: &Path) -> CoreResult<Option<LogFormat>> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| CoreError::Storage(format!("open captured object: {error}")))?;
    let mut prefix = vec![0_u8; 8192];
    let read = file
        .read(&mut prefix)
        .map_err(|error| CoreError::Storage(format!("read captured object: {error}")))?;
    prefix.truncate(read);
    Ok(LogFormat::detect(&prefix))
}

fn config_digest(format: LogFormat, request: &ImportRequest<'_>) -> CoreResult<String> {
    let mut config = serde_json::Map::new();
    config.insert("format".into(), Value::String(format.id().into()));
    config.insert(
        "adapter_version".into(),
        Value::String(ADAPTER_VERSION.into()),
    );
    config.insert(
        "max_record_bytes".into(),
        Value::from(request.max_record_bytes),
    );
    config.insert("max_records".into(), Value::from(request.max_records));
    if format == LogFormat::Jsonl {
        let mut jsonl = serde_json::Map::new();
        jsonl.insert(
            "time_field".into(),
            Value::String(request.jsonl.time_field.clone()),
        );
        jsonl.insert(
            "time_format".into(),
            Value::String(request.jsonl.time_format.id().into()),
        );
        jsonl.insert(
            "message_field".into(),
            request
                .jsonl
                .message_field
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        jsonl.insert(
            "host_field".into(),
            request
                .jsonl
                .host_field
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        jsonl.insert(
            "kind_field".into(),
            request
                .jsonl
                .kind_field
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        jsonl.insert(
            "default_kind".into(),
            Value::String(request.jsonl.default_kind.clone()),
        );
        config.insert("jsonl".into(), Value::Object(jsonl));
    } else {
        let mut syslog = serde_json::Map::new();
        syslog.insert(
            "timezone".into(),
            request
                .syslog
                .timezone
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        syslog.insert(
            "year".into(),
            request.syslog.year.map(Value::from).unwrap_or(Value::Null),
        );
        config.insert("syslog".into(), Value::Object(syslog));
    }
    let text = serde_json::to_string(&Value::Object(config))
        .map_err(|error| CoreError::Storage(format!("config digest: {error}")))?;
    Ok(sha256_hex(&sha256_bytes(text.as_bytes())))
}

/// Encode operator-supplied path text the same way captured paths are stored.
fn encode_path_text(text: &str) -> String {
    #[cfg(unix)]
    {
        crate::domain::path::NativePath::unix(text.as_bytes()).encoded()
    }
    #[cfg(not(unix))]
    {
        crate::domain::path::NativePath::windows(text.encode_utf16().collect::<Vec<_>>()).encoded()
    }
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

/// Render an RFC 3339 instant as an exactly resolved, zone-declared time.
pub(crate) fn resolved_text_time(
    field: &str,
    text: &str,
    instant: chrono::DateTime<chrono::FixedOffset>,
    assumption: &str,
) -> EventTime {
    EventTime {
        status: TimeStatus::Resolved,
        candidates: vec![crate::domain::time::UnixTime::from_datetime_utc(
            instant.with_timezone(&chrono::Utc),
        )],
        raw: Some(RawTimeValue {
            field: field.to_string(),
            integer: None,
            text: Some(text.to_string()),
            epoch: Epoch::Unix,
            unit: TimeUnit::Seconds,
            declared_precision: crate::domain::time::TimePrecision::Seconds,
        }),
        semantic: TimeSemantic::LoggedTime,
        clock_domain: crate::domain::time::ClockDomain::Host,
        declared_precision: crate::domain::time::TimePrecision::Seconds,
        assumptions: vec![crate::domain::time::TimeAssumption {
            description: assumption.to_string(),
            zone: instant.offset().to_string().into(),
            year_assumed: None,
        }],
    }
}

/// Build a resolved numeric time from an already validated integer.
pub(crate) fn numeric_time(field: &str, value: i128, format: TimeFormat) -> EventTime {
    let raw = RawTimeValue::integer_raw(field, value, Epoch::Unix, format.unit());
    let mut time = EventTime::from_raw(
        raw,
        TimeSemantic::LoggedTime,
        crate::domain::time::ClockDomain::Host,
    );
    time.assumptions.push(crate::domain::time::TimeAssumption {
        description: format!("numeric timestamp read as {}", format.id()),
        zone: None,
        year_assumed: None,
    });
    time
}

/// Build an invalid time: the value exists but cannot be interpreted.
pub(crate) fn invalid_time(field: &str, text: &str, reason: &str) -> EventTime {
    EventTime {
        status: TimeStatus::Invalid,
        candidates: Vec::new(),
        raw: Some(RawTimeValue {
            field: field.to_string(),
            integer: None,
            text: Some(text.to_string()),
            epoch: Epoch::Unix,
            unit: TimeUnit::Seconds,
            declared_precision: crate::domain::time::TimePrecision::Unknown,
        }),
        semantic: TimeSemantic::LoggedTime,
        clock_domain: crate::domain::time::ClockDomain::Host,
        declared_precision: crate::domain::time::TimePrecision::Unknown,
        assumptions: vec![crate::domain::time::TimeAssumption {
            description: reason.to_string(),
            zone: None,
            year_assumed: None,
        }],
    }
}

/// Build an unresolved time that preserves why it is unresolved.
pub(crate) fn unresolved_time(field: &str, text: Option<&str>, reason: &str) -> EventTime {
    EventTime {
        status: TimeStatus::Unresolved,
        candidates: Vec::new(),
        raw: Some(RawTimeValue {
            field: field.to_string(),
            integer: None,
            text: text.map(str::to_string),
            epoch: Epoch::Unix,
            unit: TimeUnit::Seconds,
            declared_precision: crate::domain::time::TimePrecision::Unknown,
        }),
        semantic: TimeSemantic::LoggedTime,
        clock_domain: crate::domain::time::ClockDomain::Host,
        declared_precision: crate::domain::time::TimePrecision::Unknown,
        assumptions: vec![crate::domain::time::TimeAssumption {
            description: reason.to_string(),
            zone: None,
            year_assumed: None,
        }],
    }
}

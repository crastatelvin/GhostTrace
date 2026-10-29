//! Versioned, length-prefixed worker protocol (plan P8.2).
//!
//! One frame is a 4-byte big-endian length followed by that many bytes of JSON.
//! Control frames and batch frames have separate bounds; a frame over its bound
//! is a protocol violation, never a larger allocation. Both sides validate the
//! messages they receive: the parent treats the worker as untrusted output (a
//! compromised parser can emit anything), and the worker treats the path it is
//! given as untrusted input.
//!
//! The wire shape is deliberately not the storage shape. Records carry only the
//! fields an adapter produces; the parent rebuilds `ParsedRecord` after
//! validating locators, kinds, JSON bodies, and time structures, and only then
//! hands them to the case writer.

use std::io::{Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::event::NamedEventTimeRef;
use crate::domain::time::{
    ClockDomain, Epoch, EventTime, RawTimeValue, TimeAssumption, TimePrecision, TimeSemantic,
    TimeStatus, UnixTime,
};
use crate::error::{CoreError, CoreResult};
use crate::ingest::{
    EventDraft, ImportDiagnostic, ImportRequest, LogFormat, ParsedRecord, RecordSink,
    produce_records,
};

/// Bumped when the frame/message contract changes incompatibly.
pub const PROTOCOL_VERSION: u32 = 1;
/// The parent's build version, echoed by the worker and compared exactly.
pub const BUILD_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const MAX_CONTROL_FRAME: usize = 64 * 1024;
pub const MAX_BATCH_FRAME: usize = 32 * 1024 * 1024;
pub const MAX_BATCH_RECORDS: usize = 500;
/// Flush a batch once its payload reaches this size, so one large record does
/// not force the next 499 records to wait.
const BATCH_BYTES: usize = 1 << 20;
const MAX_LOCATOR: usize = 512;
const MAX_MAPPED_JSON: usize = 256 * 1024;
const MAX_KIND: usize = 128;
const MAX_SUMMARY: usize = 4096;
const MAX_HOST: usize = 1024;
const MAX_TIMES: usize = 8;
const MAX_CANDIDATES: usize = 8;
const MAX_ASSUMPTIONS: usize = 16;
const MAX_RECORD_DIAGNOSTICS: usize = 32;
const MAX_DIAGNOSTIC_DETAIL: usize = 4096;
const MAX_WORKER_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAX_WORKER_RECORDS: u64 = 10_000_000;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Hello {
        protocol: u32,
        version: String,
    },
    Parse {
        job_id: String,
        format: String,
        path: String,
        max_records: u64,
        max_record_bytes: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Ready {
        protocol: u32,
        version: String,
    },
    Progress {
        job_id: String,
        records: u64,
    },
    Batch {
        job_id: String,
        seq: u64,
        records: Vec<WireRecord>,
    },
    Done {
        job_id: String,
        records: u64,
        observations: u64,
        events: u64,
        diagnostics: Vec<ImportDiagnostic>,
        diagnostics_total: u64,
    },
    Failed {
        job_id: String,
        code: String,
        message: String,
    },
}

/// One adapter record on the wire. `locator_kind` is a string here and is
/// mapped back to the internal static set by validation, so a worker cannot
/// introduce a locator kind the storage schema does not accept.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRecord {
    pub locator: String,
    pub locator_kind: String,
    pub raw_json: Option<String>,
    pub mapped_json: Option<String>,
    pub event: Option<WireEvent>,
    pub diagnostics: Vec<ImportDiagnostic>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEvent {
    pub kind: String,
    pub summary: String,
    pub host: Option<String>,
    pub times: Vec<WireNamedTime>,
}

/// A named time on the wire. `RawTimeValue.integer` is `i128`, which
/// `serde_json` cannot deserialize, so it travels as exact decimal text and is
/// parsed back during validation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireNamedTime {
    pub name: String,
    pub semantic: TimeSemantic,
    pub value: WireEventTime,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEventTime {
    pub status: TimeStatus,
    pub candidates: Vec<UnixTime>,
    pub raw: Option<WireRawTime>,
    pub semantic: TimeSemantic,
    pub clock_domain: ClockDomain,
    pub declared_precision: TimePrecision,
    pub assumptions: Vec<TimeAssumption>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRawTime {
    pub field: String,
    pub integer: Option<String>,
    pub text: Option<String>,
    pub epoch: Epoch,
    pub unit: crate::domain::time::TimeUnit,
    pub declared_precision: TimePrecision,
}

impl From<EventTime> for WireEventTime {
    fn from(time: EventTime) -> Self {
        Self {
            status: time.status,
            candidates: time.candidates,
            raw: time.raw.map(|raw| WireRawTime {
                field: raw.field,
                integer: raw.integer.map(|value| value.to_string()),
                text: raw.text,
                epoch: raw.epoch,
                unit: raw.unit,
                declared_precision: raw.declared_precision,
            }),
            semantic: time.semantic,
            clock_domain: time.clock_domain,
            declared_precision: time.declared_precision,
            assumptions: time.assumptions,
        }
    }
}

impl TryFrom<WireEventTime> for EventTime {
    type Error = String;

    fn try_from(time: WireEventTime) -> Result<Self, Self::Error> {
        let raw = match time.raw {
            None => None,
            Some(raw) => Some(RawTimeValue {
                field: raw.field,
                integer: match raw.integer {
                    None => None,
                    Some(text) => Some(
                        text.parse::<i128>()
                            .map_err(|_| format!("raw time integer {text:?} is not an i128"))?,
                    ),
                },
                text: raw.text,
                epoch: raw.epoch,
                unit: raw.unit,
                declared_precision: raw.declared_precision,
            }),
        };
        Ok(EventTime {
            status: time.status,
            candidates: time.candidates,
            raw,
            semantic: time.semantic,
            clock_domain: time.clock_domain,
            declared_precision: time.declared_precision,
            assumptions: time.assumptions,
        })
    }
}

impl WireRecord {
    fn from_record(record: ParsedRecord) -> Self {
        Self {
            locator: record.locator,
            locator_kind: record.locator_kind.to_string(),
            raw_json: record.raw_json,
            mapped_json: record.mapped_json,
            event: record.event.map(|draft| WireEvent {
                kind: draft.kind,
                summary: draft.summary,
                host: draft.host,
                times: draft
                    .times
                    .into_iter()
                    .map(|time| WireNamedTime {
                        name: time.name,
                        semantic: time.semantic,
                        value: time.value.into(),
                    })
                    .collect(),
            }),
            diagnostics: record.diagnostics,
        }
    }

    /// Validate a worker record and rebuild the internal shape. Every bound is
    /// a constant in this module; a violation is a protocol error, not a
    /// partial record.
    pub(crate) fn into_record(self, max_record_bytes: usize) -> Result<ParsedRecord, String> {
        let locator_kind = match self.locator_kind.as_str() {
            "byte_range" => "byte_range",
            "logical_row" => "logical_row",
            "binary_record" => "binary_record",
            "filesystem_entry" => "filesystem_entry",
            other => return Err(format!("unknown locator kind {other:?}")),
        };
        check_text("locator", &self.locator, MAX_LOCATOR)?;
        if let Some(raw) = &self.raw_json {
            if raw.len() > max_record_bytes {
                return Err(format!(
                    "raw record is {} bytes, over the {} byte limit",
                    raw.len(),
                    max_record_bytes
                ));
            }
            require_json_container("raw_json", raw)?;
        }
        if let Some(mapped) = &self.mapped_json {
            if mapped.len() > MAX_MAPPED_JSON {
                return Err(format!("mapped fields are {} bytes", mapped.len()));
            }
            require_json_object("mapped_json", mapped)?;
        }
        if self.diagnostics.len() > MAX_RECORD_DIAGNOSTICS {
            return Err(format!(
                "{} record diagnostics, over the {MAX_RECORD_DIAGNOSTICS} limit",
                self.diagnostics.len()
            ));
        }
        for diagnostic in &self.diagnostics {
            check_diagnostic(diagnostic)?;
        }
        let event = match self.event {
            None => None,
            Some(event) => Some(validate_event(event)?),
        };
        if self.raw_json.is_none() && event.is_none() && self.diagnostics.is_empty() {
            return Err("record carries no observation, event, or diagnostic".to_string());
        }
        Ok(ParsedRecord {
            locator: self.locator,
            locator_kind,
            raw_json: self.raw_json,
            mapped_json: self.mapped_json,
            event,
            diagnostics: self.diagnostics,
        })
    }
}

fn validate_event(event: WireEvent) -> Result<EventDraft, String> {
    check_kind(&event.kind)?;
    check_text("summary", &event.summary, MAX_SUMMARY)?;
    if let Some(host) = &event.host {
        check_text("host", host, MAX_HOST)?;
    }
    if event.times.len() > MAX_TIMES {
        return Err(format!(
            "{} named times, over the {MAX_TIMES} limit",
            event.times.len()
        ));
    }
    let mut times = Vec::with_capacity(event.times.len());
    for time in event.times {
        check_text("time name", &time.name, 64)?;
        if time.value.candidates.len() > MAX_CANDIDATES {
            return Err(format!(
                "{} time candidates, over the {MAX_CANDIDATES} limit",
                time.value.candidates.len()
            ));
        }
        if time.value.assumptions.len() > MAX_ASSUMPTIONS {
            return Err(format!(
                "{} time assumptions, over the {MAX_ASSUMPTIONS} limit",
                time.value.assumptions.len()
            ));
        }
        for assumption in &time.value.assumptions {
            check_text("time assumption", &assumption.description, 1024)?;
        }
        if let Some(raw) = &time.value.raw {
            check_text("raw time field", &raw.field, 128)?;
            if let Some(text) = &raw.text {
                check_text("raw time text", text, 4096)?;
            }
        }
        let value = EventTime::try_from(time.value)?;
        times.push(NamedEventTimeRef {
            name: time.name,
            semantic: time.semantic,
            value,
        });
    }
    Ok(EventDraft {
        kind: event.kind,
        summary: event.summary,
        host: event.host,
        times,
    })
}

fn check_kind(kind: &str) -> Result<(), String> {
    if kind.is_empty() || kind.len() > MAX_KIND {
        return Err(format!("event kind has {} bytes", kind.len()));
    }
    if !kind.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        return Err(format!("event kind {kind:?} is not a machine code"));
    }
    Ok(())
}

fn check_text(field: &str, text: &str, max: usize) -> Result<(), String> {
    if text.is_empty() {
        return Err(format!("{field} is empty"));
    }
    if text.len() > max {
        return Err(format!(
            "{field} is {} bytes, over the {max} limit",
            text.len()
        ));
    }
    if text.chars().any(char::is_control) {
        return Err(format!("{field} contains a control character"));
    }
    Ok(())
}

fn check_diagnostic(diagnostic: &ImportDiagnostic) -> Result<(), String> {
    if diagnostic.code.is_empty()
        || diagnostic.code.len() > 64
        || !diagnostic
            .code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(format!(
            "diagnostic code {:?} is not a machine code",
            diagnostic.code
        ));
    }
    check_text("diagnostic locator", &diagnostic.locator, MAX_LOCATOR)?;
    check_text(
        "diagnostic detail",
        &diagnostic.detail,
        MAX_DIAGNOSTIC_DETAIL,
    )
}

fn require_json_container(field: &str, text: &str) -> Result<(), String> {
    match serde_json::from_str::<Value>(text) {
        // The journal adapter keeps ordered `[name, value]` pairs, so a raw
        // record may be an array; every other adapter writes an object.
        Ok(Value::Object(_) | Value::Array(_)) => Ok(()),
        Ok(_) => Err(format!("{field} is not a JSON object or array")),
        Err(error) => Err(format!("{field} is not valid JSON: {error}")),
    }
}

fn require_json_object(field: &str, text: &str) -> Result<(), String> {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(_)) => Ok(()),
        Ok(_) => Err(format!("{field} is not a JSON object")),
        Err(error) => Err(format!("{field} is not valid JSON: {error}")),
    }
}

/// Validate one serialized record against the parent's bounds without building
/// an internal record. Exposed so the protocol contract is testable from
/// outside the crate.
pub fn validate_wire_record(body: &[u8], max_record_bytes: usize) -> Result<(), String> {
    let record: WireRecord = serde_json::from_slice(body).map_err(|error| error.to_string())?;
    record.into_record(max_record_bytes).map(|_| ())
}

/// Write one frame. The length prefix is written only after the body is known
/// to fit, so a rejected frame writes nothing.
pub fn write_frame(output: &mut dyn Write, body: &[u8], max: usize) -> std::io::Result<()> {
    if body.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "empty frame",
        ));
    }
    if body.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame is {} bytes, over the {max} limit", body.len()),
        ));
    }
    let length = u32::try_from(body.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "frame length overflow")
    })?;
    output.write_all(&length.to_be_bytes())?;
    output.write_all(body)?;
    output.flush()
}

/// Read one frame. `Ok(None)` is a clean EOF at a frame boundary; a truncated
/// frame is an error, never a shorter message.
pub fn read_frame(input: &mut dyn Read, max: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut length = [0_u8; 4];
    match input.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "empty frame",
        ));
    }
    if length > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame is {length} bytes, over the {max} limit"),
        ));
    }
    let mut body = vec![0_u8; length];
    input.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Worker side: serve one parse job over the given streams and return the exit
/// code. The worker owns no case handle and writes nothing but protocol frames.
pub fn serve(mut input: impl Read, mut output: impl Write) -> u8 {
    match serve_inner(&mut input, &mut output) {
        Ok(code) => code,
        Err(error) => {
            let _ = write_response(
                &mut output,
                &Response::Failed {
                    job_id: String::new(),
                    code: "worker_protocol".to_string(),
                    message: format!("worker protocol failure: {error}"),
                },
            );
            2
        }
    }
}

fn serve_inner(input: &mut dyn Read, output: &mut dyn Write) -> std::io::Result<u8> {
    let hello = match read_frame(input, MAX_CONTROL_FRAME)? {
        Some(body) => body,
        None => return Ok(2),
    };
    let hello: Request = serde_json::from_slice(&hello).map_err(invalid)?;
    let Request::Hello { protocol, version } = hello else {
        return Ok(2);
    };
    if protocol != PROTOCOL_VERSION || version != BUILD_VERSION {
        let _ = write_response(
            output,
            &Response::Failed {
                job_id: String::new(),
                code: "incompatible_worker".to_string(),
                message: format!(
                    "worker speaks protocol {PROTOCOL_VERSION} build {BUILD_VERSION}; the parent asked for protocol {protocol} build {version}"
                ),
            },
        );
        return Ok(2);
    }
    write_response(
        output,
        &Response::Ready {
            protocol: PROTOCOL_VERSION,
            version: BUILD_VERSION.to_string(),
        },
    )?;

    let parse = match read_frame(input, MAX_CONTROL_FRAME)? {
        Some(body) => body,
        None => return Ok(2),
    };
    let parse: Request = serde_json::from_slice(&parse).map_err(invalid)?;
    let Request::Parse {
        job_id,
        format,
        path,
        max_records,
        max_record_bytes,
    } = parse
    else {
        return Ok(2);
    };
    if job_id.is_empty() || job_id.len() > 128 {
        return failed(output, &job_id, "worker_protocol", "invalid job id");
    }
    let Some(format) = LogFormat::from_id(&format) else {
        return failed(output, &job_id, "unsupported_format", "unknown format id");
    };
    if !format.runs_isolated() {
        return failed(
            output,
            &job_id,
            "unsupported_format",
            "this adapter is not served by the worker",
        );
    }
    let path = match validate_input(&path) {
        Ok(path) => path,
        Err(message) => return failed(output, &job_id, "invalid_input", &message),
    };
    let max_record_bytes = (max_record_bytes as usize).min(MAX_WORKER_RECORD_BYTES);
    let max_records = max_records.min(MAX_WORKER_RECORDS);

    let never = std::sync::atomic::AtomicBool::new(false);
    let mut request = ImportRequest::new(&never);
    request.format = Some(format);
    request.max_record_bytes = max_record_bytes.max(1);
    request.max_records = max_records.max(1);
    let mut cancelled = false;
    // The sink borrows the output stream; the outcome is computed first so the
    // failure path can still write its final frame.
    let outcome = {
        let mut sink = IpcSink {
            output: &mut *output,
            job_id: &job_id,
            seq: 0,
            records: 0,
            observations: 0,
            events: 0,
            diagnostics: Vec::new(),
            diagnostics_total: 0,
            batch: Vec::new(),
            batch_bytes: 0,
            progress_sent: 0,
        };
        match produce_records(format, &path, &request, &mut cancelled, &mut sink) {
            Ok(()) => match sink.flush() {
                Ok(()) => {
                    let (diagnostics, diagnostics_total) = sink.diagnostics();
                    Outcome::Done {
                        records: sink.records,
                        observations: sink.observations,
                        events: sink.events,
                        diagnostics,
                        diagnostics_total,
                    }
                }
                Err(error) => Outcome::Failed {
                    code: error.code().to_string(),
                    detail: error.detail().to_string(),
                },
            },
            Err(error) => Outcome::Failed {
                code: error.code().to_string(),
                detail: error.detail().to_string(),
            },
        }
    };
    match outcome {
        Outcome::Done {
            records,
            observations,
            events,
            diagnostics,
            diagnostics_total,
        } => {
            write_response(
                output,
                &Response::Done {
                    job_id: job_id.clone(),
                    records,
                    observations,
                    events,
                    diagnostics,
                    diagnostics_total,
                },
            )?;
            Ok(0)
        }
        Outcome::Failed { code, detail } => failed(output, &job_id, &code, &detail),
    }
}

enum Outcome {
    Done {
        records: u64,
        observations: u64,
        events: u64,
        diagnostics: Vec<ImportDiagnostic>,
        diagnostics_total: u64,
    },
    Failed {
        code: String,
        detail: String,
    },
}

/// The input must be an absolute, regular, non-symlink file inside the
/// worker's private directory. The parent passes a staged copy; anything else
/// is refused rather than read.
fn validate_input(path: &str) -> Result<std::path::PathBuf, String> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err("the input path is not absolute".to_string());
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("the input path is not readable: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err("the input path is a symlink".to_string());
    }
    if !metadata.is_file() {
        return Err("the input path is not a regular file".to_string());
    }
    let cwd = std::env::current_dir()
        .and_then(|dir| dir.canonicalize())
        .map_err(|error| format!("the worker has no private working directory: {error}"))?;
    let path = path
        .canonicalize()
        .map_err(|error| format!("the input path cannot be resolved: {error}"))?;
    if !path.starts_with(&cwd) {
        return Err("the input path is outside the worker's private directory".to_string());
    }
    Ok(path)
}

fn failed(output: &mut dyn Write, job_id: &str, code: &str, message: &str) -> std::io::Result<u8> {
    let _ = write_response(
        output,
        &Response::Failed {
            job_id: job_id.to_string(),
            code: code.to_string(),
            message: message.to_string(),
        },
    );
    Ok(1)
}

fn write_response(output: &mut dyn Write, response: &Response) -> std::io::Result<()> {
    let body = serde_json::to_vec(response).map_err(invalid)?;
    let max = match response {
        Response::Batch { .. } => MAX_BATCH_FRAME,
        _ => MAX_CONTROL_FRAME,
    };
    write_frame(output, &body, max)
}

fn invalid(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

/// Streams adapter output as batches. Adapter-level diagnostics (limits,
/// truncation, unreadable chunks) are collected for the final `Done`; per-record
/// diagnostics stay on their record.
struct IpcSink<'a> {
    output: &'a mut dyn Write,
    job_id: &'a str,
    seq: u64,
    records: u64,
    observations: u64,
    events: u64,
    diagnostics: Vec<ImportDiagnostic>,
    diagnostics_total: u64,
    batch: Vec<WireRecord>,
    batch_bytes: usize,
    progress_sent: u64,
}

impl IpcSink<'_> {
    fn flush(&mut self) -> CoreResult<()> {
        if self.batch.is_empty() {
            return Ok(());
        }
        let records = std::mem::take(&mut self.batch);
        self.batch_bytes = 0;
        let response = Response::Batch {
            job_id: self.job_id.to_string(),
            seq: self.seq,
            records,
        };
        self.seq += 1;
        write_response(self.output, &response)
            .map_err(|error| CoreError::Storage(format!("worker ipc: {error}")))
    }

    fn diagnostics(&mut self) -> (Vec<ImportDiagnostic>, u64) {
        (
            std::mem::take(&mut self.diagnostics),
            self.diagnostics_total,
        )
    }

    fn push_diagnostic(&mut self, code: &str, locator: &str, detail: &str) {
        self.diagnostics_total += 1;
        if self.diagnostics.len() < crate::ingest::MAX_DIAGNOSTICS {
            self.diagnostics.push(ImportDiagnostic {
                code: code.to_string(),
                locator: locator.to_string(),
                detail: detail.to_string(),
            });
        }
    }
}

impl RecordSink for IpcSink<'_> {
    fn record(&mut self, record: ParsedRecord) -> CoreResult<()> {
        if record.raw_json.is_some() {
            self.observations += 1;
        }
        if record.event.is_some() {
            self.events += 1;
        }
        self.records += 1;
        self.batch_bytes += record
            .raw_json
            .as_ref()
            .map(String::len)
            .unwrap_or_default()
            + record
                .mapped_json
                .as_ref()
                .map(String::len)
                .unwrap_or_default()
            + 4096;
        self.batch.push(WireRecord::from_record(record));
        if self.batch.len() >= MAX_BATCH_RECORDS || self.batch_bytes >= BATCH_BYTES {
            self.flush()?;
        }
        Ok(())
    }

    fn diagnostic(&mut self, code: &str, locator: &str, detail: &str) -> CoreResult<()> {
        self.push_diagnostic(code, locator, detail);
        Ok(())
    }

    fn progress(&mut self, records: u64) -> CoreResult<()> {
        if records.saturating_sub(self.progress_sent) >= 1000 {
            self.progress_sent = records;
            let response = Response::Progress {
                job_id: self.job_id.to_string(),
                records,
            };
            write_response(self.output, &response)
                .map_err(|error| CoreError::Storage(format!("worker ipc: {error}")))?;
        }
        Ok(())
    }
}

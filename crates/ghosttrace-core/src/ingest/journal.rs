//! systemd journal export parsing (plan Section 5, P4.2).
//!
//! The export format is binary safe and may repeat fields, so it is parsed as
//! bytes and stored as ordered `[name, value]` pairs. Nothing is collapsed into
//! a map: `MESSAGE` twice stays twice. Binary values are preserved exactly and
//! rendered as `{"binary_hex": "..."}` inside the JSON raw-fields document.
//!
//! Realtime and monotonic timestamps are separate clock domains. A monotonic
//! value is scoped to its `_BOOT_ID`; [`compare_boot_times`] refuses to order
//! values from different boots, and only realtime decides an event's position
//! on the timeline.

use std::cmp::Ordering;
use std::io::BufRead;

use serde_json::{Value, json};

use crate::domain::event::NamedEventTimeRef;
use crate::domain::time::{
    ClockDomain, Epoch, EventTime, RawTimeValue, TimeAssumption, TimePrecision, TimeSemantic,
    TimeStatus, TimeUnit, UnixTime,
};
use crate::error::{CoreError, CoreResult};

use super::{EventDraft, ImportDiagnostic, ParsedRecord, hex_bytes, truncate_text};

const MAX_FIELD_NAME: usize = 256;
const KIND: &str = "journal.record";

type FieldError = (&'static str, String);
type FieldResult = Result<(String, FieldValue), FieldError>;

/// Compare two monotonic times only when they belong to the same boot clock.
/// Different boots have unrelated origins, so no order is returned.
pub fn compare_boot_times(left: &EventTime, right: &EventTime) -> Option<Ordering> {
    match (&left.clock_domain, &right.clock_domain) {
        (ClockDomain::Boot(left_boot), ClockDomain::Boot(right_boot))
            if left_boot == right_boot =>
        {
            Some(left.candidates.first()?.cmp(right.candidates.first()?))
        }
        _ => None,
    }
}

pub(crate) struct Reader<'a, R: BufRead> {
    stream: &'a mut R,
    offset: u64,
    entry: u64,
    limit: usize,
}

impl<'a, R: BufRead> Reader<'a, R> {
    pub(crate) fn new(stream: &'a mut R, limit: usize) -> Self {
        Self {
            stream,
            offset: 0,
            entry: 0,
            limit,
        }
    }

    pub(crate) fn offset(&self) -> u64 {
        self.offset
    }

    /// Read the next entry. `None` means a clean end of stream; a corrupt or
    /// oversized entry is returned as a diagnostic-only record.
    pub(crate) fn next(&mut self) -> CoreResult<Option<ParsedRecord>> {
        loop {
            let entry_start = self.offset;
            let Some(line) = self.read_line()? else {
                return Ok(None);
            };
            if line.bytes.is_empty() && !line.too_long {
                continue; // entry separator
            }
            self.entry += 1;
            let locator = format!("entry:{}:offset:{entry_start}", self.entry);
            if line.too_long {
                let diagnostic = diagnostic(
                    "record_too_large",
                    &format!(
                        "entry exceeds the configured {} byte limit; not parsed",
                        self.limit
                    ),
                );
                self.drain_entry()?;
                return Ok(Some(skipped(locator, diagnostic)));
            }
            return Ok(Some(self.read_entry(line.bytes, entry_start, locator)?));
        }
    }

    fn read_entry(
        &mut self,
        first: Vec<u8>,
        entry_start: u64,
        locator: String,
    ) -> CoreResult<ParsedRecord> {
        let mut fields: Vec<(String, FieldValue)> = Vec::new();
        let mut diagnostics: Vec<ImportDiagnostic> = Vec::new();
        let mut line = first;
        let mut too_long = false;
        loop {
            if line.is_empty() && !too_long {
                break;
            }
            if self.offset.saturating_sub(entry_start) > self.limit as u64 {
                diagnostics.push(diagnostic(
                    "record_too_large",
                    &format!(
                        "entry exceeds the configured {} byte limit; not parsed",
                        self.limit
                    ),
                ));
                self.drain_entry()?;
                return Ok(ParsedRecord {
                    locator,
                    locator_kind: "byte_range",
                    raw_json: None,
                    event: None,
                    diagnostics,
                });
            }
            if too_long {
                diagnostics.push(diagnostic(
                    "record_too_large",
                    &format!(
                        "field exceeds the configured {} byte limit; entry not parsed",
                        self.limit
                    ),
                ));
                self.drain_entry()?;
                return Ok(ParsedRecord {
                    locator,
                    locator_kind: "byte_range",
                    raw_json: None,
                    event: None,
                    diagnostics,
                });
            }
            match self.parse_field(&line)? {
                Ok(field) => fields.push(field),
                Err((code, detail)) => {
                    diagnostics.push(diagnostic(code, &detail));
                    self.drain_entry()?;
                    return Ok(ParsedRecord {
                        locator,
                        locator_kind: "byte_range",
                        raw_json: None,
                        event: None,
                        diagnostics,
                    });
                }
            }
            match self.read_line()? {
                None => break,
                Some(next) => {
                    line = next.bytes;
                    too_long = next.too_long;
                }
            }
        }
        Ok(build_record(fields, locator, diagnostics))
    }

    fn parse_field(&mut self, line: &[u8]) -> CoreResult<FieldResult> {
        if let Some(position) = line.iter().position(|byte| *byte == b'=') {
            let name = match field_name(&line[..position]) {
                Some(name) => name,
                None => {
                    return Ok(Err((
                        "malformed_field",
                        "text field name is not A-Z0-9_".to_string(),
                    )));
                }
            };
            let Ok(value) = std::str::from_utf8(&line[position + 1..]) else {
                return Ok(Err((
                    "malformed_field",
                    "text field value is not UTF-8".to_string(),
                )));
            };
            if value.chars().any(|ch| ch.is_control() && ch != '\t') {
                return Ok(Err((
                    "malformed_field",
                    "text field value contains control characters".to_string(),
                )));
            }
            return Ok(Ok((name, FieldValue::Text(value.to_string()))));
        }

        let name = match field_name(line) {
            Some(name) => name,
            None => {
                return Ok(Err((
                    "malformed_field",
                    "binary field name is not A-Z0-9_".to_string(),
                )));
            }
        };
        let mut size = [0_u8; 8];
        if !self.read_exact_into(&mut size)? {
            return Ok(Err((
                "truncated_field",
                "binary field length is truncated".to_string(),
            )));
        }
        let length = u64::from_le_bytes(size);
        if length > self.limit as u64 {
            if !self.skip(length)? {
                return Ok(Err((
                    "truncated_field",
                    "binary field data is truncated".to_string(),
                )));
            }
            match self.read_byte()? {
                Some(b'\n') => {}
                _ => {
                    return Ok(Err((
                        "malformed_field",
                        "binary field is not newline-terminated".to_string(),
                    )));
                }
            }
            return Ok(Err((
                "record_too_large",
                format!("binary field length {length} exceeds the entry limit"),
            )));
        }
        let Some(bytes) = self.read_exact_bytes(length)? else {
            return Ok(Err((
                "truncated_field",
                "binary field data is truncated".to_string(),
            )));
        };
        match self.read_byte()? {
            Some(b'\n') => Ok(Ok((name, FieldValue::Binary(bytes)))),
            _ => Ok(Err((
                "malformed_field",
                "binary field is not newline-terminated".to_string(),
            ))),
        }
    }

    /// Resynchronise at the next blank line, keeping field framing so a
    /// newline inside binary data cannot end the entry early.
    fn drain_entry(&mut self) -> CoreResult<()> {
        loop {
            let Some(line) = self.read_line()? else {
                return Ok(());
            };
            if line.bytes.is_empty() && !line.too_long {
                return Ok(());
            }
            if line.too_long || line.bytes.contains(&b'=') {
                continue;
            }
            let mut size = [0_u8; 8];
            if !self.read_exact_into(&mut size)? {
                return Ok(());
            }
            let length = u64::from_le_bytes(size);
            if !self.skip(length)? {
                return Ok(());
            }
            match self.read_byte()? {
                Some(b'\n') => {}
                _ => return Ok(()),
            }
        }
    }

    fn read_line(&mut self) -> CoreResult<Option<Line>> {
        let mut bytes = Vec::new();
        let mut too_long = false;
        let mut seen = false;
        loop {
            let mut consumed = 0_usize;
            let mut done = false;
            {
                let available = self.stream.fill_buf().map_err(|error| {
                    CoreError::Storage(format!("read captured object: {error}"))
                })?;
                if available.is_empty() {
                    done = true;
                } else if let Some(position) = available.iter().position(|byte| *byte == b'\n') {
                    let chunk = &available[..position];
                    if too_long || bytes.len() + chunk.len() > self.limit {
                        too_long = true;
                    } else {
                        bytes.extend_from_slice(chunk);
                    }
                    consumed = position + 1;
                    done = true;
                } else if too_long || bytes.len() + available.len() > self.limit {
                    too_long = true;
                    consumed = available.len();
                } else {
                    consumed = available.len();
                    bytes.extend_from_slice(available);
                }
            }
            seen |= consumed > 0;
            self.offset += consumed as u64;
            self.stream.consume(consumed);
            if done {
                break;
            }
        }
        if !seen {
            return Ok(None);
        }
        Ok(Some(Line { bytes, too_long }))
    }

    fn read_exact_into(&mut self, buffer: &mut [u8]) -> CoreResult<bool> {
        let mut filled = 0;
        while filled < buffer.len() {
            match self.stream.read(&mut buffer[filled..]) {
                Ok(0) => {
                    self.offset += filled as u64;
                    return Ok(false);
                }
                Ok(read) => filled += read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(CoreError::Storage(format!("read captured object: {error}")));
                }
            }
        }
        self.offset += filled as u64;
        Ok(true)
    }

    fn read_exact_bytes(&mut self, length: u64) -> CoreResult<Option<Vec<u8>>> {
        let mut bytes = vec![0_u8; length as usize];
        if self.read_exact_into(&mut bytes)? {
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }

    fn read_byte(&mut self) -> CoreResult<Option<u8>> {
        let mut byte = [0_u8; 1];
        if self.read_exact_into(&mut byte)? {
            Ok(Some(byte[0]))
        } else {
            Ok(None)
        }
    }

    fn skip(&mut self, length: u64) -> CoreResult<bool> {
        let mut remaining = length;
        let mut buffer = [0_u8; 8192];
        while remaining > 0 {
            let take = remaining.min(buffer.len() as u64) as usize;
            match self.stream.read(&mut buffer[..take]) {
                Ok(0) => return Ok(false),
                Ok(read) => {
                    remaining -= read as u64;
                    self.offset += read as u64;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(CoreError::Storage(format!("read captured object: {error}")));
                }
            }
        }
        Ok(true)
    }
}

struct Line {
    bytes: Vec<u8>,
    too_long: bool,
}

enum FieldValue {
    Text(String),
    Binary(Vec<u8>),
}

fn build_record(
    fields: Vec<(String, FieldValue)>,
    locator: String,
    mut diagnostics: Vec<ImportDiagnostic>,
) -> ParsedRecord {
    let realtime = text_field(&fields, "__REALTIME_TIMESTAMP");
    let monotonic = text_field(&fields, "__MONOTONIC_TIMESTAMP");
    let boot = text_field(&fields, "_BOOT_ID");
    let host = text_field(&fields, "_HOSTNAME").filter(|host| host.len() <= 255);
    let message = text_field(&fields, "MESSAGE");

    let raw_json = raw_pairs(&fields);

    let realtime_time = match realtime {
        None => {
            diagnostics.push(diagnostic(
                "time_missing",
                "entry has no __REALTIME_TIMESTAMP; nothing was inferred",
            ));
            unresolved_realtime()
        }
        Some(text) => resolved_realtime(text, &mut diagnostics),
    };
    let mut times = vec![NamedEventTimeRef {
        name: "timestamp".to_string(),
        semantic: TimeSemantic::Realtime,
        value: realtime_time,
    }];
    if let Some(text) = monotonic {
        times.push(NamedEventTimeRef {
            name: "monotonic".to_string(),
            semantic: TimeSemantic::Monotonic,
            value: boot_time(text, boot, &mut diagnostics),
        });
    }

    ParsedRecord {
        locator,
        locator_kind: "byte_range",
        raw_json: Some(raw_json),
        event: Some(EventDraft {
            kind: KIND.to_string(),
            summary: message.map_or_else(|| KIND.to_string(), |text| truncate_text(text, 512)),
            host: host.map(str::to_string),
            times,
        }),
        diagnostics,
    }
}

fn raw_pairs(fields: &[(String, FieldValue)]) -> String {
    let mut pairs = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        let value = match value {
            FieldValue::Text(text) => Value::String(text.clone()),
            FieldValue::Binary(bytes) => json!({ "binary_hex": hex_bytes(bytes) }),
        };
        pairs.push(Value::Array(vec![Value::String(name.clone()), value]));
    }
    Value::Array(pairs).to_string()
}

fn text_field<'a>(fields: &'a [(String, FieldValue)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(field, value)| field == name && matches!(value, FieldValue::Text(_)))
        .and_then(|(_, value)| match value {
            FieldValue::Text(text) => Some(text.as_str()),
            FieldValue::Binary(_) => None,
        })
}

fn resolved_realtime(text: &str, diagnostics: &mut Vec<ImportDiagnostic>) -> EventTime {
    let Ok(micros) = text.parse::<u64>() else {
        diagnostics.push(diagnostic(
            "invalid_time",
            "__REALTIME_TIMESTAMP is not an unsigned integer",
        ));
        return invalid_realtime(text);
    };
    let value = i128::from(micros);
    let candidates: Vec<UnixTime> = UnixTime::from_parts(value, Epoch::Unix, TimeUnit::Micros)
        .ok()
        .into_iter()
        .collect();
    if candidates.is_empty() {
        diagnostics.push(diagnostic(
            "invalid_time",
            "__REALTIME_TIMESTAMP is outside the representable range",
        ));
        return invalid_realtime(text);
    }
    EventTime {
        status: TimeStatus::Resolved,
        candidates,
        raw: Some(RawTimeValue::integer_raw(
            "__REALTIME_TIMESTAMP",
            value,
            Epoch::Unix,
            TimeUnit::Micros,
        )),
        semantic: TimeSemantic::Realtime,
        clock_domain: ClockDomain::Host,
        declared_precision: TimePrecision::Micros,
        assumptions: vec![TimeAssumption {
            description: "realtime timestamp is microseconds since the Unix epoch".to_string(),
            zone: None,
            year_assumed: None,
        }],
    }
}

fn unresolved_realtime() -> EventTime {
    EventTime {
        status: TimeStatus::Unresolved,
        candidates: Vec::new(),
        raw: None,
        semantic: TimeSemantic::Realtime,
        clock_domain: ClockDomain::Host,
        declared_precision: TimePrecision::Unknown,
        assumptions: vec![TimeAssumption {
            description: "entry has no realtime timestamp; nothing was inferred".to_string(),
            zone: None,
            year_assumed: None,
        }],
    }
}

fn invalid_realtime(text: &str) -> EventTime {
    EventTime {
        status: TimeStatus::Invalid,
        candidates: Vec::new(),
        raw: Some(RawTimeValue {
            field: "__REALTIME_TIMESTAMP".to_string(),
            integer: None,
            text: Some(text.to_string()),
            epoch: Epoch::Unix,
            unit: TimeUnit::Micros,
            declared_precision: TimePrecision::Micros,
        }),
        semantic: TimeSemantic::Realtime,
        clock_domain: ClockDomain::Host,
        declared_precision: TimePrecision::Micros,
        assumptions: vec![TimeAssumption {
            description: "realtime timestamp cannot be interpreted".to_string(),
            zone: None,
            year_assumed: None,
        }],
    }
}

fn boot_time(text: &str, boot: Option<&str>, diagnostics: &mut Vec<ImportDiagnostic>) -> EventTime {
    let value = text.parse::<u64>().ok().map(i128::from);
    let candidates: Vec<UnixTime> = value
        .and_then(|value| UnixTime::from_parts(value, Epoch::Unix, TimeUnit::Micros).ok())
        .into_iter()
        .collect();
    let domain = boot.map_or(ClockDomain::Unknown, |boot| {
        ClockDomain::Boot(boot.to_string())
    });
    let scoped = boot.is_some() && !candidates.is_empty();
    if !scoped {
        diagnostics.push(diagnostic(
            "invalid_time",
            if boot.is_none() {
                "__MONOTONIC_TIMESTAMP has no _BOOT_ID; it cannot be scoped or ordered"
            } else {
                "__MONOTONIC_TIMESTAMP is not an unsigned integer"
            },
        ));
    }
    EventTime {
        status: if scoped {
            TimeStatus::Resolved
        } else if boot.is_none() {
            TimeStatus::Unresolved
        } else {
            TimeStatus::Invalid
        },
        candidates: if scoped { candidates } else { Vec::new() },
        raw: Some(RawTimeValue {
            field: "__MONOTONIC_TIMESTAMP".to_string(),
            integer: value,
            text: Some(text.to_string()),
            epoch: Epoch::Unix,
            unit: TimeUnit::Micros,
            declared_precision: TimePrecision::Micros,
        }),
        semantic: TimeSemantic::Monotonic,
        clock_domain: domain,
        declared_precision: TimePrecision::Micros,
        assumptions: vec![TimeAssumption {
            description: "monotonic microseconds are scoped to one boot clock".to_string(),
            zone: None,
            year_assumed: None,
        }],
    }
}

fn field_name(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > MAX_FIELD_NAME {
        return None;
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return None;
    }
    std::str::from_utf8(bytes).ok().map(str::to_string)
}

fn diagnostic(code: &str, detail: &str) -> ImportDiagnostic {
    ImportDiagnostic {
        code: code.to_string(),
        locator: String::new(),
        detail: detail.to_string(),
    }
}

fn skipped(locator: String, diagnostic: ImportDiagnostic) -> ParsedRecord {
    ParsedRecord {
        locator,
        locator_kind: "byte_range",
        raw_json: None,
        event: None,
        diagnostics: vec![diagnostic],
    }
}

//! Bounded JSONL field mapping (plan P4.1).
//!
//! The mapping names fields; it never evaluates expressions. A record that
//! parses but does not fit the declared types is preserved as a raw
//! observation and reported, never coerced into an event.

use serde_json::Value;

use super::{
    EventDraft, JsonlConfig, ParsedRecord, TimeFormat, invalid_time, numeric_time,
    resolved_text_time, unresolved_time,
};

/// Parse one JSONL record. The line is already known to be valid UTF-8.
pub(crate) fn parse_line(text: &str, config: &JsonlConfig) -> ParsedRecord {
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(error) => {
            return ParsedRecord::with_diagnostic(
                "malformed_record",
                format!("line is not valid JSON: {error}"),
            );
        }
    };
    let Value::Object(fields) = value else {
        return ParsedRecord::with_diagnostic("schema_mismatch", "record is not a JSON object");
    };

    let mut record = ParsedRecord {
        raw_fields: Some(fields.clone()),
        event: None,
        diagnostics: Vec::new(),
    };

    let time = match fields.get(&config.time_field) {
        None => {
            record.diagnostic(
                "time_missing",
                format!(
                    "mapped time field {:?} is absent; time stays unresolved",
                    config.time_field
                ),
            );
            unresolved_time(&config.time_field, None, "mapped time field is absent")
        }
        Some(value) => match parse_time_value(&config.time_field, value, config.time_format) {
            Ok(time) => time,
            Err(detail) => {
                record.diagnostic("invalid_time", detail);
                invalid_time(
                    &config.time_field,
                    &value.to_string(),
                    "time value is invalid",
                )
            }
        },
    };

    let kind = match &config.kind_field {
        None => config.default_kind.clone(),
        Some(field) => match fields.get(field) {
            Some(Value::String(kind)) if !kind.is_empty() && kind.len() <= 128 => kind.clone(),
            Some(Value::String(_)) => {
                record.diagnostic(
                    "schema_mismatch",
                    format!("mapped kind field {field:?} is empty or longer than 128 bytes"),
                );
                return record;
            }
            Some(_) => {
                record.diagnostic(
                    "schema_mismatch",
                    format!("mapped kind field {field:?} is not a string"),
                );
                return record;
            }
            None => {
                record.diagnostic(
                    "schema_mismatch",
                    format!("mapped kind field {field:?} is absent"),
                );
                return record;
            }
        },
    };

    let summary = match &config.message_field {
        None => kind.clone(),
        Some(field) => match fields.get(field) {
            None => kind.clone(),
            Some(Value::String(message)) => truncate(message, 512),
            Some(_) => {
                record.diagnostic(
                    "schema_mismatch",
                    format!("mapped message field {field:?} is not a string"),
                );
                return record;
            }
        },
    };

    let host = match &config.host_field {
        None => None,
        Some(field) => match fields.get(field) {
            None => None,
            Some(Value::String(host)) if host.len() <= 255 => Some(host.clone()),
            Some(Value::String(_)) => {
                record.diagnostic(
                    "schema_mismatch",
                    format!("mapped host field {field:?} is longer than 255 bytes"),
                );
                return record;
            }
            Some(_) => {
                record.diagnostic(
                    "schema_mismatch",
                    format!("mapped host field {field:?} is not a string"),
                );
                return record;
            }
        },
    };

    record.event = Some(EventDraft {
        kind,
        summary,
        host,
        time,
    });
    record
}

fn parse_time_value(
    field: &str,
    value: &Value,
    format: TimeFormat,
) -> Result<crate::domain::time::EventTime, String> {
    match format {
        TimeFormat::Rfc3339 => {
            let Value::String(text) = value else {
                return Err(format!(
                    "mapped time field {field:?} must be an RFC 3339 string"
                ));
            };
            let instant = chrono::DateTime::parse_from_rfc3339(text)
                .map_err(|_| format!("mapped time field {field:?} is not RFC 3339"))?;
            Ok(resolved_text_time(
                field,
                text,
                instant,
                "RFC 3339 offset declared in the record",
            ))
        }
        numeric => {
            let Value::Number(number) = value else {
                return Err(format!(
                    "mapped time field {field:?} must be a JSON integer for {}",
                    numeric.id()
                ));
            };
            let integer = number
                .as_i64()
                .map(i128::from)
                .or_else(|| number.as_u64().map(i128::from))
                .ok_or_else(|| {
                    format!(
                        "mapped time field {field:?} is not an integer for {}",
                        numeric.id()
                    )
                })?;
            let mut time = numeric_time(field, integer, numeric);
            if let Some(raw) = time.raw.as_mut() {
                raw.text = Some(number.to_string());
            }
            Ok(time)
        }
    }
}

fn truncate(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

//! RFC 5424 and selected RFC 3164 syslog parsing (plan P4.1).
//!
//! Only tested patterns become events. Every other parsed line is preserved as
//! a raw observation with no invented event type. RFC 3164 headers carry no
//! year and no zone: both stay unresolved unless the operator supplies them,
//! and a December→January sequence is reported as ambiguous, never guessed.

use std::str::FromStr;

use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use chrono_tz::Tz;

use crate::domain::event::NamedEventTimeRef;
use crate::domain::time::{
    EventTime, RawTimeValue, TimeAssumption, TimePrecision, TimeSemantic, TimeStatus, TimeUnit,
};
use crate::error::{CoreError, CoreResult};

use super::{
    EventDraft, ParsedRecord, SyslogConfig, invalid_time, resolved_text_time, unresolved_time,
};

/// Validate operator-supplied syslog assumptions before any run is recorded.
pub fn validate(config: &SyslogConfig) -> CoreResult<()> {
    if let Some(zone) = &config.timezone {
        Tz::from_str(zone)
            .map_err(|_| CoreError::InvalidInput(format!("unknown IANA timezone {zone:?}")))?;
    }
    if let Some(year) = config.year
        && !(1970..=9999).contains(&year)
    {
        return Err(CoreError::InvalidInput(format!(
            "year {year} is outside the supported range 1970..=9999"
        )));
    }
    Ok(())
}

pub(crate) struct Adapter {
    timezone: Option<Tz>,
    year: Option<i32>,
    previous_month: Option<u32>,
    crossed_new_year: bool,
}

impl Adapter {
    pub(crate) fn new(config: &SyslogConfig) -> CoreResult<Self> {
        validate(config)?;
        Ok(Self {
            timezone: config
                .timezone
                .as_deref()
                .map(|zone| {
                    Tz::from_str(zone).map_err(|_| {
                        CoreError::InvalidInput(format!("unknown IANA timezone {zone:?}"))
                    })
                })
                .transpose()?,
            year: config.year,
            previous_month: None,
            crossed_new_year: false,
        })
    }

    pub(crate) fn parse_line(&mut self, text: &str, locator: &str, rfc5424: bool) -> ParsedRecord {
        let header = if rfc5424 {
            parse_5424(text)
        } else {
            parse_3164(text)
        };
        let header = match header {
            Ok(header) => header,
            Err(reason) => {
                return ParsedRecord::with_diagnostic(locator, "malformed_record", reason);
            }
        };

        let mut record = ParsedRecord {
            locator: locator.to_string(),
            raw_json: Some(serde_json::Value::Object(header.raw_fields()).to_string()),
            event: None,
            diagnostics: Vec::new(),
        };

        let time = match &header.timestamp {
            None => unresolved_time("timestamp", None, "syslog header has a nil timestamp"),
            Some(raw) if rfc5424 => match chrono::DateTime::parse_from_rfc3339(raw) {
                Ok(instant) => resolved_text_time(
                    "timestamp",
                    raw,
                    instant,
                    "RFC 5424 timestamp offset declared in the record",
                ),
                Err(_) => {
                    record.diagnostic("invalid_time", "RFC 5424 timestamp is not RFC 3339");
                    invalid_time("timestamp", raw, "timestamp cannot be interpreted")
                }
            },
            Some(raw) => self.legacy_time(raw, &mut record),
        };

        if let Some(message) = header.message.as_deref()
            && let Some((kind, summary)) = auth_event(header.app.as_deref(), message)
        {
            record.event = Some(EventDraft {
                kind,
                summary,
                host: header.hostname.clone(),
                times: vec![NamedEventTimeRef {
                    name: "logged".to_string(),
                    semantic: TimeSemantic::LoggedTime,
                    value: time,
                }],
            });
        }
        record
    }

    /// Interpret an RFC 3164 wall-clock header. Year and zone are only applied
    /// when the operator declared them.
    fn legacy_time(&mut self, raw: &str, record: &mut ParsedRecord) -> EventTime {
        let parsed = match parse_legacy_stamp(raw) {
            Ok(parsed) => parsed,
            Err(reason) => {
                record.diagnostic("invalid_time", reason);
                return invalid_time("timestamp", raw, "timestamp cannot be interpreted");
            }
        };
        let month = parsed.month;
        if self.previous_month == Some(12) && month == 1 {
            self.crossed_new_year = true;
        }
        self.previous_month = Some(month);

        let Some(year) = self.year else {
            return unresolved_time(
                "timestamp",
                Some(raw),
                "RFC 3164 header has no year; supply --year",
            );
        };
        let Some(zone) = self.timezone else {
            return unresolved_time(
                "timestamp",
                Some(raw),
                "RFC 3164 header has no timezone; supply --timezone",
            );
        };
        let date = match NaiveDate::from_ymd_opt(year, month, parsed.day) {
            Some(date) => date,
            None => {
                record.diagnostic("invalid_time", "header day is not valid for its month");
                return invalid_time("timestamp", raw, "calendar date cannot be interpreted");
            }
        };
        let naive = NaiveDateTime::new(date, parsed.time);

        let mut time =
            EventTime::from_local_wall_clock(naive, Some(&zone), TimeSemantic::LoggedTime);
        time.raw = Some(RawTimeValue {
            field: "timestamp".to_string(),
            integer: None,
            text: Some(raw.to_string()),
            epoch: crate::domain::time::Epoch::Unix,
            unit: TimeUnit::Seconds,
            declared_precision: TimePrecision::Seconds,
        });
        time.assumptions.push(TimeAssumption {
            description: "year supplied by the operator; RFC 3164 has none".to_string(),
            zone: Some(zone.name().to_string()),
            year_assumed: Some(year),
        });

        if self.crossed_new_year {
            let mut candidates = Vec::new();
            for candidate_year in [year, year + 1] {
                let Some(date) = NaiveDate::from_ymd_opt(candidate_year, month, parsed.day) else {
                    continue;
                };
                let naive = NaiveDateTime::new(date, parsed.time);
                let interpreted =
                    EventTime::from_local_wall_clock(naive, Some(&zone), TimeSemantic::LoggedTime);
                for candidate in interpreted.candidates {
                    if !candidates.contains(&candidate) {
                        candidates.push(candidate);
                    }
                }
            }
            candidates.sort();
            time.status = if candidates.len() > 1 {
                TimeStatus::Ambiguous
            } else if candidates.len() == 1 {
                TimeStatus::Resolved
            } else {
                TimeStatus::Unresolved
            };
            time.candidates = candidates;
            time.assumptions.push(TimeAssumption {
                description:
                    "file order crossed December→January; the unrecorded year is ambiguous"
                        .to_string(),
                zone: Some(zone.name().to_string()),
                year_assumed: Some(year),
            });
        }
        time
    }
}

struct Header {
    pri: u16,
    facility: u16,
    severity: u16,
    timestamp: Option<String>,
    hostname: Option<String>,
    app: Option<String>,
    proc_id: Option<String>,
    msg_id: Option<String>,
    structured_data: Option<String>,
    message: Option<String>,
    legacy_tag: bool,
}

impl Header {
    fn raw_fields(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut fields = serde_json::Map::new();
        fields.insert("pri".into(), self.pri.into());
        fields.insert("facility".into(), self.facility.into());
        fields.insert("severity".into(), self.severity.into());
        if let Some(value) = &self.timestamp {
            fields.insert("timestamp".into(), value.clone().into());
        }
        if let Some(value) = &self.hostname {
            fields.insert("hostname".into(), value.clone().into());
        }
        if let Some(value) = &self.app {
            fields.insert(
                if self.legacy_tag { "tag" } else { "app_name" }.into(),
                value.clone().into(),
            );
        }
        if let Some(value) = &self.proc_id {
            fields.insert("proc_id".into(), value.clone().into());
        }
        if let Some(value) = &self.msg_id {
            fields.insert("msg_id".into(), value.clone().into());
        }
        if let Some(value) = &self.structured_data {
            fields.insert("structured_data".into(), value.clone().into());
        }
        if let Some(value) = &self.message {
            fields.insert("message".into(), value.clone().into());
        }
        fields
    }
}

fn split_priority(text: &str) -> Result<(u16, &str), &'static str> {
    let rest = text
        .strip_prefix('<')
        .ok_or("record does not start with a priority")?;
    let (digits, tail) = rest.split_once('>').ok_or("priority is not terminated")?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("priority is not numeric");
    }
    let pri: u16 = digits.parse().map_err(|_| "priority is out of range")?;
    if pri > 191 {
        return Err("priority is out of range");
    }
    Ok((pri, tail))
}

fn parse_5424(text: &str) -> Result<Header, &'static str> {
    let (pri, rest) = split_priority(text)?;
    let rest = rest
        .strip_prefix("1 ")
        .ok_or("unsupported RFC 5424 version or missing version")?;
    let mut parts = rest.splitn(6, ' ');
    let timestamp = parts.next().ok_or("missing timestamp")?;
    let hostname = parts.next().ok_or("missing hostname")?;
    let app = parts.next().ok_or("missing app name")?;
    let proc_id = parts.next().ok_or("missing proc id")?;
    let msg_id = parts.next().ok_or("missing msg id")?;
    let remainder = parts.next().ok_or("missing structured data")?;
    let (structured_data, message) = split_structured_data(remainder)?;
    Ok(Header {
        pri,
        facility: pri / 8,
        severity: pri % 8,
        timestamp: nil_value(timestamp),
        hostname: nil_value(hostname),
        app: nil_value(app),
        proc_id: nil_value(proc_id),
        msg_id: nil_value(msg_id),
        structured_data,
        message: message.filter(|text| !text.is_empty()),
        legacy_tag: false,
    })
}

fn split_structured_data(text: &str) -> Result<(Option<String>, Option<String>), &'static str> {
    if let Some(rest) = text.strip_prefix('-') {
        return Ok((None, rest.strip_prefix(' ').map(str::to_string)));
    }
    if !text.starts_with('[') {
        return Err("structured data is neither '-' nor bracketed");
    }
    let mut index = 0;
    while index < text.len() && text.as_bytes()[index] == b'[' {
        let mut in_quotes = false;
        let mut escaped = false;
        let mut end = None;
        for (offset, ch) in text[index..].char_indices() {
            let position = index + offset;
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' if in_quotes => escaped = true,
                '"' => in_quotes = !in_quotes,
                ']' if !in_quotes => {
                    end = Some(position + 1);
                    break;
                }
                _ => {}
            }
        }
        let end = end.ok_or("unterminated structured data element")?;
        index = end;
        if index == text.len() {
            return Ok((Some(text.to_string()), None));
        }
        match text.as_bytes()[index] {
            b'[' => continue,
            b' ' => {
                return Ok((
                    Some(text[..index].to_string()),
                    Some(text[index + 1..].to_string()),
                ));
            }
            _ => return Err("malformed structured data separator"),
        }
    }
    Err("malformed structured data")
}

fn parse_3164(text: &str) -> Result<Header, &'static str> {
    let (pri, rest) = split_priority(text)?;
    if rest.len() < 16 {
        return Err("truncated RFC 3164 header");
    }
    let stamp = rest
        .as_bytes()
        .get(..15)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .ok_or("RFC 3164 timestamp is not ASCII")?;
    // Validate the stamp shape here; interpretation happens in `legacy_time`.
    parse_legacy_stamp(stamp)?;
    let remainder = rest[15..].trim_start_matches(' ');
    let (hostname, tail) = match remainder.split_once(' ') {
        Some((host, tail)) => (Some(host.to_string()), tail),
        None if remainder.is_empty() => (None, ""),
        None => (Some(remainder.to_string()), ""),
    };
    let (tag, message) = match tail.split_once(':') {
        Some((tag, message)) => (
            Some(tag.trim().to_string()),
            Some(message.trim_start().to_string()),
        ),
        None => (None, (!tail.is_empty()).then(|| tail.to_string())),
    };
    Ok(Header {
        pri,
        facility: pri / 8,
        severity: pri % 8,
        timestamp: Some(stamp.to_string()),
        hostname,
        app: tag,
        proc_id: None,
        msg_id: None,
        structured_data: None,
        message,
        legacy_tag: true,
    })
}

struct LegacyStamp {
    month: u32,
    day: u32,
    time: NaiveTime,
}

fn parse_legacy_stamp(text: &str) -> Result<LegacyStamp, &'static str> {
    let mut parts = text.split_whitespace();
    let month_name = parts.next().ok_or("missing month")?;
    let day = parts.next().ok_or("missing day")?;
    let clock = parts.next().ok_or("missing time")?;
    let month = match month_name {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return Err("unknown month name"),
    };
    let day: u32 = day.parse().map_err(|_| "day is not numeric")?;
    if !(1..=31).contains(&day) {
        return Err("day is out of range");
    }
    let time = NaiveTime::parse_from_str(clock, "%H:%M:%S").map_err(|_| "time is not HH:MM:SS")?;
    Ok(LegacyStamp { month, day, time })
}

fn nil_value(value: &str) -> Option<String> {
    (value != "-").then(|| value.to_string())
}

/// Tested authentication outcomes only. Everything else stays raw.
fn auth_event(app: Option<&str>, message: &str) -> Option<(String, String)> {
    let app = app.unwrap_or_default();
    if app.starts_with("sshd") {
        if let Some(rest) = message.strip_prefix("Accepted ") {
            let method = token(Some(rest))?;
            let user = token_after(rest, " for ")?;
            let source = token_after(rest, " from ");
            return Some((
                "auth.login_succeeded".to_string(),
                match source {
                    Some(source) => format!("sshd accepted {method} for {user} from {source}"),
                    None => format!("sshd accepted {method} for {user}"),
                },
            ));
        }
        if let Some(rest) = message
            .strip_prefix("Failed password for invalid user ")
            .or_else(|| message.strip_prefix("Failed password for "))
        {
            let user = token(Some(rest))?;
            let source = token_after(rest, " from ");
            return Some((
                "auth.login_failed".to_string(),
                match source {
                    Some(source) => format!("sshd failed password for {user} from {source}"),
                    None => format!("sshd failed password for {user}"),
                },
            ));
        }
    }
    if app.starts_with("sudo") && message.contains(" COMMAND=") {
        let user = message.split(" :").next()?.trim();
        return Some((
            "auth.sudo_command".to_string(),
            if user.is_empty() {
                "sudo command".to_string()
            } else {
                format!("sudo command by {user}")
            },
        ));
    }
    None
}

fn token(text: Option<&str>) -> Option<&str> {
    text?.split_whitespace().next()
}

fn token_after<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    token(text.split_once(marker).map(|(_, rest)| rest))
}

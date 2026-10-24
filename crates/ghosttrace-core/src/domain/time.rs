//! Exact timestamp semantics (plan Section 6, P1.1).
//!
//! Rules embodied here:
//! - Normalized instants are exact signed Unix seconds + integer nanoseconds.
//!   We never collapse everything into one signed nanosecond integer: its
//!   range is too narrow for forensic inputs.
//! - The original value (integer or text), epoch, unit, and source field are
//!   preserved next to the normalized instant.
//! - A missing time is not epoch zero. Statuses are Resolved, Ambiguous,
//!   Unresolved, or Invalid, with zero or more candidate instants.
//! - Declared resolution is not a measured accuracy bound.
//! - The analyst workstation's timezone is never silently assumed.

use std::fmt;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

/// Epoch reference for a raw numeric timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Epoch {
    /// Seconds since 1970-01-01T00:00:00Z.
    Unix,
    /// 100 ns intervals since 1601-01-01 (Windows FILETIME).
    WindowsFileTime1601,
    /// Microseconds since 1601-01-01 (Chromium family).
    Chrome1601,
    /// Seconds since 2001-01-01 (macOS absolute time).
    MacAbsolute2001,
}

impl Epoch {
    /// Seconds from this epoch to the Unix epoch (positive means this epoch
    /// starts earlier than Unix).
    pub fn offset_seconds(self) -> i128 {
        match self {
            Epoch::Unix => 0,
            Epoch::WindowsFileTime1601 | Epoch::Chrome1601 => 11_644_473_600,
            Epoch::MacAbsolute2001 => -978_307_200,
        }
    }
}

/// Unit of a raw numeric timestamp value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeUnit {
    Seconds,
    Millis,
    Micros,
    Nanos,
    /// 100 ns intervals (Windows FILETIME).
    Ticks100Ns,
}

impl TimeUnit {
    pub fn nanos_per_unit(self) -> i128 {
        match self {
            TimeUnit::Seconds => 1_000_000_000,
            TimeUnit::Millis => 1_000_000,
            TimeUnit::Micros => 1_000,
            TimeUnit::Nanos => 1,
            TimeUnit::Ticks100Ns => 100,
        }
    }
}

/// Declared timestamp resolution. This is a statement about the *format*,
/// never a measurement of source clock accuracy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimePrecision {
    Nanos,
    Micros,
    Millis,
    Seconds,
    Minutes,
    Unknown,
}

/// Which clock domain a value belongs to. Monotonic values are only orderable
/// within the same boot (plan Sections 6, P4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClockDomain {
    /// Wall-clock domain of a host (still subject to clock skew).
    Host,
    /// Monotonic/boot-scoped domain; the ID identifies the boot clock.
    Boot(String),
    /// Not known; treated cautiously in ordering and correlation.
    Unknown,
}

/// What a timestamp means semantically. Accuracy interpretation depends on it
/// (`ctime` is a metadata change, `mtime` a content change, ...).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeSemantic {
    ContentModified,
    StatusChanged,
    Created,
    Accessed,
    LoggedTime,
    OccurrenceTime,
    Realtime,
    Monotonic,
    Other(String),
}

/// An explicit assumption used to interpret a raw time: an investigator- or
/// parser-recorded zone, year, or correction rationale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeAssumption {
    pub description: String,
    /// IANA zone name or raw offset label actually assumed.
    pub zone: Option<String>,
    pub year_assumed: Option<i32>,
}

/// The original observed time value, preserved exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawTimeValue {
    /// Source field name (e.g. `mtime`, `_SOURCE_REALTIME_TIMESTAMP`).
    pub field: String,
    /// Original integer, when the source was numeric.
    pub integer: Option<i128>,
    /// Original text, when the source was textual.
    pub text: Option<String>,
    pub epoch: Epoch,
    pub unit: TimeUnit,
    pub declared_precision: TimePrecision,
}

impl RawTimeValue {
    pub fn integer_raw(field: &str, value: i128, epoch: Epoch, unit: TimeUnit) -> Self {
        let declared_precision = match unit {
            TimeUnit::Nanos | TimeUnit::Ticks100Ns => TimePrecision::Nanos,
            TimeUnit::Micros => TimePrecision::Micros,
            TimeUnit::Millis => TimePrecision::Millis,
            TimeUnit::Seconds => TimePrecision::Seconds,
        };
        Self {
            field: field.to_string(),
            integer: Some(value),
            text: None,
            epoch,
            unit,
            declared_precision,
        }
    }
}

/// An exact instant: signed Unix seconds plus integer nanoseconds in
/// `[0, 999_999_999]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnixTime {
    pub seconds: i64,
    pub nanos: u32,
}

impl UnixTime {
    pub const EPOCH: UnixTime = UnixTime {
        seconds: 0,
        nanos: 0,
    };

    /// Convert a raw integer from an epoch/unit into an exact instant.
    pub fn from_parts(value: i128, epoch: Epoch, unit: TimeUnit) -> CoreResult<UnixTime> {
        let unit_nanos = value
            .checked_mul(unit.nanos_per_unit())
            .ok_or_else(|| CoreError::InvalidInput("time_overflow: value times unit".into()))?;
        let offset_nanos = epoch
            .offset_seconds()
            .checked_mul(1_000_000_000)
            .ok_or_else(|| CoreError::InvalidInput("time_overflow: epoch offset".into()))?;
        // A 1601-epoch value counts more seconds than the Unix instant, so the
        // epoch offset is subtracted here (and added back by `to_parts`).
        let total = unit_nanos
            .checked_sub(offset_nanos)
            .ok_or_else(|| CoreError::InvalidInput("time_overflow: total".into()))?;
        let seconds = total.div_euclid(1_000_000_000);
        let nanos = total.rem_euclid(1_000_000_000);
        let seconds = i64::try_from(seconds)
            .map_err(|_| CoreError::InvalidInput("time_overflow: seconds range".into()))?;
        let nanos = u32::try_from(nanos)
            .map_err(|_| CoreError::InvalidInput("time_overflow: nanos range".into()))?;
        Ok(UnixTime { seconds, nanos })
    }

    /// Convert this instant back into a raw integer of the given epoch/unit.
    /// Returns `None` when the value does not fit that representation.
    pub fn to_parts(self, epoch: Epoch, unit: TimeUnit) -> Option<i128> {
        let total = i128::from(self.seconds) * 1_000_000_000 + i128::from(self.nanos);
        let shifted = total + epoch.offset_seconds() * 1_000_000_000;
        let unit_nanos = unit.nanos_per_unit();
        if shifted % unit_nanos != 0 {
            return None; // not representable at this resolution
        }
        Some(shifted / unit_nanos)
    }

    pub fn from_datetime_utc(value: DateTime<Utc>) -> Self {
        UnixTime {
            seconds: value.timestamp(),
            nanos: value.timestamp_subsec_nanos(),
        }
    }

    pub fn to_datetime_utc(self) -> Option<DateTime<Utc>> {
        Utc.timestamp_opt(self.seconds, self.nanos).single()
    }

    /// Display in UTC as RFC 3339 (`Z`). This is a display of the *earliest
    /// interpretation*; the status and remaining candidates carry uncertainty.
    pub fn display_utc(&self) -> Option<String> {
        self.to_datetime_utc()
            .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
    }
}

impl fmt::Display for UnixTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.display_utc() {
            Some(text) => f.write_str(&text),
            None => write!(f, "{}s+{}ns (out of range)", self.seconds, self.nanos),
        }
    }
}

/// A timestamp with its uncertainty preserved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventTime {
    pub status: TimeStatus,
    /// Zero or more candidate instants, chronological when more than one.
    /// Empty for Unresolved/Invalid by construction.
    pub candidates: Vec<UnixTime>,
    /// Preserved original value.
    pub raw: Option<RawTimeValue>,
    pub semantic: TimeSemantic,
    pub clock_domain: ClockDomain,
    pub declared_precision: TimePrecision,
    pub assumptions: Vec<TimeAssumption>,
}

/// Resolution state of an [`EventTime`]. Never `Resolved` with zero candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeStatus {
    Resolved,
    /// More than one genuine interpretation (e.g. DST overlap).
    Ambiguous,
    /// Not determined; no silent local or zero default was applied.
    Unresolved,
    /// The value exists but cannot be interpreted (overflow, malformed).
    Invalid,
}

impl EventTime {
    /// Build from a raw numeric value, converting to at most one candidate.
    pub fn from_raw(raw: RawTimeValue, semantic: TimeSemantic, clock_domain: ClockDomain) -> Self {
        let Some(value) = raw.integer else {
            // Textual raw values without a parsed instant remain unresolved.
            return Self {
                status: TimeStatus::Unresolved,
                candidates: Vec::new(),
                declared_precision: raw.declared_precision,
                raw: Some(raw),
                semantic,
                clock_domain,
                assumptions: Vec::new(),
            };
        };
        match UnixTime::from_parts(value, raw.epoch, raw.unit) {
            Ok(instant) => Self {
                status: TimeStatus::Resolved,
                candidates: vec![instant],
                declared_precision: raw.declared_precision,
                raw: Some(raw),
                semantic,
                clock_domain,
                assumptions: Vec::new(),
            },
            Err(_) => Self {
                status: TimeStatus::Invalid,
                candidates: Vec::new(),
                declared_precision: raw.declared_precision,
                raw: Some(raw),
                semantic,
                clock_domain,
                assumptions: Vec::new(),
            },
        }
    }

    /// An exactly known Unix instant.
    pub fn from_unix_seconds(seconds: i64, semantic: TimeSemantic) -> Self {
        Self {
            status: TimeStatus::Resolved,
            candidates: vec![UnixTime { seconds, nanos: 0 }],
            raw: None,
            semantic,
            clock_domain: ClockDomain::Host,
            declared_precision: TimePrecision::Seconds,
            assumptions: Vec::new(),
        }
    }

    /// Interpret a local wall-clock time in a *declared* zone.
    ///
    /// - no zone given -> Unresolved (the analyst workstation is never assumed)
    /// - DST overlap -> Ambiguous with both candidates, earliest first
    /// - nonexistent local time -> Unresolved unless a recorded assumption
    ///   resolves it
    pub fn from_local_wall_clock(
        naive: NaiveDateTime,
        zone: Option<&Tz>,
        semantic: TimeSemantic,
    ) -> Self {
        let Some(zone) = zone else {
            return Self {
                status: TimeStatus::Unresolved,
                candidates: Vec::new(),
                raw: None,
                semantic,
                clock_domain: ClockDomain::Host,
                declared_precision: TimePrecision::Seconds,
                assumptions: Vec::new(),
            };
        };
        match naive.and_local_timezone(*zone) {
            chrono::LocalResult::Single(dt) => {
                let instant = UnixTime::from_datetime_utc(dt.with_timezone(&Utc));
                Self {
                    status: TimeStatus::Resolved,
                    candidates: vec![instant],
                    raw: None,
                    semantic,
                    clock_domain: ClockDomain::Host,
                    declared_precision: TimePrecision::Seconds,
                    assumptions: vec![TimeAssumption {
                        description: "declared zone interpretation".into(),
                        zone: Some(zone.name().to_string()),
                        year_assumed: None,
                    }],
                }
            }
            chrono::LocalResult::Ambiguous(first, second) => Self {
                status: TimeStatus::Ambiguous,
                candidates: vec![
                    UnixTime::from_datetime_utc(first.with_timezone(&Utc)),
                    UnixTime::from_datetime_utc(second.with_timezone(&Utc)),
                ],
                raw: None,
                semantic,
                clock_domain: ClockDomain::Host,
                declared_precision: TimePrecision::Seconds,
                assumptions: vec![TimeAssumption {
                    description: "DST overlap: both local readings are genuine".into(),
                    zone: Some(zone.name().to_string()),
                    year_assumed: None,
                }],
            },
            chrono::LocalResult::None => Self {
                status: TimeStatus::Unresolved,
                candidates: Vec::new(),
                raw: None,
                semantic,
                clock_domain: ClockDomain::Host,
                declared_precision: TimePrecision::Seconds,
                assumptions: vec![TimeAssumption {
                    description: "nonexistent local time (DST gap); unresolved".into(),
                    zone: Some(zone.name().to_string()),
                    year_assumed: None,
                }],
            },
        }
    }

    /// The single resolved instant, if exactly one interpretation exists.
    pub fn resolved_instant(&self) -> Option<UnixTime> {
        match self.status {
            TimeStatus::Resolved if self.candidates.len() == 1 => Some(self.candidates[0]),
            _ => None,
        }
    }
}

impl fmt::Display for EventTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            TimeStatus::Resolved => match self.candidates.first() {
                Some(instant) => write!(f, "{}", instant),
                None => f.write_str("invalid: resolved without candidate"),
            },
            TimeStatus::Ambiguous => {
                write!(
                    f,
                    "ambiguous ({} candidates, earliest first)",
                    self.candidates.len()
                )
            }
            TimeStatus::Unresolved => f.write_str("unknown"),
            TimeStatus::Invalid => f.write_str("invalid"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chromium_micros_since_1601_normalize_to_unix_epoch() {
        let instant =
            UnixTime::from_parts(11_644_473_600_000_000, Epoch::Chrome1601, TimeUnit::Micros)
                .expect("in range");
        assert_eq!(instant, UnixTime::EPOCH);
    }

    #[test]
    fn windows_filetime_ticks_normalize_to_unix_epoch() {
        let instant = UnixTime::from_parts(
            116_444_736_000_000_000,
            Epoch::WindowsFileTime1601,
            TimeUnit::Ticks100Ns,
        )
        .expect("in range");
        assert_eq!(instant, UnixTime::EPOCH);
    }

    #[test]
    fn firefox_prtime_micros_since_1970_is_one_second() {
        let instant =
            UnixTime::from_parts(1_000_000, Epoch::Unix, TimeUnit::Micros).expect("in range");
        assert_eq!(
            instant,
            UnixTime {
                seconds: 1,
                nanos: 0
            }
        );
    }

    #[test]
    fn negative_dates_are_exact_not_sentinels() {
        let instant =
            UnixTime::from_parts(-100_000, Epoch::Unix, TimeUnit::Seconds).expect("in range");
        assert_eq!(instant.seconds, -100_000);
        assert_eq!(
            instant
                .to_datetime_utc()
                .map(|dt| dt.to_rfc3339())
                .as_deref(),
            Some("1969-12-30T20:13:20+00:00")
        );
    }

    #[test]
    fn extreme_values_are_invalid_not_panics() {
        assert!(UnixTime::from_parts(i128::MAX, Epoch::Unix, TimeUnit::Nanos).is_err());
        assert!(UnixTime::from_parts(i128::MIN, Epoch::Chrome1601, TimeUnit::Ticks100Ns).is_err());
    }

    #[test]
    fn round_trip_between_epoch_preserves_value() {
        let value = 13_337_001_234_567i128;
        let instant = UnixTime::from_parts(value, Epoch::Chrome1601, TimeUnit::Micros).expect("ok");
        assert_eq!(
            instant.to_parts(Epoch::Chrome1601, TimeUnit::Micros),
            Some(value)
        );
    }

    #[test]
    fn raw_value_is_preserved_beside_normalized_instant() {
        let raw = RawTimeValue::integer_raw(
            "mtime",
            11_644_473_600_000_000,
            Epoch::Chrome1601,
            TimeUnit::Micros,
        );
        let time = EventTime::from_raw(raw, TimeSemantic::ContentModified, ClockDomain::Host);
        assert_eq!(time.status, TimeStatus::Resolved);
        assert_eq!(time.resolved_instant(), Some(UnixTime::EPOCH));
        let raw = time.raw.expect("raw preserved");
        assert_eq!(raw.field, "mtime");
        assert_eq!(raw.integer, Some(11_644_473_600_000_000));
    }

    #[test]
    fn dst_overlap_has_two_candidates() {
        let naive =
            NaiveDateTime::parse_from_str("2024-11-03T01:30:00", "%Y-%m-%dT%H:%M:%S").unwrap();
        let time = EventTime::from_local_wall_clock(
            naive,
            Some(&chrono_tz::America::New_York),
            TimeSemantic::Other("wall".into()),
        );
        assert_eq!(time.status, TimeStatus::Ambiguous);
        assert_eq!(time.candidates.len(), 2);
        let utcs: Vec<String> = time
            .candidates
            .iter()
            .map(|c| c.display_utc().unwrap())
            .collect();
        assert_eq!(utcs[0], "2024-11-03T05:30:00.000000000Z");
        assert_eq!(utcs[1], "2024-11-03T06:30:00.000000000Z");
    }

    #[test]
    fn nonexistent_local_time_stays_unresolved() {
        let naive =
            NaiveDateTime::parse_from_str("2024-03-10T02:30:00", "%Y-%m-%dT%H:%M:%S").unwrap();
        let time = EventTime::from_local_wall_clock(
            naive,
            Some(&chrono_tz::America::New_York),
            TimeSemantic::Other("wall".into()),
        );
        assert_eq!(time.status, TimeStatus::Unresolved);
        assert!(time.candidates.is_empty());
        assert_eq!(time.to_string(), "unknown");
    }

    #[test]
    fn missing_zone_never_assumes_workstation_zone() {
        let naive =
            NaiveDateTime::parse_from_str("2024-11-03T01:30:00", "%Y-%m-%dT%H:%M:%S").unwrap();
        let time = EventTime::from_local_wall_clock(
            naive,
            None,
            TimeSemantic::Other("legacy syslog".into()),
        );
        assert_eq!(time.status, TimeStatus::Unresolved);
        assert!(
            time.assumptions.is_empty(),
            "no silent zone assumption may be recorded"
        );
    }

    #[test]
    fn declared_precision_is_not_accuracy() {
        let raw = RawTimeValue::integer_raw(
            "visit_time",
            13_337_001_234_567,
            Epoch::Chrome1601,
            TimeUnit::Micros,
        );
        let time = EventTime::from_raw(
            raw,
            TimeSemantic::Other("browser.visit".into()),
            ClockDomain::Host,
        );
        assert_eq!(time.declared_precision, TimePrecision::Micros);
        // The precision statement is about the format only; there is no field
        // asserting measured accuracy, by design.
    }

    #[test]
    fn json_round_trip_preserves_status_candidates_and_raw() {
        let raw = RawTimeValue::integer_raw(
            "_SOURCE_REALTIME_TIMESTAMP",
            500_000,
            Epoch::Unix,
            TimeUnit::Micros,
        );
        let time = EventTime::from_raw(raw, TimeSemantic::Realtime, ClockDomain::Boot("b1".into()));
        let json = serde_json::to_string(&time).expect("serialize");
        let back: EventTime = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(time, back);
        assert_eq!(back.clock_domain, ClockDomain::Boot("b1".into()));
    }
}

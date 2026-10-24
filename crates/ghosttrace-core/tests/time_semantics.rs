//! P1.1 time-semantics contract (plan Section 17: focused check
//! `cargo test -p ghosttrace-core --test time_semantics --test native_paths --locked`).

use chrono::NaiveDateTime;
use chrono_tz::America::New_York;
use ghosttrace_core::domain::time::{
    ClockDomain, Epoch, EventTime, RawTimeValue, TimePrecision, TimeSemantic, TimeStatus, TimeUnit,
    UnixTime,
};

#[test]
fn chromium_microseconds_normalize_exactly() {
    let raw = RawTimeValue::integer_raw(
        "visit_time",
        11_644_473_600_000_000,
        Epoch::Chrome1601,
        TimeUnit::Micros,
    );
    let time = EventTime::from_raw(
        raw,
        TimeSemantic::Other("browser.visit".into()),
        ClockDomain::Host,
    );
    assert_eq!(time.status, TimeStatus::Resolved);
    assert_eq!(time.resolved_instant(), Some(UnixTime::EPOCH));
    assert_eq!(
        time.resolved_instant()
            .unwrap()
            .to_parts(Epoch::Chrome1601, TimeUnit::Micros),
        Some(11_644_473_600_000_000)
    );
}

#[test]
fn windows_filetime_ticks_normalize_exactly() {
    let raw = RawTimeValue::integer_raw(
        "mtime",
        116_444_736_000_000_000,
        Epoch::WindowsFileTime1601,
        TimeUnit::Ticks100Ns,
    );
    let time = EventTime::from_raw(raw, TimeSemantic::ContentModified, ClockDomain::Host);
    assert_eq!(time.status, TimeStatus::Resolved);
    assert_eq!(time.resolved_instant(), Some(UnixTime::EPOCH));
}

#[test]
fn firefox_prtime_one_second() {
    let raw = RawTimeValue::integer_raw("visit_date", 1_000_000, Epoch::Unix, TimeUnit::Micros);
    let time = EventTime::from_raw(
        raw,
        TimeSemantic::Other("browser.visit".into()),
        ClockDomain::Host,
    );
    assert_eq!(
        time.resolved_instant(),
        Some(UnixTime {
            seconds: 1,
            nanos: 0
        })
    );
}

#[test]
fn dst_overlap_keeps_both_candidates() {
    let naive = NaiveDateTime::parse_from_str("2024-11-03T01:30:00", "%Y-%m-%dT%H:%M:%S").unwrap();
    let time = EventTime::from_local_wall_clock(
        naive,
        Some(&New_York),
        TimeSemantic::Other("wall".into()),
    );
    assert_eq!(time.status, TimeStatus::Ambiguous);
    let utcs: Vec<String> = time
        .candidates
        .iter()
        .map(|c| c.display_utc().unwrap())
        .collect();
    assert_eq!(
        utcs,
        vec![
            "2024-11-03T05:30:00.000000000Z",
            "2024-11-03T06:30:00.000000000Z"
        ]
    );
}

#[test]
fn nonexistent_local_time_is_unresolved() {
    let naive = NaiveDateTime::parse_from_str("2024-03-10T02:30:00", "%Y-%m-%dT%H:%M:%S").unwrap();
    let time = EventTime::from_local_wall_clock(
        naive,
        Some(&New_York),
        TimeSemantic::Other("wall".into()),
    );
    assert_eq!(time.status, TimeStatus::Unresolved);
    assert!(time.candidates.is_empty());
}

#[test]
fn missing_zone_stays_unresolved_without_assumptions() {
    let naive = NaiveDateTime::parse_from_str("2024-11-03T01:30:00", "%Y-%m-%dT%H:%M:%S").unwrap();
    let time =
        EventTime::from_local_wall_clock(naive, None, TimeSemantic::Other("syslog legacy".into()));
    assert_eq!(time.status, TimeStatus::Unresolved);
    assert!(time.assumptions.is_empty());
}

#[test]
fn negative_and_overflow_are_handled_without_sentinels() {
    let negative = EventTime::from_raw(
        RawTimeValue::integer_raw("epoch", -100_000, Epoch::Unix, TimeUnit::Seconds),
        TimeSemantic::Other("epoch".into()),
        ClockDomain::Host,
    );
    assert_eq!(negative.status, TimeStatus::Resolved);
    assert_eq!(negative.resolved_instant().unwrap().seconds, -100_000);

    let overflow = EventTime::from_raw(
        RawTimeValue::integer_raw("epoch", i128::MAX, Epoch::Unix, TimeUnit::Nanos),
        TimeSemantic::Other("epoch".into()),
        ClockDomain::Host,
    );
    assert_eq!(overflow.status, TimeStatus::Invalid);
    assert!(overflow.candidates.is_empty());
}

#[test]
fn declared_precision_is_recorded_not_accuracy() {
    let time = EventTime::from_raw(
        RawTimeValue::integer_raw("visit_time", 1, Epoch::Chrome1601, TimeUnit::Micros),
        TimeSemantic::Other("browser.visit".into()),
        ClockDomain::Host,
    );
    assert_eq!(time.declared_precision, TimePrecision::Micros);
}

#[test]
fn json_projection_preserves_everything() {
    let time = EventTime::from_raw(
        RawTimeValue::integer_raw("mtime", 1_700_000_000, Epoch::Unix, TimeUnit::Seconds),
        TimeSemantic::ContentModified,
        ClockDomain::Boot("boot-42".into()),
    );
    let json = serde_json::to_string_pretty(&time).unwrap();
    let back: EventTime = serde_json::from_str(&json).unwrap();
    assert_eq!(time, back);
}

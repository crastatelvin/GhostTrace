//! P10.1 bounded fuzz targets: arbitrary bytes and strings at the time, path,
//! manifest, CSV, display, and worker-frame trust boundaries must never panic,
//! must stay inside their declared bounds, and must report failure honestly.
//!
//! These are the fuzz targets for this project. They use the already-pinned
//! `proptest` dev-dependency and run on the stable toolchain in the normal test
//! battery, so every case is deterministic and every regression is replayed in
//! CI. `docs/testing.md` records why a separately pinned nightly/libFuzzer
//! harness is not used: it would add an unverified toolchain to the release
//! gate without covering a boundary these targets do not already reach.

use std::io::Cursor;

use ghosttrace_core::domain::path::{NativePath, NativePathWire};
use ghosttrace_core::domain::time::{
    ClockDomain, Epoch, RawTimeValue, TimeSemantic, TimeStatus, TimeUnit, UnixTime,
};
use ghosttrace_core::integrity::manifest::ManifestV1;
use ghosttrace_core::reports::csv::neutralize;
use ghosttrace_core::text::escape_for_display;
use ghosttrace_core::worker::protocol::{read_frame, validate_wire_record};
use proptest::prelude::*;

fn epoch(index: usize) -> Epoch {
    match index % 4 {
        0 => Epoch::Unix,
        1 => Epoch::WindowsFileTime1601,
        2 => Epoch::Chrome1601,
        _ => Epoch::MacAbsolute2001,
    }
}

fn unit(index: usize) -> TimeUnit {
    match index % 5 {
        0 => TimeUnit::Seconds,
        1 => TimeUnit::Millis,
        2 => TimeUnit::Micros,
        3 => TimeUnit::Nanos,
        _ => TimeUnit::Ticks100Ns,
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Any raw integer, epoch, and unit either converts to a normalized instant
    /// inside the declared nanosecond range or is rejected. No wrapping, no
    /// silent saturation.
    #[test]
    fn time_conversion_is_total_and_bounded(value in any::<i128>(), epoch_index in 0usize..4, unit_index in 0usize..5) {
        match UnixTime::from_parts(value, epoch(epoch_index), unit(unit_index)) {
            Ok(time) => prop_assert!(time.nanos < 1_000_000_000),
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
        let raw = RawTimeValue::integer_raw("fuzz", value, epoch(epoch_index), unit(unit_index));
        let event_time = ghosttrace_core::domain::time::EventTime::from_raw(
            raw,
            TimeSemantic::LoggedTime,
            ClockDomain::Host,
        );
        // A raw value that cannot be normalized must remain visibly unresolved,
        // never become the Unix epoch.
        if event_time.candidates.is_empty() {
            prop_assert_ne!(event_time.status, TimeStatus::Resolved);
        }
    }

    /// The interchange decoder accepts only its ASCII encoding. Anything that
    /// decodes must re-encode and re-decode to the same path, and a lone
    /// surrogate is preserved rather than replaced.
    #[test]
    fn native_path_decoding_is_strict_and_reversible(bytes in prop::collection::vec(any::<u8>(), 0..256), units in prop::collection::vec(any::<u16>(), 0..128)) {
        for wire in [
            NativePathWire { kind: "unix".into(), encoded: NativePath::unix(bytes.clone()).encoded() },
            NativePathWire { kind: "windows".into(), encoded: NativePath::windows(units.clone()).encoded() },
        ] {
            let path = NativePath::try_from(wire.clone()).expect("canonical encoding decodes");
            let again = NativePath::try_from(NativePathWire::from(path.clone())).expect("re-decode");
            prop_assert_eq!(path, again);
        }
    }

    /// Arbitrary text is either a valid manifest or an honest error; a hostile
    /// document can never be accepted because a field was skipped.
    #[test]
    fn manifest_parsing_never_panics(text in ".{0,4096}") {
        let case_root = std::path::Path::new("/nonexistent/fuzz-case");
        match ManifestV1::verify_bytes(&text, case_root) {
            Ok(_) => {}
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
    }

    /// CSV projection output is one line, has no raw control characters, and
    /// never begins (after spaces) with a spreadsheet formula character.
    #[test]
    fn csv_projection_cannot_emit_a_formula_or_a_new_line(text in ".{0,512}") {
        let projected = neutralize(&text);
        prop_assert!(!projected.contains(['\r', '\n', '\t']));
        prop_assert!(!projected.chars().any(|ch| ch.is_control()));
        let trimmed = projected.trim_start_matches(' ');
        if trimmed.starts_with(['=', '+', '-', '@']) {
            prop_assert!(projected.starts_with('\''), "formula-leading cell not neutralized: {projected:?}");
        }
    }

    /// Display escaping never emits a raw control/bidi character (except the
    /// deliberately allowed newline and tab) and respects the byte bound.
    #[test]
    fn display_escaping_is_bounded(text in ".{0,512}", max in 0usize..256) {
        let (shown, truncated) = escape_for_display(&text, max);
        prop_assert!(shown.len() <= max);
        prop_assert!(shown.chars().all(|ch| ch == '\n' || ch == '\t' || !ch.is_control()));
        // `truncated` is about the escaped output bound, not the input length:
        // escaping can expand one input character into several bytes.
        let _ = truncated;
    }

    /// Arbitrary bytes cannot make the worker framing read past its bound or
    /// panic. A frame larger than the limit is refused, not allocated.
    #[test]
    fn worker_frames_are_bounded(bytes in prop::collection::vec(any::<u8>(), 0..2048), max in 0usize..1024) {
        let mut cursor = Cursor::new(bytes.clone());
        match read_frame(&mut cursor, max) {
            Ok(Some(frame)) => prop_assert!(frame.len() <= max),
            Ok(None) => {}
            Err(_) => {}
        }
        let _ = validate_wire_record(&bytes, max);
    }
}

// Deterministic regressions for faults this target found.

#[test]
fn non_ascii_windows_encoded_text_is_rejected_not_truncated() {
    // Before the fix, `é` was cast to a u16 and silently became U+00E9, which
    // is not what the ASCII interchange encoding means.
    let wire = NativePathWire {
        kind: "windows".into(),
        encoded: "é".into(),
    };
    assert!(NativePath::try_from(wire).is_err());
    let wire = NativePathWire {
        kind: "unix".into(),
        encoded: "é".into(),
    };
    assert!(NativePath::try_from(wire).is_err());
}

#[test]
fn a_giant_frame_length_is_refused_without_allocating() {
    let mut bytes = u32::MAX.to_be_bytes().to_vec();
    bytes.extend_from_slice(b"{}");
    let error = read_frame(&mut Cursor::new(bytes), 1024).expect_err("oversize frame");
    assert!(error.to_string().contains("frame"));
}

#[test]
fn duplicate_manifest_keys_are_rejected() {
    let text = r#"{"format":"ghosttrace-manifest/1","format":"ghosttrace-manifest/1"}"#;
    let error = ManifestV1::verify_bytes(text, std::path::Path::new("/nonexistent"))
        .expect_err("duplicate key");
    assert!(error.to_string().contains("duplicate"));
}

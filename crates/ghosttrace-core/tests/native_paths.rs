//! P1.1 native-path contract. Byte and code-unit identity, reversible
//! interchange encoding, escaped display that is never identity.

use ghosttrace_core::domain::path::{NativePath, NativePathDecodeError};

#[test]
fn unix_byte_paths_round_trip_reversibly() {
    let path = NativePath::unix(vec![b'a', b'/', 0x80, 0xff, b'/', 0x1b, 0x01]);
    let wire = serde_json::to_string(&path).unwrap();
    let back: NativePath = serde_json::from_str(&wire).unwrap();
    assert_eq!(path, back);
}

#[test]
fn windows_utf16_paths_round_trip_reversibly() {
    let path = NativePath::windows(vec![0x0043, 0x003a, 0x005c, 0xD83D, 0xDE00, 0x0061]);
    let wire = serde_json::to_string(&path).unwrap();
    let back: NativePath = serde_json::from_str(&wire).unwrap();
    assert_eq!(path, back);
}

#[test]
fn invalid_utf8_names_are_distinct_despite_display_collision() {
    let first = NativePath::unix(vec![b'r', b'e', b'p', 0xff]);
    let second = NativePath::unix(vec![b'r', b'e', b'p', 0xfe]);
    assert_ne!(first, second);
    assert_eq!(first.display(), second.display());
}

#[test]
fn display_must_not_become_identity() {
    let unix = NativePath::unix("docs/report.txt".as_bytes().to_vec());
    let windows: NativePath =
        NativePath::windows("docs/report.txt".encode_utf16().collect::<Vec<u16>>());
    assert_ne!(unix, windows, "platform-tagged identity differs");
    let unix_again = NativePath::unix("docs/report.txt".as_bytes().to_vec());
    assert_eq!(unix, unix_again);
}

#[test]
fn control_characters_never_reach_a_terminal_unescaped() {
    let path = NativePath::unix(vec![b'a', 0x1b, b'[', b'2', b'J', 0x07]);
    let display = path.display();
    assert!(!display.contains('\u{1b}'));
    assert!(!display.contains('\u{07}'));
}

#[test]
fn malformed_encodings_are_rejected_not_guessed() {
    let error: Result<NativePath, _> = serde_json::from_str(r#"{"kind":"unix","encoded":"a%G0"}"#);
    assert!(error.is_err());
    let unknown_kind: Result<NativePath, _> =
        serde_json::from_str(r#"{"kind":"plan9","encoded":"a"}"#);
    assert!(unknown_kind.is_err());
}

#[test]
fn decode_error_is_an_invalid_request() {
    let path_error = NativePathDecodeError::UnknownKind("plan9".into());
    let core: ghosttrace_core::CoreError = path_error.into();
    assert_eq!(core.code(), "invalid_request");
    assert!(core.to_string().contains("native_path"));
}

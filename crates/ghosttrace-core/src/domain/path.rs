//! Lossless native path representation (plan Section 6, P1.1).
//!
//! Rules embodied here:
//! - Unix paths are bytes; Windows paths are UTF-16 code units. Byte/case/
//!   Unicode-normalization differences never silently merge identities.
//! - A reversible encoded form exists for interchange (JSON, manifests).
//! - The escaping display form is for humans only and is never identity: two
//!   distinct invalid-byte names may display alike and still compare unequal.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A native filesystem path, kept exactly as observed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "NativePathWire", into = "NativePathWire")]
pub enum NativePath {
    /// Unix path as raw bytes.
    Unix(Vec<u8>),
    /// Windows path as native UTF-16 code units.
    Windows(Vec<u16>),
}

/// Serialized interchange form: a kind tag plus the reversible encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativePathWire {
    pub kind: String,
    pub encoded: String,
}

impl NativePath {
    pub fn unix(bytes: impl Into<Vec<u8>>) -> Self {
        NativePath::Unix(bytes.into())
    }

    pub fn windows(units: impl Into<Vec<u16>>) -> Self {
        NativePath::Windows(units.into())
    }

    /// Reversible, ASCII-only interchange encoding.
    ///
    /// Unix: percent-encoding of unsafe bytes (`%` itself included).
    /// Windows: `%U....` per code unit, lowercase hex for consistency.
    pub fn encoded(&self) -> String {
        match self {
            NativePath::Unix(bytes) => {
                let mut out = String::new();
                for byte in bytes {
                    match byte {
                        b'0'..=b'9'
                        | b'a'..=b'z'
                        | b'A'..=b'Z'
                        | b'-'
                        | b'.'
                        | b'_'
                        | b'~'
                        | b'/' => out.push(char::from(*byte)),
                        other => out.push_str(&format!("%{other:02X}")),
                    }
                }
                out
            }
            NativePath::Windows(units) => {
                let mut out = String::new();
                for unit in units {
                    if u8::try_from(*unit).is_ok_and(|b| b.is_ascii_alphanumeric()) {
                        out.push(char::from(*unit as u8));
                    } else {
                        out.push_str(&format!("%u{unit:04X}"));
                    }
                }
                out
            }
        }
    }

    /// Human-readable display form. Control characters are escaped so evidence
    /// can never emit terminal sequences. Lossy: invented bytes become U+FFFD.
    pub fn display(&self) -> String {
        let escaped = |text: &str| -> String {
            let mut out = String::with_capacity(text.len());
            for ch in text.chars() {
                match ch {
                    c if (c as u32) < 0x20 || c == '\u{7f}' => {
                        out.push_str(&format!("\\x{:02x}", c as u32))
                    }
                    c => out.push(c),
                }
            }
            out
        };
        match self {
            NativePath::Unix(bytes) => escaped(&String::from_utf8_lossy(bytes)),
            NativePath::Windows(units) => escaped(&String::from_utf16_lossy(units)),
        }
    }

    /// Final component for coarse grouping, display-only.
    pub fn display_file_name(&self) -> String {
        let text = self.display();
        let cut = text.rfind('/').map(|i| i + 1).unwrap_or(0);
        text[cut..].to_string()
    }
}

impl fmt::Display for NativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

impl TryFrom<NativePathWire> for NativePath {
    type Error = NativePathDecodeError;

    fn try_from(wire: NativePathWire) -> Result<Self, Self::Error> {
        let NativePathWire { kind, encoded } = wire;
        let decoded = match kind.as_str() {
            "unix" => decode_percent_bytes(&encoded).map(NativePath::Unix),
            "windows" => decode_percent_units(&encoded).map(NativePath::Windows),
            _ => None,
        };
        let Some(path) = decoded else {
            return Err(match kind.as_str() {
                "unix" | "windows" => NativePathDecodeError::MalformedEncoding(encoded),
                _ => NativePathDecodeError::UnknownKind(kind),
            });
        };
        Ok(path)
    }
}

impl From<NativePath> for NativePathWire {
    fn from(path: NativePath) -> Self {
        let kind = match &path {
            NativePath::Unix(_) => "unix",
            NativePath::Windows(_) => "windows",
        };
        NativePathWire {
            kind: kind.to_string(),
            encoded: path.encoded(),
        }
    }
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

fn decode_percent_bytes(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            out.push(hex_value(high)? << 4 | hex_value(low)?);
            index += 3;
        } else if bytes[index].is_ascii() {
            out.push(bytes[index]);
            index += 1;
        } else {
            // The interchange form is ASCII by construction. A non-ASCII
            // character here is malformed, not a byte to copy: copying its
            // UTF-8 bytes would invent a path that was never encoded.
            return None;
        }
    }
    Some(out)
}

fn decode_percent_units(input: &str) -> Option<Vec<u16>> {
    let chars: Vec<char> = input.chars().collect();
    let mut out = Vec::with_capacity(chars.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '%' {
            let tag = *chars.get(index + 1)?;
            if tag != 'u' {
                return None;
            }
            let mut unit: u32 = 0;
            for offset in 2..6 {
                let digit = *chars.get(index + offset)?;
                let digit = u32::from(hex_value(digit as u8)?);
                unit = unit * 16 + digit;
            }
            out.push(u16::try_from(unit).ok()?);
            index += 6;
        } else if chars[index].is_ascii_alphanumeric() {
            out.push(chars[index] as u16);
            index += 1;
        } else {
            // Only ASCII alphanumerics are emitted literally; anything else
            // must be a `%uXXXX` escape. Casting an arbitrary char would
            // truncate it silently.
            return None;
        }
    }
    Some(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativePathDecodeError {
    UnknownKind(String),
    MalformedEncoding(String),
}

impl fmt::Display for NativePathDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NativePathDecodeError::UnknownKind(kind) => {
                write!(f, "unknown native path kind: {kind}")
            }
            NativePathDecodeError::MalformedEncoding(encoded) => {
                write!(f, "malformed native path encoding: {encoded}")
            }
        }
    }
}

impl std::error::Error for NativePathDecodeError {}

impl From<NativePathDecodeError> for crate::error::CoreError {
    fn from(error: NativePathDecodeError) -> Self {
        crate::error::CoreError::InvalidInput(format!("native_path: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_bytes_round_trip_through_encoding() {
        let path = NativePath::unix(vec![b'd', b'o', b'c', 0xff, 0xfe, b'/', 0x01]);
        let encoded = path.encoded();
        let decoded: NativePath = NativePathWire {
            kind: "unix".into(),
            encoded,
        }
        .try_into()
        .expect("reversible");
        assert_eq!(path, decoded);
    }

    #[test]
    fn windows_units_round_trip_through_encoding() {
        let path = NativePath::windows(vec![0x0043, 0x003a, 0x0000, 0xD83D, 0xDE00]);
        let wire: NativePathWire = path.clone().into();
        let decoded: NativePath = wire.try_into().expect("reversible");
        assert_eq!(path, decoded);
    }

    #[test]
    fn invalid_utf8_names_stay_distinct_despite_display_collision() {
        let first = NativePath::unix(vec![b'a', 0xff, b'b']);
        let second = NativePath::unix(vec![b'a', 0xfe, b'b']);
        assert_ne!(first, second, "identity must be byte-exact");
        assert_eq!(first.display(), second.display(), "display may collide");
        assert_eq!(first.display_file_name(), "a\u{fffd}b");
    }

    #[test]
    fn unicode_distinct_identities_survive_round_trip() {
        let first = NativePath::unix("café.txt".as_bytes().to_vec());
        let second = NativePath::unix("cafe\u{301}.txt".as_bytes().to_vec());
        assert_ne!(
            first, second,
            "no Unicode normalization may merge identities"
        );
        let wire_first: NativePathWire = first.clone().into();
        let decoded: NativePath = wire_first.try_into().expect("reversible");
        assert_eq!(first, decoded);
    }

    #[test]
    fn control_characters_are_escaped_in_display() {
        let path = NativePath::unix(vec![b'l', b'o', b'g', 0x1b, b'[', b'3', b'1', b'm']);
        let display = path.display();
        assert!(
            !display.contains('\u{1b}'),
            "ESC must be escaped: {display}"
        );
        assert!(display.contains("\\x1b"), "escape form: {display}");
    }

    #[test]
    fn percent_is_reversible_not_identity() {
        let literal_percent = NativePath::unix(vec![b'a', b'%', b'b']);
        let encoded_a = NativePath::unix(vec![b'a', b'%', b'4', b'1', b'b']);
        assert_eq!(literal_percent.encoded(), "a%25b");
        assert_eq!(encoded_a.encoded(), "a%2541b");
        let wire: NativePathWire = literal_percent.clone().into();
        let decoded: NativePath = wire.try_into().expect("reversible");
        assert_eq!(literal_percent, decoded);
    }

    #[test]
    fn decoding_reports_malformed_input() {
        let error = <NativePath as TryFrom<NativePathWire>>::try_from(NativePathWire {
            kind: "unix".into(),
            encoded: "a%zz".into(),
        })
        .unwrap_err();
        assert!(matches!(error, NativePathDecodeError::MalformedEncoding(_)));
    }
}

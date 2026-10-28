//! Display escaping for recorded text (plan Section 10, P6.2).
//!
//! Evidence is shown, never executed. Control characters, escape sequences,
//! and bidirectional overrides are rendered as visible escapes so a record
//! cannot move the cursor, recolor the interface, or spoof a path. The same
//! function bounds the preview: a huge record is truncated at a character
//! boundary with an explicit `truncated` flag instead of being cut silently.

/// Default preview bound for one raw record shown in the inspector.
pub const MAX_PREVIEW_BYTES: usize = 64 * 1024;

/// Escape control and bidi characters and stop at `max_bytes` of output.
///
/// Returns `(text, truncated)`. Newlines and tabs stay readable; everything
/// else non-printable becomes an escape sequence.
pub fn escape_for_display(text: &str, max_bytes: usize) -> (String, bool) {
    let mut out = String::with_capacity(text.len().min(max_bytes));
    for ch in text.chars() {
        let escaped = if ch == '\n' || ch == '\t' {
            ch.to_string()
        } else if ch.is_control() || is_bidi_control(ch) {
            ch.escape_default().to_string()
        } else {
            ch.to_string()
        };
        if out.len() + escaped.len() > max_bytes {
            return (out, true);
        }
        out.push_str(&escaped);
    }
    (out, false)
}

fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_and_bidi_characters_are_visible() {
        let (text, truncated) = escape_for_display("a\u{1b}[31mred\u{202e}txt", 1024);
        assert!(!truncated);
        assert_eq!(text, "a\\u{1b}[31mred\\u{202e}txt");
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains('\u{202e}'));
    }

    #[test]
    fn newlines_and_tabs_stay_readable() {
        let (text, truncated) = escape_for_display("line\n\tindent", 1024);
        assert!(!truncated);
        assert_eq!(text, "line\n\tindent");
    }

    #[test]
    fn truncation_is_explicit_and_lands_on_a_character_boundary() {
        let (text, truncated) = escape_for_display("éééé", 5);
        assert!(truncated);
        assert_eq!(text, "éé");
        assert!(text.len() <= 5);
    }
}

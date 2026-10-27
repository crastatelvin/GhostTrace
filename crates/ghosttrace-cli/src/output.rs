//! Terminal-safe output (plan Section 9): machine JSON on stdout, human
//! progress on stderr, and no raw evidence control sequences ever.

use serde::Serialize;

/// Emit one JSON line on stdout. Machine output is never ANSI-decorated.
pub fn emit_json<T: Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(text) => println!("{text}"),
        Err(error) => eprintln!(
            "{{\"error\":\"internal\",\"message\":\"serialize: {}\"}}",
            escape(&error.to_string())
        ),
    }
}

/// Emit a stable error object on stderr. Messages are operational only; the
/// escaping keeps a hostile path or OS string from emitting terminal control.
pub fn emit_error(code: &str, message: &str) {
    eprintln!(
        "{{\"error\":\"{}\",\"message\":\"{}\"}}",
        escape(code),
        escape(message)
    );
}

/// Progress belongs on stderr so stdout stays pipe-safe.
pub fn emit_progress(bytes: u64, objects: u64) {
    eprintln!("progress: {bytes} bytes copied, {objects} objects published");
}

/// Escape control characters (including C1) so display never moves the cursor.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            c if (c as u32) < 0x20 || (0x7f..=0x9f).contains(&(c as u32)) => {
                out.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

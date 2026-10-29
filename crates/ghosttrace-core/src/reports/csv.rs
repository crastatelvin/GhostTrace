//! Spreadsheet-safe CSV projection of a report (plan Section 12; P9.2).
//!
//! CSV is the format a spreadsheet opens by default, and a spreadsheet treats
//! some leading characters as formulas. This projection therefore neutralizes
//! them explicitly:
//!
//! - `\r`, `\n`, `\t`, and every other C0/C1 control character is replaced by
//!   its visible `\u{...}` escape, so a cell can never span lines or start with
//!   an invisible tab;
//! - a cell whose first non-space character is `=`, `+`, `-`, or `@` gets a
//!   leading apostrophe, so the spreadsheet shows text instead of evaluating
//!   it;
//! - cells containing a comma, quote, or apostrophe are quoted with `"` and
//!   embedded quotes doubled, per RFC 4180.
//!
//! These are projection transformations, not fidelity claims. The JSON report
//! keeps every value byte-for-byte; the CSV is for reading in a spreadsheet.

use chrono::{DateTime, SecondsFormat, Utc};

use crate::reports::ReportV1;

/// A note a consumer can print beside the CSV.
pub const CSV_NOTE: &str = "CSV is a spreadsheet-safe projection: control characters are escaped and formula-leading \
cells are prefixed with an apostrophe. The JSON report keeps exact values.";

/// Escape controls and neutralize formula-leading cells. The result is one
/// line with no invisible leading whitespace.
pub fn neutralize(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\r' => escaped.push_str("\\u{d}"),
            '\n' => escaped.push_str("\\u{a}"),
            '\t' => escaped.push_str("\\u{9}"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{{{:x}}}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    let trimmed = escaped.trim_start_matches(' ');
    if trimmed.starts_with(['=', '+', '-', '@']) {
        return format!("'{escaped}");
    }
    escaped
}

/// Quote one already-neutralized cell for RFC 4180.
pub fn quote(cell: &str) -> String {
    if cell.contains([',', '"', '\n', '\r', '\'']) {
        format!("\"{}\"", cell.replace('"', "\"\""))
    } else {
        cell.to_string()
    }
}

fn cell(value: &str) -> String {
    quote(&neutralize(value))
}

/// Render the timeline as CSV. Times are UTC; an unresolved time is empty and
/// the `time_status` column says why.
pub fn timeline_csv(report: &ReportV1) -> String {
    let mut out =
        String::from("event_id,source,kind,summary,host_claim,chosen_time_utc,time_status\n");
    for row in &report.timeline {
        let chosen = row.chosen_seconds.and_then(|seconds| {
            DateTime::<Utc>::from_timestamp(seconds, row.chosen_nanos.max(0) as u32)
                .map(|time| time.to_rfc3339_opts(SecondsFormat::AutoSi, true))
        });
        out.push_str(
            &[
                cell(&row.event_id),
                cell(&row.source),
                cell(&row.kind),
                cell(&row.summary),
                cell(row.host_claim.as_deref().unwrap_or("")),
                cell(chosen.as_deref().unwrap_or("")),
                cell(&row.time_status),
            ]
            .join(","),
        );
        out.push('\n');
    }
    out
}

/// Render stored objects as CSV (path, digest, length).
pub fn objects_csv(report: &ReportV1) -> String {
    let mut out = String::from("path,sha256,byte_length\n");
    for object in &report.objects {
        out.push_str(
            &[
                cell(&object.path),
                cell(&object.sha256),
                object.byte_length.to_string(),
            ]
            .join(","),
        );
        out.push('\n');
    }
    out
}

//! Self-contained HTML report rendering (plan Sections 9, 12; P3.2).
//!
//! No scripts, no remote resources, no links. Every value is escaped for HTML
//! and control/bidi characters are rendered as visible `\u{...}` escapes, so
//! a hostile file name stays inert *and* readable.

use std::fmt::Write;

use super::{REPORT_FORMAT, ReportV1};

/// Render the report as one self-contained HTML document.
pub fn render(report: &ReportV1) -> String {
    let mut out = String::with_capacity(16 * 1024);
    out.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    let _ = writeln!(
        out,
        "<title>GhostTrace report — {}</title>",
        escape(&report.case.label)
    );
    out.push_str("<style>\n:root{color-scheme:light dark}body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:72rem;padding:0 1rem;line-height:1.45}h1{margin-bottom:.2rem}h2{margin-top:2rem;border-bottom:1px solid #8884;padding-bottom:.3rem}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border:1px solid #8884;padding:.35rem .5rem;text-align:left;vertical-align:top}th{background:#8881}code,td.path{font-family:ui-monospace,monospace;word-break:break-all}.meta{color:#666}.warn{border-left:4px solid #c80;padding-left:.75rem}ul{margin-top:.4rem}caption{caption-side:top;text-align:left;padding:.3rem 0;font-weight:600}\n</style>\n</head>\n<body>\n");
    out.push_str("<h1>GhostTrace report</h1>\n");
    let _ = writeln!(
        out,
        "<p class=\"meta\">Format <code>{}</code> · report <code>{}</code> · generated <time>{}</time> by <code>{}</code></p>",
        escape(REPORT_FORMAT),
        escape(&report.report_id),
        escape(&report.created_utc),
        escape(&report.tool_version)
    );

    out.push_str("<h2>Case</h2>\n<table>\n<tbody>\n");
    row(&mut out, "Case label", &report.case.label);
    row(&mut out, "Case ID", &report.case.case_id);
    row(&mut out, "Display timezone", &report.case.display_timezone);
    out.push_str("</tbody>\n</table>\n");

    out.push_str("<h2>Acquisition</h2>\n<table>\n<tbody>\n");
    row(&mut out, "Acquisition ID", &report.acquisition.id);
    row(&mut out, "Method", &report.acquisition.method);
    row(
        &mut out,
        "Claimed source",
        &report.acquisition.claimed_source,
    );
    row(&mut out, "State", &report.acquisition.state);
    row(&mut out, "Link policy", &report.acquisition.link_policy);
    row(
        &mut out,
        "Started",
        &report
            .acquisition
            .started_seconds
            .map(format_seconds)
            .unwrap_or_else(|| "not recorded".to_string()),
    );
    row(
        &mut out,
        "Ended",
        &report
            .acquisition
            .ended_seconds
            .map(format_seconds)
            .unwrap_or_else(|| "not recorded".to_string()),
    );
    out.push_str("</tbody>\n</table>\n");
    if !report.acquisition.roots.is_empty() {
        out.push_str("<h3>Roots</h3>\n<ul>\n");
        for root in &report.acquisition.roots {
            let _ = writeln!(out, "<li class=\"path\"><code>{}</code></li>", escape(root));
        }
        out.push_str("</ul>\n");
    }

    let coverage = &report.coverage;
    out.push_str("<h2>Coverage</h2>\n<table>\n<caption>Every observed path has a status; gaps are listed, never assumed absent.</caption>\n<thead><tr><th>Status</th><th>Count</th></tr></thead>\n<tbody>\n");
    for (status, count) in [
        ("captured", coverage.captured),
        ("excluded", coverage.excluded),
        ("inaccessible", coverage.inaccessible),
        ("unstable", coverage.unstable),
        ("vanished", coverage.vanished),
        ("unsupported", coverage.unsupported),
        ("unobserved", coverage.unobserved),
    ] {
        let _ = writeln!(out, "<tr><td>{status}</td><td>{count}</td></tr>");
    }
    out.push_str("</tbody>\n</table>\n");

    if !coverage.gaps.is_empty() {
        out.push_str("<table>\n<caption>Gaps (bounded sample; the complete ledger is in the case)</caption>\n<thead><tr><th>Path</th><th>Status</th><th>Code</th></tr></thead>\n<tbody>\n");
        for gap in &coverage.gaps {
            let _ = writeln!(
                out,
                "<tr><td class=\"path\"><code>{}</code></td><td>{}</td><td><code>{}</code></td></tr>",
                escape(&gap.path),
                escape(&gap.status),
                escape(&gap.code)
            );
        }
        out.push_str("</tbody>\n</table>\n");
        if !coverage.gaps_complete {
            out.push_str("<p class=\"warn\">Gap list truncated for this report; the case holds the complete ledger.</p>\n");
        }
    }

    out.push_str("<h2>Captured objects</h2>\n");
    if report.objects.is_empty() {
        out.push_str("<p>No content objects were captured in this acquisition.</p>\n");
    } else {
        out.push_str("<table>\n<caption>Each path's stored copy is identified by its full SHA-256.</caption>\n<thead><tr><th>Path</th><th>Bytes</th><th>SHA-256</th></tr></thead>\n<tbody>\n");
        for object in &report.objects {
            let _ = writeln!(
                out,
                "<tr><td class=\"path\"><code>{}</code></td><td>{}</td><td><code>{}</code></td></tr>",
                escape(&object.path),
                object.byte_length,
                escape(&object.sha256)
            );
        }
        out.push_str("</tbody>\n</table>\n");
    }

    out.push_str("<h2>Timeline</h2>\n");
    if report.timeline.is_empty() {
        out.push_str("<p>No events recorded for this acquisition.</p>\n");
    } else {
        out.push_str("<table>\n<caption>Application-clock capture events; unresolved times stay separate.</caption>\n<thead><tr><th>Time (UTC)</th><th>Kind</th><th>Source</th><th>Summary</th><th>Host claim</th><th>Status</th></tr></thead>\n<tbody>\n");
        for event in &report.timeline {
            let time = event
                .chosen_seconds
                .and_then(|seconds| {
                    chrono::DateTime::from_timestamp(seconds, event.chosen_nanos as u32)
                        .map(|instant| instant.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                })
                .unwrap_or_else(|| "unresolved".to_string());
            let _ = writeln!(
                out,
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(&time),
                escape(&event.kind),
                escape(&event.source),
                escape(&event.summary),
                escape(event.host_claim.as_deref().unwrap_or("")),
                escape(&event.time_status)
            );
        }
        out.push_str("</tbody>\n</table>\n");
    }

    out.push_str("<h2>Provenance</h2>\n<table>\n<tbody>\n");
    row(&mut out, "Generated by", &report.provenance.generated_by);
    row(&mut out, "Tool version", &report.provenance.tool_version);
    row(&mut out, "Method", &report.provenance.method);
    row(
        &mut out,
        "Claimed source",
        &report.provenance.claimed_source,
    );
    row(&mut out, "Link policy", &report.provenance.link_policy);
    row(
        &mut out,
        "Signed",
        if report.provenance.signed {
            "yes"
        } else {
            "no"
        },
    );
    row(
        &mut out,
        "Timeline selection",
        &report.provenance.timeline_selection,
    );
    out.push_str("</tbody>\n</table>\n");

    out.push_str("<h2>Limitations</h2>\n<ul class=\"warn\">\n");
    for limitation in &report.limitations {
        let _ = writeln!(out, "<li>{}</li>", escape(limitation));
    }
    out.push_str("</ul>\n</body>\n</html>\n");
    out
}

fn row(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(
        out,
        "<tr><th scope=\"row\">{}</th><td>{}</td></tr>",
        escape(label),
        escape(value)
    );
}

fn format_seconds(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|instant| instant.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| seconds.to_string())
}

/// Escape HTML metacharacters and render control/bidi characters visibly.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if is_unsafe_control(c) => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn is_unsafe_control(ch: char) -> bool {
    let code = ch as u32;
    (code < 0x20)
        || (0x7f..=0x9f).contains(&code)
        || matches!(code,
            0x061c | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x2064
            | 0x2066..=0x206f | 0xfeff)
}

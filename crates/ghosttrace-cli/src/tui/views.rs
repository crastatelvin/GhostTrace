//! Terminal rendering for the TUI (plan P7).
//!
//! Every evidence-derived string goes through
//! `ghosttrace_core::text::escape_for_display` before it reaches the terminal,
//! so OSC/CSI/control bytes in a log can never act on the operator's terminal.
//! Meaning is carried by text and modifiers, never by colour alone.

use ghosttrace_core::text::escape_for_display;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table, Wrap};

use super::state::{Mode, TuiState, View, describe_filters};

/// Bound for one rendered evidence value. Longer values are explicitly marked
/// truncated by `escape_for_display`.
const FIELD_LIMIT: usize = 240;

pub fn draw(frame: &mut Frame, state: &mut TuiState) {
    let [header, body, detail, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(10),
        Constraint::Length(2),
    ])
    .areas(frame.area());

    frame.render_widget(Paragraph::new(header_line(state)), header);
    match state.view {
        View::Timeline => draw_timeline(frame, body, state),
        View::Findings => draw_findings(frame, body, state),
        View::Help => draw_help(frame, body),
    }
    if state.view == View::Help {
        frame.render_widget(
            Paragraph::new("The timeline and its detail pane are unchanged; Esc or ? returns.")
                .block(Block::bordered().title("Help")),
            detail,
        );
    } else {
        frame.render_widget(
            Paragraph::new(detail_text(state))
                .block(Block::bordered().title(detail_title(state)))
                .wrap(Wrap { trim: false }),
            detail,
        );
    }
    draw_footer(frame, footer, state);
}

fn header_line(state: &TuiState) -> Line<'static> {
    let view = match state.view {
        View::Timeline => "timeline",
        View::Findings => "findings",
        View::Help => "help",
    };
    let revision = if state.revision.is_empty() {
        "no parse run".to_string()
    } else {
        short(&state.revision, 20)
    };
    Line::from(format!(
        "GhostTrace · {} · revision {} · time zone {} · {}",
        cell(&state.case_label, FIELD_LIMIT),
        revision,
        cell(&state.display_timezone, 64),
        view
    ))
}

fn draw_timeline(frame: &mut Frame, area: ratatui::layout::Rect, state: &mut TuiState) {
    let block = Block::bordered().title(format!(
        "Timeline · page {}{}{}",
        state.page,
        if state.search.is_empty() {
            String::new()
        } else {
            format!(" · search {:?}", state.search)
        },
        if state.query.unresolved_only {
            " · unresolved only"
        } else {
            ""
        }
    ));
    if state.rows.is_empty() {
        frame.render_widget(
            Paragraph::new(
                "No events match this view. Press / to search, f for filters, u for unresolved, \
                 or a to analyze the active revision.",
            )
            .block(block),
            area,
        );
        return;
    }
    let rows = state.rows.iter().map(|row| {
        Row::new(vec![
            Cell::from(time_text(state, row.chosen_seconds, row.chosen_nanos)),
            Cell::from(cell(&row.kind, FIELD_LIMIT)),
            Cell::from(
                row.host_claim
                    .as_deref()
                    .map(|host| cell(host, FIELD_LIMIT))
                    .unwrap_or_default(),
            ),
            Cell::from(cell(&row.summary, FIELD_LIMIT)),
        ])
    });
    let header = Row::new(vec!["Time", "Kind", "Host", "Summary"])
        .style(Style::default().add_modifier(Modifier::BOLD));
    let table = Table::new(
        rows,
        [
            Constraint::Length(19),
            Constraint::Length(16),
            Constraint::Length(14),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .block(block)
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol("> ");
    state.table.select(Some(state.selected));
    frame.render_stateful_widget(table, area, &mut state.table);
}

fn draw_findings(frame: &mut Frame, area: ratatui::layout::Rect, state: &mut TuiState) {
    let block = Block::bordered().title(format!(
        "Findings · {} · run {}",
        state.findings.len(),
        state
            .findings_run
            .as_deref()
            .map(|run| short(run, 20))
            .unwrap_or_else(|| "not run".into())
    ));
    if state.findings.is_empty() {
        frame.render_widget(
            Paragraph::new(
                "No findings loaded. Press a to run the five compiled rules against the active \
                 revision; an empty result stays empty instead of being filled in.",
            )
            .block(block),
            area,
        );
        return;
    }
    let rows = state.findings.iter().map(|finding| {
        Row::new(vec![
            Cell::from(finding.severity.as_str().to_string()),
            Cell::from(cell(&finding.rule_id, FIELD_LIMIT)),
            Cell::from(finding.disposition.as_str().to_string()),
            Cell::from(cell(&finding.rationale, FIELD_LIMIT)),
        ])
    });
    let header = Row::new(vec!["Severity", "Rule", "Disposition", "Rationale"])
        .style(Style::default().add_modifier(Modifier::BOLD));
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(26),
            Constraint::Length(12),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .block(block)
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol("> ");
    state.findings_table.select(Some(state.findings_selected));
    frame.render_stateful_widget(table, area, &mut state.findings_table);
}

fn draw_help(frame: &mut Frame, area: ratatui::layout::Rect) {
    let text = Text::from(vec![
        Line::from(Span::styled(
            "Keys (always shown at the bottom)",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("  j/k, Up/Down      move the selection"),
        Line::from("  PgUp/PgDn, J/K    move ten rows"),
        Line::from("  g/G, Home/End     first or last row"),
        Line::from("  n / p             next or previous page"),
        Line::from("  /                 search (same grammar as `ghosttrace search`)"),
        Line::from("  f                 filters: kind= host= source= after= before="),
        Line::from("  u                 toggle the unresolved-time view"),
        Line::from("  a                 analyze the active revision (five compiled rules)"),
        Line::from("  Tab               switch timeline and findings"),
        Line::from("  ?                 this help"),
        Line::from("  q, Ctrl+C         quit"),
        Line::from(""),
        Line::from(
            "Filter values are exact and cannot contain spaces. after/before take RFC 3339 \
             instants. Evidence text is escaped before it reaches the terminal.",
        ),
    ]);
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::bordered().title("Help"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn detail_title(state: &TuiState) -> &'static str {
    match state.view {
        View::Timeline => "Event detail",
        View::Findings => "Finding",
        View::Help => "Help",
    }
}

fn detail_text(state: &TuiState) -> Text<'static> {
    match state.view {
        View::Findings => finding_text(state),
        _ => event_text(state),
    }
}

fn event_text(state: &TuiState) -> Text<'static> {
    let Some(detail) = &state.detail else {
        return Text::from("No event selected.");
    };
    let row = &detail.event;
    let mut lines = vec![
        Line::from(format!(
            "{} · {} · host {}",
            time_text(state, row.chosen_seconds, row.chosen_nanos),
            cell(&row.kind, FIELD_LIMIT),
            row.host_claim
                .as_deref()
                .map(|host| cell(host, FIELD_LIMIT))
                .unwrap_or_else(|| "not recorded".into())
        )),
        Line::from(format!(
            "event {} · parser {} {} · source link: {} · time status {}",
            short(&row.event_id, 24),
            cell(&detail.parser_id, FIELD_LIMIT),
            cell(&detail.parser_version, 32),
            if detail.source_linked {
                "recorded"
            } else {
                "not recorded (raw record cannot be re-read)"
            },
            cell(&row.time_status, 64)
        )),
        Line::from(""),
        heading("Observations"),
    ];
    if detail.observations.is_empty() {
        lines.push(Line::from("  none recorded"));
    }
    for observation in detail.observations.iter().take(5) {
        lines.push(Line::from(format!(
            "  {} · {}:{} · {}",
            cell(&observation.evidence_path, FIELD_LIMIT),
            cell(&observation.locator_kind, 32),
            cell(&observation.locator_identity, 96),
            cell(&observation.raw_fields_json, FIELD_LIMIT)
        )));
    }
    if detail.observations.len() > 5 {
        lines.push(Line::from(format!(
            "  … {} more observation(s)",
            detail.observations.len() - 5
        )));
    }
    lines.push(heading("Times"));
    if detail.times.is_empty() {
        lines.push(Line::from("  none recorded"));
    }
    for time in detail.times.iter().take(4) {
        lines.push(Line::from(format!(
            "  {} [{}] {} · candidates {} · assumptions {}",
            cell(&time.name, 48),
            cell(&time.status, 32),
            cell(&time.epoch, 32),
            cell(&time.candidates_json, 120),
            cell(&time.assumptions_json, 120)
        )));
    }
    if !detail.entities.is_empty() {
        lines.push(heading("Entities"));
        for entity in detail.entities.iter().take(4) {
            lines.push(Line::from(format!(
                "  {} {} ({})",
                cell(&entity.kind, 32),
                cell(&entity.display_form, FIELD_LIMIT),
                cell(&entity.role, 32)
            )));
        }
    }
    if !detail.run_diagnostics.is_empty() {
        lines.push(heading("Run diagnostics"));
        for diagnostic in detail.run_diagnostics.iter().take(3) {
            lines.push(Line::from(format!(
                "  {} · {} · {}",
                cell(&diagnostic.code, 64),
                cell(&diagnostic.locator, 96),
                cell(&diagnostic.detail, FIELD_LIMIT)
            )));
        }
    }
    Text::from(lines)
}

fn finding_text(state: &TuiState) -> Text<'static> {
    let Some(finding) = state.selected_finding() else {
        return Text::from("No finding selected. Press a to analyze the active revision.");
    };
    let mut lines = vec![
        Line::from(format!(
            "{} · {} {} · {}",
            cell(&finding.rule_id, FIELD_LIMIT),
            cell(&finding.rule_version, 32),
            finding.severity.as_str(),
            finding.disposition.as_str()
        )),
        Line::from(format!(
            "finding {} · analysis run {}",
            short(&finding.id, 24),
            short(&finding.analysis_run_id, 24)
        )),
        Line::from(""),
        heading("Rationale"),
        Line::from(format!("  {}", cell(&finding.rationale, 900))),
        heading("Alternatives that remain plausible"),
    ];
    if finding.alternatives.is_empty() {
        lines.push(Line::from("  none recorded"));
    }
    for alternative in finding.alternatives.iter().take(4) {
        lines.push(Line::from(format!("  - {}", cell(alternative, 400))));
    }
    lines.push(heading("Recorded predicates"));
    lines.push(Line::from(format!(
        "  {}",
        cell(&finding.predicates.to_string(), 900)
    )));
    lines.push(heading("Supporting events"));
    for event in finding.event_ids.iter().take(5) {
        lines.push(Line::from(format!("  {}", short(event, 40))));
    }
    if finding.event_ids.len() > 5 {
        lines.push(Line::from(format!(
            "  … {} more event(s)",
            finding.event_ids.len() - 5
        )));
    }
    Text::from(lines)
}

fn draw_footer(frame: &mut Frame, area: ratatui::layout::Rect, state: &TuiState) {
    let [status, keys] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    let status_line = match state.mode {
        Mode::Browse => {
            let prefix = if state.status_is_error { "error: " } else { "" };
            Line::from(format!("{prefix}{}", state.status))
        }
        Mode::Search => Line::from(format!("Search: {}_", state.draft)),
        Mode::Filters => {
            let applied = describe_filters(&state.filters);
            Line::from(format!(
                "Filters: {}_  (kind= host= source= after= before={})",
                state.draft,
                if applied.is_empty() {
                    String::new()
                } else {
                    format!("; applied: {applied}")
                }
            ))
        }
    };
    let style = if state.status_is_error && state.mode == Mode::Browse {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    frame.render_widget(Paragraph::new(status_line).style(style), status);
    frame.render_widget(
        Paragraph::new(
            "j/k move  PgUp/PgDn  n/p page  / search  f filters  u unresolved  a analyze  \
             Tab view  ? help  q quit",
        )
        .style(Style::default().add_modifier(Modifier::DIM)),
        keys,
    );
}

fn heading(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        text.to_string(),
        Style::default().add_modifier(Modifier::BOLD),
    ))
}

fn time_text(state: &TuiState, seconds: Option<i64>, nanos: u32) -> String {
    let Some(seconds) = seconds else {
        return "unresolved".into();
    };
    let Some(instant) = chrono::DateTime::from_timestamp(seconds, nanos) else {
        return format!("unrepresentable ({seconds})");
    };
    match state.display_timezone.parse::<chrono_tz::Tz>() {
        Ok(zone) => instant
            .with_timezone(&zone)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
        Err(_) => instant.format("%Y-%m-%d %H:%M:%SZ").to_string(),
    }
}

/// One table/prompt cell. Unlike the detail pane, a cell is a single line:
/// a newline in evidence must not fabricate a row or a column.
fn cell(value: &str, limit: usize) -> String {
    escape_for_display(value, limit)
        .0
        .replace(['\n', '\t'], " ")
}

fn short(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        value.to_string()
    } else {
        let mut text: String = value.chars().take(limit.saturating_sub(1)).collect();
        text.push('…');
        text
    }
}

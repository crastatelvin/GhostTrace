//! Timeline screen: filters, declared histogram, virtualized event list, and
//! the provenance inspector (plan P6.2).
//!
//! Rendering only formats already-loaded state and queues requests. Every read
//! happens on the query worker; a scroll or keystroke never blocks on SQLite.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use eframe::egui;
use ghosttrace_core::analysis::views::SavedFilter;
use ghosttrace_core::domain::query::EventRow;
use ghosttrace_core::text::escape_for_display;

use crate::state::{AppState, TimelineFilters, labeled_text};

const ROW_HEIGHT: f32 = 22.0;

pub fn ui(state: &mut AppState, ui: &mut egui::Ui) {
    let theme = state.theme;
    let Some(revision) = state.timeline.revision.clone() else {
        crate::theme::title(ui, theme, "Timeline");
        crate::theme::muted(
            ui,
            theme,
            "This case has no parse run yet. Import a captured object or scan a case \
             to create a revision, then return here.",
        );
        return;
    };

    // The inspector owns the right side and is resizable.
    egui::Panel::right("ghosttrace-inspector")
        .resizable(true)
        .default_size(430.0)
        .frame(crate::theme::side_frame(ui.style(), theme))
        .show(ui, |ui| crate::evidence::ui(state, ui));

    crate::theme::title(ui, theme, "Timeline");
    crate::theme::muted(
        ui,
        theme,
        format!(
            "Revision {revision} · times shown in {} · {} event(s) matching",
            state.timeline.display_timezone,
            state
                .timeline
                .histogram
                .as_ref()
                .map_or(0, |histogram| histogram.total)
        ),
    );

    crate::theme::card(ui, theme, |ui| {
        crate::theme::section(ui, theme, "Filters");
        filters(state, ui);
        views(state, ui);
    });
    histogram(state, ui);
    crate::theme::section(ui, theme, "Events");
    event_list(state, ui);
    shortcuts(state, ui);
}

fn filters(state: &mut AppState, ui: &mut egui::Ui) {
    let theme = state.theme;
    let now = ui.input(|input| input.time);
    let mut text_changed = false;
    ui.horizontal_wrapped(|ui| {
        let search = labeled_text(ui, "Search events", &mut state.timeline.filters.text);
        state.timeline.search_id = Some(search.id);
        text_changed |= search.changed();
        text_changed |=
            labeled_text(ui, "Filter by kind", &mut state.timeline.filters.kind).changed();
        text_changed |=
            labeled_text(ui, "Filter by host", &mut state.timeline.filters.host).changed();
        text_changed |=
            labeled_text(ui, "Filter by source", &mut state.timeline.filters.source).changed();
        if ui
            .checkbox(
                &mut state.timeline.filters.unresolved_only,
                "Unresolved times only",
            )
            .changed()
        {
            state.refresh_timeline();
        }
        if crate::theme::quiet(ui, theme, "Reset filters").clicked() {
            state.timeline.filters = TimelineFilters::default();
            state.refresh_timeline();
        }
    });
    if text_changed {
        state.timeline.schedule_search(now);
    }
}

/// Saved views are typed filters over the same query contract. Applying one
/// only changes the visible filters; it never runs stored SQL.
fn views(state: &mut AppState, ui: &mut egui::Ui) {
    let theme = state.theme;
    egui::CollapsingHeader::new(format!("Saved views · {}", state.timeline.view_status))
        .default_open(false)
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                labeled_text(ui, "Saved view name", &mut state.timeline.view_name);
                if crate::theme::quiet(ui, theme, "Save current filters").clicked() {
                    state.save_current_view();
                }
                if crate::theme::quiet(ui, theme, "Reload saved views").clicked() {
                    state.reload_views();
                }
            });
            for view in state.timeline.views.clone() {
                let label = format!("Apply {} · {}", view.name, describe_filter(&view.filter));
                if crate::theme::quiet(ui, theme, &label).clicked() {
                    state.apply_view(&view.name);
                }
            }
        });
}

fn describe_filter(filter: &SavedFilter) -> String {
    let mut parts = Vec::new();
    if let Some(kind) = &filter.kind {
        parts.push(format!("kind {kind}"));
    }
    if let Some(host) = &filter.host {
        parts.push(format!("host {host}"));
    }
    if let Some(source) = &filter.source {
        parts.push(format!("source {source}"));
    }
    if let Some(text) = &filter.text {
        parts.push(format!("text {text:?}"));
    }
    if let (Some(after), Some(before)) = (filter.after_seconds, filter.before_seconds) {
        parts.push(format!("window {after}..{before} (Unix seconds)"));
    }
    if filter.unresolved_only {
        parts.push("unresolved only".into());
    }
    if parts.is_empty() {
        "all events".into()
    } else {
        parts.join(", ")
    }
}

fn histogram(state: &mut AppState, ui: &mut egui::Ui) {
    let theme = state.theme;
    let Some(histogram) = state.timeline.histogram.clone() else {
        return;
    };
    let zone = state.timeline.display_timezone.clone();
    let mut select = None;
    let mut clear = false;
    ui.add_space(crate::theme::SECTION_GAP);
    crate::theme::card(ui, theme, |ui| {
        egui::CollapsingHeader::new(format!(
            "Time histogram · {} bin(s) of {} · {} matching event(s)",
            histogram.bins.len(),
            bin_width_label(histogram.bin_seconds),
            histogram.total
        ))
        .default_open(true)
        .show(ui, |ui| {
            if histogram.unresolved_count > 0 {
                crate::theme::muted(
                    ui,
                    theme,
                    format!(
                        "{} matching event(s) have no chosen time; they cannot be placed in a \
                     window and are reported here instead of being dropped.",
                        histogram.unresolved_count
                    ),
                );
            }
            if histogram.bins.is_empty() {
                crate::theme::muted(ui, theme, "No binned events in this view.");
                return;
            }
            if (state.timeline.filters.after_seconds.is_some()
                || state.timeline.filters.before_seconds.is_some())
                && crate::theme::quiet(ui, theme, "Clear time window").clicked()
            {
                clear = true;
            }
            egui::ScrollArea::vertical()
                .max_height(160.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    for bin in &histogram.bins {
                        let selected = state.timeline.filters.after_seconds
                            == Some(bin.start_seconds)
                            && state.timeline.filters.before_seconds == Some(bin.end_seconds);
                        let label = format!(
                            "{} to {} · {} event(s)",
                            format_instant(bin.start_seconds, &zone),
                            format_instant(bin.end_seconds, &zone),
                            bin.count
                        );
                        if ui.selectable_label(selected, label).clicked() {
                            select = Some((bin.start_seconds, bin.end_seconds));
                        }
                    }
                });
        });
    });
    if clear {
        state.timeline.filters.after_seconds = None;
        state.timeline.filters.before_seconds = None;
        state.refresh_timeline();
    }
    if let Some((start, end)) = select {
        state.select_bin(start, end);
    }
}

fn event_list(state: &mut AppState, ui: &mut egui::Ui) {
    let theme = state.theme;
    let rows = state.timeline.events.clone();
    let zone = state.timeline.display_timezone.clone();
    let selected = state.timeline.selected.clone();
    let mut clicked = None;
    let mut near_end = false;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show_rows(ui, ROW_HEIGHT, rows.len(), |ui, range| {
            for index in range.clone() {
                let row = &rows[index];
                let label = row_label(row, &zone);
                if ui
                    .selectable_label(selected.as_deref() == Some(row.event_id.as_str()), label)
                    .clicked()
                {
                    clicked = Some(row.event_id.clone());
                }
            }
            near_end = range.end + 20 >= rows.len();
        });
    if let Some(event_id) = clicked {
        state.select_event(&event_id);
    }
    if near_end {
        state.load_more_timeline();
    }
    crate::theme::muted(ui, theme, state.timeline.status.clone());
}

fn shortcuts(state: &mut AppState, ui: &mut egui::Ui) {
    let theme = state.theme;
    if !ui.ctx().egui_wants_keyboard_input() {
        if ui.input(|input| input.key_pressed(egui::Key::J)) {
            state.move_selection(1);
        }
        if ui.input(|input| input.key_pressed(egui::Key::K)) {
            state.move_selection(-1);
        }
        if ui.input(|input| input.key_pressed(egui::Key::U)) {
            state.toggle_unresolved();
        }
        if ui.input(|input| input.key_pressed(egui::Key::Slash))
            && let Some(id) = state.timeline.search_id
        {
            ui.memory_mut(|memory| memory.request_focus(id));
        }
    }
    crate::theme::muted(
        ui,
        theme,
        "Keys: J/K next/previous event · U unresolved view · / search",
    );
}

/// One row, with every uncertainty stated in words rather than color.
pub fn row_label(row: &EventRow, zone: &str) -> String {
    let time = match row.chosen_seconds {
        Some(seconds) => format_instant(seconds, zone),
        None => "no chosen time".to_string(),
    };
    let host = row.host_claim.as_deref().unwrap_or("no host");
    let (mut summary, truncated) = escape_for_display(&row.summary, 512);
    if truncated {
        summary.push_str("...");
    }
    let uncertainty = match row.time_status.as_str() {
        "resolved" => "",
        "ambiguous" => " · ambiguous time",
        "unresolved" => " · unresolved time",
        "invalid" => " · invalid time",
        _ => " · unknown time status",
    };
    format!("{time} · {} · {host} · {summary}{uncertainty}", row.kind)
}

/// Format Unix seconds in the case display zone. An unknown zone or an
/// out-of-range instant is stated, never silently replaced by UTC.
pub fn format_instant(seconds: i64, zone: &str) -> String {
    let Ok(zone) = Tz::from_str(zone) else {
        return format!("{seconds} (unknown zone {zone})");
    };
    let Some(instant) = DateTime::<Utc>::from_timestamp(seconds, 0) else {
        return format!("{seconds} (outside the representable range)");
    };
    instant
        .with_timezone(&zone)
        .format("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}

fn bin_width_label(seconds: i64) -> String {
    if seconds % 86_400 == 0 {
        format!("{} day(s)", seconds / 86_400)
    } else if seconds % 3_600 == 0 {
        format!("{} hour(s)", seconds / 3_600)
    } else if seconds % 60 == 0 {
        format!("{} minute(s)", seconds / 60)
    } else {
        format!("{seconds} second(s)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instants_are_shown_in_the_declared_zone() {
        // 2026-10-27T10:00:00Z
        assert_eq!(
            format_instant(1_793_095_200, "Europe/Berlin"),
            "2026-10-27 11:00:00 CET"
        );
        assert_eq!(
            format_instant(1_793_095_200, "UTC"),
            "2026-10-27 10:00:00 UTC"
        );
        assert!(format_instant(1_793_095_200, "Not/AZone").contains("unknown zone"));
    }

    #[test]
    fn unresolved_rows_say_so_in_words() {
        let row = EventRow {
            event_id: "ev-1".into(),
            revision: "run-1".into(),
            kind: "log.record".into(),
            summary: "login failed".into(),
            host_claim: Some("host-a".into()),
            chosen_seconds: None,
            chosen_nanos: 0,
            time_status: "unresolved".into(),
        };
        let label = row_label(&row, "UTC");
        assert!(label.contains("unresolved time"), "{label}");
        assert!(!label.contains('\u{1b}'));
    }
}

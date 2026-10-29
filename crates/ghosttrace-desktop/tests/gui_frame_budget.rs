//! P10.2 GUI responsiveness measurement.
//!
//! The render pass never touches SQLite (asserted in `desktop_case_workflow`),
//! so frame cost is drawing and layout only. This test fills the timeline cache
//! to its bound and a 60-bin histogram, then times frames through the real
//! widget tree.
//!
//! Ignored by default: absolute times depend on the host, and the plan says not
//! to gate CI on noisy wall times. Run in release and record the result in
//! `docs/performance.md`:
//!
//! ```text
//! cargo test --release -p ghosttrace-desktop --test gui_frame_budget -- --ignored --nocapture
//! ```

use std::time::{Duration, Instant};

use egui_kittest::Harness;
use ghosttrace_core::domain::detail::{Histogram, HistogramBin};
use ghosttrace_core::domain::query::EventRow;
use ghosttrace_desktop::state::{AppState, Screen, TIMELINE_MAX_ROWS, TimelineState};

fn row(index: usize) -> EventRow {
    EventRow {
        event_id: format!("ev-{index:04}"),
        revision: "run-1".into(),
        kind: "log.record".into(),
        summary: format!(
            "event {index} from host-{:02} with a representative summary",
            index % 100
        ),
        host_claim: Some(format!("host-{:02}", index % 100)),
        chosen_seconds: Some(1_793_095_200 + index as i64),
        chosen_nanos: 0,
        time_status: "resolved".into(),
    }
}

fn state() -> AppState {
    let mut state = AppState::new();
    state.screen = Screen::Timeline;
    let mut timeline = TimelineState::new("UTC");
    timeline.revision = Some("run-1".into());
    timeline.events = (0..TIMELINE_MAX_ROWS).map(row).collect();
    timeline.histogram = Some(Histogram {
        bin_seconds: 3_600,
        from_seconds: 1_793_095_200,
        to_seconds: 1_793_095_200 + 60 * 3_600,
        bins: (0..60)
            .map(|index| HistogramBin {
                start_seconds: 1_793_095_200 + index * 3_600,
                end_seconds: 1_793_095_200 + (index + 1) * 3_600,
                count: (index as u64 * 17) % 1_000,
            })
            .collect(),
        unresolved_count: 3,
        total: TIMELINE_MAX_ROWS as u64 + 3,
    });
    timeline.status = format!("{} events (measured)", TIMELINE_MAX_ROWS);
    state.timeline = timeline;
    state
}

#[test]
#[ignore = "host-dependent timing; run in release and record docs/performance.md"]
fn a_full_timeline_renders_within_the_no_block_budget() {
    let mut harness = Harness::new_ui_state(|ui, state| state.ui(ui), state());
    harness.run_steps(5);
    let mut samples = Vec::with_capacity(30);
    for _ in 0..30 {
        let started = Instant::now();
        harness.run_steps(1);
        samples.push(started.elapsed());
    }
    samples.sort();
    let p50 = samples[samples.len() / 2];
    let p95 = samples[(samples.len() - 1) * 95 / 100];
    let max = *samples.last().expect("sample");
    eprintln!(
        "timeline frame: p50={:.2} ms p95={:.2} ms max={:.2} ms ({} rows, 60 bins)",
        p50.as_secs_f64() * 1_000.0,
        p95.as_secs_f64() * 1_000.0,
        max.as_secs_f64() * 1_000.0,
        TIMELINE_MAX_ROWS
    );
    assert!(
        p95 < Duration::from_millis(100),
        "no operation may block input for more than 100 ms; p95 was {p95:?}"
    );
}

//! GhostTrace desktop — P0.1 pilot (plan Sections 3, 10, 17/P0.1).
//!
//! Proves the native GUI stack on the real egui/eframe API: labeled controls,
//! a bounded background job that never blocks the render thread, and
//! observable frame pacing. Written against egui 0.37, where `eframe::App`
//! splits per-frame non-UI work into `logic` and rendering into `ui`.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use eframe::Renderer;
use eframe::egui;
use ghosttrace_core::sqlite_report;
use tokio::sync::mpsc;

const JOB_TICK: Duration = Duration::from_millis(25);
const JOB_ITEMS: usize = 200;
const JOB_QUEUE_DEPTH: usize = 64;
const MAX_RECENT_FRAMES: usize = 240;

#[derive(Clone, Copy, PartialEq, Eq)]
enum JobState {
    Idle,
    Running,
    Completed,
    Cancelled,
}

impl JobState {
    fn label(self) -> &'static str {
        match self {
            JobState::Idle => "idle",
            JobState::Running => "running",
            JobState::Completed => "completed",
            JobState::Cancelled => "cancelled",
        }
    }
}

struct PilotApp {
    filter: String,
    items: Vec<String>,
    selected: Option<usize>,
    progress: f32,
    job_state: JobState,
    job_rx: Option<mpsc::Receiver<String>>,
    cancel_tx: Option<tokio::sync::watch::Sender<bool>>,
    runtime: tokio::runtime::Runtime,
    frame_count: u64,
    frame_sum_ms: f64,
    frame_max_ms: f64,
    frame_recent: VecDeque<f64>,
    last_frame: Option<Instant>,
    started: Instant,
    auto_exit_after: Option<Duration>,
    runtime_summary: String,
    summary_printed: bool,
}

impl PilotApp {
    fn new(auto_exit_after: Option<Duration>) -> Self {
        let report = sqlite_report::sqlite_report();
        let runtime_summary = format!(
            "sqlite {} · fts5 {} · fk {} · wal {}",
            report.sqlite_library_version,
            if report.fts5.created_and_indexed {
                "ok"
            } else {
                "MISSING"
            },
            if report.foreign_keys_enforced {
                "ok"
            } else {
                "MISSING"
            },
            if report.wal_mode_supported {
                "ok"
            } else {
                "MISSING"
            },
        );
        let mut app = Self {
            filter: String::new(),
            items: Vec::new(),
            selected: None,
            progress: 0.0,
            job_state: JobState::Idle,
            job_rx: None,
            cancel_tx: None,
            runtime: tokio::runtime::Builder::new_multi_thread()
                .enable_time()
                .build()
                .expect("tokio runtime"),
            frame_count: 0,
            frame_sum_ms: 0.0,
            frame_max_ms: 0.0,
            frame_recent: VecDeque::new(),
            last_frame: None,
            started: Instant::now(),
            auto_exit_after,
            runtime_summary,
            summary_printed: false,
        };
        // Measurement mode (`--pilot-seconds`): start the background job
        // immediately so frame pacing is sampled while job work runs.
        if app.auto_exit_after.is_some() {
            app.start_job();
        }
        app
    }

    fn start_job(&mut self) {
        let (tx, rx) = mpsc::channel(JOB_QUEUE_DEPTH);
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        self.runtime.spawn(async move {
            for i in 0..JOB_ITEMS {
                tokio::time::sleep(JOB_TICK).await;
                if *cancel_rx.borrow() {
                    let _ = tx.send("__cancelled__".to_string()).await;
                    return;
                }
                if tx.send(format!("item {i}")).await.is_err() {
                    return; // UI went away; stop quietly
                }
            }
            let _ = tx.send("__done__".to_string()).await;
        });
        self.job_rx = Some(rx);
        self.cancel_tx = Some(cancel_tx);
        self.job_state = JobState::Running;
        self.items.clear();
        self.selected = None;
        self.progress = 0.0;
    }

    fn cancel_job(&mut self) {
        if let Some(tx) = &self.cancel_tx {
            let _ = tx.send(true);
        }
    }

    /// Drain the bounded job queue. Uses try_recv, so the UI thread never
    /// blocks on job work regardless of how fast the background task runs.
    fn drain_job_messages(&mut self) {
        let mut messages = Vec::new();
        if let Some(rx) = self.job_rx.as_mut() {
            while let Ok(message) = rx.try_recv() {
                messages.push(message);
            }
        }
        for message in messages {
            match message.as_str() {
                "__done__" => {
                    self.job_state = JobState::Completed;
                    self.progress = 1.0;
                    self.job_rx = None;
                    self.cancel_tx = None;
                }
                "__cancelled__" => {
                    self.job_state = JobState::Cancelled;
                    self.job_rx = None;
                    self.cancel_tx = None;
                }
                other => {
                    self.items.push(other.to_string());
                    self.progress = (self.items.len() as f32 / JOB_ITEMS as f32).min(1.0);
                }
            }
        }
    }

    fn frame_avg_ms(&self) -> f64 {
        if self.frame_count == 0 {
            0.0
        } else {
            self.frame_sum_ms / self.frame_count as f64
        }
    }

    /// p95 of the most recent frames, for the ≤16.7 ms frame budget claim.
    fn frame_p95_ms(&self) -> f64 {
        if self.frame_recent.is_empty() {
            return 0.0;
        }
        let mut samples: Vec<f64> = self.frame_recent.iter().copied().collect();
        samples.sort_by(|a, b| a.partial_cmp(b).expect("frame times are finite"));
        let index = ((samples.len() as f64) * 0.95).ceil() as usize;
        samples[index.min(samples.len() - 1)]
    }

    fn print_summary(&mut self) {
        if self.summary_printed {
            return; // auto-exit already reported; Drop must not duplicate
        }
        self.summary_printed = true;
        println!(
            "pilot: frames={} avg_ms={:.2} p95_ms={:.2} max_ms={:.2} items={} state={}",
            self.frame_count,
            self.frame_avg_ms(),
            self.frame_p95_ms(),
            self.frame_max_ms,
            self.items.len(),
            self.job_state.label(),
        );
    }
}

impl Drop for PilotApp {
    fn drop(&mut self) {
        if !self.summary_printed {
            self.print_summary();
        }
    }
}

impl eframe::App for PilotApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Frame pacing bookkeeping; `logic` runs before each `ui` call.
        let now = Instant::now();
        if let Some(last) = self.last_frame.replace(now) {
            let dt_ms = now.duration_since(last).as_secs_f64() * 1000.0;
            self.frame_count += 1;
            self.frame_sum_ms += dt_ms;
            self.frame_max_ms = self.frame_max_ms.max(dt_ms);
            if self.frame_recent.len() == MAX_RECENT_FRAMES {
                self.frame_recent.pop_front();
            }
            self.frame_recent.push_back(dt_ms);
        }

        self.drain_job_messages();

        if self.job_state == JobState::Running {
            // Keep frames coming while the background task produces work.
            ctx.request_repaint_after(JOB_TICK);
        }

        if let Some(limit) = self.auto_exit_after
            && self.started.elapsed() >= limit
        {
            self.print_summary();
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("ghosttrace-header").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("GhostTrace · pilot");
                ui.separator();
                ui.label("Case time zone: UTC (default)");
                ui.separator();
                ui.label(&self.runtime_summary);
            });
        });

        egui::Panel::bottom("ghosttrace-status").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("items: {}", self.items.len()));
                ui.separator();
                ui.label(format!("job: {}", self.job_state.label()));
                ui.separator();
                ui.label(format!(
                    "frames: {} · avg {:.2} ms · p95 {:.2} ms · max {:.2} ms",
                    self.frame_count,
                    self.frame_avg_ms(),
                    self.frame_p95_ms(),
                    self.frame_max_ms
                ));
            });
        });

        egui::Panel::left("ghosttrace-timeline").show(ui, |ui| {
            ui.label("Filter");
            ui.text_edit_singleline(&mut self.filter);
            ui.separator();
            ui.label("Timeline (pilot records)");
            let needle = self.filter.to_lowercase();
            let visible: Vec<usize> = self
                .items
                .iter()
                .enumerate()
                .filter(|(_, item)| needle.is_empty() || item.to_lowercase().contains(&needle))
                .map(|(index, _)| index)
                .collect();
            egui::ScrollArea::vertical().show_rows(ui, 18.0, visible.len(), |ui, row_range| {
                for index in &visible[row_range] {
                    if ui
                        .selectable_label(self.selected == Some(*index), &self.items[*index])
                        .clicked()
                    {
                        self.selected = Some(*index);
                    }
                }
            });
        });

        egui::CentralPanel::default().show(ui, |ui| {
            ui.group(|ui| {
                ui.label("Background job");
                ui.add_enabled_ui(self.job_state != JobState::Running, |ui| {
                    if ui.button("Start job").clicked() {
                        self.start_job();
                    }
                });
                ui.add_enabled_ui(self.job_state == JobState::Running, |ui| {
                    if ui.button("Cancel").clicked() {
                        self.cancel_job();
                    }
                });
                ui.add(egui::ProgressBar::new(self.progress).show_percentage());
                ui.label(format!("Job state: {}", self.job_state.label()));
            });
            ui.separator();
            ui.group(|ui| {
                ui.label("Linked runtime (from ghosttrace-core)");
                ui.label(&self.runtime_summary);
                if let Some(selected) = self.selected {
                    ui.label(format!(
                        "Selected record: {}",
                        self.items.get(selected).cloned().unwrap_or_default()
                    ));
                } else {
                    ui.label("Selected record: none");
                }
            });
        });
    }
}

struct Options {
    renderer: Renderer,
    pilot_seconds: Option<u64>,
}

/// Default renderer: glow when compiled in (smaller binary, widest Linux
/// driver coverage), else wgpu. See docs/adr/0001-native-rust-ui.md.
#[cfg(feature = "glow")]
const DEFAULT_RENDERER: Renderer = Renderer::Glow;
#[cfg(all(not(feature = "glow"), feature = "wgpu"))]
const DEFAULT_RENDERER: Renderer = Renderer::Wgpu;

/// Pilot flags: `--renderer glow|wgpu`, `--pilot-seconds N` (auto-exit for
/// headless measurement). Screenshots use eframe's built-in
/// `EFRAME_SCREENSHOT_TO=/path.png` env var (glow renderer only).
fn parse_args() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
    let mut options = Options {
        renderer: DEFAULT_RENDERER,
        pilot_seconds: None,
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--renderer" => {
                options.renderer = match args.next().as_deref() {
                    #[cfg(feature = "glow")]
                    Some("glow") => Renderer::Glow,
                    #[cfg(feature = "wgpu")]
                    Some("wgpu") => Renderer::Wgpu,
                    other => return Err(format!("unknown --renderer value: {other:?}")),
                }
            }
            "--pilot-seconds" => {
                options.pilot_seconds = Some(
                    args.next()
                        .ok_or("--pilot-seconds needs a value")?
                        .parse()
                        .map_err(|_| "--pilot-seconds needs an integer")?,
                );
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(options)
}

fn main() -> eframe::Result<()> {
    let options = match parse_args() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("error: {message}");
            // Exit 2 = invalid usage, per the planned CLI exit-code policy.
            std::process::exit(2);
        }
    };
    let native_options = eframe::NativeOptions {
        renderer: options.renderer,
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 700.0])
            .with_title("GhostTrace (pilot)"),
        ..Default::default()
    };
    eframe::run_native(
        "GhostTrace (pilot)",
        native_options,
        Box::new(|_cc| {
            Ok(Box::new(PilotApp::new(
                options.pilot_seconds.map(Duration::from_secs),
            )))
        }),
    )
}

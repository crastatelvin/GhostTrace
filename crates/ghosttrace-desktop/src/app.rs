//! The eframe application shell: wires state to the background worker.
//!
//! `logic` runs before rendering and is the only place worker results are
//! drained and commands are sent. `ui` only draws and mutates state.

use std::time::Duration;

use eframe::egui;

use crate::commands::CommandBus;
use crate::query::QueryWorker;
use crate::state::{AppState, JobState};

const REPAINT_WHILE_RUNNING: Duration = Duration::from_millis(50);
const MAX_EVENTS_PER_FRAME: usize = 64;

pub struct DesktopApp {
    state: AppState,
    bus: CommandBus,
    queries: QueryWorker,
}

impl DesktopApp {
    pub fn new() -> Self {
        Self {
            state: AppState::new(),
            bus: CommandBus::spawn().expect("start the desktop worker thread"),
            queries: QueryWorker::spawn().expect("start the desktop query thread"),
        }
    }

    /// Test-only access to the state; the real app only renders it.
    pub fn state(&self) -> &AppState {
        &self.state
    }
}

impl Default for DesktopApp {
    fn default() -> Self {
        Self::new()
    }
}

impl eframe::App for DesktopApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let now = ctx.input(|input| input.time);
        self.state.begin_frame(now);
        for _ in 0..MAX_EVENTS_PER_FRAME {
            match self.queries.try_recv() {
                Some(result) => self.state.apply_query(result),
                None => break,
            }
        }
        for request in self.state.take_queries() {
            self.queries.send(request);
        }
        for _ in 0..MAX_EVENTS_PER_FRAME {
            match self.bus.try_recv() {
                Some(event) => self.state.apply(event),
                None => break,
            }
        }
        for id in self.state.take_cancels() {
            self.bus.cancel(id);
        }
        for command in self.state.take_commands() {
            self.bus.send(command);
        }
        if self.state.job.state == JobState::Running
            || self.state.timeline.is_loading()
            || self.state.timeline.is_debouncing()
            || self.state.diff.is_loading()
            || self.state.relations.is_loading()
            || self.state.findings.is_loading()
        {
            ctx.request_repaint_after(REPAINT_WHILE_RUNNING);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.state.ui(ui);
    }
}

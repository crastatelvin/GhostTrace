//! Interactive terminal workflow (plan P7).
//!
//! `ghosttrace tui` opens one case and drives the same query/analysis contracts
//! as the CLI and desktop. The terminal is entered behind a restoration guard;
//! redirected output is refused so pipelines never receive ANSI control bytes.

pub mod input;
pub mod state;
pub mod terminal;
pub mod views;

use std::io;
use std::path::Path;
use std::time::Duration;

use crossterm::event::{self, Event, KeyEventKind};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::commands::{EXIT_FAILED, EXIT_OK, EXIT_USAGE};
use state::App;

/// Run the interactive view. Returns a CLI exit code; terminal errors are
/// reported only after the guard has restored the screen.
pub fn run(case: &Path, revision: Option<String>) -> u8 {
    if !terminal::is_interactive() {
        eprintln!(
            "error: `ghosttrace tui` needs an interactive terminal; use `timeline`, `search`, \
             or `analyze` for pipelines"
        );
        return EXIT_USAGE;
    }
    let mut app = match App::open(case, revision) {
        Ok(app) => app,
        Err(error) => {
            crate::output::emit_error(error.code(), &error.to_string());
            return EXIT_FAILED;
        }
    };
    let guard = match terminal::Restoration::enter(terminal::CrosstermOps) {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("error: cannot enter the interactive terminal: {error}");
            return EXIT_FAILED;
        }
    };
    let mut tui = match Terminal::new(CrosstermBackend::new(io::stdout())) {
        Ok(tui) => tui,
        Err(error) => {
            drop(guard);
            eprintln!("error: cannot create the terminal: {error}");
            return EXIT_FAILED;
        }
    };
    let result = event_loop(&mut tui, &mut app);
    // Restore before anything is printed; the guard's Drop is the safety net
    // for errors and unwinds.
    drop(guard);
    match result {
        Ok(()) => EXIT_OK,
        Err(error) => {
            eprintln!("error: terminal read/write failed: {error}");
            EXIT_FAILED
        }
    }
}

fn event_loop(tui: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> io::Result<()> {
    loop {
        tui.draw(|frame| views::draw(frame, &mut app.state))?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        // Windows terminals report release events too; only act on presses and
        // repeats, or every key would fire twice.
        if key.kind == KeyEventKind::Release {
            continue;
        }
        let Some(action) = input::map(key, app.state.mode) else {
            continue;
        };
        if app.handle(action) {
            return Ok(());
        }
    }
}

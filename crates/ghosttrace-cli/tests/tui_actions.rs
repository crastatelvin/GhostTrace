//! P7 TUI contract: state and input transitions driven against a real case,
//! without a terminal. Also checks that a selection yields the same recorded
//! event/detail as the shared query contract the GUI uses, and that hostile
//! control bytes never reach the terminal buffer.

use std::path::{Path, PathBuf};
use std::process::Command;

use ghosttrace_cli::tui::state::{Action, App, Mode, View};
use ghosttrace_cli::tui::views;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

const JSONL: &str = concat!(
    "{\"ts\":\"2026-10-27T10:00:00Z\",\"msg\":\"first record\"}\n",
    "{\"ts\":\"2026-10-27T10:00:01Z\",\"msg\":\"second record\"}\n",
    "{\"ts\":\"2026-10-27T10:00:02Z\",\"msg\":\"third record\"}\n",
    "{\"ts\":\"2026-10-27T10:00:03Z\",\"msg\":\"hostile \\u001b]0;pwned\\u0007 text\"}\n",
);

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ghosttrace"))
        .args(args)
        .output()
        .expect("cli runs")
}

fn scanned_case(dir: &Path) -> PathBuf {
    let evidence = dir.join("evidence");
    std::fs::create_dir_all(&evidence).expect("evidence dir");
    std::fs::write(evidence.join("app.jsonl"), JSONL).expect("jsonl");
    let case = dir.join("demo.ghosttrace-case");
    let created = run(&[
        "case",
        "create",
        "--case",
        case.to_str().unwrap(),
        "--label",
        "Demo",
        "--timezone",
        "UTC",
    ]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let scanned = run(&[
        "scan",
        "--case",
        case.to_str().unwrap(),
        "--source",
        evidence.to_str().unwrap(),
    ]);
    assert_eq!(scanned.status.code(), Some(0));
    let imported = run(&[
        "import",
        "--case",
        case.to_str().unwrap(),
        "--path",
        "app.jsonl",
        "--format",
        "jsonl",
        "--message-field",
        "msg",
    ]);
    assert_eq!(
        imported.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    case
}

fn open_app(dir: &Path) -> (App, PathBuf) {
    let case = scanned_case(dir);
    let app = App::open(&case, None).expect("tui opens the case");
    (app, case)
}

fn render(app: &mut App) -> String {
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("test terminal");
    terminal
        .draw(|frame| views::draw(frame, &mut app.state))
        .expect("draw");
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

#[test]
fn the_tui_opens_the_newest_revision_and_selects_the_first_event() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (app, _case) = open_app(dir.path());
    let state = &app.state;

    assert!(!state.revision.is_empty(), "a revision must be resolved");
    assert_eq!(state.rows.len(), 4);
    assert_eq!(state.selected, 0);
    assert_eq!(state.view, View::Timeline);
    assert_eq!(state.mode, Mode::Browse);
    assert!(
        state.detail.is_some(),
        "the selected row has a detail record"
    );
    assert!(
        state.status.contains("4 event(s)"),
        "status: {}",
        state.status
    );
    assert!(!state.status_is_error);
}

#[test]
fn a_selection_yields_the_same_detail_record_as_the_shared_query_contract() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut app, case) = open_app(dir.path());
    let selected = app.state.rows[1].event_id.clone();
    let revision = app.state.revision.clone();

    app.handle(Action::MoveDown);
    assert_eq!(app.state.selected, 1);
    let detail = app.state.detail.as_ref().expect("detail");
    assert_eq!(detail.event.event_id, selected);

    let reader = ghosttrace_core::storage::read::CaseReader::open(&case.join("case.sqlite"))
        .expect("reader");
    let same = reader
        .event_detail(&revision, &selected)
        .expect("same detail");
    assert_eq!(
        detail, &same,
        "the TUI must show the record the GUI's query returns"
    );

    // Clamping never leaves the selection pointing past the page.
    app.handle(Action::MoveUp);
    app.handle(Action::MoveUp);
    assert_eq!(app.state.selected, 0);
    app.handle(Action::Last);
    assert_eq!(app.state.selected, 3);
    app.handle(Action::First);
    assert_eq!(app.state.selected, 0);
}

#[test]
fn the_tui_rows_are_the_same_identifiers_as_the_cli_timeline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (app, case) = open_app(dir.path());
    let output = run(&[
        "timeline",
        "--case",
        case.to_str().unwrap(),
        "--limit",
        "50",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let page: serde_json::Value = serde_json::from_slice(&output.stdout).expect("timeline json");
    let cli_ids: Vec<&str> = page["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| row["event_id"].as_str().expect("event id"))
        .collect();
    let tui_ids: Vec<&str> = app
        .state
        .rows
        .iter()
        .map(|row| row.event_id.as_str())
        .collect();
    assert_eq!(
        tui_ids, cli_ids,
        "same filters, same identifiers, same order"
    );
}

#[test]
fn search_uses_the_shared_grammar_and_a_typo_stays_visible() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut app, _case) = open_app(dir.path());

    app.handle(Action::StartSearch);
    assert_eq!(app.state.mode, Mode::Search);
    for ch in "record".chars() {
        app.handle(Action::Input(ch));
    }
    app.handle(Action::Commit);
    assert_eq!(app.state.mode, Mode::Browse);
    assert_eq!(app.state.search, "record");
    assert_eq!(
        app.state.rows.len(),
        4,
        "the search path returns the matches"
    );

    // A search that matches nothing is an empty result, not an error.
    app.handle(Action::StartSearch);
    for ch in "nonexistent".chars() {
        app.handle(Action::Input(ch));
    }
    app.handle(Action::Commit);
    assert_eq!(app.state.rows.len(), 0);
    assert!(!app.state.status_is_error);
    app.handle(Action::StartSearch);
    for ch in "record".chars() {
        app.handle(Action::Input(ch));
    }
    app.handle(Action::Commit);
    assert_eq!(app.state.rows.len(), 4);

    // An unbalanced quote is rejected by the shared validator, and the view
    // does not silently change.
    app.handle(Action::StartSearch);
    app.handle(Action::Input('"'));
    app.handle(Action::Commit);
    assert_eq!(app.state.mode, Mode::Search, "the prompt stays open");
    assert!(app.state.status_is_error);
    assert!(
        app.state.status.contains("unterminated quote"),
        "status: {}",
        app.state.status
    );
    assert_eq!(app.state.rows.len(), 4, "the previous view is intact");
    app.handle(Action::Cancel);
    assert_eq!(app.state.mode, Mode::Browse);
}

#[test]
fn filters_apply_exact_fields_and_reject_unknown_keys() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut app, _case) = open_app(dir.path());

    app.handle(Action::StartFilters);
    for ch in "source=jsonl.fields".chars() {
        app.handle(Action::Input(ch));
    }
    app.handle(Action::Commit);
    assert_eq!(app.state.query.source.as_deref(), Some("jsonl.fields"));
    assert_eq!(app.state.rows.len(), 4);

    app.handle(Action::StartFilters);
    for ch in "source=nope".chars() {
        app.handle(Action::Input(ch));
    }
    app.handle(Action::Commit);
    assert!(app.state.rows.is_empty());
    assert!(app.state.status.contains("0 event(s)"));

    app.handle(Action::StartFilters);
    for ch in "kindx=auth".chars() {
        app.handle(Action::Input(ch));
    }
    app.handle(Action::Commit);
    assert_eq!(app.state.mode, Mode::Filters, "the prompt stays open");
    assert!(app.state.status_is_error);
    assert!(app.state.status.contains("unknown filter"));
}

#[test]
fn the_unresolved_view_is_the_explicit_empty_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut app, _case) = open_app(dir.path());
    assert_eq!(app.state.rows.len(), 4);

    app.handle(Action::ToggleUnresolved);
    assert!(app.state.query.unresolved_only);
    assert!(
        app.state.rows.is_empty(),
        "every record resolved a time, so this view is empty instead of reusing rows"
    );
    assert!(app.state.detail.is_none());

    app.handle(Action::ToggleUnresolved);
    assert!(!app.state.query.unresolved_only);
    assert_eq!(app.state.rows.len(), 4);
}

#[test]
fn analysis_runs_on_the_active_revision_and_switches_to_findings() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut app, _case) = open_app(dir.path());

    app.handle(Action::Analyze);
    assert_eq!(app.state.view, View::Findings);
    assert!(
        app.state.findings_run.is_some(),
        "analysis status: {}",
        app.state.status
    );
    assert!(
        app.state.status.starts_with("analysis"),
        "status: {}",
        app.state.status
    );
    // A bounded pass is surfaced as partial, never as a complete success.
    assert_eq!(
        app.state.status_is_error,
        app.state.status.contains("partial")
    );

    app.handle(Action::ToggleView);
    assert_eq!(app.state.view, View::Timeline);
    app.handle(Action::Help);
    assert_eq!(app.state.view, View::Help);
    app.handle(Action::Cancel);
    assert_eq!(app.state.view, View::Timeline);
}

#[test]
fn hostile_control_bytes_never_reach_the_terminal_buffer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut app, _case) = open_app(dir.path());
    app.handle(Action::Last);
    assert!(
        app.state.rows[3].summary.contains('\u{1b}'),
        "the fixture must carry a real escape byte in the indexed summary"
    );

    let screen = render(&mut app);
    assert!(
        !screen.contains('\u{1b}'),
        "no raw escape byte may reach the terminal: {screen:?}"
    );
    assert!(
        !screen.contains('\u{7}'),
        "no raw bell byte may reach the terminal: {screen:?}"
    );
    assert!(
        screen.contains("\\u{1b}"),
        "the escape is shown as visible text instead of disappearing"
    );
    assert!(
        screen.contains("hostile"),
        "the record stays readable after escaping"
    );
}

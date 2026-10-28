//! Key mapping for the TUI (plan P7).
//!
//! Mapping is a pure function so key handling is tested without a terminal.
//! Browse mode uses single letters; the search and filter prompts take text
//! until Enter or Escape.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::state::{Action, Mode};

/// Map one key press. `None` means the key has no meaning in this mode; it is
/// ignored instead of being guessed at.
pub fn map(key: KeyEvent, mode: Mode) -> Option<Action> {
    // Ctrl+C always quits; Ctrl+U clears the prompt line.
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            KeyCode::Char('c') => Some(Action::Quit),
            KeyCode::Char('u') if mode != Mode::Browse => Some(Action::Cancel),
            _ => None,
        };
    }
    match mode {
        Mode::Search | Mode::Filters => match key.code {
            KeyCode::Char(ch) => Some(Action::Input(ch)),
            KeyCode::Backspace => Some(Action::Backspace),
            KeyCode::Enter => Some(Action::Commit),
            KeyCode::Esc => Some(Action::Cancel),
            _ => None,
        },
        Mode::Browse => match key.code {
            KeyCode::Char('q') => Some(Action::Quit),
            KeyCode::Char('j') | KeyCode::Down => Some(Action::MoveDown),
            KeyCode::Char('k') | KeyCode::Up => Some(Action::MoveUp),
            KeyCode::PageDown => Some(Action::PageDown),
            KeyCode::PageUp => Some(Action::PageUp),
            KeyCode::Char('g') | KeyCode::Home => Some(Action::First),
            KeyCode::Char('G') | KeyCode::End => Some(Action::Last),
            KeyCode::Char('n') => Some(Action::NextPage),
            KeyCode::Char('p') => Some(Action::PreviousPage),
            KeyCode::Char('u') => Some(Action::ToggleUnresolved),
            KeyCode::Char('/') => Some(Action::StartSearch),
            KeyCode::Char('f') => Some(Action::StartFilters),
            KeyCode::Char('a') => Some(Action::Analyze),
            KeyCode::Tab => Some(Action::ToggleView),
            KeyCode::Char('?') => Some(Action::Help),
            KeyCode::Esc => Some(Action::Cancel),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn browse_keys_map_to_intents() {
        assert_eq!(
            map(press(KeyCode::Char('j')), Mode::Browse),
            Some(Action::MoveDown)
        );
        assert_eq!(
            map(press(KeyCode::Char('k')), Mode::Browse),
            Some(Action::MoveUp)
        );
        assert_eq!(
            map(press(KeyCode::Char('/')), Mode::Browse),
            Some(Action::StartSearch)
        );
        assert_eq!(
            map(press(KeyCode::Char('f')), Mode::Browse),
            Some(Action::StartFilters)
        );
        assert_eq!(
            map(press(KeyCode::Char('a')), Mode::Browse),
            Some(Action::Analyze)
        );
        assert_eq!(
            map(press(KeyCode::Char('u')), Mode::Browse),
            Some(Action::ToggleUnresolved)
        );
        assert_eq!(
            map(press(KeyCode::Tab), Mode::Browse),
            Some(Action::ToggleView)
        );
        assert_eq!(
            map(press(KeyCode::Char('q')), Mode::Browse),
            Some(Action::Quit)
        );
        assert_eq!(map(press(KeyCode::Char('z')), Mode::Browse), None);
    }

    #[test]
    fn prompts_take_text_and_finish_on_enter_or_escape() {
        for mode in [Mode::Search, Mode::Filters] {
            assert_eq!(
                map(press(KeyCode::Char('a')), mode),
                Some(Action::Input('a'))
            );
            assert_eq!(
                map(press(KeyCode::Backspace), mode),
                Some(Action::Backspace)
            );
            assert_eq!(map(press(KeyCode::Enter), mode), Some(Action::Commit));
            assert_eq!(map(press(KeyCode::Esc), mode), Some(Action::Cancel));
            // Browse-only actions must not fire while typing.
            assert_eq!(map(press(KeyCode::Tab), mode), None);
            assert_eq!(
                map(press(KeyCode::Char('q')), mode),
                Some(Action::Input('q'))
            );
        }
    }

    #[test]
    fn control_c_quits_from_every_mode() {
        let key = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        for mode in [Mode::Browse, Mode::Search, Mode::Filters] {
            assert_eq!(map(key, mode), Some(Action::Quit));
        }
    }
}

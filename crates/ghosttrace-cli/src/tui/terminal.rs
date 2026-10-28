//! Terminal setup and the restoration guard (plan P7).
//!
//! Raw mode and the alternate screen are entered once and restored through a
//! `Drop` guard, so a normal exit, an error return, and an unwinding panic all
//! put the terminal back. The guard talks to a [`TerminalOps`] trait so tests
//! assert the exact enter/leave sequence without a real terminal.

use std::io::{self, IsTerminal};

/// Terminal operations the guard performs. Implemented for crossterm and for
/// a recording fake in tests.
pub trait TerminalOps {
    fn enter(&mut self) -> io::Result<()>;
    fn leave(&mut self) -> io::Result<()>;
}

pub struct Restoration<O: TerminalOps> {
    ops: O,
    active: bool,
}

impl<O: TerminalOps> Restoration<O> {
    /// Enter raw mode and the alternate screen. If any step fails, nothing is
    /// marked active and the caller gets the error.
    pub fn enter(mut ops: O) -> io::Result<Self> {
        ops.enter()?;
        Ok(Self { ops, active: true })
    }

    /// Restore the terminal now. Idempotent; `Drop` calls it again safely.
    pub fn restore(&mut self) {
        if self.active {
            // Best effort: a failed restoration must not mask the original
            // error or panic that is already on its way out.
            let _ = self.ops.leave();
            self.active = false;
        }
    }
}

impl<O: TerminalOps> Drop for Restoration<O> {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Crossterm-backed operations. Cursor visibility is restored before leaving
/// the alternate screen, and raw mode last, so a partial failure still leaves
/// the terminal in a usable state.
pub struct CrosstermOps;

impl TerminalOps for CrosstermOps {
    fn enter(&mut self) -> io::Result<()> {
        crossterm::terminal::enable_raw_mode()?;
        crossterm::execute!(
            io::stdout(),
            crossterm::terminal::EnterAlternateScreen,
            crossterm::cursor::Hide
        )
    }

    fn leave(&mut self) -> io::Result<()> {
        let _ = crossterm::execute!(io::stdout(), crossterm::cursor::Show);
        let _ = crossterm::execute!(io::stdout(), crossterm::terminal::LeaveAlternateScreen);
        let _ = crossterm::terminal::disable_raw_mode();
        Ok(())
    }
}

/// The TUI needs a terminal on both ends. Redirected output is refused by the
/// caller instead of writing ANSI control bytes into a pipeline.
pub fn is_interactive() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    #[derive(Clone, Default)]
    struct Fake {
        calls: Rc<RefCell<Vec<&'static str>>>,
        fail_enter: bool,
    }

    impl TerminalOps for Fake {
        fn enter(&mut self) -> io::Result<()> {
            if self.fail_enter {
                return Err(io::Error::other("no terminal"));
            }
            self.calls.borrow_mut().push("enter");
            Ok(())
        }

        fn leave(&mut self) -> io::Result<()> {
            self.calls.borrow_mut().push("leave");
            Ok(())
        }
    }

    #[test]
    fn normal_exit_restores_exactly_once() {
        let fake = Fake::default();
        let calls = fake.calls.clone();
        {
            let mut guard = Restoration::enter(fake).expect("enter");
            guard.restore();
        }
        assert_eq!(*calls.borrow(), vec!["enter", "leave"]);
    }

    #[test]
    fn an_enter_failure_restores_nothing() {
        let fake = Fake {
            fail_enter: true,
            ..Fake::default()
        };
        let calls = fake.calls.clone();
        assert!(Restoration::enter(fake).is_err());
        assert!(calls.borrow().is_empty());
    }

    #[test]
    fn an_unwind_still_restores_the_terminal() {
        let fake = Fake::default();
        let calls = fake.calls.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = Restoration::enter(fake).expect("enter");
            panic!("analysis exploded");
        }));
        assert!(result.is_err());
        assert_eq!(*calls.borrow(), vec!["enter", "leave"]);
    }
}

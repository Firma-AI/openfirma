//! Terminal lifecycle for the control surface.
//!
//! The UI normally owns the terminal in raw mode and draws into the alternate
//! screen. Blocking tools, especially editors, need the normal terminal back.
//! Tui is the one place that performs that handoff so the rest of the control
//! code does not need to remember which cursor, raw-mode, or screen state is
//! currently active.

use std::io;

use crossterm::{
    cursor::{Hide, Show},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::control::{app::App, render};

type TerminalBackend = CrosstermBackend<io::Stdout>;

/// Owns raw-mode and alternate-screen terminal state.
///
/// Dropping this value restores the terminal. Setup failures also attempt to
/// restore whatever state was already changed before returning the error.
pub struct Tui {
    terminal: Terminal<TerminalBackend>,
}

impl Tui {
    /// Enters raw mode and moves rendering into the alternate screen.
    ///
    /// # Errors
    ///
    /// Returns an error when raw mode, alternate screen setup, or terminal
    /// backend initialization fails.
    pub fn enter() -> anyhow::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, Hide) {
            restore_terminal();
            return Err(error.into());
        }

        let backend = CrosstermBackend::new(stdout);
        match Terminal::new(backend) {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                restore_terminal();
                Err(error.into())
            }
        }
    }

    /// Draws one frame of the current application state.
    ///
    /// # Errors
    ///
    /// Returns an error when the terminal backend cannot draw the frame.
    pub fn draw(&mut self, app: &App) -> anyhow::Result<()> {
        self.terminal.draw(|frame| render::render(frame, app))?;
        Ok(())
    }

    /// Restores the caller's terminal while a blocking process runs.
    ///
    /// This is used for editor integration. The blocking process gets a normal
    /// terminal, then the TUI re-enters the alternate screen and clears the
    /// frame before drawing resumes.
    pub fn suspend<T, F>(&mut self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce() -> T,
    {
        // The callback must run after the primary screen and canonical input
        // mode are restored. Otherwise editors will read raw key bytes and draw
        // over the alternate-screen frame instead of behaving like a normal
        // foreground terminal process.
        self.leave_for_blocking_process()?;
        let action_result = f();
        self.resume_after_blocking_process()?;
        Ok(action_result)
    }

    fn leave_for_blocking_process(&mut self) -> anyhow::Result<()> {
        disable_raw_mode()?;
        execute!(self.terminal.backend_mut(), Show, LeaveAlternateScreen)?;
        Ok(())
    }

    fn resume_after_blocking_process(&mut self) -> anyhow::Result<()> {
        execute!(self.terminal.backend_mut(), EnterAlternateScreen, Hide)?;
        enable_raw_mode()?;
        self.terminal.clear()?;
        Ok(())
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let mut stdout = io::stdout();
    let _ = execute!(stdout, Show, LeaveAlternateScreen);
}

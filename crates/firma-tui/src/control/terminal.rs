//! Terminal lifecycle for the Policy Control surface.

use std::io;

use crossterm::{
    cursor::{Hide, Show},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::control::{app::App, render};

type TerminalBackend = CrosstermBackend<io::Stdout>;

pub struct Tui {
    terminal: Terminal<TerminalBackend>,
}

impl Tui {
    /// Enters raw mode and moves rendering into the alternate screen.
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
    pub fn draw(&mut self, app: &App) -> anyhow::Result<()> {
        self.terminal.draw(|frame| render::render(frame, app))?;
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

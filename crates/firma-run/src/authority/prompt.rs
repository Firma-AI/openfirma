//! TTY-aware y/N prompt for Authority bootstrap.
//!
//! Backed by `dialoguer` for consistency with `firma config` prompts.
//! The [`AuthorityPromptIo`] trait keeps the call site mockable so unit
//! tests can drive selection logic without touching real stdin.

use std::io;

use dialoguer::Confirm;
use dialoguer::console::Term;
use dialoguer::theme::ColorfulTheme;

/// Y/N prompt abstraction.
pub trait AuthorityPromptIo {
    /// Whether stderr is attached to a terminal capable of answering.
    fn is_tty(&self) -> bool;

    /// Print `prompt` and read a single y/N answer. Default is `false`.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if the terminal interaction fails.
    fn confirm(&mut self, prompt: &str) -> io::Result<bool>;
}

/// Production implementation backed by `dialoguer` on stderr.
pub struct StdAuthorityPrompt;

impl AuthorityPromptIo for StdAuthorityPrompt {
    fn is_tty(&self) -> bool {
        Term::stderr().is_term()
    }

    fn confirm(&mut self, prompt: &str) -> io::Result<bool> {
        Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .default(false)
            .interact_on(&Term::stderr())
            .map_err(io::Error::other)
    }
}

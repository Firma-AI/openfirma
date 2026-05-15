//! TTY-aware y/N prompt for Authority bootstrap.
//!
//! The trait exists so tests can inject canned answers without touching
//! real stdin. The prod impl [`StdAuthorityPrompt`] uses
//! `std::io::IsTerminal` on stdin to decide whether interaction is even
//! possible, and reads a single line for the answer.

use std::io::{self, BufRead, IsTerminal, Write};

/// Y/N prompt abstraction.
pub trait AuthorityPromptIo {
    /// Whether stdin is attached to a terminal capable of answering.
    fn is_tty(&self) -> bool;

    /// Print `prompt` to stderr, read one line from stdin, return `true`
    /// on `y` / `Y` / `yes`; `false` on empty / `n` / `N` / `no` /
    /// anything else.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if stdin/stderr fail.
    fn confirm(&mut self, prompt: &str) -> io::Result<bool>;
}

/// Production implementation backed by real stdin/stderr.
pub struct StdAuthorityPrompt;

impl AuthorityPromptIo for StdAuthorityPrompt {
    fn is_tty(&self) -> bool {
        io::stdin().is_terminal()
    }

    fn confirm(&mut self, prompt: &str) -> io::Result<bool> {
        let mut stderr = io::stderr();
        stderr.write_all(prompt.as_bytes())?;
        stderr.flush()?;

        let mut buf = String::new();
        io::stdin().lock().read_line(&mut buf)?;
        Ok(parse_yes(&buf))
    }
}

fn parse_yes(input: &str) -> bool {
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_yes_accepts_y_yes_case_insensitive() {
        assert!(parse_yes("y\n"));
        assert!(parse_yes("Y\n"));
        assert!(parse_yes("yes\n"));
        assert!(parse_yes("YES\n"));
        assert!(parse_yes("  yes  \n"));
    }

    #[test]
    fn parse_yes_rejects_empty_n_and_garbage() {
        assert!(!parse_yes(""));
        assert!(!parse_yes("\n"));
        assert!(!parse_yes("n\n"));
        assert!(!parse_yes("No\n"));
        assert!(!parse_yes("maybe\n"));
        assert!(!parse_yes("ye\n"));
    }
}

//! Consistent terminal output formatting for the firma CLI.
//!
//! Emits a standardized `[LEVEL]` prefix with tty-aware ANSI color and
//! 80-column wrapping with hanging indent. Stream selection mirrors Unix
//! convention: `ok`/`info` go to stdout, `warn`/`err` go to stderr.
//!
//! Use [`ok`], [`info`], [`warn`], [`err`] from CLI subcommands instead of
//! raw `println!` / `eprintln!` so warnings, errors, and status lines all
//! render the same way across `firma run`, `firma authority`, `firma config`,
//! `firma doctor`, `firma monitor`, `firma policy`, and friends.

#![allow(
    dead_code,
    reason = "Info is reserved for future callers in the shared CLI output surface"
)]

use std::io::{IsTerminal as _, Write as _};

use owo_colors::{OwoColorize as _, Stream};

const TERM_WIDTH: usize = 80;
/// Width of the fixed `[LEVEL]` prefix including its trailing space.
const PREFIX_WIDTH: usize = 7;

#[derive(Clone, Copy)]
enum Level {
    Ok,
    Info,
    Warn,
    Err,
}

impl Level {
    fn prefix(self) -> &'static str {
        match self {
            Self::Ok => "[OK]   ",
            Self::Info => "[INFO] ",
            Self::Warn => "[WARN] ",
            Self::Err => "[ERR]  ",
        }
    }

    fn stream(self) -> Stream {
        match self {
            Self::Ok | Self::Info => Stream::Stdout,
            Self::Warn | Self::Err => Stream::Stderr,
        }
    }

    fn colored_prefix(self) -> String {
        let p = self.prefix();
        let s = self.stream();
        match self {
            Self::Ok => format!("{}", p.if_supports_color(s, |t| t.green())),
            Self::Info => format!("{}", p.if_supports_color(s, |t| t.cyan())),
            Self::Warn => format!("{}", p.if_supports_color(s, |t| t.yellow())),
            Self::Err => format!("{}", p.if_supports_color(s, |t| t.bright_red())),
        }
    }
}

/// Emit a success line to stdout.
pub fn ok(msg: impl AsRef<str>) {
    emit(Level::Ok, msg.as_ref());
}

/// Emit an informational line to stdout.
pub fn info(msg: impl AsRef<str>) {
    emit(Level::Info, msg.as_ref());
}

/// Emit a warning line to stderr.
pub fn warn(msg: impl AsRef<str>) {
    emit(Level::Warn, msg.as_ref());
}

/// Emit an error line to stderr.
pub fn err(msg: impl AsRef<str>) {
    emit(Level::Err, msg.as_ref());
}

fn emit(level: Level, msg: &str) {
    match level {
        Level::Ok | Level::Info => {
            let lines = format_lines(level, msg, std::io::stdout().is_terminal());
            let mut out = std::io::stdout().lock();
            for line in lines {
                let _ = writeln!(out, "{line}");
            }
        }
        Level::Warn | Level::Err => {
            let lines = format_lines(level, msg, std::io::stderr().is_terminal());
            let mut out = std::io::stderr().lock();
            for line in lines {
                let _ = writeln!(out, "{line}");
            }
        }
    }
}

/// Wrap `msg` and prepend the level prefix on the first line.
///
/// When `is_tty` is true, lines are wrapped at 80 cols with continuation lines
/// indented by `PREFIX_WIDTH` spaces so they visually align with the start of
/// the first line's message text. When false (piped / captured), the original
/// message is preserved verbatim so callers grepping stderr aren't broken by
/// embedded newlines. Multi-paragraph input (separated by blank lines) is
/// handled paragraph by paragraph so the blank lines survive.
fn format_lines(level: Level, msg: &str, is_tty: bool) -> Vec<String> {
    let prefix = level.colored_prefix();

    if !is_tty {
        let mut out = Vec::new();
        let mut first = true;
        for line in msg.split('\n') {
            if first {
                out.push(format!("{prefix}{line}"));
                first = false;
            } else {
                out.push(line.to_string());
            }
        }
        if out.is_empty() {
            out.push(prefix);
        }
        return out;
    }

    let indent = " ".repeat(PREFIX_WIDTH);
    let wrap_width = TERM_WIDTH.saturating_sub(PREFIX_WIDTH).max(20);
    let options = textwrap::Options::new(wrap_width).subsequent_indent(indent.as_str());

    let mut out = Vec::new();
    let mut first = true;
    for paragraph in msg.split("\n\n") {
        if !first {
            out.push(String::new());
        }
        first = false;
        if paragraph.is_empty() {
            continue;
        }
        let mut wrapped = textwrap::wrap(paragraph, &options).into_iter();
        if let Some(head) = wrapped.next() {
            out.push(format!("{prefix}{head}"));
        }
        for tail in wrapped {
            out.push(tail.into_owned());
        }
    }
    if out.is_empty() {
        out.push(prefix);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for nxt in chars.by_ref() {
                    if nxt.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn short_message_has_single_line_with_prefix() {
        let lines = format_lines(Level::Warn, "config file missing", true);
        assert_eq!(lines.len(), 1);
        assert_eq!(strip_ansi(&lines[0]), "[WARN] config file missing");
    }

    #[test]
    fn long_message_wraps_at_80_cols_with_hanging_indent() {
        let msg = "this configuration includes private signing keys; ensure \
                   file mode is 0600 before distributing the bundle";
        let lines = format_lines(Level::Warn, msg, true);
        assert!(lines.len() >= 2);
        let cleaned: Vec<String> = lines.iter().map(|l| strip_ansi(l)).collect();
        assert!(cleaned[0].starts_with("[WARN] "));
        for line in cleaned.iter().skip(1) {
            assert!(line.starts_with("       "), "got: {line:?}");
            assert!(line.len() <= TERM_WIDTH, "line too long: {line:?}");
        }
    }

    #[test]
    fn all_levels_emit_seven_char_prefix() {
        for level in [Level::Ok, Level::Info, Level::Warn, Level::Err] {
            assert_eq!(level.prefix().len(), PREFIX_WIDTH);
        }
    }

    #[test]
    fn empty_message_still_emits_prefix() {
        let lines = format_lines(Level::Info, "", true);
        assert_eq!(lines.len(), 1);
        assert!(strip_ansi(&lines[0]).starts_with("[INFO] "));
    }

    #[test]
    fn non_tty_skips_wrapping_so_scripts_can_grep_the_full_phrase() {
        let msg = "invalid capability seed '/very/long/path/to/seed/file.toml': \
                   raw_token claims do not match seed claims";
        let lines = format_lines(Level::Err, msg, false);
        assert_eq!(lines.len(), 1);
        let cleaned = strip_ansi(&lines[0]);
        assert!(cleaned.starts_with("[ERR]  "));
        assert!(cleaned.contains("raw_token claims do not match seed claims"));
    }

    #[test]
    fn blank_line_between_paragraphs_preserved() {
        let lines = format_lines(Level::Info, "first paragraph\n\nsecond paragraph", true);
        let cleaned: Vec<String> = lines.iter().map(|l| strip_ansi(l)).collect();
        assert_eq!(cleaned[0], "[INFO] first paragraph");
        assert!(cleaned.iter().any(String::is_empty));
        assert!(cleaned.iter().any(|l| l.starts_with("[INFO] second")));
    }
}

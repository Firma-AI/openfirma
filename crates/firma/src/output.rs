//! Consistent terminal output formatting for the firma CLI.
//!
//! Emits a standardized `[LEVEL]` prefix with tty-aware ANSI color. Stream
//! selection mirrors Unix convention: `ok`/`info` go to stdout, `warn`/`err`
//! go to stderr. Lines are not hard-wrapped — the terminal soft-wraps long
//! messages itself, so output stays a single logical line and callers grepping
//! stdout/stderr aren't broken by injected line breaks.
//!
//! Use [`ok`], [`info`], [`warn`], [`err`] from CLI subcommands instead of
//! raw `println!` / `eprintln!` so warnings, errors, and status lines all
//! render the same way across `firma run`, `firma authority`, `firma config`,
//! `firma doctor`, `firma monitor`, `firma policy`, and friends.

#![allow(
    dead_code,
    reason = "Info is reserved for future callers in the shared CLI output surface"
)]

use std::io::Write as _;

use owo_colors::{OwoColorize as _, Stream};

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
    let lines = format_lines(level, msg);
    match level {
        Level::Ok | Level::Info => {
            let mut out = std::io::stdout().lock();
            for line in lines {
                let _ = writeln!(out, "{line}");
            }
        }
        Level::Warn | Level::Err => {
            let mut out = std::io::stderr().lock();
            for line in lines {
                let _ = writeln!(out, "{line}");
            }
        }
    }
}

/// Prepend the level prefix to the first line of `msg` and align the rest.
///
/// No hard-wrapping is applied, so each logical line is left to the terminal's
/// own soft-wrap and piped/captured output keeps the full phrase on one line
/// for grepping. Explicit newlines inside `msg` start a continuation line
/// indented by `PREFIX_WIDTH` spaces so it lines up under the first line's
/// message text rather than the `[LEVEL]` prefix.
fn format_lines(level: Level, msg: &str) -> Vec<String> {
    let prefix = level.colored_prefix();
    let indent = " ".repeat(PREFIX_WIDTH);

    let mut out = Vec::new();
    let mut first = true;
    for line in msg.split('\n') {
        if first {
            out.push(format!("{prefix}{line}"));
            first = false;
        } else {
            out.push(format!("{indent}{line}"));
        }
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
        let lines = format_lines(Level::Warn, "config file missing");
        assert_eq!(lines.len(), 1);
        assert_eq!(strip_ansi(&lines[0]), "[WARN] config file missing");
    }

    #[test]
    fn long_message_stays_on_one_line_so_terminal_soft_wraps() {
        let msg = "this configuration includes private signing keys; ensure \
                   file mode is 0600 before distributing the bundle";
        let lines = format_lines(Level::Warn, msg);
        assert_eq!(lines.len(), 1);
        let cleaned = strip_ansi(&lines[0]);
        assert_eq!(cleaned, format!("[WARN] {msg}"));
    }

    #[test]
    fn all_levels_emit_seven_char_prefix() {
        for level in [Level::Ok, Level::Info, Level::Warn, Level::Err] {
            assert_eq!(level.prefix().len(), PREFIX_WIDTH);
        }
    }

    #[test]
    fn empty_message_still_emits_prefix() {
        let lines = format_lines(Level::Info, "");
        assert_eq!(lines.len(), 1);
        assert!(strip_ansi(&lines[0]).starts_with("[INFO] "));
    }

    #[test]
    fn message_kept_verbatim_so_scripts_can_grep_the_full_phrase() {
        let msg = "invalid capability seed '/very/long/path/to/seed/file.toml': \
                   raw_token claims do not match seed claims";
        let lines = format_lines(Level::Err, msg);
        assert_eq!(lines.len(), 1);
        let cleaned = strip_ansi(&lines[0]);
        assert!(cleaned.starts_with("[ERR]  "));
        assert!(cleaned.contains("raw_token claims do not match seed claims"));
    }

    #[test]
    fn embedded_newlines_indent_continuation_under_message_text() {
        let lines = format_lines(Level::Info, "first line\nsecond line");
        let cleaned: Vec<String> = lines.iter().map(|l| strip_ansi(l)).collect();
        assert_eq!(cleaned[0], "[INFO] first line");
        assert_eq!(cleaned[1], "       second line");
        assert_eq!(cleaned[1].len(), PREFIX_WIDTH + "second line".len());
    }
}

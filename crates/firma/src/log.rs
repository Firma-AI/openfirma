//! Unified logging init for the `firma` CLI.
//!
//! Two output modes, picked at init time:
//!
//! - **File** (`--log-file <path>`): the full structured `tracing` format
//!   with timestamps, target, line numbers, and span close events. Stable
//!   for long-running daemons (`firma run`, `firma sidecar`) and machine
//!   processing.
//! - **Stderr** (default): a compact CLI-style format that mirrors the
//!   `output::{ok,info,warn,err}` helpers — `[INFO]` / `[WARN]` / `[ERR]`
//!   prefix, TTY-gated ANSI color, no timestamp/target/line. Span close
//!   events are dropped so the interactive surface stays clean.

use std::fmt;
use std::fs::OpenOptions;
use std::io::IsTerminal as _;
use std::path::Path;

use owo_colors::{OwoColorize as _, Stream};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::{FmtSpan, Writer};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// Initialize the global tracing subscriber.
///
/// `filter` is an `EnvFilter` directive (e.g. `"info,firma=debug"`).
/// `file` writes logs to the given path (truncated on open) instead of stderr.
///
/// # Errors
///
/// Returns an error if `filter` is not a valid `EnvFilter` directive,
/// the log file cannot be opened, or a global subscriber is already set.
pub fn init(filter: &str, file: Option<&Path>) -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_new(filter)
        .map_err(|e| anyhow::anyhow!("invalid log filter `{filter}`: {e}"))?;

    if let Some(path) = file {
        let f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .map_err(|e| anyhow::anyhow!("failed to open log file {}: {e}", path.display()))?;
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_span_events(FmtSpan::CLOSE)
            .with_target(true)
            .with_line_number(true)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(f))
            .try_init()
            .map_err(|e| anyhow::anyhow!("failed to set tracing subscriber: {e}"))?;
    } else {
        // Compact CLI format on stderr. Drops `FmtSpan::CLOSE` because span
        // open/close pairs are diagnostic noise in interactive use.
        // `CompactFormatter` renders fields itself (without ANSI) so the
        // default field formatter cannot leak italic codes into piped output.
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .event_format(CompactFormatter)
            .with_writer(std::io::stderr)
            .try_init()
            .map_err(|e| anyhow::anyhow!("failed to set tracing subscriber: {e}"))?;
    }
    Ok(())
}

/// Minimal `FormatEvent` impl that renders each event as `[LEVEL] message
/// key=value …`, matching the `output::*` prefix scheme. Color is gated on
/// stderr being a TTY through owo-colors, so piped output / log capture stays
/// plain ASCII and existing test/script grep patterns keep working.
struct CompactFormatter;

impl<S, N> FormatEvent<S, N> for CompactFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let level = *event.metadata().level();
        let prefix = compact_prefix(level);
        let tty = std::io::stderr().is_terminal();
        if tty {
            // Match output.rs: green/cyan/yellow/bright_red, dim for debug/trace.
            match level {
                Level::ERROR => write!(
                    writer,
                    "{}",
                    prefix.if_supports_color(Stream::Stderr, |t| t.bright_red())
                )?,
                Level::WARN => write!(
                    writer,
                    "{}",
                    prefix.if_supports_color(Stream::Stderr, |t| t.yellow())
                )?,
                Level::INFO => write!(
                    writer,
                    "{}",
                    prefix.if_supports_color(Stream::Stderr, |t| t.cyan())
                )?,
                Level::DEBUG | Level::TRACE => write!(
                    writer,
                    "{}",
                    prefix.if_supports_color(Stream::Stderr, |t| t.dimmed())
                )?,
            }
        } else {
            write!(writer, "{prefix}")?;
        }

        let mut visitor = CompactFieldVisitor {
            writer: &mut writer,
            first: true,
        };
        event.record(&mut visitor);
        writeln!(writer)
    }
}

/// Renders event fields as `message key=value …` without ANSI.
///
/// The first field named `message` is emitted bare (no `message=` key). All
/// other fields use `Debug` form so structured values keep their shape
/// (`Some("…")`, `Path("/tmp")`, etc.). Newlines inside a field value are
/// preserved but never followed by extra padding — wrapping is the caller's
/// concern, not this formatter's.
struct CompactFieldVisitor<'a, 'w> {
    writer: &'a mut Writer<'w>,
    first: bool,
}

impl CompactFieldVisitor<'_, '_> {
    fn write_field(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let name = field.name();
        let sep = if self.first { "" } else { " " };
        self.first = false;
        if name == "message" {
            let _ = write!(self.writer, "{sep}{value:?}");
        } else {
            let _ = write!(self.writer, "{sep}{name}={value:?}");
        }
    }
}

impl Visit for CompactFieldVisitor<'_, '_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // `message` arrives as a Display value wrapped in Debug; the {:?}
        // form already renders the captured text. For all other fields the
        // user expects Debug output.
        if field.name() == "message" {
            let sep = if self.first { "" } else { " " };
            self.first = false;
            let _ = write!(self.writer, "{sep}{value:?}");
        } else {
            self.write_field(field, value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let sep = if self.first { "" } else { " " };
        self.first = false;

        if field.name() == "message" {
            let _ = write!(self.writer, "{sep}{value}");
        } else {
            let _ = write!(self.writer, "{sep}{}={value}", field.name());
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.write_field(field, &value);
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.write_field(field, &value);
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.write_field(field, &value);
    }
}

/// Fixed-width 7-char prefix for a tracing level so wrapped continuation lines
/// in operator scripts can align with `output::*` prefixes if needed.
const fn compact_prefix(level: Level) -> &'static str {
    match level {
        Level::ERROR => "[ERR]  ",
        Level::WARN => "[WARN] ",
        Level::INFO => "[INFO] ",
        Level::DEBUG => "[DBG]  ",
        Level::TRACE => "[TRC]  ",
    }
}

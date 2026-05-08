//! Unified logging init for the `firma` CLI.

use std::fs::OpenOptions;
use std::path::Path;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::FmtSpan;

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

    let builder = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(true)
        .with_line_number(true);

    if let Some(path) = file {
        let f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .map_err(|e| anyhow::anyhow!("failed to open log file {}: {e}", path.display()))?;
        builder
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(f))
            .try_init()
            .map_err(|e| anyhow::anyhow!("failed to set tracing subscriber: {e}"))?;
    } else {
        builder
            .with_writer(std::io::stderr)
            .try_init()
            .map_err(|e| anyhow::anyhow!("failed to set tracing subscriber: {e}"))?;
    }
    Ok(())
}

use std::fs::{File, OpenOptions};
use std::path::Path;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::{Layer as _, filter};

use crate::args::LogLevel;

pub struct LogFileWriter(File);

impl<'a> MakeWriter<'a> for LogFileWriter {
    type Writer = Box<dyn std::io::Write + 'a>;

    fn make_writer(&'a self) -> Self::Writer {
        Box::new(&self.0)
    }
}

impl TryFrom<&Path> for LogFileWriter {
    type Error = anyhow::Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self(file))
    }
}

/// Initialize the log configuration based on the CLI arguments
/// Initialize the log configuration based on the CLI arguments.
///
/// # Errors
///
/// Returns an error if the log file cannot be opened or the global
/// subscriber cannot be set.
pub fn init_log(
    log_level: LogLevel,
    log_file: Option<&Path>,
    log_filter: Option<String>,
) -> anyhow::Result<()> {
    let stdout_logger = tracing_subscriber::fmt::layer()
        .compact()
        .with_ansi(true)
        .with_span_events(FmtSpan::CLOSE)
        .with_line_number(true)
        .with_writer(std::io::stdout);

    let log_filter = std::sync::Arc::new(log_filter);

    let make_target_filter = {
        let log_filter = std::sync::Arc::clone(&log_filter);
        move || {
            let log_filter = std::sync::Arc::clone(&log_filter);
            filter::filter_fn(
                move |metadata: &tracing::Metadata<'_>| match log_filter.as_deref() {
                    Some(f) => metadata.target().contains(f),
                    None => true,
                },
            )
        }
    };

    let registry = tracing_subscriber::registry().with(
        stdout_logger
            .with_filter(LevelFilter::from(log_level))
            .with_filter(make_target_filter()),
    );

    if let Some(log_file) = log_file {
        let file_writer = LogFileWriter::try_from(log_file)?;
        let file_logger = tracing_subscriber::fmt::layer()
            .compact()
            .with_ansi(false)
            .with_span_events(FmtSpan::CLOSE)
            .with_line_number(true)
            .with_writer(file_writer);

        let registry = registry.with(
            file_logger
                .with_filter(LevelFilter::from(log_level))
                .with_filter(make_target_filter()),
        );
        tracing::subscriber::set_global_default(registry)
            .map_err(|e| anyhow::anyhow!("failed to set global default subscriber: {e}"))?;
    } else {
        tracing::subscriber::set_global_default(registry)
            .map_err(|e| anyhow::anyhow!("failed to set global default subscriber: {e}"))?;
    }

    Ok(())
}

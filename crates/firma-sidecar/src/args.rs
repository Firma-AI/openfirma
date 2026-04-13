//! CLI Arguments for the Firma Sidecar.

use std::{net::SocketAddr, path::PathBuf, str::FromStr};

/// CLI Arguments for the Firma Sidecar.
#[derive(Debug, clap::Parser)]
pub struct Args {
    /// The path to the configuration file for the sidecar.
    #[clap(
        long,
        short = 'c',
        env = "FIRMA_SIDECAR_CONFIG_FILE",
        default_value = "firma_sidecar.toml"
    )]
    pub config_file: PathBuf,
    /// Health check binding address.
    #[clap(
        long,
        env = "FIRMA_SIDECAR_HEALTH_BIND_ADDR",
        default_value = "127.0.0.1:9000"
    )]
    pub health_bind_addr: SocketAddr,
    /// Log file path for the sidecar.
    #[clap(long, short = 'L', env = "FIRMA_SIDECAR_LOG_FILE")]
    pub log_file: Option<PathBuf>,
    /// Log filter for the sidecar.
    #[clap(long, short = 'f', env = "FIRMA_SIDECAR_LOG_FILTER")]
    pub log_filter: Option<String>,
    /// Log level for the sidecar.
    #[clap(
        long,
        short = 'l',
        env = "FIRMA_SIDECAR_LOG_LEVEL",
        default_value = "info"
    )]
    pub log_level: LogLevel,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(format!("Invalid log level: {s}")),
        }
    }
}

impl From<LogLevel> for tracing::level_filters::LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => Self::ERROR,
            LogLevel::Warn => Self::WARN,
            LogLevel::Info => Self::INFO,
            LogLevel::Debug => Self::DEBUG,
            LogLevel::Trace => Self::TRACE,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_log_level_from_str() {
        assert_eq!(LogLevel::from_str("trace").unwrap(), LogLevel::Trace);
        assert_eq!(LogLevel::from_str("debug").unwrap(), LogLevel::Debug);
        assert_eq!(LogLevel::from_str("info").unwrap(), LogLevel::Info);
        assert_eq!(LogLevel::from_str("warn").unwrap(), LogLevel::Warn);
        assert_eq!(LogLevel::from_str("error").unwrap(), LogLevel::Error);
        assert!(LogLevel::from_str("invalid").is_err());
    }

    #[test]
    fn test_log_level_into_level_filter() {
        assert_eq!(
            tracing::level_filters::LevelFilter::from(LogLevel::Trace),
            tracing::level_filters::LevelFilter::TRACE
        );
        assert_eq!(
            tracing::level_filters::LevelFilter::from(LogLevel::Debug),
            tracing::level_filters::LevelFilter::DEBUG
        );
        assert_eq!(
            tracing::level_filters::LevelFilter::from(LogLevel::Info),
            tracing::level_filters::LevelFilter::INFO
        );
        assert_eq!(
            tracing::level_filters::LevelFilter::from(LogLevel::Warn),
            tracing::level_filters::LevelFilter::WARN
        );
        assert_eq!(
            tracing::level_filters::LevelFilter::from(LogLevel::Error),
            tracing::level_filters::LevelFilter::ERROR
        );
    }
}

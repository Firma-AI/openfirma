//! Error surface for runtime state operations.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Error type returned by runtime filesystem state operations.
#[derive(Debug, Error)]
pub enum RuntimeStateError {
    /// A sidecar marker file (`metadata.toml`) is present but not valid TOML.
    #[error("failed to parse sidecar marker '{path}': {source}")]
    MarkerParse {
        /// Path of the offending marker file.
        path: PathBuf,
        /// Underlying TOML parser error (boxed to keep the error type small).
        #[source]
        source: Box<toml::de::Error>,
    },

    /// State-dir resolution chain (flag, env, platform default) produced
    /// no usable path. The string carries a human-readable cause.
    #[error("state dir resolution failed: {0}")]
    StateDirResolve(String),

    /// Generic I/O error.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, RuntimeStateError>;

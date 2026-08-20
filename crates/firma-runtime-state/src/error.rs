//! Error surface for runtime state operations.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Error type returned by runtime filesystem state operations.
#[derive(Debug, Error)]
pub enum RuntimeStateError {
    /// A pidfile is present but is not in canonical format.
    #[error(
        "invalid pidfile '{path}': expected one canonical non-zero decimal process ID followed by a newline, got {value:?}"
    )]
    PidfileParse {
        /// Path of the malformed pidfile.
        path: PathBuf,
        /// Malformed value read from the file.
        value: String,
    },

    /// A sidecar marker file (`metadata.toml`) is present but not valid TOML.
    #[error("failed to parse sidecar marker '{path}': {source}")]
    MarkerParse {
        /// Path of the offending marker file.
        path: PathBuf,
        /// Underlying TOML parser error (boxed to keep the error type small).
        #[source]
        source: Box<toml::de::Error>,
    },

    /// A sidecar marker could not be serialized as TOML.
    #[error("failed to serialize sidecar marker: {0}")]
    MarkerSerialize(#[from] toml::ser::Error),

    /// A marker's validated identity does not match its containing directory.
    #[error(
        "sidecar marker identity mismatch at '{path}': directory is '{directory}', metadata is '{metadata}'"
    )]
    MarkerIdentityMismatch {
        /// Path of the marker directory.
        path: PathBuf,
        /// Marker directory basename.
        directory: String,
        /// Sandbox identity declared in metadata.
        metadata: String,
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

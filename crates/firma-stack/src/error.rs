//! Error surface for `firma-stack`.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Error type returned by every public operation in this crate.
///
/// All variants carry enough context to be rendered as a single-line
/// operator-facing message. Callers should generally print
/// `format!("{err}")` and exit non-zero rather than introspect variants.
#[derive(Debug, Error)]
pub enum StackError {
    /// Reading the stack config file from disk failed.
    #[error("failed to read stack config '{path}': {source}")]
    ConfigRead {
        /// Path of the config file that could not be opened.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The stack config file is present but not valid TOML.
    #[error("failed to parse stack config '{path}': {source}")]
    ConfigParse {
        /// Path of the offending config file.
        path: PathBuf,
        /// Underlying TOML parser error (boxed to keep `StackError` small).
        #[source]
        source: Box<toml::de::Error>,
    },

    /// A required field is absent from the stack config.
    #[error("stack config '{path}' is missing required field '{field}'")]
    ConfigMissing {
        /// Path of the config file that lacks the field.
        path: PathBuf,
        /// Name of the missing field.
        field: &'static str,
    },

    /// A sidecar marker file (`metadata.toml`) is present but not valid TOML.
    #[error("failed to parse sidecar marker '{path}': {source}")]
    MarkerParse {
        /// Path of the offending marker file.
        path: PathBuf,
        /// Underlying TOML parser error (boxed to keep `StackError` small).
        #[source]
        source: Box<toml::de::Error>,
    },

    /// State-dir resolution chain (flag, env, platform default) produced
    /// no usable path. The string carries a human-readable cause.
    #[error("state dir resolution failed: {0}")]
    StateDir(String),

    /// Creating the state directory on disk failed.
    #[error("failed to create state dir '{path}': {source}")]
    StateDirCreate {
        /// Path that could not be created.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Another supervisor already holds the stack lock for this state dir.
    #[error("stack already running (lock held at '{path}')")]
    AlreadyRunning {
        /// Path of the lock file that is currently held.
        path: PathBuf,
    },

    /// Spawning a child component (authority or sidecar) failed.
    #[error("failed to spawn '{component}': {source}")]
    Spawn {
        /// Logical component name (`authority` / `sidecar` / `supervisor`).
        component: String,
        /// Underlying spawn / I/O error.
        #[source]
        source: io::Error,
    },

    /// A component did not become ready (TCP listen or CA material) within
    /// the configured timeout.
    #[error("'{component}' did not become ready within {timeout_secs}s")]
    Readiness {
        /// Logical component name.
        component: String,
        /// Timeout, in seconds, that was exceeded.
        timeout_secs: u64,
    },

    /// Generic I/O error not classified by a more specific variant.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// OS-level failure surfaced from `platform_unix` / `platform_windows`
    /// (process-group setup, Job Object operations, signal delivery, etc).
    #[error("platform error: {0}")]
    Platform(String),
}

/// Convenience alias used throughout the crate for `Result<T, StackError>`.
pub type Result<T> = std::result::Result<T, StackError>;

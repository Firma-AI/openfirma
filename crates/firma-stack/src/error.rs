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

    /// Creating or securing the state directory failed.
    #[error(transparent)]
    StateDir(firma_fs::CreatePrivateDirError),

    /// Reading or writing shared runtime state failed.
    #[error(transparent)]
    RuntimeState(#[from] firma_runtime_state::RuntimeStateError),

    /// Another supervisor already holds the stack lock for this state dir.
    #[error("stack already running (lock held at '{path}')")]
    AlreadyRunning {
        /// Path of the lock file that is currently held.
        path: PathBuf,
    },

    /// Runtime-state cleanup could not acquire serialization without blocking.
    #[error("stack runtime state is busy at '{path}'; cleanup deferred")]
    RuntimeStateBusy {
        /// Runtime-state directory whose cleanup transaction is held elsewhere.
        path: PathBuf,
    },

    /// The persisted [`crate::StackGeneration`] is present but malformed.
    #[error("invalid stack.lock generation")]
    InvalidStackGeneration {
        /// UUID parser failure retained for diagnostics.
        #[source]
        source: uuid::Error,
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

    /// One or more process targets remained present after forced termination.
    #[error("termination targets remained present after {timeout_secs}s")]
    TerminationTimeout {
        /// Internal settlement window used after hard termination.
        timeout_secs: u64,
    },

    /// A startup operation failed and its required rollback also failed.
    #[error("{operation}; rollback failed: {rollback}")]
    Rollback {
        /// Original startup or attachment failure.
        operation: Box<Self>,
        /// Failure encountered while tearing the partial stack down.
        rollback: Box<Self>,
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

use std::path::PathBuf;

/// Error type used by `openauthority-run` runtime orchestration.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("invalid command: no executable was provided")]
    MissingCommand,

    #[error("failed to parse config at {path}: {reason}")]
    ConfigParse { path: PathBuf, reason: String },

    #[error("config validation failed: {0}")]
    ConfigValidation(String),

    #[error("unsupported backend {backend} on this host: {reason}")]
    UnsupportedBackend { backend: String, reason: String },

    #[error("backend error ({backend}): {reason}")]
    Backend { backend: String, reason: String },

    #[error("capability lease error: {0}")]
    Capability(String),

    #[error("failed to spawn wrapped command: {0}")]
    Spawn(String),

    #[error("failed while waiting for wrapped command: {0}")]
    Wait(String),

    #[error("internal runtime error: {0}")]
    Internal(String),
}

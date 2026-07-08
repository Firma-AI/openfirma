use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Result type used when reading and decoding guest result files.
pub type GuestResultResult<T> = Result<T, GuestResultError>;

/// Typed failures raised while reading the guest result protocol.
#[derive(Debug, Error)]
pub enum GuestResultError {
    /// The guest result file could not be read.
    #[error("read guest result {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The guest result file could not be parsed as the expected JSON shape.
    #[error("parse guest result {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    /// The guest result schema version is newer or otherwise unsupported.
    #[error("unsupported guest result version {found}; runner supports version {supported}")]
    UnsupportedVersion { found: u32, supported: u32 },
    /// An exited guest result did not include an exit code.
    #[error("guest result status exited requires exit_code")]
    MissingExitCode,
    /// A signaled guest result did not include a signal number.
    #[error("guest result status signaled requires signal")]
    MissingSignal,
    /// A guest setup/spawn error result did not include an error message.
    #[error("guest result error status requires error")]
    MissingError,
}

//! Errors of the connection store.

use std::path::PathBuf;

/// Why a connection could not be loaded, saved or removed.
///
/// No variant, in any rendering or source chain, carries secret bytes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// Neither `FIRMA_CONNECTION_DIR` nor a per-user configuration directory
    /// is available.
    #[error("no configuration directory is available for this user; set FIRMA_CONNECTION_DIR")]
    NoConfigDirectory,
    /// The connection directory is a relative path, which would change with
    /// the working directory.
    #[error("the connection directory must be an absolute path, not {}", path.display())]
    RelativeDirectory {
        /// The rejected value.
        path: PathBuf,
    },
    /// The directory or one of its files is a symlink, is not the expected
    /// kind of file, belongs to another user, or is accessible to group or
    /// others.
    #[error("{} is not private to the current user", path.display())]
    UnprotectedPath {
        /// The rejected directory or file.
        path: PathBuf,
    },
    /// A filesystem operation failed.
    #[error("could not {action} {}", path.display())]
    Io {
        /// What the store was doing.
        action: &'static str,
        /// The path involved.
        path: PathBuf,
        /// The operating system error.
        #[source]
        source: std::io::Error,
    },
    /// The connection lock could not be taken.
    #[error("could not lock {}", path.display())]
    Lock {
        /// The lock file.
        path: PathBuf,
        /// The operating system error.
        #[source]
        source: std::io::Error,
    },
    /// The operating system could not supply randomness for a connection id.
    #[error("could not generate a connection id")]
    Randomness(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The connection could not be serialized.
    #[error("could not encode the connection")]
    Encode(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The saved connection file is not a valid version 1 record.
    #[error("the saved connection in {} is unreadable ({reason}); run `firma login` again", path.display())]
    CorruptConnection {
        /// The connection file.
        path: PathBuf,
        /// What is wrong, without any stored value.
        reason: String,
    },
    /// The connection record exceeds the supported size limit.
    #[error("the connection record is too large (maximum 16 MiB)")]
    RecordTooLarge,
    /// The operating system credential store cannot be used here.
    #[error("the operating system credential store is not available: {reason}")]
    NativeStorageUnavailable {
        /// The platform's explanation.
        reason: String,
    },
    /// The operating system credential store refused an operation.
    #[error("the operating system credential store failed: {0}")]
    Native(NativeFailure),
    /// The saved connection refers to a credential that no longer exists.
    #[error("the secret of the saved connection is missing; run `firma login` again")]
    SecretMissing,
    /// Storing or reading a secret in a file is not supported on this
    /// platform.
    #[error("storing the connection secret in a file is not supported on this platform")]
    PlaintextFileUnsupported,
}

/// A credential-store failure, stripped of any payload that could hold
/// secret bytes.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NativeFailure {
    /// The stored credential is not valid text.
    #[error("the stored secret is malformed")]
    BadData,
    /// Any other failure, described by the platform.
    #[error("{0}")]
    Other(String),
}

//! Structured diagnostics for the control surface.

use std::{
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use thiserror::Error;

use crate::control::toggle::PolicyState;

/// Stored display text for an error that came from another layer.
///
/// Status values need to be cloned and compared while the TUI is running.
/// Many source errors do not support that, so this captures their message at
/// the boundary where the richer error type is no longer needed.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{message}")]
pub struct ErrorMessage {
    message: String,
}

impl ErrorMessage {
    /// Creates an error message from text.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Captures the display text of another error.
    #[must_use]
    pub fn capture(error: impl fmt::Display) -> Self {
        Self::new(error.to_string())
    }
}

/// Error returned while waiting on a rewrite event probe.
#[derive(Debug, Error)]
pub enum RewriteEventProbeError {
    /// The expected event was not observed before the wait budget expired.
    #[error("rewrite completion event was not observed within {timeout:?}")]
    Timeout {
        /// Total timeout supplied by the caller.
        timeout: Duration,
    },
    /// The rewrite worker side of the probe was dropped before completion.
    #[error("rewrite event probe disconnected before completion was observed")]
    Disconnected,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PolicyRewriteError {
    #[error("policy rewrite requires enabled or disabled state")]
    InvalidRequestedState,
    #[error("failed to read `{path}`: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: ErrorMessage,
    },
    #[error("source does not parse as Cedar: {source}")]
    ParseSource {
        #[source]
        source: ErrorMessage,
    },
    #[error("invalid policy annotation key `{key}`: {source}")]
    InvalidPolicyAnnotationKey {
        key: String,
        #[source]
        source: ErrorMessage,
    },
    #[error("duplicate policy id `{id}`")]
    DuplicatePolicyId { id: String },
    #[error("policy `{id}` has no source span")]
    MissingSourceSpan { id: String },
    #[error("policy `{id}` has invalid source span")]
    InvalidPolicySourceSpan { id: String },
    #[error("managed condition is outside policy `{id}`")]
    ManagedConditionOutsidePolicy { id: String },
    #[error("policy source span is empty")]
    EmptyPolicySourceSpan,
    #[error("policy source span does not end with a semicolon")]
    PolicySourceSpanMissingSemicolon,
    #[error("managed condition is not attached to a policy body")]
    UnattachedManagedCondition,
    #[error("policy id `{id}` was not found")]
    MissingId { id: String },
    #[error("duplicate requested policy id `{id}`")]
    DuplicateRequestedId { id: String },
    #[error("policy source span is outside source")]
    SourceSpanOutsideSource,
    #[error("source does not parse as Cedar CST: {source}")]
    ParseCst {
        #[source]
        source: ErrorMessage,
    },
    #[error("source does not contain Cedar policies")]
    EmptyCst,
    #[error("generated policy id `{id}` has no CST policy")]
    MissingCstPolicy { id: String },
    #[error("generated policy id `{id}` was not found in Cedar CST")]
    MissingGeneratedPolicy { id: String },
    #[error("candidate `{path}` does not parse as Cedar: {source}")]
    InvalidCandidate {
        path: PathBuf,
        #[source]
        source: ErrorMessage,
    },
    #[error("cannot determine parent directory for `{path}`")]
    MissingParentDir { path: PathBuf },
    #[error("failed to create temporary file in `{path}`: {source}")]
    CreateTempFile {
        path: PathBuf,
        #[source]
        source: ErrorMessage,
    },
    #[error("failed to write temporary file for `{path}`: {source}")]
    WriteTempFile {
        path: PathBuf,
        #[source]
        source: ErrorMessage,
    },
    #[error("failed to sync temporary file for `{path}`: {source}")]
    SyncTempFile {
        path: PathBuf,
        #[source]
        source: ErrorMessage,
    },
    #[error("failed to atomically replace `{path}` with `{temp_path}`: {source}")]
    AtomicReplace {
        path: PathBuf,
        temp_path: PathBuf,
        #[source]
        source: ErrorMessage,
    },
    #[error("requested {requested}, but disk state differs")]
    StateMismatch { requested: PolicyState },
    #[error("{message}")]
    Operation { message: String },
}

impl PolicyRewriteError {
    #[must_use]
    pub fn operation(message: impl Into<String>) -> Self {
        Self::Operation {
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PolicyDiscoveryError {
    #[error("policy directory does not exist: {path}")]
    MissingDirectory { path: PathBuf },
    #[error("failed to read policy directory `{path}`: {source}")]
    ReadDirectory {
        path: PathBuf,
        #[source]
        source: ErrorMessage,
    },
    #[error("failed to read `{path}`: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: ErrorMessage,
    },
    #[error("failed to parse `{path}`: {source}")]
    ParseFile {
        path: PathBuf,
        #[source]
        source: ErrorMessage,
    },
    #[error("policy id in `{path}` must not be empty")]
    EmptyId { path: PathBuf },
    #[error("duplicate policy id `{id}`")]
    DuplicateId { id: String },
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EditorError {
    #[error("finish pending policy rewrite before editing policies")]
    PendingRewrite,
    #[error("failed to launch editor: {source}")]
    Launch {
        #[source]
        source: ErrorMessage,
    },
    #[error("editor exited unsuccessfully: {status}")]
    Exit { status: String },
    #[error("{message}")]
    Operation { message: String },
}

impl EditorError {
    #[must_use]
    pub fn operation(message: impl Into<String>) -> Self {
        Self::Operation {
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RuntimeError {
    /// Generic runtime failure with a user-facing message.
    #[error("{message}")]
    Operation { message: String },
}

impl RuntimeError {
    /// Creates a generic runtime failure.
    #[must_use]
    pub fn operation(message: impl Into<String>) -> Self {
        Self::Operation {
            message: message.into(),
        }
    }
}

/// Failures while connecting to or translating the audit source.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuditSourceError {
    /// The audit log path could not be resolved from config or state.
    #[error("failed to resolve audit log path: {source}")]
    ResolvePath {
        #[source]
        source: ErrorMessage,
    },
    /// The audit tailing worker stopped unexpectedly.
    #[error("audit tailer stopped")]
    TailerStopped,
    /// The audit forwarding worker stopped unexpectedly.
    #[error("audit forwarder stopped")]
    ForwarderStopped,
    /// One audit log line could not be translated.
    #[error("failed to parse audit line: {source}")]
    ParseLine {
        #[source]
        source: ErrorMessage,
    },
    /// Generic audit source failure.
    #[error("{message}")]
    Operation { message: String },
}

impl AuditSourceError {
    /// Creates a generic audit source failure.
    #[must_use]
    pub fn operation(message: impl Into<String>) -> Self {
        Self::Operation {
            message: message.into(),
        }
    }
}

impl From<&str> for AuditSourceError {
    fn from(message: &str) -> Self {
        Self::operation(message)
    }
}

impl From<String> for AuditSourceError {
    fn from(message: String) -> Self {
        Self::operation(message)
    }
}

/// Error value stored in UI state and status snapshots.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ControlError {
    /// Runtime-level UI failure.
    #[error("{error}")]
    Runtime { error: Box<RuntimeError> },
    /// Policy discovery failed for the given policy directory.
    #[error("failed to discover policies in `{path}`: {error}")]
    PolicyDiscovery {
        path: PathBuf,
        error: Box<PolicyDiscoveryError>,
    },
    /// Policy rewrite failed for one or more rows in the same source file.
    #[error("failed to rewrite {count} policy row(s) in `{path}`: {error}")]
    PolicyRewrite {
        path: PathBuf,
        ids: Vec<String>,
        count: usize,
        error: Box<PolicyRewriteError>,
    },
    /// External editor failed while opening a policy source file.
    #[error("failed to edit policy source `{path}`: {error}")]
    Editor {
        path: PathBuf,
        error: Box<EditorError>,
    },
    /// Audit-source setup or forwarding failed.
    #[error("audit source error: {error}")]
    AuditSource { error: Box<AuditSourceError> },
}

impl ControlError {
    /// Creates a runtime-level UI failure.
    #[must_use]
    pub fn runtime(message: impl Into<String>) -> Self {
        Self::Runtime {
            error: Box::new(RuntimeError::operation(message)),
        }
    }

    /// Creates a policy discovery failure.
    #[must_use]
    pub(crate) fn policy_discovery(path: impl Into<PathBuf>, error: PolicyDiscoveryError) -> Self {
        Self::PolicyDiscovery {
            path: path.into(),
            error: Box::new(error),
        }
    }

    /// Creates a policy rewrite failure and records the number of affected rows.
    #[must_use]
    pub fn policy_rewrite(
        path: impl Into<PathBuf>,
        ids: Vec<String>,
        error: PolicyRewriteError,
    ) -> Self {
        let count = ids.len();
        Self::PolicyRewrite {
            path: path.into(),
            ids,
            count,
            error: Box::new(error),
        }
    }

    /// Creates an external editor failure.
    #[must_use]
    pub fn editor(path: impl Into<PathBuf>, error: EditorError) -> Self {
        Self::Editor {
            path: path.into(),
            error: Box::new(error),
        }
    }

    /// Creates an audit-source failure.
    #[must_use]
    pub fn audit_source(error: impl Into<AuditSourceError>) -> Self {
        Self::AuditSource {
            error: Box::new(error.into()),
        }
    }

    /// File path most closely associated with the error, when one exists.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::PolicyDiscovery { path, .. }
            | Self::PolicyRewrite { path, .. }
            | Self::Editor { path, .. } => Some(path),
            Self::Runtime { .. } | Self::AuditSource { .. } => None,
        }
    }

    /// Short message suitable for status display.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Runtime { error } => error.to_string(),
            Self::PolicyDiscovery { error, .. } => error.to_string(),
            Self::PolicyRewrite { error, .. } => error.to_string(),
            Self::Editor { error, .. } => error.to_string(),
            Self::AuditSource { error } => error.to_string(),
        }
    }
}

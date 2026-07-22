//! Structured diagnostics for the control surface.

use std::{fmt, path::Path};

use thiserror::Error;

/// Snapshot-friendly error message.
///
/// It stores rendered error text for sources whose concrete error type is not
/// cloneable or comparable, while still keeping the surrounding error variant
/// typed.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{message}")]
pub struct ErrorMessage {
    message: String,
}

impl ErrorMessage {
    /// Creates a message from displayable text.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Captures the display text of an error-like value.
    #[must_use]
    pub fn capture(error: impl fmt::Display) -> Self {
        Self::new(error.to_string())
    }
}

/// Runtime error that is not tied to a specific input source.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RuntimeError {
    /// Generic runtime operation failure.
    #[error("{message}")]
    Operation { message: String },
}

impl RuntimeError {
    /// Creates a generic runtime operation failure.
    #[must_use]
    pub fn operation(message: impl Into<String>) -> Self {
        Self::Operation {
            message: message.into(),
        }
    }
}

/// Error emitted by the audit source plumbing.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuditSourceError {
    /// The audit log path could not be resolved from config or state dir.
    #[error("failed to resolve audit log path: {source}")]
    ResolvePath {
        #[source]
        source: ErrorMessage,
    },
    /// The tailer stopped before the UI stopped consuming audit rows.
    #[error("audit tailer stopped")]
    TailerStopped,
    /// The audit forwarding thread stopped before the UI stopped consuming rows.
    #[error("audit forwarder stopped")]
    ForwarderStopped,
    /// A raw audit line could not be parsed into the monitor-lite shape.
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

/// Error recorded by the control surface and rendered by status-aware views.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ControlError {
    /// Runtime failure not tied to a specific source.
    #[error("{error}")]
    Runtime { error: Box<RuntimeError> },
    /// Audit source failure.
    #[error("audit source error: {error}")]
    AuditSource { error: Box<AuditSourceError> },
}

impl ControlError {
    /// Creates a runtime error from displayable text.
    #[must_use]
    pub fn runtime(message: impl Into<String>) -> Self {
        Self::Runtime {
            error: Box::new(RuntimeError::operation(message)),
        }
    }

    /// Creates an audit source error.
    #[must_use]
    pub fn audit_source(error: impl Into<AuditSourceError>) -> Self {
        Self::AuditSource {
            error: Box::new(error.into()),
        }
    }

    /// Path associated with this error, if there is one.
    #[must_use]
    pub const fn path(&self) -> Option<&Path> {
        match self {
            Self::Runtime { .. } | Self::AuditSource { .. } => None,
        }
    }

    /// User-facing error message.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Runtime { error } => error.to_string(),
            Self::AuditSource { error } => error.to_string(),
        }
    }
}

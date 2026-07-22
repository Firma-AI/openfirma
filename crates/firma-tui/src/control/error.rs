//! Structured diagnostics for the control surface.

use std::{fmt, path::Path};

use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{message}")]
pub struct ErrorMessage {
    message: String,
}

impl ErrorMessage {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn capture(error: impl fmt::Display) -> Self {
        Self::new(error.to_string())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RuntimeError {
    #[error("{message}")]
    Operation { message: String },
}

impl RuntimeError {
    #[must_use]
    pub fn operation(message: impl Into<String>) -> Self {
        Self::Operation {
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ControlError {
    #[error("{error}")]
    Runtime { error: Box<RuntimeError> },
}

impl ControlError {
    #[must_use]
    pub fn runtime(message: impl Into<String>) -> Self {
        Self::Runtime {
            error: Box::new(RuntimeError::operation(message)),
        }
    }

    #[must_use]
    pub const fn path(&self) -> Option<&Path> {
        match self {
            Self::Runtime { .. } => None,
        }
    }

    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Runtime { error } => error.to_string(),
        }
    }
}

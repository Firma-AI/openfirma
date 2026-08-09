//! Firma stack configuration and startup errors.

use std::io;
use std::net::AddrParseError;
use std::path::PathBuf;

use firma_config_loader::ConfigResolveError;
use firma_process_orchestrator::{OrchestratorError, StartError};
use thiserror::Error;

/// Error returned by Firma-specific stack operations.
#[derive(Debug, Error)]
pub enum StackError {
    /// Discovering the current Firma executable failed.
    #[error("failed to resolve current Firma executable: {source}")]
    CurrentExecutable {
        /// Executable discovery failure.
        #[source]
        source: io::Error,
    },
    /// Resolving a selected stack configuration failed.
    #[error(transparent)]
    ConfigResolution {
        /// Configuration resolver failure.
        source: ConfigResolveError,
    },
    /// No stack configuration was found in any supported location.
    #[error("no stack config found (expected '{path}')")]
    ConfigNotFound {
        /// Default or explicitly requested path reported to the operator.
        path: PathBuf,
    },
    /// Loading or deserializing Firma configuration failed.
    #[error("{source:#}")]
    ConfigValidation {
        /// Configuration loader's error chain.
        #[source]
        source: anyhow::Error,
    },
    /// The Authority listen address is invalid.
    #[error("invalid authority listen_addr '{address}': {source}")]
    InvalidAuthorityListenAddr {
        /// Invalid configured address.
        address: String,
        /// Socket-address parser failure.
        #[source]
        source: AddrParseError,
    },
    /// Staged planning did not receive a required prior endpoint.
    #[error("missing ready endpoint for prior component '{component}'")]
    MissingReadyEndpoint {
        /// Prior component required by this plan stage.
        component: &'static str,
    },
    /// Generic process orchestration failed.
    #[error(transparent)]
    Orchestrator(#[from] OrchestratorError),
    /// Stack planning or startup failed and process rollback also failed.
    #[error("{operation}; rollback failed: {rollback}")]
    Rollback {
        /// Original stack failure.
        operation: Box<Self>,
        /// Failure encountered while rolling back the partial stack.
        rollback: Box<OrchestratorError>,
    },
}

impl From<StartError<Self>> for StackError {
    fn from(error: StartError<Self>) -> Self {
        match error {
            StartError::Plan(error) => error,
            StartError::Orchestrator(error) => Self::Orchestrator(error),
            StartError::Rollback {
                operation,
                rollback,
            } => Self::Rollback {
                operation: Box::new(Self::from(*operation)),
                rollback,
            },
        }
    }
}

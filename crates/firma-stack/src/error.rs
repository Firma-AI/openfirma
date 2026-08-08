//! Firma stack configuration and startup errors.

use std::net::AddrParseError;
use std::path::PathBuf;

use firma_config_loader::ConfigResolveError;
use firma_process_orchestrator::{OrchestratorError, StartError};
use thiserror::Error;

/// Error returned by Firma-specific stack operations.
#[derive(Debug, Error)]
pub enum StackError {
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
    /// The configuration path cannot be passed to a child process.
    #[error("non-utf8 config path")]
    NonUtf8ConfigPath,
    /// The Authority listen address is invalid.
    #[error("invalid authority listen_addr '{address}': {source}")]
    InvalidAuthorityListenAddr {
        /// Invalid configured address.
        address: String,
        /// Socket-address parser failure.
        #[source]
        source: AddrParseError,
    },
    /// Generic process orchestration failed.
    #[error(transparent)]
    Orchestrator(#[from] OrchestratorError),
}

impl From<StartError<Self>> for StackError {
    fn from(error: StartError<Self>) -> Self {
        match error {
            StartError::Plan(error) => error,
            StartError::Orchestrator(error) => Self::Orchestrator(error),
        }
    }
}

use std::io;
use std::path::PathBuf;

use thiserror::Error;

pub type RunnerResult<T> = std::result::Result<T, RunnerError>;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("firma-vz-runner is macOS-only; parsed contract v{version} for sandbox {sandbox_id}")]
    UnsupportedHost { version: u32, sandbox_id: String },

    #[error("Apple Virtualization.framework is not supported on this host")]
    VirtualizationUnsupported,

    #[error("VZ VM plan unexpectedly requested {count} network device(s)")]
    NetworkDevicesRequested { count: usize },

    #[error("{action} {path}: {source}")]
    HostIo {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("{action}: {source}")]
    HostOperation {
        action: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("install Ctrl-C handler for VZ runner: {source}")]
    InterruptHandler {
        #[source]
        source: ctrlc::Error,
    },

    #[error("path is not valid UTF-8: {path}")]
    NonUtf8Path { path: PathBuf },

    #[error("configure {step}: {reason}")]
    ConfigurationStep { step: &'static str, reason: String },

    #[error("validate VZ VM configuration: {reason}")]
    ConfigurationValidation { reason: String },

    #[error("start VM: {reason}")]
    StartFailed { reason: String },

    #[error("VM start callback disconnected")]
    StartCallbackDisconnected,

    #[error("timed out waiting {timeout_secs}s for VM to start")]
    StartTimedOut { timeout_secs: u64 },

    #[error("VM entered error state after startup")]
    VmEnteredErrorState,

    #[error("request guest shutdown after interrupt: {reason}")]
    StopRequestFailed { reason: String },

    #[error("force-stop VM after interrupt: {reason}")]
    ForceStopFailed { reason: String },

    #[error("{operation}: {reason}")]
    OperationFailed {
        operation: &'static str,
        reason: String,
    },

    #[error("{operation} callback disconnected")]
    OperationCallbackDisconnected { operation: &'static str },

    #[error("timed out waiting {timeout_secs}s to {operation}")]
    OperationTimedOut {
        operation: &'static str,
        timeout_secs: u64,
    },
}

use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU32;
#[cfg(target_os = "macos")]
use std::os::fd::RawFd;
use std::path::PathBuf;

use thiserror::Error;

#[cfg(not(target_os = "macos"))]
type RawFd = i32;

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

    #[error("VZ VM plan must use vsock_sidecar network mode")]
    InvalidVsockNetworkMode,

    #[error("VZ VM plan must request exactly one VSOCK socket device, got {count}")]
    InvalidSocketDeviceCount { count: usize },

    #[error("VZ VM plan must request a Virtio VSOCK sidecar device")]
    InvalidSocketDeviceKind,

    #[error("VZ VM plan VSOCK sidecar port must be non-zero")]
    ZeroSidecarPort,

    #[error("terminal.pty=true requires a VM command PTY data port")]
    CommandPtyMissingPlan,

    #[error(
        "VZ VM plan command PTY port {pty_port} must be distinct from Sidecar port {sidecar_port}"
    )]
    CommandPtyPortConflictsWithSidecar {
        pty_port: NonZeroU32,
        sidecar_port: u32,
    },

    #[error("terminal.pty=true requires host stdin and stdout to be terminals")]
    CommandPtyHostTerminalUnavailable,

    #[error("enable raw host terminal mode for command PTY: {source}")]
    CommandPtyRawMode {
        #[source]
        source: io::Error,
    },

    #[error("duplicate command PTY fd {fd}: {source}")]
    CommandPtyDuplicateFd {
        fd: RawFd,
        #[source]
        source: io::Error,
    },

    #[error("VSOCK connection file descriptor is closed")]
    CommandPtyClosedConnectionFd,

    #[error("command PTY connection registry is poisoned")]
    CommandPtyConnectionRegistryPoisoned,

    #[error("connect VSOCK bridge upstream {addr}: {source}")]
    SidecarUpstreamConnect {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },

    #[error("VZ runtime exposed no socket device for Sidecar bridge")]
    MissingRuntimeSocketDevice,

    #[error("VZ runtime exposed {count} socket device(s), expected 1")]
    UnexpectedRuntimeSocketDevice { count: usize },

    #[error("VZ runtime socket device is not a VZVirtioSocketDevice")]
    UnexpectedRuntimeSocketDeviceKind,

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

mod firecracker;
mod linux_bwrap;
mod macos_vz;
mod windows_wsl2;

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::process::Child;

use serde::{Deserialize, Serialize};

use crate::config::{MountSpec, NetworkPolicy, ResolvedProfile, SandboxIdentityMode};
use crate::error::RunError;
use crate::identity::RunIdentity;

pub use firecracker::FirecrackerBackend;
pub use linux_bwrap::BwrapBackend;
pub use macos_vz::VzBackend;
pub use windows_wsl2::Wsl2Backend;

/// Supported runtime backend choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Bwrap,
    Vz,
    Wsl2,
    Firecracker,
}

impl BackendKind {
    /// Default backend for current host platform.
    #[must_use]
    pub fn default_for_current_host() -> Self {
        #[cfg(target_os = "linux")]
        {
            return Self::Bwrap;
        }

        #[cfg(target_os = "macos")]
        {
            return Self::Vz;
        }

        #[cfg(target_os = "windows")]
        {
            return Self::Wsl2;
        }

        #[allow(unreachable_code)]
        Self::Bwrap
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Bwrap => "bwrap",
            Self::Vz => "vz",
            Self::Wsl2 => "wsl2",
            Self::Firecracker => "firecracker",
        };
        write!(f, "{text}")
    }
}

/// Request payload for backend prepare stage.
#[derive(Debug, Clone)]
pub struct PrepareRequest {
    pub identity: RunIdentity,
    pub profile: ResolvedProfile,
    pub working_dir: PathBuf,
}

/// Handle produced by backend prepare stage.
#[derive(Debug, Clone)]
pub struct SandboxHandle {
    pub backend: BackendKind,
    pub runtime_dir: PathBuf,
    pub identity: RunIdentity,
    pub mounts: Vec<MountSpec>,
    pub network_policy: NetworkPolicy,
}

/// Network enforcement proof returned by backend.
#[derive(Debug, Clone)]
pub struct EnforcementProof {
    pub backend: BackendKind,
    pub structural: bool,
    pub fail_closed: bool,
    pub detail: String,
}

/// Launch payload for wrapped command.
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub identity_mode: SandboxIdentityMode,
}

/// Backend interface for sandbox runtime implementations.
pub trait SandboxBackend: Send + Sync {
    /// Returns the concrete backend kind.
    fn kind(&self) -> BackendKind;

    /// Prepare host/sandbox state before launching an agent.
    ///
    /// # Errors
    ///
    /// Returns an error when runtime directories, mounts, or backend preflight
    /// requirements cannot be created/validated.
    fn prepare(&self, request: &PrepareRequest) -> Result<SandboxHandle, RunError>;

    /// Install structural network routing and return proof metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when backend-specific network confinement fails.
    fn enforce_network(
        &self,
        _handle: &SandboxHandle,
        policy: &NetworkPolicy,
    ) -> Result<EnforcementProof, RunError>;

    /// Verify fail-closed invariants after network policy application.
    ///
    /// # Errors
    ///
    /// Returns an error when fail-closed guarantees cannot be established.
    fn verify_fail_closed(
        &self,
        handle: &SandboxHandle,
        proof: &EnforcementProof,
    ) -> Result<(), RunError>;

    /// Launch the wrapped command inside the prepared sandbox.
    ///
    /// # Errors
    ///
    /// Returns an error when the child process cannot be spawned.
    fn start_agent(&self, handle: &SandboxHandle, launch: &LaunchSpec) -> Result<Child, RunError>;

    /// Tear down backend runtime state after execution.
    ///
    /// # Errors
    ///
    /// Returns an error when backend cleanup fails.
    fn teardown(&self, handle: SandboxHandle) -> Result<(), RunError>;
}

/// Construct backend implementation for a kind.
#[must_use]
pub fn build_backend(kind: BackendKind) -> Box<dyn SandboxBackend> {
    match kind {
        BackendKind::Bwrap => Box::new(BwrapBackend::new()),
        BackendKind::Vz => Box::new(VzBackend::new()),
        BackendKind::Wsl2 => Box::new(Wsl2Backend::new()),
        BackendKind::Firecracker => Box::new(FirecrackerBackend::new()),
    }
}

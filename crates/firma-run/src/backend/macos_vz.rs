use std::process::Child;

use crate::backend::{
    BackendKind, EnforcementProof, LaunchSpec, PrepareRequest, SandboxBackend, SandboxHandle,
};
use crate::config::NetworkPolicy;
use crate::error::RunError;

/// Apple Virtualization Framework backend placeholder.
#[derive(Debug, Default)]
pub struct VzBackend;

impl VzBackend {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SandboxBackend for VzBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Vz
    }

    fn prepare(&self, _request: &PrepareRequest) -> Result<SandboxHandle, RunError> {
        Err(RunError::UnsupportedBackend {
            backend: BackendKind::Vz.to_string(),
            reason: "macOS VZ backend is not implemented yet in FIR-61".to_string(),
        })
    }

    fn enforce_network(
        &self,
        _handle: &SandboxHandle,
        _policy: &NetworkPolicy,
    ) -> Result<EnforcementProof, RunError> {
        Err(RunError::UnsupportedBackend {
            backend: BackendKind::Vz.to_string(),
            reason: "macOS VZ backend is not implemented yet in FIR-61".to_string(),
        })
    }

    fn verify_fail_closed(
        &self,
        _handle: &SandboxHandle,
        _proof: &EnforcementProof,
    ) -> Result<(), RunError> {
        Err(RunError::UnsupportedBackend {
            backend: BackendKind::Vz.to_string(),
            reason: "macOS VZ backend is not implemented yet in FIR-61".to_string(),
        })
    }

    fn start_agent(
        &self,
        _handle: &SandboxHandle,
        _launch: &LaunchSpec,
    ) -> Result<Child, RunError> {
        Err(RunError::UnsupportedBackend {
            backend: BackendKind::Vz.to_string(),
            reason: "macOS VZ backend is not implemented yet in FIR-61".to_string(),
        })
    }

    fn teardown(&self, _handle: SandboxHandle) -> Result<(), RunError> {
        Ok(())
    }
}

use std::process::Child;

use crate::backend::{
    BackendKind, EnforcementProof, LaunchSpec, PrepareRequest, SandboxBackend, SandboxHandle,
};
use crate::config::NetworkPolicy;
use crate::error::RunError;

/// Linux enterprise Firecracker backend placeholder.
#[derive(Debug, Default)]
pub struct FirecrackerBackend;

impl FirecrackerBackend {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self
    }
}

impl SandboxBackend for FirecrackerBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Firecracker
    }

    fn prepare(&self, _request: &PrepareRequest) -> Result<SandboxHandle, RunError> {
        Err(RunError::UnsupportedBackend {
            backend: BackendKind::Firecracker.to_string(),
            reason: "Firecracker backend is planned as enterprise additive profile".to_string(),
        })
    }

    fn enforce_network(
        &self,
        _handle: &SandboxHandle,
        _policy: &NetworkPolicy,
    ) -> Result<EnforcementProof, RunError> {
        Err(RunError::UnsupportedBackend {
            backend: BackendKind::Firecracker.to_string(),
            reason: "Firecracker backend is planned as enterprise additive profile".to_string(),
        })
    }

    fn verify_fail_closed(
        &self,
        _handle: &SandboxHandle,
        _proof: &EnforcementProof,
    ) -> Result<(), RunError> {
        Err(RunError::UnsupportedBackend {
            backend: BackendKind::Firecracker.to_string(),
            reason: "Firecracker backend is planned as enterprise additive profile".to_string(),
        })
    }

    fn start_agent(
        &self,
        _handle: &SandboxHandle,
        _launch: &LaunchSpec,
    ) -> Result<Child, RunError> {
        Err(RunError::UnsupportedBackend {
            backend: BackendKind::Firecracker.to_string(),
            reason: "Firecracker backend is planned as enterprise additive profile".to_string(),
        })
    }

    fn teardown(&self, _handle: SandboxHandle) -> Result<(), RunError> {
        Ok(())
    }
}

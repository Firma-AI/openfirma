mod error;

#[cfg(target_os = "macos")]
mod console;

#[cfg(target_os = "macos")]
mod vz;

use error::{RunnerError, RunnerResult};

#[cfg(target_os = "macos")]
pub use vz::run;

#[cfg(not(target_os = "macos"))]
use std::process::ExitCode;

#[cfg(not(target_os = "macos"))]
use crate::vm::VmPlan;

/// Rejects VZ runner execution on non-macOS hosts after contract validation.
///
/// The binary is intentionally macOS-only for now because this runner targets
/// Apple Virtualization.framework. Keeping the unsupported-host path behind the
/// same function preserves the CLI contract on every platform.
#[cfg(not(target_os = "macos"))]
pub fn run(vm_plan: &VmPlan) -> RunnerResult<ExitCode> {
    Err(RunnerError::UnsupportedHost {
        version: vm_plan.version(),
        sandbox_id: vm_plan.sandbox_id().to_string(),
    })
}

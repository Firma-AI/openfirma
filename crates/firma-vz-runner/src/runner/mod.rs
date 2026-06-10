mod error;

#[cfg(target_os = "macos")]
mod vz;

use error::{RunnerError, RunnerResult};

#[cfg(target_os = "macos")]
pub use vz::run;

#[cfg(not(target_os = "macos"))]
use std::process::ExitCode;

#[cfg(not(target_os = "macos"))]
use crate::vm::VmPlan;

#[cfg(all(test, not(target_os = "macos")))]
fn runner_test_vm_plan() -> anyhow::Result<crate::vm::VmPlan> {
    let (_temp, plan) =
        crate::test_utils::vm_plan_fixture(crate::test_utils::VALID_ROOTFS_SIZE_BYTES)?;

    Ok(plan)
}

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

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use anyhow::{Result, anyhow};

    use super::{RunnerError, run, runner_test_vm_plan};

    #[test]
    fn run_rejects_unsupported_host() -> Result<()> {
        let vm_plan = runner_test_vm_plan()?;
        let error = run(&vm_plan).err().ok_or_else(|| {
            anyhow!("non-macOS runner should reject execution after contract validation")
        })?;

        assert!(matches!(
            error,
            RunnerError::UnsupportedHost { version: 1, sandbox_id }
                if sandbox_id == "sandbox-test"
        ));

        Ok(())
    }
}

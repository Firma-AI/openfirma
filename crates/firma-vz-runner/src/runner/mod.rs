pub use error::{RunnerError, RunnerResult};

mod error;

#[cfg(target_os = "macos")]
mod vz;

#[cfg(target_os = "macos")]
pub use vz::run;

#[cfg(not(target_os = "macos"))]
use std::process::ExitCode;

#[cfg(not(target_os = "macos"))]
use crate::contract::Contract;

#[cfg(test)]
fn runner_test_contract() -> anyhow::Result<crate::contract::Contract> {
    use anyhow::Context as _;
    use serde_json::Value;

    use crate::contract::ContractDocument;

    const ROOT_PLACEHOLDER: &str = "${ROOT}";
    const VALID_CONTRACT_JSON: &str = include_str!("../contract/fixtures/valid-contract.json");

    /// Replaces fixture root placeholders with the test temp directory.
    fn replace_root_placeholder(value: &mut Value, root: &str) {
        match value {
            Value::String(text) => {
                if text.contains(ROOT_PLACEHOLDER) {
                    *text = text.replace(ROOT_PLACEHOLDER, root);
                }
            }
            Value::Array(values) => {
                for value in values {
                    replace_root_placeholder(value, root);
                }
            }
            Value::Object(values) => {
                for value in values.values_mut() {
                    replace_root_placeholder(value, root);
                }
            }
            Value::Bool(_) | Value::Null | Value::Number(_) => {}
        }
    }

    let temp = tempfile::tempdir()?;
    for artifact in [
        "firma-vz-runner",
        "vmlinuz",
        "initrd.img",
        "rootfs.img",
        "seccomp.bpf",
    ] {
        std::fs::write(temp.path().join(artifact), artifact)?;
    }

    std::fs::create_dir(temp.path().join("runtime"))?;

    let root = temp
        .path()
        .to_str()
        .context("test contract root must be UTF-8")?;
    let mut json = serde_json::from_str::<Value>(VALID_CONTRACT_JSON)?;
    replace_root_placeholder(&mut json, root);

    let contract_path = temp.path().join("vz-guest-launch.json");
    std::fs::write(&contract_path, serde_json::to_vec(&json)?)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&contract_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(ContractDocument::read_from_path(&contract_path)?.validate()?)
}

/// Rejects VZ runner execution on non-macOS hosts after contract validation.
///
/// The binary is intentionally macOS-only for now because this runner targets
/// Apple Virtualization.framework. Keeping the unsupported-host path behind the
/// same function preserves the CLI contract on every platform.
#[cfg(not(target_os = "macos"))]
pub fn run(contract: &Contract) -> RunnerResult<ExitCode> {
    Err(RunnerError::UnsupportedHost {
        version: contract.version(),
        sandbox_id: contract.sandbox_id().to_string(),
    })
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use anyhow::{Result, anyhow};

    use super::{RunnerError, run, runner_test_contract};

    #[test]
    fn run_rejects_unsupported_host() -> Result<()> {
        let contract = runner_test_contract()?;
        let error = run(&contract).err().ok_or_else(|| {
            anyhow!("non-macOS runner should reject execution after contract validation")
        })?;

        assert!(matches!(
            error,
            RunnerError::UnsupportedHost { version: 1, ref sandbox_id }
                if sandbox_id == "sandbox-test"
        ));

        Ok(())
    }
}

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

mod contract;
mod runner;
mod vm;

#[derive(Debug, Parser)]
#[command(
    name = "firma-vz-runner",
    version,
    about = "Run an OpenFirma macOS VZ guest launch contract"
)]
struct Args {
    #[arg(long, value_name = "PATH")]
    launch_contract: PathBuf,

    #[arg(long, hide = true)]
    validate_only: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("firma-vz-runner: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<ExitCode> {
    let contract = contract::ContractDocument::read_from_path(&args.launch_contract)?.validate()?;
    let vm_plan = vm::VmPlan::from_contract(&contract)?;

    if args.validate_only {
        println!(
            "validation ok: contract=checked vm_plan=checked sandbox_id={} version={}",
            contract.sandbox_id(),
            contract.version()
        );
        return Ok(ExitCode::SUCCESS);
    }

    Ok(runner::run(&vm_plan)?)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use anyhow::Result;
    use serde_json::Value;

    use super::{Args, run};

    const ROOT_PLACEHOLDER: &str = "${ROOT}";
    const VALID_CONTRACT_JSON: &str = include_str!("contract/fixtures/valid-contract.json");
    const VALID_ROOTFS_SIZE_BYTES: u64 = 512;
    const UNALIGNED_ROOTFS_SIZE_BYTES: u64 = 513;

    #[test]
    fn validate_only_succeeds_after_vm_plan_preparation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let contract_path = temp
            .path()
            .join("runtime")
            .join("vz-guest")
            .join("vz-guest-launch.json");
        write_contract_with_rootfs_size(temp.path(), &contract_path, VALID_ROOTFS_SIZE_BYTES)?;

        let code = run(&Args {
            launch_contract: contract_path,
            validate_only: true,
        })?;

        assert_eq!(code, super::ExitCode::SUCCESS);
        Ok(())
    }

    #[test]
    fn validate_only_fails_when_vm_plan_is_not_launchable() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let contract_path = temp
            .path()
            .join("runtime")
            .join("vz-guest")
            .join("vz-guest-launch.json");
        write_contract_with_rootfs_size(temp.path(), &contract_path, UNALIGNED_ROOTFS_SIZE_BYTES)?;

        let error = run(&Args {
            launch_contract: contract_path,
            validate_only: true,
        })
        .err()
        .ok_or_else(|| anyhow::anyhow!("validate-only should fail on invalid VM plan"))?;

        assert!(error.to_string().contains("guest.rootfs size"));
        Ok(())
    }

    /// Writes a valid contract with a rootfs fixture of the requested size.
    fn write_contract_with_rootfs_size(
        root: &Path,
        contract_path: &Path,
        rootfs_size: u64,
    ) -> Result<()> {
        if let Some(contract_dir) = contract_path.parent() {
            std::fs::create_dir_all(contract_dir)?;
        }

        for artifact in ["firma-vz-runner", "vmlinuz", "initrd.img", "seccomp.bpf"] {
            std::fs::write(root.join(artifact), artifact)?;
        }
        let rootfs = std::fs::File::create(root.join("rootfs.img"))?;
        rootfs.set_len(rootfs_size)?;

        let contract = valid_contract_json(root)?;
        std::fs::write(contract_path, serde_json::to_vec(&contract)?)?;
        make_contract_file_owner_only(contract_path)?;
        Ok(())
    }

    /// Loads the shared valid contract fixture with its root placeholder resolved.
    fn valid_contract_json(root: &Path) -> Result<Value> {
        let mut contract = serde_json::from_str(VALID_CONTRACT_JSON)?;
        replace_root_placeholder(
            &mut contract,
            root.to_str()
                .ok_or_else(|| anyhow::anyhow!("test contract root path must be UTF-8"))?,
        );
        Ok(contract)
    }

    /// Replaces all root placeholders inside a JSON value tree.
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

    /// Applies owner-only contract file custody on platforms that support it.
    #[cfg(unix)]
    fn make_contract_file_owner_only(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(path, permissions)?;
        Ok(())
    }

    /// Keeps the test helper portable on non-Unix hosts.
    #[cfg(not(unix))]
    fn make_contract_file_owner_only(path: &Path) -> Result<()> {
        let _ = std::fs::metadata(path)?;
        Ok(())
    }
}

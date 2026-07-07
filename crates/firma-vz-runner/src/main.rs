use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

mod contract;
#[cfg(any(target_os = "macos", test))]
mod guest;
mod runner;
mod vm;

#[cfg(test)]
pub(crate) mod test_utils;

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

/// Parses CLI arguments and maps runner failures to a process exit code.
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

/// Validates the launch contract and optionally starts the configured VM.
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
    use anyhow::Result;

    use super::{Args, run};
    use crate::test_utils::{
        UNALIGNED_ROOTFS_SIZE_BYTES, VALID_ROOTFS_SIZE_BYTES, make_contract_file_owner_only,
        write_contract_at,
    };

    #[test]
    fn validate_only_succeeds_after_vm_plan_preparation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let contract_path = temp
            .path()
            .join("runtime")
            .join("vz-guest")
            .join("vz-guest-launch.json");
        write_contract_at(
            temp.path(),
            temp.path(),
            &temp.path().join("runtime"),
            &contract_path,
            VALID_ROOTFS_SIZE_BYTES,
        )?;
        make_contract_file_owner_only(&contract_path)?;

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
        write_contract_at(
            temp.path(),
            temp.path(),
            &temp.path().join("runtime"),
            &contract_path,
            UNALIGNED_ROOTFS_SIZE_BYTES,
        )?;
        make_contract_file_owner_only(&contract_path)?;

        let error = run(&Args {
            launch_contract: contract_path,
            validate_only: true,
        })
        .err()
        .ok_or_else(|| anyhow::anyhow!("validate-only should fail on invalid VM plan"))?;

        assert!(error.to_string().contains("guest.rootfs size"));
        Ok(())
    }
}

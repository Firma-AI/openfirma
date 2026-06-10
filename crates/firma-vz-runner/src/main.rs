use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

mod contract;
mod runner;

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

    if args.validate_only {
        println!(
            "contract ok: sandbox_id={} version={}",
            contract.sandbox_id(),
            contract.version()
        );
        return Ok(ExitCode::SUCCESS);
    }

    Ok(runner::run(&contract)?)
}

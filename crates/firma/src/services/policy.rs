//! Runner for `firma policy` subcommands.

use std::process::ExitCode;

use clap::ValueEnum as _;

use crate::args::config::{Mapping, Posture};
use crate::args::policy::{PolicyArgs, PolicyCommand};

/// # Errors
///
/// Returns an error on I/O or policy parse failure.
pub fn run(args: PolicyArgs) -> anyhow::Result<ExitCode> {
    match args.command {
        PolicyCommand::List => Ok(list()),
        PolicyCommand::Validate { file } => crate::policy::validate::run(&file),
        PolicyCommand::Test { fixture } => crate::policy::test_fixture::run(&fixture),
    }
}

pub fn list() -> ExitCode {
    println!("Postures  (--posture):\n");
    for p in Posture::value_variants() {
        println!("  {:<28}  {}", p.file_name(), p.description());
    }
    println!("\nMappings  (--mapping, repeatable):\n");
    for m in Mapping::value_variants() {
        println!("  {:<28}  {}", m.as_str(), m.description());
    }
    println!();
    ExitCode::SUCCESS
}

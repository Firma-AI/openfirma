//! Runner for `firma policy` subcommands.

use std::process::ExitCode;

use clap::ValueEnum as _;

use crate::args::init::{Mapping, Posture};
use crate::args::policy::{PolicyArgs, PolicyCommand};

pub fn run(args: &PolicyArgs) -> ExitCode {
    match args.command {
        PolicyCommand::List => list(),
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

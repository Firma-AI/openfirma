//! Hidden `__supervise` entry.

use std::process::ExitCode;

use tracing::{error, info};

use crate::args::supervise::Args;

pub fn run(args: Args) -> ExitCode {
    let Args { state_dir } = args;
    info!(state_dir = %state_dir.display(), "supervisor process starting");
    match firma_stack::supervise(&state_dir) {
        Ok(()) => {
            info!("supervisor exited cleanly");
            ExitCode::SUCCESS
        }
        Err(err) => {
            error!(error = %err, "supervisor failed");
            eprintln!("firma __supervise: {err}");
            ExitCode::from(2)
        }
    }
}

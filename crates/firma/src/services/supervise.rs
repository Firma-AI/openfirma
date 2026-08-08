//! Hidden `__supervise` entry.

use std::process::ExitCode;

use tracing::{error, info};

use crate::args::supervise::Args;

pub fn run(args: Args) -> ExitCode {
    let Args {
        state_dir,
        config,
        generation,
        firma_bin,
    } = args;
    info!(state_dir = %state_dir.display(), "supervisor process starting");
    let config = firma_stack::StackConfig {
        config_file: config,
        firma_bin,
    };
    match firma_stack::supervise_owned_generation(&config, &state_dir, generation) {
        Ok(()) => {
            info!("supervisor exited cleanly");
            ExitCode::SUCCESS
        }
        Err(err) => {
            error!(error = %err, "supervisor failed");
            crate::output::err(format!("__supervise: {err}"));
            ExitCode::from(2)
        }
    }
}

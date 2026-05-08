//! Runner for `firma run`.

use std::process::ExitCode;

use firma_run::runtime::{RunInput, execute_run};

use crate::args::run::RunArgs;

/// Run the `firma run` subcommand. Sync — must not be called from inside
/// a tokio runtime.
///
/// # Errors
///
/// Returns an error if `firma_run` fails to launch or supervise the
/// wrapped command.
pub fn run(args: RunArgs) -> anyhow::Result<ExitCode> {
    let input = RunInput {
        profile: args.profile,
        config: args.config,
        backend: args.backend.map(Into::into),
        sidecar_endpoint: args.sidecar_endpoint,
        capability_file: args.capability_file,
        identity_mode: args.identity_mode.map(Into::into),
        preserve_host_user: args.preserve_host_user,
        print_effective_config: args.print_effective_config,
        command: args.command,
    };
    match execute_run(&input) {
        Ok(code) => Ok(exit_code(code)),
        Err(error) => Err(anyhow::anyhow!("{error}")),
    }
}

fn exit_code(code: i32) -> ExitCode {
    if code == 0 {
        ExitCode::SUCCESS
    } else {
        let exit = u8::try_from(code).unwrap_or(1);
        ExitCode::from(exit)
    }
}

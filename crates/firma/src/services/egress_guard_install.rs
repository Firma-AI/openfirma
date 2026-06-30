//! Runner for `firma __egress-guard-install`.
//!
//! Runs inside the sandbox as the agent's launcher: installs the seccomp
//! loopback filter, hands the notification listener fd to the host supervisor,
//! then `execve`s the wrapped command. On any failure it returns an error so
//! the wrapped command never starts — fail closed.

use std::process::ExitCode;

use crate::args::run::EgressGuardInstallArgs;

/// Install the loopback egress guard and exec the wrapped command.
///
/// # Errors
///
/// Returns an error when the guard cannot be installed, the listener fd cannot
/// be handed to the supervisor, or `exec` fails. On success this never returns
/// (the process image is replaced by the wrapped command).
pub fn run(args: EgressGuardInstallArgs) -> anyhow::Result<ExitCode> {
    let EgressGuardInstallArgs {
        supervisor_socket,
        command,
    } = args;
    match firma_run::egress_guard::install_and_exec(&supervisor_socket, &command) {
        Ok(never) => match never {},
        Err(error) => Err(anyhow::anyhow!("{error}")),
    }
}

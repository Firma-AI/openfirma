//! Runner for `firma __egress-guarded-run`.
//!
//! Runs inside the sandbox as the agent's launcher: installs the seccomp
//! loopback filter, hands the notification listener fd to the host supervisor,
//! then `execve`s the wrapped command. On any failure it returns an error so
//! the wrapped command never starts — fail closed.

use std::process::ExitCode;

use crate::args::run::EgressGuardedRunArgs;

/// Install the loopback egress guard and exec the wrapped command.
///
/// # Errors
///
/// Returns an error when the guard cannot be installed, the listener fd cannot
/// be handed to the supervisor, or `exec` fails. On success this never returns
/// (the process image is replaced by the wrapped command).
#[cfg(target_os = "linux")]
pub fn run(args: EgressGuardedRunArgs) -> anyhow::Result<ExitCode> {
    let EgressGuardedRunArgs {
        supervisor_socket,
        command,
    } = args;
    let never = firma_run::egress_guard::install_and_exec(&supervisor_socket, &command)?;
    match never {}
}

/// The seccomp loopback egress guard has no non-Linux implementation. The
/// `__egress-guarded-run` wrapper is only ever spawned by the Linux structural
/// path, so on other targets it fails closed rather than silently running the
/// wrapped command unguarded.
///
/// # Errors
///
/// Always returns an error: the guard is Linux-only.
#[cfg(not(target_os = "linux"))]
pub fn run(_args: EgressGuardedRunArgs) -> anyhow::Result<ExitCode> {
    anyhow::bail!("the loopback egress guard is only supported on Linux")
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use std::path::PathBuf;

    use super::run;
    use crate::args::run::EgressGuardedRunArgs;

    #[test]
    fn run_fails_closed_when_supervisor_socket_is_unreachable() {
        // install_and_exec connects to the supervisor before installing any
        // filter or exec'ing; a missing socket errors there, so run returns Err
        // and the wrapped command never starts.
        let args = EgressGuardedRunArgs {
            supervisor_socket: PathBuf::from("/nonexistent/firma-egress-guard.sock"),
            command: vec!["/bin/true".to_string()],
        };
        assert!(run(args).is_err());
    }
}

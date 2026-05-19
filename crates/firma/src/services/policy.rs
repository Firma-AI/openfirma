//! Wire `firma policy` CLI args to the policy module.

use std::process::ExitCode;

use crate::args::policy::{PolicyArgs, PolicyCommand};

/// Dispatch the `firma policy` subcommand.
///
/// Routes `validate` to [`crate::policy::validate::run`] and `test` to
/// [`crate::policy::test_fixture::run`].
///
/// # Errors
///
/// Neither subcommand returns `Err`: each maps every failure to a non-zero
/// [`ExitCode`] (fail-closed). The `anyhow::Result` is the shared dispatch
/// contract used by `main.rs`.
pub fn run(args: PolicyArgs) -> anyhow::Result<ExitCode> {
    match args.command {
        PolicyCommand::Validate { file } => crate::policy::validate::run(&file),
        PolicyCommand::Test { fixture } => crate::policy::test_fixture::run(&fixture),
    }
}

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

use super::contract::Contract;
use super::error::{InitError, InitResult};
use super::log;
use super::mount::create_dir_path;

/// Guest command completion reported back to the host runner.
#[derive(Debug)]
pub enum CommandOutcome {
    /// Process exited normally with an exit status.
    Exited(u8),
    /// Process terminated because of a Unix signal.
    Signaled(i32),
}

/// Runs the accepted launch contract command.
pub fn execute_contract(contract: &Contract) -> InitResult<CommandOutcome> {
    run_command(contract)
}

/// Spawns the payload with the contract-provided cwd, argv, and environment.
fn run_command(contract: &Contract) -> InitResult<CommandOutcome> {
    let command = contract.command();
    create_dir_path(&command.cwd)?;
    log(&format!(
        "running command: {} {:?} cwd={}",
        command.executable,
        command.args,
        command.cwd.display()
    ));

    let status = Command::new(&command.executable)
        .args(&command.args)
        .current_dir(&command.cwd)
        .env_clear()
        .envs(&command.env)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| InitError::SpawnCommand {
            executable: command.executable.clone(),
            source: error,
        })?;

    match (status.code(), status.signal()) {
        (Some(code), _) => {
            let code = u8::try_from(code).unwrap_or(u8::MAX);
            log(&format!("command exited with status {code}"));
            Ok(CommandOutcome::Exited(code))
        }
        (None, Some(signal)) => {
            log(&format!("command terminated by signal {signal}"));
            Ok(CommandOutcome::Signaled(signal))
        }
        (None, None) => Err(InitError::CommandMissingStatus),
    }
}

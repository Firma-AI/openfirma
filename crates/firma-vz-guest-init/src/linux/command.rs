use std::fs::File;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};

use super::contract::Contract;
use super::error::{InitError, InitResult};
use super::log;
use super::mount::create_dir_path;

const GUEST_STDIN_FILE: &str = "guest-stdin.bin";
const GUEST_STDOUT_FILE: &str = "guest-stdout.log";
const GUEST_STDERR_FILE: &str = "guest-stderr.log";

/// Guest command completion reported back to the host runner.
#[derive(Debug)]
pub enum CommandOutcome {
    /// Process exited normally with an exit status.
    Exited(u8),
    /// Process terminated because of a Unix signal.
    Signaled(i32),
}

/// Runs the accepted launch contract command.
pub fn execute_contract(contract_path: &Path, contract: &Contract) -> InitResult<CommandOutcome> {
    run_command(contract_path, contract)
}

/// Spawns the payload with the contract-provided cwd, argv, and environment.
fn run_command(contract_path: &Path, contract: &Contract) -> InitResult<CommandOutcome> {
    let command = contract.command();
    create_dir_path(&command.cwd)?;
    let stdin = command_stdin(contract_path)?;
    let stdout = create_command_stdio_file(contract_path, GUEST_STDOUT_FILE)?;
    let stderr = create_command_stdio_file(contract_path, GUEST_STDERR_FILE)?;

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
        .stdin(stdin)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
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

/// Opens optional guest stdin captured by the host runner.
fn command_stdin(contract_path: &Path) -> InitResult<Stdio> {
    let Some(parent) = contract_path.parent() else {
        return Ok(Stdio::null());
    };
    let stdin_path = parent.join(GUEST_STDIN_FILE);
    match File::open(&stdin_path) {
        Ok(file) => {
            log(&format!("using guest stdin {}", stdin_path.display()));
            Ok(Stdio::from(file))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Stdio::null()),
        Err(source) => Err(InitError::OpenGuestStdin {
            path: stdin_path,
            source,
        }),
    }
}

/// Creates an owner-only command output stream file for host replay.
fn create_command_stdio_file(contract_path: &Path, file_name: &str) -> InitResult<File> {
    let parent =
        contract_path
            .parent()
            .ok_or_else(|| InitError::CommandStdioPathWithoutParent {
                path: contract_path.to_path_buf(),
            })?;
    let path = parent.join(file_name);
    let file = File::options()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .map_err(|source| InitError::CreateCommandStdioFile {
            path: path.clone(),
            source,
        })?;
    let mut permissions = file
        .metadata()
        .map_err(|source| InitError::StatCommandStdioFile {
            path: path.clone(),
            source,
        })?
        .permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)
        .map_err(|source| InitError::SetCommandStdioFilePermissions { path, source })?;
    Ok(file)
}

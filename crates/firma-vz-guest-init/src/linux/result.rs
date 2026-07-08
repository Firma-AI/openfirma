use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde::Serialize;

use super::command::CommandOutcome;
use super::error::{InitError, InitResult};
use super::log;

const RUNTIME_SHARE: &str = "/firma-shares/runtime";
const RESULT_VERSION: u32 = 1;
const GUEST_RESULT_FILE: &str = "guest-result.json";

/// Status vocabulary written to `guest-result.json`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum GuestStatus {
    /// Payload exited with a status code.
    Exited,
    /// Payload terminated because of a Unix signal.
    Signaled,
    /// Guest setup failed before payload spawn.
    SetupError,
    /// Payload spawn failed after guest setup.
    SpawnError,
}

/// Writes a setup failure if the launch contract result path is mounted.
pub fn write_setup_error(contract_path: &Path, error: &InitError) -> InitResult<()> {
    if !contract_path.starts_with(RUNTIME_SHARE) {
        return Ok(());
    }
    write_guest_result(contract_path, &GuestResult::setup_error(error.to_string()))
}

/// Writes the final payload result next to the launch contract.
pub fn write_result(contract_path: &Path, result: &InitResult<CommandOutcome>) -> InitResult<()> {
    write_guest_result(contract_path, &guest_result_from_command_result(result))
}

/// Converts a command execution result into the JSON result payload shape.
pub fn guest_result_from_command_result(result: &InitResult<CommandOutcome>) -> GuestResult {
    match result {
        Ok(CommandOutcome::Exited(code)) => GuestResult::exited(*code),
        Ok(CommandOutcome::Signaled(signal)) => GuestResult::signaled(*signal),
        Err(error @ InitError::SpawnCommand { .. }) => GuestResult::spawn_error(error.to_string()),
        Err(error) => GuestResult::setup_error(error.to_string()),
    }
}

/// Atomically writes `guest-result.json` with owner-only permissions.
fn write_guest_result(contract_path: &Path, result: &GuestResult) -> InitResult<()> {
    let parent = contract_path
        .parent()
        .ok_or_else(|| InitError::ResultPathWithoutParent {
            path: contract_path.to_path_buf(),
        })?;
    let result_path = parent.join(GUEST_RESULT_FILE);
    let temp_path = parent.join(format!("{GUEST_RESULT_FILE}.tmp"));
    let json =
        serde_json::to_vec_pretty(result).map_err(|error| InitError::SerializeGuestResult {
            path: result_path.clone(),
            source: error,
        })?;

    fs::write(&temp_path, json).map_err(|error| InitError::WriteGuestResultTemp {
        path: temp_path.clone(),
        source: error,
    })?;

    let mut permissions = fs::metadata(&temp_path)
        .map_err(|error| InitError::StatGuestResultTemp {
            path: temp_path.clone(),
            source: error,
        })?
        .permissions();

    permissions.set_mode(0o600);
    fs::set_permissions(&temp_path, permissions).map_err(|error| {
        InitError::SetGuestResultTempPermissions {
            path: temp_path.clone(),
            source: error,
        }
    })?;

    fs::rename(&temp_path, &result_path).map_err(|error| InitError::RenameGuestResult {
        from: temp_path,
        to: result_path.clone(),
        source: error,
    })?;

    log(&format!("wrote guest result {}", result_path.display()));

    Ok(())
}

/// Serialized result returned from guest init to the host runner.
#[derive(Debug, Serialize)]
pub struct GuestResult {
    version: u32,
    status: GuestStatus,
    exit_code: Option<u8>,
    signal: Option<i32>,
    error: Option<String>,
}

impl GuestResult {
    /// Builds a successful exit result.
    const fn exited(exit_code: u8) -> Self {
        Self {
            version: RESULT_VERSION,
            status: GuestStatus::Exited,
            exit_code: Some(exit_code),
            signal: None,
            error: None,
        }
    }

    /// Builds a signal termination result.
    const fn signaled(signal: i32) -> Self {
        Self {
            version: RESULT_VERSION,
            status: GuestStatus::Signaled,
            exit_code: None,
            signal: Some(signal),
            error: None,
        }
    }

    /// Builds a setup failure result.
    fn setup_error(error: String) -> Self {
        Self {
            version: RESULT_VERSION,
            status: GuestStatus::SetupError,
            exit_code: None,
            signal: None,
            error: Some(error),
        }
    }

    /// Builds a payload spawn failure result.
    fn spawn_error(error: String) -> Self {
        Self {
            version: RESULT_VERSION,
            status: GuestStatus::SpawnError,
            exit_code: None,
            signal: None,
            error: Some(error),
        }
    }
}

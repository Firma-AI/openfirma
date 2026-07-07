use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::command::CommandOutcome;
use super::contract::Contract;
use super::error::{InitError, InitResult};
use super::log;

const RUNTIME_SHARE: &str = "/firma-shares/runtime";
const RESULT_VERSION: u32 = 1;
const GUEST_RESULT_FILE: &str = "guest-result.json";
const GUEST_HEARTBEAT_FILE: &str = "guest-heartbeat.json";

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

/// Writes a guest heartbeat after a major startup milestone succeeds.
pub fn write_heartbeat(
    contract_path: &Path,
    contract: &Contract,
    phase: GuestHeartbeatPhase,
) -> InitResult<()> {
    let heartbeat = GuestHeartbeat {
        version: RESULT_VERSION,
        phase,
        contract_path,
        executable: Some(&contract.command().executable),
        cwd: Some(&contract.command().cwd),
        mounts: Some(contract.mounts().len()),
    };
    let heartbeat_path = write_guest_json_file(contract_path, GUEST_HEARTBEAT_FILE, &heartbeat)?;
    log(&format!(
        "wrote guest heartbeat phase={} path={}",
        heartbeat.phase.label(),
        heartbeat_path.display()
    ));
    Ok(())
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
    let result_path = write_guest_json_file(contract_path, GUEST_RESULT_FILE, result)?;
    log(&format!("wrote guest result {}", result_path.display()));
    Ok(())
}

/// Atomically writes a guest JSON file with owner-only permissions.
fn write_guest_json_file<T: Serialize>(
    contract_path: &Path,
    file_name: &str,
    value: &T,
) -> InitResult<PathBuf> {
    let parent = contract_path
        .parent()
        .ok_or_else(|| InitError::ResultPathWithoutParent {
            path: contract_path.to_path_buf(),
        })?;
    let result_path = parent.join(file_name);
    let temp_path = parent.join(format!("{file_name}.tmp"));
    let json =
        serde_json::to_vec_pretty(value).map_err(|error| InitError::SerializeGuestResult {
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

    Ok(result_path)
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

/// Guest startup phase written to the heartbeat file.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestHeartbeatPhase {
    /// The runtime share was mounted and the contract path is reachable.
    RuntimeMounted,
    /// The launch contract was read and accepted.
    ContractReady,
    /// The contract mounts were exposed inside the guest.
    MountsReady,
}

impl GuestHeartbeatPhase {
    /// Returns the serialized phase label used in logs.
    const fn label(self) -> &'static str {
        match self {
            Self::RuntimeMounted => "runtime_mounted",
            Self::ContractReady => "contract_ready",
            Self::MountsReady => "mounts_ready",
        }
    }
}

/// Serialized startup heartbeat returned from guest init to the host runner.
#[derive(Debug, Serialize)]
struct GuestHeartbeat<'a> {
    version: u32,
    phase: GuestHeartbeatPhase,
    contract_path: &'a Path,
    executable: Option<&'a str>,
    cwd: Option<&'a Path>,
    mounts: Option<usize>,
}

/// Writes a guest heartbeat before the launch contract has been accepted.
pub fn write_boot_heartbeat(contract_path: &Path, phase: GuestHeartbeatPhase) -> InitResult<()> {
    let heartbeat = GuestHeartbeat {
        version: RESULT_VERSION,
        phase,
        contract_path,
        executable: None,
        cwd: None,
        mounts: None,
    };
    let heartbeat_path = write_guest_json_file(contract_path, GUEST_HEARTBEAT_FILE, &heartbeat)?;
    log(&format!(
        "wrote guest heartbeat phase={} path={}",
        heartbeat.phase.label(),
        heartbeat_path.display()
    ));
    Ok(())
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

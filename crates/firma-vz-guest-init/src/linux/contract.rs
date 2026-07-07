use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::error::{InitError, InitResult};
use super::log;

const SECRET_ENV_KEYS: &[&str] = &["FIRMA_CAPABILITY_TOKEN"];

/// Raw launch contract shape read from the runtime share.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchContract {
    /// Contract schema version.
    pub version: u32,
    /// Command payload to run inside the guest.
    pub command: CommandContract,
    /// Guest mount targets requested by the host runner.
    pub mounts: Vec<MountContract>,
}

/// Launch contract that has passed guest-side validation.
#[derive(Debug)]
pub struct Contract {
    contract: LaunchContract,
}

impl Contract {
    /// Returns the accepted command payload.
    pub fn command(&self) -> &CommandContract {
        &self.contract.command
    }

    /// Returns the accepted mount targets.
    pub fn mounts(&self) -> &[MountContract] {
        &self.contract.mounts
    }
}

impl TryFrom<LaunchContract> for Contract {
    type Error = InitError;

    /// Accepts a parsed launch contract after guest-side validation.
    fn try_from(contract: LaunchContract) -> Result<Self, Self::Error> {
        validate_contract(&contract)?;
        Ok(Self { contract })
    }
}

/// Command payload from the launch contract.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandContract {
    /// Executable path or name to run.
    pub executable: String,
    /// Arguments passed to the executable.
    pub args: Vec<String>,
    /// Working directory created and selected before process spawn.
    pub cwd: PathBuf,
    /// Complete guest process environment.
    pub env: BTreeMap<String, String>,
}

/// Mount target requested by the launch contract.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountContract {
    /// Guest path where the indexed virtiofs share should be bind-mounted.
    pub target: PathBuf,
    /// Whether the bind mount should be remounted read-only.
    pub read_only: bool,
}

/// Reads and parses a launch contract without accepting it for execution.
pub fn read_contract(contract_path: &Path) -> InitResult<LaunchContract> {
    let metadata = fs::metadata(contract_path).map_err(|error| InitError::ContractNotVisible {
        path: contract_path.to_path_buf(),
        source: error,
    })?;

    if !metadata.is_file() {
        return Err(InitError::ContractNotRegularFile {
            path: contract_path.to_path_buf(),
        });
    }

    log(&format!(
        "contract visible at {} ({} bytes)",
        contract_path.display(),
        metadata.len()
    ));

    let json = fs::read(contract_path).map_err(|error| InitError::ReadContract {
        path: contract_path.to_path_buf(),
        source: error,
    })?;

    serde_json::from_slice(&json).map_err(|error| InitError::ParseContract {
        path: contract_path.to_path_buf(),
        source: error,
    })
}

/// Reads, validates, and accepts a launch contract for execution.
pub fn accept_contract(contract_path: &Path) -> InitResult<Contract> {
    read_contract(contract_path)?.try_into()
}

/// Validates contract schema semantics before guest execution can start.
pub fn validate_contract(contract: &LaunchContract) -> InitResult<()> {
    if contract.version != 1 {
        return Err(InitError::InvalidContractVersion {
            version: contract.version,
        });
    }

    if contract.command.executable.trim().is_empty() {
        return Err(InitError::EmptyExecutable);
    }

    if !contract.command.cwd.is_absolute() {
        return Err(InitError::RelativeCommandCwd {
            path: contract.command.cwd.clone(),
        });
    }

    for key in SECRET_ENV_KEYS {
        if contract.command.env.contains_key(*key) {
            return Err(InitError::SecretEnvKey { key });
        }
    }

    for mount in &contract.mounts {
        if !mount.target.is_absolute() {
            return Err(InitError::RelativeMountTarget {
                path: mount.target.clone(),
            });
        }
    }

    Ok(())
}

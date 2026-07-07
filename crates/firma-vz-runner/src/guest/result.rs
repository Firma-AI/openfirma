use std::path::Path;
use std::process::ExitCode;

use serde::Deserialize;

use super::{GuestResultError, GuestResultResult};

const RESULT_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestResult {
    version: u32,
    status: GuestStatus,
    exit_code: Option<u8>,
    signal: Option<i32>,
    error: Option<String>,
}

impl GuestResult {
    /// Reads, parses, and validates a guest result file.
    pub fn read(path: &Path) -> GuestResultResult<Self> {
        let json = std::fs::read(path).map_err(|source| GuestResultError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let result =
            serde_json::from_slice::<Self>(&json).map_err(|source| GuestResultError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        result.validate()?;
        Ok(result)
    }

    /// Converts a validated guest result into the runner process exit code.
    pub fn to_exit_code(&self) -> GuestResultResult<ExitCode> {
        match self.status {
            GuestStatus::Exited => {
                let code = self.exit_code.ok_or(GuestResultError::MissingExitCode)?;
                Ok(ExitCode::from(code))
            }
            GuestStatus::Signaled => {
                let signal = self.signal.ok_or(GuestResultError::MissingSignal)?;
                let code = 128_u8.saturating_add(u8::try_from(signal).unwrap_or(u8::MAX));
                Ok(ExitCode::from(code))
            }
            GuestStatus::SetupError | GuestStatus::SpawnError => {
                let error = self.guest_error()?;
                eprintln!("firma-vz-runner: guest {}: {error}", self.status.label());
                Ok(ExitCode::FAILURE)
            }
        }
    }

    /// Validates the result shape before the runner trusts it.
    fn validate(&self) -> GuestResultResult<()> {
        if self.version != RESULT_VERSION {
            return Err(GuestResultError::UnsupportedVersion {
                found: self.version,
                supported: RESULT_VERSION,
            });
        }
        match self.status {
            GuestStatus::Exited => {
                if self.exit_code.is_none() {
                    return Err(GuestResultError::MissingExitCode);
                }
            }
            GuestStatus::Signaled => {
                if self.signal.is_none() {
                    return Err(GuestResultError::MissingSignal);
                }
            }
            GuestStatus::SetupError | GuestStatus::SpawnError => {
                let _error = self.guest_error()?;
            }
        }
        Ok(())
    }

    /// Returns the guest error string for guest setup/spawn failures.
    fn guest_error(&self) -> GuestResultResult<&str> {
        self.error
            .as_deref()
            .filter(|error| !error.is_empty())
            .ok_or(GuestResultError::MissingError)
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GuestStatus {
    Exited,
    Signaled,
    SetupError,
    SpawnError,
}

impl GuestStatus {
    /// Returns the label used in runner diagnostics.
    const fn label(self) -> &'static str {
        match self {
            Self::Exited => "exited",
            Self::Signaled => "signaled",
            Self::SetupError => "setup error",
            Self::SpawnError => "spawn error",
        }
    }
}

use std::net::SocketAddr;
use std::path::Path;

use super::error::{ContractValidationError, ValidationResult};

#[derive(Debug, Clone, Copy)]
/// Limits applied while preparing a raw launch contract for execution.
///
/// These bounds keep contract validation deterministic and prevent unbounded
/// input from reaching the runner planning code.
pub struct ContractValidationLimits {
    pub mounts: usize,
    pub env_vars: usize,
    pub env_key_len: usize,
    pub env_value_len: usize,
    pub command_args: usize,
    pub command_arg_len: usize,
    pub path_len: usize,
    pub dns_stub_addr_len: usize,
    pub attribution_headers: usize,
    pub attribution_header_name_len: usize,
    pub attribution_header_value_len: usize,
}

impl Default for ContractValidationLimits {
    fn default() -> Self {
        Self {
            mounts: 64,
            env_vars: 256,
            env_key_len: 256,
            env_value_len: 8192,
            command_args: 256,
            command_arg_len: 4096,
            path_len: 4096,
            dns_stub_addr_len: 128,
            attribution_headers: 32,
            attribution_header_name_len: 128,
            attribution_header_value_len: 1024,
        }
    }
}

/// Requires a contract path to be absolute, bounded, and present as a file.
pub fn require_file(
    field: &'static str,
    path: &Path,
    max_path_len: usize,
    is_file: &mut impl FnMut(&Path) -> bool,
) -> ValidationResult<()> {
    require_path(field, path, max_path_len)?;
    if !is_file(path) {
        return Err(ContractValidationError::MissingFile {
            field,
            path: path.to_path_buf(),
        });
    }

    Ok(())
}

/// Requires a contract path to be within the configured length limit and absolute.
pub fn require_path(field: &'static str, path: &Path, max_path_len: usize) -> ValidationResult<()> {
    require_len_at_most(
        field,
        path.as_os_str().to_string_lossy().len(),
        max_path_len,
    )?;

    require_absolute_path(field, path)
}

/// Requires a Linux guest path to be within the configured length limit and absolute.
pub fn require_guest_path(
    field: &'static str,
    path: &Path,
    max_path_len: usize,
) -> ValidationResult<()> {
    let path_text = path.as_os_str().to_string_lossy();
    require_len_at_most(field, path_text.len(), max_path_len)?;

    if !path_text.starts_with('/') {
        return Err(ContractValidationError::RelativePath {
            field,
            path: path.to_path_buf(),
        });
    }

    Ok(())
}

/// Requires a contract path to be absolute.
pub fn require_absolute_path(field: &'static str, path: &Path) -> ValidationResult<()> {
    if !path.is_absolute() {
        return Err(ContractValidationError::RelativePath {
            field,
            path: path.to_path_buf(),
        });
    }

    Ok(())
}

/// Requires an item count to stay within the configured contract limit.
pub fn require_count_at_most(
    field: &'static str,
    actual: usize,
    max: usize,
) -> ValidationResult<()> {
    if actual > max {
        return Err(ContractValidationError::TooManyItems { field, actual, max });
    }

    Ok(())
}

/// Requires a field length to stay within the configured contract limit.
pub fn require_len_at_most(field: &'static str, actual: usize, max: usize) -> ValidationResult<()> {
    if actual > max {
        return Err(ContractValidationError::FieldTooLong { field, actual, max });
    }

    Ok(())
}

/// Requires a socket address to parse and point at loopback.
pub fn require_loopback_socket_addr(
    field: &'static str,
    value: &str,
) -> ValidationResult<SocketAddr> {
    let addr = value.parse::<SocketAddr>().map_err(|source| {
        ContractValidationError::InvalidSocketAddr {
            field,
            value: value.to_string(),
            source,
        }
    })?;

    if !addr.ip().is_loopback() {
        return Err(ContractValidationError::NonLoopbackSocketAddr {
            field,
            value: value.to_string(),
        });
    }

    Ok(addr)
}

/// Requires a string field to contain non-whitespace content.
pub fn require_non_empty(field: &'static str, value: &str) -> ValidationResult<()> {
    if value.trim().is_empty() {
        return Err(ContractValidationError::EmptyField { field });
    }

    Ok(())
}

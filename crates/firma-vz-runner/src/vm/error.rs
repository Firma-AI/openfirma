use std::path::PathBuf;

use thiserror::Error;

use crate::contract::ContractValidationError;

pub type VmPlanResult<T> = std::result::Result<T, VmPlanError>;

#[derive(Debug, Error)]
pub enum VmPlanError {
    #[error("VZ launch contract source path is unavailable")]
    MissingSourcePath,
    #[error("VZ launch contract {contract_path} must live under runtime_dir {runtime_dir}")]
    ContractOutsideRuntimeDir {
        contract_path: PathBuf,
        runtime_dir: PathBuf,
    },
    #[error("runtime_dir must be an existing directory: {path}")]
    RuntimeDirMissing { path: PathBuf },
    #[error("stat rootfs image {path}: {source}")]
    RootfsMetadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "guest.rootfs size must be a multiple of {alignment_bytes} bytes: {path} has {size} bytes"
    )]
    RootfsUnaligned {
        path: PathBuf,
        size: u64,
        alignment_bytes: u64,
    },
    #[error("virtiofs mount source must be an existing directory: {path}")]
    MountSourceNotDirectory { path: PathBuf },
    #[error("read VZ Sidecar host endpoint from launch contract: {source}")]
    SidecarHostAddr {
        #[source]
        source: ContractValidationError,
    },
    #[error("{field} must be non-zero in the accepted command PTY plan")]
    InvalidCommandPtyPort { field: &'static str },
    #[error("accepted command PTY plan requires both data and control ports")]
    IncompleteCommandPtyPlan,
    #[error("secret_shims.shim_share_directory must be an existing directory: {path}")]
    ShimShareDirectoryMissing { path: PathBuf },
}

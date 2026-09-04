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
    #[error("canonicalize {field} path {path}: {source}")]
    CanonicalizePath {
        field: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    WritableShareOverlapsSensitivePath(Box<WritableShareOverlap>),
    #[error("accepted secret shims plan is missing canonical sensitive paths")]
    MissingCanonicalSensitivePaths,
    #[error("{field} must be non-zero in the accepted broker plan")]
    InvalidBrokerPort { field: &'static str },
    #[error("read guest broker address from launch contract: {source}")]
    GuestBrokerAddr {
        #[source]
        source: ContractValidationError,
    },
    #[error("accepted secret shims plan is missing its guest broker address")]
    MissingGuestBrokerAddr,
}

#[derive(Debug, Error)]
#[error(
    "writable guest share {share_name} source {share_source} aliases or overlaps {sensitive_field} {sensitive_path} (canonical paths: {canonical_share_source}, {canonical_sensitive_path})"
)]
pub struct WritableShareOverlap {
    pub share_name: String,
    pub share_source: PathBuf,
    pub canonical_share_source: PathBuf,
    pub sensitive_field: &'static str,
    pub sensitive_path: PathBuf,
    pub canonical_sensitive_path: PathBuf,
}

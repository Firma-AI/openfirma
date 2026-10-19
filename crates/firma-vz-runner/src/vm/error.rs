use std::path::PathBuf;

use thiserror::Error;

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
    GuestShareOverlapsSensitivePath(Box<GuestShareOverlap>),
}

#[derive(Debug, Error)]
#[error(
    "{share_access} guest share {share_name} source {share_source} aliases or overlaps {sensitive_field} {sensitive_path} (canonical paths: {canonical_share_source}, {canonical_sensitive_path})"
)]
pub struct GuestShareOverlap {
    pub share_name: String,
    pub share_access: &'static str,
    pub share_source: PathBuf,
    pub canonical_share_source: PathBuf,
    pub sensitive_field: &'static str,
    pub sensitive_path: PathBuf,
    pub canonical_sensitive_path: PathBuf,
}

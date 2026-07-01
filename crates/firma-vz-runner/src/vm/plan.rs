use std::path::{Component, Path, PathBuf};

use crate::contract::Contract;
use crate::vm::{VmPlanError, VmPlanResult};

pub const FIRMA_VIRTIOFS_TAG: &str = "firma";
const GUEST_RUNTIME_ROOT: &str = "/runtime";
const VZ_BLOCK_DEVICE_SECTOR_SIZE_BYTES: u64 = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmPlan {
    version: u32,
    sandbox_id: String,
    pub runtime_dir: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub rootfs: PathBuf,
    pub kernel_command_line: String,
    pub directory_shares: Vec<DirectorySharePlan>,
    pub network_devices: Vec<NetworkDevicePlan>,
}

impl VmPlan {
    /// Returns the launch contract version used to build this VM plan.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the sandbox id that this VM plan will launch.
    pub fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }

    /// Converts a validated launch contract into concrete VM launch inputs.
    ///
    /// This is the plan-time boundary between schema validation and runner
    /// execution. It checks that host paths have the properties needed by the
    /// VM backend before the runner starts building a Virtualization.framework
    /// configuration.
    pub fn from_contract(contract: &Contract) -> VmPlanResult<Self> {
        let source_contract = contract
            .source_path()
            .ok_or(VmPlanError::MissingSourcePath)?;
        let contract_relative_path = source_contract
            .strip_prefix(contract.runtime_dir())
            .map_err(|_| VmPlanError::ContractOutsideRuntimeDir {
                contract_path: source_contract.to_path_buf(),
                runtime_dir: contract.runtime_dir().to_path_buf(),
            })?;

        if !contract.runtime_dir().is_dir() {
            return Err(VmPlanError::RuntimeDirMissing {
                path: contract.runtime_dir().to_path_buf(),
            });
        }

        validate_rootfs(contract.guest().rootfs())?;

        let mut directory_shares = vec![DirectorySharePlan {
            name: "runtime".to_string(),
            source: contract.runtime_dir().to_path_buf(),
            read_only: true,
        }];

        for (index, mount) in contract.mounts().iter().enumerate() {
            if !mount.source().is_dir() {
                return Err(VmPlanError::MountSourceNotDirectory {
                    path: mount.source().to_path_buf(),
                });
            }
            directory_shares.push(DirectorySharePlan {
                name: format!("mount{index}"),
                source: mount.source().to_path_buf(),
                read_only: mount.read_only(),
            });
        }

        let guest_contract_path = guest_runtime_path(contract_relative_path);
        Ok(Self {
            version: contract.version(),
            sandbox_id: contract.sandbox_id().to_string(),
            runtime_dir: contract.runtime_dir().to_path_buf(),
            kernel: contract.guest().kernel().to_path_buf(),
            initrd: contract.guest().initrd().to_path_buf(),
            rootfs: contract.guest().rootfs().to_path_buf(),
            kernel_command_line: kernel_command_line(&guest_contract_path),
            directory_shares,
            network_devices: Vec::new(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectorySharePlan {
    pub name: String,
    pub source: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkDevicePlan {}

/// Builds the Linux boot arguments that point guest init at the launch contract.
fn kernel_command_line(guest_contract_path: &str) -> String {
    format!(
        "console=hvc0 root=/dev/vda rw firma.virtiofs_tag={FIRMA_VIRTIOFS_TAG} \
         firma.launch_contract={guest_contract_path} firma.network=none"
    )
}

/// Converts a host-relative runtime path into the Linux guest path.
fn guest_runtime_path(host_relative_path: &Path) -> String {
    let mut guest_path = String::from(GUEST_RUNTIME_ROOT);

    for component in host_relative_path.components() {
        if let Component::Normal(segment) = component {
            guest_path.push('/');
            guest_path.push_str(&segment.to_string_lossy());
        }
    }

    guest_path
}

/// Verifies that the rootfs image can be attached as a VZ block device.
fn validate_rootfs(path: &Path) -> VmPlanResult<()> {
    let metadata = std::fs::metadata(path).map_err(|source| VmPlanError::RootfsMetadata {
        path: path.to_path_buf(),
        source,
    })?;

    if metadata.len() % VZ_BLOCK_DEVICE_SECTOR_SIZE_BYTES != 0 {
        return Err(VmPlanError::RootfsUnaligned {
            path: path.to_path_buf(),
            size: metadata.len(),
            alignment_bytes: VZ_BLOCK_DEVICE_SECTOR_SIZE_BYTES,
        });
    }

    Ok(())
}

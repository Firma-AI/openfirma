use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Component, Path, PathBuf};

use firma_identifiers::SandboxId;

use crate::contract::{Contract, NetworkMode};
use crate::vm::error::WritableShareOverlap;
use crate::vm::{VmPlanError, VmPlanResult};

pub const FIRMA_VIRTIOFS_TAG: &str = "firma";
const GUEST_SHARE_ROOT: &str = "/firma-shares";
const VZ_BLOCK_DEVICE_SECTOR_SIZE_BYTES: u64 = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmPlan {
    version: u32,
    sandbox_id: SandboxId,
    pub runtime_dir: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub rootfs: PathBuf,
    pub kernel_command_line: String,
    pub directory_shares: Vec<DirectorySharePlan>,
    pub network_devices: Vec<NetworkDevicePlan>,
    pub interactive: bool,
    pub pty: bool,
    pub term: Option<String>,
    pub rows: Option<u16>,
    pub cols: Option<u16>,
    pub socket_devices: Vec<SocketDevicePlan>,
    pub network_mode: VmNetworkMode,
    pub broker: Option<BrokerPlan>,
}

impl VmPlan {
    /// Returns the launch contract version used to build this VM plan.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the sandbox id that this VM plan will launch.
    pub const fn sandbox_id(&self) -> &SandboxId {
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

        validate_rootfs(contract.guest().rootfs())?;
        let PreparedDirectoryShares {
            runtime_dir,
            plans: directory_shares,
            sensitive_paths,
        } = prepare_directory_shares(contract)?;

        let guest_contract_path = guest_runtime_path(contract_relative_path);
        let network_mode = match contract.network_mode() {
            NetworkMode::VsockSidecar => VmNetworkMode::VsockSidecar,
        };
        let broker = contract
            .secret_shims()
            .map(|shims| {
                Ok(BrokerPlan {
                    vsock_port: NonZeroU32::new(shims.broker_vsock_port()).ok_or(
                        VmPlanError::InvalidBrokerPort {
                            field: "secret_shims.broker_vsock_port",
                        },
                    )?,
                    socket_path: sensitive_paths
                        .as_ref()
                        .ok_or(VmPlanError::MissingCanonicalSensitivePaths)?[1]
                        .canonical
                        .clone(),
                    guest_addr: contract
                        .guest_broker_addr()
                        .map_err(|source| VmPlanError::GuestBrokerAddr { source })?
                        .ok_or(VmPlanError::MissingGuestBrokerAddr)?,
                })
            })
            .transpose()?;

        Ok(Self {
            version: contract.version(),
            sandbox_id: *contract.sandbox_id(),
            runtime_dir,
            kernel: contract.guest().kernel().to_path_buf(),
            initrd: contract.guest().initrd().to_path_buf(),
            rootfs: contract.guest().rootfs().to_path_buf(),
            kernel_command_line: kernel_command_line(&guest_contract_path, network_mode),
            directory_shares,
            network_devices: Vec::new(),
            interactive: contract.terminal().interactive(),
            pty: contract.terminal().pty(),
            term: contract.terminal().term().map(str::to_string),
            rows: contract.terminal().rows(),
            cols: contract.terminal().cols(),
            socket_devices: vec![SocketDevicePlan {
                kind: SocketDeviceKind::VirtioVsockSidecar,
                sidecar_port: contract.vsock_sidecar_port(),
                sidecar_host_addr: contract
                    .sidecar_host_addr()
                    .map_err(|source| VmPlanError::SidecarHostAddr { source })?,
                command_pty: CommandPtyPlan::from_contract(contract)?,
            }],
            network_mode,
            broker,
        })
    }
}

struct SensitivePath {
    field: &'static str,
    configured: PathBuf,
    canonical: PathBuf,
}

struct WritableShareSource {
    name: String,
    configured: PathBuf,
    canonical: PathBuf,
}

struct PreparedDirectoryShares {
    runtime_dir: PathBuf,
    plans: Vec<DirectorySharePlan>,
    sensitive_paths: Option<[SensitivePath; 2]>,
}

fn prepare_directory_shares(contract: &Contract) -> VmPlanResult<PreparedDirectoryShares> {
    if !contract.runtime_dir().is_dir() {
        return Err(VmPlanError::RuntimeDirMissing {
            path: contract.runtime_dir().to_path_buf(),
        });
    }
    let runtime_dir = canonicalize_path("runtime_dir", contract.runtime_dir())?;
    let mut writable_sources = vec![WritableShareSource {
        name: "runtime".to_string(),
        configured: contract.runtime_dir().to_path_buf(),
        canonical: runtime_dir.clone(),
    }];
    let mut plans = vec![DirectorySharePlan {
        name: "runtime".to_string(),
        source: runtime_dir.clone(),
        read_only: false,
    }];

    for (index, mount) in contract.mounts().iter().enumerate() {
        if !mount.source().is_dir() {
            return Err(VmPlanError::MountSourceNotDirectory {
                path: mount.source().to_path_buf(),
            });
        }
        let name = format!("mount{index}");
        let source = if mount.read_only() {
            mount.source().to_path_buf()
        } else {
            let canonical = canonicalize_path("mount.source", mount.source())?;
            writable_sources.push(WritableShareSource {
                name: name.clone(),
                configured: mount.source().to_path_buf(),
                canonical: canonical.clone(),
            });
            canonical
        };
        plans.push(DirectorySharePlan {
            name,
            source,
            read_only: mount.read_only(),
        });
    }

    let sensitive_paths = prepare_sensitive_paths(contract)?;
    if let Some(sensitive_paths) = &sensitive_paths {
        validate_writable_share_separation(&writable_sources, sensitive_paths)?;
        plans.push(DirectorySharePlan {
            name: "secret-shims".to_string(),
            source: sensitive_paths[0].canonical.clone(),
            read_only: true,
        });
    }

    Ok(PreparedDirectoryShares {
        runtime_dir,
        plans,
        sensitive_paths,
    })
}

fn prepare_sensitive_paths(contract: &Contract) -> VmPlanResult<Option<[SensitivePath; 2]>> {
    contract
        .secret_shims()
        .map(|shims| {
            let shim_dir = shims.shim_share_directory();
            if !shim_dir.is_dir() {
                return Err(VmPlanError::ShimShareDirectoryMissing {
                    path: shim_dir.to_path_buf(),
                });
            }

            Ok([
                SensitivePath {
                    field: "secret_shims.shim_share_directory",
                    configured: shim_dir.to_path_buf(),
                    canonical: canonicalize_path("secret_shims.shim_share_directory", shim_dir)?,
                },
                SensitivePath {
                    field: "secret_shims.broker_socket_path",
                    configured: shims.broker_socket_path().to_path_buf(),
                    canonical: canonicalize_path(
                        "secret_shims.broker_socket_path",
                        shims.broker_socket_path(),
                    )?,
                },
            ])
        })
        .transpose()
}

fn canonicalize_path(field: &'static str, path: &Path) -> VmPlanResult<PathBuf> {
    std::fs::canonicalize(path).map_err(|source| VmPlanError::CanonicalizePath {
        field,
        path: path.to_path_buf(),
        source,
    })
}

fn validate_writable_share_separation(
    writable_shares: &[WritableShareSource],
    sensitive_paths: &[SensitivePath; 2],
) -> VmPlanResult<()> {
    for share in writable_shares {
        for sensitive in sensitive_paths {
            if share.canonical.starts_with(&sensitive.canonical)
                || sensitive.canonical.starts_with(&share.canonical)
            {
                return Err(VmPlanError::WritableShareOverlapsSensitivePath(Box::new(
                    WritableShareOverlap {
                        share_name: share.name.clone(),
                        share_source: share.configured.clone(),
                        canonical_share_source: share.canonical.clone(),
                        sensitive_field: sensitive.field,
                        sensitive_path: sensitive.configured.clone(),
                        canonical_sensitive_path: sensitive.canonical.clone(),
                    },
                )));
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectorySharePlan {
    pub name: String,
    pub source: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkDevicePlan {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketDevicePlan {
    pub kind: SocketDeviceKind,
    pub sidecar_port: u32,
    pub sidecar_host_addr: SocketAddr,
    pub command_pty: Option<CommandPtyPlan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandPtyPlan {
    pub data_port: NonZeroU32,
    pub control_port: NonZeroU32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerPlan {
    pub vsock_port: NonZeroU32,
    pub socket_path: PathBuf,
    pub guest_addr: SocketAddr,
}

impl CommandPtyPlan {
    /// Accepts command PTY ports from the validated launch contract.
    fn from_contract(contract: &Contract) -> VmPlanResult<Option<Self>> {
        match (
            contract.command_pty_vsock_port(),
            contract.command_pty_control_vsock_port(),
        ) {
            (Some(data_port), Some(control_port)) => {
                let data_port =
                    NonZeroU32::new(data_port).ok_or(VmPlanError::InvalidCommandPtyPort {
                        field: "terminal.pty_vsock_port",
                    })?;
                let control_port =
                    NonZeroU32::new(control_port).ok_or(VmPlanError::InvalidCommandPtyPort {
                        field: "terminal.pty_control_vsock_port",
                    })?;

                Ok(Some(Self {
                    data_port,
                    control_port,
                }))
            }
            (None, None) => Ok(None),
            _ => Err(VmPlanError::IncompleteCommandPtyPlan),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketDeviceKind {
    VirtioVsockSidecar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmNetworkMode {
    VsockSidecar,
}

impl VmNetworkMode {
    pub const fn as_kernel_arg(self) -> &'static str {
        match self {
            Self::VsockSidecar => "vsock_sidecar",
        }
    }
}

/// Builds the Linux boot arguments that point guest init at the launch contract.
fn kernel_command_line(guest_contract_path: &str, network_mode: VmNetworkMode) -> String {
    let network = network_mode.as_kernel_arg();

    format!(
        "console=hvc0 earlyprintk=hvc0 ignore_loglevel loglevel=8 printk.time=1 \
         rdinit=/firma-init init=/firma-init panic=1 \
         firma.virtiofs_tag={FIRMA_VIRTIOFS_TAG} \
         firma.launch_contract={guest_contract_path} firma.network={network}"
    )
}

/// Converts a host-relative runtime path into the Linux guest path.
fn guest_runtime_path(host_relative_path: &Path) -> String {
    let mut guest_path = format!("{GUEST_SHARE_ROOT}/runtime");

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

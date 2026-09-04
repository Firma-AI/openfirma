use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as _;
use std::io::{IsTerminal, Read as _};
use std::num::NonZeroU16;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Mutex;

use crate::backend::{
    BackendKind, BrokerBridgeKind, EnforcementProof, LaunchSpec, NetworkConfinement,
    PrepareRequest, SandboxBackend, SandboxHandle, SandboxMount, SandboxRuntimeLayout,
    SecretShimSupport, SecretShimUnsupportedReason, ShimTarget,
};
use crate::config::{MountSpec, NetworkPolicy, SidecarEndpoint};
use crate::error::RunError;
use sha2::{Digest as _, Sha256};

const VZ_GUEST_MODE_ENV: &str = "FIRMA_RUN_VZ_GUEST";
const VZ_STRUCTURAL_NETWORK_ENV: &str = "FIRMA_RUN_VZ_STRUCTURAL_NETWORK";
const VZ_GUEST_RUNNER_ENV: &str = "FIRMA_RUN_VZ_GUEST_RUNNER";
const VZ_GUEST_KERNEL_ENV: &str = "FIRMA_RUN_VZ_GUEST_KERNEL";
const VZ_GUEST_INITRD_ENV: &str = "FIRMA_RUN_VZ_GUEST_INITRD";
const VZ_GUEST_ROOTFS_ENV: &str = "FIRMA_RUN_VZ_GUEST_ROOTFS";
const VZ_GUEST_LAUNCH_CONTRACT_VERSION: u32 = 2;
const VZ_GUEST_SECRET_ENV_KEYS: &[&str] = &[
    "FIRMA_CAPABILITY_TOKEN",
    "FIRMA_BROKER_ADDR",
    "FIRMA_SECRET_PROVIDER_NAMES",
    "FIRMA_SECRET_SHIM_SHARE_DIRECTORY",
    "FIRMA_SECRET_BROKER_SOCKET_PATH",
];
const VZ_GUEST_HOST_NETWORK_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "FIRMA_DNS_STUB_ADDR",
    "FIRMA_RUN_PROXY_LISTEN_ADDR",
    "FIRMA_RUN_DNS_STUB_LISTEN_ADDR",
    "FIRMA_RUN_PROXY_BRIDGE_UPSTREAM_UDS",
];
const VZ_GUEST_HTTP_PROXY_ADDR: &str = "127.0.0.1:18080";
const VZ_GUEST_DNS_STUB_ADDR: &str = "127.0.0.1:1053";
const VZ_GUEST_SIDECAR_VSOCK_PORT: u32 = 18080;
const VZ_GUEST_COMMAND_PTY_VSOCK_PORT: u32 = 18081;
const VZ_GUEST_COMMAND_PTY_CONTROL_VSOCK_PORT: u32 = 18082;
const VZ_GUEST_BROKER_VSOCK_PORT: u32 = 18083;

/// Host paths owned by the VZ guest-launch handoff.
struct VzGuestLayout {
    runtime_dir: PathBuf,
}

impl VzGuestLayout {
    /// Create a VZ guest layout beneath the sandbox runtime directory.
    fn from_runtime_dir(runtime_dir: impl Into<PathBuf>) -> Self {
        Self {
            runtime_dir: runtime_dir.into(),
        }
    }

    /// Return the private directory containing VZ guest artifacts.
    fn guest_dir(&self) -> PathBuf {
        self.runtime_dir.join("vz-guest")
    }

    /// Return the launch contract consumed by `firma-vz-runner`.
    fn launch_contract(&self) -> PathBuf {
        self.guest_dir().join("vz-guest-launch.json")
    }
}

/// macOS runtime backend.
///
/// Operates in one of three modes:
///
/// - **Compatibility mode** (default): `sandbox-exec` + `HTTP_PROXY` injection.
///   Proxy-only; requires `--allow-non-structural`. Equivalent to the current
///   macOS compatibility baseline.
///
/// - **Sandbox-exec structural mode** (`FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1`):
///   `sandbox-exec` with `deny network-outbound` policy that restricts the
///   wrapped process to the Firma proxy bridge and DNS stub on loopback — the
///   re-allow is port-scoped to those endpoints, so other host loopback
///   services (admin ports, daemons, MCP servers) are denied too. This mode
///   reports `structural=true` with `network_confinement=macos_sandbox_network_deny`.
///   This is an intermediate structural step before the guest-backed path.
///
/// - **VZ guest structural mode** (`FIRMA_RUN_VZ_GUEST=1`): launch a configured
///   host runner with an explicit JSON contract. The runner owns the
///   Virtualization.framework lifecycle and must boot a guest whose only
///   usable egress path is the sidecar bridge provided in the contract.
///   This mode reports `structural=true` with
///   `network_confinement=macos_vz_guest`.
#[derive(Debug, Default)]
pub struct VzBackend {
    guest_context: Mutex<Option<VzGuestRunContext>>,
}

impl VzBackend {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn guest_context(&self) -> Result<VzGuestRunContext, RunError> {
        let cached = self
            .guest_context
            .lock()
            .map_err(|_| RunError::Internal("VZ guest input cache lock poisoned".to_string()))?
            .clone();
        cached.ok_or_else(|| {
            RunError::Internal("VZ guest run context was not resolved before launch".to_string())
        })
    }
}

/// Returns the active structural mode for the VZ backend.
fn vz_structural_mode() -> VzStructuralMode {
    vz_structural_mode_from_flags(
        crate::config::env_truthy(VZ_GUEST_MODE_ENV),
        crate::config::env_truthy(VZ_STRUCTURAL_NETWORK_ENV),
    )
}

fn vz_structural_mode_from_flags(vz_guest: bool, sandbox_exec_network: bool) -> VzStructuralMode {
    if vz_guest {
        VzStructuralMode::VzGuest
    } else if sandbox_exec_network {
        VzStructuralMode::SandboxExecNetworkDeny
    } else {
        VzStructuralMode::Compatibility
    }
}

/// Structural mode for the macOS VZ backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VzStructuralMode {
    /// Compatibility mode: sandbox-exec + proxy env. Not structural.
    Compatibility,
    /// Structural mode via `TrustedBSD` MAC sandbox with network denial.
    /// The wrapped process may only reach loopback addresses (proxy bridge
    /// and DNS stub). All external outbound connections are denied.
    SandboxExecNetworkDeny,
    /// Apple Virtualization.framework guest with isolated virtio networking.
    /// The external runner owns the platform framework calls; this backend
    /// validates inputs, emits the launch contract, and supervises the runner.
    VzGuest,
}

impl SandboxBackend for VzBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Vz
    }

    fn prepare(&self, request: &PrepareRequest) -> Result<SandboxHandle, RunError> {
        if !cfg!(target_os = "macos") {
            return Err(RunError::UnsupportedBackend {
                backend: BackendKind::Vz.to_string(),
                reason: "VZ backend is only available on macOS hosts".to_string(),
            });
        }

        let mode = vz_structural_mode();
        match mode {
            VzStructuralMode::Compatibility | VzStructuralMode::SandboxExecNetworkDeny => {
                if !command_available("sandbox-exec") {
                    return Err(RunError::Backend {
                        backend: BackendKind::Vz.to_string(),
                        reason: "sandbox-exec is not installed or not executable".to_string(),
                    });
                }

                if mode == VzStructuralMode::SandboxExecNetworkDeny {
                    tracing::info!(
                        mode = "sandbox_exec_network_deny",
                        "macOS VZ structural preflight: sandbox-exec with deny network-outbound selected"
                    );
                }
            }
            VzStructuralMode::VzGuest => {
                tracing::info!(mode = "vz_guest", "macOS VZ structural mode selected");
            }
        }

        let runtime_dir =
            SandboxRuntimeLayout::in_temp_dir(&env::temp_dir(), &request.identity.sandbox_id)
                .into_root();

        create_vz_runtime_dir(&runtime_dir)?;

        let mounts = request
            .profile
            .mounts
            .iter()
            .cloned()
            .map(SandboxMount::operator_provided)
            .chain(std::iter::once(SandboxMount::framework(MountSpec {
                source: request.working_dir.clone(),
                target: request.working_dir.clone(),
                read_only: false,
            })))
            .collect::<Vec<_>>();

        Ok(SandboxHandle {
            backend: BackendKind::Vz,
            runtime_dir,
            identity: request.identity.clone(),
            mounts,
            network_policy: request.profile.network.clone(),
        })
    }

    fn enforce_network(
        &self,
        _handle: &SandboxHandle,
        policy: &NetworkPolicy,
    ) -> Result<EnforcementProof, RunError> {
        let mode = vz_structural_mode();
        match mode {
            VzStructuralMode::SandboxExecNetworkDeny => Ok(EnforcementProof {
                backend: BackendKind::Vz,
                structural: true,
                fail_closed: policy.fail_closed,
                detail: "macOS sandbox-exec with deny network-outbound; wrapped process may only \
                         reach the Firma proxy bridge + DNS stub on loopback (port-scoped); all \
                         other loopback and external outbound denied by TrustedBSD MAC policy"
                    .to_string(),
                network_confinement: NetworkConfinement::MacosSandboxNetworkDeny,
            }),
            VzStructuralMode::VzGuest => Ok(EnforcementProof {
                backend: BackendKind::Vz,
                structural: true,
                fail_closed: policy.fail_closed,
                detail:
                    "macOS Virtualization.framework guest mode selected; configured runner must \
                         boot the guest with bridge-only egress, deterministic DNS, and \
                         fail-closed sidecar reachability checks"
                        .to_string(),
                network_confinement: NetworkConfinement::MacosVzGuest,
            }),
            VzStructuralMode::Compatibility => Ok(EnforcementProof {
                backend: BackendKind::Vz,
                structural: false,
                fail_closed: policy.fail_closed,
                detail: "macOS backend active; outbound mediation is currently proxy-based"
                    .to_string(),
                network_confinement: NetworkConfinement::ProxyOnly,
            }),
        }
    }

    fn verify_fail_closed(
        &self,
        _handle: &SandboxHandle,
        proof: &EnforcementProof,
    ) -> Result<(), RunError> {
        if !proof.fail_closed {
            return Err(RunError::Backend {
                backend: BackendKind::Vz.to_string(),
                reason: "fail-closed policy is disabled".to_string(),
            });
        }
        Ok(())
    }

    fn start_agent(
        &self,
        _runtime_layout: &firma_runtime_state::RuntimeLayout,
        handle: &SandboxHandle,
        launch: &LaunchSpec,
        shim_support: &SecretShimSupport,
    ) -> Result<Child, RunError> {
        if !cfg!(target_os = "macos") {
            return Err(RunError::UnsupportedBackend {
                backend: BackendKind::Vz.to_string(),
                reason: "cannot start VZ backend agent on non-macOS host".to_string(),
            });
        }

        let mode = vz_structural_mode();
        if mode == VzStructuralMode::VzGuest {
            let context = self.guest_context()?;
            return start_vz_guest_runner(handle, launch, context.inputs, shim_support);
        }

        let mut command = Command::new("sandbox-exec");

        let profile = build_sandbox_profile(launch, mode);
        command.arg("-p").arg(&profile);
        command.arg(&launch.executable).args(&launch.args);
        command.current_dir(&launch.cwd);
        command.envs(&launch.env);

        let claude_profile = launch
            .env
            .get("FIRMA_RUN_PROFILE")
            .is_some_and(|profile| profile == "claude-code");
        if claude_profile {
            let runtime_home = handle.runtime_dir.display().to_string();
            command.env("HOME", &runtime_home);
            command.env("XDG_CONFIG_HOME", &runtime_home);
            command.env("XDG_CACHE_HOME", &runtime_home);
        }

        if mode == VzStructuralMode::SandboxExecNetworkDeny {
            tracing::info!(
                mode = "sandbox_exec_network_deny",
                "macOS VZ: launching agent with network-deny sandbox profile"
            );
        }

        command.spawn().map_err(|error| {
            RunError::Spawn(format!(
                "failed to spawn command through VZ backend: {error}"
            ))
        })
    }

    fn teardown(&self, handle: SandboxHandle) -> Result<(), RunError> {
        remove_runtime_dir(&handle.runtime_dir);
        Ok(())
    }

    fn secret_shim_support(&self) -> SecretShimSupport {
        let mode = vz_structural_mode();
        match mode {
            VzStructuralMode::Compatibility | VzStructuralMode::SandboxExecNetworkDeny => {
                SecretShimSupport::Unsupported {
                    reason: SecretShimUnsupportedReason::HostCallable,
                }
            }
            VzStructuralMode::VzGuest => {
                isolated_guest_shim_support(ShimTarget::linux_musl(), None)
            }
        }
    }

    fn resolve_secret_shim_support(
        &self,
        runtime_layout: &firma_runtime_state::RuntimeLayout,
        handle: &SandboxHandle,
        firma_exe: &Path,
        requires_cli_shim: bool,
    ) -> Result<SecretShimSupport, RunError> {
        if vz_structural_mode() == VzStructuralMode::VzGuest {
            let custody_dir = runtime_layout
                .run_entry_layout(&handle.identity.sandbox_id)
                .into_root()
                .join("vz-bundle");
            let context = VzGuestRunContext::resolve(&custody_dir)?;
            let guest_target = context.guest_target;
            let guest_shim = requires_cli_shim
                .then(|| {
                    crate::runtime::secret_shims::resolve_guest_shim(
                        firma_exe,
                        guest_target,
                        &context.shim_sha256,
                    )
                })
                .transpose()?;
            tracing::info!(
                mode = "vz_guest",
                runner = %context.inputs.runner.display(),
                kernel = %context.inputs.kernel.display(),
                initrd = %context.inputs.initrd.display(),
                rootfs = %context.inputs.rootfs.display(),
                guest_target = guest_target.triple,
                "macOS VZ structural preflight: guest bundle copied into run custody and validated"
            );
            let mut cached = self.guest_context.lock().map_err(|_| {
                RunError::Internal("VZ guest input cache lock poisoned".to_string())
            })?;
            if cached.replace(context).is_some() {
                return Err(RunError::Internal(
                    "VZ guest run context was resolved more than once".to_string(),
                ));
            }
            drop(cached);
            return Ok(isolated_guest_shim_support(guest_target, guest_shim));
        }
        Ok(self.secret_shim_support())
    }
}

fn isolated_guest_shim_support(
    guest_target: ShimTarget,
    guest_shim: Option<crate::backend::ResolvedGuestShim>,
) -> SecretShimSupport {
    SecretShimSupport::IsolatedGuest {
        guest_target,
        broker_bridge: BrokerBridgeKind::VsockPort {
            port: VZ_GUEST_BROKER_VSOCK_PORT,
        },
        guest_shim,
    }
}

/// Create the VZ runtime tree with owner-only custody.
///
/// VZ guest mode writes launch context under this directory later in the run,
/// so the whole runtime tree must be private before any contract or runner
/// artifacts appear there.
fn create_vz_runtime_dir(runtime_dir: &Path) -> Result<(), RunError> {
    firma_fs::create_private_dir_all(runtime_dir).map_err(|error| RunError::Backend {
        backend: BackendKind::Vz.to_string(),
        reason: format!(
            "failed to create private runtime dir {}: {error}",
            runtime_dir.display()
        ),
    })
}

#[derive(Debug, Clone)]
struct VzGuestLaunchInputs {
    runner: PathBuf,
    kernel: PathBuf,
    initrd: PathBuf,
    rootfs: PathBuf,
}

#[derive(Debug, Clone)]
struct VzGuestRunContext {
    inputs: VzGuestLaunchInputs,
    guest_target: ShimTarget,
    shim_sha256: [u8; 32],
}

impl VzGuestRunContext {
    fn resolve(custody_dir: &Path) -> Result<Self, RunError> {
        Self::resolve_with_lookup(custody_dir, |name| std::env::var(name).ok())
    }

    fn resolve_with_lookup(
        custody_dir: &Path,
        lookup: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self, RunError> {
        let source = VzGuestLaunchInputs::from_env_lookup(lookup)?;
        let manifest = VzGuestManifest::read(&source)?;
        firma_fs::create_private_dir_all(custody_dir).map_err(|error| RunError::Backend {
            backend: BackendKind::Vz.to_string(),
            reason: format!(
                "create private VZ guest bundle custody {}: {error}",
                custody_dir.display()
            ),
        })?;
        let inputs = source.copy_into(custody_dir)?;
        #[cfg(unix)]
        ensure_executable_file(VZ_GUEST_RUNNER_ENV, &inputs.runner)?;
        #[cfg(not(unix))]
        ensure_executable_file(VZ_GUEST_RUNNER_ENV, &inputs.runner);
        validate_runner_contract_version(&inputs.runner)?;
        manifest.validate_artifacts(&inputs)?;
        Ok(Self {
            inputs,
            guest_target: manifest.guest_target,
            shim_sha256: manifest.shim_sha256,
        })
    }
}

impl VzGuestLaunchInputs {
    fn from_env_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self, RunError> {
        let runner =
            validate_required_file_env_value(VZ_GUEST_RUNNER_ENV, lookup(VZ_GUEST_RUNNER_ENV))?;
        #[cfg(unix)]
        ensure_executable_file(VZ_GUEST_RUNNER_ENV, &runner)?;
        #[cfg(not(unix))]
        ensure_executable_file(VZ_GUEST_RUNNER_ENV, &runner);
        Ok(Self {
            runner,
            kernel: validate_required_file_env_value(
                VZ_GUEST_KERNEL_ENV,
                lookup(VZ_GUEST_KERNEL_ENV),
            )?,
            initrd: validate_required_file_env_value(
                VZ_GUEST_INITRD_ENV,
                lookup(VZ_GUEST_INITRD_ENV),
            )?,
            rootfs: validate_required_file_env_value(
                VZ_GUEST_ROOTFS_ENV,
                lookup(VZ_GUEST_ROOTFS_ENV),
            )?,
        })
    }

    fn copy_into(&self, custody_dir: &Path) -> Result<Self, RunError> {
        Ok(Self {
            runner: copy_vz_guest_artifact(&self.runner, &custody_dir.join("firma-vz-runner"))?,
            kernel: copy_vz_guest_artifact(&self.kernel, &custody_dir.join("vmlinuz"))?,
            initrd: copy_vz_guest_artifact(&self.initrd, &custody_dir.join("initrd.img"))?,
            rootfs: copy_vz_guest_artifact(&self.rootfs, &custody_dir.join("rootfs.img"))?,
        })
    }
}

fn copy_vz_guest_artifact(source: &Path, destination: &Path) -> Result<PathBuf, RunError> {
    std::fs::copy(source, destination).map_err(|error| RunError::Backend {
        backend: BackendKind::Vz.to_string(),
        reason: format!(
            "copy VZ guest artifact {} into run custody {}: {error}",
            source.display(),
            destination.display()
        ),
    })?;
    Ok(destination.to_path_buf())
}

fn validate_runner_contract_version(runner: &Path) -> Result<(), RunError> {
    let output = Command::new(runner)
        .arg("--supported-contract-version")
        .output()
        .map_err(|error| RunError::Backend {
            backend: BackendKind::Vz.to_string(),
            reason: format!(
                "failed to query VZ runner contract version {}: {error}",
                runner.display()
            ),
        })?;
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !output.status.success() || version != VZ_GUEST_LAUNCH_CONTRACT_VERSION.to_string() {
        return Err(RunError::Backend {
            backend: BackendKind::Vz.to_string(),
            reason: format!(
                "VZ runner {} is incompatible: expected contract version {}, got '{}'",
                runner.display(),
                VZ_GUEST_LAUNCH_CONTRACT_VERSION,
                version
            ),
        });
    }
    Ok(())
}

#[derive(Debug)]
struct VzGuestManifest {
    path: PathBuf,
    guest_target: ShimTarget,
    shim_sha256: [u8; 32],
    kernel_sha256: [u8; 32],
    initrd_sha256: [u8; 32],
    rootfs_sha256: [u8; 32],
}

impl VzGuestManifest {
    #[expect(
        clippy::too_many_lines,
        reason = "manifest parsing and bundle-coherence validation form one fail-closed boundary"
    )]
    fn read(inputs: &VzGuestLaunchInputs) -> Result<Self, RunError> {
        let manifest_path = inputs.initrd.with_file_name("manifest.txt");
        let manifest = std::fs::read_to_string(&manifest_path).map_err(|error| RunError::Backend {
        backend: BackendKind::Vz.to_string(),
        reason: format!(
            "read VZ guest manifest {}: {error}; rebuild guest artifacts with scripts/macos-vz/build-guest-artifacts.sh",
            manifest_path.display()
        ),
    })?;
        let mut values = BTreeMap::new();
        for line in manifest.lines().filter(|line| !line.is_empty()) {
            let (key, value) = line.split_once('=').ok_or_else(|| RunError::Backend {
                backend: BackendKind::Vz.to_string(),
                reason: format!(
                    "VZ guest manifest {} contains a malformed entry",
                    manifest_path.display()
                ),
            })?;
            if values.insert(key, value).is_some() {
                return Err(RunError::Backend {
                    backend: BackendKind::Vz.to_string(),
                    reason: format!(
                        "VZ guest manifest {} contains duplicate field '{key}'",
                        manifest_path.display()
                    ),
                });
            }
        }
        let expected_version = VZ_GUEST_LAUNCH_CONTRACT_VERSION.to_string();
        if values.get("contract_version") != Some(&expected_version.as_str()) {
            return Err(vz_manifest_error(
                &manifest_path,
                "contract_version",
                &expected_version,
                values.get("contract_version").copied(),
            ));
        }
        let rust_target = values.get("rust_target").copied().unwrap_or("missing");
        let guest_target =
            ShimTarget::from_linux_musl_triple(rust_target).ok_or_else(|| RunError::Backend {
                backend: BackendKind::Vz.to_string(),
                reason: format!(
                    "VZ guest manifest {} has unsupported rust_target '{rust_target}'",
                    manifest_path.display()
                ),
            })?;
        let shim_sha256 = parse_manifest_sha256(
            &manifest_path,
            "shim_sha256",
            values.get("shim_sha256").copied(),
        )?;

        let canonical_manifest =
            std::fs::canonicalize(&manifest_path).map_err(|error| RunError::Backend {
                backend: BackendKind::Vz.to_string(),
                reason: format!(
                    "resolve VZ guest manifest {}: {error}",
                    manifest_path.display()
                ),
            })?;
        let bundle_dir = canonical_manifest
            .parent()
            .ok_or_else(|| RunError::Backend {
                backend: BackendKind::Vz.to_string(),
                reason: format!(
                    "VZ guest manifest {} has no bundle directory",
                    manifest_path.display()
                ),
            })?;
        for (artifact, path) in [
            ("kernel", &inputs.kernel),
            ("initrd", &inputs.initrd),
            ("rootfs", &inputs.rootfs),
        ] {
            let canonical_artifact =
                std::fs::canonicalize(path).map_err(|error| RunError::Backend {
                    backend: BackendKind::Vz.to_string(),
                    reason: format!("resolve VZ guest {artifact} {}: {error}", path.display()),
                })?;
            if canonical_artifact.parent() != Some(bundle_dir) {
                return Err(RunError::Backend {
                    backend: BackendKind::Vz.to_string(),
                    reason: format!(
                        "VZ guest {artifact} {} is not a sibling of manifest {}",
                        path.display(),
                        manifest_path.display()
                    ),
                });
            }
        }
        Ok(Self {
            path: manifest_path.clone(),
            guest_target,
            shim_sha256,
            kernel_sha256: parse_manifest_sha256(
                &manifest_path,
                "kernel_sha256",
                values.get("kernel_sha256").copied(),
            )?,
            initrd_sha256: parse_manifest_sha256(
                &manifest_path,
                "initrd_sha256",
                values.get("initrd_sha256").copied(),
            )?,
            rootfs_sha256: parse_manifest_sha256(
                &manifest_path,
                "rootfs_sha256",
                values.get("rootfs_sha256").copied(),
            )?,
        })
    }

    fn validate_artifacts(&self, inputs: &VzGuestLaunchInputs) -> Result<(), RunError> {
        for (field, expected, path) in [
            ("kernel_sha256", &self.kernel_sha256, &inputs.kernel),
            ("initrd_sha256", &self.initrd_sha256, &inputs.initrd),
            ("rootfs_sha256", &self.rootfs_sha256, &inputs.rootfs),
        ] {
            validate_guest_artifact_hash(&self.path, field, expected, path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
fn validate_guest_manifest(
    inputs: &VzGuestLaunchInputs,
) -> Result<(ShimTarget, [u8; 32]), RunError> {
    let manifest = VzGuestManifest::read(inputs)?;
    manifest.validate_artifacts(inputs)?;
    Ok((manifest.guest_target, manifest.shim_sha256))
}

fn parse_manifest_sha256(
    manifest_path: &Path,
    field: &str,
    value: Option<&str>,
) -> Result<[u8; 32], RunError> {
    let value = value.ok_or_else(|| RunError::Backend {
        backend: BackendKind::Vz.to_string(),
        reason: format!(
            "VZ guest manifest {} is missing required {field}; rebuild guest artifacts with scripts/macos-vz/build-guest-artifacts.sh",
            manifest_path.display()
        ),
    })?;
    let mut digest = [0_u8; 32];
    if value.len() != 64 || hex::decode_to_slice(value, &mut digest).is_err() {
        return Err(RunError::Backend {
            backend: BackendKind::Vz.to_string(),
            reason: format!(
                "VZ guest manifest {} has malformed {field}: expected 64 hexadecimal characters, got '{value}'",
                manifest_path.display()
            ),
        });
    }
    Ok(digest)
}

fn validate_guest_artifact_hash(
    manifest_path: &Path,
    field: &str,
    expected: &[u8; 32],
    artifact_path: &Path,
) -> Result<(), RunError> {
    let mut artifact = std::fs::File::open(artifact_path).map_err(|error| RunError::Backend {
        backend: BackendKind::Vz.to_string(),
        reason: format!(
            "read VZ guest artifact {}: {error}",
            artifact_path.display()
        ),
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = artifact
            .read(&mut buffer)
            .map_err(|error| RunError::Backend {
                backend: BackendKind::Vz.to_string(),
                reason: format!(
                    "read VZ guest artifact {}: {error}",
                    artifact_path.display()
                ),
            })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let actual: [u8; 32] = digest.finalize().into();
    if expected != &actual {
        return Err(vz_manifest_error(
            manifest_path,
            field,
            &hex::encode(expected),
            Some(&hex::encode(actual)),
        ));
    }
    Ok(())
}

fn vz_manifest_error(path: &Path, field: &str, expected: &str, actual: Option<&str>) -> RunError {
    RunError::Backend {
        backend: BackendKind::Vz.to_string(),
        reason: format!(
            "VZ guest manifest {} has incompatible {field}: expected '{expected}', got '{}'",
            path.display(),
            actual.unwrap_or("missing")
        ),
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct VzGuestLaunchContract {
    version: u32,
    sandbox_id: String,
    runtime_dir: PathBuf,
    runner: VzGuestRunnerContract,
    guest: VzGuestImageContract,
    command: VzGuestCommandContract,
    terminal: VzGuestTerminalContract,
    mounts: Vec<MountSpec>,
    network: VzGuestNetworkContract,
    invariants: Vec<VzGuestInvariantContract>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_shims: Option<VzGuestSecretShimsContract>,
}

impl VzGuestLaunchContract {
    /// Serializes the host launch state into the VZ guest contract boundary.
    fn from_launch(
        handle: &SandboxHandle,
        launch: &LaunchSpec,
        inputs: VzGuestLaunchInputs,
        shim_support: &SecretShimSupport,
    ) -> Result<Self, RunError> {
        Self::from_launch_with_terminal_snapshot(
            handle,
            launch,
            inputs,
            TerminalSnapshot::from_host(),
            shim_support,
        )
    }

    fn from_launch_with_terminal_snapshot(
        handle: &SandboxHandle,
        launch: &LaunchSpec,
        inputs: VzGuestLaunchInputs,
        terminal_snapshot: TerminalSnapshot,
        shim_support: &SecretShimSupport,
    ) -> Result<Self, RunError> {
        let terminal =
            VzGuestTerminalContract::from_launch_with_terminal_snapshot(launch, terminal_snapshot);

        let provider_names = vz_guest_shim_provider_names(&launch.env)?;
        let secret_shims = match (shim_support, provider_names) {
            (
                SecretShimSupport::IsolatedGuest {
                    guest_target,
                    broker_bridge,
                    ..
                },
                Some(provider_names),
            ) => Some(VzGuestSecretShimsContract {
                guest_target_triple: guest_target.triple.to_string(),
                provider_names,
                broker_vsock_port: match broker_bridge {
                    BrokerBridgeKind::VsockPort { port } => *port,
                },
                shim_share_directory: required_launch_path(
                    &launch.env,
                    "FIRMA_SECRET_SHIM_SHARE_DIRECTORY",
                )?,
                broker_socket_path: required_launch_path(
                    &launch.env,
                    "FIRMA_SECRET_BROKER_SOCKET_PATH",
                )?,
                guest_broker_addr: "127.0.0.1:18083".to_string(),
            }),
            (SecretShimSupport::IsolatedGuest { .. }, None)
            | (
                SecretShimSupport::HostBindMount { .. } | SecretShimSupport::Unsupported { .. },
                _,
            ) => None,
        };

        Ok(Self {
            version: VZ_GUEST_LAUNCH_CONTRACT_VERSION,
            sandbox_id: handle.identity.sandbox_id.to_string(),
            runtime_dir: handle.runtime_dir.clone(),
            runner: VzGuestRunnerContract {
                path: inputs.runner,
            },
            guest: VzGuestImageContract {
                kernel: inputs.kernel,
                initrd: inputs.initrd,
                rootfs: inputs.rootfs,
            },
            command: VzGuestCommandContract {
                executable: launch.executable.clone(),
                args: launch.args.clone(),
                cwd: launch.cwd.clone(),
                env: vz_guest_contract_env(&launch.env),
                identity_mode: launch.identity_mode,
            },
            terminal,
            mounts: handle
                .mounts
                .iter()
                .map(SandboxMount::spec)
                .cloned()
                .collect(),
            network: VzGuestNetworkContract::from_launch(
                launch,
                handle.identity.full_attribution_headers(),
            )?,
            invariants: VzGuestInvariantContract::required_set(handle.network_policy.fail_closed),
            secret_shims,
        })
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct VzGuestRunnerContract {
    path: PathBuf,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct VzGuestImageContract {
    kernel: PathBuf,
    initrd: PathBuf,
    rootfs: PathBuf,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct VzGuestCommandContract {
    executable: String,
    args: Vec<String>,
    cwd: PathBuf,
    env: BTreeMap<String, String>,
    identity_mode: crate::config::SandboxIdentityMode,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct VzGuestTerminalContract {
    interactive: bool,
    pty: bool,
    pty_vsock_port: Option<u32>,
    pty_control_vsock_port: Option<u32>,
    term: Option<String>,
    rows: Option<u16>,
    cols: Option<u16>,
}

struct TerminalSnapshot {
    interactive: bool,
    term: Option<String>,
    size: Option<TerminalSize>,
}

impl TerminalSnapshot {
    fn from_host() -> Self {
        Self {
            interactive: std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
            term: terminal_type(),
            size: TerminalSize::from_host(),
        }
    }
}

impl VzGuestTerminalContract {
    fn from_launch_with_terminal_snapshot(
        launch: &LaunchSpec,
        terminal_snapshot: TerminalSnapshot,
    ) -> Self {
        Self::from_selection(GuestTerminalSelection::from_launch(
            launch,
            terminal_snapshot,
        ))
    }

    fn from_selection(selection: GuestTerminalSelection) -> Self {
        match selection {
            GuestTerminalSelection::NonInteractive => Self {
                interactive: false,
                pty: false,
                pty_vsock_port: None,
                pty_control_vsock_port: None,
                term: None,
                rows: None,
                cols: None,
            },
            GuestTerminalSelection::Pty(request) => {
                let (rows, cols) = request.size.map_or((None, None), |size| {
                    (Some(size.rows.get()), Some(size.cols.get()))
                });

                Self {
                    interactive: true,
                    pty: true,
                    pty_vsock_port: Some(request.data_port),
                    pty_control_vsock_port: Some(request.control_port),
                    term: request.term,
                    rows,
                    cols,
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GuestTerminalSelection {
    NonInteractive,
    Pty(GuestPtyRequest),
}

impl GuestTerminalSelection {
    /// Selects whether this launch should ask the guest runner for PTY mode.
    fn from_launch(launch: &LaunchSpec, terminal_snapshot: TerminalSnapshot) -> Self {
        if !terminal_snapshot.interactive {
            return Self::NonInteractive;
        }

        let requests_guest_pty = command_requests_guest_pty(launch);
        if requests_guest_pty {
            Self::Pty(GuestPtyRequest {
                data_port: VZ_GUEST_COMMAND_PTY_VSOCK_PORT,
                control_port: VZ_GUEST_COMMAND_PTY_CONTROL_VSOCK_PORT,
                term: terminal_snapshot.term,
                size: terminal_snapshot.size,
            })
        } else {
            Self::NonInteractive
        }
    }
}

/// Returns whether this launch should ask the guest runner for PTY mode.
///
/// This profile gate is temporary. It exists only for the very first
/// interactive TUI path while the VZ PTY transport is still being brought up
/// incrementally. A later launch policy should replace this inference with an
/// explicit user-facing contract.
fn command_requests_guest_pty(launch: &LaunchSpec) -> bool {
    launch
        .env
        .get("FIRMA_RUN_PROFILE")
        .is_some_and(|profile| profile == "codex")
        && Path::new(&launch.executable)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "codex")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestPtyRequest {
    data_port: u32,
    control_port: u32,
    term: Option<String>,
    size: Option<TerminalSize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TerminalSize {
    rows: NonZeroU16,
    cols: NonZeroU16,
}

impl TerminalSize {
    fn from_host() -> Option<Self> {
        Self::from_parts(terminal_dimension("LINES"), terminal_dimension("COLUMNS"))
    }

    const fn from_parts(rows: Option<NonZeroU16>, cols: Option<NonZeroU16>) -> Option<Self> {
        match (rows, cols) {
            (Some(rows), Some(cols)) => Some(Self { rows, cols }),
            _ => None,
        }
    }
}

/// Reads the host terminal type to carry into the launch contract.
fn terminal_type() -> Option<String> {
    std::env::var("TERM")
        .ok()
        .map(|term| term.trim().to_string())
        .filter(|term| !term.is_empty())
}

/// Parses one non-zero terminal dimension from the host environment.
fn terminal_dimension(key: &str) -> Option<NonZeroU16> {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .and_then(NonZeroU16::new)
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct VzGuestNetworkContract {
    mode: VzGuestNetworkMode,
    guest_http_proxy_addr: String,
    guest_dns_stub_addr: String,
    vsock_sidecar_port: u32,
    sidecar_host_addr: String,
    direct_network_devices_allowed: bool,
    dns_mode: VzGuestDnsMode,
    attribution_headers: BTreeMap<String, String>,
}

impl VzGuestNetworkContract {
    /// Builds the guest-visible network contract from the host sidecar endpoint.
    fn from_launch(
        launch: &LaunchSpec,
        attribution_headers: BTreeMap<String, String>,
    ) -> Result<Self, RunError> {
        Ok(Self {
            mode: VzGuestNetworkMode::VsockSidecar,
            guest_http_proxy_addr: VZ_GUEST_HTTP_PROXY_ADDR.to_string(),
            guest_dns_stub_addr: VZ_GUEST_DNS_STUB_ADDR.to_string(),
            vsock_sidecar_port: VZ_GUEST_SIDECAR_VSOCK_PORT,
            sidecar_host_addr: sidecar_host_addr(&launch.sidecar_endpoint)?,
            direct_network_devices_allowed: false,
            dns_mode: VzGuestDnsMode::ConfinedStub,
            attribution_headers,
        })
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum VzGuestNetworkMode {
    VsockSidecar,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum VzGuestDnsMode {
    ConfinedStub,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct VzGuestInvariantContract {
    name: VzGuestInvariantName,
    mode: VzGuestInvariantMode,
}

impl VzGuestInvariantContract {
    fn required_set(fail_closed_startup: bool) -> Vec<Self> {
        vec![
            Self::required(VzGuestInvariantName::SidecarOnlyEgress),
            Self::required(VzGuestInvariantName::DnsConfined),
            Self {
                name: VzGuestInvariantName::FailClosedStartup,
                mode: if fail_closed_startup {
                    VzGuestInvariantMode::Required
                } else {
                    VzGuestInvariantMode::DisabledByPolicy
                },
            },
            Self::required(VzGuestInvariantName::FailClosedRuntime),
            Self::required(VzGuestInvariantName::DirectBypassResistant),
            Self::required(VzGuestInvariantName::PreserveStdioSignalsExit),
        ]
    }

    fn required(name: VzGuestInvariantName) -> Self {
        Self {
            name,
            mode: VzGuestInvariantMode::Required,
        }
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum VzGuestInvariantName {
    SidecarOnlyEgress,
    DnsConfined,
    FailClosedStartup,
    FailClosedRuntime,
    DirectBypassResistant,
    PreserveStdioSignalsExit,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum VzGuestInvariantMode {
    Required,
    DisabledByPolicy,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct VzGuestSecretShimsContract {
    guest_target_triple: String,
    provider_names: Vec<String>,
    broker_vsock_port: u32,
    shim_share_directory: PathBuf,
    broker_socket_path: PathBuf,
    guest_broker_addr: String,
}

/// Extracts the provider names that need shims from the launch environment.
///
/// Provider names are communicated via the `FIRMA_SECRET_PROVIDER_NAMES` env
/// var set by `secret_shims::prepare` when it sets up the broker.
fn vz_guest_shim_provider_names(
    env: &BTreeMap<String, String>,
) -> Result<Option<Vec<String>>, RunError> {
    env.get("FIRMA_SECRET_PROVIDER_NAMES")
        .map(|value| {
            serde_json::from_str::<Vec<String>>(value).map_err(|error| {
                RunError::Internal(format!(
                    "parse internal VZ secret provider metadata: {error}"
                ))
            })
        })
        .transpose()
}

fn required_launch_path(env: &BTreeMap<String, String>, key: &str) -> Result<PathBuf, RunError> {
    env.get(key).map(PathBuf::from).ok_or_else(|| {
        RunError::Internal(format!("internal VZ secret shim metadata is missing {key}"))
    })
}

fn start_vz_guest_runner(
    handle: &SandboxHandle,
    launch: &LaunchSpec,
    inputs: VzGuestLaunchInputs,
    shim_support: &SecretShimSupport,
) -> Result<Child, RunError> {
    start_vz_guest_runner_with_inputs(handle, launch, inputs, shim_support)
}

fn start_vz_guest_runner_with_inputs(
    handle: &SandboxHandle,
    launch: &LaunchSpec,
    inputs: VzGuestLaunchInputs,
    shim_support: &SecretShimSupport,
) -> Result<Child, RunError> {
    let runner = inputs.runner.clone();
    let contract = VzGuestLaunchContract::from_launch(handle, launch, inputs, shim_support)?;
    let contract_path = write_vz_guest_launch_contract(handle, &contract)?;

    tracing::info!(
        mode = "vz_guest",
        runner = %runner.display(),
        contract = %contract_path.display(),
        "macOS VZ: launching guest runner"
    );

    Command::new(&runner)
        .arg("--launch-contract")
        .arg(&contract_path)
        .spawn()
        .map_err(|error| {
            RunError::Spawn(format!(
                "failed to spawn macOS VZ guest runner {}: {error}",
                runner.display()
            ))
        })
}

/// Return the command environment that is safe to serialize into the VZ launch
/// contract.
///
/// The wrapped process may still receive compatibility-mode secret material,
/// but the launch contract must not create a second persisted copy of it.
fn vz_guest_contract_env(env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    env.iter()
        .filter(|(key, _)| {
            !VZ_GUEST_SECRET_ENV_KEYS.contains(&key.as_str())
                && !VZ_GUEST_HOST_NETWORK_ENV_KEYS.contains(&key.as_str())
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// Write the VZ launch contract into the run directory with owner-only access.
///
/// The contract carries enough launch context for the external runner to start
/// the guest, so it is kept under a dedicated custody directory and written as
/// an owner-readable file rather than a normal temporary artifact.
fn write_vz_guest_launch_contract(
    handle: &SandboxHandle,
    contract: &VzGuestLaunchContract,
) -> Result<PathBuf, RunError> {
    let layout = VzGuestLayout::from_runtime_dir(&handle.runtime_dir);
    let contract_dir = layout.guest_dir();
    firma_fs::create_private_dir_all(&contract_dir).map_err(|error| RunError::Backend {
        backend: BackendKind::Vz.to_string(),
        reason: format!(
            "failed to create private VZ guest contract dir {}: {error}",
            contract_dir.display()
        ),
    })?;

    let contract_path = layout.launch_contract();
    let json = serde_json::to_vec_pretty(contract).map_err(|error| {
        RunError::Internal(format!(
            "failed to serialize macOS VZ guest launch contract: {error}"
        ))
    })?;

    firma_fs::write_private_file(&contract_path, &json).map_err(|error| RunError::Backend {
        backend: BackendKind::Vz.to_string(),
        reason: format!(
            "failed to write VZ guest launch contract {}: {error}",
            contract_path.display()
        ),
    })?;

    Ok(contract_path)
}

/// Extracts the loopback TCP sidecar endpoint required by the VZ bridge.
fn sidecar_host_addr(endpoint: &SidecarEndpoint) -> Result<String, RunError> {
    match endpoint {
        SidecarEndpoint::Tcp { addr } if addr.ip().is_loopback() => Ok(addr.to_string()),
        SidecarEndpoint::Tcp { addr } => Err(RunError::UnsupportedBackend {
            backend: BackendKind::Vz.to_string(),
            reason: format!(
                "VZ guest launch requires a loopback TCP sidecar endpoint for the host bridge; got {addr}"
            ),
        }),
        SidecarEndpoint::Unix { path } => Err(RunError::UnsupportedBackend {
            backend: BackendKind::Vz.to_string(),
            reason: format!(
                "VZ guest launch requires a TCP sidecar endpoint for the host bridge; got unix://{}",
                path.display()
            ),
        }),
    }
}

fn validate_required_file_env_value(
    name: &str,
    value: Option<String>,
) -> Result<PathBuf, RunError> {
    let path = read_required_path_env_value(name, value)?;
    if !path.exists() {
        return Err(RunError::Backend {
            backend: BackendKind::Vz.to_string(),
            reason: format!("{name} does not exist: {}", path.display()),
        });
    }
    if !path.is_file() {
        return Err(RunError::Backend {
            backend: BackendKind::Vz.to_string(),
            reason: format!("{name} must point to a file: {}", path.display()),
        });
    }

    Ok(path)
}

fn read_required_path_env_value(name: &str, value: Option<String>) -> Result<PathBuf, RunError> {
    let value = value.ok_or_else(|| RunError::Backend {
        backend: BackendKind::Vz.to_string(),
        reason: format!("VZ guest mode requires {name}"),
    })?;
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(RunError::Backend {
            backend: BackendKind::Vz.to_string(),
            reason: format!("{name} must be an absolute path: {}", path.display()),
        });
    }

    Ok(path)
}

#[cfg(unix)]
fn ensure_executable_file(name: &str, path: &Path) -> Result<(), RunError> {
    let metadata = path.metadata().map_err(|error| RunError::Backend {
        backend: BackendKind::Vz.to_string(),
        reason: format!("failed to inspect {name} {}: {error}", path.display()),
    })?;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(RunError::Backend {
            backend: BackendKind::Vz.to_string(),
            reason: format!("{name} must be executable: {}", path.display()),
        });
    }

    Ok(())
}

#[cfg(not(unix))]
fn ensure_executable_file(name: &str, path: &Path) {
    let _ = (name, path);
}

/// Build the `sandbox-exec` SBPL profile for the given mode.
///
/// In `SandboxExecNetworkDeny` mode the profile adds `deny network-outbound`
/// after the default `allow`, then re-allows loopback **only to Firma's own
/// endpoints** — the proxy bridge (`HTTP_PROXY`) and DNS stub
/// (`FIRMA_DNS_STUB_ADDR`). All external IP connections are denied by
/// `TrustedBSD` MAC at the socket layer — including raw sockets, direct
/// TCP/UDP, Unix-domain socket connects, and UDP-based DNS to external
/// resolvers — and so are other host loopback services (admin ports, daemons,
/// MCP servers). See [`loopback_allow_rules`] for the port-scoping, including
/// the unscoped fallback used when the endpoint ports are unknown.
fn build_sandbox_profile(launch: &LaunchSpec, mode: VzStructuralMode) -> String {
    let home = launch
        .env
        .get("HOME")
        .cloned()
        .or_else(|| std::env::var("HOME").ok())
        .unwrap_or_default();

    let claude_profile = launch
        .env
        .get("FIRMA_RUN_PROFILE")
        .is_some_and(|p| p == "claude-code");

    let mut profile = String::from("(version 1)\n(allow default)\n");

    // Structural network denial: block all outbound, then re-allow loopback —
    // but only to Firma's own endpoints (proxy bridge + DNS stub), so other
    // host loopback services (admin ports, daemons, MCP servers) stay denied.
    if mode == VzStructuralMode::SandboxExecNetworkDeny {
        profile.push_str(
            "; macOS structural: deny all outbound, allow only Firma loopback endpoints\n\
             (deny network-outbound)\n",
        );
        profile.push_str(&loopback_allow_rules(launch));
    }

    // Sensitive home path masking for claude-code profile.
    if claude_profile && is_absolute_sandbox_path(&home) {
        for suffix in crate::backend::DEFAULT_SENSITIVE_HOME_SUFFIXES {
            let path = format!("{home}/{suffix}");
            let escaped = escape_sandbox_path(&path);
            let _ = write!(
                profile,
                "(deny file-read* (subpath \"{escaped}\"))\n\
                 (deny file-write* (subpath \"{escaped}\"))\n"
            );
        }
    }
    profile
}

/// Builds the SBPL loopback allow rules for structural mode.
///
/// Scopes the loopback re-allow to Firma's own endpoints — the proxy bridge
/// (from `HTTP_PROXY`) and the DNS stub (from `FIRMA_DNS_STUB_ADDR`) — so other
/// host loopback services stay denied by the `(deny network-outbound)` above.
///
/// When neither port can be determined (e.g. a proxyless context) it falls back
/// to allowing all loopback so functionality is preserved; that fallback is the
/// old, unscoped behavior and the only path that leaves the residual caveat.
fn loopback_allow_rules(launch: &LaunchSpec) -> String {
    let mut ports: Vec<u16> = Vec::new();
    if let Some(port) = loopback_port_from(launch.env.get("HTTP_PROXY")) {
        ports.push(port);
    }
    if let Some(port) = loopback_port_from(launch.env.get("FIRMA_DNS_STUB_ADDR")) {
        ports.push(port);
    }
    ports.sort_unstable();
    ports.dedup();

    if ports.is_empty() {
        return "; loopback ports unknown — allow all loopback (unscoped fallback)\n\
                (allow network-outbound (remote ip4 \"localhost:*\"))\n\
                (allow network-outbound (remote ip6 \"localhost:*\"))\n"
            .to_string();
    }

    let mut out = String::new();
    for port in ports {
        let _ = write!(
            out,
            "(allow network-outbound (remote ip4 \"localhost:{port}\"))\n\
             (allow network-outbound (remote ip6 \"localhost:{port}\"))\n"
        );
    }
    out
}

/// Extracts the port from a `host:port` or `scheme://host:port[/path]` env value
/// (e.g. `http://127.0.0.1:18080`, `http://127.0.0.1:18080/`, or `127.0.0.1:5353`).
fn loopback_port_from(value: Option<&String>) -> Option<u16> {
    let raw = value?.trim();
    // Drop the scheme, then keep only the authority (everything before the
    // first '/', '?', or '#') so a trailing slash or path cannot swallow the
    // port. Finally take the last ':'-delimited field as the port.
    let after_scheme = raw.split_once("://").map_or(raw, |(_, rest)| rest);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let port_str = authority.rsplit(':').next()?;
    port_str.parse::<u16>().ok()
}

fn is_absolute_sandbox_path(path: &str) -> bool {
    path.starts_with('/')
}

fn escape_sandbox_path(path: &str) -> String {
    path.replace('\\', "\\\\").replace('"', "\\\"")
}

fn command_available(binary: &str) -> bool {
    // `sandbox-exec` with no args writes its usage banner to stderr and
    // exits non-zero. Probe by spawning with stdio silenced; `status()`
    // returns `Ok` whenever the binary could be launched, which is all we
    // need to assert availability.
    Command::new(binary)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

fn remove_runtime_dir(runtime_dir: &std::path::Path) {
    if runtime_dir.exists() {
        let _ = std::fs::remove_dir_all(runtime_dir);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    #[cfg(unix)]
    use std::collections::BTreeSet;
    use std::num::NonZeroU16;
    use std::path::Path;
    use std::path::PathBuf;

    use crate::backend::{BackendKind, LaunchSpec, SandboxHandle};
    use crate::config::{NetworkPolicy, SandboxIdentityMode, SidecarEndpoint};
    use crate::error::RunError;
    use crate::identity::RunIdentity;
    use sha2::{Digest as _, Sha256};

    use super::{
        BrokerBridgeKind, GuestPtyRequest, GuestTerminalSelection, SecretShimSupport, ShimTarget,
        TerminalSize, TerminalSnapshot, VZ_GUEST_BROKER_VSOCK_PORT,
        VZ_GUEST_COMMAND_PTY_CONTROL_VSOCK_PORT, VZ_GUEST_COMMAND_PTY_VSOCK_PORT,
        VzGuestLaunchContract, VzGuestLaunchInputs, VzGuestLayout, VzGuestRunContext,
        VzGuestTerminalContract, VzStructuralMode, build_sandbox_profile,
        isolated_guest_shim_support, loopback_port_from, validate_guest_manifest,
        vz_structural_mode_from_flags, write_vz_guest_launch_contract,
    };

    const SHARED_V2_CONTRACT_FIXTURE: &str =
        include_str!("../../../../tests/fixtures/vz-guest-launch-v2.json");
    const SHARED_V2_CONTRACT_ROOT: &str = "/openfirma-contract-v2";
    #[cfg(unix)]
    use super::{
        VZ_GUEST_INITRD_ENV, VZ_GUEST_KERNEL_ENV, VZ_GUEST_ROOTFS_ENV, VZ_GUEST_RUNNER_ENV,
        start_vz_guest_runner_with_inputs,
    };

    fn test_launch(profile_name: &str) -> LaunchSpec {
        let mut env = BTreeMap::new();
        env.insert("HOME".to_string(), "/Users/tester".to_string());
        env.insert("FIRMA_RUN_PROFILE".to_string(), profile_name.to_string());
        LaunchSpec {
            executable: "/usr/bin/true".to_string(),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env,
            sidecar_endpoint: test_sidecar_endpoint(),
            seccomp_filter_path: None,
            identity_mode: SandboxIdentityMode::SandboxUser,
            config_file: None,
        }
    }

    fn test_sidecar_endpoint() -> SidecarEndpoint {
        SidecarEndpoint::Tcp {
            addr: "127.0.0.1:18081".parse().expect("test sidecar addr"),
        }
    }

    fn test_handle(runtime_dir: PathBuf) -> SandboxHandle {
        SandboxHandle {
            backend: BackendKind::Vz,
            runtime_dir,
            identity: RunIdentity::new(crate::identity::test_agent_id(), "claude-code"),
            mounts: Vec::new(),
            network_policy: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        }
    }

    fn shared_v2_contract_inputs() -> (SandboxHandle, LaunchSpec, VzGuestLaunchInputs) {
        let identity = RunIdentity {
            sandbox_id: "sbx_01j0000000e008000000000001"
                .parse()
                .expect("valid fixture sandbox id"),
            session_id: "ses_contract_v2_fixture".to_string(),
            agent_id: crate::identity::test_agent_id(),
            execution_profile: "contract-v2".to_string(),
        };
        let handle = SandboxHandle {
            backend: BackendKind::Vz,
            runtime_dir: PathBuf::from(format!("{SHARED_V2_CONTRACT_ROOT}/runtime")),
            identity,
            mounts: vec![crate::backend::SandboxMount::operator_provided(
                crate::config::MountSpec {
                    source: PathBuf::from(format!("{SHARED_V2_CONTRACT_ROOT}/workspace")),
                    target: PathBuf::from("/workspace"),
                    read_only: false,
                },
            )],
            network_policy: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };
        let launch = LaunchSpec {
            executable: "/usr/bin/true".to_string(),
            args: vec!["--version".to_string()],
            cwd: PathBuf::from("/workspace"),
            env: BTreeMap::from([
                (
                    "FIRMA_SECRET_PROVIDER_NAMES".to_string(),
                    r#"["op","vault"]"#.to_string(),
                ),
                (
                    "FIRMA_SECRET_SHIM_SHARE_DIRECTORY".to_string(),
                    format!("{SHARED_V2_CONTRACT_ROOT}/sensitive/secret-shims"),
                ),
                (
                    "FIRMA_SECRET_BROKER_SOCKET_PATH".to_string(),
                    format!("{SHARED_V2_CONTRACT_ROOT}/sensitive/broker.sock"),
                ),
            ]),
            sidecar_endpoint: SidecarEndpoint::Tcp {
                addr: "127.0.0.1:19080"
                    .parse()
                    .expect("valid fixture sidecar addr"),
            },
            seccomp_filter_path: None,
            identity_mode: SandboxIdentityMode::SandboxUser,
            config_file: None,
        };
        let inputs = VzGuestLaunchInputs {
            runner: PathBuf::from(format!("{SHARED_V2_CONTRACT_ROOT}/firma-vz-runner")),
            kernel: PathBuf::from(format!("{SHARED_V2_CONTRACT_ROOT}/vmlinuz")),
            initrd: PathBuf::from(format!("{SHARED_V2_CONTRACT_ROOT}/initrd.img")),
            rootfs: PathBuf::from(format!("{SHARED_V2_CONTRACT_ROOT}/rootfs.img")),
        };

        (handle, launch, inputs)
    }

    fn shared_v2_shim_support() -> SecretShimSupport {
        SecretShimSupport::IsolatedGuest {
            guest_target: ShimTarget::from_linux_musl_triple("x86_64-unknown-linux-musl")
                .expect("supported fixture target"),
            broker_bridge: BrokerBridgeKind::VsockPort {
                port: VZ_GUEST_BROKER_VSOCK_PORT,
            },
            guest_shim: None,
        }
    }

    #[test]
    fn vz_guest_v2_contract_matches_shared_fixture() {
        let (handle, launch, inputs) = shared_v2_contract_inputs();
        let contract =
            VzGuestLaunchContract::from_launch(&handle, &launch, inputs, &shared_v2_shim_support())
                .expect("fixture contract should build through the production constructor");
        let mut actual = serde_json::to_value(contract).expect("serialize fixture contract");
        actual["network"]["attribution_headers"]["x-firma-user"] =
            serde_json::Value::String("${USER}".to_string());
        let expected: serde_json::Value =
            serde_json::from_str(SHARED_V2_CONTRACT_FIXTURE).expect("parse shared fixture");

        assert_eq!(actual, expected);
        assert_eq!(actual["version"], 2);
        assert_eq!(
            actual["secret_shims"],
            serde_json::json!({
                "guest_target_triple": "x86_64-unknown-linux-musl",
                "provider_names": ["op", "vault"],
                "broker_vsock_port": 18083,
                "shim_share_directory": "/openfirma-contract-v2/sensitive/secret-shims",
                "broker_socket_path": "/openfirma-contract-v2/sensitive/broker.sock",
                "guest_broker_addr": "127.0.0.1:18083",
            })
        );
    }

    #[test]
    fn vz_guest_contract_omits_secret_shims_without_prepared_metadata() {
        let (handle, _, inputs) = shared_v2_contract_inputs();
        let launch = test_launch("no-secret-shims");
        let contract =
            VzGuestLaunchContract::from_launch(&handle, &launch, inputs, &shared_v2_shim_support())
                .expect("launch without CLI metadata should produce a contract");
        let json = serde_json::to_value(contract).expect("serialize contract");

        assert!(json.get("secret_shims").is_none());
    }

    fn test_terminal_snapshot(interactive: bool) -> TerminalSnapshot {
        TerminalSnapshot {
            interactive,
            term: Some("xterm-256color".to_string()),
            size: TerminalSize::from_parts(NonZeroU16::new(40), NonZeroU16::new(120)),
        }
    }

    fn test_contract(handle: &SandboxHandle) -> VzGuestLaunchContract {
        let mut launch = test_launch("claude-code");
        launch.env.insert(
            "HTTP_PROXY".to_string(),
            "http://127.0.0.1:18080".to_string(),
        );
        launch.env.insert(
            "FIRMA_DNS_STUB_ADDR".to_string(),
            "127.0.0.1:5353".to_string(),
        );

        VzGuestLaunchContract::from_launch(
            handle,
            &launch,
            VzGuestLaunchInputs {
                runner: PathBuf::from("/Applications/Firma/vz-runner"),
                kernel: PathBuf::from("/var/lib/firma/vz/vmlinuz"),
                initrd: PathBuf::from("/var/lib/firma/vz/initrd.img"),
                rootfs: PathBuf::from("/var/lib/firma/vz/rootfs.img"),
            },
            &SecretShimSupport::IsolatedGuest {
                guest_target: ShimTarget::linux_musl(),
                broker_bridge: BrokerBridgeKind::VsockPort {
                    port: VZ_GUEST_BROKER_VSOCK_PORT,
                },
                guest_shim: None,
            },
        )
        .expect("guest contract should build from prepared launch")
    }

    #[test]
    fn guest_pty_selection_requires_matching_profile_and_executable() {
        let mut codex = test_launch("codex");
        codex.executable = "codex".to_string();
        assert_eq!(
            GuestTerminalSelection::from_launch(&codex, test_terminal_snapshot(true)),
            GuestTerminalSelection::Pty(GuestPtyRequest {
                data_port: VZ_GUEST_COMMAND_PTY_VSOCK_PORT,
                control_port: VZ_GUEST_COMMAND_PTY_CONTROL_VSOCK_PORT,
                term: Some("xterm-256color".to_string()),
                size: TerminalSize::from_parts(NonZeroU16::new(40), NonZeroU16::new(120)),
            })
        );

        let mut codex_path = test_launch("codex");
        codex_path.executable = "/usr/bin/codex".to_string();
        assert!(matches!(
            GuestTerminalSelection::from_launch(&codex_path, test_terminal_snapshot(true)),
            GuestTerminalSelection::Pty(_)
        ));

        let mut codex_version = test_launch("codex");
        codex_version.executable = "/usr/bin/true".to_string();
        assert_eq!(
            GuestTerminalSelection::from_launch(&codex_version, test_terminal_snapshot(true)),
            GuestTerminalSelection::NonInteractive
        );

        let mut generic_codex = test_launch("generic");
        generic_codex.executable = "codex".to_string();
        assert_eq!(
            GuestTerminalSelection::from_launch(&generic_codex, test_terminal_snapshot(true)),
            GuestTerminalSelection::NonInteractive
        );
    }

    #[test]
    fn generic_launch_stays_noninteractive_with_host_terminal() {
        let generic = test_launch("generic");
        let terminal_snapshot = test_terminal_snapshot(true);

        let terminal = VzGuestTerminalContract::from_launch_with_terminal_snapshot(
            &generic,
            terminal_snapshot,
        );

        assert!(!terminal.interactive);
        assert!(!terminal.pty);
        assert_eq!(terminal.pty_vsock_port, None);
        assert_eq!(terminal.pty_control_vsock_port, None);
        assert_eq!(terminal.term, None);
        assert_eq!(terminal.rows, None);
        assert_eq!(terminal.cols, None);
    }

    #[test]
    fn guest_pty_contract_captures_host_terminal_metadata() {
        let mut codex = test_launch("codex");
        codex.executable = "codex".to_string();
        let terminal_snapshot = test_terminal_snapshot(true);

        let terminal =
            VzGuestTerminalContract::from_launch_with_terminal_snapshot(&codex, terminal_snapshot);

        assert!(terminal.interactive);
        assert!(terminal.pty);
        assert_eq!(
            terminal.pty_vsock_port,
            Some(VZ_GUEST_COMMAND_PTY_VSOCK_PORT)
        );
        assert_eq!(
            terminal.pty_control_vsock_port,
            Some(VZ_GUEST_COMMAND_PTY_CONTROL_VSOCK_PORT)
        );
        assert_eq!(terminal.term.as_deref(), Some("xterm-256color"));
        assert_eq!(terminal.rows, Some(40));
        assert_eq!(terminal.cols, Some(120));
    }

    #[test]
    fn guest_pty_launch_stays_noninteractive_without_host_terminal() {
        let identity = RunIdentity::new(crate::identity::test_agent_id(), "codex");
        let handle = SandboxHandle {
            backend: BackendKind::Vz,
            runtime_dir: PathBuf::from("/tmp/firma-test-vz-guest"),
            identity,
            mounts: vec![],
            network_policy: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };

        let mut launch = test_launch("codex");
        launch.executable = "codex".to_string();
        let terminal_snapshot = test_terminal_snapshot(false);

        let contract = VzGuestLaunchContract::from_launch_with_terminal_snapshot(
            &handle,
            &launch,
            VzGuestLaunchInputs {
                runner: PathBuf::from("/Applications/Firma/vz-runner"),
                kernel: PathBuf::from("/var/lib/firma/vz/vmlinuz"),
                initrd: PathBuf::from("/var/lib/firma/vz/initrd.img"),
                rootfs: PathBuf::from("/var/lib/firma/vz/rootfs.img"),
            },
            terminal_snapshot,
            &SecretShimSupport::IsolatedGuest {
                guest_target: ShimTarget::linux_musl(),
                broker_bridge: BrokerBridgeKind::VsockPort {
                    port: VZ_GUEST_BROKER_VSOCK_PORT,
                },
                guest_shim: None,
            },
        )
        .expect("guest contract should build from prepared launch");

        let json = serde_json::to_value(&contract).expect("serialize contract");
        assert_eq!(json["command"]["executable"], "codex");
        assert_eq!(json["terminal"]["interactive"], false);
        assert_eq!(json["terminal"]["pty"], false);
        assert_eq!(json["terminal"]["pty_vsock_port"], serde_json::Value::Null);
        assert_eq!(
            json["terminal"]["pty_control_vsock_port"],
            serde_json::Value::Null
        );
        assert_eq!(json["terminal"]["term"], serde_json::Value::Null);
        assert_eq!(json["terminal"]["rows"], serde_json::Value::Null);
        assert_eq!(json["terminal"]["cols"], serde_json::Value::Null);
    }

    #[cfg(unix)]
    fn json_keys(value: &serde_json::Value) -> BTreeSet<String> {
        value
            .as_object()
            .expect("json object")
            .keys()
            .cloned()
            .collect()
    }

    #[cfg(unix)]
    fn key_set(keys: &[&str]) -> BTreeSet<String> {
        keys.iter().map(|key| (*key).to_string()).collect()
    }

    #[cfg(unix)]
    fn assert_stable_vz_guest_contract_shape(json: &serde_json::Value) {
        assert_eq!(
            json_keys(json),
            key_set(&[
                "command",
                "guest",
                "invariants",
                "mounts",
                "network",
                "runner",
                "runtime_dir",
                "sandbox_id",
                "terminal",
                "version",
            ])
        );
        assert_eq!(json_keys(&json["runner"]), key_set(&["path"]));
        assert_eq!(
            json_keys(&json["guest"]),
            key_set(&["initrd", "kernel", "rootfs"])
        );
        assert_eq!(
            json_keys(&json["command"]),
            key_set(&["args", "cwd", "env", "executable", "identity_mode",])
        );
        assert_eq!(
            json_keys(&json["terminal"]),
            key_set(&[
                "cols",
                "interactive",
                "pty",
                "pty_control_vsock_port",
                "pty_vsock_port",
                "rows",
                "term"
            ])
        );
        assert_eq!(
            json_keys(&json["network"]),
            key_set(&[
                "attribution_headers",
                "direct_network_devices_allowed",
                "dns_mode",
                "guest_dns_stub_addr",
                "guest_http_proxy_addr",
                "mode",
                "sidecar_host_addr",
                "vsock_sidecar_port",
            ])
        );

        let invariants = json["invariants"].as_array().expect("invariants array");
        let invariant_names = invariants
            .iter()
            .map(|invariant| invariant["name"].as_str().expect("invariant name"))
            .collect::<Vec<_>>();
        assert_eq!(
            invariant_names,
            vec![
                "sidecar_only_egress",
                "dns_confined",
                "fail_closed_startup",
                "fail_closed_runtime",
                "direct_bypass_resistant",
                "preserve_stdio_signals_exit",
            ]
        );
        for invariant in invariants {
            assert_eq!(json_keys(invariant), key_set(&["mode", "name"]));
        }
    }

    #[cfg(unix)]
    fn assert_vz_guest_runner_contract_json(
        json: &serde_json::Value,
        identity: &RunIdentity,
        expected_runner: &Path,
        kernel: &Path,
        initrd: &Path,
        rootfs: &Path,
    ) {
        assert_stable_vz_guest_contract_shape(json);
        assert_eq!(json["version"], 2);
        assert_eq!(json["sandbox_id"], identity.sandbox_id.to_string());
        assert_eq!(
            json["runner"]["path"],
            expected_runner.display().to_string()
        );
        assert_eq!(json["guest"]["kernel"], kernel.display().to_string());
        assert_eq!(json["guest"]["initrd"], initrd.display().to_string());
        assert_eq!(json["guest"]["rootfs"], rootfs.display().to_string());
        assert_eq!(json["command"]["executable"], "codex");
        assert_eq!(json["command"]["args"][0], "--version");
        assert_eq!(json["network"]["mode"], "vsock_sidecar");
        assert_eq!(json["network"]["guest_http_proxy_addr"], "127.0.0.1:18080");
        assert_eq!(json["network"]["guest_dns_stub_addr"], "127.0.0.1:1053");
        assert_eq!(json["network"]["vsock_sidecar_port"], 18080);
        assert_eq!(json["network"]["sidecar_host_addr"], "127.0.0.1:18081");
        assert_eq!(json["network"]["direct_network_devices_allowed"], false);
        assert_eq!(json["network"]["dns_mode"], "confined_stub");
        assert_eq!(
            json["network"]["attribution_headers"]["x-firma-sandbox-id"],
            identity.sandbox_id.to_string()
        );
        assert!(
            json["command"]["env"]
                .as_object()
                .expect("contract env")
                .get("FIRMA_CAPABILITY_TOKEN")
                .is_none(),
            "runner contract must not serialize capability tokens"
        );
    }

    fn assert_backend_error_contains(error: &RunError, expected: &str) {
        if let RunError::Backend { backend, reason } = error {
            assert_eq!(backend, "vz");
            assert!(
                reason.contains(expected),
                "expected backend error reason to contain {expected:?}, got {reason:?}"
            );
            return;
        }

        assert!(
            matches!(error, RunError::Backend { .. }),
            "expected backend error containing {expected:?}, got {error:?}"
        );
    }

    #[cfg(unix)]
    fn write_regular_file(path: &Path, contents: &str) -> PathBuf {
        std::fs::write(path, contents).expect("write file");
        path.to_path_buf()
    }

    #[cfg(unix)]
    fn write_fake_vz_runner(
        dir: &Path,
        args_capture_path: &Path,
        contract_copy_path: &Path,
    ) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let runner_path = dir.join("fake-vz-runner.sh");
        let script = include_str!("fixtures/fake-vz-runner.sh")
            .replace(
                "__FIRMA_ARGS_CAPTURE__",
                &args_capture_path.display().to_string(),
            )
            .replace(
                "__FIRMA_CONTRACT_COPY__",
                &contract_copy_path.display().to_string(),
            );

        std::fs::write(&runner_path, script).expect("write fake runner");
        let mut permissions = std::fs::metadata(&runner_path)
            .expect("fake runner metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&runner_path, permissions).expect("chmod fake runner");

        runner_path
    }

    #[cfg(unix)]
    fn complete_vz_guest_input_env(root: &Path) -> BTreeMap<String, String> {
        let args_capture_path = root.join("runner-args.txt");
        let contract_copy_path = root.join("contract-copy.json");
        let runner = write_fake_vz_runner(root, &args_capture_path, &contract_copy_path);
        let kernel = write_regular_file(&root.join("vmlinuz"), "kernel");
        let initrd = write_regular_file(&root.join("initrd.img"), "initrd");
        let rootfs = write_regular_file(&root.join("rootfs.img"), "rootfs");

        BTreeMap::from([
            (
                VZ_GUEST_RUNNER_ENV.to_string(),
                runner.display().to_string(),
            ),
            (
                VZ_GUEST_KERNEL_ENV.to_string(),
                kernel.display().to_string(),
            ),
            (
                VZ_GUEST_INITRD_ENV.to_string(),
                initrd.display().to_string(),
            ),
            (
                VZ_GUEST_ROOTFS_ENV.to_string(),
                rootfs.display().to_string(),
            ),
        ])
    }

    fn write_guest_bundle(root: &Path, rust_target: &str) -> VzGuestLaunchInputs {
        let kernel = root.join("vmlinuz");
        let initrd = root.join("initrd.img");
        let rootfs = root.join("rootfs.img");
        std::fs::write(&kernel, b"kernel").expect("write kernel");
        std::fs::write(&initrd, b"initrd").expect("write initrd");
        std::fs::write(&rootfs, b"rootfs").expect("write rootfs");
        let hash = |value: &[u8]| hex::encode(Sha256::digest(value));
        std::fs::write(
            root.join("manifest.txt"),
            format!(
                "contract_version=2\nrust_target={rust_target}\nkernel_sha256={}\ninitrd_sha256={}\nrootfs_sha256={}\nshim_sha256={}\n",
                hash(b"kernel"),
                hash(b"initrd"),
                hash(b"rootfs"),
                hash(b"shim")
            ),
        )
        .expect("write manifest");
        VzGuestLaunchInputs {
            runner: root.join("runner"),
            kernel,
            initrd,
            rootfs,
        }
    }

    #[test]
    fn guest_manifest_target_is_authoritative_for_shim_selection() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let inputs = write_guest_bundle(tempdir.path(), "aarch64-unknown-linux-musl");

        let (target, shim_sha256) =
            validate_guest_manifest(&inputs).expect("validate guest bundle");
        let expected_shim_sha256: [u8; 32] = Sha256::digest(b"shim").into();

        assert_eq!(target.triple, "aarch64-unknown-linux-musl");
        assert_eq!(shim_sha256, expected_shim_sha256);
    }

    #[test]
    fn guest_manifest_requires_shim_digest() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let inputs = write_guest_bundle(tempdir.path(), "x86_64-unknown-linux-musl");
        let manifest_path = tempdir.path().join("manifest.txt");
        let manifest = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = manifest
            .lines()
            .filter(|line| !line.starts_with("shim_sha256="))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&manifest_path, manifest).expect("write manifest without shim digest");

        let error = validate_guest_manifest(&inputs).expect_err("missing shim digest must fail");

        assert_backend_error_contains(&error, "missing required shim_sha256");
    }

    #[test]
    fn guest_manifest_rejects_malformed_shim_digest() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let inputs = write_guest_bundle(tempdir.path(), "x86_64-unknown-linux-musl");
        let manifest_path = tempdir.path().join("manifest.txt");
        let manifest = std::fs::read_to_string(&manifest_path)
            .expect("read manifest")
            .replace(&hex::encode(Sha256::digest(b"shim")), "not-a-sha256-digest");
        std::fs::write(&manifest_path, manifest).expect("write malformed manifest");

        let error = validate_guest_manifest(&inputs).expect_err("malformed shim digest must fail");

        assert_backend_error_contains(&error, "malformed shim_sha256");
    }

    #[test]
    fn guest_manifest_requires_all_artifacts_to_be_siblings() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let other = tempfile::tempdir().expect("other tempdir");
        let mut inputs = write_guest_bundle(tempdir.path(), "x86_64-unknown-linux-musl");
        inputs.kernel = other.path().join("vmlinuz");
        std::fs::write(&inputs.kernel, b"kernel").expect("write displaced kernel");

        let error = validate_guest_manifest(&inputs).expect_err("split bundle must fail");

        assert_backend_error_contains(&error, "not a sibling");
    }

    #[test]
    fn guest_manifest_verifies_every_bundle_artifact_checksum() {
        for (artifact, checksum_field) in [
            ("vmlinuz", "kernel_sha256"),
            ("initrd.img", "initrd_sha256"),
            ("rootfs.img", "rootfs_sha256"),
        ] {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let inputs = write_guest_bundle(tempdir.path(), "x86_64-unknown-linux-musl");
            std::fs::write(tempdir.path().join(artifact), b"tampered")
                .expect("tamper guest artifact");

            let error =
                validate_guest_manifest(&inputs).expect_err("artifact checksum mismatch must fail");

            assert_backend_error_contains(&error, checksum_field);
            if artifact == "vmlinuz"
                && let RunError::Backend { backend, reason } = &error
            {
                assert_eq!(backend, "vz");
                let manifest_path = tempdir.path().join("manifest.txt");
                let manifest_path = manifest_path.display().to_string();
                assert!(reason.contains(&manifest_path));
                insta::assert_snapshot!(
                    error.to_string().replace(&manifest_path, "[MANIFEST]"),
                    @"backend error (vz): VZ guest manifest [MANIFEST] has incompatible kernel_sha256: expected '6923dd1bc0460082c5d55a831908c24a282860b7f1cd6c2b79cf1bc8857c639c', got 'd121be3103007b41edf96f8262925f8c7d61894afe9a041843b631f69445bc57'"
                );
            }
        }
    }

    // ── compatibility mode ────────────────────────────────────────────────────

    #[test]
    fn compatibility_mode_allows_default_no_network_deny() {
        let launch = test_launch("generic");
        let profile = build_sandbox_profile(&launch, VzStructuralMode::Compatibility);
        assert!(profile.contains("(allow default)"));
        assert!(
            !profile.contains("deny network-outbound"),
            "compatibility mode must not restrict network: {profile}"
        );
    }

    #[test]
    fn claude_profile_denies_sensitive_home_paths_in_compatibility_mode() {
        let launch = test_launch("claude-code");
        let profile = build_sandbox_profile(&launch, VzStructuralMode::Compatibility);
        assert!(profile.contains("deny file-read* (subpath \"/Users/tester/.ssh\")"));
        assert!(profile.contains("deny file-write* (subpath \"/Users/tester/.config\")"));
    }

    // ── structural mode ───────────────────────────────────────────────────────

    #[test]
    fn vz_guest_mode_takes_precedence_over_sandbox_exec_flag() {
        assert_eq!(
            vz_structural_mode_from_flags(true, false),
            VzStructuralMode::VzGuest
        );
        assert_eq!(
            vz_structural_mode_from_flags(true, true),
            VzStructuralMode::VzGuest
        );
        assert_eq!(
            vz_structural_mode_from_flags(false, true),
            VzStructuralMode::SandboxExecNetworkDeny
        );
        assert_eq!(
            vz_structural_mode_from_flags(false, false),
            VzStructuralMode::Compatibility
        );
    }

    #[test]
    fn structural_mode_adds_network_deny_rule() {
        let launch = test_launch("generic");
        let profile = build_sandbox_profile(&launch, VzStructuralMode::SandboxExecNetworkDeny);
        assert!(
            profile.contains("(deny network-outbound)"),
            "structural mode must deny outbound network: {profile}"
        );
    }

    #[test]
    fn structural_mode_allows_loopback_unscoped_fallback_when_ports_unknown() {
        // `generic` launch has no HTTP_PROXY / FIRMA_DNS_STUB_ADDR, so the
        // builder cannot scope ports and falls back to allowing all loopback.
        let launch = test_launch("generic");
        let profile = build_sandbox_profile(&launch, VzStructuralMode::SandboxExecNetworkDeny);
        assert!(
            profile.contains("(allow network-outbound (remote ip4 \"localhost:*\"))"),
            "fallback must allow IPv4 localhost loopback: {profile}"
        );
        assert!(
            profile.contains("(allow network-outbound (remote ip6 \"localhost:*\"))"),
            "fallback must allow IPv6 localhost loopback: {profile}"
        );
        assert!(
            !profile.contains("(remote ip4 \"127.0.0.1\")"),
            "sandbox-exec rejects loopback rules without a port: {profile}"
        );
    }

    #[test]
    fn structural_mode_port_scopes_loopback_to_firma_endpoints() {
        let mut launch = test_launch("generic");
        launch.env.insert(
            "HTTP_PROXY".to_string(),
            "http://127.0.0.1:18080".to_string(),
        );
        launch.env.insert(
            "FIRMA_DNS_STUB_ADDR".to_string(),
            "127.0.0.1:5353".to_string(),
        );
        let profile = build_sandbox_profile(&launch, VzStructuralMode::SandboxExecNetworkDeny);

        assert!(profile.contains("(deny network-outbound)"), "{profile}");
        assert!(
            profile.contains("(allow network-outbound (remote ip4 \"localhost:18080\"))"),
            "proxy-bridge port must be allow-listed: {profile}"
        );
        assert!(
            profile.contains("(allow network-outbound (remote ip6 \"localhost:18080\"))"),
            "{profile}"
        );
        assert!(
            profile.contains("(allow network-outbound (remote ip4 \"localhost:5353\"))"),
            "DNS stub port must be allow-listed: {profile}"
        );
        assert!(
            !profile.contains("localhost:*"),
            "loopback must be port-scoped, not wildcard, when ports are known: {profile}"
        );
    }

    #[test]
    fn loopback_port_parsing_handles_scheme_path_and_bare_forms() {
        let cases = [
            ("http://127.0.0.1:18080", Some(18080)),
            ("http://127.0.0.1:18080/", Some(18080)),
            ("http://127.0.0.1:18080/path?q=1", Some(18080)),
            ("127.0.0.1:5353", Some(5353)),
            ("http://[::1]:18080", Some(18080)),
            ("127.0.0.1", None),
            ("http://127.0.0.1:notaport", None),
        ];
        for (input, expected) in cases {
            let value = input.to_string();
            assert_eq!(
                loopback_port_from(Some(&value)),
                expected,
                "parsing {input:?}"
            );
        }
        assert_eq!(loopback_port_from(None), None);
    }

    #[test]
    fn structural_deny_appears_after_allow_default() {
        let launch = test_launch("generic");
        let profile = build_sandbox_profile(&launch, VzStructuralMode::SandboxExecNetworkDeny);
        let allow_pos = profile.find("(allow default)").expect("allow default");
        let deny_pos = profile
            .find("(deny network-outbound)")
            .expect("deny outbound");
        assert!(
            deny_pos > allow_pos,
            "network-deny rule must appear after (allow default): {profile}"
        );
    }

    #[test]
    fn structural_mode_with_claude_profile_combines_both_rules() {
        let launch = test_launch("claude-code");
        let profile = build_sandbox_profile(&launch, VzStructuralMode::SandboxExecNetworkDeny);
        assert!(
            profile.contains("(deny network-outbound)"),
            "needs network deny"
        );
        assert!(
            profile.contains("(allow network-outbound (remote ip4 \"localhost:*\"))"),
            "needs loopback allow"
        );
        assert!(
            profile.contains("deny file-read* (subpath \"/Users/tester/.ssh\")"),
            "needs sensitive path denial"
        );
    }

    #[test]
    fn vz_runtime_dir_is_created() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let runtime_dir = tempdir.path().join("runtime").join("nested");

        super::create_vz_runtime_dir(&runtime_dir).expect("create runtime dir");

        assert!(runtime_dir.is_dir(), "runtime dir should exist");
    }

    #[cfg(unix)]
    #[test]
    fn vz_runtime_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().expect("tempdir");
        let runtime_dir = tempdir.path().join("runtime").join("nested");

        super::create_vz_runtime_dir(&runtime_dir).expect("create runtime dir");

        let mode = std::fs::metadata(&runtime_dir)
            .expect("runtime dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "runtime dir must be owner-only");
    }

    #[test]
    fn vz_runtime_dir_creation_error_is_backend_error() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let blocker = tempdir.path().join("runtime-file");
        std::fs::write(&blocker, b"not a directory").expect("write blocker file");
        let runtime_dir = blocker.join("nested");

        let error =
            super::create_vz_runtime_dir(&runtime_dir).expect_err("runtime dir should fail");

        assert_backend_error_contains(&error, "failed to create private runtime dir");
        assert_backend_error_contains(&error, &runtime_dir.display().to_string());
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "linear contract shape regression test"
    )]
    fn vz_guest_contract_carries_command_mounts_network_and_invariants() {
        let identity = RunIdentity::new(crate::identity::test_agent_id(), "claude-code");
        let handle = SandboxHandle {
            backend: BackendKind::Vz,
            runtime_dir: PathBuf::from("/tmp/firma-test-vz-guest"),
            identity: identity.clone(),
            mounts: vec![crate::backend::SandboxMount::operator_provided(
                crate::config::MountSpec {
                    source: PathBuf::from("/Users/tester/project"),
                    target: PathBuf::from("/workspace"),
                    read_only: false,
                },
            )],
            network_policy: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };
        let mut launch = test_launch("claude-code");
        launch.env.insert(
            "HTTP_PROXY".to_string(),
            "http://127.0.0.1:18080".to_string(),
        );
        launch.env.insert(
            "FIRMA_DNS_STUB_ADDR".to_string(),
            "127.0.0.1:5353".to_string(),
        );
        launch.env.insert(
            "FIRMA_CAPABILITY_TOKEN".to_string(),
            "secret-capability-token".to_string(),
        );
        launch.args = vec!["--print".to_string()];

        let contract = VzGuestLaunchContract::from_launch(
            &handle,
            &launch,
            VzGuestLaunchInputs {
                runner: PathBuf::from("/Applications/Firma/vz-runner"),
                kernel: PathBuf::from("/var/lib/firma/vz/vmlinuz"),
                initrd: PathBuf::from("/var/lib/firma/vz/initrd.img"),
                rootfs: PathBuf::from("/var/lib/firma/vz/rootfs.img"),
            },
            &SecretShimSupport::IsolatedGuest {
                guest_target: ShimTarget::linux_musl(),
                broker_bridge: BrokerBridgeKind::VsockPort {
                    port: VZ_GUEST_BROKER_VSOCK_PORT,
                },
                guest_shim: None,
            },
        )
        .expect("guest contract should build from prepared launch");

        let json = serde_json::to_value(&contract).expect("serialize contract");
        assert_eq!(json["version"], 2);
        assert_eq!(json["sandbox_id"], identity.sandbox_id.to_string());
        assert_eq!(json["command"]["executable"], "/usr/bin/true");
        assert_eq!(json["command"]["args"][0], "--print");
        assert_eq!(json["command"]["env"]["HOME"], "/Users/tester");
        assert_eq!(json["terminal"]["interactive"], false);
        assert_eq!(json["terminal"]["pty"], false);
        assert_eq!(json["terminal"]["pty_vsock_port"], serde_json::Value::Null);
        assert_eq!(
            json["terminal"]["pty_control_vsock_port"],
            serde_json::Value::Null
        );
        assert!(
            json["command"]["env"]
                .as_object()
                .expect("contract env object")
                .get("HTTP_PROXY")
                .is_none(),
            "host proxy env must not be serialized into VZ guest command env"
        );
        assert!(
            json["command"]["env"]
                .as_object()
                .expect("contract env object")
                .get("FIRMA_DNS_STUB_ADDR")
                .is_none(),
            "host DNS stub env must not be serialized into VZ guest command env"
        );
        assert!(
            json["command"]["env"]
                .as_object()
                .expect("contract env object")
                .get("FIRMA_CAPABILITY_TOKEN")
                .is_none(),
            "capability token must not be serialized into VZ guest contract"
        );
        assert_eq!(json["mounts"][0]["target"], "/workspace");
        assert_eq!(json["network"]["mode"], "vsock_sidecar");
        assert_eq!(json["network"]["guest_http_proxy_addr"], "127.0.0.1:18080");
        assert_eq!(json["network"]["guest_dns_stub_addr"], "127.0.0.1:1053");
        assert_eq!(json["network"]["vsock_sidecar_port"], 18080);
        assert_eq!(json["network"]["sidecar_host_addr"], "127.0.0.1:18081");
        assert_eq!(json["network"]["direct_network_devices_allowed"], false);
        assert_eq!(json["network"]["dns_mode"], "confined_stub");
        assert_eq!(
            json["network"]["attribution_headers"]["x-firma-profile"],
            "claude-code"
        );
        let invariants = json["invariants"].as_array().expect("invariants array");
        assert!(
            invariants
                .iter()
                .any(|invariant| invariant["name"] == "sidecar_only_egress"
                    && invariant["mode"] == "required"),
            "sidecar-only egress invariant must be required: {invariants:?}"
        );
        assert!(
            invariants
                .iter()
                .any(|invariant| invariant["name"] == "dns_confined"
                    && invariant["mode"] == "required"),
            "DNS confinement invariant must be required: {invariants:?}"
        );
        assert!(
            invariants
                .iter()
                .any(|invariant| invariant["name"] == "direct_bypass_resistant"
                    && invariant["mode"] == "required"),
            "direct-bypass invariant must be required: {invariants:?}"
        );
    }

    #[test]
    fn vz_guest_contract_write_reports_contract_dir_creation_error() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let runtime_file = tempdir.path().join("runtime-file");
        std::fs::write(&runtime_file, b"not a directory").expect("write blocker file");
        let handle = test_handle(runtime_file);
        let layout = VzGuestLayout::from_runtime_dir(&handle.runtime_dir);
        let contract = test_contract(&handle);

        let error = write_vz_guest_launch_contract(&handle, &contract)
            .expect_err("contract dir creation should fail");

        assert_backend_error_contains(&error, "failed to create private VZ guest contract dir");
        assert_backend_error_contains(&error, &layout.guest_dir().display().to_string());
    }

    #[test]
    fn vz_guest_contract_write_reports_contract_file_error() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let handle = test_handle(tempdir.path().join("runtime"));
        let layout = VzGuestLayout::from_runtime_dir(&handle.runtime_dir);
        let contract_dir = layout.guest_dir();
        std::fs::create_dir_all(&contract_dir).expect("create contract dir");
        std::fs::create_dir(layout.launch_contract()).expect("create contract path directory");
        let contract = test_contract(&handle);

        let error = write_vz_guest_launch_contract(&handle, &contract)
            .expect_err("contract file write should fail");

        assert_backend_error_contains(&error, "failed to write VZ guest launch contract");
        assert_backend_error_contains(&error, &layout.launch_contract().display().to_string());
    }

    #[test]
    fn vz_guest_contract_rejects_non_loopback_sidecar_endpoint() {
        let handle = test_handle(PathBuf::from("/tmp/firma-test-vz-guest"));
        let mut launch = test_launch("claude-code");
        launch.sidecar_endpoint = SidecarEndpoint::Tcp {
            addr: "10.0.0.2:18081".parse().expect("test sidecar addr"),
        };

        let error = VzGuestLaunchContract::from_launch(
            &handle,
            &launch,
            VzGuestLaunchInputs {
                runner: PathBuf::from("/Applications/Firma/vz-runner"),
                kernel: PathBuf::from("/var/lib/firma/vz/vmlinuz"),
                initrd: PathBuf::from("/var/lib/firma/vz/initrd.img"),
                rootfs: PathBuf::from("/var/lib/firma/vz/rootfs.img"),
            },
            &SecretShimSupport::IsolatedGuest {
                guest_target: ShimTarget::linux_musl(),
                broker_bridge: BrokerBridgeKind::VsockPort {
                    port: VZ_GUEST_BROKER_VSOCK_PORT,
                },
                guest_shim: None,
            },
        )
        .expect_err("non-loopback sidecar endpoint must fail closed");

        if let RunError::UnsupportedBackend { reason, .. } = &error {
            assert!(
                reason.contains("loopback TCP sidecar endpoint"),
                "expected reason to mention loopback sidecar endpoint, got {reason:?}"
            );
            return;
        }

        assert!(
            matches!(error, RunError::UnsupportedBackend { .. }),
            "expected unsupported backend error, got {error:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn vz_guest_contract_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after unix epoch")
            .as_nanos();

        let runtime_dir = std::env::temp_dir().join(format!(
            "firma-test-vz-contract-{}-{now}",
            std::process::id()
        ));

        let identity = RunIdentity::new(crate::identity::test_agent_id(), "claude-code");
        let handle = SandboxHandle {
            backend: BackendKind::Vz,
            runtime_dir: runtime_dir.clone(),
            identity,
            mounts: Vec::new(),
            network_policy: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };

        let mut launch = test_launch("claude-code");
        launch.env.insert(
            "HTTP_PROXY".to_string(),
            "http://127.0.0.1:18080".to_string(),
        );
        launch.env.insert(
            "FIRMA_DNS_STUB_ADDR".to_string(),
            "127.0.0.1:5353".to_string(),
        );
        launch.env.insert(
            "FIRMA_CAPABILITY_TOKEN".to_string(),
            "secret-capability-token".to_string(),
        );

        let contract = VzGuestLaunchContract::from_launch(
            &handle,
            &launch,
            VzGuestLaunchInputs {
                runner: PathBuf::from("/Applications/Firma/vz-runner"),
                kernel: PathBuf::from("/var/lib/firma/vz/vmlinuz"),
                initrd: PathBuf::from("/var/lib/firma/vz/initrd.img"),
                rootfs: PathBuf::from("/var/lib/firma/vz/rootfs.img"),
            },
            &SecretShimSupport::IsolatedGuest {
                guest_target: ShimTarget::linux_musl(),
                broker_bridge: BrokerBridgeKind::VsockPort {
                    port: VZ_GUEST_BROKER_VSOCK_PORT,
                },
                guest_shim: None,
            },
        )
        .expect("guest contract should build from prepared launch");

        let contract_path =
            write_vz_guest_launch_contract(&handle, &contract).expect("write contract");

        let layout = VzGuestLayout::from_runtime_dir(&runtime_dir);
        assert_eq!(contract_path, layout.launch_contract());

        let dir_mode = std::fs::metadata(contract_path.parent().expect("contract dir"))
            .expect("contract dir metadata")
            .permissions()
            .mode()
            & 0o777;
        let file_mode = std::fs::metadata(&contract_path)
            .expect("contract file metadata")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(dir_mode, 0o700, "contract dir must be owner-only");
        assert_eq!(file_mode, 0o600, "contract file must be owner-only");

        let written_contract =
            std::fs::read_to_string(&contract_path).expect("contract should be readable");
        assert!(!written_contract.contains("FIRMA_CAPABILITY_TOKEN"));
        assert!(!written_contract.contains("secret-capability-token"));

        let _ = std::fs::remove_dir_all(runtime_dir);
    }

    #[cfg(unix)]
    #[test]
    fn vz_guest_runner_receives_launch_contract_arg_and_stable_contract() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let args_capture_path = tempdir.path().join("runner-args.txt");
        let contract_copy_path = tempdir.path().join("contract-copy.json");
        let runner = write_fake_vz_runner(tempdir.path(), &args_capture_path, &contract_copy_path);
        let expected_runner = runner.clone();
        let kernel = write_regular_file(&tempdir.path().join("vmlinuz"), "kernel");
        let initrd = write_regular_file(&tempdir.path().join("initrd.img"), "initrd");
        let rootfs = write_regular_file(&tempdir.path().join("rootfs.img"), "rootfs");
        let identity = RunIdentity::new(crate::identity::test_agent_id(), "codex");
        let handle = SandboxHandle {
            backend: BackendKind::Vz,
            runtime_dir: tempdir.path().join("runtime"),
            identity: identity.clone(),
            mounts: vec![crate::backend::SandboxMount::operator_provided(
                crate::config::MountSpec {
                    source: PathBuf::from("/Users/tester/project"),
                    target: PathBuf::from("/workspace"),
                    read_only: false,
                },
            )],
            network_policy: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };
        let mut launch = test_launch("codex");
        launch.executable = "codex".to_string();
        launch.args = vec!["--version".to_string()];
        launch.env.insert(
            "HTTP_PROXY".to_string(),
            "http://127.0.0.1:18080".to_string(),
        );
        launch.env.insert(
            "FIRMA_DNS_STUB_ADDR".to_string(),
            "127.0.0.1:5353".to_string(),
        );
        launch.env.insert(
            "FIRMA_CAPABILITY_TOKEN".to_string(),
            "secret-capability-token".to_string(),
        );

        let mut child = start_vz_guest_runner_with_inputs(
            &handle,
            &launch,
            VzGuestLaunchInputs {
                runner,
                kernel: kernel.clone(),
                initrd: initrd.clone(),
                rootfs: rootfs.clone(),
            },
            &SecretShimSupport::IsolatedGuest {
                guest_target: ShimTarget::linux_musl(),
                broker_bridge: BrokerBridgeKind::VsockPort {
                    port: VZ_GUEST_BROKER_VSOCK_PORT,
                },
                guest_shim: None,
            },
        )
        .expect("fake VZ runner should spawn");
        let status = child.wait().expect("fake VZ runner should exit");
        assert!(status.success(), "fake runner failed: {status:?}");

        let captured_args =
            std::fs::read_to_string(&args_capture_path).expect("fake runner should capture args");
        let args = captured_args.lines().collect::<Vec<_>>();
        assert_eq!(
            args.len(),
            2,
            "runner must receive exactly --launch-contract and its path"
        );
        assert_eq!(args[0], "--launch-contract");
        let contract_path = PathBuf::from(args[1]);
        let layout = VzGuestLayout::from_runtime_dir(&handle.runtime_dir);
        assert_eq!(contract_path, layout.launch_contract());
        assert!(
            contract_path.exists(),
            "firma-run should write the source launch contract before spawning the runner"
        );

        let copied_contract =
            std::fs::read_to_string(&contract_copy_path).expect("fake runner contract copy");
        let json: serde_json::Value =
            serde_json::from_str(&copied_contract).expect("contract json");
        assert_vz_guest_runner_contract_json(
            &json,
            &identity,
            &expected_runner,
            &kernel,
            &initrd,
            &rootfs,
        );
    }

    #[cfg(unix)]
    #[test]
    fn vz_guest_launch_uses_custody_bundle_after_source_replacement() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let source_dir = tempdir.path().join("source");
        let custody_dir = tempdir.path().join("custody");
        std::fs::create_dir_all(&source_dir).expect("create source dir");
        let mut source = write_guest_bundle(&source_dir, "x86_64-unknown-linux-musl");
        let args_capture_path = tempdir.path().join("runner-args.txt");
        let contract_copy_path = tempdir.path().join("contract-copy.json");
        source.runner = write_fake_vz_runner(&source_dir, &args_capture_path, &contract_copy_path);
        let values = BTreeMap::from([
            (
                VZ_GUEST_RUNNER_ENV.to_string(),
                source.runner.display().to_string(),
            ),
            (
                VZ_GUEST_KERNEL_ENV.to_string(),
                source.kernel.display().to_string(),
            ),
            (
                VZ_GUEST_INITRD_ENV.to_string(),
                source.initrd.display().to_string(),
            ),
            (
                VZ_GUEST_ROOTFS_ENV.to_string(),
                source.rootfs.display().to_string(),
            ),
        ]);
        let context =
            VzGuestRunContext::resolve_with_lookup(&custody_dir, |key| values.get(key).cloned())
                .expect("resolve immutable VZ bundle context");

        for path in [&source.kernel, &source.initrd, &source.rootfs] {
            std::fs::write(path, b"replaced after resolution").expect("replace source artifact");
        }
        std::fs::write(&source.runner, b"replaced runner").expect("replace source runner");
        std::fs::write(
            source.initrd.with_file_name("manifest.txt"),
            b"replaced manifest",
        )
        .expect("replace source manifest");

        let handle = test_handle(tempdir.path().join("runtime"));
        let launch = test_launch("immutable-bundle");
        let expected_inputs = context.inputs.clone();
        let mut child = start_vz_guest_runner_with_inputs(
            &handle,
            &launch,
            context.inputs,
            &isolated_guest_shim_support(context.guest_target, None),
        )
        .expect("spawn runner from custody");
        assert!(child.wait().expect("wait for runner").success());

        let contract: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&contract_copy_path).expect("read captured contract"),
        )
        .expect("parse captured contract");
        assert_eq!(
            contract["runner"]["path"],
            serde_json::json!(expected_inputs.runner)
        );
        assert_eq!(
            contract["guest"]["kernel"],
            serde_json::json!(expected_inputs.kernel)
        );
        assert_eq!(
            contract["guest"]["initrd"],
            serde_json::json!(expected_inputs.initrd)
        );
        assert_eq!(
            contract["guest"]["rootfs"],
            serde_json::json!(expected_inputs.rootfs)
        );
        assert_eq!(
            std::fs::read(&expected_inputs.kernel).expect("read custody kernel"),
            b"kernel"
        );
        assert_eq!(
            std::fs::read(&expected_inputs.initrd).expect("read custody initrd"),
            b"initrd"
        );
        assert_eq!(
            std::fs::read(&expected_inputs.rootfs).expect("read custody rootfs"),
            b"rootfs"
        );
    }

    #[cfg(unix)]
    #[test]
    fn vz_guest_inputs_fail_closed_when_required_env_is_unset() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let complete_env = complete_vz_guest_input_env(tempdir.path());

        for missing_key in [
            VZ_GUEST_RUNNER_ENV,
            VZ_GUEST_KERNEL_ENV,
            VZ_GUEST_INITRD_ENV,
            VZ_GUEST_ROOTFS_ENV,
        ] {
            let mut values = complete_env.clone();
            values.remove(missing_key);
            let error = VzGuestLaunchInputs::from_env_lookup(|key| values.get(key).cloned())
                .expect_err("missing VZ guest input must fail closed");
            assert_backend_error_contains(&error, missing_key);
            assert_backend_error_contains(&error, "requires");
        }
    }

    #[cfg(unix)]
    #[test]
    fn vz_guest_inputs_fail_closed_when_required_artifacts_are_missing() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let complete_env = complete_vz_guest_input_env(tempdir.path());

        for missing_key in [
            VZ_GUEST_RUNNER_ENV,
            VZ_GUEST_KERNEL_ENV,
            VZ_GUEST_INITRD_ENV,
            VZ_GUEST_ROOTFS_ENV,
        ] {
            let mut values = complete_env.clone();
            values.insert(
                missing_key.to_string(),
                tempdir
                    .path()
                    .join(format!("missing-{missing_key}"))
                    .display()
                    .to_string(),
            );
            let error = VzGuestLaunchInputs::from_env_lookup(|key| values.get(key).cloned())
                .expect_err("missing VZ guest artifact must fail closed");
            assert_backend_error_contains(&error, missing_key);
            assert_backend_error_contains(&error, "does not exist");
        }
    }

    // ── EnforcementProof ─────────────────────────────────────────────────────

    #[test]
    fn enforce_network_compatibility_proof_is_proxy_only() {
        // Verify the compatibility branch directly via proof construction.
        // The structural mode is env-var gated; we test the proxy-only branch.
        use crate::backend::{NetworkConfinement, SandboxBackend, SandboxHandle};
        use crate::config::NetworkPolicy;
        use crate::identity::RunIdentity;

        let backend = super::VzBackend::new();
        let handle = SandboxHandle {
            backend: BackendKind::Vz,
            runtime_dir: PathBuf::from("/tmp/firma-test-vz"),
            identity: RunIdentity::new(crate::identity::test_agent_id(), "generic"),
            mounts: vec![],
            network_policy: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };

        // On non-macOS hosts the enforce_network call returns UnsupportedBackend;
        // on macOS without the env var it returns ProxyOnly.
        if cfg!(target_os = "macos") && std::env::var("FIRMA_RUN_VZ_STRUCTURAL_NETWORK").is_err() {
            let proof = backend
                .enforce_network(&handle, &handle.network_policy)
                .expect("enforce_network must succeed on macOS in compatibility mode");
            assert!(
                !proof.structural,
                "compatibility mode must be non-structural"
            );
            assert_eq!(proof.network_confinement, NetworkConfinement::ProxyOnly);
        }
    }

    #[test]
    fn network_confinement_serializes_correctly() {
        use crate::backend::NetworkConfinement;
        let json =
            serde_json::to_string(&NetworkConfinement::MacosSandboxNetworkDeny).expect("serialize");
        assert_eq!(json, r#""macos_sandbox_network_deny""#);
        let json =
            serde_json::to_string(&NetworkConfinement::LinuxNetworkNamespace).expect("serialize");
        assert_eq!(json, r#""linux_network_namespace""#);
        let json = serde_json::to_string(&NetworkConfinement::MacosVzGuest).expect("serialize");
        assert_eq!(json, r#""macos_vz_guest""#);
        let json = serde_json::to_string(&NetworkConfinement::ProxyOnly).expect("serialize");
        assert_eq!(json, r#""proxy_only""#);
    }
}

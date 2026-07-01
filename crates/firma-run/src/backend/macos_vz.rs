use std::collections::BTreeMap;
use std::fmt::Write as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use crate::backend::{
    BackendKind, EnforcementProof, LaunchSpec, NetworkConfinement, PrepareRequest, SandboxBackend,
    SandboxHandle,
};
use crate::config::MountSpec;
use crate::config::NetworkPolicy;
use crate::error::RunError;

const VZ_GUEST_MODE_ENV: &str = "FIRMA_RUN_VZ_GUEST";
const VZ_STRUCTURAL_NETWORK_ENV: &str = "FIRMA_RUN_VZ_STRUCTURAL_NETWORK";
const VZ_GUEST_RUNNER_ENV: &str = "FIRMA_RUN_VZ_GUEST_RUNNER";
const VZ_GUEST_KERNEL_ENV: &str = "FIRMA_RUN_VZ_GUEST_KERNEL";
const VZ_GUEST_INITRD_ENV: &str = "FIRMA_RUN_VZ_GUEST_INITRD";
const VZ_GUEST_ROOTFS_ENV: &str = "FIRMA_RUN_VZ_GUEST_ROOTFS";
const VZ_GUEST_LAUNCH_CONTRACT_VERSION: u32 = 1;
const VZ_GUEST_CONTRACT_DIR: &str = "vz-guest";
const VZ_GUEST_CONTRACT_FILE: &str = "vz-guest-launch.json";
const VZ_GUEST_SECRET_ENV_KEYS: &[&str] = &["FIRMA_CAPABILITY_TOKEN"];

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
pub struct VzBackend;

impl VzBackend {
    #[must_use]
    pub fn new() -> Self {
        Self
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
                let inputs = VzGuestLaunchInputs::from_env()?;
                tracing::info!(
                    mode = "vz_guest",
                    runner = %inputs.runner.display(),
                    kernel = %inputs.kernel.display(),
                    initrd = %inputs.initrd.display(),
                    rootfs = %inputs.rootfs.display(),
                    "macOS VZ structural preflight: guest runner and images validated"
                );
            }
        }

        let runtime_dir = std::env::temp_dir()
            .join("firma-run")
            .join(&request.identity.sandbox_id);

        create_vz_runtime_dir(&runtime_dir)?;

        let mounts = request
            .profile
            .mounts
            .iter()
            .cloned()
            .chain(std::iter::once(MountSpec {
                source: request.working_dir.clone(),
                target: request.working_dir.clone(),
                read_only: false,
            }))
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

    fn start_agent(&self, handle: &SandboxHandle, launch: &LaunchSpec) -> Result<Child, RunError> {
        if !cfg!(target_os = "macos") {
            return Err(RunError::UnsupportedBackend {
                backend: BackendKind::Vz.to_string(),
                reason: "cannot start VZ backend agent on non-macOS host".to_string(),
            });
        }

        let mode = vz_structural_mode();
        if mode == VzStructuralMode::VzGuest {
            return start_vz_guest_runner(handle, launch);
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
            let runtime_home = std::env::temp_dir()
                .join("firma-run")
                .join(
                    launch
                        .env
                        .get("FIRMA_RUN_SANDBOX_ID")
                        .cloned()
                        .unwrap_or_else(|| "claude-code".to_string()),
                )
                .display()
                .to_string();
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
}

/// Create the VZ runtime tree with owner-only custody.
///
/// VZ guest mode writes launch context under this directory later in the run,
/// so the whole runtime tree must be private before any contract or runner
/// artifacts appear there.
fn create_vz_runtime_dir(runtime_dir: &Path) -> Result<(), RunError> {
    firma_runtime_state::fs::create_private_dir_all(runtime_dir).map_err(|error| {
        RunError::Backend {
            backend: BackendKind::Vz.to_string(),
            reason: format!(
                "failed to create private runtime dir {}: {error}",
                runtime_dir.display()
            ),
        }
    })
}

#[derive(Debug, Clone)]
struct VzGuestLaunchInputs {
    runner: PathBuf,
    kernel: PathBuf,
    initrd: PathBuf,
    rootfs: PathBuf,
}

impl VzGuestLaunchInputs {
    fn from_env() -> Result<Self, RunError> {
        Self::from_env_lookup(|name| std::env::var(name).ok())
    }

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
    mounts: Vec<MountSpec>,
    network: VzGuestNetworkContract,
    invariants: Vec<VzGuestInvariantContract>,
}

impl VzGuestLaunchContract {
    fn from_launch(
        handle: &SandboxHandle,
        launch: &LaunchSpec,
        inputs: VzGuestLaunchInputs,
    ) -> Result<Self, RunError> {
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
                seccomp_filter_path: launch.seccomp_filter_path.clone(),
            },
            mounts: handle.mounts.clone(),
            network: VzGuestNetworkContract::from_launch_env(
                &launch.env,
                handle.identity.full_attribution_headers(),
            )?,
            invariants: VzGuestInvariantContract::required_set(handle.network_policy.fail_closed),
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
    seccomp_filter_path: Option<PathBuf>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct VzGuestNetworkContract {
    proxy_url: String,
    dns_stub_addr: String,
    attribution_headers: BTreeMap<String, String>,
}

impl VzGuestNetworkContract {
    fn from_launch_env(
        env: &BTreeMap<String, String>,
        attribution_headers: BTreeMap<String, String>,
    ) -> Result<Self, RunError> {
        Ok(Self {
            proxy_url: required_launch_env(env, "HTTP_PROXY")?.to_string(),
            dns_stub_addr: required_launch_env(env, "FIRMA_DNS_STUB_ADDR")?.to_string(),
            attribution_headers,
        })
    }
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

fn start_vz_guest_runner(handle: &SandboxHandle, launch: &LaunchSpec) -> Result<Child, RunError> {
    let inputs = VzGuestLaunchInputs::from_env()?;
    start_vz_guest_runner_with_inputs(handle, launch, inputs)
}

fn start_vz_guest_runner_with_inputs(
    handle: &SandboxHandle,
    launch: &LaunchSpec,
    inputs: VzGuestLaunchInputs,
) -> Result<Child, RunError> {
    let runner = inputs.runner.clone();
    let contract = VzGuestLaunchContract::from_launch(handle, launch, inputs)?;
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
        .filter(|(key, _)| !VZ_GUEST_SECRET_ENV_KEYS.contains(&key.as_str()))
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
    let contract_dir = handle.runtime_dir.join(VZ_GUEST_CONTRACT_DIR);
    firma_runtime_state::fs::create_private_dir_all(&contract_dir).map_err(|error| {
        RunError::Backend {
            backend: BackendKind::Vz.to_string(),
            reason: format!(
                "failed to create private VZ guest contract dir {}: {error}",
                contract_dir.display()
            ),
        }
    })?;

    let contract_path = contract_dir.join(VZ_GUEST_CONTRACT_FILE);
    let json = serde_json::to_vec_pretty(contract).map_err(|error| {
        RunError::Internal(format!(
            "failed to serialize macOS VZ guest launch contract: {error}"
        ))
    })?;

    firma_runtime_state::fs::write_private_file(&contract_path, &json).map_err(|error| {
        RunError::Backend {
            backend: BackendKind::Vz.to_string(),
            reason: format!(
                "failed to write VZ guest launch contract {}: {error}",
                contract_path.display()
            ),
        }
    })?;

    Ok(contract_path)
}

fn required_launch_env<'a>(
    env: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, RunError> {
    env.get(key)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| RunError::Backend {
            backend: BackendKind::Vz.to_string(),
            reason: format!(
                "VZ guest launch requires {key} from network runtime; sidecar bridge was not prepared"
            ),
        })
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

/// Extracts the port from a `host:port` or `scheme://host:port` env value
/// (e.g. `http://127.0.0.1:18080` or `127.0.0.1:5353`).
fn loopback_port_from(value: Option<&String>) -> Option<u16> {
    let raw = value?.trim();
    // Drop any scheme/path so only the authority remains, then take the port.
    let authority = raw.rsplit('/').next().unwrap_or(raw);
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
    #[cfg(unix)]
    use std::path::Path;
    use std::path::PathBuf;

    use crate::backend::{BackendKind, LaunchSpec, SandboxHandle};
    use crate::config::{NetworkPolicy, SandboxIdentityMode};
    use crate::error::RunError;
    use crate::identity::RunIdentity;

    #[cfg(unix)]
    use super::{
        VZ_GUEST_CONTRACT_DIR, VZ_GUEST_CONTRACT_FILE, VZ_GUEST_INITRD_ENV, VZ_GUEST_KERNEL_ENV,
        VZ_GUEST_ROOTFS_ENV, VZ_GUEST_RUNNER_ENV, start_vz_guest_runner_with_inputs,
    };
    use super::{
        VzGuestLaunchContract, VzGuestLaunchInputs, VzStructuralMode, build_sandbox_profile,
        vz_structural_mode_from_flags,
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
            seccomp_filter_path: None,
            identity_mode: SandboxIdentityMode::SandboxUser,
        }
    }

    fn test_handle(runtime_dir: PathBuf) -> SandboxHandle {
        SandboxHandle {
            backend: BackendKind::Vz,
            runtime_dir,
            identity: RunIdentity::new("claude-code"),
            mounts: Vec::new(),
            network_policy: NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
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
        )
        .expect("guest contract should build from prepared launch")
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
            key_set(&[
                "args",
                "cwd",
                "env",
                "executable",
                "identity_mode",
                "seccomp_filter_path",
            ])
        );
        assert_eq!(
            json_keys(&json["network"]),
            key_set(&["attribution_headers", "dns_stub_addr", "proxy_url"])
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
        assert_eq!(json["version"], 1);
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
        assert_eq!(json["network"]["proxy_url"], "http://127.0.0.1:18080");
        assert_eq!(json["network"]["dns_stub_addr"], "127.0.0.1:5353");
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
    fn vz_guest_contract_carries_command_mounts_network_and_invariants() {
        let identity = RunIdentity::new("claude-code");
        let handle = SandboxHandle {
            backend: BackendKind::Vz,
            runtime_dir: PathBuf::from("/tmp/firma-test-vz-guest"),
            identity: identity.clone(),
            mounts: vec![crate::config::MountSpec {
                source: PathBuf::from("/Users/tester/project"),
                target: PathBuf::from("/workspace"),
                read_only: false,
            }],
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
        )
        .expect("guest contract should build from prepared launch");

        let json = serde_json::to_value(&contract).expect("serialize contract");
        assert_eq!(json["version"], 1);
        assert_eq!(json["sandbox_id"], identity.sandbox_id.to_string());
        assert_eq!(json["command"]["executable"], "/usr/bin/true");
        assert_eq!(json["command"]["args"][0], "--print");
        assert_eq!(json["command"]["env"]["HOME"], "/Users/tester");
        assert!(
            json["command"]["env"]
                .as_object()
                .expect("contract env object")
                .get("FIRMA_CAPABILITY_TOKEN")
                .is_none(),
            "capability token must not be serialized into VZ guest contract"
        );
        assert_eq!(json["mounts"][0]["target"], "/workspace");
        assert_eq!(json["network"]["proxy_url"], "http://127.0.0.1:18080");
        assert_eq!(json["network"]["dns_stub_addr"], "127.0.0.1:5353");
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
        let contract = test_contract(&handle);

        let error = super::write_vz_guest_launch_contract(&handle, &contract)
            .expect_err("contract dir creation should fail");

        assert_backend_error_contains(&error, "failed to create private VZ guest contract dir");
        assert_backend_error_contains(&error, super::VZ_GUEST_CONTRACT_DIR);
    }

    #[test]
    fn vz_guest_contract_write_reports_contract_file_error() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let handle = test_handle(tempdir.path().join("runtime"));
        let contract_dir = handle.runtime_dir.join(super::VZ_GUEST_CONTRACT_DIR);
        std::fs::create_dir_all(&contract_dir).expect("create contract dir");
        std::fs::create_dir(contract_dir.join(super::VZ_GUEST_CONTRACT_FILE))
            .expect("create contract path directory");
        let contract = test_contract(&handle);

        let error = super::write_vz_guest_launch_contract(&handle, &contract)
            .expect_err("contract file write should fail");

        assert_backend_error_contains(&error, "failed to write VZ guest launch contract");
        assert_backend_error_contains(&error, super::VZ_GUEST_CONTRACT_FILE);
    }

    #[cfg(unix)]
    #[test]
    fn vz_guest_contract_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        use super::{
            VZ_GUEST_CONTRACT_DIR, VZ_GUEST_CONTRACT_FILE, write_vz_guest_launch_contract,
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after unix epoch")
            .as_nanos();

        let runtime_dir = std::env::temp_dir().join(format!(
            "firma-test-vz-contract-{}-{now}",
            std::process::id()
        ));

        let identity = RunIdentity::new("claude-code");
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
        )
        .expect("guest contract should build from prepared launch");

        let contract_path =
            write_vz_guest_launch_contract(&handle, &contract).expect("write contract");

        assert_eq!(
            contract_path.file_name().expect("file name"),
            std::ffi::OsStr::new(VZ_GUEST_CONTRACT_FILE)
        );
        assert_eq!(
            contract_path
                .parent()
                .and_then(|path| path.file_name())
                .expect("contract dir name"),
            std::ffi::OsStr::new(VZ_GUEST_CONTRACT_DIR)
        );

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
        let identity = RunIdentity::new("codex");
        let handle = SandboxHandle {
            backend: BackendKind::Vz,
            runtime_dir: tempdir.path().join("runtime"),
            identity: identity.clone(),
            mounts: vec![crate::config::MountSpec {
                source: PathBuf::from("/Users/tester/project"),
                target: PathBuf::from("/workspace"),
                read_only: false,
            }],
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
        assert_eq!(
            contract_path.file_name().expect("contract file name"),
            std::ffi::OsStr::new(VZ_GUEST_CONTRACT_FILE)
        );
        assert_eq!(
            contract_path
                .parent()
                .and_then(|path| path.file_name())
                .expect("contract dir name"),
            std::ffi::OsStr::new(VZ_GUEST_CONTRACT_DIR)
        );
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
            identity: RunIdentity::new("generic"),
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

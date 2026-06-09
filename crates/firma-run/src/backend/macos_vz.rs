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
///   wrapped process to loopback connections only. The host-side proxy bridge
///   and DNS stub run on loopback; other loopback services remain a residual
///   caveat until the guest-backed path can narrow the boundary further. This mode
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
        std::fs::create_dir_all(&runtime_dir).map_err(|error| RunError::Backend {
            backend: BackendKind::Vz.to_string(),
            reason: format!(
                "failed to create runtime dir {}: {error}",
                runtime_dir.display()
            ),
        })?;

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
                         reach loopback addresses (proxy bridge + DNS stub); all external outbound \
                         denied by TrustedBSD MAC policy"
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

#[derive(Debug, Clone)]
struct VzGuestLaunchInputs {
    runner: PathBuf,
    kernel: PathBuf,
    initrd: PathBuf,
    rootfs: PathBuf,
}

impl VzGuestLaunchInputs {
    fn from_env() -> Result<Self, RunError> {
        let runner = validate_required_file_env(VZ_GUEST_RUNNER_ENV)?;
        #[cfg(unix)]
        ensure_executable_file(VZ_GUEST_RUNNER_ENV, &runner)?;
        #[cfg(not(unix))]
        ensure_executable_file(VZ_GUEST_RUNNER_ENV, &runner);
        Ok(Self {
            runner,
            kernel: validate_required_file_env(VZ_GUEST_KERNEL_ENV)?,
            initrd: validate_required_file_env(VZ_GUEST_INITRD_ENV)?,
            rootfs: validate_required_file_env(VZ_GUEST_ROOTFS_ENV)?,
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
                env: launch.env.clone(),
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
    let runner = inputs.runner.clone();
    let contract = VzGuestLaunchContract::from_launch(handle, launch, inputs)?;
    let contract_path = handle.runtime_dir.join("vz-guest-launch.json");
    let json = serde_json::to_vec_pretty(&contract).map_err(|error| {
        RunError::Internal(format!(
            "failed to serialize macOS VZ guest launch contract: {error}"
        ))
    })?;
    std::fs::write(&contract_path, json).map_err(|error| RunError::Backend {
        backend: BackendKind::Vz.to_string(),
        reason: format!(
            "failed to write VZ guest launch contract {}: {error}",
            contract_path.display()
        ),
    })?;

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

fn validate_required_file_env(name: &str) -> Result<PathBuf, RunError> {
    let path = read_required_path_env(name)?;
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

fn read_required_path_env(name: &str) -> Result<PathBuf, RunError> {
    let value = std::env::var(name).map_err(|_| RunError::Backend {
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
/// after the default `allow`, then re-allows loopback. This means the wrapped
/// process can only make outbound connections to localhost loopback endpoints
/// (the host-side proxy bridge and DNS stub live there), and all external IP
/// connections are denied by `TrustedBSD` MAC at the socket layer — including raw sockets,
/// direct TCP/UDP, Unix-domain socket connects, and UDP-based DNS to external
/// resolvers. This is not port-scoped: other host loopback services are a
/// known residual caveat.
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

    // Structural network denial: block all outbound, then re-allow loopback.
    // This is applied for all profiles in structural mode. The rule blocks
    // ambient external egress; loopback remains a documented residual caveat.
    if mode == VzStructuralMode::SandboxExecNetworkDeny {
        profile.push_str(
            "; macOS structural: deny all outbound, allow loopback only\n\
             (deny network-outbound)\n\
             (allow network-outbound (remote ip4 \"localhost:*\"))\n\
             (allow network-outbound (remote ip6 \"localhost:*\"))\n",
        );
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
    use std::path::PathBuf;

    use crate::backend::{BackendKind, LaunchSpec, SandboxHandle};
    use crate::config::{NetworkPolicy, SandboxIdentityMode};
    use crate::identity::RunIdentity;

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
    fn structural_mode_allows_loopback() {
        let launch = test_launch("generic");
        let profile = build_sandbox_profile(&launch, VzStructuralMode::SandboxExecNetworkDeny);
        assert!(
            profile.contains("(allow network-outbound (remote ip4 \"localhost:*\"))"),
            "structural mode must allow IPv4 localhost loopback: {profile}"
        );
        assert!(
            profile.contains("(allow network-outbound (remote ip6 \"localhost:*\"))"),
            "structural mode must allow IPv6 localhost loopback: {profile}"
        );
        assert!(
            !profile.contains("(remote ip4 \"127.0.0.1\")"),
            "sandbox-exec rejects loopback rules without a port: {profile}"
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

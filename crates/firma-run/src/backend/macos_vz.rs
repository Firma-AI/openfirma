use std::fmt::Write as _;
use std::process::{Child, Command};

use crate::backend::{
    BackendKind, ConfinementMechanism, EnforcementProof, LaunchSpec, PrepareRequest,
    SandboxBackend, SandboxHandle,
};
use crate::config::MountSpec;
use crate::config::NetworkPolicy;
use crate::error::RunError;

/// macOS runtime backend.
///
/// Operates in one of two modes selected by the `FIRMA_RUN_VZ_STRUCTURAL_NETWORK`
/// environment variable:
///
/// - **Compatibility mode** (default): `sandbox-exec` + `HTTP_PROXY` injection.
///   Proxy-only; requires `--allow-non-structural`. Equivalent to the current
///   macOS baseline described in FIR-112.
///
/// - **Sandbox-exec structural mode** (`FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1`):
///   `sandbox-exec` with `deny network-outbound` policy that restricts the
///   wrapped process to loopback connections only. The host-side proxy bridge
///   and DNS stub run on loopback and are the sole egress paths. This mode
///   reports `structural=true` with `confinement_mechanism=macos_sandbox_network_deny`.
///   Tracking: FIR-112 Milestone 2 intermediate step.
///
/// The future VZ guest mode (FIR-112B) will replace sandbox-exec with an
/// Apple Virtualization.framework Linux guest for full network namespace
/// isolation equivalent to Linux `bwrap --unshare-net`.
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
    // Future: VZ guest path check (FIR-112B).
    // For now: env var selects sandbox-exec network-deny mode.
    if crate::config::env_truthy("FIRMA_RUN_VZ_STRUCTURAL_NETWORK") {
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
    /// Future: Apple Virtualization.framework Linux guest with isolated
    /// virtio networking. Not yet implemented — tracked in FIR-112B.
    #[allow(dead_code)]
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

        if !command_available("sandbox-exec") {
            return Err(RunError::Backend {
                backend: BackendKind::Vz.to_string(),
                reason: "sandbox-exec is not installed or not executable".to_string(),
            });
        }

        let mode = vz_structural_mode();
        if mode == VzStructuralMode::SandboxExecNetworkDeny {
            tracing::info!(
                mode = "sandbox_exec_network_deny",
                "macOS VZ structural preflight: sandbox-exec with deny network-outbound selected"
            );
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
                confinement_mechanism: ConfinementMechanism::MacosSandboxNetworkDeny,
            }),
            VzStructuralMode::Compatibility | VzStructuralMode::VzGuest => Ok(EnforcementProof {
                backend: BackendKind::Vz,
                structural: false,
                fail_closed: policy.fail_closed,
                detail: "macOS backend active; outbound mediation is currently proxy-based"
                    .to_string(),
                confinement_mechanism: ConfinementMechanism::ProxyOnly,
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

    fn start_agent(&self, _handle: &SandboxHandle, launch: &LaunchSpec) -> Result<Child, RunError> {
        if !cfg!(target_os = "macos") {
            return Err(RunError::UnsupportedBackend {
                backend: BackendKind::Vz.to_string(),
                reason: "cannot start VZ backend agent on non-macOS host".to_string(),
            });
        }

        let mode = vz_structural_mode();
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

/// Build the `sandbox-exec` SBPL profile for the given mode.
///
/// In `SandboxExecNetworkDeny` mode the profile adds `deny network-outbound`
/// after the default `allow`, then re-allows loopback. This means the wrapped
/// process can only make outbound connections to `127.0.0.1` (the host-side
/// proxy bridge and DNS stub), and all external IP connections are denied by
/// `TrustedBSD` MAC at the socket layer — including raw sockets, direct TCP/UDP,
/// and UDP-based DNS to external resolvers.
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
    // This is applied for ALL profiles in structural mode — the loopback-only
    // rule is the security boundary that makes the mode structural.
    if mode == VzStructuralMode::SandboxExecNetworkDeny {
        profile.push_str(
            "; FIR-112 macOS structural: deny all outbound, allow loopback only\n\
             (deny network-outbound)\n\
             (allow network-outbound (remote ip4 \"127.0.0.1\"))\n\
             (allow network-outbound (remote unix-socket))\n",
        );
    }

    // Sensitive home path masking for claude-code profile.
    if claude_profile && !home.is_empty() && home.starts_with('/') {
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

    use crate::backend::{BackendKind, LaunchSpec};
    use crate::config::SandboxIdentityMode;

    use super::{VzStructuralMode, build_sandbox_profile};

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
            profile.contains("(allow network-outbound (remote ip4 \"127.0.0.1\"))"),
            "structural mode must allow loopback: {profile}"
        );
    }

    #[test]
    fn structural_mode_allows_unix_sockets() {
        let launch = test_launch("generic");
        let profile = build_sandbox_profile(&launch, VzStructuralMode::SandboxExecNetworkDeny);
        assert!(
            profile.contains("(allow network-outbound (remote unix-socket))"),
            "structural mode must allow unix sockets for IPC: {profile}"
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
            profile.contains("(allow network-outbound (remote ip4 \"127.0.0.1\"))"),
            "needs loopback allow"
        );
        assert!(
            profile.contains("deny file-read* (subpath \"/Users/tester/.ssh\")"),
            "needs sensitive path denial"
        );
    }

    // ── EnforcementProof ─────────────────────────────────────────────────────

    #[test]
    fn enforce_network_compatibility_proof_is_proxy_only() {
        // Verify the compatibility branch directly via proof construction.
        // The structural mode is env-var gated; we test the proxy-only branch.
        use crate::backend::{ConfinementMechanism, SandboxBackend, SandboxHandle};
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
            assert_eq!(proof.confinement_mechanism, ConfinementMechanism::ProxyOnly);
        }
    }

    #[test]
    fn confinement_mechanism_serializes_correctly() {
        use crate::backend::ConfinementMechanism;
        let json = serde_json::to_string(&ConfinementMechanism::MacosSandboxNetworkDeny)
            .expect("serialize");
        assert_eq!(json, r#""macos_sandbox_network_deny""#);
        let json =
            serde_json::to_string(&ConfinementMechanism::LinuxNetworkNamespace).expect("serialize");
        assert_eq!(json, r#""linux_network_namespace""#);
        let json = serde_json::to_string(&ConfinementMechanism::ProxyOnly).expect("serialize");
        assert_eq!(json, r#""proxy_only""#);
    }
}

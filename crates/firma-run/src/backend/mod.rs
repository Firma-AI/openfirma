mod firecracker;
mod linux_bwrap;
mod macos_vz;
pub mod platform;
mod windows_wsl2;

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::Arc;

use firma_identifiers::SandboxId;
use serde::{Deserialize, Serialize};

use crate::config::{
    MountSpec, NetworkPolicy, ResolvedProfile, SandboxIdentityMode, SidecarEndpoint,
};
use crate::error::RunError;
use crate::identity::RunIdentity;

/// Whether a backend supports CLI secret-provider shim mediation and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretShimSupport {
    /// The backend cannot mediate CLI secret providers.
    Unsupported { reason: SecretShimUnsupportedReason },
    /// The backend can bind-mount a host-platform shim over the real provider
    /// executable because the guest shares the host filesystem and architecture.
    HostBindMount { guest_target: ShimTarget },
    /// The guest is an isolated VM that cannot reach the host directly; a
    /// guest-architecture shim is deployed alongside a redaction-only broker
    /// bridge so the guest can reach the host secret broker safely.
    IsolatedGuest {
        guest_target: ShimTarget,
        broker_bridge: BrokerBridgeKind,
        /// Immutable, bundle-matched shim selected for this run.
        guest_shim: Option<ResolvedGuestShim>,
    },
}

/// A guest shim whose exact bytes were validated against the guest manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGuestShim {
    pub(crate) target: ShimTarget,
    pub(crate) source_path: PathBuf,
    pub(crate) bytes: Arc<[u8]>,
}

/// Why a backend does not support CLI secret-provider shims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretShimUnsupportedReason {
    /// The guest can call the host directly, so mediation is unnecessary.
    HostCallable,
    /// Guest artifact deployment is not yet implemented for this backend.
    NotYetImplemented,
}

/// How the guest reaches the host-side secret broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerBridgeKind {
    /// VSOCK port forwarding to the host broker listener.
    VsockPort { port: u32 },
}

/// Target platform triple and executable suffix for a shim binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShimTarget {
    /// Rust-style target triple (e.g. `"x86_64-unknown-linux-musl"`).
    pub(crate) triple: &'static str,
    /// Platform executable suffix (e.g. `""` on Linux, `".exe"` on Windows).
    pub(crate) exe_suffix: &'static str,
}

impl ShimTarget {
    /// Resolve a supported Linux musl target triple.
    pub(crate) fn from_linux_musl_triple(triple: &str) -> Option<Self> {
        match triple {
            "x86_64-unknown-linux-musl" => Some(Self {
                triple: "x86_64-unknown-linux-musl",
                exe_suffix: "",
            }),
            "aarch64-unknown-linux-musl" => Some(Self {
                triple: "aarch64-unknown-linux-musl",
                exe_suffix: "",
            }),
            _ => None,
        }
    }

    /// Linux musl target for the current CPU architecture.
    #[must_use]
    #[cfg(target_arch = "x86_64")]
    pub(crate) const fn linux_musl() -> Self {
        Self {
            triple: "x86_64-unknown-linux-musl",
            exe_suffix: "",
        }
    }

    /// Linux musl target for the current CPU architecture.
    #[must_use]
    #[cfg(target_arch = "aarch64")]
    pub(crate) const fn linux_musl() -> Self {
        Self {
            triple: "aarch64-unknown-linux-musl",
            exe_suffix: "",
        }
    }
}

/// Identifies the OS-level mechanism that provides network confinement.
///
/// Used in [`EnforcementProof`] so operators and audit systems can
/// distinguish structurally equivalent guarantees achieved by different
/// primitives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkConfinement {
    /// Linux unprivileged network namespace (`bwrap --unshare-net`).
    LinuxNetworkNamespace,
    /// macOS `TrustedBSD` MAC sandbox with `deny network-outbound` policy.
    /// Provides kernel-enforced loopback-only egress without a VM guest.
    MacosSandboxNetworkDeny,
    /// Apple Virtualization.framework guest with isolated virtio networking.
    /// Implemented as a runner launch contract owned by the macOS VZ backend.
    MacosVzGuest,
    /// KVM micro-VM (Firecracker). Planned as enterprise additive path.
    KvmMicroVm,
    /// Proxy-only compatibility mode: enforcement depends on `HTTP_PROXY`
    /// cooperation from the wrapped process. Not structural.
    ProxyOnly,
}

pub use firecracker::FirecrackerBackend;
pub use linux_bwrap::BwrapBackend;
pub use macos_vz::VzBackend;
pub use windows_wsl2::Wsl2Backend;

/// Shared default home-relative paths considered sensitive across agent CLIs.
pub(crate) const DEFAULT_SENSITIVE_HOME_SUFFIXES: &[&str] = &[
    ".ssh",
    ".aws",
    ".azure",
    ".kube",
    ".gnupg",
    ".config",
    ".config/gcloud",
];

/// Host-side scratch directory owned by one sandbox backend instance.
struct SandboxRuntimeLayout {
    root: PathBuf,
}

impl SandboxRuntimeLayout {
    /// Create the standard layout beneath `temp_dir` for `sandbox_id`.
    fn in_temp_dir(temp_dir: &Path, sandbox_id: &SandboxId) -> Self {
        Self {
            root: temp_dir.join("firma-run").join(sandbox_id.to_string()),
        }
    }

    /// Consume the layout and return its sandbox-specific root directory.
    fn into_root(self) -> PathBuf {
        self.root
    }
}

/// Supported runtime backend choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Bwrap,
    Vz,
    Wsl2,
    Firecracker,
}

impl BackendKind {
    /// Default backend for current host platform.
    #[cfg_attr(
        all(target_os = "linux", not(test)),
        expect(dead_code, reason = "Linux resolves automatic backends separately")
    )]
    #[must_use]
    pub(crate) fn default_for_current_host() -> Self {
        #[cfg(target_os = "linux")]
        {
            return Self::Bwrap;
        }

        #[cfg(target_os = "macos")]
        {
            return Self::Vz;
        }

        #[cfg(target_os = "windows")]
        {
            return Self::Wsl2;
        }

        #[expect(
            unreachable_code,
            reason = "fallback satisfies exhaustive return typing after cfg-gated platform branches"
        )]
        Self::Bwrap
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Bwrap => "bwrap",
            Self::Vz => "vz",
            Self::Wsl2 => "wsl2",
            Self::Firecracker => "firecracker",
        };
        write!(f, "{text}")
    }
}

impl std::str::FromStr for BackendKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "bwrap" => Ok(Self::Bwrap),
            "vz" => Ok(Self::Vz),
            "wsl2" => Ok(Self::Wsl2),
            "firecracker" => Ok(Self::Firecracker),
            other => Err(format!(
                "unsupported backend '{other}'; expected one of: bwrap, vz, wsl2, firecracker"
            )),
        }
    }
}

/// Request payload for backend prepare stage.
#[derive(Debug, Clone)]
pub struct PrepareRequest {
    pub identity: RunIdentity,
    pub profile: ResolvedProfile,
    pub working_dir: PathBuf,
}

/// Handle produced by backend prepare stage.
#[derive(Debug, Clone)]
pub struct SandboxHandle {
    pub backend: BackendKind,
    pub runtime_dir: PathBuf,
    pub identity: RunIdentity,
    /// Prepared mounts, retaining their security authority until a backend
    /// emits its launch contract.
    pub mounts: Vec<SandboxMount>,
    pub network_policy: NetworkPolicy,
}

/// A mount carried by a prepared sandbox together with its security authority.
///
/// Operator-provided mounts and framework mounts cannot expose control-plane
/// state. Sandbox-infrastructure mounts are the narrow class allowed to
/// originate in the private per-sandbox runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxMount {
    spec: MountSpec,
    authority: SandboxMountAuthority,
    placement: SandboxMountPlacement,
}

/// Security authority assigned to a prepared [`SandboxMount`].
///
/// Backends use the authority to constrain which host sources a mount may
/// expose. The bwrap backend reserves access to its private sandbox runtime for
/// sandbox-infrastructure mounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::backend) enum SandboxMountAuthority {
    /// Mount controlled by the operator through external configuration.
    OperatorProvided,
    /// Mount introduced by an ordinary `OpenFirma` runtime integration.
    Framework,
    /// Backend-owned mount sourced from the private per-sandbox runtime.
    SandboxInfrastructure(SandboxInfrastructureKind),
}

/// Narrow facility represented by a sandbox-infrastructure mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::backend) enum SandboxInfrastructureKind {
    /// Identity database mounted at `/etc/passwd`.
    Passwd,
    /// Identity database mounted at `/etc/group`.
    Group,
    /// Resolver configuration mounted at `/etc/resolv.conf` or its host-side
    /// canonical target.
    ResolverConfig,
}

/// Layer in which a prepared mount may be emitted by an ordered backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::backend) enum SandboxMountPlacement {
    /// Ordinary overlay that must precede security seals.
    Overlay,
    /// Framework-owned subpath intentionally restored after configuration
    /// directories have been sealed.
    FrameworkProtectedSubpath,
}

impl SandboxMount {
    /// Assigns the authority used for an operator-provided mount.
    fn operator_provided(spec: MountSpec) -> Self {
        Self {
            spec,
            authority: SandboxMountAuthority::OperatorProvided,
            placement: SandboxMountPlacement::Overlay,
        }
    }

    /// Tags a mount introduced by an ordinary runtime integration.
    ///
    /// Framework mounts do not receive the privileged source-path exemption
    /// reserved for [`SandboxMountAuthority::SandboxInfrastructure`].
    pub(crate) fn framework(spec: MountSpec) -> Self {
        Self {
            spec,
            authority: SandboxMountAuthority::Framework,
            placement: SandboxMountPlacement::Overlay,
        }
    }

    /// Assigns framework authority to a mount that must remain visible inside
    /// an otherwise protected configuration directory.
    ///
    /// Ordered backends emit this narrow capability after configuration seals
    /// but before the final control-plane seal. The backend validates that the
    /// target is a strict protected-directory subpath.
    pub(crate) fn framework_protected_subpath(spec: MountSpec) -> Self {
        Self {
            spec,
            authority: SandboxMountAuthority::Framework,
            placement: SandboxMountPlacement::FrameworkProtectedSubpath,
        }
    }

    /// Creates a read-only backend facility sourced from private sandbox
    /// infrastructure.
    ///
    /// This authority is intentionally constructible only inside `backend`: the
    /// bwrap backend permits it to re-expose paths beneath its private sandbox
    /// runtime after masking the host control-plane runtime.
    fn sandbox_infrastructure(
        kind: SandboxInfrastructureKind,
        source: PathBuf,
        target: PathBuf,
    ) -> Self {
        Self {
            spec: MountSpec {
                source,
                target,
                read_only: true,
            },
            authority: SandboxMountAuthority::SandboxInfrastructure(kind),
            placement: SandboxMountPlacement::Overlay,
        }
    }

    /// Returns the backend-neutral mount specification.
    ///
    /// Backends without authority-sensitive mount validation use this at their
    /// serialization boundary to discard `OpenFirma`'s internal authority
    /// metadata.
    pub(crate) fn spec(&self) -> &MountSpec {
        &self.spec
    }

    /// Returns whether this mount carries the narrow framework capability to
    /// restore a subpath after configuration sealing.
    pub(crate) fn is_framework_protected_subpath(&self) -> bool {
        self.authority == SandboxMountAuthority::Framework
            && self.placement == SandboxMountPlacement::FrameworkProtectedSubpath
    }

    /// Returns whether this mount was introduced by a framework integration.
    pub(crate) fn is_framework(&self) -> bool {
        self.authority == SandboxMountAuthority::Framework
    }

    /// Returns the security authority retained with this prepared mount.
    fn authority(&self) -> SandboxMountAuthority {
        self.authority
    }

    /// Returns the security layer assigned to this prepared mount.
    fn placement(&self) -> SandboxMountPlacement {
        self.placement
    }
}

/// Network enforcement proof returned by backend.
#[derive(Debug, Clone)]
pub struct EnforcementProof {
    pub backend: BackendKind,
    pub structural: bool,
    pub fail_closed: bool,
    pub detail: String,
    /// OS primitive that enforces the network boundary, if any.
    pub network_confinement: NetworkConfinement,
}

/// Launch payload for wrapped command.
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    pub(crate) executable: String,
    pub(crate) args: Vec<String>,
    pub(crate) cwd: PathBuf,
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) sidecar_endpoint: SidecarEndpoint,
    /// Optional static seccomp cBPF artifact path resolved by runtime.
    ///
    /// Backends should treat this as the authoritative source for seccomp
    /// loading instead of relying on environment-variable indirection.
    #[cfg_attr(
        not(target_os = "linux"),
        expect(dead_code, reason = "seccomp is consumed only by the Linux backend")
    )]
    pub(crate) seccomp_filter_path: Option<PathBuf>,
    pub(crate) identity_mode: SandboxIdentityMode,
    /// Resolved `firma.toml` the agent is running under, if any.
    ///
    /// The Linux bwrap backend masks this file (and, when it lives in a
    /// `.firma/` directory, the whole directory) so the agent cannot read
    /// Authority topology / `agent_id` or poison its own config for a later
    /// run. It can sit outside the workspace cwd because config discovery walks
    /// up parent directories.
    pub(crate) config_file: Option<PathBuf>,
}

/// Backend interface for sandbox runtime implementations.
pub trait SandboxBackend: Send + Sync {
    /// Returns the concrete backend kind.
    fn kind(&self) -> BackendKind;

    /// Prepare host/sandbox state before launching an agent.
    ///
    /// # Errors
    ///
    /// Returns an error when runtime directories, mounts, or backend preflight
    /// requirements cannot be created/validated.
    fn prepare(&self, request: &PrepareRequest) -> Result<SandboxHandle, RunError>;

    /// Install structural network routing and return proof metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when backend-specific network confinement fails.
    fn enforce_network(
        &self,
        _handle: &SandboxHandle,
        policy: &NetworkPolicy,
    ) -> Result<EnforcementProof, RunError>;

    /// Verify fail-closed invariants after network policy application.
    ///
    /// # Errors
    ///
    /// Returns an error when fail-closed guarantees cannot be established.
    fn verify_fail_closed(
        &self,
        handle: &SandboxHandle,
        proof: &EnforcementProof,
    ) -> Result<(), RunError>;

    /// Launch the wrapped command inside the prepared sandbox.
    ///
    /// # Errors
    ///
    /// Returns an error when the child process cannot be spawned.
    fn start_agent(
        &self,
        runtime_layout: &firma_runtime_state::RuntimeLayout,
        handle: &SandboxHandle,
        launch: &LaunchSpec,
        shim_support: &SecretShimSupport,
    ) -> Result<Child, RunError>;

    /// Tear down backend runtime state after execution.
    ///
    /// # Errors
    ///
    /// Returns an error when backend cleanup fails.
    fn teardown(&self, handle: SandboxHandle) -> Result<(), RunError>;

    /// Returns whether this backend supports CLI secret-provider shim mediation.
    fn secret_shim_support(&self) -> SecretShimSupport;

    /// Resolve launch-specific shim support after validating runtime artifacts.
    ///
    /// # Errors
    ///
    /// Returns an error when a backend's runtime artifact metadata is missing
    /// or incompatible.
    fn resolve_secret_shim_support(
        &self,
        _runtime_layout: &firma_runtime_state::RuntimeLayout,
        _handle: &SandboxHandle,
        _firma_exe: &Path,
        _requires_cli_shim: bool,
    ) -> Result<SecretShimSupport, RunError> {
        Ok(self.secret_shim_support())
    }
}

/// Construct backend implementation for a kind.
#[must_use]
pub(crate) fn build_backend(kind: BackendKind) -> Box<dyn SandboxBackend> {
    match kind {
        BackendKind::Bwrap => Box::new(BwrapBackend::new()),
        BackendKind::Vz => Box::new(VzBackend::new()),
        BackendKind::Wsl2 => Box::new(Wsl2Backend::new()),
        BackendKind::Firecracker => Box::new(FirecrackerBackend::new()),
    }
}

//! Schema for the `[run]` section of `firma.toml`.
//!
//! Representation only. `firma-run` layers built-in profile defaults, file
//! config, and CLI overrides onto these patch types, merges them, then builds
//! its validated `ResolvedProfile` from the result. The merge and validation
//! behavior lives in `firma-run`; this module holds the deserialized shape.
//!
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Sandbox backend selected for a Run profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Bwrap,
    Vz,
    Wsl2,
    Firecracker,
}

/// Identity mode used inside sandboxed execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxIdentityMode {
    SandboxUser,
    HostUser,
}

/// Human-in-the-loop mediation mode for governed local execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandMediatorHitlMode {
    SyncWait,
    AsyncToken,
}

/// How the sandbox CA trust store is assembled for the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CaTrustMode {
    /// Inject only the firma-ca path (current behavior). System roots are not
    /// added; correct when every reachable host is MITM'd by firma.
    #[default]
    Sole,
    /// Inject a bundle of system roots + firma-ca. Needed for agents that talk
    /// to non-MITM'd hosts (e.g. Copilot → real GitHub) while still trusting
    /// firma-ca for intercepted hosts.
    AppendSystemRoots,
}

/// Runtime behavior for managed seccomp artifact selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompRuntimeMode {
    /// Compile/update managed seccomp artifacts during launch and then load.
    CompileOnLaunch,
    /// Require a precompiled managed seccomp artifact; do not compile at launch.
    PrecompiledOnly,
}

/// Top-level `[run]` file config.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Profile used by `firma run` when `--profile` is not supplied.
    pub profile: Option<String>,
    #[serde(default)]
    pub defaults: ProfilePatch,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfilePatch>,
}

/// Partial profile configuration merged from defaults, file, and CLI layers.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProfilePatch {
    /// Sandbox backend (`bwrap`, `vz`, `wsl2`, or `firecracker`).
    pub backend: Option<BackendKind>,
    pub sidecar_endpoint: Option<String>,
    pub seccomp_policy: Option<SeccompPolicyPatch>,
    #[serde(default)]
    pub env_passthrough: Vec<String>,
    #[serde(default)]
    pub env_set: BTreeMap<String, String>,
    #[serde(default)]
    pub mounts: Vec<MountPatch>,
    pub network: Option<NetworkPolicyPatch>,
    pub identity_mode: Option<SandboxIdentityMode>,
    pub capability: Option<CapabilityLeasePatch>,
    /// Preferred governance config path. This routes local tool execution
    /// decisions through a Sidecar-owned endpoint.
    pub sidecar_local_exec: Option<CommandMediatorPatch>,
    #[serde(default)]
    pub executable_policies: BTreeMap<String, ExecutableLaunchPolicyPatch>,
    #[serde(default)]
    pub codex_cli: Option<ExecutableLaunchPolicyPatch>,
    /// Configure the autostarted sidecar in HTTP proxy interceptor mode.
    /// Should be `true` for profiles whose agent uses standard HTTP proxy env vars.
    #[serde(default)]
    pub use_http_proxy_sidecar: bool,
    /// Allow non-structural (proxy-only) backends to run without failing closed.
    /// Intentional opt-in: proxy-only enforcement can be bypassed by clients
    /// that ignore `HTTP_PROXY`, open raw sockets, or spawn children with
    /// a clean environment.
    #[serde(default)]
    pub allow_non_structural: bool,
    /// Home-relative paths to mask with a tmpfs overlay inside the bwrap sandbox.
    /// Overrides the built-in `DEFAULT_SENSITIVE_HOME_SUFFIXES` for this profile.
    /// Example: `[".ssh", ".gnupg", ".aws"]` leaves `.config` accessible.
    pub mask_home_paths: Option<Vec<PathBuf>>,
    /// How the sandbox CA trust store is assembled. `None` resolves to the
    /// default `CaTrustMode::Sole`.
    pub ca_trust_mode: Option<CaTrustMode>,
}

/// Mount entry patch.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct MountPatch {
    pub source: PathBuf,
    pub target: PathBuf,
    #[serde(default)]
    pub read_only: bool,
}

/// Network policy toggles patch.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyPatch {
    pub enforce_network_namespace: Option<bool>,
    pub fail_closed: Option<bool>,
}

/// Seccomp policy compilation settings patch.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompPolicyPatch {
    pub source_policy_path: PathBuf,
    pub artifact_dir: PathBuf,
    pub runtime_mode: Option<SeccompRuntimeMode>,
}

/// Capability lease settings patch.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLeasePatch {
    pub source: Option<CapabilitySourcePatch>,
    #[serde(default)]
    pub kind: Option<CapabilitySourceKind>,
    #[serde(default)]
    pub path: Option<PathBuf>,
    pub public_key_path: Option<PathBuf>,
    pub refresh_ratio: Option<f64>,
    #[serde(
        with = "jiff::fmt::serde::unsigned_duration::friendly::compact::optional",
        default
    )]
    pub grace: Option<Duration>,
    #[serde(default)]
    pub requested_actions: Option<Vec<String>>,
}

/// Per-executable CLI argument policy patch.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableLaunchPolicyPatch {
    pub enforce_wrapper_defaults: Option<bool>,
    pub sandbox_mode: Option<String>,
    pub approval_policy: Option<String>,
    #[serde(default)]
    pub config_overrides: BTreeMap<String, String>,
}

/// Runtime command mediation settings patch.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandMediatorPatch {
    pub endpoint: Option<String>,
    #[serde(
        with = "jiff::fmt::serde::unsigned_duration::friendly::compact::optional",
        default
    )]
    pub timeout: Option<Duration>,
    pub hitl_mode: Option<CommandMediatorHitlMode>,
    #[serde(
        with = "jiff::fmt::serde::unsigned_duration::friendly::compact::optional",
        default
    )]
    pub hitl_max_wait: Option<Duration>,
    pub enforce_known_executables: Option<bool>,
    #[serde(default)]
    pub allowed_executables: Vec<PathBuf>,
}

/// Source for capability material patch.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilitySourcePatch {
    Disabled,
    File { path: PathBuf },
}

/// Legacy flat capability source selector retained for compatibility with
/// `capability.kind` plus `capability.path`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySourceKind {
    Disabled,
    File,
}

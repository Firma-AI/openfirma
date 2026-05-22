//! Args for `firma run`, `firma __dns-stub`, and `firma __proxy-bridge`.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, ValueEnum};

use firma_run::backend::BackendKind;
use firma_run::config::SandboxIdentityMode;

/// Arguments for `firma run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Built-in agent profile (e.g. `generic`, `codex`, `claude`) that selects
    /// default backend, identity mode and policy bundle.
    #[arg(long, default_value = "generic")]
    pub profile: String,

    /// Path to a runtime config file (`.toml`, `.yaml`, `.yml`) layered on top
    /// of the selected profile.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Force a specific sandbox backend instead of the profile's default.
    #[arg(long)]
    pub backend: Option<BackendOverride>,

    /// Path to a capability-token file made available to the agent for
    /// runtime lease refresh.
    #[arg(long)]
    pub capability_file: Option<PathBuf>,

    /// Override how the agent's identity is mapped inside the sandbox
    /// (`sandbox-user` for an isolated uid, `host-user` to keep the caller's uid).
    #[arg(long, value_enum)]
    pub identity_mode: Option<IdentityModeOverride>,

    /// Keep the host user's identity inside the sandbox. Required by tools
    /// that read `$HOME`-relative paths or expect a matching uid.
    #[arg(long, default_value_t = false)]
    pub preserve_host_user: bool,

    /// Print the merged effective config as JSON before launching the agent.
    /// Useful for debugging which knobs actually took effect.
    #[arg(long, default_value_t = false)]
    pub print_effective_config: bool,

    /// Sidecar selection. `local` autostarts a per-run sidecar; a
    /// `tcp://host:port` or `unix:///path/to/sock` value targets an existing
    /// external sidecar at that endpoint and never autostarts. When omitted,
    /// falls back to the persisted `sidecar_endpoint` in `firma.toml`
    /// (external) or, if none, local autostart.
    #[arg(long)]
    pub sidecar: Option<String>,

    /// Fail with a typed error instead of autostarting any missing component
    /// (sidecar or authority). CI / production safety net. Incompatible with
    /// `--sidecar local` and `--authority local`.
    #[arg(long, default_value_t = false)]
    pub no_autostart: bool,

    /// Optional sidecar config template path for the autostarted sidecar.
    /// Falls back to `FIRMA_SIDECAR_CONFIG_FILE`, then `./firma_sidecar.toml`,
    /// then a synthesized minimal config.
    #[arg(long)]
    pub sidecar_config: Option<PathBuf>,

    /// Seconds to wait for the autostarted sidecar's `ready` line.
    /// `0` reverts to the built-in default (10s).
    #[arg(long, default_value_t = 10)]
    pub sidecar_startup_timeout_secs: u64,

    /// Authority selection. `local` autostarts a local Mini Authority on
    /// `[::1]:50051`; any other value is treated as a remote Authority URL.
    /// When unset, falls back to the persisted `[authority]` section or
    /// the y/N bootstrap prompt.
    #[arg(long)]
    pub authority: Option<String>,

    /// Profile name materialised by the autostarted Mini Authority.
    /// Ignored when Authority is remote or already reachable.
    #[arg(long, default_value = firma_authority::DEFAULT_PROFILE)]
    pub authority_profile: String,

    /// Wrapped command and args (pass after `--`).
    #[arg(required = true, num_args = 1.., allow_hyphen_values = true)]
    pub command: Vec<String>,
}

/// Internal helper args for proxy-bridge process.
#[derive(Debug, Args)]
pub struct ProxyBridgeArgs {
    /// TCP listen address reachable by the sandboxed agent process.
    #[arg(long, default_value = "127.0.0.1:18080")]
    pub listen: SocketAddr,

    /// Upstream host-side Unix socket path exposed by `firma run`.
    #[arg(long)]
    pub upstream_uds: PathBuf,
}

/// Internal helper args for DNS stub process.
#[derive(Debug, Clone, Copy, Args)]
pub struct DnsStubArgs {
    /// UDP/TCP DNS listen address reachable by the sandboxed agent process.
    #[arg(long, default_value = "127.0.0.1:53")]
    pub listen: SocketAddr,
}

/// User-facing backend override values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BackendOverride {
    Bwrap,
    Vz,
    Wsl2,
    Firecracker,
}

/// User-facing identity mode override values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum IdentityModeOverride {
    SandboxUser,
    HostUser,
}

impl From<BackendOverride> for BackendKind {
    fn from(value: BackendOverride) -> Self {
        match value {
            BackendOverride::Bwrap => Self::Bwrap,
            BackendOverride::Vz => Self::Vz,
            BackendOverride::Wsl2 => Self::Wsl2,
            BackendOverride::Firecracker => Self::Firecracker,
        }
    }
}

impl From<IdentityModeOverride> for SandboxIdentityMode {
    fn from(value: IdentityModeOverride) -> Self {
        match value {
            IdentityModeOverride::SandboxUser => Self::SandboxUser,
            IdentityModeOverride::HostUser => Self::HostUser,
        }
    }
}

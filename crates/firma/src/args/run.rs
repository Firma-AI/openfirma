//! Args for `firma run`, `firma __dns-stub`, and `firma __proxy-bridge`.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, ValueEnum};

use firma_run::backend::BackendKind;
use firma_run::config::SandboxIdentityMode;

/// Arguments for `firma run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Built-in profile id to use.
    #[arg(long, default_value = "generic")]
    pub profile: String,

    /// Optional runtime config path (.toml, .yaml, .yml).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Override backend selection.
    #[arg(long)]
    pub backend: Option<BackendOverride>,

    /// Optional sidecar endpoint override.
    ///
    /// Accepted forms: `<tcp://127.0.0.1:8080>`, `<unix:///run/firma-sidecar.sock>`
    #[arg(long)]
    pub sidecar_endpoint: Option<String>,

    /// Optional capability token file path for runtime lease refresh.
    #[arg(long)]
    pub capability_file: Option<PathBuf>,

    /// Override sandbox identity mode.
    #[arg(long, value_enum)]
    pub identity_mode: Option<IdentityModeOverride>,

    /// Preserve host user identity inside sandbox for compatibility workflows.
    #[arg(long, default_value_t = false)]
    pub preserve_host_user: bool,

    /// Print the resolved effective config as JSON before execution.
    #[arg(long, default_value_t = false)]
    pub print_effective_config: bool,

    /// Sidecar selection. `auto` autostarts a per-run sidecar when the
    /// configured endpoint is unreachable; `external` requires an
    /// already-running sidecar at `--sidecar-endpoint`.
    #[arg(long, value_enum, default_value_t = SidecarSelector::Auto)]
    pub sidecar: SidecarSelector,

    /// Fail with a typed error if no sidecar is reachable at the
    /// configured endpoint, instead of autostarting one. CI safety net.
    #[arg(long, default_value_t = false, conflicts_with = "sidecar")]
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

/// User-facing sidecar selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SidecarSelector {
    /// Autostart a per-run sidecar when the configured endpoint is unreachable.
    Auto,
    /// Use the existing sidecar at the configured endpoint; never autostart.
    External,
}

impl From<SidecarSelector> for firma_run::runtime::SidecarMode {
    fn from(value: SidecarSelector) -> Self {
        match value {
            SidecarSelector::Auto => Self::Auto,
            SidecarSelector::External => Self::External,
        }
    }
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

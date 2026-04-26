use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::backend::BackendKind;

/// Top-level CLI for `firma` binary.
#[derive(Debug, Parser)]
#[command(name = "firma")]
#[command(about = "Firma runtime tools")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Supported top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run an agent command through the Firma runtime wrapper.
    Run(RunArgs),
    /// Internal process-local bridge from sandbox TCP proxy to host-side UDS.
    #[command(name = "__proxy-bridge", hide = true)]
    ProxyBridge(ProxyBridgeArgs),
}

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

    /// Print the resolved effective config as JSON before execution.
    #[arg(long, default_value_t = false)]
    pub print_effective_config: bool,

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

/// User-facing backend override values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BackendOverride {
    Bwrap,
    Vz,
    Wsl2,
    Firecracker,
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

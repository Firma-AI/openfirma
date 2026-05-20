//! Args for the `firma sidecar` subcommand.
//!
//! Bare `firma sidecar` runs the enforcement server (back-compat, used by
//! `firma run` autostart). Nested subcommands cover the operator-facing
//! lifecycle: `start`, `stop`, `status`.

use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Alternate sidecar mode. Absent => run the enforcement server.
    #[command(subcommand)]
    pub command: Option<SidecarCommand>,

    #[clap(flatten)]
    pub serve: ServeArgs,
}

#[derive(Debug, clap::Subcommand)]
pub enum SidecarCommand {
    /// Start the sidecar as a long-lived daemon. Bootstraps the local
    /// authority + sidecar pair so the operator-facing entry point
    /// (and `firma run --sidecar=external`) has something to talk to.
    Start(StartArgs),
    /// Stop the long-lived sidecar daemon (and any authority started
    /// alongside it).
    Stop(StopArgs),
    /// docker-ps-style listing / health probe of live sidecars.
    Status(StatusArgs),
}

#[derive(Debug, clap::Args)]
pub struct ServeArgs {
    /// The path to the configuration file for the sidecar.
    ///
    /// When unset, `firma.toml` is discovered from platform config
    /// dirs (see docs/cli.md).
    #[clap(long, short = 'c', env = "FIRMA_SIDECAR_CONFIG_FILE")]
    pub config: Option<PathBuf>,
    /// Health check binding address.
    #[clap(
        long,
        env = "FIRMA_SIDECAR_HEALTH_BIND_ADDR",
        default_value = "127.0.0.1:9000"
    )]
    pub health_bind_addr: SocketAddr,
}

#[derive(Debug, clap::Args)]
pub struct StartArgs {
    /// Stack config file. When unset, the platform `firma.toml` is used.
    #[arg(long, env = "FIRMA_SIDECAR_CONFIG_FILE")]
    pub config: Option<PathBuf>,
    /// Detach after readiness succeeds.
    #[arg(long)]
    pub detach: bool,
    /// State dir override.
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct StopArgs {
    /// Accepted for compatibility; `state_dir` is resolved from
    /// `--state-dir` / `FIRMA_STATE_DIR` / XDG.
    #[arg(long, env = "FIRMA_SIDECAR_CONFIG_FILE")]
    pub config: Option<PathBuf>,
    /// State dir override.
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    /// Soft-shutdown grace before hard-kill, in seconds.
    #[arg(long, default_value_t = 2)]
    pub timeout: u64,
}

#[derive(Debug, clap::Args)]
pub struct StatusArgs {
    /// Health-probe only the sidecar with this sandbox id.
    #[clap(long)]
    pub sandbox_id: Option<String>,
    /// Emit a single JSON array, one object per sidecar.
    #[clap(long)]
    pub json: bool,
    /// Probe the long-lived daemon sidecar instead of per-run markers.
    #[clap(long)]
    pub daemon: bool,
}

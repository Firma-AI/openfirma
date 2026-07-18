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
    /// Start the Sidecar (and a local Authority alongside it) as a long-lived
    /// daemon. Once running, `firma run --sidecar <url>` and any external
    /// callers can connect to the shared enforcement endpoint.
    Start(StartArgs),
    /// Stop the long-lived Sidecar daemon and any Authority that was started
    /// alongside it. Graceful by default; falls back to hard-kill after
    /// `--timeout` seconds.
    Stop(StopArgs),
    /// List live Sidecars and probe their health (docker-ps-style table, or
    /// JSON with `--json`). Covers per-run Sidecars and the long-lived daemon.
    Status(StatusArgs),
}

#[derive(Debug, clap::Args)]
pub struct ServeArgs {
    /// Path to the Sidecar's `firma.toml` config (listen addresses, Authority
    /// endpoint, mapping rules, …). When unset, discovered from platform config
    /// dirs (see docs/cli.md).
    #[clap(long, short = 'c', env = "FIRMA_SIDECAR_CONFIG_FILE")]
    pub config: Option<PathBuf>,
    /// Address the readiness / health-check HTTP endpoint binds to.
    #[clap(
        long,
        env = "FIRMA_SIDECAR_HEALTH_BIND_ADDR",
        default_value = "127.0.0.1:9000"
    )]
    pub health_bind_addr: SocketAddr,
}

#[derive(Debug, clap::Args)]
pub struct StartArgs {
    /// Path to the `firma.toml` config used to launch the stack. When unset,
    /// the platform-default config is used.
    #[arg(long, env = "FIRMA_SIDECAR_CONFIG_FILE")]
    pub config: Option<PathBuf>,
    /// Detach into the background once readiness has been confirmed. Without
    /// this flag the command stays attached to the foreground.
    #[arg(long)]
    pub detach: bool,
    /// Override the runtime state directory (pid files, sockets, logs).
    /// Defaults to `FIRMA_STATE_DIR` or the platform default.
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct StopArgs {
    /// Accepted for symmetry with `start`; the running daemon is located via
    /// `--state-dir` / `FIRMA_STATE_DIR` / XDG, not via this file.
    #[arg(long, env = "FIRMA_SIDECAR_CONFIG_FILE")]
    pub config: Option<PathBuf>,
    /// Override the runtime state directory used to locate the running daemon.
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    /// Seconds to wait for a graceful shutdown before sending SIGKILL.
    #[arg(long, default_value_t = 2)]
    pub timeout: u64,
}

#[derive(Debug, clap::Args)]
pub struct StatusArgs {
    /// Restrict the probe to the Sidecar with this sandbox id (set by
    /// `firma run` for per-run Sidecars).
    #[clap(long)]
    pub sandbox_id: Option<firma_runtime_state::SandboxId>,
    /// Emit machine-readable JSON (one array, one object per Sidecar) instead
    /// of the human-readable table.
    #[clap(long)]
    pub json: bool,
    /// Probe the long-lived daemon Sidecar instead of per-run markers.
    #[clap(long)]
    pub daemon: bool,
}

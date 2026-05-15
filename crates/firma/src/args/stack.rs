//! `firma stack {start|stop|status}` arg structs.

use std::path::PathBuf;

use clap::{Args, Subcommand};

/// Top-level `firma stack` arg container; dispatches to one of the three
/// subcommands.
#[derive(Debug, Args)]
pub struct StackArgs {
    /// Selected `firma stack` subcommand.
    #[command(subcommand)]
    pub command: StackCommand,
}

/// `firma stack` subcommands.
#[derive(Debug, Subcommand)]
pub enum StackCommand {
    /// Scaffold a fresh state directory: keys, config files, empty
    /// policy/issuance dirs, revocation file. Run once before `start`.
    Init(InitArgs),
    /// Start the stack.
    Start(StartArgs),
    /// Stop the stack.
    Stop(StopArgs),
    /// Print stack status.
    Status(StatusArgs),
}

/// Parsed `firma stack init` arguments.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Config directory (TOML config, keys, policy dirs). When unset,
    /// resolves to the platform config dir (`~/.config/firma` etc.).
    #[arg(long)]
    pub config_dir: Option<PathBuf>,
    /// Runtime state directory (revocations, generated-CA, pids/logs).
    /// When unset, resolves via `FIRMA_STATE_DIR` / `$XDG_RUNTIME_DIR`.
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    /// Overwrite existing files instead of preserving them.
    #[arg(long)]
    pub force: bool,
    /// Authority gRPC listen address.
    #[arg(long, default_value = "127.0.0.1:50051")]
    pub authority_listen: String,
    /// Sidecar HTTP proxy listen address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub sidecar_listen: String,
}

/// Parsed `firma stack start` arguments.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Stack config file.
    #[arg(long, env = "FIRMA_STACK_CONFIG")]
    pub config: Option<PathBuf>,
    /// Detach after readiness succeeds.
    #[arg(long)]
    pub detach: bool,
    /// State dir.
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
}

/// Parsed `firma stack stop` arguments.
#[derive(Debug, Args)]
pub struct StopArgs {
    /// Accepted for compatibility; `state_dir` is resolved from
    /// `--state-dir` / `FIRMA_STATE_DIR` / XDG.
    #[arg(long, env = "FIRMA_STACK_CONFIG")]
    pub config: Option<PathBuf>,
    /// State dir override.
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    /// Soft-shutdown grace before hard-kill, in seconds.
    #[arg(long, default_value_t = 2)]
    pub timeout: u64,
}

/// Parsed `firma stack status` arguments.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Accepted for compatibility; `state_dir` is resolved from
    /// `--state-dir` / `FIRMA_STATE_DIR` / XDG.
    #[arg(long, env = "FIRMA_STACK_CONFIG")]
    pub config: Option<PathBuf>,
    /// State dir override.
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

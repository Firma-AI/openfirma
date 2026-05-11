//! `firma monitor` arg struct.

use std::path::PathBuf;

use clap::{Args as ClapArgs, ValueEnum};

/// Parsed `firma monitor` command-line arguments.
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Stack config file. Used to read `state_dir` when `--state-dir` is
    /// not set.
    #[arg(long, env = "FIRMA_STACK_CONFIG")]
    pub config: Option<PathBuf>,
    /// State dir override.
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,

    /// Read once and exit instead of following file tails.
    #[arg(long = "no-follow", default_value_t = true, action = clap::ArgAction::SetFalse)]
    pub follow: bool,

    /// Source to monitor.
    #[arg(long, value_enum, default_value_t = Source::All)]
    pub source: Source,

    /// Audit decision filter.
    #[arg(long, value_enum)]
    pub decision: Option<Decision>,

    /// Audit action class filter.
    #[arg(long)]
    pub action_class: Option<String>,

    /// Backfill since a duration or RFC3339 timestamp.
    #[arg(long)]
    pub since: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Pretty)]
    pub format: Format,
}

/// Log source selector for `firma monitor`.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Source {
    /// Audit log only (`<state_dir>/audit.jsonl`).
    Audit,
    /// Authority component stdout/stderr (`<state_dir>/authority.log`).
    Authority,
    /// Sidecar component stdout/stderr (`<state_dir>/sidecar.log`).
    Sidecar,
    /// Interleave all three sources with a `[source]` prefix.
    All,
}

/// Audit-record decision filter for `firma monitor --decision`.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Decision {
    /// Match records where the sidecar allowed the request.
    Allow,
    /// Match records where the sidecar denied the request.
    Deny,
    /// Match records that bypassed enforcement.
    Passthrough,
}

/// Output format for `firma monitor`.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Format {
    /// Human-readable single-line rendering with optional color when stdout
    /// is a TTY.
    Pretty,
    /// One JSON object per line. Stable schema for downstream tooling.
    Json,
}

//! `firma monitor` arg struct.

use std::path::PathBuf;

use clap::{Args as ClapArgs, ValueEnum};

/// Parsed `firma monitor` command-line arguments.
// X-compliance: struct_excessive_bools is acceptable for CLI args structs where
// each bool maps 1-to-1 to a distinct command-line flag.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Accepted for compatibility; `state_dir` is resolved from
    /// `--state-dir` / `FIRMA_STATE_DIR` / XDG.
    #[arg(long, env = "FIRMA_STACK_CONFIG")]
    pub config: Option<PathBuf>,
    /// Override the runtime state directory containing the audit log and
    /// component log files.
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,

    /// Follow the log as new records are written, regardless of whether stdout
    /// is a TTY. Mutually exclusive with `--no-follow`.
    #[arg(long, conflicts_with = "no_follow")]
    pub tail: bool,
    /// Read once and exit instead of following the log. Overrides the default
    /// TTY-driven auto-tail.
    #[arg(long = "no-follow")]
    pub no_follow: bool,

    /// Which log to read: the audit log (default), one component's stdout/stderr,
    /// or all three interleaved with a `[source]` prefix.
    #[arg(long, value_enum, default_value_t = Source::Audit)]
    pub source: Source,

    /// Show only audit records with this decision (`allow`, `deny`, `passthrough`).
    #[arg(long, value_enum)]
    pub decision: Option<Decision>,
    /// Shortcut for `--decision deny`. Mutually exclusive with `--decision`.
    #[arg(long = "only-deny", conflicts_with = "decision")]
    pub only_deny: bool,

    /// Show only audit records matching this action class (e.g. `repo.read`).
    #[arg(long)]
    pub action_class: Option<String>,

    /// Show only audit records whose `agent_id` exactly matches this value.
    #[arg(long)]
    pub agent: Option<String>,

    /// Show only audit records whose `sandbox_id` exactly matches this
    /// value. The `sandbox_id` identifies a single `firma run`
    /// invocation and matches the marker directory name under
    /// `$XDG_RUNTIME_DIR/firma/run/<sandbox_id>/`.
    #[arg(long = "sandbox-id")]
    pub sandbox_id: Option<String>,

    /// Backfill records since this point: a duration (`15m`, `2h`) or an
    /// RFC3339 timestamp.
    #[arg(long)]
    pub since: Option<String>,

    /// Output rendering. `pretty` is colorised single-line; `json` is one
    /// stable-schema object per line for downstream tooling.
    #[arg(long, value_enum, default_value_t = Format::Pretty)]
    pub format: Format,
    /// Shortcut for `--format json`. Mutually exclusive with `--format`.
    #[arg(long, conflicts_with = "format")]
    pub json: bool,
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use clap::Parser;

    /// Wrap `Args` so tests can drive `clap::Parser::try_parse_from`.
    #[derive(Debug, clap::Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: Args,
    }

    fn try_parse(argv: &[&str]) -> Result<Args, clap::Error> {
        Wrapper::try_parse_from(argv).map(|w| w.args)
    }

    #[test]
    fn default_source_is_audit() {
        let args = try_parse(&["firma-monitor"]).expect("parse default");
        assert!(matches!(args.source, Source::Audit));
    }

    #[test]
    fn only_deny_conflicts_with_decision() {
        let err = try_parse(&["firma-monitor", "--only-deny", "--decision", "allow"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn json_conflicts_with_format() {
        let err = try_parse(&["firma-monitor", "--json", "--format", "pretty"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn tail_conflicts_with_no_follow() {
        let err = try_parse(&["firma-monitor", "--tail", "--no-follow"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn agent_filter_parses() {
        let args = try_parse(&["firma-monitor", "--agent", "demo-1"]).expect("parse agent");
        assert_eq!(args.agent.as_deref(), Some("demo-1"));
    }

    #[test]
    fn sandbox_id_filter_parses() {
        let args =
            try_parse(&["firma-monitor", "--sandbox-id", "sbx_1"]).expect("parse sandbox-id");
        assert_eq!(args.sandbox_id.as_deref(), Some("sbx_1"));
    }
}

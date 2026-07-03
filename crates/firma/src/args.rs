//! Top-level CLI for the unified `firma` binary.

pub mod authority;
pub mod config;
pub mod doctor;
pub mod monitor;
pub mod policy;
pub mod run;
pub mod sidecar;
pub mod supervise;
pub mod token;

use std::path::PathBuf;

use clap::{Command as ClapCommand, CommandFactory, FromArgMatches, Parser, Subcommand};

const HELP_WIDTH: usize = 100;
const HELP_TEMPLATE: &str = "\
{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}";

/// Parse CLI arguments after applying Firma shared help-output policy.
///
/// clap's derive parser does not give us a hook to adjust every generated
/// subcommand before parsing. Build the command tree first, apply the help
/// template recursively, then convert the resulting matches back into `Cli`.
pub fn parse() -> Cli {
    let mut command = Cli::command();
    configure_help(&mut command);
    let matches = command.get_matches();
    Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit())
}

/// Apply one help layout to the whole clap command tree.
///
/// the explicit width is the fallback used when clap cannot infer a terminal
/// size. `wrap_help` still uses the real terminal width when available; this
/// keeps non-TTY output and narrow terminals from falling back to clap's
/// defaults. the recursion is what keeps firma, nested commands and hidden
/// internal commands on the same template policy.
fn configure_help(command: &mut ClapCommand) {
    *command = command
        .clone()
        .max_term_width(HELP_WIDTH)
        .subcommand_help_heading("Commands")
        .next_help_heading("Options")
        .help_template(HELP_TEMPLATE);

    for subcommand in command.get_subcommands_mut() {
        configure_help(subcommand);
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "firma",
    version,
    about = "Firma — L7 policy enforcement and capability-token governance for AI agents.",
    long_about = "Firma enforces what an AI agent can do at the network layer. Every \
                  outbound call from a wrapped agent passes through the Sidecar, which \
                  authorizes it against Cedar policies and short-lived capability tokens \
                  issued by the Authority.\n\n\
                  Typical workflow:\n  \
                  firma config        — scaffold a new project\n  \
                  firma sidecar start — bring up the enforcement stack\n  \
                  firma run …         — launch your agent under enforcement\n  \
                  firma monitor       — watch audit decisions\n  \
                  firma doctor        — diagnose setup issues"
)]
pub struct Cli {
    /// Write logs to this file instead of stderr.
    #[arg(long, global = true, env = "FIRMA_LOG_FILE")]
    pub log_file: Option<PathBuf>,
    /// `tracing` `EnvFilter` directive controlling log verbosity (e.g. `info,firma=debug`).
    /// Falls back to `RUST_LOG`, then `info`.
    #[arg(long, global = true, env = "FIRMA_LOG_FILTER")]
    pub log_filter: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the Authority: issues tokens, streams policy bundles, serves revocations.
    Authority(authority::Args),
    /// Scaffold a new agent config directory interactively.
    Config(config::InitArgs),
    /// Browse the template catalogue and validate Cedar policy bundles.
    Policy(policy::PolicyArgs),
    /// Internal sandbox-local DNS stub.
    #[command(name = "__dns-stub", hide = true)]
    DnsStub(run::DnsStubArgs),
    /// Internal in-sandbox seccomp loopback-egress guard installer + agent runner.
    #[cfg(target_os = "linux")]
    #[command(name = "__egress-guarded-run", hide = true)]
    EgressGuardedRun(run::EgressGuardedRunArgs),
    /// Diagnose a Firma install. Run this first when `firma run` misbehaves.
    Doctor(doctor::Args),
    /// Tail audit decisions and component logs. Use `--source` to switch log streams.
    Monitor(monitor::Args),
    /// Internal proxy bridge for sandbox.
    #[command(name = "__proxy-bridge", hide = true)]
    ProxyBridge(run::ProxyBridgeArgs),
    /// Launch an agent in a sandbox under enforcement. Main entry point for agents.
    Run(run::RunArgs),
    /// Run or manage the enforcement Sidecar. Bare form = foreground server;
    /// `start`/`stop`/`status` manage a long-lived daemon.
    Sidecar(sidecar::Args),
    /// Internal detached supervisor process.
    #[command(name = "__supervise", hide = true)]
    Supervise(supervise::Args),
    /// Approve or revoke HITL governance tokens for high-risk actions.
    Token(token::TokenArgs),
}

pub fn resolve_log_filter(firma_log_filter: Option<&str>, rust_log: Option<&str>) -> String {
    firma_log_filter.or(rust_log).unwrap_or("info").to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn log_filter_falls_back_to_rust_log() {
        assert_eq!(
            super::resolve_log_filter(None, Some("debug")),
            "debug",
            "RUST_LOG should control logging when FIRMA_LOG_FILTER/--log-filter is absent"
        );
    }

    #[test]
    fn explicit_firma_log_filter_wins_over_rust_log() {
        assert_eq!(
            super::resolve_log_filter(Some("warn"), Some("debug")),
            "warn",
            "FIRMA_LOG_FILTER/--log-filter should keep precedence over RUST_LOG"
        );
    }

    #[test]
    fn default_log_filter_is_info() {
        assert_eq!(super::resolve_log_filter(None, None), "info");
    }
}

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

use clap::{Parser, Subcommand};

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
    #[arg(long, global = true, env = "FIRMA_LOG_FILTER", default_value = "info")]
    pub log_filter: String,

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

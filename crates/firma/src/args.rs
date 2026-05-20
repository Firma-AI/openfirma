//! Top-level CLI for the unified `firma` binary.

pub mod authority;
pub mod doctor;
pub mod init;
pub mod monitor;
pub mod policy;
pub mod run;
pub mod sidecar;
pub mod stack;
pub mod supervise;
pub mod token;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "firma", version, about = "Firma OSS unified CLI")]
pub struct Cli {
    /// Optional log file (else stderr).
    #[arg(long, global = true, env = "FIRMA_LOG_FILE")]
    pub log_file: Option<PathBuf>,
    /// `EnvFilter` directive (e.g. `info,firma=debug`).
    #[arg(long, global = true, env = "FIRMA_LOG_FILTER", default_value = "info")]
    pub log_filter: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the authority (mini reference impl).
    Authority(authority::Args),
    /// Scaffold a new agent config directory interactively.
    Init(init::InitArgs),
    /// Browse the built-in policy template catalogue.
    Policy(policy::PolicyArgs),
    /// Internal sandbox-local DNS stub.
    #[command(name = "__dns-stub", hide = true)]
    DnsStub(run::DnsStubArgs),
    /// Print a structured diagnostic report of installed components,
    /// reachable endpoints, and resolved configuration.
    Doctor(doctor::Args),
    /// Tail audit and component logs.
    Monitor(monitor::Args),
    /// Internal proxy bridge for sandbox.
    #[command(name = "__proxy-bridge", hide = true)]
    ProxyBridge(run::ProxyBridgeArgs),
    /// Wrap an agent process via firma-run.
    Run(run::RunArgs),
    /// Run the enforcement sidecar.
    Sidecar(sidecar::Args),
    /// Supervise authority + sidecar as one unit.
    Stack(stack::StackArgs),
    /// Internal detached stack supervisor.
    #[command(name = "__supervise", hide = true)]
    Supervise(supervise::Args),
    /// Manage local-exec governance tokens (approve / revoke).
    Token(token::TokenArgs),
}

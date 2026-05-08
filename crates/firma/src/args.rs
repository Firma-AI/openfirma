//! Top-level CLI for the unified `firma` binary.

pub mod authority;
pub mod run;
pub mod sidecar;

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
    /// Run the enforcement sidecar.
    Sidecar(sidecar::Args),
    /// Run the authority (mini reference impl).
    Authority(authority::Args),
    /// Wrap an agent process via firma-run.
    Run(run::RunArgs),
    /// Internal sandbox-local DNS stub.
    #[command(name = "__dns-stub", hide = true)]
    DnsStub(run::DnsStubArgs),
    /// Internal proxy bridge for sandbox.
    #[command(name = "__proxy-bridge", hide = true)]
    ProxyBridge(run::ProxyBridgeArgs),
}

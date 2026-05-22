mod args;
mod doctor;
mod log;
mod monitor;
mod policy;
mod services;
mod signal;

use std::process::ExitCode;

use clap::Parser as _;

use crate::args::{Cli, Command};

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(e) = log::init(&cli.log_filter, cli.log_file.as_deref()) {
        eprintln!("error: {e}");
        return ExitCode::from(1);
    }

    let result = match cli.command {
        Command::Authority(a) => block_on_async(services::authority::run(a)),
        Command::DnsStub(a) => services::dns_stub::run(a),
        Command::Doctor(a) => Ok(services::doctor::run(a)),
        Command::Init(a) => Ok(services::init::run(a)),
        Command::Monitor(a) => Ok(services::monitor::run(a)),
        Command::Policy(a) => services::policy::run(a),
        Command::ProxyBridge(a) => services::proxy_bridge::run(a),
        Command::Run(a) => services::run::run(a),
        Command::Sidecar(a) => block_on_async(services::sidecar::run(a)),
        Command::Supervise(a) => Ok(services::supervise::run(a)),
        Command::Token(a) => services::token::run(a),
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn block_on_async<F>(fut: F) -> anyhow::Result<ExitCode>
where
    F: std::future::Future<Output = anyhow::Result<ExitCode>>,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build tokio runtime: {e}"))?;
    runtime.block_on(fut)
}

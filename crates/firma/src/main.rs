mod args;
mod doctor;
mod fs;
mod log;
mod monitor;
mod output;
mod policy;
mod services;
mod signal;

use std::process::ExitCode;

use crate::args::Command;

fn main() -> ExitCode {
    let cli = args::parse();
    let rust_log = std::env::var("RUST_LOG").ok();
    let log_filter = args::resolve_log_filter(cli.log_filter.as_deref(), rust_log.as_deref());

    if let Err(e) = log::init(&log_filter, cli.log_file.as_deref()) {
        output::err(format!("{e}"));
        return ExitCode::from(1);
    }

    let result = match cli.command {
        Command::Authority(a) => block_on_async(services::authority::run(a)),
        Command::DnsStub(a) => services::dns_stub::run(a),
        #[cfg(target_os = "linux")]
        Command::EgressGuardedRun(a) => services::egress_guarded_run::run(a),
        Command::Doctor(a) => Ok(services::doctor::run(a)),
        Command::Config(a) => services::config::run(&a),
        Command::Policy(a) => services::policy::run(a),
        Command::Monitor(a) => Ok(services::monitor::run(&a)),
        Command::ProxyBridge(a) => services::proxy_bridge::run(a),
        Command::Run(a) => services::run::run(a),
        Command::Sidecar(a) => block_on_async(services::sidecar::run(a)),
        Command::Supervise(a) => Ok(services::supervise::run(a)),
        Command::Token(a) => services::token::run(a),
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            output::err(format!("{e:#}"));
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

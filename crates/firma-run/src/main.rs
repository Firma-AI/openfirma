use std::process::ExitCode;

use clap::Parser;
use firma_run::args::{Cli, Command};
use firma_run::proxy_bridge::execute_proxy_bridge;
use firma_run::runtime::execute_run;

fn init_tracing() {
    let filter = std::env::var("FIRMA_RUN_LOG_FILTER").unwrap_or_else(|_| "info".to_string());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .try_init();
}

fn main() -> ExitCode {
    init_tracing();

    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => match execute_run(&args) {
            Ok(code) => {
                if code == 0 {
                    ExitCode::SUCCESS
                } else {
                    let exit = u8::try_from(code).unwrap_or(1);
                    ExitCode::from(exit)
                }
            }
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::from(1)
            }
        },
        Command::ProxyBridge(args) => match execute_proxy_bridge(&args) {
            Ok(code) => {
                if code == 0 {
                    ExitCode::SUCCESS
                } else {
                    let exit = u8::try_from(code).unwrap_or(1);
                    ExitCode::from(exit)
                }
            }
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::from(1)
            }
        },
    }
}

//! `firma-secret-shim` — the in-sandbox secret mediation shim.
//!
//! Bind-mounted over a configured executable inside the sandbox, this shim:
//!
//! 1. Reads `FIRMA_BROKER_ADDR` to find the out-of-sandbox broker.
//! 2. Sends the executable basename and original argument vector to the broker.
//! 3. Replays the broker's stdout and stderr chunks.
//! 4. Exits with the broker-executed process's status.
//!
//! The real tool is executed by the broker outside the sandbox; the shim holds
//! no credentials and no plaintext secrets. Fail-closed: on any error the shim
//! exits non-zero without running the tool.

use std::io::Write as _;
use std::path::Path;
use std::str::FromStr as _;

use firma_config_schema::broker::BrokerConfig;
use firma_secret_provider::{
    broker::{BrokerExitStatus, BrokerOutputChunk, client::BrokerClient},
    endpoint::client::ClientEndpoint,
};

const FIRMA_BROKER_ADDR: &str = "FIRMA_BROKER_ADDR";

fn main() -> std::process::ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("firma-secret-shim: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<std::process::ExitCode, Box<dyn std::error::Error>> {
    let addr = std::env::var(FIRMA_BROKER_ADDR).map_err(|_| {
        std::io::Error::other(format!(
            "missing required environment variable {FIRMA_BROKER_ADDR}"
        ))
    })?;

    let mut raw_args = std::env::args();
    let argv0 = raw_args.next().unwrap_or_default();
    let bin = Path::new(&argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(argv0.as_str())
        .to_string();
    let args = raw_args.collect::<Vec<_>>();
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    let endpoint = ClientEndpoint::from_str(&addr)?;
    let client = BrokerClient::new(endpoint, BrokerConfig::default());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let output = runtime.block_on(client.run(&bin, &arg_refs))?;

    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    for chunk in output.output {
        match chunk {
            BrokerOutputChunk::Stdout(bytes) => stdout.write_all(&bytes)?,
            BrokerOutputChunk::Stderr(bytes) => stderr.write_all(&bytes)?,
        }
    }
    stdout.flush()?;
    stderr.flush()?;

    Ok(match output.status {
        BrokerExitStatus::Exited { code: 0 } => std::process::ExitCode::SUCCESS,
        BrokerExitStatus::Exited { code } => std::process::ExitCode::from(
            u8::try_from(code)
                .ok()
                .filter(|code| *code != 0)
                .unwrap_or(1),
        ),
        BrokerExitStatus::Signaled { signal } => {
            std::process::ExitCode::from(u8::try_from(128_i32.saturating_add(signal)).unwrap_or(1))
        }
        BrokerExitStatus::Unknown => std::process::ExitCode::FAILURE,
    })
}

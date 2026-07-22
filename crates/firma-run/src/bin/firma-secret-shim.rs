//! `firma-secret-shim` — the in-sandbox secret mediation shim.
//!
//! Bind-mounted over a configured executable inside the sandbox, this shim:
//!
//! 1. Reads `FIRMA_BROKER_ADDR` to find the out-of-sandbox broker.
//! 2. Sends `{"bin":"<basename>","args":"<space-joined argv[1..]>"}` to the broker.
//! 3. Writes the broker's decoded stdout to its own stdout.
//! 4. Exits (0 on success, 1 on any error).
//!
//! The real tool is executed by the broker outside the sandbox; the shim holds
//! no credentials and no plaintext secrets. Fail-closed: on any error the shim
//! exits non-zero without running the tool.

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    match imp::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("firma-secret-shim: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("firma-secret-shim: secret mediation requires a Unix platform");
    std::process::ExitCode::FAILURE
}

#[cfg(unix)]
mod imp {
    use std::io::{self, Write};
    use std::path::Path;

    use firma_run::secret::broker::BrokerRequest;
    use firma_run::secret::shim::{FIRMA_BROKER_ADDR, call_broker};

    pub fn run() -> io::Result<()> {
        let addr = std::env::var(FIRMA_BROKER_ADDR).map_err(|_| {
            io::Error::other(format!(
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
        let args = raw_args.collect::<Vec<_>>().join(" ");

        let request = BrokerRequest { bin, args };
        let response = call_broker(&addr, &request)?;
        let stdout = response.into_stdout().map_err(io::Error::other)?;

        io::stdout().write_all(&stdout)?;
        io::stdout().flush()
    }
}

//! Runner for `firma token approve` / `firma token revoke`.

#[cfg(target_family = "unix")]
use std::io::{self, BufRead as _, Write as _};
#[cfg(target_family = "unix")]
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
#[cfg(target_family = "unix")]
use std::time::Duration;

use crate::args::token::{TokenActionArgs, TokenArgs, TokenCommand};

/// Run the token subcommand.
///
/// # Errors
///
/// Returns an error if the socket connection or I/O fails.
pub fn run(args: TokenArgs) -> anyhow::Result<ExitCode> {
    match args.command {
        TokenCommand::Approve(a) => send_management("local.exec.approve", &a),
        TokenCommand::Revoke(a) => send_management("local.exec.revoke", &a),
    }
}

fn send_management(action: &str, args: &TokenActionArgs) -> anyhow::Result<ExitCode> {
    #[cfg(not(target_family = "unix"))]
    {
        let _ = action;
        let _ = args;
        Err(anyhow::anyhow!(
            "`firma token` requires Unix domain sockets and is unsupported on this platform"
        ))
    }

    #[cfg(target_family = "unix")]
    {
        let socket_path = strip_unix_prefix(&args.socket);
        let management_token = resolve_management_token(args)?;

        let mut stream = UnixStream::connect(socket_path).map_err(|e| {
            anyhow::anyhow!(
                "could not connect to local-exec socket '{socket_path}': {e}\n\
             Is the sidecar running and local_exec enabled?"
            )
        })?;

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| anyhow::anyhow!("set_read_timeout: {e}"))?;

        let request = serde_json::json!({
            "action": action,
            "token_id": args.token_id,
            "management_token": management_token,
        });
        let mut payload =
            serde_json::to_vec(&request).map_err(|e| anyhow::anyhow!("serialize request: {e}"))?;
        payload.push(b'\n');
        stream
            .write_all(&payload)
            .map_err(|e| anyhow::anyhow!("write request: {e}"))?;

        let reader = io::BufReader::new(&stream);
        let line = reader
            .lines()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no response from sidecar"))?
            .map_err(|e| anyhow::anyhow!("read response: {e}"))?;

        let resp: serde_json::Value =
            serde_json::from_str(&line).map_err(|e| anyhow::anyhow!("parse response: {e}"))?;

        let outcome = resp
            .get("outcome")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let reason = resp.get("reason").and_then(|v| v.as_str());

        match outcome {
            "ok" => {
                if let Some(r) = reason {
                    crate::output::ok(format!("{action} {}: {r}", args.token_id));
                } else {
                    crate::output::ok(format!("{action} {}", args.token_id));
                }
                Ok(ExitCode::SUCCESS)
            }
            other => {
                if let Some(r) = reason {
                    crate::output::err(format!("{other} — {r}"));
                } else {
                    crate::output::err(other);
                }
                Ok(ExitCode::from(1))
            }
        }
    }
}

/// Strip a leading `unix://` prefix so plain paths also work.
#[cfg(target_family = "unix")]
fn strip_unix_prefix(s: &str) -> &str {
    s.strip_prefix("unix://").unwrap_or(s)
}

/// Default environment variable holding the operator management token.
#[cfg(target_family = "unix")]
const MANAGEMENT_TOKEN_ENV: &str = "FIRMA_LOCAL_EXEC_MANAGEMENT_TOKEN";

/// Resolve the operator management token to attach to the management command.
///
/// Precedence: `--management-token-path` (file) over the
/// [`MANAGEMENT_TOKEN_ENV`] environment variable. The sidecar must be
/// configured with the matching source so the token compares equal.
#[cfg(target_family = "unix")]
fn resolve_management_token(args: &TokenActionArgs) -> anyhow::Result<Option<String>> {
    if let Some(path) = args.management_token_path.as_deref() {
        let value = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read management token file '{path}': {e}"))?;
        let token = trim_trailing_newlines(value);
        if token.is_empty() {
            return Err(anyhow::anyhow!("management token file '{path}' is empty"));
        }
        return Ok(Some(token));
    }

    match std::env::var(MANAGEMENT_TOKEN_ENV) {
        Ok(value) => {
            let token = trim_trailing_newlines(value);
            if token.is_empty() {
                return Err(anyhow::anyhow!("{MANAGEMENT_TOKEN_ENV} is set but empty"));
            }
            Ok(Some(token))
        }
        Err(_) => Err(anyhow::anyhow!(
            "management token is required: pass --management-token-path <file> or set the \
             {MANAGEMENT_TOKEN_ENV} environment variable (must match the sidecar's \
             local_exec.management_token_env / management_token_path)"
        )),
    }
}

#[cfg(target_family = "unix")]
fn trim_trailing_newlines(mut value: String) -> String {
    while value.ends_with('\n') || value.ends_with('\r') {
        value.pop();
    }
    value
}

//! Runner for `firma token approve` / `firma token revoke`.

use std::io::{self, BufRead as _, Write as _};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
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
    let socket_path = strip_unix_prefix(&args.socket);

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
                println!("{action} {}: ok — {r}", args.token_id);
            } else {
                println!("{action} {}: ok", args.token_id);
            }
            Ok(ExitCode::SUCCESS)
        }
        other => {
            if let Some(r) = reason {
                eprintln!("error: {other} — {r}");
            } else {
                eprintln!("error: {other}");
            }
            Ok(ExitCode::from(1))
        }
    }
}

/// Strip a leading `unix://` prefix so plain paths also work.
fn strip_unix_prefix(s: &str) -> &str {
    s.strip_prefix("unix://").unwrap_or(s)
}

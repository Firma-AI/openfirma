use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(target_family = "unix")]
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{CommandMediatorConfig, CommandMediatorEndpoint};
use crate::error::RunError;
use crate::identity::RunIdentity;

#[derive(Debug, Serialize)]
struct MediatorRequest<'a> {
    action: &'static str,
    executable: &'a str,
    args: &'a [String],
    sandbox_id: &'a str,
    session_id: &'a str,
    profile: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MediatorResponse {
    decision: String,
    reason: Option<String>,
}

/// Enforces a mandatory pre-execution mediator decision in fail-closed mode.
///
/// # Errors
///
/// Returns [`RunError::Governance`] when the mediator denies, is unavailable,
/// times out, or returns invalid/unsupported data.
pub fn enforce_local_command_governance(
    mediator: &CommandMediatorConfig,
    identity: &RunIdentity,
    executable: &str,
    args: &[String],
) -> Result<(), RunError> {
    let payload = MediatorRequest {
        action: "local.exec",
        executable,
        args,
        sandbox_id: &identity.sandbox_id,
        session_id: &identity.session_id,
        profile: &identity.profile,
    };

    let request_json = serde_json::to_string(&payload).map_err(|error| {
        RunError::Internal(format!("failed to serialize mediator request: {error}"))
    })?;

    let response_json = match &mediator.endpoint {
        CommandMediatorEndpoint::Tcp { addr } => {
            request_over_tcp(*addr, &request_json, mediator.timeout_ms)
        }
        CommandMediatorEndpoint::Unix { path } => {
            request_over_unix(path, &request_json, mediator.timeout_ms)
        }
    }?;

    let response: MediatorResponse = serde_json::from_str(&response_json).map_err(|error| {
        RunError::Governance(format!(
            "mediator returned invalid response payload: {error}"
        ))
    })?;

    apply_mediator_decision(&response, identity, executable)
}

fn apply_mediator_decision(
    response: &MediatorResponse,
    identity: &RunIdentity,
    executable: &str,
) -> Result<(), RunError> {
    match response.decision.as_str() {
        "allow" => {
            tracing::info!(
                decision = "allow",
                executable = executable,
                sandbox_id = %identity.sandbox_id,
                session_id = %identity.session_id,
                "local command mediator decision"
            );
            Ok(())
        }
        "deny" | "pending_hitl" => {
            let reason = response
                .reason
                .clone()
                .unwrap_or_else(|| "policy denied execution".to_string());
            tracing::warn!(
                decision = %response.decision,
                reason = %reason,
                executable = executable,
                sandbox_id = %identity.sandbox_id,
                session_id = %identity.session_id,
                "local command mediator blocked execution"
            );
            Err(RunError::Governance(format!(
                "decision={} reason={reason}",
                response.decision
            )))
        }
        other => Err(RunError::Governance(format!(
            "mediator returned unsupported decision '{other}'"
        ))),
    }
}

fn request_over_tcp(
    addr: SocketAddr,
    request_json: &str,
    timeout_ms: u64,
) -> Result<String, RunError> {
    let timeout = Duration::from_millis(timeout_ms);
    let stream = TcpStream::connect_timeout(&addr, timeout).map_err(|error| {
        RunError::Governance(format!(
            "mediator unavailable (tcp://{addr}) in fail-closed mode: {error}"
        ))
    })?;
    stream.set_read_timeout(Some(timeout)).map_err(|error| {
        RunError::Internal(format!("failed to set mediator read timeout: {error}"))
    })?;
    stream.set_write_timeout(Some(timeout)).map_err(|error| {
        RunError::Internal(format!("failed to set mediator write timeout: {error}"))
    })?;
    send_and_receive(stream, request_json)
}

fn request_over_unix(
    path: &std::path::Path,
    request_json: &str,
    timeout_ms: u64,
) -> Result<String, RunError> {
    #[cfg(not(target_family = "unix"))]
    {
        let _ = (path, request_json, timeout_ms);
        Err(RunError::Governance(
            "unix mediator endpoint is unsupported on non-unix host".to_string(),
        ))
    }
    #[cfg(target_family = "unix")]
    {
        let timeout = Duration::from_millis(timeout_ms);
        let stream = UnixStream::connect(path).map_err(|error| {
            RunError::Governance(format!(
                "mediator unavailable (unix://{}) in fail-closed mode: {error}",
                path.display()
            ))
        })?;
        stream.set_read_timeout(Some(timeout)).map_err(|error| {
            RunError::Internal(format!("failed to set mediator read timeout: {error}"))
        })?;
        stream.set_write_timeout(Some(timeout)).map_err(|error| {
            RunError::Internal(format!("failed to set mediator write timeout: {error}"))
        })?;
        send_and_receive(stream, request_json)
    }
}

fn send_and_receive<T: Write + std::io::Read>(
    mut stream: T,
    request_json: &str,
) -> Result<String, RunError> {
    stream
        .write_all(request_json.as_bytes())
        .and_then(|()| stream.write_all(b"\n"))
        .and_then(|()| stream.flush())
        .map_err(|error| {
            RunError::Governance(format!(
                "mediator request failed in fail-closed mode: {error}"
            ))
        })?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|error| {
        RunError::Governance(format!(
            "mediator response failed in fail-closed mode: {error}"
        ))
    })?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(RunError::Governance(
            "mediator returned empty response in fail-closed mode".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mediator_allow_decision_is_accepted() {
        let identity = RunIdentity {
            sandbox_id: "sbx".to_string(),
            session_id: "sess".to_string(),
            profile: "generic".to_string(),
        };
        let out = apply_mediator_decision(
            &MediatorResponse {
                decision: "allow".to_string(),
                reason: Some("ok".to_string()),
            },
            &identity,
            "/bin/echo",
        );
        assert!(out.is_ok(), "unexpected result: {out:?}");
    }

    #[test]
    fn mediator_deny_decision_blocks_execution() {
        let identity = RunIdentity {
            sandbox_id: "sbx".to_string(),
            session_id: "sess".to_string(),
            profile: "generic".to_string(),
        };
        let err = apply_mediator_decision(
            &MediatorResponse {
                decision: "deny".to_string(),
                reason: Some("blocked".to_string()),
            },
            &identity,
            "/bin/echo",
        )
        .expect_err("expected deny");
        assert!(
            err.to_string().contains("governance denied execution"),
            "unexpected error: {err}"
        );
    }
}

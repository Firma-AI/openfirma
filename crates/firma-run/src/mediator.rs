use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(target_family = "unix")]
use std::os::unix::net::UnixStream;
use std::time::Duration;

use sha2::Digest as _;

#[cfg(target_os = "linux")]
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde::{Deserialize, Serialize};

use crate::config::{CommandMediatorConfig, CommandMediatorEndpoint, CommandMediatorHitlMode};
use crate::error::RunError;
use crate::identity::{RunIdentity, SandboxId};

#[derive(Debug, Serialize)]
struct MediatorRequest<'a> {
    action: &'static str,
    executable: &'a str,
    args: &'a [String],
    sandbox_id: &'a SandboxId,
    session_id: &'a str,
    /// Agent identity forwarded from `FIRMA_AGENT_ID` env var when present.
    /// Used by the sidecar to bind approval tokens to the issuing agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
    profile: &'a str,
    hitl_mode: &'static str,
    /// SHA-256 fingerprint of (`canonical_executable` ‖ argv ‖ `session_id` ‖ `sandbox_id` ‖ `agent_id`).
    /// The sidecar binds approval tokens to this fingerprint so a token issued for
    /// one command cannot authorize a different command in the same session.
    request_fingerprint: String,
    /// Token ID from a prior `pending_hitl` response. Absent on the first
    /// attempt; present on every retry so the sidecar can advance the token
    /// state machine (`Pending` → polled, `Approved` → `Consumed`).
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_token: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MediatorResponse {
    decision: String,
    reason: Option<String>,
    approval_token: Option<String>,
    retry_after_ms: Option<u64>,
}

/// Enforces a mandatory pre-execution Sidecar local-exec governance decision in
/// fail-closed mode.
///
/// For `hitl_mode = "async_token"` this function blocks — sleeping between
/// retries — until the sidecar returns `allow` or `deny`, or until
/// `hitl_max_wait_ms` is exceeded (fail-closed). The operator approves the
/// pending token out-of-band via `firma token approve <token-id>`.
///
/// # Errors
///
/// Returns [`RunError::Governance`] when the local-exec governance endpoint
/// denies, is unavailable, times out, or returns invalid/unsupported data.
pub fn enforce_local_command_governance(
    mediator: &CommandMediatorConfig,
    identity: &RunIdentity,
    executable: &str,
    args: &[String],
) -> Result<(), RunError> {
    let agent_id = std::env::var("FIRMA_AGENT_ID")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let fingerprint = compute_request_fingerprint(
        executable,
        args,
        &identity.session_id,
        &identity.sandbox_id,
        agent_id.as_deref(),
    );
    let deadline = std::time::Instant::now() + Duration::from_millis(mediator.hitl_max_wait_ms);

    let mut approval_token: Option<String> = None;
    loop {
        let response = call_mediator(
            mediator,
            identity,
            executable,
            args,
            agent_id.as_deref(),
            &fingerprint,
            approval_token.as_deref(),
        )?;

        match response.decision.as_str() {
            "allow" => {
                tracing::info!(
                    executable,
                    sandbox_id = %identity.sandbox_id,
                    session_id = %identity.session_id,
                    "local command governance: allowed"
                );
                return Ok(());
            }
            "deny" => {
                let reason = response
                    .reason
                    .unwrap_or_else(|| "policy denied execution".to_string());
                tracing::warn!(
                    reason = %reason,
                    executable,
                    sandbox_id = %identity.sandbox_id,
                    session_id = %identity.session_id,
                    "local command governance: denied"
                );
                return Err(RunError::Governance(format!(
                    "governance denied execution: {reason}"
                )));
            }
            "pending_hitl" => {
                approval_token = handle_pending_hitl(mediator, executable, &response, deadline)?;
            }
            other => {
                return Err(RunError::Governance(format!(
                    "local-exec governance returned unsupported decision '{other}'"
                )));
            }
        }
    }
}

/// Build and send one local-exec governance request; return the parsed response.
fn call_mediator(
    mediator: &CommandMediatorConfig,
    identity: &RunIdentity,
    executable: &str,
    args: &[String],
    agent_id: Option<&str>,
    fingerprint: &str,
    approval_token: Option<&str>,
) -> Result<MediatorResponse, RunError> {
    let hitl_mode_str = match mediator.hitl_mode {
        CommandMediatorHitlMode::SyncWait => "sync_wait",
        CommandMediatorHitlMode::AsyncToken => "async_token",
    };
    let payload = MediatorRequest {
        action: "local.exec",
        executable,
        args,
        sandbox_id: &identity.sandbox_id,
        session_id: &identity.session_id,
        agent_id: agent_id.map(ToOwned::to_owned),
        profile: &identity.execution_profile,
        hitl_mode: hitl_mode_str,
        request_fingerprint: fingerprint.to_string(),
        approval_token,
    };
    let request_json = serde_json::to_string(&payload).map_err(|e| {
        RunError::Internal(format!(
            "failed to serialize local-exec governance request: {e}"
        ))
    })?;
    let response_json = match &mediator.endpoint {
        CommandMediatorEndpoint::Tcp { addr } => {
            request_over_tcp(*addr, &request_json, mediator.timeout_ms)
        }
        CommandMediatorEndpoint::Unix { path } => {
            request_over_unix(path, &request_json, mediator.timeout_ms)
        }
    }?;
    serde_json::from_str(&response_json).map_err(|e| {
        RunError::Governance(format!(
            "local-exec governance returned invalid response payload: {e}"
        ))
    })
}

/// Handle a `pending_hitl` response. Returns the token to carry into the next
/// retry, or an error if the mode is `sync_wait`, the token is missing, or the
/// deadline is exceeded.
fn handle_pending_hitl(
    mediator: &CommandMediatorConfig,
    executable: &str,
    response: &MediatorResponse,
    deadline: std::time::Instant,
) -> Result<Option<String>, RunError> {
    if mediator.hitl_mode == CommandMediatorHitlMode::SyncWait {
        return Err(RunError::Governance(
            "governance denied execution: approval required (sync_wait mode fail-closed)"
                .to_string(),
        ));
    }
    let token = response
        .approval_token
        .clone()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            RunError::Governance(
                "governance denied execution: \
                 missing approval_token in pending_hitl response"
                    .to_string(),
            )
        })?;
    let retry_after = Duration::from_millis(response.retry_after_ms.unwrap_or(500));
    if std::time::Instant::now() + retry_after >= deadline {
        return Err(RunError::Governance(format!(
            "governance denied execution: HITL approval wait exceeded \
             hitl_max_wait_ms={} (fail-closed)",
            mediator.hitl_max_wait_ms
        )));
    }
    tracing::info!(
        approval_token = %token,
        retry_after_ms = response.retry_after_ms.unwrap_or(500),
        executable,
        "local command pending HITL approval — run: firma token approve {token}",
    );
    std::thread::sleep(retry_after);
    Ok(Some(token))
}

fn request_over_tcp(
    addr: SocketAddr,
    request_json: &str,
    timeout_ms: u64,
) -> Result<String, RunError> {
    let timeout = Duration::from_millis(timeout_ms);
    let stream = TcpStream::connect_timeout(&addr, timeout).map_err(|error| {
        RunError::Governance(format!(
            "local-exec governance endpoint unavailable (tcp://{addr}) in fail-closed mode: {error}"
        ))
    })?;
    stream.set_read_timeout(Some(timeout)).map_err(|error| {
        RunError::Internal(format!(
            "failed to set local-exec governance read timeout: {error}"
        ))
    })?;
    stream.set_write_timeout(Some(timeout)).map_err(|error| {
        RunError::Internal(format!(
            "failed to set local-exec governance write timeout: {error}"
        ))
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
            "unix local-exec governance endpoint is unsupported on non-unix host".to_string(),
        ))
    }
    #[cfg(target_family = "unix")]
    {
        let timeout = Duration::from_millis(timeout_ms);
        let stream = UnixStream::connect(path).map_err(|error| {
            RunError::Governance(format!(
                "local-exec governance endpoint unavailable (unix://{}) in fail-closed mode: {error}",
                path.display()
            ))
        })?;
        stream.set_read_timeout(Some(timeout)).map_err(|error| {
            RunError::Internal(format!(
                "failed to set local-exec governance read timeout: {error}"
            ))
        })?;
        stream.set_write_timeout(Some(timeout)).map_err(|error| {
            RunError::Internal(format!(
                "failed to set local-exec governance write timeout: {error}"
            ))
        })?;
        #[cfg(all(target_os = "linux", not(test)))]
        validate_unix_peer_credentials(&stream)?;
        #[cfg(all(target_os = "linux", test))]
        let _ = &stream;
        #[cfg(not(target_os = "linux"))]
        validate_unix_peer_credentials(&stream);
        send_and_receive(stream, request_json)
    }
}

#[cfg(target_family = "unix")]
#[cfg(target_os = "linux")]
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "linux peer-credential validation is compiled but not exercised by unit tests"
    )
)]
fn validate_unix_peer_credentials(stream: &UnixStream) -> Result<(), RunError> {
    let creds = getsockopt(stream, PeerCredentials).map_err(|error| {
        RunError::Governance(format!(
            "local-exec governance unix peer credential validation failed in fail-closed mode: {error}"
        ))
    })?;
    let peer_uid = creds.uid();
    let current_uid = nix::unistd::Uid::current().as_raw();
    if peer_uid != current_uid {
        return Err(RunError::Governance(format!(
            "local-exec governance unix peer uid mismatch in fail-closed mode: expected uid={current_uid} got uid={peer_uid}"
        )));
    }
    Ok(())
}

#[cfg(target_family = "unix")]
#[cfg(not(target_os = "linux"))]
fn validate_unix_peer_credentials(_stream: &UnixStream) {}

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
                "local-exec governance request failed in fail-closed mode: {error}"
            ))
        })?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|error| {
        RunError::Governance(format!(
            "local-exec governance response failed in fail-closed mode: {error}"
        ))
    })?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(RunError::Governance(
            "local-exec governance returned empty response in fail-closed mode".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

/// Compute a deterministic SHA-256 fingerprint over the key fields of a
/// local-exec request. The sidecar binds approval tokens to this fingerprint
/// so that a token issued for one command cannot be replayed for a different
/// command, even within the same session.
///
/// Fields included: canonical executable path, each arg (NUL-delimited),
/// `session_id`, `sandbox_id`, and `agent_id` when present.
/// `env` is intentionally excluded — it is too large and unstable for V1.
fn compute_request_fingerprint(
    executable: &str,
    args: &[String],
    session_id: &str,
    sandbox_id: &SandboxId,
    agent_id: Option<&str>,
) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(executable.as_bytes());
    hasher.update(b"\0");
    for arg in args {
        hasher.update(arg.as_bytes());
        hasher.update(b"\0");
    }
    hasher.update(session_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(sandbox_id.to_string().as_bytes());
    hasher.update(b"\0");
    if let Some(aid) = agent_id {
        hasher.update(aid.as_bytes());
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io::ErrorKind;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::config::CommandMediatorEndpoint;
    use crate::identity::RunIdentity;

    fn mediator_config(addr: SocketAddr) -> CommandMediatorConfig {
        CommandMediatorConfig {
            endpoint: CommandMediatorEndpoint::Tcp { addr },
            timeout_ms: 500,
            hitl_mode: CommandMediatorHitlMode::SyncWait,
            hitl_max_wait_ms: 5_000,
            enforce_known_executables: false,
            allowed_executables: BTreeSet::default(),
        }
    }

    fn identity() -> RunIdentity {
        RunIdentity {
            sandbox_id: crate::identity::SandboxId::generate(),
            session_id: "sess".to_string(),
            agent_id: crate::identity::test_agent_id(),
            execution_profile: "generic".to_string(),
        }
    }

    fn try_bind_tcp_local() -> Option<TcpListener> {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => Some(listener),
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping bind-dependent test: {err}");
                None
            }
            Err(err) => panic!("{err}"),
        }
    }

    /// Spawn a one-shot loopback TCP server that serves a fixed JSON response line.
    fn serve_once(response: &'static str) -> Option<SocketAddr> {
        let listener = try_bind_tcp_local()?;
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap_or_else(|e| panic!("{e}"));
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .unwrap_or_else(|e| panic!("{e}"));
            stream
                .write_all(format!("{response}\n").as_bytes())
                .unwrap_or_else(|e| panic!("{e}"));
        });
        Some(addr)
    }

    #[test]
    fn mediator_allow_decision_is_accepted() {
        let Some(addr) = serve_once(r#"{"decision":"allow"}"#) else {
            return;
        };
        let cfg = mediator_config(addr);
        let result = enforce_local_command_governance(&cfg, &identity(), "/bin/echo", &[]);
        assert!(result.is_ok(), "unexpected: {result:?}");
    }

    #[test]
    fn mediator_deny_decision_blocks_execution() {
        let Some(addr) = serve_once(r#"{"decision":"deny","reason":"blocked"}"#) else {
            return;
        };
        let cfg = mediator_config(addr);
        let err = enforce_local_command_governance(&cfg, &identity(), "/bin/echo", &[])
            .expect_err("expected deny");
        assert!(
            err.to_string().contains("governance denied execution"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn mediator_sync_wait_pending_hitl_fails_closed() {
        let Some(addr) = serve_once(
            r#"{"decision":"pending_hitl","approval_token":"tok1","retry_after_ms":50}"#,
        ) else {
            return;
        };
        let cfg = mediator_config(addr);
        let err = enforce_local_command_governance(&cfg, &identity(), "/bin/echo", &[])
            .expect_err("expected fail-closed on pending_hitl in sync_wait");
        assert!(err.to_string().contains("fail-closed"), "unexpected: {err}");
    }

    #[test]
    fn mediator_async_token_retries_until_approved() {
        // Server: first request -> pending_hitl, second -> allow.
        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let requests_srv = Arc::clone(&requests);
        let Some(listener) = try_bind_tcp_local() else {
            return;
        };
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        std::thread::spawn(move || {
            let responses = [
                r#"{"decision":"pending_hitl","approval_token":"tok42","retry_after_ms":10}"#,
                r#"{"decision":"allow"}"#,
            ];
            for response in &responses {
                let (mut stream, _) = listener.accept().unwrap_or_else(|e| panic!("{e}"));
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .unwrap_or_else(|e| panic!("{e}"));
                requests_srv
                    .lock()
                    .unwrap_or_else(|e| panic!("{e}"))
                    .push(line.trim().to_string());
                stream
                    .write_all(format!("{response}\n").as_bytes())
                    .unwrap_or_else(|e| panic!("{e}"));
            }
        });

        let mut cfg = mediator_config(addr);
        cfg.hitl_mode = CommandMediatorHitlMode::AsyncToken;
        cfg.hitl_max_wait_ms = 5_000;

        let result = enforce_local_command_governance(&cfg, &identity(), "/bin/echo", &[]);
        assert!(result.is_ok(), "unexpected: {result:?}");

        let snapshot: Vec<String> = {
            let reqs = requests.lock().unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(reqs.len(), 2, "expected exactly 2 requests");
            reqs.clone()
        };
        let first: serde_json::Value =
            serde_json::from_str(&snapshot[0]).unwrap_or_else(|e| panic!("{e}"));
        let second: serde_json::Value =
            serde_json::from_str(&snapshot[1]).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            first.get("approval_token").is_none(),
            "first request must not include approval_token"
        );
        assert_eq!(
            second.get("approval_token").and_then(|v| v.as_str()),
            Some("tok42"),
            "second request must carry the token from the pending_hitl response"
        );
    }

    #[test]
    fn mediator_async_token_times_out_fail_closed() {
        // Server: always returns pending_hitl.
        let Some(listener) = try_bind_tcp_local() else {
            return;
        };
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        std::thread::spawn(move || {
            loop {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut reader = BufReader::new(&stream);
                    let mut line = String::new();
                    let _ = reader.read_line(&mut line);
                    let _ = stream.write_all(
                    b"{\"decision\":\"pending_hitl\",\"approval_token\":\"t\",\"retry_after_ms\":50}\n",
                );
                }
            }
        });

        let mut cfg = mediator_config(addr);
        cfg.hitl_mode = CommandMediatorHitlMode::AsyncToken;
        cfg.hitl_max_wait_ms = 60; // expires after first retry_after (50ms) would push past deadline

        let err = enforce_local_command_governance(&cfg, &identity(), "/bin/echo", &[])
            .expect_err("expected timeout fail-closed");
        assert!(
            err.to_string().contains("hitl_max_wait_ms"),
            "unexpected: {err}"
        );
    }
}

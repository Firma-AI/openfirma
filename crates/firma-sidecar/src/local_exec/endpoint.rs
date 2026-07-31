//! Local-exec governance UDS endpoint.
//!
//! [`LocalExecEndpoint::run`] binds a Unix domain socket, accepts connections
//! from `firma-run` clients and operator management tools, and dispatches each
//! request through the [`LocalExecHandler`].
//!
//! # Protocol
//!
//! One newline-terminated JSON object per connection (request then response).
//! Requests are dispatched by the `action` field:
//!
//! - `"local.exec"` — governance request from `firma-run`; responds with
//!   [`LocalExecResponse`].
//! - `"local.exec.approve"` / `"local.exec.revoke"` — management commands from
//!   an operator or the `firma token` CLI; responds with
//!   [`LocalExecManagementResponse`].
//!
//! # Security
//!
//! On Linux the endpoint validates the peer UID via `SO_PEERCRED` before
//! parsing the request. Connections from a different UID are rejected
//! fail-closed with no response. On non-Linux Unix the credential check
//! is omitted (the socket file's filesystem permissions are the primary
//! access control).
//!
//! The same-UID peer check cannot distinguish the sandboxed agent (which runs
//! as the Sidecar's UID and can reach the socket) from the operator, so
//! self-approval is prevented by **socket isolation**: `firma-run` shadows this
//! socket with `/dev/null` inside the `bwrap` sandbox, so the agent cannot
//! `connect()` to it. Management commands (`local.exec.approve` /
//! `local.exec.revoke`) additionally require an operator management token (see
//! [`super::handler::RedactedManagementToken`]) as defense-in-depth for
//! deployments where the agent could reach the socket. Without a configured
//! token, management commands are rejected fail-closed.
//!
//! # Lifecycle
//!
//! The endpoint removes any stale socket file before binding and removes it
//! again on shutdown (cancel signal). The background token-pruning task runs
//! on the same cancellation token and shares the `Arc<dyn TokenStore>`.

use std::io;
use std::path::PathBuf;
#[cfg(target_family = "unix")]
use std::sync::Arc;
#[cfg(target_family = "unix")]
use std::time::Duration;

#[cfg(target_family = "unix")]
use serde::Deserialize;
#[cfg(target_family = "unix")]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(target_family = "unix")]
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;

use super::handler::LocalExecHandler;
#[cfg(target_family = "unix")]
use super::handler::{
    LocalExecDecision, LocalExecManagementRequest, LocalExecManagementResponse, LocalExecRequest,
    LocalExecResponse, ManagementOutcome,
};

/// Hard cap on incoming request line length. Protects against memory exhaustion
/// from a misbehaving same-UID process sending an unbounded line.
#[cfg(target_family = "unix")]
const MAX_REQUEST_LINE_BYTES: usize = 64 * 1024;

/// Per-connection read timeout. Requests must complete within this window;
/// connections that stall are closed fail-closed.
#[cfg(target_family = "unix")]
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

/// The local-exec governance UDS endpoint.
pub struct LocalExecEndpoint {
    socket_path: PathBuf,
    #[cfg(target_family = "unix")]
    handler: Arc<LocalExecHandler>,
}

impl LocalExecEndpoint {
    /// Create the endpoint with the given socket path and handler.
    #[must_use]
    #[cfg_attr(
        not(target_family = "unix"),
        expect(
            clippy::needless_pass_by_value,
            reason = "non-unix builds keep the constructor signature aligned with the unix implementation"
        )
    )]
    pub fn new(socket_path: PathBuf, handler: LocalExecHandler) -> Self {
        #[cfg(target_family = "unix")]
        {
            Self {
                socket_path,
                handler: Arc::new(handler),
            }
        }
        #[cfg(not(target_family = "unix"))]
        {
            let _ = handler;
            Self { socket_path }
        }
    }

    /// Bind the socket, spawn the pruning task, and accept connections until
    /// `cancel` fires.
    ///
    /// # Errors
    ///
    /// Returns an error when the socket cannot be bound (permissions, path).
    #[cfg(target_family = "unix")]
    pub async fn run(self, cancel: CancellationToken) -> io::Result<()> {
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "local-exec: could not remove stale socket {}: {e}",
                        self.socket_path.display()
                    ),
                )
            })?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!(
                            "local-exec: failed to set socket permissions (0600) on {}: {e}",
                            self.socket_path.display()
                        ),
                    )
                })?;
        }
        tracing::info!(
            socket = %self.socket_path.display(),
            "local-exec governance endpoint listening"
        );

        // Background task: prune expired tokens every 60 seconds.
        let store_for_pruner = self.handler.token_store();
        let prune_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_mins(1));
            loop {
                tokio::select! {
                    () = prune_cancel.cancelled() => break,
                    _ = interval.tick() => store_for_pruner.prune_expired(),
                }
            }
        });

        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    tracing::info!(
                        socket = %self.socket_path.display(),
                        "local-exec endpoint shutting down"
                    );
                    break;
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            let handler = Arc::clone(&self.handler);
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, &handler).await {
                                    tracing::warn!(error = %e, "local-exec connection error");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "local-exec accept failed");
                        }
                    }
                }
            }
        }

        let _ = std::fs::remove_file(&self.socket_path);
        Ok(())
    }

    #[cfg(not(target_family = "unix"))]
    ///
    /// # Errors
    ///
    /// Always returns `io::ErrorKind::Unsupported` because the local-exec
    /// endpoint requires Unix domain sockets.
    pub async fn run(self, _cancel: CancellationToken) -> io::Result<()> {
        tokio::task::yield_now().await;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "local-exec endpoint requires unix domain sockets; unsupported on this platform (path={})",
                self.socket_path.display()
            ),
        ))
    }
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

/// Peek at the `action` field without fully deserializing the request.
#[cfg(target_family = "unix")]
#[derive(Deserialize)]
struct ActionPeek {
    action: String,
}

#[cfg(target_family = "unix")]
async fn handle_connection(stream: UnixStream, handler: &LocalExecHandler) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    validate_peer_uid(&stream)?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    tokio::time::timeout(CONNECTION_READ_TIMEOUT, reader.read_line(&mut line))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "local-exec: connection read timeout (fail-closed)",
            )
        })??;

    if line.len() > MAX_REQUEST_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "local-exec: request line exceeds {MAX_REQUEST_LINE_BYTES} bytes (fail-closed)"
            ),
        ));
    }

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local-exec: empty request line",
        ));
    }

    // Peek at the action field to determine the dispatch path.
    let action = match serde_json::from_str::<ActionPeek>(trimmed) {
        Ok(p) => p.action,
        Err(e) => {
            tracing::warn!(error = %e, "local-exec: malformed request (no action field); failing closed");
            let response = LocalExecResponse {
                decision: LocalExecDecision::Deny,
                reason: Some(format!("malformed request: {e}")),
                approval_token: None,
                retry_after_ms: None,
            };
            return send_governance_response(reader.into_inner(), &response).await;
        }
    };

    match action.as_str() {
        "local.exec" => {
            let request = match serde_json::from_str::<LocalExecRequest>(trimmed) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "local-exec: malformed governance request; failing closed");
                    let response = LocalExecResponse {
                        decision: LocalExecDecision::Deny,
                        reason: Some(format!("malformed request: {e}")),
                        approval_token: None,
                        retry_after_ms: None,
                    };
                    return send_governance_response(reader.into_inner(), &response).await;
                }
            };
            let response = handler.decide(&request);
            send_governance_response(reader.into_inner(), &response).await
        }
        "local.exec.approve" | "local.exec.revoke" => {
            let request = match serde_json::from_str::<LocalExecManagementRequest>(trimmed) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "local-exec: malformed management request");
                    let response = LocalExecManagementResponse {
                        outcome: ManagementOutcome::UnsupportedAction,
                        reason: Some(format!("malformed management request: {e}")),
                    };
                    return send_management_response(reader.into_inner(), &response).await;
                }
            };
            let response = handler.decide_management(&request);
            send_management_response(reader.into_inner(), &response).await
        }
        other => {
            tracing::warn!(action = %other, "local-exec: unknown action; failing closed");
            let response = LocalExecResponse {
                decision: LocalExecDecision::Deny,
                reason: Some(format!("unknown action '{other}'")),
                approval_token: None,
                retry_after_ms: None,
            };
            send_governance_response(reader.into_inner(), &response).await
        }
    }
}

#[cfg(target_family = "unix")]
async fn send_governance_response(
    mut stream: UnixStream,
    response: &LocalExecResponse,
) -> io::Result<()> {
    let mut payload = serde_json::to_vec(response)
        .map_err(|e| io::Error::other(format!("local-exec: failed to serialize response: {e}")))?;
    payload.push(b'\n');
    stream.write_all(&payload).await?;
    stream.flush().await
}

#[cfg(target_family = "unix")]
async fn send_management_response(
    mut stream: UnixStream,
    response: &LocalExecManagementResponse,
) -> io::Result<()> {
    let mut payload = serde_json::to_vec(response)
        .map_err(|e| io::Error::other(format!("local-exec: failed to serialize response: {e}")))?;
    payload.push(b'\n');
    stream.write_all(&payload).await?;
    stream.flush().await
}

// ---------------------------------------------------------------------------
// Linux peer UID validation
// ---------------------------------------------------------------------------

/// Verify that the connecting process runs as the same UID as the sidecar.
///
/// This is a defense-in-depth measure; the primary access control is the
/// socket file's filesystem permissions (mode 0600 or 0700 directory).
#[cfg(target_os = "linux")]
fn validate_peer_uid(stream: &UnixStream) -> io::Result<()> {
    let creds = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("local-exec: peer credential check failed (fail-closed): {e}"),
            )
        })?;

    let peer_uid = creds.uid();
    let own_uid = nix::unistd::getuid().as_raw();

    if peer_uid != own_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "local-exec: peer uid {peer_uid} does not match sidecar uid {own_uid} (fail-closed)"
            ),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, target_family = "unix"))]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "unix-only endpoint tests use expect for socket setup and wire round-trips"
    )]
    use std::time::Duration;

    use super::*;
    use crate::local_exec::handler::{
        DefaultAction, LocalExecDecision, LocalExecHandlerConfig, RedactedManagementToken,
    };

    const MGMT_TOKEN: &str = "endpoint-test-mgmt-token";

    async fn start_endpoint(
        tmp: &tempfile::TempDir,
        action: DefaultAction,
    ) -> (PathBuf, CancellationToken) {
        let socket_path = tmp.path().join("test-local-exec.sock");
        let config = LocalExecHandlerConfig {
            default_action: action,
            expected_sandbox_id: None,
            token_ttl: Duration::from_mins(1),
            retry_after_ms: 500,
            management_token: Some(RedactedManagementToken::new(MGMT_TOKEN.to_string())),
        };
        let handler = LocalExecHandler::new(config);
        let endpoint = LocalExecEndpoint::new(socket_path.clone(), handler);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            endpoint.run(cancel_clone).await.expect("endpoint failed");
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        (socket_path, cancel)
    }

    async fn send_governance(socket_path: &PathBuf, req: &LocalExecRequest) -> LocalExecResponse {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let mut stream = tokio::net::UnixStream::connect(socket_path)
            .await
            .expect("connect");
        let payload = serde_json::to_string(req).expect("serialize");
        stream
            .write_all(format!("{payload}\n").as_bytes())
            .await
            .expect("write");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read");
        serde_json::from_str(line.trim()).expect("deserialize governance response")
    }

    async fn send_management(
        socket_path: &PathBuf,
        req: &LocalExecManagementRequest,
    ) -> LocalExecManagementResponse {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let mut stream = tokio::net::UnixStream::connect(socket_path)
            .await
            .expect("connect");
        let payload = serde_json::to_string(req).expect("serialize");
        stream
            .write_all(format!("{payload}\n").as_bytes())
            .await
            .expect("write");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read");
        serde_json::from_str(line.trim()).expect("deserialize management response")
    }

    fn base_request() -> LocalExecRequest {
        LocalExecRequest {
            action: "local.exec".to_string(),
            executable: "/usr/bin/env".to_string(),
            args: vec![],
            sandbox_id: "sbx_01j0000000e008000000000001"
                .parse()
                .expect("valid sandbox ID fixture"),
            session_id: "sess_1".to_string(),
            agent_id: Some("agent_1".to_string()),
            profile: "generic".to_string(),
            hitl_mode: "async_token".to_string(),
            request_fingerprint: None,
            approval_token: None,
        }
    }

    fn mgmt(action: &str, token_id: &str) -> LocalExecManagementRequest {
        LocalExecManagementRequest {
            action: action.to_string(),
            token_id: token_id.to_string(),
            management_token: Some(MGMT_TOKEN.to_string()),
        }
    }

    #[tokio::test]
    async fn endpoint_allow_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, cancel) = start_endpoint(&tmp, DefaultAction::Allow).await;
        let resp = send_governance(&path, &base_request()).await;
        assert_eq!(resp.decision, LocalExecDecision::Allow);
        cancel.cancel();
    }

    #[tokio::test]
    async fn endpoint_deny_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, cancel) = start_endpoint(&tmp, DefaultAction::Deny).await;
        let resp = send_governance(&path, &base_request()).await;
        assert_eq!(resp.decision, LocalExecDecision::Deny);
        cancel.cancel();
    }

    #[tokio::test]
    async fn endpoint_hitl_full_approve_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, cancel) = start_endpoint(&tmp, DefaultAction::PendingHitl).await;

        // Fresh request — pending, token issued.
        let pending = send_governance(&path, &base_request()).await;
        assert_eq!(pending.decision, LocalExecDecision::PendingHitl);
        let token = pending.approval_token.unwrap();

        // Retry before approval — still pending, same token returned.
        let mut retry = base_request();
        retry.approval_token = Some(token.clone());
        let still_pending = send_governance(&path, &retry).await;
        assert_eq!(still_pending.decision, LocalExecDecision::PendingHitl);
        assert_eq!(
            still_pending.approval_token.as_deref(),
            Some(token.as_str())
        );

        // Operator approves via management command.
        let approve = mgmt("local.exec.approve", &token);
        let mgmt_resp = send_management(&path, &approve).await;
        assert_eq!(mgmt_resp.outcome, ManagementOutcome::Ok);

        // Retry after approval — allowed and token consumed.
        let allowed = send_governance(&path, &retry).await;
        assert_eq!(allowed.decision, LocalExecDecision::Allow);

        // Replay — denied (already consumed).
        let denied = send_governance(&path, &retry).await;
        assert_eq!(denied.decision, LocalExecDecision::Deny);

        cancel.cancel();
    }

    #[tokio::test]
    async fn endpoint_hitl_revoke_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, cancel) = start_endpoint(&tmp, DefaultAction::PendingHitl).await;

        let pending = send_governance(&path, &base_request()).await;
        let token = pending.approval_token.unwrap();

        // Operator revokes.
        let revoke = mgmt("local.exec.revoke", &token);
        let mgmt_resp = send_management(&path, &revoke).await;
        assert_eq!(mgmt_resp.outcome, ManagementOutcome::Ok);

        // Retry after revocation — denied.
        let mut retry = base_request();
        retry.approval_token = Some(token);
        let denied = send_governance(&path, &retry).await;
        assert_eq!(denied.decision, LocalExecDecision::Deny);
        assert!(denied.reason.unwrap_or_default().contains("revoked"));

        cancel.cancel();
    }

    #[tokio::test]
    async fn endpoint_management_rejects_missing_token() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, cancel) = start_endpoint(&tmp, DefaultAction::PendingHitl).await;

        let pending = send_governance(&path, &base_request()).await;
        let token = pending.approval_token.unwrap();

        // A same-UID process (e.g. the sandboxed agent) tries to self-approve
        // without the operator management token — must be rejected.
        let mut approve = mgmt("local.exec.approve", &token);
        approve.management_token = None;
        let resp = send_management(&path, &approve).await;
        assert_eq!(resp.outcome, ManagementOutcome::Unauthorized);

        // The token is still pending: the failed self-approve did not release it.
        let mut retry = base_request();
        retry.approval_token = Some(token.clone());
        let still_pending = send_governance(&path, &retry).await;
        assert_eq!(still_pending.decision, LocalExecDecision::PendingHitl);

        // The operator, with the token, can still approve.
        let approve = mgmt("local.exec.approve", &token);
        let resp = send_management(&path, &approve).await;
        assert_eq!(resp.outcome, ManagementOutcome::Ok);

        cancel.cancel();
    }

    #[tokio::test]
    async fn endpoint_management_rejects_wrong_token() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, cancel) = start_endpoint(&tmp, DefaultAction::PendingHitl).await;

        let pending = send_governance(&path, &base_request()).await;
        let token = pending.approval_token.unwrap();

        let mut approve = mgmt("local.exec.approve", &token);
        approve.management_token = Some("wrong-token".to_string());
        let resp = send_management(&path, &approve).await;
        assert_eq!(resp.outcome, ManagementOutcome::Unauthorized);

        cancel.cancel();
    }
}

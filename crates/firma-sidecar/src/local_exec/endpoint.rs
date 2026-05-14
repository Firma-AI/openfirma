//! Local-exec governance UDS endpoint.
//!
//! [`LocalExecEndpoint::run`] binds a Unix domain socket, accepts connections
//! from `firma-run` clients, and dispatches each request through the
//! [`LocalExecHandler`].
//!
//! # Protocol
//!
//! One newline-terminated JSON object per connection (request then response).
//! The client writes one `LocalExecRequest` JSON line; the server responds
//! with one `LocalExecResponse` JSON line and closes the connection.
//!
//! # Security
//!
//! On Linux the endpoint validates the peer UID via `SO_PEERCRED` before
//! parsing the request. Connections from a different UID are rejected
//! fail-closed with no response. On non-Linux Unix the credential check
//! is omitted (the socket file's filesystem permissions are the primary
//! access control).
//!
//! # Lifecycle
//!
//! The endpoint removes any stale socket file before binding and removes it
//! again on shutdown (cancel signal). The background token-pruning task runs
//! on the same cancellation token and shares the `Arc<dyn TokenStore>`.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;

use super::handler::{LocalExecDecision, LocalExecHandler, LocalExecRequest, LocalExecResponse};

/// Hard cap on incoming request line length. Protects against memory exhaustion
/// from a misbehaving same-UID process sending an unbounded line.
const MAX_REQUEST_LINE_BYTES: usize = 64 * 1024;

/// Per-connection read timeout. Local UDS governance requests must complete
/// within this window; connections that stall are closed fail-closed.
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

/// The local-exec governance UDS endpoint.
pub struct LocalExecEndpoint {
    socket_path: PathBuf,
    handler: Arc<LocalExecHandler>,
}

impl LocalExecEndpoint {
    /// Create the endpoint with the given socket path and handler.
    #[must_use]
    pub fn new(socket_path: PathBuf, handler: LocalExecHandler) -> Self {
        Self {
            socket_path,
            handler: Arc::new(handler),
        }
    }

    /// Bind the socket, spawn the pruning task, and accept connections until
    /// `cancel` fires.
    ///
    /// # Errors
    ///
    /// Returns an error when the socket cannot be bound (permissions, path).
    pub async fn run(self, cancel: CancellationToken) -> io::Result<()> {
        // Remove stale socket from a previous run.
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
        tracing::info!(
            socket = %self.socket_path.display(),
            "local-exec governance endpoint listening"
        );

        // Background task: prune expired tokens every 60 seconds.
        let store_for_pruner = self.handler.token_store();
        let prune_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    () = prune_cancel.cancelled() => break,
                    _ = interval.tick() => store_for_pruner.prune_expired(),
                }
            }
        });

        // Accept loop.
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
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

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

    let request: LocalExecRequest = match serde_json::from_str(trimmed) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "local-exec: malformed request; failing closed");
            let response = LocalExecResponse {
                decision: LocalExecDecision::Deny,
                reason: Some(format!("malformed request: {e}")),
                approval_token: None,
                retry_after_ms: None,
            };
            send_response(reader.into_inner(), &response).await?;
            return Ok(());
        }
    };

    let response = handler.decide(&request);
    send_response(reader.into_inner(), &response).await
}

async fn send_response(mut stream: UnixStream, response: &LocalExecResponse) -> io::Result<()> {
    let mut payload = serde_json::to_vec(response)
        .map_err(|e| io::Error::other(format!("local-exec: failed to serialize response: {e}")))?;
    payload.push(b'\n');
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::local_exec::handler::{DefaultAction, LocalExecDecision, LocalExecHandlerConfig};

    async fn start_endpoint(
        tmp: &tempfile::TempDir,
        action: DefaultAction,
    ) -> (PathBuf, CancellationToken) {
        let socket_path = tmp.path().join("test-local-exec.sock");
        let config = LocalExecHandlerConfig {
            default_action: action,
            token_ttl: Duration::from_secs(60),
            retry_after_ms: 500,
        };
        let handler = LocalExecHandler::new(config);
        let endpoint = LocalExecEndpoint::new(socket_path.clone(), handler);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            endpoint.run(cancel_clone).await.expect("endpoint failed");
        });
        // Give the task a moment to bind.
        tokio::time::sleep(Duration::from_millis(20)).await;
        (socket_path, cancel)
    }

    async fn send_request(socket_path: &PathBuf, req: &LocalExecRequest) -> LocalExecResponse {
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
        serde_json::from_str(line.trim()).expect("deserialize response")
    }

    fn base_request() -> LocalExecRequest {
        LocalExecRequest {
            action: "local.exec".to_string(),
            executable: "/usr/bin/env".to_string(),
            args: vec![],
            sandbox_id: "sbx_1".to_string(),
            session_id: "sess_1".to_string(),
            agent_id: Some("agent_1".to_string()),
            profile: "generic".to_string(),
            hitl_mode: "async_token".to_string(),
            budget_state_ref: None,
            request_fingerprint: None,
            approval_token: None,
        }
    }

    #[tokio::test]
    async fn endpoint_allow_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, cancel) = start_endpoint(&tmp, DefaultAction::Allow).await;
        let resp = send_request(&path, &base_request()).await;
        assert_eq!(resp.decision, LocalExecDecision::Allow);
        cancel.cancel();
    }

    #[tokio::test]
    async fn endpoint_deny_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, cancel) = start_endpoint(&tmp, DefaultAction::Deny).await;
        let resp = send_request(&path, &base_request()).await;
        assert_eq!(resp.decision, LocalExecDecision::Deny);
        cancel.cancel();
    }

    #[tokio::test]
    async fn endpoint_hitl_token_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, cancel) = start_endpoint(&tmp, DefaultAction::PendingHitl).await;

        // Fresh request — should return pending_hitl with a token.
        let pending = send_request(&path, &base_request()).await;
        assert_eq!(pending.decision, LocalExecDecision::PendingHitl);
        let token = pending.approval_token.unwrap();

        // Retry with the issued token — should return allow.
        let mut retry = base_request();
        retry.approval_token = Some(token.clone());
        let allowed = send_request(&path, &retry).await;
        assert_eq!(allowed.decision, LocalExecDecision::Allow);

        // Second retry — token already consumed, should deny.
        let mut replay = base_request();
        replay.approval_token = Some(token);
        let denied = send_request(&path, &replay).await;
        assert_eq!(denied.decision, LocalExecDecision::Deny);

        cancel.cancel();
    }
}

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
#[cfg(target_family = "unix")]
use firma_core::{AgentId, SecretDecision};

#[cfg(target_family = "unix")]
use crate::enforcement::constraint_enforcement::PolicyEvaluation;

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
    /// Live policy evaluator for `secret.mediate` decisions. `None` until a
    /// caller supplies one via [`LocalExecEndpoint::with_evaluator`]; a
    /// `secret.mediate` request with no evaluator fails closed.
    #[cfg(target_family = "unix")]
    evaluator: Option<Arc<dyn PolicyEvaluation + Send + Sync>>,
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
                evaluator: None,
            }
        }
        #[cfg(not(target_family = "unix"))]
        {
            let _ = handler;
            Self { socket_path }
        }
    }

    /// Attach the live policy evaluator used to decide `secret.mediate`
    /// requests. Without this, `secret.mediate` requests fail closed.
    #[cfg(target_family = "unix")]
    #[must_use]
    pub fn with_evaluator(mut self, evaluator: Arc<dyn PolicyEvaluation + Send + Sync>) -> Self {
        self.evaluator = Some(evaluator);
        self
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
                            let evaluator = self.evaluator.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    handle_connection(stream, &handler, evaluator.as_deref()).await
                                {
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
async fn handle_connection(
    stream: UnixStream,
    handler: &LocalExecHandler,
    evaluator: Option<&(dyn PolicyEvaluation + Send + Sync)>,
) -> io::Result<()> {
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
        "secret.mediate" => {
            if let Some(evaluator) = evaluator {
                handle_secret_mediation(reader.into_inner(), evaluator, trimmed).await
            } else {
                tracing::warn!("secret.mediate requested but no evaluator wired; failing closed");
                send_secret_error(
                    reader.into_inner(),
                    "secret mediation is not available on this sidecar",
                )
                .await
            }
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

/// Deserialized `secret.mediate` governance request (broker → Sidecar). The
/// `action` field is already consumed by the [`ActionPeek`] dispatch.
#[cfg(target_family = "unix")]
#[derive(Deserialize)]
struct SecretMediateRequest {
    #[serde(default)]
    argv: Vec<String>,
    session_id: String,
    #[serde(default)]
    agent_id: Option<String>,
}

/// Evaluate a `secret.mediate` request against the live policy evaluator and
/// write back the [`SecretDecision`]. Any internal failure is written as an
/// error object, which does not decode as a `SecretDecision` on the broker
/// side, so the broker fails closed to deny.
#[cfg(target_family = "unix")]
async fn handle_secret_mediation(
    stream: UnixStream,
    evaluator: &(dyn PolicyEvaluation + Send + Sync),
    trimmed: &str,
) -> io::Result<()> {
    let request = match serde_json::from_str::<SecretMediateRequest>(trimmed) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "secret.mediate: malformed request; failing closed");
            return send_secret_error(stream, &format!("malformed secret.mediate request: {e}"))
                .await;
        }
    };

    let principal = match secret_principal(request.agent_id.as_deref()) {
        Ok(p) => p,
        Err(e) => return send_secret_error(stream, &format!("invalid agent id: {e}")).await,
    };
    let argv = request.argv.join(" ");
    let context = launch_context(&request.session_id);

    match evaluator.evaluate_secret_mediation(&principal, &argv, context) {
        Ok(decision) => send_secret_decision(stream, &decision).await,
        Err(reason) => {
            tracing::warn!(error = %reason, "secret.mediate: evaluation failed; failing closed");
            send_secret_error(stream, &reason).await
        }
    }
}

/// Parse the request's agent id, falling back to a fixed sentinel when absent.
/// The `secret.mediate` decision does not scope by principal today, but Cedar
/// still requires a valid principal UID.
#[cfg(target_family = "unix")]
fn secret_principal(agent_id: Option<&str>) -> Result<AgentId, String> {
    agent_id
        .unwrap_or("unknown-agent")
        .parse::<AgentId>()
        .map_err(|e| e.to_string())
}

/// Build the minimal `EnforcementContext` for a launch-time secret decision.
/// Mirrors the required fields produced by `ConstraintEnforcer::build_context`;
/// counters that only matter for HTTP actions default to zero.
#[cfg(target_family = "unix")]
fn launch_context(session_id: &str) -> serde_json::Value {
    serde_json::json!({
        "session_id": session_id,
        "timestamp_ms": now_unix_ms(),
        "params": "{}",
        "risk_score": 0i64,
        "budget_remaining": i64::MAX,
        "session_duration_s": 0i64,
        "action_count": 0i64,
        "raw_transport": "local",
        "deny_count": 0i64,
        "prior_action_classes": Vec::<String>::new(),
        "last_resource": "",
        "transfer_amount": 0i64,
        "daily_cumulative_amount": 0i64,
        "transfers_last_10m": 0i64,
        "same_payee_count_30m": 0i64,
        "session_transfer_count": 0i64,
    })
}

#[cfg(target_family = "unix")]
fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(target_family = "unix")]
async fn send_secret_decision(mut stream: UnixStream, decision: &SecretDecision) -> io::Result<()> {
    let mut payload = serde_json::to_vec(decision).map_err(|e| {
        io::Error::other(format!("secret.mediate: failed to serialize decision: {e}"))
    })?;
    payload.push(b'\n');
    stream.write_all(&payload).await?;
    stream.flush().await
}

#[cfg(target_family = "unix")]
async fn send_secret_error(mut stream: UnixStream, reason: &str) -> io::Result<()> {
    let mut payload = serde_json::to_vec(&serde_json::json!({ "error": reason }))
        .map_err(|e| io::Error::other(format!("secret.mediate: failed to serialize error: {e}")))?;
    payload.push(b'\n');
    stream.write_all(&payload).await?;
    stream.flush().await
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
    use crate::local_exec::handler::{DefaultAction, LocalExecDecision, LocalExecHandlerConfig};

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

    async fn send_secret_mediate(socket_path: &PathBuf, req: &serde_json::Value) -> String {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let mut stream = tokio::net::UnixStream::connect(socket_path)
            .await
            .expect("connect");
        stream
            .write_all(format!("{req}\n").as_bytes())
            .await
            .expect("write");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read");
        line.trim().to_string()
    }

    fn deny_handler() -> LocalExecHandler {
        LocalExecHandler::new(LocalExecHandlerConfig {
            default_action: DefaultAction::Deny,
            token_ttl: Duration::from_mins(1),
            retry_after_ms: 500,
        })
    }

    #[tokio::test]
    async fn secret_mediation_returns_mediate_for_matching_launch() {
        use crate::enforcement::cedar_evaluator::CedarPolicyEvaluator;
        use firma_core::policy::PolicyBundle;

        let tmp = tempfile::tempdir().expect("tempdir");
        let socket_path = tmp.path().join("secret.sock");

        let policy = br#"
            @mode("intercept")
            @adapter("bws")
            @placeholder("firma-secret://bitwarden/{name}")
            permit(principal, action == Firma::Action::"secret.mediate", resource)
            when { resource.id like "bws*" };
        "#;
        let bundle = PolicyBundle::new(
            "v1".to_string(),
            policy.to_vec(),
            firma_core::cedar::FIRMA_SCHEMA.as_bytes().to_vec(),
            30,
        );
        let evaluator: Arc<dyn PolicyEvaluation + Send + Sync> =
            Arc::new(CedarPolicyEvaluator::from_bundle(&bundle).expect("build evaluator"));

        let endpoint =
            LocalExecEndpoint::new(socket_path.clone(), deny_handler()).with_evaluator(evaluator);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            endpoint.run(cancel_clone).await.expect("endpoint");
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let response = send_secret_mediate(
            &socket_path,
            &serde_json::json!({
                "action": "secret.mediate",
                "argv": ["bws", "secret", "get", "x"],
                "session_id": "sess_1",
                "agent_id": "agent_1",
            }),
        )
        .await;

        match serde_json::from_str::<SecretDecision>(&response) {
            Ok(SecretDecision::Mediate(m)) => assert_eq!(m.adapter.as_deref(), Some("bws")),
            other => panic!("expected Mediate; got {other:?} (raw: {response})"),
        }
        cancel.cancel();
    }

    #[tokio::test]
    async fn secret_mediation_without_evaluator_fails_closed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let socket_path = tmp.path().join("secret-noeval.sock");

        let endpoint = LocalExecEndpoint::new(socket_path.clone(), deny_handler());
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            endpoint.run(cancel_clone).await.expect("endpoint");
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let response = send_secret_mediate(
            &socket_path,
            &serde_json::json!({"action": "secret.mediate", "argv": ["bws"], "session_id": "s"}),
        )
        .await;

        // No evaluator wired → not a decodable SecretDecision, so the broker
        // fails closed to deny.
        assert!(serde_json::from_str::<SecretDecision>(&response).is_err());
        cancel.cancel();
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
        let approve = LocalExecManagementRequest {
            action: "local.exec.approve".to_string(),
            token_id: token.clone(),
        };
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
        let revoke = LocalExecManagementRequest {
            action: "local.exec.revoke".to_string(),
            token_id: token.clone(),
        };
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
}

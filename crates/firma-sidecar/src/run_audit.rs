//! `firma run` audit channel ingest.
//!
//! `firma run` performs some enforcement outside the Sidecar's request pipeline
//! — most notably the egress guard, which blocks an agent's direct loopback
//! connections at the sandbox boundary before they could reach `HTTP_PROXY`. To
//! keep the audit trail complete, `firma run` reports each such fact to the
//! Sidecar over a local control socket as a [`RunAuditMessage`]. This module
//! turns those messages into signed audit events by feeding the same
//! [`AuditPayload`] channel the enforcement hot path uses, so an out-of-band
//! block surfaces in `firma monitor` exactly like a hot-path DENY.
//!
//! The Sidecar owns the audit semantics: <code>[AuditPayload]::from(&msg)</code> maps
//! each [`RunAuditEvent`] variant to a fixed `(action_class, decision,
//! deny_reason, resource)`. The producer only states observations, so the
//! signature over the resulting event keeps meaning.
//!
//! The listener is mode-independent (it sits beside the audit channel, not
//! inside the interceptor) and Unix-only (the control socket is a UDS).

#![cfg(unix)]

use std::path::{Path, PathBuf};

use firma_core::{DenyReason, RunAuditEvent, RunAuditMessage};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::audit::{AuditPayload, Decision};

/// Canonical action class for a blocked loopback connection attempt.
///
/// Registered in `docs/markdown/firma_action_class_registry.md` as an
/// out-of-band, audit-only class. Owned by the Sidecar because the Sidecar
/// signs the event and therefore owns its meaning.
pub const NETWORK_LOOPBACK_ACTION_CLASS: &str = "network.loopback";

/// Maps a `firma run` audit message to a signed-ready [`AuditPayload`].
///
/// This is where the Sidecar assigns audit semantics to a bare observation:
/// each [`RunAuditEvent`] variant resolves to a fixed action class, decision,
/// and reason. Dispatch/latency fields are zero because the call never reached
/// a connector.
impl From<&RunAuditMessage> for AuditPayload {
    fn from(msg: &RunAuditMessage) -> Self {
        let (action, decision, deny_reason, resource) = match &msg.event {
            RunAuditEvent::LoopbackBlocked { dst_ip, dst_port } => (
                NETWORK_LOOPBACK_ACTION_CLASS.to_string(),
                Decision::Deny,
                DenyReason::LoopbackBlocked.to_string(),
                loopback_resource(dst_ip, *dst_port),
            ),
        };
        Self {
            session_id: msg.session_id.clone(),
            token_id: String::new(),
            agent_id: msg.agent_id.clone(),
            action,
            resource,
            decision,
            deny_reason,
            enforcement_latency_us: 0,
            context_hash: String::new(),
            bundle_version: String::new(),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
            provenance: String::new(),
            thread_id: String::new(),
            parent_action_id: String::new(),
        }
    }
}

/// Renders a blocked loopback destination as an audit `resource` string.
///
/// IPv6 destinations are bracketed so the `host:port` form stays unambiguous
/// (`[::1]:9000`); IPv4 destinations are left bare. The `tcp://` scheme marks
/// the transport.
fn loopback_resource(dst_ip: &str, dst_port: u16) -> String {
    if dst_ip.contains(':') {
        format!("tcp://[{dst_ip}]:{dst_port}")
    } else {
        format!("tcp://{dst_ip}:{dst_port}")
    }
}

/// Binds the audit control socket and serves messages until `exit`.
///
/// Each accepted connection streams newline-delimited JSON [`RunAuditMessage`]s.
/// Every well-formed message is converted into an [`AuditPayload`] and forwarded
/// to `audit_tx`; malformed lines are logged and skipped (the enforcement that
/// the message describes already happened in `firma run`, so a parse failure
/// must not stall the audit pipeline).
///
/// A stale socket file at `socket_path` is removed before binding so a crashed
/// previous run does not block startup.
///
/// # Errors
///
/// Returns an error when the socket directory cannot be created or the socket
/// cannot be bound.
pub fn spawn_listener(
    socket_path: PathBuf,
    audit_tx: mpsc::Sender<AuditPayload>,
    exit: CancellationToken,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    if let Some(parent) = socket_path.parent() {
        firma_runtime_state::fs::create_private_dir_all(parent).map_err(|error| {
            anyhow::anyhow!(
                "failed to create run-audit socket dir {}: {error}",
                parent.display()
            )
        })?;
    }
    // A leftover socket file from a crashed run would make bind fail with
    // EADDRINUSE; remove it first. Safe because the path is per-run.
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path).map_err(|error| {
        anyhow::anyhow!(
            "failed to bind run-audit socket {}: {error}",
            socket_path.display()
        )
    })?;
    info!(socket = %socket_path.display(), "run-audit listener bound");

    Ok(tokio::spawn(async move {
        serve(&listener, &audit_tx, &exit).await;
        // Best-effort cleanup so the next run starts clean.
        let _ = std::fs::remove_file(&socket_path);
        debug!("run-audit listener stopped");
    }))
}

async fn serve(
    listener: &UnixListener,
    audit_tx: &mpsc::Sender<AuditPayload>,
    exit: &CancellationToken,
) {
    loop {
        tokio::select! {
            () = exit.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        let audit_tx = audit_tx.clone();
                        let exit = exit.clone();
                        tokio::spawn(async move {
                            handle_connection(stream, &audit_tx, &exit).await;
                        });
                    }
                    Err(error) => {
                        warn!(%error, "run-audit accept failed");
                    }
                }
            }
        }
    }
}

async fn handle_connection(
    stream: UnixStream,
    audit_tx: &mpsc::Sender<AuditPayload>,
    exit: &CancellationToken,
) {
    let mut lines = BufReader::new(stream).lines();
    loop {
        tokio::select! {
            () = exit.cancelled() => break,
            next = lines.next_line() => {
                match next {
                    Ok(Some(line)) => {
                        if line.trim().is_empty() {
                            continue;
                        }
                        ingest_line(&line, audit_tx).await;
                    }
                    Ok(None) => break,
                    Err(error) => {
                        warn!(%error, "run-audit connection read failed");
                        break;
                    }
                }
            }
        }
    }
}

async fn ingest_line(line: &str, audit_tx: &mpsc::Sender<AuditPayload>) {
    match serde_json::from_str::<RunAuditMessage>(line) {
        Ok(msg) => {
            debug!(
                session_id = %msg.session_id,
                event = ?msg.event,
                "run-audit message received; emitting audit event"
            );
            let payload = AuditPayload::from(&msg);
            if audit_tx.send(payload).await.is_err() {
                warn!("audit channel closed; dropping run-audit message");
            }
        }
        Err(error) => {
            warn!(%error, "skipping malformed run-audit message");
        }
    }
}

/// Resolves the per-run audit socket path from the directory the Sidecar shares
/// with `firma run`. Kept here so the producer and consumer agree on the
/// filename.
#[must_use]
pub fn socket_path_in(dir: &Path) -> PathBuf {
    dir.join("run-audit.sock")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    fn loopback_msg(dst_ip: &str, dst_port: u16) -> RunAuditMessage {
        RunAuditMessage {
            session_id: "sess-1".to_string(),
            agent_id: "claude-code".to_string(),
            event: RunAuditEvent::LoopbackBlocked {
                dst_ip: dst_ip.to_string(),
                dst_port,
            },
        }
    }

    #[test]
    fn loopback_event_maps_to_deny_payload() {
        let payload = AuditPayload::from(&loopback_msg("127.0.0.1", 6379));
        assert_eq!(payload.decision, Decision::Deny);
        assert_eq!(payload.action, "network.loopback");
        assert_eq!(payload.resource, "tcp://127.0.0.1:6379");
        assert_eq!(payload.deny_reason, "loopback blocked");
        assert_eq!(payload.session_id, "sess-1");
        assert_eq!(payload.agent_id, "claude-code");
    }

    #[test]
    fn ipv6_loopback_resource_is_bracketed() {
        let payload = AuditPayload::from(&loopback_msg("::1", 53));
        assert_eq!(payload.resource, "tcp://[::1]:53");
    }

    #[tokio::test]
    async fn listener_emits_audit_payload_for_reported_message() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = socket_path_in(dir.path());
        let (tx, mut rx) = mpsc::channel(4);
        let exit = CancellationToken::new();
        let handle =
            spawn_listener(socket.clone(), tx, exit.clone()).expect("listener should bind");

        let mut client = UnixStream::connect(&socket).await.expect("connect");
        let mut line = serde_json::to_string(&loopback_msg("::1", 9000)).expect("serialize");
        line.push('\n');
        client.write_all(line.as_bytes()).await.expect("write");
        client.flush().await.expect("flush");

        let payload = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("payload within timeout")
            .expect("payload present");
        assert_eq!(payload.action, "network.loopback");
        assert_eq!(payload.resource, "tcp://[::1]:9000");
        assert_eq!(payload.decision, Decision::Deny);

        exit.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn malformed_line_is_skipped_without_emitting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = socket_path_in(dir.path());
        let (tx, mut rx) = mpsc::channel(4);
        let exit = CancellationToken::new();
        let handle =
            spawn_listener(socket.clone(), tx, exit.clone()).expect("listener should bind");

        let mut client = UnixStream::connect(&socket).await.expect("connect");
        client.write_all(b"not json\n").await.expect("write");
        client.flush().await.expect("flush");

        let got = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
        assert!(got.is_err(), "malformed line must not emit a payload");

        exit.cancel();
        let _ = handle.await;
    }
}

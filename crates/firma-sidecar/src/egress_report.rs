//! Out-of-band egress report ingest.
//!
//! The `firma run` egress guard blocks an agent's direct loopback connections
//! at the sandbox boundary — before they ever reach `HTTP_PROXY` and therefore
//! before they could enter the enforcement pipeline. To keep the audit trail
//! complete, the guard reports each blocked attempt to the Sidecar over a local
//! control socket. This module turns those reports into signed audit events by
//! feeding the same [`AuditPayload`] channel the enforcement hot path uses, so
//! a blocked loopback connection surfaces in `firma monitor` exactly like a
//! hot-path DENY.
//!
//! The listener is intentionally mode-independent: it works whether the
//! interceptor runs in HTTP-proxy or Unix-socket mode, because it sits beside
//! the audit channel rather than inside the interceptor.
//!
//! The control socket is a Unix domain socket, so this module is Unix-only.
//! Windows guests report through their own guest↔host channel (handled by the
//! respective backend), not through this listener.

#![cfg(unix)]

use std::path::{Path, PathBuf};

use firma_core::{BlockedLoopbackReport, DenyReason, NETWORK_LOOPBACK_ACTION_CLASS};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::audit::{AuditPayload, Decision};

/// Converts a blocked-loopback report into a DENY [`AuditPayload`].
///
/// The payload carries the [`NETWORK_LOOPBACK_ACTION_CLASS`] action and the
/// [`DenyReason::LoopbackBlocked`] reason string; dispatch and latency fields
/// are zero because the call never reached a connector.
#[must_use]
pub fn build_loopback_audit_payload(report: &BlockedLoopbackReport) -> AuditPayload {
    AuditPayload {
        session_id: report.session_id.clone(),
        token_id: String::new(),
        agent_id: report.agent_id.clone(),
        action: NETWORK_LOOPBACK_ACTION_CLASS.to_string(),
        resource: report.resource(),
        decision: Decision::Deny,
        deny_reason: DenyReason::LoopbackBlocked.to_string(),
        enforcement_latency_us: 0,
        context_hash: String::new(),
        bundle_version: String::new(),
        dispatch_status: 0,
        dispatch_latency_us: 0,
        response_size: 0,
    }
}

/// Binds the egress-report control socket and serves reports until `exit`.
///
/// Each accepted connection streams newline-delimited JSON
/// [`BlockedLoopbackReport`]s. Every well-formed report is converted into a
/// DENY [`AuditPayload`] and forwarded to `audit_tx`; malformed lines are
/// logged and skipped (fail-open on parsing keeps a noisy guard from stalling
/// the audit pipeline, while the block itself already happened in the guard).
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
        std::fs::create_dir_all(parent).map_err(|error| {
            anyhow::anyhow!(
                "failed to create egress-report socket dir {}: {error}",
                parent.display()
            )
        })?;
    }
    // A leftover socket file from a crashed run would make bind fail with
    // EADDRINUSE; remove it first. Safe because the path is per-run.
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path).map_err(|error| {
        anyhow::anyhow!(
            "failed to bind egress-report socket {}: {error}",
            socket_path.display()
        )
    })?;
    info!(socket = %socket_path.display(), "egress-report listener bound");

    Ok(tokio::spawn(async move {
        serve(&listener, &audit_tx, &exit).await;
        // Best-effort cleanup so the next run starts clean.
        let _ = std::fs::remove_file(&socket_path);
        debug!("egress-report listener stopped");
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
                        warn!(%error, "egress-report accept failed");
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
                        warn!(%error, "egress-report connection read failed");
                        break;
                    }
                }
            }
        }
    }
}

async fn ingest_line(line: &str, audit_tx: &mpsc::Sender<AuditPayload>) {
    match serde_json::from_str::<BlockedLoopbackReport>(line) {
        Ok(report) => {
            debug!(
                session_id = %report.session_id,
                dst = %report.resource(),
                "loopback connection blocked; emitting audit event"
            );
            let payload = build_loopback_audit_payload(&report);
            if audit_tx.send(payload).await.is_err() {
                warn!("audit channel closed; dropping egress report");
            }
        }
        Err(error) => {
            warn!(%error, "skipping malformed egress report");
        }
    }
}

/// Resolves the per-run egress-report socket path from the directory the
/// Sidecar shares with `firma run`. Kept here so the producer and consumer
/// agree on the filename.
#[must_use]
pub fn socket_path_in(dir: &Path) -> PathBuf {
    dir.join("egress-report.sock")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    #[test]
    fn builds_deny_payload_with_loopback_action() {
        let report = BlockedLoopbackReport {
            session_id: "sess-1".to_string(),
            agent_id: "claude-code".to_string(),
            dst_ip: "127.0.0.1".to_string(),
            dst_port: 6379,
        };
        let payload = build_loopback_audit_payload(&report);
        assert_eq!(payload.decision, Decision::Deny);
        assert_eq!(payload.action, "network.loopback");
        assert_eq!(payload.resource, "tcp://127.0.0.1:6379");
        assert_eq!(payload.deny_reason, "loopback blocked");
        assert_eq!(payload.session_id, "sess-1");
        assert_eq!(payload.agent_id, "claude-code");
    }

    #[tokio::test]
    async fn listener_emits_audit_payload_for_reported_block() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = socket_path_in(dir.path());
        let (tx, mut rx) = mpsc::channel(4);
        let exit = CancellationToken::new();
        let handle =
            spawn_listener(socket.clone(), tx, exit.clone()).expect("listener should bind");

        let mut client = UnixStream::connect(&socket).await.expect("connect");
        let report = BlockedLoopbackReport {
            session_id: "s".to_string(),
            agent_id: "a".to_string(),
            dst_ip: "::1".to_string(),
            dst_port: 9000,
        };
        let mut line = serde_json::to_string(&report).expect("serialize");
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

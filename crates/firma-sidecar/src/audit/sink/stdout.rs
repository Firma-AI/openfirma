//! Structured JSON-lines audit sink writing to stdout.
//!
//! Default sink for containerized deployments. Each
//! [`ExecutionEvent`](crate::audit::ExecutionEvent) is serialized as a
//! single JSON line and written to stdout, making it trivial to
//! collect with any log aggregator that reads container stdout
//! (Fluentd, Vector, etc.).
//!
//! Events that fail to serialize are logged as warnings and skipped
//! rather than crashing the sidecar — the enforcement pipeline must
//! never be blocked by an audit formatting error.

use crate::audit::{AuditSink, AuditSinkError, ExecutionEvent};

/// Audit sink that writes JSON-lines to stdout.
#[derive(Debug, Default)]
pub struct StdoutAuditSink;

impl StdoutAuditSink {
    /// Constructs a new [`StdoutAuditSink`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Serialize and print a single event. Serialization failures are
    /// logged and skipped — they must never block the pipeline.
    fn emit(event: &ExecutionEvent) {
        match serde_json::to_string(event) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                tracing::warn!(
                    event_id = %event.event_id,
                    "failed to serialize audit event: {err}"
                );
            }
        }
    }
}

impl AuditSink for StdoutAuditSink {
    async fn run(
        self,
        mut rx: tokio::sync::mpsc::Receiver<ExecutionEvent>,
        exit: tokio_util::sync::CancellationToken,
    ) -> Result<(), AuditSinkError> {
        tracing::debug!("starting StdoutAuditSink");

        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    Self::emit(&event);
                }
                () = exit.cancelled() => {
                    // Drain any remaining buffered events before
                    // shutting down.
                    while let Some(event) = rx.recv().await {
                        Self::emit(&event);
                    }
                    break;
                }
            }
        }
        tracing::debug!("stopping StdoutAuditSink");

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    fn sample_event(id: &str) -> ExecutionEvent {
        ExecutionEvent {
            event_id: id.to_string(),
            session_id: "sess-1".parse().expect("literal session id"),
            token_id: "2acea42e-bb57-44d6-3ad3-aad955ec50af"
                .parse()
                .expect("literal token id"),
            agent_id: "agent-1".parse().expect("literal agent id"),
            action: "http_get".to_string(),
            resource: "https://api.example.com/v1".to_string(),
            decision: 1,
            deny_reason: String::new(),
            enforcement_latency_us: 42,
            context_hash: "abc123".to_string(),
            bundle_version: "v1".to_string(),
            timestamp: Some(1_700_000_000_000_000_000),
            dispatch_status: 0,
            dispatch_latency_us: 0,
            response_size: 0,
            sandbox_id: String::new(),
            signature: vec![0xDE, 0xAD],
        }
    }

    #[tokio::test]
    async fn test_sink_processes_events_and_shuts_down() {
        let (tx, rx) = mpsc::channel(16);
        let exit = CancellationToken::new();

        let sink = StdoutAuditSink::new();
        let exit_clone = exit.clone();
        let handle = tokio::spawn(async move { sink.run(rx, exit_clone).await });

        tx.send(sample_event("evt-1")).await.ok();
        tx.send(sample_event("evt-2")).await.ok();

        // Signal shutdown, then drop the sender so the drain loop
        // terminates.
        exit.cancel();
        drop(tx);

        let result = handle.await;
        assert!(result.is_ok(), "task should not panic");
        assert!(
            result.ok().and_then(std::result::Result::ok).is_some(),
            "sink should return Ok(())"
        );
    }

    #[tokio::test]
    async fn test_sink_returns_ok_when_channel_empty() {
        let (tx, rx) = mpsc::channel::<ExecutionEvent>(1);
        let exit = CancellationToken::new();

        let sink = StdoutAuditSink::new();
        let exit_clone = exit.clone();
        let handle = tokio::spawn(async move { sink.run(rx, exit_clone).await });

        // Drop the sender so recv returns None immediately after
        // cancel.
        drop(tx);
        exit.cancel();

        let result = handle.await;
        assert!(result.is_ok(), "task should not panic");
    }

    #[test]
    fn test_emit_does_not_panic_on_valid_event() {
        // Smoke test: emit should not panic on a well-formed event.
        StdoutAuditSink::emit(&sample_event("evt-smoke"));
    }
}

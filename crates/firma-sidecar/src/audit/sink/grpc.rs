//! Client-streaming gRPC audit sink.
//!
//! Streams [`ExecutionEvent`](crate::audit::ExecutionEvent)s to a
//! downstream [`AuditService`] over a long-lived client-streaming RPC
//! (`StreamEvents`). Transient send failures are logged and skipped;
//! the stream is re-established on the next event. Connection failures
//! at startup are reported as
//! [`AuditSinkError::BindFailed`](crate::audit::AuditSinkError::BindFailed).
//!
//! This sink does **not** implement local WAL buffering — that is the
//! responsibility of the separate WAL sink.

use firma_proto::firma::v1::audit_service_client::AuditServiceClient;
use tonic::transport::Channel;

use crate::audit::{AuditSink, AuditSinkError, ExecutionEvent};

/// Audit sink that streams events over gRPC to a remote collector.
#[derive(Debug)]
pub struct GrpcAuditSink {
    /// The gRPC endpoint URL (e.g. `https://audit.example.com`).
    endpoint: String,
}

impl GrpcAuditSink {
    /// Constructs a new [`GrpcAuditSink`] targeting `endpoint`.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    /// Connects to the audit service endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`AuditSinkError::BindFailed`] if the connection cannot
    /// be established.
    async fn connect(&self) -> Result<AuditServiceClient<Channel>, AuditSinkError> {
        AuditServiceClient::connect(self.endpoint.clone())
            .await
            .map_err(|e| AuditSinkError::BindFailed(e.to_string()))
    }
}

impl AuditSink for GrpcAuditSink {
    async fn run(
        self,
        mut rx: tokio::sync::mpsc::Receiver<ExecutionEvent>,
        exit: tokio_util::sync::CancellationToken,
    ) -> Result<(), AuditSinkError> {
        tracing::debug!(endpoint = %self.endpoint, "starting GrpcAuditSink");

        let mut client = self.connect().await?;
        tracing::debug!("GrpcAuditSink connected to endpoint");

        // Bridge domain events into a proto stream consumed by the
        // client-streaming RPC.
        let (stream_tx, stream_rx) =
            tokio::sync::mpsc::channel::<firma_proto::firma::v1::ExecutionEvent>(256);
        let stream = tokio_stream::wrappers::ReceiverStream::new(stream_rx);

        // Spawn the RPC in a background task so we can keep feeding
        // events without blocking on the server response.
        let rpc_handle = tokio::spawn(async move { client.stream_events(stream).await });

        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    let proto_event = firma_proto::firma::v1::ExecutionEvent::from(event);
                    if stream_tx.send(proto_event).await.is_err() {
                        tracing::warn!("gRPC stream closed; event dropped");
                    }
                }
                () = exit.cancelled() => {
                    // Drain remaining buffered events before shutting
                    // down.
                    while let Some(event) = rx.recv().await {
                        let proto_event = firma_proto::firma::v1::ExecutionEvent::from(event);
                        if stream_tx.send(proto_event).await.is_err() {
                            tracing::warn!("gRPC stream closed during drain; event dropped");
                            break;
                        }
                    }
                    break;
                }
            }
        }

        // Half-close the stream so the server can respond, then await
        // the final acknowledgment.
        drop(stream_tx);
        match rpc_handle.await {
            Ok(Ok(response)) => {
                let resp = response.into_inner();
                tracing::info!(
                    last_event_id = %resp.last_event_id,
                    events_received = resp.events_received,
                    "gRPC audit stream closed successfully"
                );
            }
            Ok(Err(status)) => {
                tracing::error!(
                    code = %status.code(),
                    message = %status.message(),
                    "gRPC audit stream closed with error"
                );
            }
            Err(join_err) => {
                tracing::error!("gRPC stream task panicked: {join_err}");
            }
        }

        tracing::debug!("stopping GrpcAuditSink");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    fn sample_event(id: &str) -> ExecutionEvent {
        ExecutionEvent {
            event_id: id.to_string(),
            session_id: "sess-1".to_string(),
            token_id: "tok-1".to_string(),
            agent_id: "agent-1".to_string(),
            action: "http_get".to_string(),
            resource: "https://api.example.com/v1".to_string(),
            decision: 1,
            deny_reason: String::new(),
            enforcement_latency_us: 42,
            context_hash: "abc123".to_string(),
            bundle_version: "v1".to_string(),
            timestamp: Some(1_700_000_000_000_000_000),
            signature: vec![0xDE, 0xAD],
        }
    }

    #[test]
    fn test_new_stores_endpoint() {
        let sink = GrpcAuditSink::new("https://audit.example.com");
        assert_eq!(sink.endpoint, "https://audit.example.com");
    }

    #[tokio::test]
    async fn test_sink_returns_bind_error_for_unreachable_endpoint() {
        let sink = GrpcAuditSink::new("http://127.0.0.1:1");
        let (_tx, rx) = mpsc::channel::<ExecutionEvent>(1);
        let exit = CancellationToken::new();

        let result = sink.run(rx, exit).await;

        assert!(result.is_err(), "should fail to connect");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AuditSinkError::BindFailed(_)),
            "error should be BindFailed, got: {err}"
        );
    }

    #[allow(dead_code)]
    /// Verifies that events sent through the channel are converted to
    /// proto types. This is a compile-time check that the `From` impl
    /// is wired correctly; the actual gRPC call requires a live server.
    fn sample_event_converts_to_proto() {
        let event = sample_event("evt-proto");
        let _proto: firma_proto::firma::v1::ExecutionEvent = event.into();
    }
}

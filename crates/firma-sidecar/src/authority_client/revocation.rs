//! `WatchRevocations` stream task.

use std::sync::Arc;
use std::time::Duration;

use firma_core::{RevocationStore, TokenId};
use firma_proto::authority_service_client::AuthorityServiceClient;
use firma_proto::{RevocationEvent, WatchRevocationsRequest};
use prost_types::Timestamp;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use crate::authority_client::backoff::ExponentialBackoff;
use crate::authority_client::readiness::ReadinessFlag;

/// Server-streaming task for revocation events.
pub struct RevocationTask {
    /// Shared Authority channel.
    pub channel: Channel,
    /// Store shared with Stage 1.
    pub store: Arc<dyn RevocationStore + Send + Sync>,
    /// Readiness writer.
    pub readiness: Arc<ReadinessFlag>,
    /// Reconnect backoff.
    pub backoff: ExponentialBackoff,
    /// Shutdown token.
    pub cancel: CancellationToken,
    /// Whether disconnects make the revocation cache not-ready.
    pub fail_closed_on_disconnect: bool,
    /// Milliseconds after a successful connect before readiness flips.
    pub readiness_grace_ms: u64,
    /// Last seen revocation timestamp for replay.
    pub last_event_time: Option<Timestamp>,
}

impl RevocationTask {
    /// Run the stream loop until cancelled.
    pub async fn run(mut self) {
        loop {
            let cancel = self.cancel.clone();
            tokio::select! {
                () = cancel.cancelled() => {
                    tracing::info!(stream = "revocations", "authority stream task stopped");
                    return;
                }
                result = self.run_once() => {
                    if let Err(err) = result {
                        tracing::warn!(
                            stream = "revocations",
                            error = %err,
                            "authority stream disconnected"
                        );
                    }
                }
            }

            if self.fail_closed_on_disconnect {
                self.readiness.set_revocation_ready(false);
            }
            let delay = self.backoff.next();
            tracing::warn!(
                stream = "revocations",
                backoff_ms = delay.as_millis(),
                "authority stream reconnect scheduled"
            );
            if wait_or_cancel(delay, &self.cancel).await {
                return;
            }
        }
    }

    async fn run_once(&mut self) -> Result<(), String> {
        let mut client = AuthorityServiceClient::new(self.channel.clone());
        let response = client
            .watch_revocations(WatchRevocationsRequest {
                since: self.last_event_time,
            })
            .await
            .map_err(|err| err.to_string())?;
        self.backoff.reset();
        tracing::info!(stream = "revocations", "authority stream connected");

        let mut stream = response.into_inner();
        let grace = tokio::time::sleep(Duration::from_millis(self.readiness_grace_ms));
        tokio::pin!(grace);
        let mut ready = false;

        loop {
            tokio::select! {
                () = self.cancel.cancelled() => return Ok(()),
                () = &mut grace, if !ready => {
                    self.readiness.set_revocation_ready(true);
                    ready = true;
                }
                message = stream.message() => {
                    let event = message.map_err(|err| err.to_string())?;
                    let Some(event) = event else {
                        return Ok(());
                    };
                    self.apply_event(&event)?;
                    if !ready {
                        self.readiness.set_revocation_ready(true);
                        ready = true;
                    }
                }
            }
        }
    }

    fn apply_event(&mut self, event: &RevocationEvent) -> Result<(), String> {
        let token_id = event
            .token_id
            .parse::<TokenId>()
            .map_err(|e| format!("invalid token id in revocation event: {e}"))?;
        self.store
            .add_revocation(&token_id)
            .map_err(|err| err.to_string())?;
        self.last_event_time = event.timestamp;
        tracing::debug!(
            token_id = %event.token_id,
            reason = %event.reason,
            "revocation event applied"
        );
        Ok(())
    }
}

async fn wait_or_cancel(delay: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        () = cancel.cancelled() => true,
        () = tokio::time::sleep(delay) => false,
    }
}

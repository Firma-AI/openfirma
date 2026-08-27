//! `WatchRevocations` stream task.

use std::sync::Arc;
use std::time::Duration;

use firma_core::RevocationStore;
use firma_identifiers::TokenId;
use firma_protobuf::v1::authority_service_client::AuthorityServiceClient;
use firma_protobuf::v1::{RevocationEvent, WatchRevocationsRequest};
use prost_types::Timestamp;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use crate::authority_client::backoff::ExponentialBackoff;
use crate::authority_client::readiness::ReadinessFlag;
use crate::authority_credentials::ResolvedSidecarCredentials;

/// Server-streaming task for revocation events.
pub(crate) struct RevocationTask {
    /// Shared Authority channel.
    pub(crate) channel: Channel,
    /// Store shared with Stage 1.
    pub(crate) store: Arc<dyn RevocationStore + Send + Sync>,
    /// Readiness writer.
    pub(crate) readiness: Arc<ReadinessFlag>,
    /// Reconnect backoff.
    pub(super) backoff: ExponentialBackoff,
    /// Shutdown token.
    pub(crate) cancel: CancellationToken,
    /// Whether disconnects make the revocation cache not-ready.
    pub(crate) fail_closed_on_disconnect: bool,
    /// Delay after a successful connect before readiness flips.
    pub(crate) readiness_grace: Duration,
    /// Last seen revocation timestamp for replay.
    pub(crate) last_event_time: Option<Timestamp>,
    /// Credentials presented on each stream connection.
    pub(crate) credentials: Option<ResolvedSidecarCredentials>,
}

impl RevocationTask {
    /// Run the stream loop until cancelled.
    pub(crate) async fn run(mut self) {
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
                credentials: self
                    .credentials
                    .as_ref()
                    .map(ResolvedSidecarCredentials::to_proto),
            })
            .await
            .map_err(|err| err.to_string())?;
        self.backoff.reset();
        tracing::info!(stream = "revocations", "authority stream connected");

        let mut stream = response.into_inner();
        let grace = tokio::time::sleep(self.readiness_grace);
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
        let token_id = token_id_from_event(event)?;
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

/// Parse and validate the capability token ID carried by a revocation event.
///
/// # Errors
///
/// Returns an error when the protobuf string is not a canonical `ctok` ID.
pub fn token_id_from_event(event: &RevocationEvent) -> Result<TokenId, String> {
    event
        .token_id
        .parse::<TokenId>()
        .map_err(|e| format!("invalid token id in revocation event: {e}"))
}

async fn wait_or_cancel(delay: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        () = cancel.cancelled() => true,
        () = tokio::time::sleep(delay) => false,
    }
}

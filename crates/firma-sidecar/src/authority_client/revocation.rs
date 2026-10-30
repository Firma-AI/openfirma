//! `WatchRevocations` stream task.

use std::sync::Arc;
use std::time::Duration;

use firma_core::RevocationStore;
use firma_identifiers::TokenId;
use firma_protobuf::v1::authority_service_client::AuthorityServiceClient;
use firma_protobuf::v1::{RevocationEvent, RevocationSet, WatchRevocationsRequest};
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use crate::authority_client::readiness::ReadinessFlag;
use crate::authority_client::{RunRejection, rejects_run};
use crate::authority_credentials::SidecarCredential;
use crate::backoff::ExponentialBackoff;

// Every message carries the workspace's whole revocation set, so its size
// grows with the number of live revocations rather than with what changed.
// Tonic's 4 MiB default would turn crossing that threshold into a permanent
// outage: the oversized message is the *opening* one, so every reconnect
// fails the same way and the store is never populated. 64 MiB is far above
// what either Authority's retention window can hold -- the Team set is
// bounded by token TTL plus `expired_purge_grace` -- while still bounding the
// allocation a Sidecar will attempt.
const MAX_REVOCATION_SET_BYTES: usize = 64 * 1024 * 1024;

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
    /// How long a connection may deliver no set before the Sidecar warns.
    /// Readiness is granted only by an applied set, never by this elapsing.
    pub(crate) readiness_grace: Duration,
    /// Credentials presented on each stream connection.
    pub(crate) credentials: Option<SidecarCredential>,
    /// Whether any connection has ever applied a set to the store, reported
    /// in the missing-set warning.
    pub(crate) applied_a_set: bool,
    /// Ends the run when the Authority rejects it.
    pub(crate) rejection: RunRejection,
}

/// Why a revocation stream connection ended.
#[derive(Debug, thiserror::Error)]
enum StreamError {
    /// The Authority ended the call; its status may reject the run.
    #[error(transparent)]
    Authority(#[from] tonic::Status),
    /// This Sidecar could not apply what the Authority sent.
    #[error("{0}")]
    Local(String),
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
                    if let Err(StreamError::Authority(status)) = &result
                        && rejects_run(status, self.credentials.as_ref())
                    {
                        // The Authority no longer accepts this run, so a
                        // reconnect cannot succeed.
                        tracing::error!(
                            stream = "revocations",
                            error = %status,
                            "authority rejected this run; shutting the sidecar down"
                        );
                        self.rejection.reject();
                        return;
                    }
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

    async fn run_once(&mut self) -> Result<(), StreamError> {
        let mut client = AuthorityServiceClient::new(self.channel.clone())
            .max_decoding_message_size(MAX_REVOCATION_SET_BYTES);
        let message = WatchRevocationsRequest {
            credentials: self
                .credentials
                .as_ref()
                .and_then(SidecarCredential::body_credentials),
        };
        let response = client
            .watch_revocations(SidecarCredential::authenticated(
                self.credentials.as_ref(),
                message,
            ))
            .await?;
        tracing::info!(stream = "revocations", "authority stream connected");

        let mut stream = response.into_inner();
        let grace = tokio::time::sleep(self.readiness_grace);
        tokio::pin!(grace);
        let mut ready = false;

        // The timer stays Ready once elapsed, so its arm is disabled by its
        // own flag rather than by `ready`, which only a delivered set sets.
        let mut grace_elapsed = false;

        loop {
            tokio::select! {
                () = self.cancel.cancelled() => return Ok(()),
                // Readiness means "this Sidecar holds the Authority's set",
                // never "a connection opened": the Authority sends the whole
                // set on connect, so a connection that produces none is one
                // whose sets this Sidecar cannot decode -- a contract
                // mismatch or an oversized message -- which repeats on every
                // reconnect. Going ready on the timer alone would enforce
                // against an empty store indefinitely, so the timer only
                // warns: readiness stays wherever the last applied set, or
                // `fail_closed_on_disconnect`, left it.
                () = &mut grace, if !ready && !grace_elapsed => {
                    grace_elapsed = true;
                    tracing::warn!(
                        stream = "revocations",
                        grace_ms = self.readiness_grace.as_millis(),
                        holds_a_set = self.applied_a_set,
                        "no revocation set received within the readiness grace"
                    );
                }
                message = stream.message() => {
                    let set = message?;
                    let Some(set) = set else {
                        return Ok(());
                    };
                    self.apply_set(&set).map_err(StreamError::Local)?;
                    // Reset the backoff on a decoded set, not on connect: an
                    // oversized opening message would otherwise reset it on
                    // every attempt and reconnect at the floor forever.
                    self.backoff.reset();
                    self.applied_a_set = true;
                    if !ready {
                        self.readiness.set_revocation_ready(true);
                        ready = true;
                    }
                }
            }
        }
    }

    /// Applies a complete revocation set to the store.
    ///
    /// The Authority sends the whole set, which the store is meant to replace
    /// what it holds with. `RevocationStore` can only be added to — the bloom
    /// filter has no removal — so entries the Authority has dropped stay
    /// cached here. Those are exactly the revocations whose capability record
    /// was purged, i.e. tokens already past expiry, which fail validation on
    /// expiry alone: the difference can only reject a token, never admit one.
    /// Replacing the store outright is the Sidecar-side slice of this change.
    fn apply_set(&self, set: &RevocationSet) -> Result<(), String> {
        for event in &set.revocations {
            let token_id = token_id_from_event(event)?;
            self.store
                .add_revocation(&token_id)
                .map_err(|err| err.to_string())?;
        }
        tracing::debug!(
            revocations = set.revocations.len(),
            "revocation set applied"
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

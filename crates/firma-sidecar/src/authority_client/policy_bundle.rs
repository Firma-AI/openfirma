//! `WatchPolicyBundle` stream task.
//!
//! Owns one connection to the Authority, receives bundle pushes, hands
//! them to the shared [`BundleLoader`] for parse + atomic swap, and
//! flips readiness once the first valid bundle lands. Parse failures
//! retain the previous snapshot (Component Reference §12).

use std::sync::Arc;
use std::time::Duration;

use firma_proto::authority_service_client::AuthorityServiceClient;
use firma_proto::{PolicyBundle, WatchPolicyBundleRequest};
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use crate::authority_client::backoff::ExponentialBackoff;
use crate::authority_client::readiness::ReadinessFlag;
use crate::enforcement::policy::{BundleLoader, RawBundle};

/// Server-streaming task for policy bundle updates.
pub struct PolicyBundleTask {
    /// Shared Authority channel.
    pub channel: Channel,
    /// Loader that parses bundles and swaps the evaluator snapshot.
    pub loader: Arc<BundleLoader>,
    /// Readiness writer.
    pub readiness: Arc<ReadinessFlag>,
    /// Reconnect backoff.
    pub backoff: ExponentialBackoff,
    /// Shutdown token.
    pub cancel: CancellationToken,
}

impl PolicyBundleTask {
    /// Run the stream loop until cancelled.
    pub async fn run(mut self) {
        let mut last_version: Option<String> = None;
        loop {
            let cancel = self.cancel.clone();
            tokio::select! {
                () = cancel.cancelled() => {
                    tracing::info!(stream = "policy_bundle", "authority stream task stopped");
                    return;
                }
                result = self.run_once(last_version.as_deref()) => {
                    match result {
                        Ok(Some(version)) => {
                            last_version = Some(version);
                        }
                        Ok(None) => {}
                        Err(err) => {
                            tracing::warn!(
                                stream = "policy_bundle",
                                error = %err,
                                "authority stream disconnected"
                            );
                        }
                    }
                }
            }

            let delay = self.backoff.next();
            tracing::warn!(
                stream = "policy_bundle",
                backoff_ms = delay.as_millis(),
                "authority stream reconnect scheduled"
            );
            if wait_or_cancel(delay, &self.cancel).await {
                return;
            }
        }
    }

    async fn run_once(&mut self, current_version: Option<&str>) -> Result<Option<String>, String> {
        let mut client = AuthorityServiceClient::new(self.channel.clone());
        let response = client
            .watch_policy_bundle(WatchPolicyBundleRequest {
                current_version: current_version.unwrap_or_default().to_string(),
            })
            .await
            .map_err(|err| err.to_string())?;
        self.backoff.reset();
        tracing::info!(stream = "policy_bundle", "authority stream connected");

        let mut stream = response.into_inner();
        let mut last_version = None;
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => return Ok(last_version),
                message = stream.message() => {
                    let update = message.map_err(|err| err.to_string())?;
                    let Some(update) = update else {
                        return Ok(last_version);
                    };
                    if let Some(version) = self.apply_bundle(update.bundle) {
                        last_version = Some(version);
                    }
                }
            }
        }
    }

    fn apply_bundle(&self, bundle: Option<PolicyBundle>) -> Option<String> {
        let Some(bundle) = bundle else {
            tracing::warn!(
                stream = "policy_bundle",
                "policy bundle update missing bundle"
            );
            return None;
        };
        if bundle.ttl_seconds <= 0 {
            tracing::warn!(
                stream = "policy_bundle",
                version = %bundle.version,
                "policy bundle has non-positive ttl"
            );
            return None;
        }
        let policies_cedar = match String::from_utf8(bundle.policies) {
            Ok(text) => text,
            Err(err) => {
                tracing::warn!(
                    stream = "policy_bundle",
                    version = %bundle.version,
                    error = %err,
                    "policy bundle policies are not valid utf-8"
                );
                return None;
            }
        };
        let schema_json = if bundle.entity_schema.is_empty() {
            None
        } else {
            match String::from_utf8(bundle.entity_schema) {
                Ok(text) => Some(text),
                Err(err) => {
                    tracing::warn!(
                        stream = "policy_bundle",
                        version = %bundle.version,
                        error = %err,
                        "policy bundle schema is not valid utf-8"
                    );
                    return None;
                }
            }
        };
        let policies_bytes = policies_cedar.len();
        let raw = RawBundle {
            policies_cedar,
            schema_json,
            // Proto does not yet carry static entities; bundle with the
            // empty store. Authority-pushed entities can be added once
            // PolicyBundle gains the field.
            entities_json: "[]".to_string(),
            version: bundle.version.clone(),
        };
        if let Err(err) = self.loader.apply(raw) {
            tracing::warn!(
                stream = "policy_bundle",
                version = %bundle.version,
                error = %err,
                "policy bundle parse failed"
            );
            return None;
        }
        self.readiness.set_policy_bundle_ready(true);
        tracing::info!(
            version = %bundle.version,
            ttl_seconds = bundle.ttl_seconds,
            policies_bytes,
            "policy bundle swapped"
        );
        Some(bundle.version)
    }
}

async fn wait_or_cancel(delay: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        () = cancel.cancelled() => true,
        () = tokio::time::sleep(delay) => false,
    }
}

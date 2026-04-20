//! `WatchPolicyBundle` stream task.

use std::sync::Arc;
use std::time::Duration;

use firma_proto::authority_service_client::AuthorityServiceClient;
use firma_proto::{PolicyBundle, WatchPolicyBundleRequest};
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use crate::authority_client::backoff::ExponentialBackoff;
use crate::authority_client::readiness::ReadinessFlag;
use crate::authority_client::swappable_policy::SwappablePolicyEvaluation;
use crate::enforcement::constraint_enforcement::PolicyEvaluation;

/// Parses policy bundle bytes into a policy evaluator snapshot.
pub trait BundleParser {
    /// Parse a bundle into an evaluator.
    ///
    /// # Errors
    ///
    /// Returns a message suitable for logs when bundle data is invalid.
    fn parse(
        &self,
        policies: &[u8],
        entity_schema: &[u8],
    ) -> Result<Box<dyn PolicyEvaluation + Send + Sync>, String>;
}

/// Temporary parser until Cedar bundle loading lands.
#[derive(Debug, Default)]
pub struct StubBundleParser;

impl BundleParser for StubBundleParser {
    fn parse(
        &self,
        policies: &[u8],
        _entity_schema: &[u8],
    ) -> Result<Box<dyn PolicyEvaluation + Send + Sync>, String> {
        if policies.is_empty() {
            return Err("policy bundle policies must not be empty".to_string());
        }
        Ok(Box::new(AllowAllPolicyEvaluation))
    }
}

/// Server-streaming task for policy bundle updates.
pub struct PolicyBundleTask {
    /// Shared Authority channel.
    pub channel: Channel,
    /// Swappable evaluator read by Stage 2.
    pub swappable: Arc<SwappablePolicyEvaluation>,
    /// Readiness writer.
    pub readiness: Arc<ReadinessFlag>,
    /// Reconnect backoff.
    pub backoff: ExponentialBackoff,
    /// Shutdown token.
    pub cancel: CancellationToken,
    /// Bundle parser.
    pub bundle_parser: Arc<dyn BundleParser + Send + Sync>,
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
        let ttl_seconds = u32::try_from(bundle.ttl_seconds).unwrap_or(0);
        if ttl_seconds == 0 {
            tracing::warn!(
                stream = "policy_bundle",
                version = %bundle.version,
                "policy bundle has non-positive ttl"
            );
            return None;
        }
        let policies_bytes = bundle.policies.len();
        let evaluator = match self
            .bundle_parser
            .parse(&bundle.policies, &bundle.entity_schema)
        {
            Ok(evaluator) => evaluator,
            Err(err) => {
                tracing::warn!(
                    stream = "policy_bundle",
                    version = %bundle.version,
                    error = %err,
                    "policy bundle parse failed"
                );
                return None;
            }
        };
        let version = bundle.version;
        self.swappable
            .swap(evaluator, ttl_seconds, Some(version.clone()));
        self.readiness.set_policy_bundle_ready(true);
        tracing::info!(
            version,
            ttl_seconds,
            policies_bytes,
            "policy bundle swapped"
        );
        Some(version)
    }
}

async fn wait_or_cancel(delay: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        () = cancel.cancelled() => true,
        () = tokio::time::sleep(delay) => false,
    }
}

#[derive(Debug)]
struct AllowAllPolicyEvaluation;

impl PolicyEvaluation for AllowAllPolicyEvaluation {
    fn evaluate(
        &self,
        _principal: &str,
        _action: &str,
        _resource: &str,
        _context: &serde_json::Value,
    ) -> Result<bool, String> {
        Ok(true)
    }

    fn is_fresh(&self) -> bool {
        true
    }

    fn version(&self) -> Option<String> {
        None
    }
}

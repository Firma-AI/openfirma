//! `WatchPolicyBundle` stream task.

mod mappings;

use std::sync::Arc;
use std::time::Duration;

use firma_core::policy::PolicyBundle as CorePolicyBundle;
use firma_protobuf::v1::authority_service_client::AuthorityServiceClient;
use firma_protobuf::v1::{PolicyBundle, PolicyBundleCapability, WatchPolicyBundleRequest};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use crate::authority_client::enforcement_publisher::{self, EnforcementStateSender};
use crate::authority_client::readiness::ReadinessFlag;
use crate::authority_client::swappable_policy::{RuntimeSnapshot, SwappablePolicyEvaluation};
use crate::authority_credentials::SidecarCredential;
use crate::backoff::ExponentialBackoff;
use crate::enforcement::cedar_evaluator::CedarPolicyEvaluator;
use crate::enforcement::constraint_enforcement::PolicyEvaluation;

// Complete managed updates include expanded rule hosts as well as policy and
// schema. Leave room above Team's 8 MiB stored-mapping budget without allowing
// an unbounded allocation at the transport boundary.
const MAX_MANAGED_UPDATE_BYTES: usize = 16 * 1024 * 1024;

// Bundle versions are Team decimal `u64` (at most 20 bytes) or standalone
// SHA-256 hex (64 bytes); bound diagnostics, stored snapshots, and reconnect
// state well above any legitimate spelling without allowing megabyte-scale
// log or memory amplification through a single version string.
const MAX_VERSION_BYTES: usize = 256;

/// Parses policy bundle bytes into a policy evaluator snapshot.
pub trait BundleParser {
    /// Parse a bundle into an evaluator, seeded with the bundle's TTL
    /// and version so the evaluator can track freshness without a
    /// separate writer.
    ///
    /// # Errors
    ///
    /// Returns a message suitable for logs when bundle data is invalid.
    fn parse(
        &self,
        policies: &[u8],
        entity_schema: &[u8],
        ttl_seconds: u32,
        version: &str,
    ) -> Result<Box<dyn PolicyEvaluation + Send + Sync>, String>;
}

/// Production [`BundleParser`] that builds a [`CedarPolicyEvaluator`]
/// from the bundle bytes pushed by the Authority.
#[derive(Debug, Default)]
pub struct CedarBundleParser;

impl BundleParser for CedarBundleParser {
    fn parse(
        &self,
        policies: &[u8],
        entity_schema: &[u8],
        ttl_seconds: u32,
        version: &str,
    ) -> Result<Box<dyn PolicyEvaluation + Send + Sync>, String> {
        let bundle = CorePolicyBundle::new(
            version.to_string(),
            policies.to_vec(),
            entity_schema.to_vec(),
            ttl_seconds,
        );
        let evaluator =
            CedarPolicyEvaluator::from_bundle(&bundle).map_err(|err| err.to_string())?;
        Ok(Box::new(evaluator))
    }
}

/// Server-streaming task for policy bundle updates.
pub(crate) struct PolicyBundleTask {
    /// Shared Authority channel.
    pub(crate) channel: Channel,
    /// Swappable evaluator read by Stage 2.
    pub(crate) swappable: Arc<SwappablePolicyEvaluation>,
    /// Readiness writer.
    pub(crate) readiness: Arc<ReadinessFlag>,
    /// Wakes the freshness watcher after each publication.
    pub(crate) swapped: Arc<Notify>,
    /// Hands each accepted bundle to the enforcement state writer.
    pub(crate) enforcement_state: Option<EnforcementStateSender>,
    /// Reconnect backoff.
    pub(super) backoff: ExponentialBackoff,
    /// Shutdown token.
    pub(crate) cancel: CancellationToken,
    /// Bundle parser.
    pub(crate) bundle_parser: Arc<dyn BundleParser + Send + Sync>,
    /// Credentials presented on each stream connection.
    pub(crate) credentials: Option<SidecarCredential>,
    pub(crate) composio_coverage_warnings: Vec<String>,
    pub(crate) composio_coverage_active: bool,
}

impl PolicyBundleTask {
    /// Run the stream loop until cancelled.
    pub(crate) async fn run(mut self) {
        loop {
            let cancel = self.cancel.clone();
            tokio::select! {
                () = cancel.cancelled() => {
                    tracing::info!(stream = "policy_bundle", "authority stream task stopped");
                    return;
                }
                result = self.run_once() => {
                    match result {
                        Ok(()) => {}
                        Err(status) if self.run_rejected(&status) => {
                            // The Authority no longer accepts this run, so a
                            // reconnect cannot succeed: stop the Sidecar, which
                            // tells `firma run` to stop the agent.
                            tracing::error!(
                                stream = "policy_bundle",
                                error = %status,
                                "authority rejected this run; shutting the sidecar down"
                            );
                            self.cancel.cancel();
                            return;
                        }
                        Err(status) => {
                            tracing::warn!(
                                stream = "policy_bundle",
                                error = %status,
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

    /// Whether `status` means the Authority rejected this run's runtime
    /// credential. A pre-shared key, or any other code, keeps reconnecting.
    fn run_rejected(&self, status: &tonic::Status) -> bool {
        status.code() == tonic::Code::Unauthenticated
            && matches!(self.credentials, Some(SidecarCredential::Runtime(_)))
    }

    async fn run_once(&mut self) -> Result<(), tonic::Status> {
        let mut client = AuthorityServiceClient::new(self.channel.clone())
            .max_decoding_message_size(MAX_MANAGED_UPDATE_BYTES);
        // The reported version is advisory: every Authority sends a complete
        // initial snapshot. Retained expired content is not reported as held.
        let current_version = {
            let snapshot = self.swappable.load();
            if snapshot.is_fresh() {
                snapshot.version().unwrap_or_default()
            } else {
                String::new()
            }
        };
        let message = WatchPolicyBundleRequest {
            supported_capabilities: vec![PolicyBundleCapability::ActionMappingSnapshotV1 as i32],
            current_version,
            credentials: self
                .credentials
                .as_ref()
                .and_then(SidecarCredential::body_credentials),
        };
        let response = client
            .watch_policy_bundle(SidecarCredential::authenticated(
                self.credentials.as_ref(),
                message,
            ))
            .await?;
        self.backoff.reset();
        tracing::info!(stream = "policy_bundle", "authority stream connected");

        let mut stream = response.into_inner();
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => return Ok(()),
                message = stream.message() => {
                    let update = message?;
                    let Some(update) = update else {
                        return Ok(());
                    };
                    self.apply_bundle(update.bundle);
                }
            }
        }
    }

    fn apply_bundle(&mut self, bundle: Option<PolicyBundle>) {
        let Some(bundle) = bundle else {
            tracing::warn!(
                stream = "policy_bundle",
                "policy bundle update missing bundle"
            );
            return;
        };
        let ttl_seconds = bundle.ttl_seconds;
        let policies_bytes = bundle.policies.len();
        let snapshot = match self.compile_bundle(&bundle) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                tracing::warn!(
                    stream = "policy_bundle",
                    ttl_seconds,
                    // Only a well-formed version is safe to echo into logs.
                    version = is_valid_version(&bundle.version).then_some(bundle.version.as_str()),
                    version_bytes = bundle.version.len(),
                    error = %err,
                    "enforcement snapshot compilation failed"
                );
                return;
            }
        };
        let covers_composio = bundle.mappings.as_ref().is_some_and(|mappings| {
            crate::startup::pipeline::mapping_hosts_reference_composio(
                mappings.rules.iter().map(|rule| rule.host.as_str()),
            )
        });
        if covers_composio && !self.composio_coverage_active {
            for warning in &self.composio_coverage_warnings {
                tracing::warn!("{warning}");
            }
        }
        self.composio_coverage_active = covers_composio;
        let version = bundle.version;
        self.swappable.swap_snapshot(snapshot);
        self.readiness.mark_policy_bundle_swapped();
        self.swapped.notify_one();
        if let Some(sender) = &self.enforcement_state {
            sender.send_replace(Some(enforcement_publisher::swapped_now(
                version.clone(),
                ttl_seconds,
            )));
        }
        tracing::info!(
            version,
            ttl_seconds,
            policies_bytes,
            "enforcement snapshot swapped"
        );
    }

    fn compile_bundle(&self, bundle: &PolicyBundle) -> Result<RuntimeSnapshot, String> {
        // Versions persist as reconnect state: a blank, padded, control, or
        // non-ASCII version would be rejected by the Team Authority on the
        // next handshake, breaking recovery. Standalone hash and Team numeric
        // versions are printable ASCII without whitespace. Versions are Team
        // decimal `u64` (at most 20 bytes) or standalone SHA-256 hex (64
        // bytes); the 256-byte bound leaves headroom for longer hashes while
        // preventing megabyte-scale log or memory amplification through one
        // version string.
        if bundle.ttl_seconds == 0 || !is_valid_version(&bundle.version) {
            return Err(
                "bundle requires a positive TTL and printable-ASCII nonempty version".to_string(),
            );
        }
        let normalizer = self
            .swappable
            .load()
            .normalizer()
            .with_mapping_table(mappings::compile(bundle.mappings.as_ref())?);
        let policy = self.bundle_parser.parse(
            &bundle.policies,
            &bundle.entity_schema,
            bundle.ttl_seconds,
            &bundle.version,
        )?;
        Ok(RuntimeSnapshot::new(
            normalizer,
            policy.into(),
            bundle.ttl_seconds,
            Some(bundle.version.clone()),
        ))
    }
}

fn is_valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_VERSION_BYTES
        && version.bytes().all(|byte| byte.is_ascii_graphic())
}

async fn wait_or_cancel(delay: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        () = cancel.cancelled() => true,
        () = tokio::time::sleep(delay) => false,
    }
}

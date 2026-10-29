//! Authority stream client facade.
//!
//! Spawns the background streams that keep policy bundles and revocations
//! current without putting the Authority on the request hot path.

pub mod channel;
mod enforcement_publisher;
mod freshness;
pub mod policy_bundle;
pub mod readiness;
pub mod revocation;
pub mod swappable_policy;

#[cfg(test)]
mod integration_tests;

use std::sync::Arc;

use firma_core::RevocationStore;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use crate::authority_credentials::SidecarCredential;
use crate::config::AuthorityConfig;

use self::freshness::FreshnessWatcher;
use self::policy_bundle::{BundleParser, PolicyBundleTask};
use self::readiness::ReadinessFlag;
use self::revocation::RevocationTask;
use self::swappable_policy::SwappablePolicyEvaluation;
use crate::backoff::ExponentialBackoff;

/// Dependencies required to spawn Authority stream clients.
pub(crate) struct AuthorityDeps {
    /// Shared tonic channel to the Authority.
    pub(crate) channel: Channel,
    /// Hot-swappable policy evaluator used by Stage 2.
    pub(crate) swappable_policy: Arc<SwappablePolicyEvaluation>,
    /// Revocation store shared with Stage 1.
    pub(crate) revocation_store: Arc<dyn RevocationStore + Send + Sync>,
    /// Readiness writer shared by stream tasks.
    pub(crate) readiness: Arc<ReadinessFlag>,
    /// Cancellation token used for graceful shutdown.
    pub(crate) cancel: CancellationToken,
    /// Authority client tuning.
    pub(crate) config: AuthorityConfig,
    /// Credentials presented on each Authority RPC.
    pub(crate) credentials: Option<SidecarCredential>,
    /// File where each accepted bundle is published for status readers.
    pub(crate) enforcement_state: Option<std::path::PathBuf>,
    /// Policy bundle parser implementation.
    pub(crate) bundle_parser: Arc<dyn BundleParser + Send + Sync>,
    /// Local HTTPS interception gaps reported when accepted rules govern Composio.
    pub(crate) composio_coverage_warnings: Vec<String>,
}

/// Join handles for the spawned stream tasks.
pub struct AuthorityClientHandle {
    /// `WatchPolicyBundle` task.
    pub policy_task: JoinHandle<()>,
    /// `WatchRevocations` task.
    pub revocation_task: JoinHandle<()>,
}

/// Spawn both Authority stream clients.
#[must_use]
pub(crate) fn spawn_authority_client(deps: AuthorityDeps) -> AuthorityClientHandle {
    let min = deps.config.reconnect_min_backoff;
    let max = deps.config.reconnect_max_backoff;

    let swapped = Arc::new(Notify::new());
    let (enforcement_state, publisher) = deps
        .enforcement_state
        .map(|path| enforcement_publisher::writer(path, deps.cancel.clone()))
        .unzip();
    let freshness = FreshnessWatcher {
        swappable: Arc::clone(&deps.swappable_policy),
        readiness: Arc::clone(&deps.readiness),
        swapped: Arc::clone(&swapped),
        cancel: deps.cancel.clone(),
    };
    let policy_task = PolicyBundleTask {
        channel: deps.channel.clone(),
        swappable: deps.swappable_policy,
        readiness: Arc::clone(&deps.readiness),
        swapped,
        enforcement_state,
        backoff: ExponentialBackoff::new(min, max),
        cancel: deps.cancel.clone(),
        bundle_parser: deps.bundle_parser,
        credentials: deps.credentials.clone(),
        composio_coverage_warnings: deps.composio_coverage_warnings,
        composio_coverage_active: false,
    };
    let revocation_task = RevocationTask {
        channel: deps.channel,
        store: deps.revocation_store,
        readiness: deps.readiness,
        backoff: ExponentialBackoff::new(min, max),
        cancel: deps.cancel,
        fail_closed_on_disconnect: deps.config.revocation_fail_closed_on_disconnect,
        readiness_grace: deps.config.revocation_readiness_grace,
        credentials: deps.credentials,
        applied_a_set: false,
    };

    AuthorityClientHandle {
        // The watcher shares the policy task's lifetime so the handle's
        // shape stays the same.
        policy_task: tokio::spawn(async move {
            let publisher = async move {
                if let Some(publisher) = publisher {
                    publisher.await;
                }
            };
            tokio::join!(policy_task.run(), freshness.run(), publisher);
        }),
        revocation_task: tokio::spawn(revocation_task.run()),
    }
}

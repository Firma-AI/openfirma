//! Authority stream client facade.
//!
//! Spawns the background streams that keep policy bundles and revocations
//! current without putting the Authority on the request hot path.

mod backoff;
pub mod channel;
pub mod policy_bundle;
pub mod readiness;
pub mod revocation;
pub mod swappable_policy;

#[cfg(test)]
mod integration_tests;

use std::sync::Arc;
use std::time::Duration;

use firma_core::RevocationStore;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use crate::authority_credentials::ResolvedSidecarCredentials;
use crate::config::AuthorityConfig;

use self::backoff::ExponentialBackoff;
use self::policy_bundle::{BundleParser, PolicyBundleTask};
use self::readiness::ReadinessFlag;
use self::revocation::RevocationTask;
use self::swappable_policy::SwappablePolicyEvaluation;

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
    pub(crate) credentials: Option<ResolvedSidecarCredentials>,
    /// Policy bundle parser implementation.
    pub(crate) bundle_parser: Arc<dyn BundleParser + Send + Sync>,
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
    let min = Duration::from_millis(deps.config.reconnect_min_backoff_ms);
    let max = Duration::from_secs(deps.config.reconnect_max_backoff_secs);

    let policy_task = PolicyBundleTask {
        channel: deps.channel.clone(),
        swappable: deps.swappable_policy,
        readiness: Arc::clone(&deps.readiness),
        backoff: ExponentialBackoff::new(min, max),
        cancel: deps.cancel.clone(),
        bundle_parser: deps.bundle_parser,
        credentials: deps.credentials.clone(),
    };
    let revocation_task = RevocationTask {
        channel: deps.channel,
        store: deps.revocation_store,
        readiness: deps.readiness,
        backoff: ExponentialBackoff::new(min, max),
        cancel: deps.cancel,
        fail_closed_on_disconnect: deps.config.revocation_fail_closed_on_disconnect,
        readiness_grace_ms: deps.config.revocation_readiness_grace_ms,
        last_event_time: None,
        credentials: deps.credentials,
    };

    AuthorityClientHandle {
        policy_task: tokio::spawn(policy_task.run()),
        revocation_task: tokio::spawn(revocation_task.run()),
    }
}

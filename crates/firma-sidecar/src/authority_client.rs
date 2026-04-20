//! Authority stream client facade.
//!
//! Spawns the background streams that keep policy bundles and revocations
//! current without putting the Authority on the request hot path.

pub mod backoff;
pub mod channel;
pub mod policy_bundle;
pub mod readiness;
pub mod revocation;

#[cfg(test)]
mod integration_tests;

use std::sync::Arc;
use std::time::Duration;

use firma_core::RevocationStore;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use crate::config::AuthorityConfig;
use crate::enforcement::policy::BundleLoader;

use self::backoff::ExponentialBackoff;
use self::policy_bundle::PolicyBundleTask;
use self::readiness::ReadinessFlag;
use self::revocation::RevocationTask;

/// Dependencies required to spawn Authority stream clients.
pub struct AuthorityDeps {
    /// Shared tonic channel to the Authority.
    pub channel: Channel,
    /// Bundle loader that parses policy pushes and swaps the Cedar
    /// evaluator snapshot shared with Stage 2.
    pub bundle_loader: Arc<BundleLoader>,
    /// Revocation store shared with Stage 1.
    pub revocation_store: Arc<dyn RevocationStore + Send + Sync>,
    /// Readiness writer shared by stream tasks.
    pub readiness: Arc<ReadinessFlag>,
    /// Cancellation token used for graceful shutdown.
    pub cancel: CancellationToken,
    /// Authority client tuning.
    pub config: AuthorityConfig,
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
pub fn spawn_authority_client(deps: AuthorityDeps) -> AuthorityClientHandle {
    let min = Duration::from_millis(deps.config.reconnect_min_backoff_ms);
    let max = Duration::from_secs(deps.config.reconnect_max_backoff_secs);

    let policy_task = PolicyBundleTask {
        channel: deps.channel.clone(),
        loader: deps.bundle_loader,
        readiness: Arc::clone(&deps.readiness),
        backoff: ExponentialBackoff::new(min, max),
        cancel: deps.cancel.clone(),
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
    };

    AuthorityClientHandle {
        policy_task: tokio::spawn(policy_task.run()),
        revocation_task: tokio::spawn(revocation_task.run()),
    }
}

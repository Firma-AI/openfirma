//! Authority stream client spawn helper.
//!
//! Wires the shared tonic channel and spawns the background
//! `WatchPolicyBundle` / `WatchRevocations` tasks when
//! [`PolicyConfig::authority_url`](crate::config::PolicyConfig::authority_url)
//! is configured. Returns `Ok(None)` when the Authority integration is
//! disabled so the binary still runs in dev mode against local state.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::authority_client::policy_bundle::CedarBundleParser;
use crate::authority_client::{self, AuthorityClientHandle, AuthorityDeps};
use crate::config;
use crate::startup::pipeline::PipelineRuntime;

/// Spawn the Authority stream clients when `policy.authority_url` is
/// set. Uses the shared policy snapshot, revocation store, and
/// readiness flag owned by the [`PipelineRuntime`].
///
/// # Errors
///
/// Returns an error when the configured Authority URL cannot be
/// parsed into a tonic endpoint.
pub fn spawn_authority_client(
    config: &config::SidecarConfig,
    runtime: &PipelineRuntime,
    cancel: CancellationToken,
) -> anyhow::Result<Option<AuthorityClientHandle>> {
    let Some(authority_url) = config.policy.authority_url.as_deref() else {
        tracing::info!("policy.authority_url not set; Authority stream clients disabled");
        return Ok(None);
    };

    let channel = authority_client::channel::build_channel(
        authority_url,
        Duration::from_secs(config.authority.connect_timeout_secs),
    )?;
    tracing::info!("Authority stream clients wired with Cedar bundle parser");

    let handle = authority_client::spawn_authority_client(AuthorityDeps {
        channel,
        swappable_policy: Arc::clone(&runtime.swappable_policy),
        revocation_store: Arc::clone(&runtime.revocation_store),
        readiness: Arc::clone(&runtime.readiness),
        cancel,
        config: config.authority.clone(),
        bundle_parser: Arc::new(CedarBundleParser),
    });
    Ok(Some(handle))
}

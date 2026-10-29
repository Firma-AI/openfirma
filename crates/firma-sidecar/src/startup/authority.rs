//! Authority stream client spawn helper.
//!
//! Wires the shared tonic channel and spawns the background
//! `WatchPolicyBundle` / `WatchRevocations` tasks for the required Authority
//! endpoint. Production readiness depends on both streams hydrating.

use std::path::PathBuf;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::authority_client::policy_bundle::CedarBundleParser;
use crate::authority_client::{self, AuthorityClientHandle, AuthorityDeps};
use crate::authority_tls::AuthorityTls;
use crate::config;
use crate::startup::pipeline::PipelineRuntime;

/// Spawn the required Authority stream clients.
/// Uses the shared policy snapshot, revocation store, and readiness
/// flag owned by the [`PipelineRuntime`].
///
/// # Errors
///
/// Returns an error when the configured Authority URL cannot be
/// parsed into a tonic endpoint, or when a configured CA cert or
/// client cert file cannot be read.
pub fn spawn_authority_client(
    config: &config::SidecarConfig,
    runtime: &PipelineRuntime,
    cancel: CancellationToken,
) -> anyhow::Result<AuthorityClientHandle> {
    let tls = AuthorityTls::read(&config.authority)?;
    spawn_authority_client_publishing(config, &tls, runtime, cancel, None)
}

/// Spawn the Authority stream clients with the TLS material `tls` read from
/// `config`, publishing each accepted bundle's version to `enforcement_state`
/// for status readers.
///
/// # Errors
///
/// Returns an error when the configured Authority URL cannot be parsed into a
/// tonic endpoint or its TLS settings are unusable.
pub fn spawn_authority_client_publishing(
    config: &config::SidecarConfig,
    tls: &AuthorityTls,
    runtime: &PipelineRuntime,
    cancel: CancellationToken,
    enforcement_state: Option<PathBuf>,
) -> anyhow::Result<AuthorityClientHandle> {
    let endpoint = config.authority.target()?;

    let channel = authority_client::channel::build_channel(
        &endpoint,
        config.authority.connect_timeout,
        tls.trust(),
        tls.client_identity(),
    )?;
    let credentials = config
        .authority
        .credentials
        .as_ref()
        .map(crate::authority_credentials::SidecarCredentialsConfig::resolve)
        .transpose()
        .map_err(|error| anyhow::anyhow!("failed to resolve authority credentials: {error}"))?;
    if let Some(ref credentials) = credentials {
        tracing::info!(
            workspace_id = %credentials.workspace_id(),
            sidecar_id = %credentials.sidecar_id(),
            source = credentials.source_kind(),
            "authority credentials configured"
        );
    } else {
        tracing::debug!("authority credentials not configured; Authority RPCs are keyless");
    }
    tracing::debug!("Authority stream clients wired with Cedar bundle parser");

    let handle = authority_client::spawn_authority_client(AuthorityDeps {
        channel,
        swappable_policy: Arc::clone(&runtime.swappable_policy),
        revocation_store: Arc::clone(&runtime.revocation_store),
        readiness: Arc::clone(&runtime.readiness),
        cancel,
        config: config.authority.clone(),
        credentials,
        enforcement_state,
        bundle_parser: Arc::new(CedarBundleParser),
        composio_coverage_warnings: if config.interceptor.mode
            == firma_config_schema::sidecar::InterceptorMode::HttpProxy
        {
            crate::startup::interceptor::composio_mitm_coverage_warnings(
                &config.interceptor.https_mitm,
            )
        } else {
            Vec::new()
        },
    });
    Ok(handle)
}

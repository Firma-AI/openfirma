//! Authority stream client spawn helper.
//!
//! Wires the shared tonic channel and spawns the background
//! `WatchPolicyBundle` / `WatchRevocations` tasks for the required Authority
//! endpoint. Production readiness depends on both streams hydrating.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use tokio_util::sync::CancellationToken;

use crate::authority_client::policy_bundle::CedarBundleParser;
use crate::authority_client::{self, AuthorityClientHandle, AuthorityDeps};
use crate::config;
use crate::startup::pipeline::PipelineRuntime;

/// Spawn the required Authority stream clients.
/// Uses the shared policy snapshot, revocation store, and readiness
/// flag owned by the [`PipelineRuntime`].
///
/// # Errors
///
/// Returns an error when the configured Authority URL cannot be
/// parsed into a tonic endpoint, or when a required CA cert or
/// client cert file cannot be read.
pub fn spawn_authority_client(
    config: &config::SidecarConfig,
    runtime: &PipelineRuntime,
    cancel: CancellationToken,
) -> anyhow::Result<AuthorityClientHandle> {
    spawn_authority_client_publishing(config, runtime, cancel, None)
}

/// Spawn the Authority stream clients, publishing each accepted bundle's
/// version to `enforcement_state` for status readers.
///
/// # Errors
///
/// Same as [`spawn_authority_client`].
pub fn spawn_authority_client_publishing(
    config: &config::SidecarConfig,
    runtime: &PipelineRuntime,
    cancel: CancellationToken,
    enforcement_state: Option<PathBuf>,
) -> anyhow::Result<AuthorityClientHandle> {
    let endpoint = config.authority.target()?;

    let ca_cert_pem: Option<Vec<u8>> = if let Some(ref path) = config.authority.ca_cert_path {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read authority CA cert {}", path.display()))?;
        Some(bytes)
    } else {
        None
    };

    let client_cert_pem: Option<Vec<u8>> =
        if let Some(ref path) = config.authority.tls_client_cert_path {
            let bytes = std::fs::read(path)
                .with_context(|| format!("failed to read mTLS client cert {}", path.display()))?;
            Some(bytes)
        } else {
            None
        };

    let client_key_pem: Option<Vec<u8>> =
        if let Some(ref path) = config.authority.tls_client_key_path {
            let bytes = std::fs::read(path)
                .with_context(|| format!("failed to read mTLS client key {}", path.display()))?;
            Some(bytes)
        } else {
            None
        };

    let channel = authority_client::channel::build_channel(
        &endpoint,
        config.authority.connect_timeout,
        ca_cert_pem.as_deref(),
        client_cert_pem.as_deref(),
        client_key_pem.as_deref(),
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
            workspace_id = %credentials.workspace_id,
            sidecar_id = %credentials.sidecar_id,
            source = credentials.source.kind(),
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

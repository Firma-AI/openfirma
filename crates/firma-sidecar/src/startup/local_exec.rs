//! Startup builder for the local-exec governance endpoint.
//!
//! [`spawn_local_exec_endpoint`] reads [`LocalExecConfig`] from
//! [`SidecarConfig`], builds the handler and endpoint, and spawns them as a
//! background tokio task. Returns `None` when `local_exec` is not configured.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::config::{LocalExecConfig, SidecarConfig};
use crate::local_exec::{LocalExecEndpoint, LocalExecHandler, LocalExecHandlerConfig};

/// Build and spawn the local-exec governance endpoint if configured.
///
/// Returns a [`JoinHandle`](tokio::task::JoinHandle) for the endpoint task,
/// or `None` when `[local_exec]` is absent from the config.
///
/// # Errors
///
/// Returns an error when the socket cannot be bound (bad path, permissions).
pub fn spawn_local_exec_endpoint(
    config: &SidecarConfig,
    cancel: CancellationToken,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    let Some(le_config) = &config.local_exec else {
        return Ok(None);
    };

    let handler = build_handler(le_config);
    let endpoint = LocalExecEndpoint::new(le_config.socket_path.clone(), handler);
    let socket_path = le_config.socket_path.display().to_string();

    tracing::info!(
        socket_path = %socket_path,
        default_action = ?le_config.default_action,
        token_ttl_secs = le_config.token_ttl_secs,
        "spawning local-exec governance endpoint"
    );

    let handle = tokio::spawn(async move {
        if let Err(e) = endpoint.run(cancel).await {
            tracing::error!(error = %e, socket_path = %socket_path, "local-exec endpoint failed");
        }
    });

    Ok(Some(handle))
}

fn build_handler(config: &LocalExecConfig) -> LocalExecHandler {
    LocalExecHandler::new(LocalExecHandlerConfig {
        default_action: config.default_action,
        token_ttl: Duration::from_secs(config.token_ttl_secs),
        retry_after_ms: config.retry_after_ms,
    })
}

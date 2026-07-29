//! Startup builder for the local-exec governance endpoint.
//!
//! [`spawn_local_exec_endpoint`] reads [`LocalExecConfig`] from
//! [`SidecarConfig`], builds the handler and endpoint, and spawns them as a
//! background tokio task. Returns `None` when `local_exec` is not configured.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use firma_runtime_state::SandboxId;

use crate::config::{LocalExecConfig, SidecarConfig};
use crate::local_exec::handler::DefaultAction;
use crate::local_exec::{
    LocalExecEndpoint, LocalExecHandler, LocalExecHandlerConfig, RedactedManagementToken,
};

/// Build and spawn the local-exec governance endpoint if configured.
///
/// Returns a [`JoinHandle`](tokio::task::JoinHandle) for the endpoint task,
/// or `None` when `[local_exec]` is absent from the config.
///
/// # Errors
///
/// Returns an error when the socket cannot be bound (bad path, permissions),
/// or when the configured management token source cannot be read.
pub fn spawn_local_exec_endpoint(
    config: &SidecarConfig,
    sandbox_id: Option<SandboxId>,
    cancel: CancellationToken,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    let Some(le_config) = &config.local_exec else {
        return Ok(None);
    };

    let management_token = resolve_management_token(le_config)?;
    let management_auth = management_token.is_some();
    if management_token.is_none() {
        // Management commands are always rejected without a token. This only
        // matters operationally for the pending_hitl flow, so warn loudly there
        // and debug otherwise to avoid noise for plain allow/deny policies.
        if le_config.default_action == DefaultAction::PendingHitl {
            tracing::warn!(
                socket_path = %le_config.socket_path.display(),
                "local-exec management commands are DISABLED: no management_token_env or \
                 management_token_path configured. pending_hitl approvals cannot be issued \
                 until a management token is set; any management command will be rejected."
            );
        } else {
            tracing::debug!(
                socket_path = %le_config.socket_path.display(),
                "local-exec management token not configured; management commands disabled"
            );
        }
    }

    let handler = build_handler(le_config, sandbox_id, management_token);
    let endpoint = LocalExecEndpoint::new(le_config.socket_path.clone(), handler);
    let socket_path = le_config.socket_path.display().to_string();

    tracing::info!(
        socket_path = %socket_path,
        default_action = ?le_config.default_action,
        token_ttl_secs = le_config.token_ttl_secs,
        management_auth,
        "spawning local-exec governance endpoint"
    );

    let handle = tokio::spawn(async move {
        if let Err(e) = endpoint.run(cancel).await {
            tracing::error!(error = %e, socket_path = %socket_path, "local-exec endpoint failed");
        }
    });

    Ok(Some(handle))
}

fn build_handler(
    config: &LocalExecConfig,
    sandbox_id: Option<SandboxId>,
    management_token: Option<RedactedManagementToken>,
) -> LocalExecHandler {
    LocalExecHandler::new(LocalExecHandlerConfig {
        default_action: config.default_action,
        expected_sandbox_id: sandbox_id,
        token_ttl: Duration::from_secs(config.token_ttl_secs),
        retry_after_ms: config.retry_after_ms,
        management_token,
    })
}

/// Resolve the operator management token from the configured source.
///
/// `None` (management disabled) is returned only when neither
/// `management_token_env` nor `management_token_path` is configured; that state
/// is logged as a warning by the caller. A configured-but-unreadable source is
/// a hard startup error so operators never silently run with a missing token.
fn resolve_management_token(
    config: &LocalExecConfig,
) -> anyhow::Result<Option<RedactedManagementToken>> {
    if let Some(env_name) = config
        .management_token_env
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        let value = std::env::var(env_name)
            .map_err(|_| anyhow::anyhow!("management_token_env {env_name} is not set"))?;
        let token = trim_trailing_newlines(value);
        if token.is_empty() {
            return Err(anyhow::anyhow!(
                "management_token_env {env_name} is empty"
            ));
        }
        return Ok(Some(RedactedManagementToken::new(token)));
    }

    if let Some(path) = config.management_token_path.as_deref()
        && !path.as_os_str().is_empty()
    {
        let value = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read management_token_path {}: {e}", path.display()))?;
        let token = trim_trailing_newlines(value);
        if token.is_empty() {
            return Err(anyhow::anyhow!(
                "management_token_path {} is empty",
                path.display()
            ));
        }
        return Ok(Some(RedactedManagementToken::new(token)));
    }

    Ok(None)
}

fn trim_trailing_newlines(mut value: String) -> String {
    while value.ends_with('\n') || value.ends_with('\r') {
        value.pop();
    }
    value
}
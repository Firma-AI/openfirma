//! Shared SIGINT/SIGTERM handling for `firma` async services.

use tokio_util::sync::CancellationToken;

/// Wait for SIGINT (or SIGTERM on Unix), then cancel `token`.
pub async fn wait_for_shutdown(token: CancellationToken) {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    res = tokio::signal::ctrl_c() => {
                        if let Err(e) = res {
                            tracing::error!(%e, "failed to listen for SIGINT");
                        } else {
                            tracing::info!("received SIGINT, shutting down");
                        }
                    }
                    _ = sigterm.recv() => {
                        tracing::info!("received SIGTERM, shutting down");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(%e, "failed to register SIGTERM handler; falling back to SIGINT only");
                if let Err(e) = tokio::signal::ctrl_c().await {
                    tracing::error!(%e, "failed to listen for SIGINT");
                } else {
                    tracing::info!("received SIGINT, shutting down");
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(%e, "failed to listen for SIGINT");
        } else {
            tracing::info!("received SIGINT, shutting down");
        }
    }
    token.cancel();
}

/// Future-based variant: resolves the first time SIGINT/SIGTERM arrives.
/// Used by the authority server which expects a `Future<Output=()>`.
pub async fn shutdown_future() {
    let token = CancellationToken::new();
    wait_for_shutdown(token).await;
}

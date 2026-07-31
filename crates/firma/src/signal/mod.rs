//! Shared SIGINT/SIGTERM handling for `firma` async services.

#[cfg(windows)]
mod windows;

use tokio_util::sync::CancellationToken;

/// Wait for SIGINT (or SIGTERM on Unix), then cancel `token`.
pub async fn wait_for_shutdown(token: CancellationToken) {
    #[cfg(windows)]
    self::windows::install_listener(token.clone());

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
    #[cfg(windows)]
    {
        // Two shutdown sources race here: tokio's ctrl_c (terminal Ctrl-C)
        // and the named-event listener installed above (`firma stack stop`).
        // Whichever fires first cancels `token`; the other becomes a no-op.
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                if let Err(e) = res {
                    tracing::error!(%e, "failed to listen for Ctrl-C");
                } else {
                    tracing::info!("received Ctrl-C, shutting down");
                }
            }
            () = token.cancelled() => {}
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

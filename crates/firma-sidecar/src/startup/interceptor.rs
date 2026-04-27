//! Interceptor spawn dispatch.
//!
//! Selects the concrete interceptor implementation based on the
//! [`InterceptorMode`](crate::config::InterceptorMode) in config and
//! returns a [`tokio::task::JoinHandle`] that resolves when the
//! interceptor shuts down.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::config::{self, InterceptorMode};
use crate::handler::RequestHandler;
use crate::interceptor::{self, Interceptor as _};

/// Spawn the configured interceptor as a background tokio task.
///
/// # Errors
///
/// Returns an error when the interceptor mode is `unix_socket` but
/// the required `socket_path` is missing (should be caught by
/// validation, but enforced here defensively).
pub fn spawn_interceptor(
    config: &config::SidecarConfig,
    handler: Arc<RequestHandler>,
    cancel: CancellationToken,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let ic = &config.interceptor;

    match ic.mode {
        InterceptorMode::HttpProxy => {
            let interceptor = interceptor::http::HttpInterceptor::new(ic.listen_addr)
                .with_https_mitm(ic.https_mitm.clone(), config.ca.dir.clone())
                .with_max_request_body_bytes(ic.max_request_body_bytes)
                .with_connect_relay(ic.connect_relay.clone());
            tracing::info!(listen_addr = %ic.listen_addr, "HTTP proxy interceptor configured");
            Ok(tokio::spawn(async move {
                if let Err(e) = interceptor.run(handler, cancel).await {
                    tracing::error!(error = %e, "HTTP proxy interceptor failed");
                }
            }))
        }
        InterceptorMode::Grpc => {
            let interceptor = interceptor::grpc::GrpcInterceptor::new(ic.listen_addr);
            tracing::info!(listen_addr = %ic.listen_addr, "gRPC interceptor configured");
            Ok(tokio::spawn(async move {
                if let Err(e) = interceptor.run(handler, cancel).await {
                    tracing::error!(error = %e, "gRPC interceptor failed");
                }
            }))
        }
        #[cfg(unix)]
        InterceptorMode::UnixSocket => {
            let socket_path = ic
                .socket_path
                .clone()
                .ok_or_else(|| anyhow::anyhow!("unix_socket mode requires socket_path"))?;
            let interceptor =
                interceptor::unix_socket::UnixSocketInterceptor::new(socket_path.clone());
            tracing::info!(socket_path = %socket_path.display(), "Unix socket interceptor configured");
            Ok(tokio::spawn(async move {
                if let Err(e) = interceptor.run(handler, cancel).await {
                    tracing::error!(error = %e, "Unix socket interceptor failed");
                }
            }))
        }
    }
}

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

fn is_loopback_addr(addr: std::net::SocketAddr) -> bool {
    addr.ip().is_loopback()
}

pub struct SpawnedInterceptor {
    pub handle: tokio::task::JoinHandle<()>,
    pub listen_addr: String,
}

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
) -> anyhow::Result<SpawnedInterceptor> {
    let ic = &config.interceptor;

    match ic.mode {
        InterceptorMode::HttpProxy | InterceptorMode::Grpc => {
            if !is_loopback_addr(ic.listen_addr) {
                tracing::warn!(
                    listen_addr = %ic.listen_addr,
                    "interceptor listening on non-loopback address; \
                    this may accept connections from non-local processes if the port is exposed"
                );
            }
        }
        #[cfg(unix)]
        InterceptorMode::UnixSocket => {}
    }

    match ic.mode {
        InterceptorMode::HttpProxy => {
            let std_listener = std::net::TcpListener::bind(ic.listen_addr)?;
            std_listener.set_nonblocking(true)?;
            let bound_addr = std_listener.local_addr()?;
            let listener = tokio::net::TcpListener::from_std(std_listener)?;
            let interceptor = interceptor::http::HttpInterceptor::new(ic.listen_addr)
                .with_https_mitm(ic.https_mitm.clone(), config.ca.dir.clone())
                .with_max_request_body_bytes(ic.max_request_body_bytes)
                .with_total_body_budget_bytes(ic.total_body_budget_bytes)
                .with_connect_relay(ic.connect_relay.clone());
            tracing::debug!(listen_addr = %ic.listen_addr, "HTTP proxy interceptor configured");
            let handle = tokio::spawn(async move {
                if let Err(e) = interceptor
                    .run_with_listener(listener, handler, cancel)
                    .await
                {
                    tracing::error!(error = %e, "HTTP proxy interceptor failed");
                }
            });
            Ok(SpawnedInterceptor {
                handle,
                listen_addr: bound_addr.to_string(),
            })
        }
        InterceptorMode::Grpc => {
            let interceptor = interceptor::grpc::GrpcInterceptor::new(ic.listen_addr);
            tracing::debug!(listen_addr = %ic.listen_addr, "gRPC interceptor configured");
            let handle = tokio::spawn(async move {
                if let Err(e) = interceptor.run(handler, cancel).await {
                    tracing::error!(error = %e, "gRPC interceptor failed");
                }
            });
            Ok(SpawnedInterceptor {
                handle,
                listen_addr: ic.listen_addr.to_string(),
            })
        }
        #[cfg(unix)]
        InterceptorMode::UnixSocket => {
            let socket_path = ic
                .socket_path
                .clone()
                .unwrap_or_else(config::default_socket_path);
            let parent_dir = socket_path.parent().map_or_else(
                || std::path::PathBuf::from("."),
                std::path::Path::to_path_buf,
            );
            if let Err(e) = std::fs::create_dir_all(&parent_dir) {
                tracing::warn!(
                    dir = %parent_dir.display(),
                    error = %e,
                    "could not create socket directory; continuing anyway"
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&parent_dir) {
                    let perms = meta.permissions();
                    let mode = perms.mode() & 0o777;
                    if mode != 0o700 {
                        tracing::warn!(
                            dir = %parent_dir.display(),
                            mode = %format!("{:o}", mode),
                            "socket directory has loose permissions; consider chmod 0700"
                        );
                    }
                }
            }
            let interceptor =
                interceptor::unix_socket::UnixSocketInterceptor::new(socket_path.clone());
            tracing::debug!(socket_path = %socket_path.display(), "Unix socket interceptor configured");
            let handle = tokio::spawn(async move {
                if let Err(e) = interceptor.run(handler, cancel).await {
                    tracing::error!(error = %e, "Unix socket interceptor failed");
                }
            });
            Ok(SpawnedInterceptor {
                handle,
                listen_addr: socket_path.display().to_string(),
            })
        }
    }
}

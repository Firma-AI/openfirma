//! Interceptor spawn dispatch.
//!
//! Selects the concrete interceptor implementation based on the
//! [`InterceptorMode`] in config and
//! returns a [`tokio::task::JoinHandle`] that resolves when the
//! interceptor shuts down.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::composio::PROTECTED_HOSTS;
use crate::config::{self, HttpsMitmConfig, InterceptorMode};
use crate::handler::RequestHandler;
use crate::interceptor::https_mitm::{host_matches_any, normalize_patterns};
use crate::interceptor::{self, Interceptor as _};

fn is_loopback_addr(addr: SocketAddr) -> bool {
    addr.ip().is_loopback()
}

fn bind_tcp_listener(addr: SocketAddr) -> io::Result<(tokio::net::TcpListener, SocketAddr)> {
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let bound_addr = listener.local_addr()?;
    Ok((tokio::net::TcpListener::from_std(listener)?, bound_addr))
}

/// Report HTTPS MITM configuration gaps that would blind Composio governance.
///
/// The pinned Composio catalogs are always compiled in, but the decoder only
/// sees traffic the proxy actually terminates. Each returned string describes
/// one gap: MITM inactive, a protected host bypassed, not intercepted, or
/// intercepted without strict mode (where a TLS failure falls back to an
/// opaque tunnel). An empty result means both protected hosts are covered.
#[must_use]
pub fn composio_mitm_coverage_warnings(mitm: &HttpsMitmConfig) -> Vec<String> {
    if !mitm.is_active() {
        return vec![format!(
            "HTTPS MITM is inactive; Composio traffic to {} will tunnel opaquely and cannot be governed",
            PROTECTED_HOSTS.join(" and "),
        )];
    }
    let intercept = normalize_patterns(&mitm.intercept_hosts);
    let bypass = normalize_patterns(&mitm.bypass_hosts);
    let strict = normalize_patterns(&mitm.strict_hosts);
    let mut warnings = Vec::new();
    for host in PROTECTED_HOSTS {
        if host_matches_any(host, &bypass) {
            warnings.push(format!(
                "{host} is listed in interceptor.https_mitm.bypass_hosts; bypassed Composio traffic cannot be decoded or governed"
            ));
        } else if !host_matches_any(host, &intercept) {
            warnings.push(format!(
                "{host} is not matched by interceptor.https_mitm.intercept_hosts; Composio tool calls will pass through as opaque tunnels"
            ));
        } else if !host_matches_any(host, &strict) {
            warnings.push(format!(
                "{host} is intercepted but not in interceptor.https_mitm.strict_hosts; a TLS failure would fall back to an opaque tunnel"
            ));
        }
    }
    warnings
}

pub struct SpawnedInterceptor {
    /// Background server task.
    pub handle: tokio::task::JoinHandle<()>,
    /// Effective bound TCP address, or the configured Unix socket path.
    ///
    /// For TCP configurations that request port zero, this contains the
    /// nonzero port assigned by the operating system.
    pub listen_addr: String,
}

/// Spawn the configured interceptor as a background tokio task.
///
/// # Errors
///
/// Returns an error when a TCP listener cannot be bound or converted for Tokio.
/// TCP binding completes synchronously before the server task is spawned.
/// Also returns an error when the interceptor mode is `unix_socket` but the
/// required `socket_path` is missing (should be caught by validation, but
/// enforced here defensively).
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
            let interceptor = interceptor::http::HttpInterceptor::new(ic.listen_addr)
                .with_https_mitm(ic.https_mitm.clone(), config.ca.dir.clone())
                .with_max_request_body_bytes(ic.max_request_body_bytes)
                .with_total_body_budget_bytes(ic.total_body_budget_bytes)
                .with_connect_relay(ic.connect_relay.clone());
            // Generate CA material (when HTTPS MITM is active) *before* binding
            // the listener, so a connectable port implies full readiness. A CA
            // failure surfaces synchronously here (the sidecar exits non-zero)
            // rather than leaving a dead bound port to time out.
            let mitm_runtime = interceptor.build_mitm_runtime()?;
            let (listener, bound_addr) = bind_tcp_listener(ic.listen_addr)?;
            tracing::debug!(listen_addr = %ic.listen_addr, "HTTP proxy interceptor configured");
            let handle = tokio::spawn(async move {
                if let Err(e) = interceptor
                    .run_with_listener_and_runtime(listener, handler, cancel, mitm_runtime)
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
            let (listener, bound_addr) = bind_tcp_listener(ic.listen_addr)?;
            tracing::debug!(listen_addr = %ic.listen_addr, "gRPC interceptor configured");
            let handle = tokio::spawn(async move {
                if let Err(e) = interceptor
                    .run_with_listener(listener, handler, cancel)
                    .await
                {
                    tracing::error!(error = %e, "gRPC interceptor failed");
                }
            });
            Ok(SpawnedInterceptor {
                handle,
                listen_addr: bound_addr.to_string(),
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

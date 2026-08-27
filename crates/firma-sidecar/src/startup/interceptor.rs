//! Interceptor spawn dispatch.
//!
//! Selects the concrete interceptor implementation based on the
//! [`InterceptorMode`] in config and
//! returns a [`tokio::task::JoinHandle`] that resolves when the
//! interceptor shuts down.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

#[cfg(unix)]
use std::{
    fs,
    path::{Path, PathBuf},
};

use firma_runtime_state::RuntimeLayout;
use tokio_util::sync::CancellationToken;

use crate::composio::PROTECTED_HOSTS;
use firma_config_schema::sidecar::InterceptorMode;

use crate::config::{self, HttpsMitmConfig};
use crate::handler::RequestHandler;
use crate::interceptor;
use crate::interceptor::https_mitm::{host_matches_any, normalize_patterns};

fn is_loopback_addr(addr: SocketAddr) -> bool {
    addr.ip().is_loopback()
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
                "{host} is listed in sidecar.interceptor.https_mitm.bypass_hosts; bypassed Composio traffic cannot be decoded or governed"
            ));
        } else if !host_matches_any(host, &intercept) {
            warnings.push(format!(
                "{host} is not matched by sidecar.interceptor.https_mitm.intercept_hosts; Composio tool calls will pass through as opaque tunnels"
            ));
        } else if !host_matches_any(host, &strict) {
            warnings.push(format!(
                "{host} is intercepted but not in sidecar.interceptor.https_mitm.strict_hosts; a TLS failure would fall back to an opaque tunnel"
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

fn spawn_grpc_interceptor(
    addr: SocketAddr,
    handler: Arc<RequestHandler>,
    cancel: CancellationToken,
) -> anyhow::Result<SpawnedInterceptor> {
    let interceptor = interceptor::grpc::GrpcInterceptor::new(addr);
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let bound_addr = listener.local_addr()?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    tracing::debug!(listen_addr = %addr, "gRPC interceptor configured");
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

/// Spawn the configured interceptor as a background tokio task.
///
/// # Errors
///
/// Returns an error when a TCP listener cannot be bound or converted for Tokio.
/// TCP binding completes synchronously before the server task is spawned.
/// Unix-socket mode derives its path from `runtime_layout` when the
/// configuration does not provide an explicit override.
pub fn spawn_interceptor(
    #[cfg_attr(
        windows,
        expect(
            unused_variables,
            reason = "the runtime layout supplies only the Unix socket default"
        )
    )]
    runtime_layout: &RuntimeLayout,
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
            let std_listener = TcpListener::bind(ic.listen_addr)?;
            std_listener.set_nonblocking(true)?;
            let bound_addr = std_listener.local_addr()?;
            let listener = tokio::net::TcpListener::from_std(std_listener)?;
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
        InterceptorMode::Grpc => spawn_grpc_interceptor(ic.listen_addr, handler, cancel),
        #[cfg(unix)]
        InterceptorMode::UnixSocket => {
            let socket_path = ic
                .socket_path
                .clone()
                .unwrap_or_else(|| runtime_layout.sidecar_socket());
            let parent_dir = socket_path
                .parent()
                .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
            if let Err(e) = fs::create_dir_all(&parent_dir) {
                tracing::warn!(
                    dir = %parent_dir.display(),
                    error = %e,
                    "could not create socket directory; continuing anyway"
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(&parent_dir) {
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
            let listener = interceptor.bind()?;
            tracing::debug!(socket_path = %socket_path.display(), "Unix socket interceptor configured");
            let handle = tokio::spawn(async move {
                if let Err(e) = interceptor
                    .run_with_listener(listener, handler, cancel)
                    .await
                {
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

//! TCP and Unix-domain-socket reachability probes for `firma doctor`.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr as _;
use std::time::Duration;

use firma_authority::config::AuthorityConfig;
use firma_sidecar::config::{InterceptorMode, SidecarConfig};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::time::timeout as tokio_timeout;

use crate::doctor::report::{Check, Status};

/// Try to TCP-connect to `addr`. Returns `Ok(())` on success or `Err(reason)`
/// on any error (including timeout).
pub async fn probe_tcp(addr: SocketAddr, deadline: Duration) -> Result<(), String> {
    match tokio_timeout(deadline, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => Ok(()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(format!("timed out after {deadline:?}")),
    }
}

/// Try to UDS-connect to `path`. Returns `Err` on non-Unix platforms.
#[cfg(unix)]
pub async fn probe_uds(path: &std::path::Path, deadline: Duration) -> Result<(), String> {
    match tokio_timeout(deadline, UnixStream::connect(path)).await {
        Ok(Ok(_stream)) => Ok(()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(format!("timed out after {deadline:?}")),
    }
}

/// Resolved endpoint pulled from sidecar / authority TOML.
#[derive(Debug, Clone)]
pub enum Endpoint {
    /// `host:port`.
    Tcp(SocketAddr),
    /// Filesystem path to a Unix socket.
    #[cfg(unix)]
    Uds(std::path::PathBuf),
}

/// Extract a probable [`Endpoint`] from a sidecar config's interceptor section.
///
/// - `http_proxy` / `grpc` modes → [`Endpoint::Tcp`] from `listen_addr`.
/// - `unix_socket` mode → [`Endpoint::Uds`] from `socket_path`, or an empty
///   path when `socket_path` is `None`.
#[must_use]
pub fn endpoint_from_sidecar(cfg: &SidecarConfig) -> Endpoint {
    match cfg.interceptor.mode {
        #[cfg(unix)]
        InterceptorMode::UnixSocket => Endpoint::Uds(
            cfg.interceptor
                .socket_path
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("")),
        ),
        InterceptorMode::HttpProxy | InterceptorMode::Grpc => {
            Endpoint::Tcp(cfg.interceptor.listen_addr)
        }
    }
}

/// Extract a probe-ready [`Endpoint`] from an authority config.
///
/// `listen_addr` is a free-form string; if it parses as [`SocketAddr`] we
/// rewrite any wildcard host (`0.0.0.0`, `::`) to the loopback equivalent
/// for the probe (connecting to a wildcard address fails on macOS).
#[must_use]
pub fn endpoint_from_authority(cfg: &AuthorityConfig) -> Option<Endpoint> {
    let parsed = SocketAddr::from_str(&cfg.listen_addr).ok()?;
    Some(Endpoint::Tcp(rewrite_wildcard(parsed)))
}

/// Rewrite a wildcard bind address to the loopback equivalent.
///
/// `0.0.0.0:N` → `127.0.0.1:N`; `[::]:N` → `[::1]:N`; all others unchanged.
fn rewrite_wildcard(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
            SocketAddr::from((Ipv4Addr::LOCALHOST, v4.port()))
        }
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
            SocketAddr::from((Ipv6Addr::LOCALHOST, v6.port()))
        }
        other => other,
    }
}

/// Run a reachability check against a resolved endpoint.
///
/// Returns [`Status::Warn`] when `endpoint` is `None` (not configured),
/// [`Status::Ok`] on a successful connection, and [`Status::Fail`] on any
/// connection error or timeout.
pub async fn check_endpoint(
    label: &'static str,
    endpoint: Option<Endpoint>,
    deadline: Duration,
) -> Check {
    let Some(endpoint) = endpoint else {
        return Check::warn(label, "not configured");
    };
    match endpoint {
        Endpoint::Tcp(addr) => match probe_tcp(addr, deadline).await {
            Ok(()) => Check::ok(label, addr.to_string()).with_detail("address", addr.to_string()),
            Err(reason) => Check::fail(label, format!("{addr}: {reason}"))
                .with_detail("address", addr.to_string()),
        },
        #[cfg(unix)]
        Endpoint::Uds(ref path) if path.as_os_str().is_empty() => {
            Check::warn(label, "unix_socket configured with empty path")
        }
        #[cfg(unix)]
        Endpoint::Uds(path) => {
            let display = path.display().to_string();
            match probe_uds(&path, deadline).await {
                Ok(()) => Check::ok(label, display.clone()).with_detail("path", display),
                Err(reason) => {
                    Check::fail(label, format!("{display}: {reason}")).with_detail("path", display)
                }
            }
        }
    }
}

/// Reconcile a configured-daemon reachability [`Check`] against the number of
/// live per-run instances discovered from runtime markers.
///
/// `firma doctor` originally probed only the configured/daemon endpoint, so a
/// pure `firma run` workflow (no long-lived daemon, ephemeral per-run
/// sidecar/authority) produced an alarming `[FAIL]` even while an agent was
/// actively running. This reconciliation:
///
/// - reports `OK` reflecting live per-run instances when any are running (AC1);
/// - downgrades an unreachable/unconfigured daemon to an informational `Check`
///   when no daemon is expected — never a hard `[FAIL]` (AC3);
/// - preserves a successful daemon probe untouched.
#[must_use]
pub fn reconcile_reachability(daemon: Check, live_running: usize) -> Check {
    let label = daemon.category;
    if live_running > 0 {
        let plural = if live_running == 1 { "" } else { "s" };
        return Check::ok(
            label,
            format!("{live_running} live per-run instance{plural} (firma run)"),
        )
        .with_detail("live_instances", live_running.to_string());
    }
    match daemon.status {
        Status::Ok => daemon,
        _ => Check::warn(
            label,
            "no long-lived daemon reachable (normal if you only use firma run)",
        )
        .with_detail("daemon", daemon.reason),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::io::ErrorKind;
    use std::net::{Ipv4Addr, TcpListener};

    use crate::doctor::report::Status;

    use super::*;

    fn try_bind_tcp_local() -> Option<TcpListener> {
        match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) {
            Ok(listener) => Some(listener),
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping bind-dependent test: {err}");
                None
            }
            Err(err) => panic!("bind: {err}"),
        }
    }

    #[tokio::test]
    async fn tcp_probe_succeeds_against_listening_port() {
        let Some(listener) = try_bind_tcp_local() else {
            return;
        };
        let addr = listener.local_addr().expect("local_addr");
        let result = probe_tcp(addr, Duration::from_millis(500)).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[tokio::test]
    async fn tcp_probe_fails_against_closed_port() {
        // Bind a listener to take a port, then drop it before connecting.
        let port = {
            let Some(listener) = try_bind_tcp_local() else {
                return;
            };
            listener.local_addr().expect("local_addr").port()
        };
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let result = probe_tcp(addr, Duration::from_millis(500)).await;
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn uds_probe_succeeds_against_listening_socket() {
        use tokio::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        let sock = tmp.path().join("d.sock");
        let listener = match UnixListener::bind(&sock) {
            Ok(listener) => listener,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping bind-dependent test: {err}");
                return;
            }
            Err(err) => panic!("bind: {err}"),
        };
        let result = probe_uds(&sock, Duration::from_millis(500)).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        drop(listener);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn uds_probe_fails_against_missing_socket() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sock = tmp.path().join("missing.sock");
        let result = probe_uds(&sock, Duration::from_millis(500)).await;
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // -- check_endpoint -------------------------------------------------------

    #[tokio::test]
    async fn sidecar_endpoint_warn_when_none() {
        let check = check_endpoint("sidecar reachable", None, Duration::from_millis(200)).await;
        assert_eq!(check.status, Status::Warn);
        assert!(check.reason.contains("not configured"));
    }

    #[tokio::test]
    async fn sidecar_endpoint_ok_when_tcp_reachable() {
        let Some(listener) = try_bind_tcp_local() else {
            return;
        };
        let addr = listener.local_addr().expect("local_addr");
        let endpoint = Endpoint::Tcp(addr);
        let check = check_endpoint(
            "sidecar reachable",
            Some(endpoint),
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(check.status, Status::Ok);
        assert_eq!(
            check.detail.get("address").map(String::as_str),
            Some(addr.to_string().as_str())
        );
    }

    #[tokio::test]
    async fn sidecar_endpoint_fail_when_tcp_unreachable() {
        let port = {
            let Some(listener) = try_bind_tcp_local() else {
                return;
            };
            listener.local_addr().expect("local_addr").port()
        };
        let endpoint = Endpoint::Tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        let check = check_endpoint(
            "sidecar reachable",
            Some(endpoint),
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(check.status, Status::Fail);
    }

    // -- authority endpoint ---------------------------------------------------

    #[test]
    fn rewrite_wildcard_swaps_zero_for_loopback() {
        let addr = SocketAddr::from(([0, 0, 0, 0], 50051));
        let rewritten = rewrite_wildcard(addr);
        assert_eq!(rewritten.ip().to_string(), "127.0.0.1");
        assert_eq!(rewritten.port(), 50051);
    }

    #[test]
    fn authority_endpoint_extracts_listen_addr() {
        let cfg = AuthorityConfig {
            listen_addr: "127.0.0.1:60051".to_owned(),
            ..AuthorityConfig::default()
        };
        let endpoint = endpoint_from_authority(&cfg).expect("endpoint");
        match endpoint {
            Endpoint::Tcp(addr) => {
                assert_eq!(addr.to_string(), "127.0.0.1:60051");
            }
            #[cfg(unix)]
            Endpoint::Uds(_) => panic!("authority always TCP today"),
        }
    }

    #[test]
    fn rewrite_wildcard_swaps_ipv6_zero_for_loopback() {
        let addr: SocketAddr = "[::]:50051".parse().expect("parse");
        let rewritten = rewrite_wildcard(addr);
        assert!(rewritten.ip().is_loopback(), "got {rewritten}");
        assert_eq!(rewritten.port(), 50051);
    }

    #[test]
    fn endpoint_from_authority_returns_none_on_unparseable_listen_addr() {
        let cfg = AuthorityConfig {
            listen_addr: "not-an-addr".to_owned(),
            ..AuthorityConfig::default()
        };
        assert!(endpoint_from_authority(&cfg).is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn check_endpoint_uds_warn_on_empty_path() {
        let endpoint = Endpoint::Uds(std::path::PathBuf::new());
        let check = check_endpoint(
            "sidecar reachable",
            Some(endpoint),
            Duration::from_millis(200),
        )
        .await;
        assert_eq!(check.status, Status::Warn);
        assert!(check.reason.contains("empty path"), "got {}", check.reason);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn check_endpoint_uds_ok_when_socket_listening() {
        use tokio::net::UnixListener;
        let tmp = tempfile::tempdir().expect("tempdir");
        let sock = tmp.path().join("d.sock");
        let listener = match UnixListener::bind(&sock) {
            Ok(listener) => listener,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping bind-dependent test: {err}");
                return;
            }
            Err(err) => panic!("bind: {err}"),
        };
        let endpoint = Endpoint::Uds(sock.clone());
        let check = check_endpoint(
            "sidecar reachable",
            Some(endpoint),
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(check.status, Status::Ok);
        drop(listener);
    }

    // -- reconcile_reachability -----------------------------------------------

    #[test]
    fn reconcile_reports_ok_when_live_per_run_instances_present() {
        // Daemon probe failed, but a per-run sidecar is live (AC1).
        let daemon = Check::fail("sidecar reachable", "127.0.0.1:9443: Connection refused");
        let reconciled = reconcile_reachability(daemon, 2);
        assert_eq!(reconciled.status, Status::Ok);
        assert!(
            reconciled.reason.contains("per-run"),
            "got {}",
            reconciled.reason
        );
        assert_eq!(
            reconciled.detail.get("live_instances").map(String::as_str),
            Some("2")
        );
    }

    #[test]
    fn reconcile_downgrades_failed_daemon_to_warn_when_no_live_instances() {
        // No daemon, no live per-run instance: normal for a firma-run-only
        // workflow — must not be a hard FAIL (AC3).
        let daemon = Check::fail("authority reachable", "127.0.0.1:9443: Connection refused");
        let reconciled = reconcile_reachability(daemon, 0);
        assert_eq!(reconciled.status, Status::Warn);
        assert!(
            reconciled.reason.contains("firma run"),
            "got {}",
            reconciled.reason
        );
    }

    #[test]
    fn reconcile_keeps_reachable_daemon_ok() {
        let daemon = Check::ok("sidecar reachable", "127.0.0.1:9443");
        let reconciled = reconcile_reachability(daemon, 0);
        assert_eq!(reconciled.status, Status::Ok);
        assert_eq!(reconciled.reason, "127.0.0.1:9443");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn check_endpoint_uds_fail_when_socket_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sock = tmp.path().join("missing.sock");
        let endpoint = Endpoint::Uds(sock);
        let check = check_endpoint(
            "sidecar reachable",
            Some(endpoint),
            Duration::from_millis(200),
        )
        .await;
        assert_eq!(check.status, Status::Fail);
    }
}

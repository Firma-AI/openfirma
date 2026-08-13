//! Bounded startup evidence for owned components.
//!
//! These probes establish only that startup reached its publication boundary;
//! they do not confer process ownership or promise ongoing health. Each wait
//! checks the caller's owned-child status before and after observing evidence,
//! closing the race where a dead component could otherwise be declared ready.
//! A supplied [`StopSignal`] also makes the wait cooperatively abortable.

use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use crate::ComponentEndpoint;
use crate::error::OrchestratorError;
use crate::supervisor::StopSignal;

const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(200);
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Wait until a live, owned component accepts a TCP connection.
///
/// The process-status callback must inspect the same [`crate::component::OwnedComponent`]
/// capabilities protected by startup. It runs before each attempt and again
/// after a successful connection so process exit takes precedence over
/// readiness publication.
///
/// # Errors
///
/// Returns termination, collection, [`OrchestratorError::ReadinessProcessExited`], or
/// [`OrchestratorError::Readiness`] errors while leaving rollback to the owner.
pub fn wait_for_tcp(
    component: &str,
    addr: SocketAddr,
    timeout: Duration,
    stop_signal: Option<&StopSignal>,
    mut process_status: impl FnMut() -> Result<Option<(String, ExitStatus)>, OrchestratorError>,
) -> Result<(), OrchestratorError> {
    let deadline = Instant::now() + timeout;
    wait_for_tcp_until(
        component,
        addr,
        deadline,
        timeout,
        stop_signal,
        &mut process_status,
    )
}

/// Wait until a live, owned component accepts a connection at an endpoint.
pub fn wait_for_endpoint(
    component: &str,
    endpoint: &ComponentEndpoint,
    timeout: Duration,
    stop_signal: Option<&StopSignal>,
    process_status: impl FnMut() -> Result<Option<(String, ExitStatus)>, OrchestratorError>,
) -> Result<(), OrchestratorError> {
    match endpoint {
        ComponentEndpoint::Tcp(addr) => {
            wait_for_tcp(component, *addr, timeout, stop_signal, process_status)
        }
        #[cfg(unix)]
        ComponentEndpoint::Unix(path) => {
            let mut process_status = process_status;
            let deadline = Instant::now() + timeout;
            loop {
                check_startup(component, stop_signal, &mut process_status)?;
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(readiness_timeout(component, timeout));
                }
                if crate::unix_connect::connect_with_timeout(
                    path.as_path().as_std_path(),
                    remaining.min(CONNECT_ATTEMPT_TIMEOUT),
                ) {
                    check_startup(component, stop_signal, &mut process_status)?;
                    return Ok(());
                }
                check_startup(component, stop_signal, &mut process_status)?;
                if Instant::now() >= deadline {
                    return Err(readiness_timeout(component, timeout));
                }
                sleep_until_next_probe(deadline);
            }
        }
    }
}

/// Wait for a live child to publish, then accept connections on, its bound endpoint.
pub fn wait_for_child_published_tcp(
    component: &str,
    requested_bind_addr: SocketAddr,
    startup_report_path: &Path,
    timeout: Duration,
    stop_signal: Option<&StopSignal>,
    mut process_status: impl FnMut() -> Result<Option<(String, ExitStatus)>, OrchestratorError>,
) -> Result<SocketAddr, OrchestratorError> {
    let deadline = Instant::now() + timeout;
    let published_bind_addr = loop {
        check_startup(component, stop_signal, &mut process_status)?;
        match crate::startup_report::read_startup_report(startup_report_path) {
            Ok(Some(published_bind_addr)) => {
                check_startup(component, stop_signal, &mut process_status)?;
                validate_startup_report(component, requested_bind_addr, published_bind_addr)?;
                break published_bind_addr;
            }
            Ok(None) => {}
            Err(error) => {
                check_startup(component, stop_signal, &mut process_status)?;
                return Err(invalid_startup_report(component, error));
            }
        }
        if Instant::now() >= deadline {
            check_startup(component, stop_signal, &mut process_status)?;
            return Err(readiness_timeout(component, timeout));
        }
        sleep_until_next_probe(deadline);
    };
    let dial_addr = dial_addr_for_bind_addr(published_bind_addr);
    wait_for_tcp_until(
        component,
        dial_addr,
        deadline,
        timeout,
        stop_signal,
        &mut process_status,
    )?;
    Ok(dial_addr)
}

/// Convert a successfully validated bind address into an endpoint clients can dial.
fn dial_addr_for_bind_addr(bind_addr: SocketAddr) -> SocketAddr {
    match bind_addr {
        SocketAddr::V4(addr) if addr.ip().is_unspecified() => {
            SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, addr.port()))
        }
        SocketAddr::V6(addr) if addr.ip().is_unspecified() => {
            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, addr.port()))
        }
        _ => bind_addr,
    }
}

fn wait_for_tcp_until(
    component: &str,
    addr: SocketAddr,
    deadline: Instant,
    timeout: Duration,
    stop_signal: Option<&StopSignal>,
    process_status: &mut impl FnMut() -> Result<Option<(String, ExitStatus)>, OrchestratorError>,
) -> Result<(), OrchestratorError> {
    loop {
        check_startup(component, stop_signal, process_status)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(readiness_timeout(component, timeout));
        }
        if TcpStream::connect_timeout(&addr, remaining.min(CONNECT_ATTEMPT_TIMEOUT)).is_ok() {
            check_startup(component, stop_signal, process_status)?;
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(readiness_timeout(component, timeout));
        }
        check_startup_stop(stop_signal)?;
        sleep_until_next_probe(deadline);
    }
}

fn validate_startup_report(
    component: &str,
    requested_bind_addr: SocketAddr,
    published_bind_addr: SocketAddr,
) -> Result<(), OrchestratorError> {
    if published_bind_addr.port() == 0 {
        return Err(invalid_startup_report(component, "effective port is zero"));
    }
    if !bind_ips_match(published_bind_addr, requested_bind_addr) {
        return Err(invalid_startup_report(
            component,
            format!(
                "effective IP {} does not match requested IP {}",
                published_bind_addr.ip(),
                requested_bind_addr.ip()
            ),
        ));
    }
    if requested_bind_addr.port() != 0 && published_bind_addr != requested_bind_addr {
        return Err(invalid_startup_report(
            component,
            format!(
                "effective endpoint {published_bind_addr} does not match requested {requested_bind_addr}"
            ),
        ));
    }
    Ok(())
}

fn bind_ips_match(published: SocketAddr, requested: SocketAddr) -> bool {
    match (published, requested) {
        (SocketAddr::V4(published), SocketAddr::V4(requested)) => published.ip() == requested.ip(),
        (SocketAddr::V6(published), SocketAddr::V6(requested)) => {
            // Flow information does not identify the bound interface, but the
            // scope does for scoped IPv6 addresses.
            published.ip() == requested.ip() && published.scope_id() == requested.scope_id()
        }
        _ => false,
    }
}

fn invalid_startup_report(component: &str, reason: impl std::fmt::Display) -> OrchestratorError {
    OrchestratorError::Platform(format!(
        "invalid startup report from '{component}': {reason}"
    ))
}

fn readiness_timeout(component: &str, timeout: Duration) -> OrchestratorError {
    OrchestratorError::Readiness {
        component: component.to_string(),
        timeout_secs: timeout.as_secs(),
    }
}

fn sleep_until_next_probe(deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if !remaining.is_zero() {
        std::thread::sleep(remaining.min(READINESS_POLL_INTERVAL));
    }
}

/// Reject termination or observed component exit before accepting readiness.
///
/// [`StopSignal`] is checked first so an explicit shutdown request consistently
/// drives rollback even when a component exits concurrently.
fn check_startup(
    _component: &str,
    stop_signal: Option<&StopSignal>,
    process_status: &mut impl FnMut() -> Result<Option<(String, ExitStatus)>, OrchestratorError>,
) -> Result<(), OrchestratorError> {
    check_startup_stop(stop_signal)?;
    if let Some((name, status)) = process_status()? {
        return Err(OrchestratorError::ReadinessProcessExited {
            component: name,
            status,
        });
    }
    Ok(())
}

/// Convert a process termination request into a rollback-triggering startup error.
fn check_startup_stop(stop_signal: Option<&StopSignal>) -> Result<(), OrchestratorError> {
    if stop_signal.is_some_and(StopSignal::requested) {
        return Err(OrchestratorError::Platform(
            "termination requested during stack startup".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        bind_ips_match, dial_addr_for_bind_addr, validate_startup_report,
        wait_for_child_published_tcp,
    };
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
    use std::time::Duration;

    use crate::error::OrchestratorError;

    #[test]
    fn wildcard_dial_addresses_preserve_ip_family_and_port() {
        assert_eq!(
            dial_addr_for_bind_addr(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 41_001))),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 41_001))
        );
        assert_eq!(
            dial_addr_for_bind_addr(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 42_001))),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 42_001))
        );
        assert_eq!(
            dial_addr_for_bind_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 43_001))),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 43_001))
        );
    }

    #[test]
    fn dynamic_ipv6_publication_must_preserve_scope() {
        let requested = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse().expect("requested IPv6"),
            0,
            0,
            3,
        ));
        let published = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse().expect("published IPv6"),
            41_002,
            7,
            4,
        ));

        assert!(!bind_ips_match(published, requested));
        let error = validate_startup_report("worker", requested, published)
            .expect_err("mismatched IPv6 scope must fail raw bind validation");
        assert!(error.to_string().contains("does not match requested IP"));
    }

    #[test]
    fn observable_child_exit_wins_over_malformed_publication() {
        let dir = tempfile::tempdir().expect("startup report dir");
        let path = dir.path().join("startup.toml");
        std::fs::write(&path, "not = valid = toml").expect("malformed startup report");
        let mut checks = 0;

        let error = wait_for_child_published_tcp(
            "worker",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            &path,
            Duration::from_secs(1),
            None,
            || {
                checks += 1;
                Ok((checks == 2).then(|| ("worker".to_string(), fixture_exit_status(17))))
            },
        )
        .expect_err("observable child exit must supersede the malformed report");

        let OrchestratorError::ReadinessProcessExited { component, status } = error else {
            panic!("unexpected readiness error: {error:?}");
        };
        assert_eq!(component, "worker");
        assert_eq!(status.code(), Some(17));
        assert_eq!(checks, 2);
    }

    #[cfg(unix)]
    fn fixture_exit_status(code: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt as _;

        std::process::ExitStatus::from_raw(code << 8)
    }

    #[cfg(windows)]
    fn fixture_exit_status(code: i32) -> std::process::ExitStatus {
        use std::os::windows::process::ExitStatusExt as _;

        std::process::ExitStatus::from_raw(code as u32)
    }
}

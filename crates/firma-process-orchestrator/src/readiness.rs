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

/// Wait for a live child to publish, then accept connections on, its bound endpoint.
pub fn wait_for_child_published_tcp(
    component: &str,
    requested_addr: SocketAddr,
    publication_path: &Path,
    timeout: Duration,
    stop_signal: Option<&StopSignal>,
    mut process_status: impl FnMut() -> Result<Option<(String, ExitStatus)>, OrchestratorError>,
) -> Result<SocketAddr, OrchestratorError> {
    let deadline = Instant::now() + timeout;
    let effective_addr = loop {
        check_startup(component, stop_signal, &mut process_status)?;
        match crate::endpoint_publication::read_tcp_endpoint(publication_path) {
            Ok(Some((version, effective))) => {
                validate_publication(component, requested_addr, version, effective)?;
                check_startup(component, stop_signal, &mut process_status)?;
                break effective;
            }
            Ok(None) => {}
            Err(error) => return Err(invalid_publication(component, error)),
        }
        if Instant::now() >= deadline {
            return Err(readiness_timeout(component, timeout));
        }
        sleep_until_next_probe(deadline);
    };
    wait_for_tcp_until(
        component,
        effective_addr,
        deadline,
        timeout,
        stop_signal,
        &mut process_status,
    )?;
    Ok(effective_addr)
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

fn validate_publication(
    component: &str,
    requested: SocketAddr,
    version: u32,
    effective: SocketAddr,
) -> Result<(), OrchestratorError> {
    if version != crate::endpoint_publication::endpoint_protocol_version() {
        return Err(invalid_publication(
            component,
            format!("unsupported protocol version {version}"),
        ));
    }
    if effective.port() == 0 {
        return Err(invalid_publication(component, "effective port is zero"));
    }
    if effective.ip() != requested.ip() {
        return Err(invalid_publication(
            component,
            format!(
                "effective IP {} does not match requested IP {}",
                effective.ip(),
                requested.ip()
            ),
        ));
    }
    if requested.port() != 0 && effective != requested {
        return Err(invalid_publication(
            component,
            format!("effective endpoint {effective} does not match requested {requested}"),
        ));
    }
    Ok(())
}

fn invalid_publication(component: &str, reason: impl std::fmt::Display) -> OrchestratorError {
    OrchestratorError::Platform(format!(
        "invalid endpoint publication from '{component}': {reason}"
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

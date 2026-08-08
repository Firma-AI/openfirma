//! Bounded startup evidence for owned components.
//!
//! These probes establish only that startup reached its publication boundary;
//! they do not confer process ownership or promise ongoing health. Each wait
//! checks the caller's owned-child status before and after observing evidence,
//! closing the race where a dead component could otherwise be declared ready.
//! A supplied [`StopSignal`] also makes the wait cooperatively abortable.

use std::net::{SocketAddr, TcpStream};
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
    loop {
        check_startup(component, stop_signal, &mut process_status)?;
        if TcpStream::connect_timeout(&addr, CONNECT_ATTEMPT_TIMEOUT).is_ok() {
            check_startup(component, stop_signal, &mut process_status)?;
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(OrchestratorError::Readiness {
                component: component.to_string(),
                timeout_secs: timeout.as_secs(),
            });
        }
        std::thread::sleep(READINESS_POLL_INTERVAL);
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

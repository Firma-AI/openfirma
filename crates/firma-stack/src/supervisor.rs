//! Foreground ownership and detached observation loops.
//!
//! Owned supervision uses [`OwnedComponent`] capabilities to detect and collect
//! leader exits. Observed supervision has only persisted [`UserProcessId`]
//! values and can establish liveness but cannot collect those processes. Both
//! loops return when a stop request or either component exit makes coordinated
//! teardown necessary; returning successfully does not stop the peer. That
//! responsibility remains with their caller.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::component::OwnedComponent;
use crate::error::Result;
use crate::platform::TerminationTarget;
use firma_runtime_state::{ChildExt as _, UserProcessId};

/// Persisted component identities available to a detached observer.
///
/// This value grants no child-collection or process-termination authority.
#[derive(Clone, Copy)]
pub struct ObservedChildren {
    pub authority_pid: UserProcessId,
    pub sidecar_pid: UserProcessId,
}

/// Wait until owned foreground supervision should begin coordinated teardown.
///
/// A direct-child exit is collected through [`OwnedComponent::try_wait`]. Stop
/// requests and exits both return [`Ok`]; collection failures are returned
/// while component teardown remains the caller's responsibility.
pub fn block_until_owned_exit(
    authority: &mut OwnedComponent,
    sidecar: &mut OwnedComponent,
) -> Result<()> {
    let stop = install_stop_handler();
    debug!(
        authority_pid = %authority.leader_pid(),
        sidecar_pid = %sidecar.leader_pid(),
        "foreground supervisor watching owned children"
    );

    loop {
        if stop.load(Ordering::SeqCst) {
            info!("Ctrl-C received; caller will tear stack down");
            return Ok(());
        }
        if authority.try_wait()?.is_some() {
            warn!(pid = %authority.leader_pid(), "authority exited unexpectedly");
            return Ok(());
        }
        if sidecar.try_wait()?.is_some() {
            warn!(pid = %sidecar.leader_pid(), "sidecar exited unexpectedly");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Wait until observed detached supervision should begin coordinated teardown.
///
/// Unlike [`block_until_owned_exit`], this function can only probe persisted
/// identities in [`ObservedChildren`]. It cannot collect a child or infer the
/// full platform termination scope from those identities.
pub fn block_until_observed_exit(children: ObservedChildren) -> Result<()> {
    let stop = install_stop_handler();
    debug!(
        authority_pid = %children.authority_pid,
        sidecar_pid = %children.sidecar_pid,
        "detached supervisor observing children"
    );

    loop {
        if stop.load(Ordering::SeqCst) {
            info!("Ctrl-C received; caller will tear stack down");
            return Ok(());
        }
        if !children.authority_pid.process_exists()? {
            warn!(
                pid = %children.authority_pid,
                "authority exited unexpectedly"
            );
            return Ok(());
        }
        if !children.sidecar_pid.process_exists()? {
            warn!(pid = %children.sidecar_pid, "sidecar exited unexpectedly");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Install a process-local request flag for both supervision loops.
///
/// The handler only requests loop termination; it never signals components.
/// Handler installation is best-effort because another crate may already own
/// the process-wide handler.
fn install_stop_handler() -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);
    let _ = ctrlc::set_handler(move || {
        stop_handler.store(true, Ordering::SeqCst);
    });
    stop
}

/// Failure to transfer component ownership into a background reaper.
///
/// The owned components remain available through [`Self::into_components`],
/// allowing the caller to retry, terminate them synchronously, or retain them.
pub struct ReaperStartError {
    source: std::io::Error,
    components: Arc<std::sync::Mutex<Option<Vec<OwnedComponent>>>>,
}

impl ReaperStartError {
    /// Return the operating-system error that prevented thread creation.
    pub const fn source(&self) -> &std::io::Error {
        &self.source
    }

    /// Recover every process capability offered to the failed reaper.
    pub fn into_components(self) -> Vec<OwnedComponent> {
        match self.components.lock() {
            Ok(mut components) => components.take().unwrap_or_default(),
            Err(components) => components.into_inner().take().unwrap_or_default(),
        }
    }

    /// Hard-terminate and synchronously collect the recovered components.
    ///
    /// This is the fail-closed fallback for callers, such as [`Drop`]
    /// implementations, that cannot return ownership to their own caller. Each
    /// [`OwnedComponent`] remains represented until its direct child receives a
    /// bounded collection attempt.
    pub fn terminate_and_collect(self, timeout: Duration) {
        let mut components = self.into_components();
        for component in &mut components {
            let _ = component.termination_target().signal_hard();
            let _ = component.kill_leader();
        }
        let deadline = std::time::Instant::now() + timeout;
        for component in &mut components {
            let _ = collect_child_until(component.child_mut(), deadline);
        }
    }
}

/// Transfer component ownership to a named background reaper.
///
/// The reaper retains each [`OwnedComponent`] until its leader is collected; it
/// does not supervise health or terminate peers. On thread-creation failure, no
/// process capability is dropped: [`ReaperStartError`] carries the complete
/// input collection back to the caller.
pub fn collect_in_background(
    components: Vec<OwnedComponent>,
) -> std::result::Result<std::thread::JoinHandle<()>, ReaperStartError> {
    collect_in_background_with(components, |job| {
        std::thread::Builder::new()
            .name("firma-component-reaper".into())
            .spawn(job)
    })
}

/// Start a component reaper through the supplied thread-spawn operation.
///
/// This seam keeps ownership recovery testable without exhausting real process
/// resources. Production callers use [`collect_in_background`].
pub fn collect_in_background_with(
    components: Vec<OwnedComponent>,
    spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<std::thread::JoinHandle<()>>,
) -> std::result::Result<std::thread::JoinHandle<()>, ReaperStartError> {
    let components = Arc::new(std::sync::Mutex::new(Some(components)));
    let worker_components = Arc::clone(&components);
    spawn(Box::new(move || {
            let mut components = match worker_components.lock() {
                Ok(mut components) => components.take().unwrap_or_default(),
                Err(components) => components.into_inner().take().unwrap_or_default(),
            };
            while !components.is_empty() {
                components.retain_mut(|component| match component.try_wait() {
                    Ok(None) => true,
                    Ok(Some(_)) => false,
                    Err(error) if child_was_collected_externally(&error) => false,
                    Err(error) => {
                        debug!(role = component.role().name(), %error, "component collection probe failed; retrying");
                        true
                    }
                });
                if !components.is_empty() {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }))
        .map_err(|source| ReaperStartError { source, components })
}

/// Transfer collection of one direct child to the legacy background fallback.
///
/// The target derived from the child leader is appropriate only when no wider
/// platform [`TerminationTarget`] is available.
pub fn collect_child_in_background(
    child: std::process::Child,
) -> Option<std::thread::JoinHandle<()>> {
    let target = TerminationTarget::for_leader(child.process_id());
    collect_target_in_background(child, target)
}

/// Transfer a paired child and [`TerminationTarget`] to the legacy fallback.
pub fn collect_target_in_background(
    child: std::process::Child,
    target: TerminationTarget,
) -> Option<std::thread::JoinHandle<()>> {
    spawn_collector(vec![CollectedChild { child, target }])
}

/// Attempt direct-child collection until a deadline without losing the handle.
///
/// Returns `true` after collection or when the platform proves another waiter
/// already collected the child. A `false` result leaves the handle usable for a
/// background or synchronous fallback.
pub fn collect_child_until(child: &mut std::process::Child, deadline: std::time::Instant) -> bool {
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => return false,
            Err(error) if child_was_collected_externally(&error) => return true,
            Err(error) if std::time::Instant::now() < deadline => {
                debug!(%error, "child collection probe failed; retrying");
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                debug!(%error, "child collection probe did not recover before deadline");
                return false;
            }
        }
    }
}

/// Legacy collection authority paired with its process-tree termination scope.
struct CollectedChild {
    child: std::process::Child,
    target: TerminationTarget,
}

impl From<OwnedComponent> for CollectedChild {
    fn from(component: OwnedComponent) -> Self {
        let (child, target) = component.into_parts();
        Self { child, target }
    }
}

/// Start the fallback collector that assumes ownership of supplied capabilities.
///
/// Thread-creation failure cannot return these already separated capabilities,
/// so this function terminates and makes a bounded collection attempt before
/// returning [`None`]. New lifecycle code should prefer
/// [`collect_in_background`], whose [`ReaperStartError`] preserves ownership.
fn spawn_collector(children: Vec<CollectedChild>) -> Option<std::thread::JoinHandle<()>> {
    let children = Arc::new(std::sync::Mutex::new(children));
    let worker_children = Arc::clone(&children);
    match std::thread::Builder::new()
        .name("firma-child-collector".into())
        .spawn(move || {
            let mut children = match worker_children.lock() {
                Ok(mut children) => std::mem::take(&mut *children),
                Err(_) => return,
            };
            while !children.is_empty() {
                children.retain_mut(|owned| match owned.child.try_wait() {
                    Ok(None) => true,
                    Ok(Some(_)) => false,
                    Err(error) if child_was_collected_externally(&error) => false,
                    Err(error) => {
                        debug!(%error, "child collection probe failed; retrying");
                        true
                    }
                });
                if !children.is_empty() {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }) {
        Ok(handle) => Some(handle),
        Err(error) => {
            warn!(%error, "could not start child collector; terminating uncollected children");
            if let Ok(mut children) = children.lock() {
                for child in children.iter_mut() {
                    let _ = child.target.signal_hard();
                    let _ = child.child.kill();
                    let _ = collect_child_until(
                        &mut child.child,
                        std::time::Instant::now() + Duration::from_secs(2),
                    );
                }
            }
            None
        }
    }
}

/// Return whether an owned child handle has already been collected elsewhere.
#[cfg(unix)]
fn child_was_collected_externally(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(nix::libc::ECHILD)
}

#[cfg(windows)]
fn child_was_collected_externally(_error: &std::io::Error) -> bool {
    false
}

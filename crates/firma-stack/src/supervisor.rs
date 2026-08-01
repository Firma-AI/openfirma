//! Owned-child supervision and collection.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::component::OwnedComponent;
use crate::error::Result;
use crate::platform::TerminationTarget;
use firma_runtime_state::ChildExt as _;

static PROCESS_STOP_EPOCH: OnceLock<std::result::Result<Arc<SignalEpoch>, String>> =
    OnceLock::new();

struct SignalEpoch {
    current: AtomicU64,
    subscriptions: AtomicU64,
}

/// Per-supervision snapshot of the process-wide termination-signal epoch.
pub struct StopSignal {
    epoch: Arc<SignalEpoch>,
    baseline: u64,
}

impl StopSignal {
    /// Install the process-wide handler before publishing supervisor readiness.
    ///
    /// Repeated calls share the process-wide handler and notification state.
    ///
    /// # Errors
    ///
    /// Returns a platform error when the process handler cannot be installed.
    pub fn install() -> Result<Self> {
        match PROCESS_STOP_EPOCH.get_or_init(|| {
            let epoch = Arc::new(SignalEpoch {
                current: AtomicU64::new(0),
                subscriptions: AtomicU64::new(0),
            });
            let handler_epoch = Arc::clone(&epoch);
            ctrlc::set_handler(move || {
                handler_epoch.current.fetch_add(1, Ordering::Relaxed);
            })
            .map(|()| epoch)
            .map_err(|error| error.to_string())
        }) {
            Ok(epoch) => {
                let observed = epoch.current.load(Ordering::Relaxed);
                let subscription = epoch.subscriptions.fetch_add(1, Ordering::Relaxed);
                let baseline = if subscription == 0 { 0 } else { observed };
                Ok(Self {
                    epoch: Arc::clone(epoch),
                    baseline,
                })
            }
            Err(error) => Err(crate::error::StackError::Platform(format!(
                "install termination handler failed: {error}"
            ))),
        }
    }

    /// Return whether `SIGINT`, `SIGTERM`, `SIGHUP`, or console shutdown fired.
    pub(crate) fn requested(&self) -> bool {
        self.epoch.current.load(Ordering::Relaxed) != self.baseline
    }
}

pub fn block_until_owned_exit(
    authority: &mut OwnedComponent,
    sidecar: &mut OwnedComponent,
) -> Result<()> {
    block_until_owned_exit_with(&StopSignal::install()?, authority, sidecar)
}

/// Supervise owned children using a handler installed before readiness.
pub fn block_until_owned_exit_with(
    stop: &StopSignal,
    authority: &mut OwnedComponent,
    sidecar: &mut OwnedComponent,
) -> Result<()> {
    debug!(
        authority_pid = %authority.leader_pid(),
        sidecar_pid = %sidecar.leader_pid(),
        "foreground supervisor watching owned children"
    );

    loop {
        if stop.requested() {
            info!("termination signal received; caller will tear stack down");
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
    /// This is the fail-closed fallback for callers, such as `Drop`
    /// implementations, that cannot return ownership to their own caller.
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
/// On thread-creation failure, no process capability is dropped; the returned
/// error carries the complete input collection.
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

pub fn collect_child_in_background(
    child: std::process::Child,
) -> Option<std::thread::JoinHandle<()>> {
    let target = TerminationTarget::for_leader(child.process_id());
    collect_target_in_background(child, target)
}

pub fn collect_target_in_background(
    child: std::process::Child,
    target: TerminationTarget,
) -> Option<std::thread::JoinHandle<()>> {
    spawn_collector(vec![CollectedChild { child, target }])
}

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

#[cfg(unix)]
fn child_was_collected_externally(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(nix::libc::ECHILD)
}

#[cfg(windows)]
fn child_was_collected_externally(_error: &std::io::Error) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_stop_signal_ignores_previous_epochs() {
        let epoch = Arc::new(SignalEpoch {
            current: AtomicU64::new(0),
            subscriptions: AtomicU64::new(0),
        });
        let first = StopSignal {
            epoch: Arc::clone(&epoch),
            baseline: epoch.current.load(Ordering::Relaxed),
        };

        epoch.current.fetch_add(1, Ordering::Relaxed);
        assert!(first.requested());

        let second = StopSignal {
            epoch: Arc::clone(&epoch),
            baseline: epoch.current.load(Ordering::Relaxed),
        };
        assert!(!second.requested());
    }
}

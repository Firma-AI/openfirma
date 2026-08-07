//! Owned-child supervision and collection.
//!
//! Supervision observes [`OwnedComponent`] values without relinquishing them.
//! Background collection is an explicit ownership transfer: component reaper
//! startup either accepts the complete capability set or returns it through
//! [`ReaperStartError`].

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::component::OwnedComponent;
use crate::error::Result;
use crate::platform::TerminationTarget;
use firma_runtime_state::ChildExt as _;

/// Operation that starts a thread owning one component-reaper job.
///
/// Keeping thread creation separate from [`collect_in_background_with`] lets
/// [`crate::start::RunningStack`] retain the operation until it relinquishes
/// its [`OwnedComponent`] capabilities.
pub type ReaperLauncher =
    fn(Box<dyn FnOnce() + Send>) -> std::io::Result<std::thread::JoinHandle<()>>;

/// Process-wide result of installing the termination handler exactly once.
///
/// Caching both success and failure prevents later supervisors from claiming
/// signal readiness under a different handler state.
static PROCESS_STOP_EPOCH: OnceLock<std::result::Result<Arc<SignalEpoch>, String>> =
    OnceLock::new();

/// Monotonic process-wide signal history and subscription sequence.
///
/// A counter rather than a boolean lets each [`StopSignal`] distinguish a new
/// termination request from one already handled by an earlier supervision run.
struct SignalEpoch {
    /// Number of termination requests observed by the installed handler.
    current: AtomicU64,
    /// Number of [`StopSignal`] snapshots issued from this epoch.
    subscriptions: AtomicU64,
}

/// Per-supervision snapshot of the process-wide termination-signal epoch.
///
/// The first subscription retains a zero baseline so it observes any signal
/// delivered during handler installation. Later subscriptions start at the
/// current epoch, preventing a handled request from terminating a replacement
/// supervisor. All snapshots share [`PROCESS_STOP_EPOCH`]. Startup readiness
/// probes and steady-state supervision must share the same snapshot so a request
/// cannot fall between those lifecycle phases.
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

    /// Return whether a new supported termination signal followed this snapshot.
    pub(crate) fn requested(&self) -> bool {
        self.epoch.current.load(Ordering::Relaxed) != self.baseline
    }
}

/// Supervise owned children using a [`StopSignal`] installed before readiness.
///
/// Return preserves both [`OwnedComponent`] values for the caller's teardown;
/// observed child exit never transfers or silently drops process authority.
///
/// # Errors
///
/// Returns the first direct-child collection probe error.
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
    /// This is the fail-closed fallback for callers, such as [`Drop`]
    /// implementations, that cannot return ownership to their own caller. It
    /// deliberately waits without a deadline: after reaper creation fails,
    /// returning early would discard the only handles capable of reaping the
    /// direct children.
    ///
    /// # Errors
    ///
    /// Returns the first child collection error after attempting to terminate
    /// and collect every recovered component.
    pub fn terminate_and_collect(self) -> std::io::Result<()> {
        let mut components = self.into_components();
        for component in &mut components {
            if let Err(error) = component.termination_target().signal_hard() {
                warn!(role = component.role().name(), %error, "fallback process-tree termination failed");
            }
            if let Err(error) = component.kill_leader() {
                debug!(role = component.role().name(), %error, "fallback leader termination failed");
            }
        }

        let mut collection_error = None;
        for component in &mut components {
            if let Err(error) = component.wait() {
                if child_was_collected_externally(&error) {
                    continue;
                }
                warn!(role = component.role().name(), %error, "fallback child collection failed");
                if collection_error.is_none() {
                    collection_error = Some(error);
                }
            }
        }
        if let Some(error) = collection_error {
            return Err(error);
        }
        Ok(())
    }
}

/// Transfer component ownership to a named background reaper.
///
/// On thread-creation failure, no process capability is dropped; the returned
/// error carries the complete input collection.
pub fn collect_in_background(
    components: Vec<OwnedComponent>,
) -> std::result::Result<std::thread::JoinHandle<()>, ReaperStartError> {
    collect_in_background_with(components, launch_reaper)
}

/// Start a named thread that owns one component-reaper job.
pub fn launch_reaper(
    job: Box<dyn FnOnce() + Send>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("firma-component-reaper".into())
        .spawn(job)
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

/// Transfer one direct child and its leader target to a background collector.
pub fn collect_child_in_background(
    child: std::process::Child,
) -> Option<std::thread::JoinHandle<()>> {
    let target = TerminationTarget::for_leader(child.process_id());
    collect_target_in_background(child, target)
}

/// Transfer a child and explicit [`TerminationTarget`] to a background collector.
pub fn collect_target_in_background(
    child: std::process::Child,
    target: TerminationTarget,
) -> Option<std::thread::JoinHandle<()>> {
    spawn_collector(vec![CollectedChild { child, target }])
}

/// Attempt direct-child collection until a deadline without relinquishing ownership.
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

/// Inseparable collection and termination capabilities owned by a collector.
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

/// Transfer all children to one reaper or terminate them if transfer fails.
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
/// Return whether another wait operation already fulfilled collection.
fn child_was_collected_externally(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(nix::libc::ECHILD)
}

#[cfg(windows)]
/// Windows child handles do not report the Unix external-collection condition.
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

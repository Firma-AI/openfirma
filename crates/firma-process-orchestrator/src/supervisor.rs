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
use crate::error::OrchestratorError;
use crate::platform::{Platform, SystemPlatform};

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
static PROCESS_STOP_EPOCH: OnceLock<Result<Arc<SignalEpoch>, String>> = OnceLock::new();

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
    pub fn install() -> Result<Self, OrchestratorError> {
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
            Err(error) => Err(OrchestratorError::Platform(format!(
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
/// Return preserves every [`OwnedComponent`] for the caller's teardown; an
/// observed child exit never transfers or silently drops process authority.
///
/// # Errors
///
/// Returns the first direct-child collection probe error.
pub fn block_until_owned_exit_with(
    stop: &StopSignal,
    components: &mut [OwnedComponent],
) -> Result<(), OrchestratorError> {
    debug!(
        component_count = components.len(),
        "foreground supervisor watching owned children"
    );

    loop {
        if stop.requested() {
            info!("termination signal received; caller will tear stack down");
            return Ok(());
        }
        for component in &mut *components {
            if component.try_wait()?.is_some() {
                warn!(
                    name = component.name().as_str(),
                    pid = %component.leader_pid(),
                    "component exited unexpectedly"
                );
                return Ok(());
            }
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
                warn!(role = component.name().as_str(), %error, "fallback process-tree termination failed");
            }
            if let Err(error) = component.kill_leader() {
                debug!(role = component.name().as_str(), %error, "fallback leader termination failed");
            }
        }

        let mut collection_error = None;
        for component in &mut components {
            if let Err(error) = component.wait() {
                if SystemPlatform::child_already_reaped(&error) {
                    continue;
                }
                warn!(role = component.name().as_str(), %error, "fallback child collection failed");
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
) -> Result<std::thread::JoinHandle<()>, ReaperStartError> {
    collect_in_background_with(components, launch_reaper)
}

/// Start a named thread that owns one component-reaper job.
pub fn launch_reaper(
    job: Box<dyn FnOnce() + Send>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("component-reaper".into())
        .spawn(job)
}

/// Start a component reaper through the supplied thread-spawn operation.
///
/// This seam keeps ownership recovery testable without exhausting real process
/// resources. Production callers use [`collect_in_background`].
pub fn collect_in_background_with(
    components: Vec<OwnedComponent>,
    spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<std::thread::JoinHandle<()>>,
) -> Result<std::thread::JoinHandle<()>, ReaperStartError> {
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
                    Err(error) if SystemPlatform::child_already_reaped(&error) => false,
                    Err(error) => {
                        debug!(role = component.name().as_str(), %error, "component collection probe failed; retrying");
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

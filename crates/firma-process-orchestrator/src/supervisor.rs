//! Owned-child supervision and collection.
//!
//! Supervision observes [`OwnedComponent`] values without relinquishing them.
//! Background collection is an explicit ownership transfer to the persistent
//! collector initialized before managed children are spawned.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::collect::HandoffError;
use crate::component::OwnedComponent;
use crate::error::OrchestratorError;

const SUPERVISION_POLL_INTERVAL: Duration = Duration::from_millis(200);

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
        std::thread::sleep(SUPERVISION_POLL_INTERVAL);
    }
}

/// Transfer component ownership to the process-global background collector.
pub fn collect_in_background(components: Vec<OwnedComponent>) -> Result<(), HandoffError> {
    crate::collect::collect_components_in_background(components)
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

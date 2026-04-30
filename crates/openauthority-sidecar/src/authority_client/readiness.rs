//! Readiness state shared between Authority stream tasks and the pipeline.

use tokio::sync::watch;

/// Initial stream readiness.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadinessState {
    /// A policy bundle has been applied successfully.
    pub policy_bundle_ready: bool,
    /// The revocation stream has connected and passed its initial barrier.
    pub revocation_ready: bool,
}

/// Writable readiness flag.
pub struct ReadinessFlag {
    tx: watch::Sender<ReadinessState>,
}

/// Read-only readiness view for the request hot path.
#[derive(Clone)]
pub struct ReadinessView {
    rx: watch::Receiver<ReadinessState>,
}

impl ReadinessFlag {
    /// Create a readiness flag and matching read view.
    #[must_use]
    pub fn new(initial: ReadinessState) -> (Self, ReadinessView) {
        let (tx, rx) = watch::channel(initial);
        (Self { tx }, ReadinessView { rx })
    }

    /// Mark the policy bundle stream ready or not ready.
    pub fn set_policy_bundle_ready(&self, ready: bool) {
        self.tx
            .send_modify(|state| state.policy_bundle_ready = ready);
    }

    /// Mark the revocation stream ready or not ready.
    pub fn set_revocation_ready(&self, ready: bool) {
        self.tx.send_modify(|state| state.revocation_ready = ready);
    }
}

impl ReadinessView {
    /// Return a lock-free snapshot of current readiness.
    #[must_use]
    pub fn snapshot(&self) -> ReadinessState {
        *self.rx.borrow()
    }

    /// Construct a view that is already fully ready.
    #[must_use]
    pub fn all_ready() -> Self {
        let (_flag, view) = ReadinessFlag::new(ReadinessState {
            policy_bundle_ready: true,
            revocation_ready: true,
        });
        view
    }
}

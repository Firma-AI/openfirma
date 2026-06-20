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

impl ReadinessState {
    /// Both streams have hydrated and the sidecar can serve traffic.
    #[must_use]
    pub fn fully_ready(self) -> bool {
        self.policy_bundle_ready && self.revocation_ready
    }
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

    /// Snapshot of current readiness without subscribing.
    #[must_use]
    pub fn snapshot(&self) -> ReadinessState {
        *self.tx.borrow()
    }

    /// Resolve once both `policy_bundle_ready` and `revocation_ready` are
    /// true. Returns immediately when both are already set. Returns
    /// without panicking if every writer has been dropped (the sender
    /// remains alive while this `ReadinessFlag` is held, so callers
    /// that own the flag will always observe the transition).
    pub async fn wait_until_fully_ready(&self) {
        let mut rx = self.tx.subscribe();
        loop {
            let state = *rx.borrow();
            if state.policy_bundle_ready && state.revocation_ready {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::{ReadinessFlag, ReadinessState};

    #[tokio::test]
    async fn wait_until_fully_ready_resolves_when_both_streams_flip() {
        let (flag, _view) = ReadinessFlag::new(ReadinessState::default());
        let flag = Arc::new(flag);
        let waiter = {
            let flag = Arc::clone(&flag);
            tokio::spawn(async move { flag.wait_until_fully_ready().await })
        };

        // Hot path must still be blocked while only one stream is up.
        flag.set_policy_bundle_ready(true);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!waiter.is_finished(), "must wait for both streams");

        flag.set_revocation_ready(true);
        tokio::time::timeout(Duration::from_millis(200), waiter)
            .await
            .expect("wait_until_fully_ready resolved before deadline")
            .expect("waiter task ok");
        assert!(flag.snapshot().fully_ready());
    }

    #[tokio::test]
    async fn wait_until_fully_ready_returns_immediately_when_already_ready() {
        let (flag, _view) = ReadinessFlag::new(ReadinessState {
            policy_bundle_ready: true,
            revocation_ready: true,
        });
        tokio::time::timeout(Duration::from_millis(50), flag.wait_until_fully_ready())
            .await
            .expect("immediate resolution");
    }
}

//! Lifecycle timeout policy and shared internal timing bounds.

use std::time::Duration;

/// Caller-selected timeout policy for stack startup and teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleTimeouts {
    /// Maximum time to wait for each component to publish readiness.
    pub component_readiness: Duration,
    /// Maximum time for the launcher to complete the two-phase detached handoff.
    ///
    /// The supervisor independently uses the same duration while waiting for
    /// the launcher's acknowledgement.
    pub detached_handoff: Duration,
    /// Maximum time to wait for graceful component shutdown.
    pub graceful_teardown: Duration,
}

impl Default for LifecycleTimeouts {
    fn default() -> Self {
        Self {
            component_readiness: Duration::from_mins(1),
            detached_handoff: Duration::from_mins(4),
            graceful_teardown: Duration::from_secs(10),
        }
    }
}

/// Maximum bounded collection attempt after a direct child is hard-killed.
pub const CHILD_COLLECTION_TIMEOUT: Duration = Duration::from_secs(2);

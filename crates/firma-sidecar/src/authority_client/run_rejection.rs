//! Ending a run the Authority no longer accepts.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use super::readiness::ReadinessFlag;
use crate::authority_credentials::SidecarCredential;

/// Ends this Sidecar's run once the Authority rejects its runtime credential,
/// whichever Authority call notices first.
///
/// Rejection is terminal: the run cannot become live again, so a reconnect
/// cannot succeed. Agent traffic is denied first, then the Sidecar stops,
/// which tells `firma run` to stop the agent.
#[derive(Clone)]
pub struct RunRejection {
    readiness: Arc<ReadinessFlag>,
    exit: CancellationToken,
}

impl std::fmt::Debug for RunRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunRejection")
            .field("readiness", &self.readiness.snapshot())
            .finish_non_exhaustive()
    }
}

impl RunRejection {
    /// Rejection that denies traffic through `readiness` and stops the
    /// Sidecar through `exit`.
    #[must_use]
    pub fn new(readiness: Arc<ReadinessFlag>, exit: CancellationToken) -> Self {
        Self { readiness, exit }
    }

    /// Denies all agent traffic for good, then stops the Sidecar.
    pub(crate) fn reject(&self) {
        self.readiness.reject_run();
        self.exit.cancel();
    }
}

/// Whether `status`, returned by the Authority, means it rejected the run of
/// `credentials`.
///
/// Only a runtime credential belongs to a run. The Authority reports a run
/// that is no longer live as `Unauthenticated`; `PermissionDenied` marks a
/// request outside the run, not the loss of the run. A pre-shared key, or any
/// other code, keeps retrying.
pub fn rejects_run(status: &tonic::Status, credentials: Option<&SidecarCredential>) -> bool {
    status.code() == tonic::Code::Unauthenticated
        && matches!(credentials, Some(SidecarCredential::Runtime(_)))
}

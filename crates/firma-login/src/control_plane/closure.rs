//! Closing a run: the outcome the CLI reports and the one the Control
//! Plane recorded.

use firma_identifiers::RunId;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use super::{CONTRACT_VERSION, ControlPlaneClient, ControlPlaneError, RunState};

/// How the CLI says a run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseOutcome {
    /// The command exited with 0.
    Completed,
    /// The command exited otherwise, or the run failed after the start.
    Failed,
    /// The user interrupted the command.
    Cancelled,
}

/// How the Control Plane recorded a terminal run: the first close wins,
/// so it may differ from the [`CloseOutcome`] asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedOutcome {
    /// Closed as completed.
    Completed,
    /// Closed as failed.
    Failed,
    /// Closed as cancelled.
    Cancelled,
    /// Expired: its Sidecar never connected, or stopped refreshing.
    Expired,
    /// Ended because its starting API key expired.
    KeyExpired,
    /// Ended because its Agent was deleted.
    AgentDeleted,
}

impl RecordedOutcome {
    /// The contract's name for this outcome.
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::KeyExpired => "key_expired",
            Self::AgentDeleted => "agent_deleted",
        }
    }
}

impl std::fmt::Display for RecordedOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<CloseOutcome> for RecordedOutcome {
    fn from(outcome: CloseOutcome) -> Self {
        match outcome {
            CloseOutcome::Completed => Self::Completed,
            CloseOutcome::Failed => Self::Failed,
            CloseOutcome::Cancelled => Self::Cancelled,
        }
    }
}

#[derive(Serialize)]
struct CloseBody {
    outcome: CloseOutcome,
}

#[derive(Deserialize)]
struct ClosedBody {
    contract_version: u32,
    run: ClosedView,
}

#[derive(Deserialize)]
struct ClosedView {
    id: RunId,
    state: RunState,
    outcome: Option<RecordedOutcome>,
}

impl ControlPlaneClient {
    /// Closes `run_id` as `outcome` and returns what the Control Plane
    /// recorded.
    ///
    /// Repeated when the Control Plane could not answer: the first close
    /// wins, so a replay returns the recorded outcome.
    ///
    /// # Errors
    /// Returns a [`ControlPlaneError`]; any answer that is not a terminal
    /// record of this run is [`ControlPlaneError::IncompatibleServer`].
    pub async fn close_run(
        &mut self,
        run_id: RunId,
        outcome: CloseOutcome,
    ) -> Result<RecordedOutcome, ControlPlaneError> {
        let id = run_id.to_string();
        let request = serde_json::to_vec(&CloseBody { outcome })
            .map_err(|_| ControlPlaneError::IncompatibleServer)?;
        let body = self
            .post_with_retries(&["runs", &id, "close"], &request, &[StatusCode::OK])
            .await?;
        let body: ClosedBody =
            serde_json::from_slice(&body).map_err(|_| ControlPlaneError::IncompatibleServer)?;
        match body.run {
            ClosedView {
                id,
                state: RunState::Terminal,
                outcome: Some(recorded),
            } if body.contract_version == CONTRACT_VERSION && id == run_id => Ok(recorded),
            _ => Err(ControlPlaneError::IncompatibleServer),
        }
    }
}

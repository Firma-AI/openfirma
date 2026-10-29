//! How a run ended: the workload's result kept apart from the cleanup after
//! it, so a caller can tell what the command did even when cleanup failed.

use crate::error::RunError;

/// The end of one run.
#[derive(Debug)]
#[must_use]
pub struct RunCompletion {
    /// The workload's exit code once it was reaped, or why the run never got
    /// one: a preparation failure or a failed wait.
    pub command: Result<i32, RunError>,
    /// Whether a termination signal reached `firma` while it waited for the
    /// workload, counted only where the workload cannot send it itself;
    /// `false` when no workload was started.
    pub interrupted: bool,
    /// Whether the workload was stopped because the run's Sidecar exited,
    /// for example when its workspace ended the run.
    pub sidecar_stopped: bool,
    /// Stopping the Sidecar and the network services.
    pub shutdown: Result<(), RunError>,
    /// Tearing down the sandbox.
    pub teardown: Result<(), RunError>,
}

impl RunCompletion {
    /// A run that failed before a sandbox existed.
    pub(super) const fn not_started(error: RunError) -> Self {
        Self {
            command: Err(error),
            interrupted: false,
            sidecar_stopped: false,
            shutdown: Ok(()),
            teardown: Ok(()),
        }
    }

    /// One result for the whole run, as a project `firma run` reports it: a
    /// cleanup failure replaces the exit code.
    ///
    /// # Errors
    ///
    /// Returns the run's error, a cleanup error, or both combined.
    pub(crate) fn into_result(self) -> Result<i32, RunError> {
        combine_run_and_teardown_results(
            combine_run_and_teardown_results(self.command, self.shutdown),
            self.teardown,
        )
    }
}

fn combine_run_and_teardown_results(
    run_result: Result<i32, RunError>,
    teardown_result: Result<(), RunError>,
) -> Result<i32, RunError> {
    match (run_result, teardown_result) {
        (Ok(code), Ok(())) => Ok(code),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(run_error), Err(teardown_error)) => Err(RunError::Internal(format!(
            "run failed: {run_error}; teardown failed: {teardown_error}"
        ))),
    }
}

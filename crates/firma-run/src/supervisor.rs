use std::process::Child;
use std::sync::mpsc;
use std::time::Duration;

use crate::error::RunError;

/// Wait for a child process while forwarding Ctrl-C termination.
///
/// # Errors
///
/// Returns an error when child wait operations fail or repeated termination
/// signals are received before process exit.
pub fn wait_with_signal_forwarding(mut child: Child) -> Result<i32, RunError> {
    let (signal_tx, signal_rx) = mpsc::channel::<()>();

    let handler_result = ctrlc::set_handler(move || {
        let _ = signal_tx.send(());
    });

    if let Err(error) = handler_result {
        tracing::warn!(
            "ctrl-c handler could not be installed (continuing without custom forwarding): {error}"
        );
    }

    let mut termination_requested = false;

    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| RunError::Wait(error.to_string()))?
        {
            return Ok(status.code().unwrap_or(1));
        }

        if signal_rx.recv_timeout(Duration::from_millis(100)).is_ok() {
            if termination_requested {
                return Err(RunError::Wait(
                    "received repeated termination signals while child did not exit".to_string(),
                ));
            }

            termination_requested = true;
            if let Err(error) = child.kill() {
                tracing::warn!("failed to terminate child process on signal: {error}");
            }
        }
    }
}

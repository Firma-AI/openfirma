//! Publishes the enforced bundle to the enforcement state file.
//!
//! Swaps hand the latest state to one writer task through a watch channel, so
//! file replacements never reorder and a slow write only skips intermediate
//! states. Publication is observational: failures are logged and never affect
//! enforcement.

use std::path::PathBuf;

use firma_runtime_state::enforcement_state::{self, EnforcementState};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Sender half held by the policy bundle task.
pub type EnforcementStateSender = watch::Sender<Option<EnforcementState>>;

/// Build the state for a bundle swapped in now.
pub fn swapped_now(version: String, ttl_seconds: u32) -> EnforcementState {
    let swapped_at = chrono::Utc::now();
    let expires_at = swapped_at + chrono::Duration::seconds(i64::from(ttl_seconds));
    EnforcementState {
        version,
        ttl_seconds,
        swapped_at: swapped_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
    }
}

/// Create the channel and the writer future for `path`.
pub fn writer(
    path: PathBuf,
    cancel: CancellationToken,
) -> (EnforcementStateSender, impl Future<Output = ()>) {
    let (sender, mut receiver) = watch::channel(None);
    let task = async move {
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                changed = receiver.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
            let Some(state) = receiver.borrow_and_update().clone() else {
                continue;
            };
            let target = path.clone();
            let result =
                tokio::task::spawn_blocking(move || enforcement_state::write(&target, &state))
                    .await;
            let error = match result {
                Ok(Ok(())) => continue,
                Ok(Err(error)) => error.to_string(),
                Err(error) => error.to_string(),
            };
            tracing::warn!(
                path = %path.display(),
                error,
                "enforcement state write failed"
            );
        }
    };
    (sender, task)
}

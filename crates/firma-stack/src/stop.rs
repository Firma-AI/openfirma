//! Firma-facing teardown entry point.
//!
//! A thin wrapper that supplies the firma component names to the generic
//! [`firma_process_orchestrator::stop_components`] teardown.

use std::path::Path;
use std::time::Duration;

use firma_process_orchestrator::{StopOutcome, stop_components};

use crate::error::StackError;
use crate::plan;

/// Stop a running stack.
///
/// # Errors
///
/// Returns pidfile, process-probe, termination, or cleanup errors. Runtime
/// state is retained when probing or hard termination fails, or when the
/// generation is malformed, so cleanup can be retried.
pub fn stop(state_dir: &Path, timeout: Duration) -> Result<StopOutcome, StackError> {
    Ok(stop_components(
        state_dir,
        timeout,
        plan::component_names(),
    )?)
}

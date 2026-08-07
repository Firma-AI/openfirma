//! Firma-facing status entry point.
//!
//! A thin wrapper that supplies the firma component names to the generic
//! [`firma_process_orchestrator::status_components`] probe.

use std::path::Path;

use firma_process_orchestrator::{StackStatus, status_components};

use crate::error::Result;
use crate::plan;

/// Return current stack status.
///
/// # Errors
///
/// Returns errors propagated by the underlying component probes.
pub fn status(state_dir: &Path) -> Result<StackStatus> {
    status_components(state_dir, plan::component_names())
}

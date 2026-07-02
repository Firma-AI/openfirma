mod error;
mod plan;

#[cfg(test)]
mod tests;

pub use error::{VmPlanError, VmPlanResult};
pub use plan::VmPlan;

#[cfg(target_os = "macos")]
pub use plan::FIRMA_VIRTIOFS_TAG;

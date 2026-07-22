//! Runtime status for the control surface.

use std::path::PathBuf;

use crate::control::error::ControlError;

use super::ControlRuntimeState;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlStatus {
    pub policy_dir: Option<PathBuf>,
    pub runtime_state: ControlRuntimeState,
    pub last_error: Option<ControlError>,
}

impl ControlStatus {
    #[must_use]
    pub const fn new(policy_dir: Option<PathBuf>) -> Self {
        Self {
            policy_dir,
            runtime_state: ControlRuntimeState::Starting,
            last_error: None,
        }
    }
}

//! Runtime state for the Policy Control surface.

use std::path::{Path, PathBuf};

use crate::control::state::{ControlRuntimeState, ControlStatus, Pane};

pub struct App {
    should_quit: bool,
    selected_pane: Pane,
    status: ControlStatus,
}

impl App {
    #[must_use]
    pub fn new(policy_dir: Option<PathBuf>) -> Self {
        let status = ControlStatus::new(policy_dir);
        Self {
            should_quit: false,
            selected_pane: Pane::Policies,
            status,
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new(None)
    }
}

impl App {
    #[must_use]
    pub const fn should_quit(&self) -> bool {
        self.should_quit || self.status.runtime_state.is_shutting_down()
    }

    pub const fn quit(&mut self) {
        self.should_quit = true;
    }

    pub fn request_quit(&mut self) {
        self.status.runtime_state = ControlRuntimeState::ShuttingDown;
        self.quit();
    }

    pub const fn mark_running(&mut self) {
        self.status.runtime_state = ControlRuntimeState::Running;
    }

    #[must_use]
    pub const fn selected_pane(&self) -> Pane {
        self.selected_pane
    }

    #[must_use]
    pub const fn status(&self) -> &ControlStatus {
        &self.status
    }

    #[must_use]
    pub fn policy_dir(&self) -> Option<&Path> {
        self.status.policy_dir.as_deref()
    }
}

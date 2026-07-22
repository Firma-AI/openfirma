//! Runtime mode for the control surface.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlRuntimeState {
    Starting,
    Running,
    ShuttingDown,
    Error,
}

impl ControlRuntimeState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::ShuttingDown => "stopping",
            Self::Error => "error",
        }
    }

    #[must_use]
    pub const fn is_shutting_down(self) -> bool {
        matches!(self, Self::ShuttingDown)
    }
}

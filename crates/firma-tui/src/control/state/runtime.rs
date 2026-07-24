//! Runtime mode for the control surface.

/// Lifecycle state used by the runner and status line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlRuntimeState {
    /// The app has been constructed but has not yet processed events.
    Starting,
    /// The app is accepting input and external events normally.
    Running,
    /// Shutdown has been requested and the runner should stop.
    ShuttingDown,
    /// The app has recorded a recoverable status error.
    Error,
}

impl ControlRuntimeState {
    /// Short label rendered in the terminal frame.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::ShuttingDown => "stopping",
            Self::Error => "error",
        }
    }

    /// Returns true once shutdown has started.
    #[must_use]
    pub const fn is_shutting_down(self) -> bool {
        matches!(self, Self::ShuttingDown)
    }
}

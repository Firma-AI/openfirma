//! State slices for the control surface.

mod audit;
mod policy;
mod runtime;
mod status;

pub use audit::{AuditDecision, AuditFilter, AuditRow, AuditState, AuditViewportMode};
pub use policy::{PoliciesState, PolicyRow, PolicyRowStatus};
pub use runtime::ControlRuntimeState;
pub use status::ControlStatus;

/// Top-level pane that currently owns keyboard focus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pane {
    /// Policy list pane.
    Policies,
    /// Audit event pane.
    Audit,
}

impl Pane {
    /// Returns the next pane in the focus cycle.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Policies => Self::Audit,
            Self::Audit => Self::Policies,
        }
    }
}

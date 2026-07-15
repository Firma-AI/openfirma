//! State slices for the control surface.

mod audit;
mod overlay;
mod policy;
mod runtime;
mod status;

pub use audit::{AuditDecision, AuditFilter, AuditRow, AuditViewportMode};
pub use policy::{
    PoliciesState, PolicyRewriteCompletion, PolicyRewriteRequest, PolicyRewriteStart, PolicyRow,
    PolicyRowStatus,
};
pub use runtime::ControlRuntimeState;
pub use status::ControlStatus;

pub use audit::AuditState;
pub use overlay::OverlayState;

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
    pub(crate) const fn next(self) -> Self {
        match self {
            Self::Policies => Self::Audit,
            Self::Audit => Self::Policies,
        }
    }
}

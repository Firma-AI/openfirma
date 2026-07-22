//! Shared state types for Policy Control.

mod runtime;
mod status;

pub use runtime::ControlRuntimeState;
pub use status::ControlStatus;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pane {
    Policies,
    Audit,
}

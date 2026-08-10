//! Generic process-supervision machinery for a local multi-component stack.
//!
//! This crate owns the platform-agnostic supervision core: ordered startup with
//! rollback, generation-fenced runtime state, foreground and detached ownership,
//! fail-closed teardown, and observational status. It is agnostic to which
//! components a stack contains — callers supply ordered component names and
//! produce each complete [`ComponentSpec`] immediately before its spawn.
//!
//! The canonical [lifecycle and ownership model](mod@start) explains how process
//! capabilities, runtime-state authority, foreground supervision, and detached
//! handoff fit together. Public lifecycle types link back to that model.
//!
//! The firma-specific topology (the `[authority, sidecar]` plan and its config
//! parsing) lives in `firma-stack`, which wraps these entry points.

pub mod error;
pub mod shutdown_event;
pub mod start;
pub mod status;
pub mod stop;
mod timeouts;
mod topology;

mod collect;
mod component;
mod detach;
mod platform;
mod readiness;
mod spawn;
mod startup_report;
mod state_lease;
mod supervisor;

pub use component::{
    ChildPublishedTcpContext, ChildPublishedTcpReadiness, ComponentName, ComponentPlanContext,
    ComponentSpec, Readiness,
};
pub use error::{OrchestratorError, StartError};
pub use start::{
    RunningStack, StackHandle, spawn_stack_from_plan, start_detached, start_foreground_from_plan,
    supervise_owned_generation_from_plan,
};
pub use startup_report::publish_startup_report;
pub use state_lease::StackGeneration;
pub use status::{ComponentStatus, StackStatus, State, status_components};
pub use stop::{StopOutcome, stop_components};
pub use timeouts::LifecycleTimeouts;
pub use topology::StackTopology;

//! Generic process supervision for a local multi-component stack.
//!
//! `firma-stack` needs to manage Authority and Sidecar as one unit: start them in
//! dependency order, pass a ready Authority endpoint to Sidecar, roll both back
//! if either fails, supervise them in the foreground or a detached process, and
//! stop and observe the same stack from another process. This crate provides
//! those lifecycle mechanics without knowing which components the stack
//! contains. Callers provide a [`StackTopology`] and build each [`ComponentSpec`]
//! immediately before its spawn.
//!
//! # Mental model
//!
//! A component is more than a PID. Firma starts one direct child, but that
//! process may create descendants. The orchestrator therefore keeps two related
//! responsibilities together:
//!
//! - **collection**: waiting on the direct-child handle after it exits;
//! - **termination**: probing and signalling the platform scope used to govern
//!   the component and its descendants.
//!
//! Firma retains and eventually consumes the non-reconstructable direct-child
//! handle to observe the child's exit and complete collection. A PID or
//! persisted state cannot replace or transfer that handle. On Unix, collection
//! includes waiting on the child so an exited process does not remain a zombie.
//!
//! [`RunningStack`] is the sole in-process owner of those capabilities after
//! startup. [`StackHandle`] is observational. Persisted runtime state is a weaker
//! cross-process coordination record: it lets another process discover and
//! request termination of a stack, but it does not transfer direct-child
//! collection ownership. Platform-specific scope and identity limitations are
//! documented by the internal `platform` module.
//!
//! ```text
//! firma-stack plan
//!       |
//!       v
//! ordered startup -- failure --> explicit rollback
//!       |
//!       v
//! RunningStack ----- shutdown --> terminate, collect, clean state
//!       |
//!       +----------- detach ----> persistent child collector
//!       |
//!       +----------- Drop ------> hard termination, collection handoff,
//!                                  state retained for retry
//!
//! persisted state -- status ----> observation only
//!       |
//!       +----------- stop ------> reconstruct termination targets,
//!                                  then generation-fenced cleanup
//! ```
//!
//! Foreground startup keeps [`RunningStack`] in the caller through supervision
//! and shutdown. Detached startup creates a supervisor that owns the components,
//! so child capabilities never cross a process boundary; the launcher returns
//! only after that ownership is established. [`start`] documents the handoff.
//!
//! # Core invariants
//!
//! - Every spawned direct child is recorded by an owner before another fallible
//!   startup operation.
//! - Normal failures use explicit, reportable rollback. [`Drop`] is a bounded,
//!   fail-closed backstop and does not claim fallible state cleanup succeeded.
//! - Runtime-state mutation is serialized and cleanup is fenced to the current
//!   [`StackGeneration`]. State is removed only after target absence is proven;
//!   the generation lock is the final cleanup commit marker.
//! - Status is observational and grants no process authority.
//!
//! # Lifecycle phases
//!
//! - [`start`] documents ordered startup, ownership transfer, foreground
//!   supervision, and detached handoff.
//! - [`RunningStack`] documents the `shutdown`, `detach`, and `Drop` contract for
//!   an in-process owner.
//! - [`stop`] documents owned and external teardown, including the limits of
//!   reconstructing termination targets from persisted identities.
//! - [`status`] documents observation without ownership.
//! - [`error`] documents how operation and rollback failures are preserved.
//!
//! The Firma-specific `[authority, sidecar]` topology and configuration parsing
//! remain in `firma-stack`, which wraps these generic entry points.

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

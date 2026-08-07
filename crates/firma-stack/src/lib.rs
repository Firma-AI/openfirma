//! Firma-specific stack topology over the generic process orchestrator.
//!
//! This crate knows the concrete `[authority, sidecar]` topology and its unified
//! `firma.toml`. It resolves that topology into a plain [`ComponentSpec`] plan
//! and hands it to [`firma_process_orchestrator`], whose generic supervision
//! machinery is re-exported here so the stable `firma_stack::` API paths are
//! unchanged.

pub mod config;
pub mod start;
pub mod status;
pub mod stop;

mod plan;

pub use config::StackConfig;
pub use plan::resolve_stack_config;
#[doc(hidden)]
pub use start::supervise_owned_generation;
pub use start::{spawn_stack, start};
pub use status::status;
pub use stop::stop;

// Re-export the generic orchestrator surface so every public type the workspace
// uses through `firma_stack::` keeps its path. The firma entry wrappers above
// intentionally shadow the generic `spawn_stack_from_plan`/`start_from_plan`/
// `stop_components`/`status_components` entries with firma-facing signatures.
pub use firma_process_orchestrator::{
    ComponentName, ComponentSpec, ComponentStatus, Result, RunningStack, StackError,
    StackGeneration, StackHandle, StackStatus, StartMode, State, StopOutcome, error,
    shutdown_event,
};

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use firma_process_orchestrator::test_support;

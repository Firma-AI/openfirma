//! Firma-specific authority and sidecar stack lifecycle.
//!
//! This crate knows the concrete `[authority, sidecar]` topology and its unified
//! `firma.toml`, and exposes the lifecycle operations used by the Firma CLI and
//! demo. [`firma_process_orchestrator`] provides the canonical lifecycle and
//! ownership model; this crate supplies the Firma-specific plan to that
//! machinery.

pub mod config;
pub mod error;
pub mod start;
pub mod status;
pub mod stop;

mod plan;

pub use config::StackConfig;
pub use error::StackError;
pub use plan::resolve_stack_config;
pub use start::StartMode;
#[doc(hidden)]
pub use start::supervise_owned_generation;
pub use start::{spawn_stack, start};
pub use status::status;
pub use stop::stop;

#[cfg(unix)]
pub use firma_process_orchestrator::UnixEndpoint;
pub use firma_process_orchestrator::{
    ComponentEndpoint, ComponentHandle, Readiness, RunningStack, StackHandle, StackStatus, State,
    StopOutcome, publish_startup_report,
};
#[doc(hidden)]
pub use firma_process_orchestrator::{StackGeneration, shutdown_event};

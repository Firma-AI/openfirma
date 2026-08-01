//! Startup builders that translate the validated
//! [`SidecarConfig`](crate::config::SidecarConfig) into the runtime
//! subsystems the `main.rs` entry point wires together.
//!
//! Each submodule owns one subsystem so that `main.rs` stays short
//! and readable:
//!
//! - [`pipeline`] — enforcement pipeline + stubs for Authority / Cedar.
//! - [`connector`] — [`ConnectorRegistry`](crate::connector::ConnectorRegistry)
//!   built from the `[connector]` section.
//! - [`credential`] — [`CredentialInjector`](crate::credential::CredentialInjector)
//!   built from the `[credentials]` section.
//! - [`audit`] — audit event builder + sink spawn helpers.
//! - [`interceptor`] — interceptor mode selection and spawn.
//! - [`authority`] — Authority stream clients
//!   (`WatchPolicyBundle` / `WatchRevocations`).

pub mod audit;
pub mod authority;
pub mod capability;
pub mod connector;
pub(crate) mod credential;
pub mod interceptor;
pub mod local_exec;
pub mod log_contract;
pub mod pipeline;

pub use self::audit::{load_audit_event_builder, spawn_audit_sink};
pub use self::authority::spawn_authority_client;
pub use self::capability::{
    CapabilityReloader, build_token_verifier, load_capability_map, seed_into_entry,
};
pub use self::connector::build_connector_registry;
pub use self::interceptor::{SpawnedInterceptor, spawn_interceptor};
pub use self::local_exec::spawn_local_exec_endpoint;
pub use self::log_contract::{
    StartupReport, compute_policy_bundle_version, log_pre_ready_sequence, log_ready_line,
};
pub use self::pipeline::{PipelineRuntime, build_pipeline_runtime};

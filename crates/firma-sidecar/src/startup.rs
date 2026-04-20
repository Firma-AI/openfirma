//! Startup builders that translate the validated
//! [`SidecarConfig`](crate::config::SidecarConfig) into the runtime
//! subsystems the [`main`] function wires together.
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
pub mod connector;
pub mod credential;
pub mod interceptor;
pub mod pipeline;

pub use self::audit::{load_audit_event_builder, spawn_audit_sink};
pub use self::authority::spawn_authority_client;
pub use self::connector::build_connector_registry;
pub use self::interceptor::spawn_interceptor;
pub use self::pipeline::build_pipeline_runtime;

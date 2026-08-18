//! Schema for the `[sidecar]` section of `firma.toml`.
//!
//! Behavior-free representation of the sidecar's configuration. The
//! `firma-sidecar` crate builds its validated configuration types from these
//! structs.
//!
//! Sections are migrated incrementally; only the modules listed here have
//! moved to the schema crate so far.

pub mod infra;
pub mod interceptor;

pub use infra::{
    CaConfig, CredentialConfig, CredentialMode, CredentialTransform, LogConfig, PolicyConfig,
    SidecarMode,
};
pub use interceptor::{ConnectRelayConfig, HttpsMitmConfig, InterceptorConfig, InterceptorMode};

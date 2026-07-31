//! Secret-provider spec types and extraction engine shared by `firma-run`
//! (CLI vault shims) and `firma-sidecar` (HTTP vault MITM interception).
//!
//! Both crates need the same `IntegrationSpec` shapes and the same
//! [`CompiledMatcher`] extraction engine as peers, so this crate exists to
//! avoid two hand-synced copies. `firma-run` resolves `secret_providers`
//! config into these types; `firma-sidecar` reads the HTTP-shaped subset
//! back out of its own synthesized startup config and runs extraction
//! itself against MITM'd response bodies.

mod gateway;
mod matcher;
pub mod non_empty;
mod placeholder;
mod registry;
pub mod spec;

pub use gateway::{GatewayRequest, PlaceholderResult, PushRequest, PushResponse, ResolveRequest};
pub use matcher::{CompiledMatcher, MatcherError};
pub use placeholder::SecretPlaceholder;
pub use registry::IntegrationRegistry;
pub use secrecy::SecretString;
pub use spec::{IntegrationSpec, MatcherRule, MatchingResolution};

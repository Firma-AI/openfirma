//! Secret-provider spec types and extraction engine shared by `firma-run`
//! (CLI vault shims) and `firma-sidecar` (HTTP vault MITM interception).
//!
//! Both crates need the same `IntegrationSpec` shapes and the same
//! [`CompiledMatcher`] extraction engine as peers, so this crate exists to
//! avoid two hand-synced copies. `firma-run` resolves `secret_providers`
//! config into these types; `firma-sidecar` reads the HTTP-shaped subset
//! back out of its own synthesized startup config and runs extraction
//! itself against MITM'd response bodies.

mod matcher;
mod placeholder;
mod secret;

pub use matcher::{CompiledJsonMatcher, CompiledMatcher, CompiledRegexMatcher, MatcherError};
pub use placeholder::SecretPlaceholder;
pub use secret::Secret;

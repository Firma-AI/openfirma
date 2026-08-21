//! Schema for the `[sidecar]` section of `firma.toml`.
//!
//! Behavior-free representation of the sidecar's configuration. The
//! `firma-sidecar` crate builds its validated configuration types from these
//! structs.
//!
//! Sections are migrated incrementally; only the modules listed here have
//! moved to the schema crate so far.

pub mod audit;
pub mod authority;
pub mod capability_seed;
pub mod config;
pub mod connector;
pub mod enforcement;
pub mod infra;
pub mod interceptor;
pub mod local_exec;
pub mod revocation;
pub mod secret_provider;
pub mod tenancy;

pub use audit::{AuditConfig, AuditSink};
pub use authority::{AuthorityConfig, SidecarCredentialsConfig};
pub use capability_seed::CapabilitySeedConfig;
pub use config::SidecarConfig;
pub use connector::{ConnectorConfig, HostConnectorConfig};
pub use enforcement::{
    CapabilityValidationConfig, ConstraintEnforcementConfig, EnforcementConfig, MappingConfig,
    SessionStateBackend,
};
pub use infra::{
    CaConfig, CredentialConfig, CredentialMode, CredentialTransform, LogConfig, PolicyConfig,
    SidecarMode,
};
pub use interceptor::{ConnectRelayConfig, HttpsMitmConfig, InterceptorConfig, InterceptorMode};
pub use local_exec::{DefaultAction, LocalExecConfig};
pub use revocation::RevocationConfig;
pub use secret_provider::{HttpMatcherRuleConfig, HttpSecretProviderConfig};
pub use tenancy::{TenancyConfig, TenancyMode};

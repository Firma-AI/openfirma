//! Schema for the `[sidecar]` section of `firma.toml`.
//!
//! Behavior-free representation of the sidecar's configuration. The
//! `firma-sidecar` crate builds its validated configuration types from these
//! structs. [`SidecarConfig`] is the top-level aggregate; each field maps to a
//! section module below.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{gateway::GatewayConfig, secret_provider::http::HttpSecretProviderConfig};

pub mod audit;
pub mod authority;
pub mod capability_seed;
pub mod connector;
pub mod enforcement;
pub mod infra;
pub mod interceptor;
pub mod local_exec;
pub mod revocation;
pub mod tenancy;

pub use audit::{AuditConfig, AuditSink};
pub use authority::{AuthorityConfig, SidecarCredentials};
pub use capability_seed::CapabilitySeedConfig;
pub use connector::{ConnectorConfig, HostConnectorConfig};
pub use enforcement::{
    CapabilityValidationConfig, ConstraintEnforcementConfig, EnforcementConfig, MappingConfig,
    SessionStateBackend,
};
pub use infra::{
    CaConfig, CredentialConfig, CredentialMode, CredentialTransform, PolicyConfig, SidecarMode,
};
pub use interceptor::{ConnectRelayConfig, HttpsMitmConfig, InterceptorConfig, InterceptorMode};
pub use local_exec::{DefaultAction, LocalExecConfig};
pub use revocation::RevocationConfig;
pub use tenancy::{TenancyConfig, TenancyMode};

/// Top-level sidecar configuration, deserialized from the `[sidecar]` section
/// of `firma.toml`.
///
/// Contains both infrastructure settings (interceptor, policy, CA,
/// credentials) and enforcement-engine settings (mapping, capability
/// validation, constraint enforcement).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarConfig {
    /// Enforcement mode: `"enforce"` (default) or `"monitor"`.
    #[serde(default)]
    pub mode: SidecarMode,
    /// Interceptor settings (mode, listen address or socket path, drain
    /// timeout).
    #[serde(default)]
    pub interceptor: InterceptorConfig,
    /// Policy directory.
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Certificate authority directory.
    #[serde(default)]
    pub ca: CaConfig,
    /// Per-target credential injection entries, keyed by an arbitrary label
    /// (e.g. `[sidecar.credentials.openai]`).
    #[serde(default)]
    pub credentials: HashMap<String, CredentialConfig>,
    /// Outbound connector settings (default timeout + per-host overrides with
    /// rate limits).
    #[serde(default)]
    pub connector: ConnectorConfig,
    /// Background Authority stream client tuning.
    #[serde(default)]
    pub authority: AuthorityConfig,
    /// Intent normalization / mapping rules.
    #[serde(default)]
    pub mapping: MappingConfig,
    /// Capability validation settings.
    #[serde(default)]
    pub capability_validation: CapabilityValidationConfig,
    /// Constraint enforcement settings.
    #[serde(default)]
    pub constraint_enforcement: ConstraintEnforcementConfig,
    /// Revocation cache settings (bloom filter + LRU sizing).
    #[serde(default)]
    pub revocation: RevocationConfig,
    /// Static capability provisioning seed files.
    #[serde(default)]
    pub capability_seed: CapabilitySeedConfig,
    /// Audit event emitter settings.
    #[serde(default)]
    pub audit: AuditConfig,
    /// Local-exec governance endpoint configuration. When absent, the
    /// local-exec endpoint is not started.
    #[serde(default)]
    pub local_exec: Option<LocalExecConfig>,
    /// Tenancy settings (agent isolation mode).
    #[serde(default)]
    pub tenancy: TenancyConfig,
    /// HTTP secret-provider registry for MITM interception.
    #[serde(default)]
    pub http_secret_providers: Vec<HttpSecretProviderConfig>,
    /// Secret-gateway client tuning.
    #[serde(default)]
    pub secret_gateway: GatewayConfig,
}

//! The top-level `[sidecar]` configuration representation.
//!
//! Behavior-free aggregate of every sidecar section. `firma-sidecar`
//! deserializes this type and builds its validated configuration from it.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::gateway::GatewayClientConfig;

use super::audit::AuditConfig;
use super::authority::AuthorityConfig;
use super::capability_seed::CapabilitySeedConfig;
use super::connector::ConnectorConfig;
use super::enforcement::EnforcementConfig;
use super::infra::{CaConfig, CredentialConfig, LogConfig, PolicyConfig, SidecarMode};
use super::interceptor::InterceptorConfig;
use super::local_exec::LocalExecConfig;
use super::revocation::RevocationConfig;
use super::secret_provider::HttpSecretProviderConfig;
use super::tenancy::TenancyConfig;

/// Top-level sidecar configuration, deserialized from the `[sidecar]` section
/// of `firma.toml`.
///
/// Contains both infrastructure settings (interceptor, policy, CA, logging,
/// credentials) and enforcement-engine settings (mapping, capability
/// validation, constraint enforcement) via a flattened [`EnforcementConfig`].
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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
    /// Log settings (level only; file/filter come from CLI args).
    #[serde(default)]
    pub log: LogConfig,
    /// Per-target credential injection entries, keyed by an arbitrary label
    /// (e.g. `[credentials.openai]`).
    #[serde(default)]
    pub credentials: HashMap<String, CredentialConfig>,
    /// Outbound connector settings (default timeout + per-host overrides with
    /// rate limits).
    #[serde(default)]
    pub connector: ConnectorConfig,
    /// Background Authority stream client tuning.
    #[serde(default)]
    pub authority: AuthorityConfig,
    /// Enforcement engine settings (mapping rules, capability validation,
    /// constraint enforcement), flattened to top-level TOML tables.
    #[serde(flatten)]
    pub enforcement: EnforcementConfig,
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
    pub secret_gateway: GatewayClientConfig,
}

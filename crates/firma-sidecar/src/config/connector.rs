//! Connector configuration parsed from the `[connector]` TOML section.
//!
//! Describes the default dispatch timeout applied to unconfigured hosts (the
//! registry fallback) and the list of per-host overrides. Each host override
//! declares the timeout plus the token-bucket rate-limit parameters consumed by
//! the [`GenericHttpConnector`](crate::connector::provider::GenericHttpConnector).

use std::collections::HashSet;

use firma_config_schema::sidecar::connector::{
    ConnectorConfig as SchemaConnectorConfig, HostConnectorConfig as SchemaHostConnectorConfig,
};

/// Validated top-level connector configuration.
#[derive(Debug, Clone)]
pub struct ConnectorConfig {
    /// Timeout in milliseconds applied to the registry default.
    pub default_timeout_ms: u64,
    /// Per-host overrides.
    pub hosts: Vec<HostConnectorConfig>,
}

/// Validated per-host connector configuration.
#[derive(Debug, Clone)]
pub struct HostConnectorConfig {
    /// Target host this entry applies to.
    pub host: String,
    /// Sustained refill rate, in requests per second.
    pub rps: u32,
    /// Token-bucket capacity.
    pub burst: u32,
    /// Dispatch timeout in milliseconds applied to this host.
    pub timeout_ms: u64,
}

/// Error validating a [`ConnectorConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorConfigError {
    /// The registry-default timeout was zero.
    #[error("connector.default_timeout_ms must be > 0")]
    ZeroDefaultTimeout,
    /// A per-host entry was invalid.
    #[error("connector.hosts[{host}]: {source}")]
    Host {
        /// The offending host.
        host: String,
        /// The per-host validation failure.
        #[source]
        source: HostConnectorConfigError,
    },
    /// Two host entries targeted the same host.
    #[error("connector.hosts: duplicate entry for host '{host}'")]
    DuplicateHost {
        /// The duplicated host.
        host: String,
    },
}

/// Error validating a [`HostConnectorConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostConnectorConfigError {
    /// `host` was empty.
    #[error("host must not be empty")]
    EmptyHost,
    /// `timeout_ms` was zero.
    #[error("timeout_ms must be > 0")]
    ZeroTimeout,
    /// `rps` was zero.
    #[error("rps must be > 0")]
    ZeroRps,
    /// `burst` was zero.
    #[error("burst must be > 0")]
    ZeroBurst,
}

impl Default for ConnectorConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: 30_000,
            hosts: Vec::new(),
        }
    }
}

impl TryFrom<SchemaHostConnectorConfig> for HostConnectorConfig {
    type Error = HostConnectorConfigError;

    fn try_from(schema: SchemaHostConnectorConfig) -> Result<Self, Self::Error> {
        if schema.host.trim().is_empty() {
            return Err(HostConnectorConfigError::EmptyHost);
        }
        if schema.timeout_ms == 0 {
            return Err(HostConnectorConfigError::ZeroTimeout);
        }
        if schema.rps == 0 {
            return Err(HostConnectorConfigError::ZeroRps);
        }
        if schema.burst == 0 {
            return Err(HostConnectorConfigError::ZeroBurst);
        }
        Ok(Self {
            host: schema.host,
            rps: schema.rps,
            burst: schema.burst,
            timeout_ms: schema.timeout_ms,
        })
    }
}

impl TryFrom<SchemaConnectorConfig> for ConnectorConfig {
    type Error = ConnectorConfigError;

    fn try_from(schema: SchemaConnectorConfig) -> Result<Self, Self::Error> {
        if schema.default_timeout_ms == 0 {
            return Err(ConnectorConfigError::ZeroDefaultTimeout);
        }
        let mut seen: HashSet<String> = HashSet::with_capacity(schema.hosts.len());
        let mut hosts = Vec::with_capacity(schema.hosts.len());
        for host in schema.hosts {
            let host_label = host.host.clone();
            let validated =
                HostConnectorConfig::try_from(host).map_err(|source| ConnectorConfigError::Host {
                    host: host_label.clone(),
                    source,
                })?;
            if !seen.insert(validated.host.clone()) {
                return Err(ConnectorConfigError::DuplicateHost { host: validated.host });
            }
            hosts.push(validated);
        }
        Ok(Self {
            default_timeout_ms: schema.default_timeout_ms,
            hosts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(host: &str, rps: u32, burst: u32, timeout_ms: u64) -> SchemaHostConnectorConfig {
        SchemaHostConnectorConfig {
            host: host.to_string(),
            rps,
            burst,
            timeout_ms,
        }
    }

    fn schema(default_timeout_ms: u64, hosts: Vec<SchemaHostConnectorConfig>) -> SchemaConnectorConfig {
        SchemaConnectorConfig {
            default_timeout_ms,
            hosts,
        }
    }

    #[test]
    fn default_config_is_valid() {
        let d = ConnectorConfig::default();
        assert!(ConnectorConfig::try_from(schema(d.default_timeout_ms, Vec::new())).is_ok());
    }

    #[test]
    fn zero_default_timeout_rejected() {
        assert!(matches!(
            ConnectorConfig::try_from(schema(0, Vec::new())),
            Err(ConnectorConfigError::ZeroDefaultTimeout)
        ));
    }

    #[test]
    fn zero_host_timeout_rejected() {
        assert!(matches!(
            ConnectorConfig::try_from(schema(30_000, vec![host("api.example.com", 10, 5, 0)])),
            Err(ConnectorConfigError::Host {
                source: HostConnectorConfigError::ZeroTimeout,
                ..
            })
        ));
    }

    #[test]
    fn zero_rps_rejected() {
        assert!(matches!(
            ConnectorConfig::try_from(schema(30_000, vec![host("api.example.com", 0, 5, 10_000)])),
            Err(ConnectorConfigError::Host {
                source: HostConnectorConfigError::ZeroRps,
                ..
            })
        ));
    }

    #[test]
    fn zero_burst_rejected() {
        assert!(matches!(
            ConnectorConfig::try_from(schema(30_000, vec![host("api.example.com", 10, 0, 10_000)])),
            Err(ConnectorConfigError::Host {
                source: HostConnectorConfigError::ZeroBurst,
                ..
            })
        ));
    }

    #[test]
    fn empty_host_rejected() {
        assert!(matches!(
            ConnectorConfig::try_from(schema(30_000, vec![host("", 10, 5, 10_000)])),
            Err(ConnectorConfigError::Host {
                source: HostConnectorConfigError::EmptyHost,
                ..
            })
        ));
    }

    #[test]
    fn duplicate_host_rejected() {
        assert!(matches!(
            ConnectorConfig::try_from(schema(
                30_000,
                vec![
                    host("api.example.com", 10, 5, 10_000),
                    host("api.example.com", 20, 10, 5_000),
                ],
            )),
            Err(ConnectorConfigError::DuplicateHost { .. })
        ));
    }

    #[test]
    fn valid_config_converts() {
        let config = ConnectorConfig::try_from(schema(
            15_000,
            vec![
                host("api.openai.com", 60, 10, 60_000),
                host("api.internal", 1_000, 100, 5_000),
            ],
        ))
        .expect("valid");
        assert_eq!(config.default_timeout_ms, 15_000);
        assert_eq!(config.hosts.len(), 2);
        assert_eq!(config.hosts[0].host, "api.openai.com");
        assert_eq!(config.hosts[1].timeout_ms, 5_000);
    }
}

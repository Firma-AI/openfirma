//! Connector configuration parsed from the `[connector]` TOML
//! section.
//!
//! Describes the default dispatch timeout applied to unconfigured
//! hosts (the registry fallback) and the list of per-host overrides.
//! Each host override declares the timeout plus the token-bucket
//! rate-limit parameters consumed by the
//! [`GenericHttpConnector`](crate::connector::provider::GenericHttpConnector).

use serde::Deserialize;

/// Default dispatch timeout (30s) applied to the registry default
/// [`GenericHttpConnector`].
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Top-level connector configuration.
///
/// Missing section or empty host list means every target uses the
/// registry default (30s timeout, no rate limit).
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectorConfig {
    /// Timeout in milliseconds applied to the registry default.
    #[serde(default = "default_timeout_ms")]
    pub default_timeout_ms: u64,
    /// Per-host overrides. Each entry becomes a
    /// [`GenericHttpConnector`](crate::connector::provider::GenericHttpConnector)
    /// registered under its host string.
    #[serde(default)]
    pub hosts: Vec<HostConnectorConfig>,
}

impl Default for ConnectorConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: default_timeout_ms(),
            hosts: Vec::new(),
        }
    }
}

impl ConnectorConfig {
    /// Validates the section.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message identifying the first invalid
    /// field: zero timeout, duplicate host, or invalid rate-limit
    /// parameters.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.default_timeout_ms == 0 {
            return Err("connector.default_timeout_ms must be > 0".into());
        }
        let mut seen: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(self.hosts.len());
        for host in &self.hosts {
            host.validate()
                .map_err(|e| format!("connector.hosts[{}]: {e}", host.host))?;
            if !seen.insert(host.host.as_str()) {
                return Err(format!(
                    "connector.hosts: duplicate entry for host '{}'",
                    host.host
                ));
            }
        }
        Ok(())
    }
}

/// Per-host connector configuration.
///
/// All fields are required for explicit host entries — the intent is
/// that operators state their per-host constraints explicitly rather
/// than inherit global defaults that could silently change.
#[derive(Debug, Clone, Deserialize)]
pub struct HostConnectorConfig {
    /// Target host this entry applies to (exact match against the
    /// host portion of the envelope resource).
    pub host: String,
    /// Sustained refill rate for the token-bucket rate limiter, in
    /// requests per second.
    pub rps: u32,
    /// Token-bucket capacity. Bounds the instantaneous burst.
    pub burst: u32,
    /// Dispatch timeout in milliseconds applied to this host.
    pub timeout_ms: u64,
}

impl HostConnectorConfig {
    fn validate(&self) -> Result<(), String> {
        if self.host.trim().is_empty() {
            return Err("host must not be empty".into());
        }
        if self.timeout_ms == 0 {
            return Err("timeout_ms must be > 0".into());
        }
        if self.rps == 0 {
            return Err("rps must be > 0".into());
        }
        if self.burst == 0 {
            return Err("burst must be > 0".into());
        }
        Ok(())
    }
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = ConnectorConfig::default();
        assert_eq!(config.default_timeout_ms, DEFAULT_TIMEOUT_MS);
        assert!(config.hosts.is_empty());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_zero_default_timeout_rejected() {
        let config = ConnectorConfig {
            default_timeout_ms: 0,
            hosts: Vec::new(),
        };
        let err = config.validate().expect_err("zero timeout must error");
        assert!(err.contains("default_timeout_ms"));
    }

    #[test]
    fn test_zero_host_timeout_rejected() {
        let config = ConnectorConfig {
            default_timeout_ms: 30_000,
            hosts: vec![HostConnectorConfig {
                host: "api.example.com".to_string(),
                rps: 10,
                burst: 5,
                timeout_ms: 0,
            }],
        };
        let err = config.validate().expect_err("zero timeout must error");
        assert!(err.contains("timeout_ms"));
    }

    #[test]
    fn test_zero_rps_rejected() {
        let config = ConnectorConfig {
            default_timeout_ms: 30_000,
            hosts: vec![HostConnectorConfig {
                host: "api.example.com".to_string(),
                rps: 0,
                burst: 5,
                timeout_ms: 10_000,
            }],
        };
        let err = config.validate().expect_err("zero rps must error");
        assert!(err.contains("rps"));
    }

    #[test]
    fn test_zero_burst_rejected() {
        let config = ConnectorConfig {
            default_timeout_ms: 30_000,
            hosts: vec![HostConnectorConfig {
                host: "api.example.com".to_string(),
                rps: 10,
                burst: 0,
                timeout_ms: 10_000,
            }],
        };
        let err = config.validate().expect_err("zero burst must error");
        assert!(err.contains("burst"));
    }

    #[test]
    fn test_empty_host_rejected() {
        let config = ConnectorConfig {
            default_timeout_ms: 30_000,
            hosts: vec![HostConnectorConfig {
                host: String::new(),
                rps: 10,
                burst: 5,
                timeout_ms: 10_000,
            }],
        };
        let err = config.validate().expect_err("empty host must error");
        assert!(err.contains("host"));
    }

    #[test]
    fn test_duplicate_host_rejected() {
        let config = ConnectorConfig {
            default_timeout_ms: 30_000,
            hosts: vec![
                HostConnectorConfig {
                    host: "api.example.com".to_string(),
                    rps: 10,
                    burst: 5,
                    timeout_ms: 10_000,
                },
                HostConnectorConfig {
                    host: "api.example.com".to_string(),
                    rps: 20,
                    burst: 10,
                    timeout_ms: 5_000,
                },
            ],
        };
        let err = config.validate().expect_err("duplicate host must error");
        assert!(err.contains("duplicate"));
    }

    #[test]
    fn test_toml_deserialization() {
        let toml_str = r#"
default_timeout_ms = 15000

[[hosts]]
host = "api.openai.com"
rps = 60
burst = 10
timeout_ms = 60000

[[hosts]]
host = "api.internal"
rps = 1000
burst = 100
timeout_ms = 5000
"#;
        let config: ConnectorConfig = toml::from_str(toml_str).expect("parse should succeed");
        assert!(config.validate().is_ok());
        assert_eq!(config.default_timeout_ms, 15_000);
        assert_eq!(config.hosts.len(), 2);
        assert_eq!(config.hosts[0].host, "api.openai.com");
        assert_eq!(config.hosts[0].rps, 60);
        assert_eq!(config.hosts[1].timeout_ms, 5_000);
    }

    #[test]
    fn test_toml_default_when_missing_section() {
        let config: ConnectorConfig = toml::from_str("").expect("empty input parses");
        assert_eq!(config.default_timeout_ms, DEFAULT_TIMEOUT_MS);
        assert!(config.hosts.is_empty());
    }
}

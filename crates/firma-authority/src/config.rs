use serde::Deserialize;
use std::path::PathBuf;

/// Authority configuration loaded from TOML file and/or environment variables.
///
/// Environment variables take precedence over TOML values and use the
/// `FIRMA_AUTHORITY_` prefix (e.g., `FIRMA_AUTHORITY_LISTEN_ADDR`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthorityConfig {
    /// gRPC listen address (default: `[::1]:50051`).
    pub listen_addr: String,
    /// Directory containing `.cedar` policy files.
    pub policy_dir: PathBuf,
    /// Optional path to the Cedar schema file.
    /// Overrides `policy_dir/schema.cedarschema`. When unset, falls back to
    /// the schema found in `policy_dir`, then to the embedded canonical schema.
    pub schema_path: Option<PathBuf>,
    /// Path to the revocation file (one token ID per line).
    pub revocation_file: PathBuf,
    /// Maximum token TTL in seconds (default: 3600).
    pub max_ttl_seconds: i32,
    /// Path to the Ed25519 signing key file (64-byte raw or PEM).
    pub key_file: PathBuf,
    /// Log level filter (default: `info`).
    pub log_level: String,
    /// Policy bundle TTL advertised to sidecars in seconds (default: 30).
    pub bundle_ttl_seconds: u32,
}

impl AuthorityConfig {
    /// Load configuration by merging an optional TOML file with environment variable overrides.
    ///
    /// # Errors
    ///
    /// Returns an error if the config file exists but cannot be parsed.
    pub fn load(config_path: Option<&PathBuf>) -> Result<AuthorityConfig, ConfigError> {
        let mut config = if let Some(path) = config_path {
            let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::IoError {
                path: path.clone(),
                reason: e.to_string(),
            })?;
            toml::from_str::<AuthorityConfig>(&contents).map_err(|e| ConfigError::ParseError {
                path: path.clone(),
                reason: e.to_string(),
            })?
        } else {
            AuthorityConfig::default()
        };

        // Environment variable overrides (FIRMA_AUTHORITY_ prefix)
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_LISTEN_ADDR") {
            config.listen_addr = v;
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_POLICY_DIR") {
            config.policy_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_SCHEMA_PATH") {
            config.schema_path = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_REVOCATION_FILE") {
            config.revocation_file = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_MAX_TTL_SECONDS")
            && let Ok(n) = v.parse::<i32>()
        {
            config.max_ttl_seconds = n;
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_KEY_FILE") {
            config.key_file = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_LOG_LEVEL") {
            config.log_level = v;
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_BUNDLE_TTL_SECONDS")
            && let Ok(n) = v.parse::<u32>()
        {
            config.bundle_ttl_seconds = n;
        }

        Ok(config)
    }
}

impl Default for AuthorityConfig {
    fn default() -> Self {
        Self {
            listen_addr: "[::1]:50051".to_string(),
            policy_dir: PathBuf::from("policies"),
            schema_path: None,
            revocation_file: PathBuf::from("revocations.txt"),
            max_ttl_seconds: 3600,
            key_file: PathBuf::from("firma-authority.key"),
            log_level: "info".to_string(),
            bundle_ttl_seconds: 30,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {reason}")]
    IoError { path: PathBuf, reason: String },
    #[error("failed to parse config file {path}: {reason}")]
    ParseError { path: PathBuf, reason: String },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sensible_values() {
        let config = AuthorityConfig::default();
        assert_eq!(config.listen_addr, "[::1]:50051");
        assert_eq!(config.max_ttl_seconds, 3600);
        assert_eq!(config.bundle_ttl_seconds, 30);
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn load_config_defaults_when_no_file() {
        let config = AuthorityConfig::load(None);
        assert!(config.is_ok());
        let config = config.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(config.listen_addr, "[::1]:50051");
    }

    #[test]
    fn load_config_nonexistent_file_errors() {
        let path = PathBuf::from("/nonexistent/config.toml");
        let result = AuthorityConfig::load(Some(&path));
        assert!(result.is_err());
    }

    #[test]
    fn toml_deserialization() {
        let toml_str = r#"
listen_addr = "0.0.0.0:9090"
policy_dir = "/etc/firma/policies"
max_ttl_seconds = 1800
"#;
        let config: AuthorityConfig = toml::from_str(toml_str).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(config.listen_addr, "0.0.0.0:9090");
        assert_eq!(config.max_ttl_seconds, 1800);
        // Defaults for unspecified fields
        assert_eq!(config.bundle_ttl_seconds, 30);
    }
}

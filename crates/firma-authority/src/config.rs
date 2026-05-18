use serde::Deserialize;
use std::path::PathBuf;

/// Sentinel: unset `policy_dir`.
pub(crate) const DEFAULT_POLICY_DIR: &str = "policies/";
/// Sentinel: unset `issuance_policy_dir`.
pub(crate) const DEFAULT_ISSUANCE_POLICY_DIR: &str = "issuance-policies/";
/// Sentinel: unset `key_file`.
pub(crate) const DEFAULT_KEY_FILE: &str = "firma-authority.key";

/// Authority configuration loaded from TOML file and/or environment variables.
///
/// Environment variables take precedence over TOML values and use the
/// `FIRMA_AUTHORITY_` prefix (e.g., `FIRMA_AUTHORITY_LISTEN_ADDR`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthorityConfig {
    /// gRPC listen address (default: `[::1]:50051`).
    pub listen_addr: String,
    /// Directory containing `.cedar` policy files streamed to sidecars for enforcement.
    pub policy_dir: PathBuf,
    /// Directory containing `.cedar` policy files used to gate capability issuance.
    ///
    /// The Authority evaluates issuance requests against this policy set.
    /// `policy_dir` is still streamed to sidecars for enforcement. This lets
    /// issuance policies differ from enforcement policies (e.g. permit issuance
    /// of `communication.external.send` while the sidecar's enforcement policy
    /// forbids the actual call).
    pub issuance_policy_dir: PathBuf,
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
    /// Authority TLS configuration.
    ///
    /// Uses `tls_cert_path` + `tls_key_path` keys in TOML via flattening.
    #[serde(flatten)]
    pub tls: AuthorityTlsConfig,
}

/// TLS configuration for the Authority gRPC server.
///
/// Both values are required together to enable TLS.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthorityTlsConfig {
    /// Path to the TLS certificate file (PEM). Must be set together with
    /// `tls_key_path`.
    #[serde(default)]
    pub tls_cert_path: Option<PathBuf>,
    /// Path to the TLS private key file (PEM). Must be set together with
    /// `tls_cert_path`.
    #[serde(default)]
    pub tls_key_path: Option<PathBuf>,
}

/// Fully validated TLS identity paths.
#[derive(Debug, Clone)]
pub struct TlsIdentityPaths {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl AuthorityConfig {
    /// Load configuration by merging an optional TOML file with environment variable overrides.
    ///
    /// # Errors
    ///
    /// Returns an error if the config file exists but cannot be parsed.
    pub fn load(config_path: Option<&PathBuf>) -> Result<Self, ConfigError> {
        let mut config = Self::parse_file(config_path)?;
        config.apply_env_overrides();
        Ok(config)
    }

    /// Parse the TOML file (or take defaults) without env overrides.
    fn parse_file(config_path: Option<&PathBuf>) -> Result<Self, ConfigError> {
        match config_path {
            Some(path) => {
                let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::IoError {
                    path: path.clone(),
                    reason: e.to_string(),
                })?;
                toml::from_str::<Self>(&contents).map_err(|e| ConfigError::ParseError {
                    path: path.clone(),
                    reason: e.to_string(),
                })
            }
            None => Ok(Self::default()),
        }
    }

    /// Apply `FIRMA_AUTHORITY_`-prefixed env overrides verbatim.
    ///
    /// Called *after* [`Self::rebase_defaults`] so an operator-supplied
    /// path env var is preserved exactly as written (no re-basing of a
    /// relative value against the config dir).
    fn apply_env_overrides(&mut self) {
        let config = self;
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_LISTEN_ADDR") {
            config.listen_addr = v;
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_POLICY_DIR") {
            config.policy_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_ISSUANCE_POLICY_DIR") {
            config.issuance_policy_dir = PathBuf::from(v);
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
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_TLS_CERT_PATH") {
            config.tls.tls_cert_path = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_TLS_KEY_PATH") {
            config.tls.tls_key_path = Some(PathBuf::from(v));
        }
    }

    /// Parse a resolved config file (flat or `[authority]`-sectioned via
    /// the caller), re-base relative paths against `config_dir`, then
    /// apply env overrides last so they win verbatim.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::IoError`] / [`ConfigError::ParseError`].
    pub fn load_resolved(
        file: &std::path::Path,
        config_dir: &std::path::Path,
    ) -> Result<Self, ConfigError> {
        let mut config = Self::parse_file(Some(&file.to_path_buf()))?;
        config.rebase_defaults(config_dir);
        config.apply_env_overrides();
        Ok(config)
    }

    /// Returns TLS identity paths when both TLS fields are configured.
    ///
    /// # Errors
    ///
    /// Returns an error if only one of `tls_cert_path` / `tls_key_path` is set.
    pub fn tls_identity_paths(&self) -> Result<Option<TlsIdentityPaths>, String> {
        match (&self.tls.tls_cert_path, &self.tls.tls_key_path) {
            (Some(cert_path), Some(key_path)) => Ok(Some(TlsIdentityPaths {
                cert_path: cert_path.clone(),
                key_path: key_path.clone(),
            })),
            (None, None) => Ok(None),
            _ => Err("tls_cert_path and tls_key_path must both be set or both be unset".into()),
        }
    }

    /// Re-base every relative resource path against `config_dir`;
    /// absolute paths are left untouched. No default-name sentinel
    /// check — relative always means "relative to the config file's
    /// directory" for consistency.
    ///
    /// `revocation_file` is intentionally excluded — state-managed.
    /// Env overrides are applied *after* this (see
    /// [`Self::apply_env_overrides`]) so an env-supplied path is kept
    /// exactly as the operator wrote it.
    pub fn rebase_defaults(&mut self, config_dir: &std::path::Path) {
        let rebase = |p: &mut PathBuf| {
            // Empty is left for the validator to reject.
            if !p.as_os_str().is_empty() && p.is_relative() {
                *p = config_dir.join(&*p);
            }
        };
        rebase(&mut self.policy_dir);
        rebase(&mut self.issuance_policy_dir);
        rebase(&mut self.key_file);
        if let Some(cert_path) = self.tls.tls_cert_path.as_mut()
            && !cert_path.as_os_str().is_empty()
            && cert_path.is_relative()
        {
            *cert_path = config_dir.join(&*cert_path);
        }
        if let Some(key_path) = self.tls.tls_key_path.as_mut()
            && !key_path.as_os_str().is_empty()
            && key_path.is_relative()
        {
            *key_path = config_dir.join(&*key_path);
        }
        if let Some(schema_path) = self.schema_path.as_mut()
            && !schema_path.as_os_str().is_empty()
            && schema_path.is_relative()
        {
            *schema_path = config_dir.join(&*schema_path);
        }
    }
}

impl Default for AuthorityConfig {
    fn default() -> Self {
        Self {
            listen_addr: "[::1]:50051".to_string(),
            policy_dir: PathBuf::from(DEFAULT_POLICY_DIR),
            issuance_policy_dir: PathBuf::from(DEFAULT_ISSUANCE_POLICY_DIR),
            schema_path: None,
            revocation_file: PathBuf::from("revocations.txt"),
            max_ttl_seconds: 3600,
            key_file: PathBuf::from(DEFAULT_KEY_FILE),
            log_level: "info".to_string(),
            bundle_ttl_seconds: 30,
            tls: AuthorityTlsConfig::default(),
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
    fn rebase_rewrites_defaults_not_revocation() {
        let mut c = AuthorityConfig::default();
        c.rebase_defaults(std::path::Path::new("/cfg"));
        assert_eq!(c.policy_dir, PathBuf::from("/cfg/policies"));
        assert_eq!(
            c.issuance_policy_dir,
            PathBuf::from("/cfg/issuance-policies")
        );
        assert_eq!(c.key_file, PathBuf::from("/cfg/firma-authority.key"));
        assert_eq!(c.revocation_file, PathBuf::from("revocations.txt"));
    }

    #[test]
    fn rebase_rewrites_relative_non_default_paths() {
        // Consistency: a relative operator-set path is config-relative,
        // not cwd-relative, even though it is not the default sentinel.
        let mut c = AuthorityConfig {
            policy_dir: PathBuf::from("custom/policies"),
            schema_path: Some(PathBuf::from("schema.cedarschema")),
            ..AuthorityConfig::default()
        };
        c.rebase_defaults(std::path::Path::new("/cfg"));
        assert_eq!(c.policy_dir, PathBuf::from("/cfg/custom/policies"));
        assert_eq!(
            c.schema_path,
            Some(PathBuf::from("/cfg/schema.cedarschema"))
        );
    }

    #[test]
    fn rebase_skips_empty_path_for_validator() {
        let mut c = AuthorityConfig {
            policy_dir: PathBuf::new(),
            ..AuthorityConfig::default()
        };
        c.rebase_defaults(std::path::Path::new("/cfg"));
        assert_eq!(c.policy_dir, PathBuf::new());
    }

    #[test]
    fn rebase_preserves_explicit_policy_dir() {
        let mut c = AuthorityConfig {
            policy_dir: PathBuf::from("/explicit"),
            ..AuthorityConfig::default()
        };
        c.rebase_defaults(std::path::Path::new("/cfg"));
        assert_eq!(c.policy_dir, PathBuf::from("/explicit"));
    }

    #[test]
    fn load_from_resolved_applies_rebase() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("firma.toml");
        std::fs::write(
            &p,
            "max_ttl_seconds = 1800\ntls_cert_path = \"authority.crt\"\ntls_key_path = \"authority.key\"\n",
        )
        .unwrap();
        let c = AuthorityConfig::load_resolved(&p, tmp.path()).unwrap();
        assert_eq!(c.max_ttl_seconds, 1800);
        assert_eq!(c.policy_dir, tmp.path().join("policies"));
        assert_eq!(c.tls.tls_cert_path, Some(tmp.path().join("authority.crt")));
        assert_eq!(c.tls.tls_key_path, Some(tmp.path().join("authority.key")));
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

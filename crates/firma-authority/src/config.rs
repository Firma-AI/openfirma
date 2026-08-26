use firma_config_schema::authority as schema;
use std::path::{Path, PathBuf};

/// Authority configuration loaded from TOML file and/or environment variables.
///
/// The field shape and default values live in
/// [`firma_config_schema::authority::AuthorityConfig`]; this type adds the
/// Authority's behavior: path re-basing against the config directory and
/// `FIRMA_AUTHORITY_`-prefixed environment overrides, which take precedence
/// over TOML values (e.g., `FIRMA_AUTHORITY_LISTEN_ADDR`).
///
/// Fields are private: the only way to obtain an `AuthorityConfig` is
/// [`Default`] (a valid, TLS-free configuration) or
/// [`AuthorityConfigBuilder::build`], which validates cross-field TLS
/// invariants. An invalid `AuthorityConfig` therefore cannot be constructed;
/// read access is through the accessors below.
///
/// This type is deliberately not `Serialize`: the wire representation is
/// [`schema::AuthorityConfig`], obtained via [`AuthorityConfig::to_schema`].
#[derive(Debug, Clone)]
pub struct AuthorityConfig {
    /// gRPC listen address (default: `[::1]:50051`).
    pub(crate) listen_addr: String,
    /// Directory containing `.cedar` policy files streamed to sidecars for enforcement.
    pub(crate) policy_dir: PathBuf,
    /// Directory containing `.cedar` policy files used to gate capability issuance.
    ///
    /// The Authority evaluates issuance requests against this policy set.
    /// `policy_dir` is still streamed to sidecars for enforcement. This lets
    /// issuance policies differ from enforcement policies (e.g. permit issuance
    /// of `communication.external.send` while the sidecar's enforcement policy
    /// forbids the actual call).
    pub(crate) issuance_policy_dir: PathBuf,
    /// Optional path to the Cedar schema file.
    /// Overrides `policy_dir/schema.cedarschema`. When unset, falls back to
    /// the schema found in `policy_dir`, then to the embedded canonical schema.
    pub(crate) schema_path: Option<PathBuf>,
    /// Path to the revocation file (one token ID per line).
    pub(crate) revocation_file: PathBuf,
    /// Maximum token TTL in seconds (default: 3600).
    pub(crate) max_ttl_seconds: i32,
    /// Path to the Ed25519 signing key file (64-byte raw or PEM).
    pub(crate) key_file: PathBuf,
    /// Log level filter (default: `info`).
    log_level: String,
    /// Policy bundle TTL advertised to sidecars in seconds (default: 30).
    pub(crate) bundle_ttl_seconds: u32,
    /// Authority TLS configuration.
    pub(crate) tls: AuthorityTlsConfig,
}

/// Read accessors. Construction stays gated behind [`AuthorityConfigBuilder`],
/// so these expose fields for consumers without letting them build or mutate an
/// unvalidated config.
impl AuthorityConfig {
    /// gRPC listen address.
    #[must_use]
    pub fn listen_addr(&self) -> &str {
        &self.listen_addr
    }

    /// Directory of `.cedar` policies streamed to sidecars for enforcement.
    #[must_use]
    pub fn policy_dir(&self) -> &Path {
        &self.policy_dir
    }

    /// Optional override path to the Cedar schema file.
    #[must_use]
    pub fn schema_path(&self) -> Option<&Path> {
        self.schema_path.as_deref()
    }

    /// Path to the revocation file.
    #[must_use]
    pub fn revocation_file(&self) -> &Path {
        &self.revocation_file
    }

    /// Maximum token TTL in seconds.
    #[must_use]
    pub fn max_ttl_seconds(&self) -> i32 {
        self.max_ttl_seconds
    }

    /// Path to the Ed25519 signing key file.
    #[must_use]
    pub fn key_file(&self) -> &Path {
        &self.key_file
    }

    /// Policy bundle TTL advertised to sidecars in seconds.
    #[must_use]
    pub fn bundle_ttl_seconds(&self) -> u32 {
        self.bundle_ttl_seconds
    }

    /// TLS configuration.
    #[must_use]
    pub fn tls(&self) -> &AuthorityTlsConfig {
        &self.tls
    }
}

/// TLS configuration for the Authority gRPC server.
///
/// Both values are required together to enable TLS. The corresponding wire keys
/// (`tls_cert_path`, `tls_key_path`, …) live on [`schema::AuthorityTlsConfig`];
/// these fields are the validated in-memory representation.
#[derive(Debug, Clone, Default)]
pub struct AuthorityTlsConfig {
    /// Path to the TLS certificate file (PEM). Must be set together with `key`.
    pub(crate) cert: Option<PathBuf>,
    /// Path to the TLS private key file (PEM). Must be set together with `cert`.
    pub(crate) key: Option<PathBuf>,
    /// Path to the PEM CA certificate used to verify Sidecar mTLS client
    /// certificates. When set (together with `authorized_clients`), the server
    /// requires client certificates and rejects connections whose identity is
    /// not in the allow-list at the TLS handshake level. Requires `cert` / `key`
    /// to also be configured.
    pub(crate) mtls_client_ca_cert: Option<PathBuf>,
    /// Path to the PEM CA private key used by `firma authority issue-client-cert`
    /// to sign new Sidecar client certificates. Not loaded at server startup;
    /// only the `issue-client-cert` subcommand reads this file.
    mtls_client_ca_key: Option<PathBuf>,
    /// Path to the TOML file listing authorized client identities (CN or DNS
    /// SAN). Required together with `mtls_client_ca_cert`.
    pub(crate) authorized_clients: Option<PathBuf>,
}

impl AuthorityTlsConfig {
    /// Path to the PEM CA certificate used to verify Sidecar mTLS client certs.
    #[must_use]
    pub fn mtls_client_ca_cert_path(&self) -> Option<&Path> {
        self.mtls_client_ca_cert.as_deref()
    }

    /// Path to the PEM CA private key used to sign new Sidecar client certs.
    #[must_use]
    pub fn mtls_client_ca_key_path(&self) -> Option<&Path> {
        self.mtls_client_ca_key.as_deref()
    }
}

impl From<schema::AuthorityTlsConfig> for AuthorityTlsConfig {
    fn from(s: schema::AuthorityTlsConfig) -> Self {
        Self {
            cert: s.tls_cert_path,
            key: s.tls_key_path,
            mtls_client_ca_cert: s.mtls_client_ca_cert_path,
            mtls_client_ca_key: s.mtls_client_ca_key_path,
            authorized_clients: s.authorized_clients_path,
        }
    }
}

impl From<&AuthorityTlsConfig> for schema::AuthorityTlsConfig {
    fn from(t: &AuthorityTlsConfig) -> Self {
        Self {
            tls_cert_path: t.cert.clone(),
            tls_key_path: t.key.clone(),
            mtls_client_ca_cert_path: t.mtls_client_ca_cert.clone(),
            mtls_client_ca_key_path: t.mtls_client_ca_key.clone(),
            authorized_clients_path: t.authorized_clients.clone(),
        }
    }
}

/// Error validating an [`AuthorityConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityConfigError {
    /// `tls_cert_path` and `tls_key_path` were not both set or both unset.
    #[error("tls_cert_path and tls_key_path must both be set or both be unset")]
    TlsPairMismatch,
    /// `mtls_client_ca_cert_path` and `authorized_clients_path` were not paired.
    #[error(
        "mtls_client_ca_cert_path and authorized_clients_path must both be set or both be unset"
    )]
    MtlsPairMismatch,
    /// mTLS was configured without the base server TLS cert/key.
    #[error(
        "mtls_client_ca_cert_path requires tls_cert_path and tls_key_path to also be configured"
    )]
    MtlsRequiresServerTls,
}

impl AuthorityConfig {
    /// Infallible field-by-field mapping from the schema representation. Only
    /// the [`AuthorityConfigBuilder`] (and [`Default`]) construct an
    /// `AuthorityConfig` from the schema; validation is deferred to
    /// [`AuthorityConfigBuilder::build`].
    fn from_schema(s: schema::AuthorityConfig) -> Self {
        Self {
            listen_addr: s.listen_addr,
            policy_dir: s.policy_dir,
            issuance_policy_dir: s.issuance_policy_dir,
            schema_path: s.schema_path,
            revocation_file: s.revocation_file,
            max_ttl_seconds: s.max_ttl_seconds,
            key_file: s.key_file,
            log_level: s.log_level,
            bundle_ttl_seconds: s.bundle_ttl_seconds,
            tls: s.tls.into(),
        }
    }

    /// Map back to the behavior-free [`schema::AuthorityConfig`] wire shape.
    ///
    /// Autostart serializes this schema form (not the validated type) so the
    /// synthetic `[authority]` TOML uses the stable wire keys.
    #[must_use]
    pub fn to_schema(&self) -> schema::AuthorityConfig {
        schema::AuthorityConfig {
            listen_addr: self.listen_addr.clone(),
            policy_dir: self.policy_dir.clone(),
            issuance_policy_dir: self.issuance_policy_dir.clone(),
            schema_path: self.schema_path.clone(),
            revocation_file: self.revocation_file.clone(),
            max_ttl_seconds: self.max_ttl_seconds,
            key_file: self.key_file.clone(),
            log_level: self.log_level.clone(),
            bundle_ttl_seconds: self.bundle_ttl_seconds,
            tls: (&self.tls).into(),
        }
    }
}

/// Assembles a validated [`AuthorityConfig`].
///
/// The schema is mapped into an `AuthorityConfig` up front; the Authority's
/// behavior — path rebasing against the config directory and
/// `FIRMA_AUTHORITY_`-prefixed environment overrides — is then applied to that
/// `AuthorityConfig`, and [`build`](Self::build) validates it. A built
/// `AuthorityConfig` is therefore always valid: nothing after `build` mutates
/// or re-validates it.
///
/// Typical order is rebase, then env overrides (kept verbatim), then build:
///
/// ```ignore
/// let config = AuthorityConfigBuilder::from_toml_str(&body)?
///     .rebase_defaults(config_dir)
///     .apply_env_overrides()
///     .build()?;
/// ```
pub struct AuthorityConfigBuilder {
    config: AuthorityConfig,
}

impl AuthorityConfigBuilder {
    /// Start from a schema representation (typically deserialized from TOML).
    #[must_use]
    pub fn new(schema: schema::AuthorityConfig) -> Self {
        Self {
            config: AuthorityConfig::from_schema(schema),
        }
    }

    /// Start from an `[authority]` TOML fragment.
    ///
    /// # Errors
    ///
    /// Returns the TOML deserialization error if the fragment is malformed.
    pub fn from_toml_str(contents: &str) -> Result<Self, toml::de::Error> {
        Ok(Self::new(toml::from_str::<schema::AuthorityConfig>(
            contents,
        )?))
    }

    /// Start from a TOML file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::IoError`] if the file cannot be read, or
    /// [`ConfigError::ParseError`] if its contents are not valid TOML.
    #[cfg(test)]
    fn from_toml_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        Self::from_toml_str(&contents).map_err(|e| ConfigError::ParseError {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })
    }

    /// Re-base the config's relative resource paths against `config_dir`.
    #[must_use]
    pub fn rebase_defaults(mut self, config_dir: &std::path::Path) -> Self {
        self.config.rebase_defaults(config_dir);
        self
    }

    /// Fold `FIRMA_AUTHORITY_`-prefixed env overrides into the config, verbatim.
    #[must_use]
    fn apply_env_overrides(mut self) -> Self {
        self.config.apply_env_overrides();
        self
    }

    /// Override the listen address on the in-progress config.
    ///
    /// Used by autostart to force a loopback listener before building.
    #[must_use]
    pub fn listen_addr(mut self, addr: impl Into<String>) -> Self {
        self.config.listen_addr = addr.into();
        self
    }

    /// Clear all TLS settings on the in-progress config.
    ///
    /// Used by autostart, which serves the Authority over loopback without TLS.
    #[must_use]
    pub fn without_tls(mut self) -> Self {
        self.config.tls = AuthorityTlsConfig::default();
        self
    }

    /// Validate the fully-resolved config and return it.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityConfigError`] if a cross-field invariant is violated.
    pub fn build(self) -> Result<AuthorityConfig, AuthorityConfigError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for AuthorityConfigBuilder {
    /// Start from the schema defaults (a valid, TLS-free configuration).
    fn default() -> Self {
        Self {
            config: AuthorityConfig::default(),
        }
    }
}

impl AuthorityConfig {
    /// Re-base relative resource paths against `config_dir`; absolute paths are
    /// left untouched. `revocation_file` is intentionally excluded — it is
    /// state-managed.
    fn rebase_defaults(&mut self, config_dir: &std::path::Path) {
        let rebase = |p: &mut PathBuf| {
            // Empty is left for the validator to reject.
            if !p.as_os_str().is_empty() && p.is_relative() {
                *p = config_dir.join(&*p);
            }
        };
        rebase(&mut self.policy_dir);
        rebase(&mut self.issuance_policy_dir);
        rebase(&mut self.key_file);
        for path in [
            &mut self.tls.cert,
            &mut self.tls.key,
            &mut self.tls.mtls_client_ca_cert,
            &mut self.tls.mtls_client_ca_key,
            &mut self.tls.authorized_clients,
            &mut self.schema_path,
        ] {
            if let Some(p) = path.as_mut()
                && !p.as_os_str().is_empty()
                && p.is_relative()
            {
                *p = config_dir.join(&*p);
            }
        }
    }

    /// Apply `FIRMA_AUTHORITY_`-prefixed env overrides verbatim.
    ///
    /// Applied *after* [`Self::rebase_defaults`] and *before*
    /// [`AuthorityConfigBuilder::build`], so an operator-supplied path env var
    /// is kept exactly as written (no re-basing) yet the built config is still
    /// validated with the overrides folded in.
    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_LISTEN_ADDR") {
            self.listen_addr = v;
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_POLICY_DIR") {
            self.policy_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_ISSUANCE_POLICY_DIR") {
            self.issuance_policy_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_SCHEMA_PATH") {
            self.schema_path = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_REVOCATION_FILE") {
            self.revocation_file = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_MAX_TTL_SECONDS")
            && let Ok(n) = v.parse::<i32>()
        {
            self.max_ttl_seconds = n;
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_KEY_FILE") {
            self.key_file = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_LOG_LEVEL") {
            self.log_level = v;
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_BUNDLE_TTL_SECONDS")
            && let Ok(n) = v.parse::<u32>()
        {
            self.bundle_ttl_seconds = n;
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_TLS_CERT_PATH") {
            self.tls.cert = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_TLS_KEY_PATH") {
            self.tls.key = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_MTLS_CLIENT_CA_CERT_PATH") {
            self.tls.mtls_client_ca_cert = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_MTLS_CLIENT_CA_KEY_PATH") {
            self.tls.mtls_client_ca_key = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("FIRMA_AUTHORITY_AUTHORIZED_CLIENTS_PATH") {
            self.tls.authorized_clients = Some(PathBuf::from(v));
        }
    }

    /// Validate the cross-field TLS invariants.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityConfigError`] on the first violated invariant.
    fn validate(&self) -> Result<(), AuthorityConfigError> {
        if self.tls.cert.is_some() != self.tls.key.is_some() {
            return Err(AuthorityConfigError::TlsPairMismatch);
        }
        if self.tls.mtls_client_ca_cert.is_some() != self.tls.authorized_clients.is_some() {
            return Err(AuthorityConfigError::MtlsPairMismatch);
        }
        if self.tls.mtls_client_ca_cert.is_some()
            && (self.tls.cert.is_none() || self.tls.key.is_none())
        {
            return Err(AuthorityConfigError::MtlsRequiresServerTls);
        }
        Ok(())
    }
}

impl AuthorityConfig {
    /// Load configuration by merging an optional TOML file with environment variable overrides.
    ///
    /// # Errors
    ///
    /// Returns an error if the config file exists but cannot be parsed.
    #[cfg(test)]
    fn load(config_path: Option<&PathBuf>) -> Result<Self, ConfigError> {
        let builder = match config_path {
            Some(path) => AuthorityConfigBuilder::from_toml_file(path)?,
            None => AuthorityConfigBuilder::default(),
        };
        builder
            .apply_env_overrides()
            .build()
            .map_err(|e| ConfigError::ParseError {
                path: config_path.cloned().unwrap_or_default(),
                reason: e.to_string(),
            })
    }

    /// Parse a resolved config file (flat or `[authority]`-sectioned via
    /// the caller), re-base relative paths against `config_dir`, then
    /// apply env overrides last so they win verbatim.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::IoError`] / [`ConfigError::ParseError`].
    #[cfg(test)]
    fn load_resolved(
        file: &std::path::Path,
        config_dir: &std::path::Path,
    ) -> Result<Self, ConfigError> {
        AuthorityConfigBuilder::from_toml_file(file)?
            .rebase_defaults(config_dir)
            .apply_env_overrides()
            .build()
            .map_err(|e| ConfigError::ParseError {
                path: file.to_path_buf(),
                reason: e.to_string(),
            })
    }

    /// Load Authority configuration from the `[authority]` section of a
    /// resolved unified `firma.toml`.
    ///
    /// Missing `[authority]` returns `Ok(None)`. A present section is parsed
    /// directly, relative paths are re-based against the resolved config
    /// directory, and environment overrides are applied last.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ParseError`] if the section exists but cannot be
    /// deserialized.
    pub fn from_resolved_section(
        resolved: &firma_config_loader::ResolvedConfig,
    ) -> Result<Option<Self>, ConfigError> {
        let config_path = resolved.config_file().to_path_buf();
        let Some(schema) = resolved
            .config
            .optional_section::<schema::AuthorityConfig>("authority")
            .map_err(|error| ConfigError::ParseError {
                path: config_path.clone(),
                reason: error.to_string(),
            })?
        else {
            return Ok(None);
        };

        // Rebase paths and fold env overrides into the config, then validate on
        // build. Env overrides run last so they stay verbatim.
        let config = AuthorityConfigBuilder::new(schema)
            .rebase_defaults(&resolved.config_dir())
            .apply_env_overrides()
            .build()
            .map_err(|error| ConfigError::ParseError {
                path: config_path,
                reason: error.to_string(),
            })?;

        Ok(Some(config))
    }
}

impl Default for AuthorityConfig {
    fn default() -> Self {
        // The schema default carries no TLS, so it is trivially valid; map it
        // directly to keep `Default` infallible.
        Self::from_schema(schema::AuthorityConfig::default())
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
mod tests {
    use firma_config_loader::CONFIG_FILE_NAME;

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
        let c = AuthorityConfigBuilder::new(schema::AuthorityConfig::default())
            .rebase_defaults(std::path::Path::new("/cfg"))
            .build()
            .unwrap();
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
        let c = AuthorityConfigBuilder::new(schema::AuthorityConfig {
            policy_dir: PathBuf::from("custom/policies"),
            schema_path: Some(PathBuf::from("schema.cedarschema")),
            ..schema::AuthorityConfig::default()
        })
        .rebase_defaults(std::path::Path::new("/cfg"))
        .build()
        .unwrap();
        assert_eq!(c.policy_dir, PathBuf::from("/cfg/custom/policies"));
        assert_eq!(
            c.schema_path,
            Some(PathBuf::from("/cfg/schema.cedarschema"))
        );
    }

    #[test]
    fn rebase_skips_empty_path_for_validator() {
        let c = AuthorityConfigBuilder::new(schema::AuthorityConfig {
            policy_dir: PathBuf::new(),
            ..schema::AuthorityConfig::default()
        })
        .rebase_defaults(std::path::Path::new("/cfg"))
        .build()
        .unwrap();
        assert_eq!(c.policy_dir, PathBuf::new());
    }

    #[test]
    fn rebase_preserves_explicit_policy_dir() {
        let c = AuthorityConfigBuilder::new(schema::AuthorityConfig {
            policy_dir: PathBuf::from("/explicit"),
            ..schema::AuthorityConfig::default()
        })
        .rebase_defaults(std::path::Path::new("/cfg"))
        .build()
        .unwrap();
        assert_eq!(c.policy_dir, PathBuf::from("/explicit"));
    }

    #[test]
    fn load_from_resolved_applies_rebase() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join(CONFIG_FILE_NAME);
        std::fs::write(
            &p,
            "max_ttl_seconds = 1800\ntls_cert_path = \"authority.crt\"\ntls_key_path = \"authority.key\"\n",
        )
        .unwrap();
        let c = AuthorityConfig::load_resolved(&p, tmp.path()).unwrap();
        assert_eq!(c.max_ttl_seconds, 1800);
        assert_eq!(c.policy_dir, tmp.path().join("policies"));
        assert_eq!(c.tls.cert, Some(tmp.path().join("authority.crt")));
        assert_eq!(c.tls.key, Some(tmp.path().join("authority.key")));
    }

    #[test]
    fn toml_deserialization() {
        let toml_str = r#"
listen_addr = "0.0.0.0:9090"
policy_dir = "/etc/firma/policies"
max_ttl_seconds = 1800
"#;
        let config = AuthorityConfigBuilder::from_toml_str(toml_str)
            .unwrap_or_else(|e| panic!("{e}"))
            .build()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(config.listen_addr, "0.0.0.0:9090");
        assert_eq!(config.max_ttl_seconds, 1800);
        // Defaults for unspecified fields
        assert_eq!(config.bundle_ttl_seconds, 30);
    }
}

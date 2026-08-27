use firma_config_schema::authority as schema;
use std::num::{NonZeroU32, NonZeroU64};
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
/// [`AuthorityConfigBuilder::build`], which validates runtime and cross-field
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
    /// Strictly positive maximum token TTL in whole seconds.
    max_ttl_seconds: NonZeroU32,
    /// Path to the Ed25519 signing key file (64-byte raw or PEM).
    pub(crate) key_file: PathBuf,
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

    /// Strictly positive maximum token TTL in whole seconds.
    #[must_use]
    pub const fn max_ttl_seconds(&self) -> NonZeroU32 {
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
/// (`tls_cert_path`, `tls_key_path`, …) live on [`schema::AuthorityConfig`];
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

/// Error validating an [`AuthorityConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityConfigError {
    /// A human-readable duration exceeds the downstream whole-second integer range.
    #[error("{field} exceeds the supported whole-second range")]
    DurationOutOfRange { field: &'static str },
    /// A human-readable duration contains a fractional second.
    #[error("{field} must be a whole number of seconds")]
    DurationNotWholeSeconds { field: &'static str },
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
    /// Convert the schema representation into the runtime whole-second shape.
    /// Cross-field validation remains deferred to [`AuthorityConfigBuilder::build`].
    fn from_schema(s: schema::AuthorityConfig) -> Result<Self, AuthorityConfigError> {
        let max_ttl = s.max_ttl.duration();
        let bundle_ttl = s.bundle_ttl.duration();
        if max_ttl.subsec_nanos() != 0 {
            return Err(AuthorityConfigError::DurationNotWholeSeconds {
                field: "authority.max_ttl",
            });
        }
        if bundle_ttl.subsec_nanos() != 0 {
            return Err(AuthorityConfigError::DurationNotWholeSeconds {
                field: "authority.bundle_ttl",
            });
        }
        let max_ttl_seconds =
            NonZeroU64::new(max_ttl.as_secs()).ok_or(AuthorityConfigError::DurationOutOfRange {
                field: "authority.max_ttl",
            })?;
        if max_ttl_seconds.get() > u64::from(i32::MAX.unsigned_abs()) {
            return Err(AuthorityConfigError::DurationOutOfRange {
                field: "authority.max_ttl",
            });
        }
        let max_ttl_seconds = NonZeroU32::try_from(max_ttl_seconds).map_err(|_| {
            AuthorityConfigError::DurationOutOfRange {
                field: "authority.max_ttl",
            }
        })?;
        let bundle_ttl_seconds = u32::try_from(bundle_ttl.as_secs()).map_err(|_| {
            AuthorityConfigError::DurationOutOfRange {
                field: "authority.bundle_ttl",
            }
        })?;

        Ok(Self {
            listen_addr: s.listen_addr,
            policy_dir: s.policy_dir,
            issuance_policy_dir: s.issuance_policy_dir,
            schema_path: s.schema_path,
            revocation_file: s.revocation_file,
            max_ttl_seconds,
            key_file: s.key_file,
            bundle_ttl_seconds,
            tls: AuthorityTlsConfig {
                cert: s.tls_cert_path,
                key: s.tls_key_path,
                mtls_client_ca_cert: s.mtls_client_ca_cert_path,
                mtls_client_ca_key: s.mtls_client_ca_key_path,
                authorized_clients: s.authorized_clients_path,
            },
        })
    }

    /// Map back to the behavior-free [`schema::AuthorityConfig`] wire shape.
    ///
    /// Autostart serializes this schema form (not the validated type) so the
    /// synthetic `[authority]` TOML uses the stable wire keys.
    ///
    /// # Errors
    ///
    /// This conversion is infallible for builder-produced runtime state. The
    /// result remains fallible for API compatibility with existing callers.
    pub fn to_schema(&self) -> Result<schema::AuthorityConfig, ConfigError> {
        let max_ttl = firma_config_schema::utils::NonZeroDuration::from(NonZeroU64::from(
            self.max_ttl_seconds,
        ));
        let bundle_ttl = firma_config_schema::utils::NonZeroDuration::new(
            std::time::Duration::from_secs(u64::from(self.bundle_ttl_seconds)),
        )
        .map_err(|_| ConfigError::DurationNotPositive {
            field: "authority.bundle_ttl",
        })?;

        Ok(schema::AuthorityConfig {
            listen_addr: self.listen_addr.clone(),
            policy_dir: self.policy_dir.clone(),
            issuance_policy_dir: self.issuance_policy_dir.clone(),
            schema_path: self.schema_path.clone(),
            revocation_file: self.revocation_file.clone(),
            max_ttl,
            key_file: self.key_file.clone(),
            bundle_ttl,
            tls_cert_path: self.tls.cert.clone(),
            tls_key_path: self.tls.key.clone(),
            mtls_client_ca_cert_path: self.tls.mtls_client_ca_cert.clone(),
            mtls_client_ca_key_path: self.tls.mtls_client_ca_key.clone(),
            authorized_clients_path: self.tls.authorized_clients.clone(),
        })
    }
}

/// Assembles a validated [`AuthorityConfig`].
///
/// The builder retains the schema representation while applying path rebasing
/// and `FIRMA_AUTHORITY_`-prefixed environment overrides. [`build`](Self::build)
/// then converts durations to the Authority's whole-second runtime shape and
/// validates cross-field invariants. A built `AuthorityConfig` is therefore
/// always valid: nothing after `build` mutates or re-validates it.
///
/// Typical order is rebase, then env overrides (kept verbatim), then build:
///
/// ```ignore
/// let config = AuthorityConfigBuilder::from_toml_str(&body)?
///     .rebase_defaults(config_dir)
///     .apply_env_overrides()?
///     .build()?;
/// ```
pub struct AuthorityConfigBuilder {
    schema: schema::AuthorityConfig,
}

impl AuthorityConfigBuilder {
    /// Start from a schema representation (typically deserialized from TOML).
    #[must_use]
    pub fn new(schema: schema::AuthorityConfig) -> Self {
        Self { schema }
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
        let rebase = |path: &mut PathBuf| {
            if !path.as_os_str().is_empty() && path.is_relative() {
                *path = config_dir.join(&*path);
            }
        };
        rebase(&mut self.schema.policy_dir);
        rebase(&mut self.schema.issuance_policy_dir);
        rebase(&mut self.schema.key_file);
        for path in [
            &mut self.schema.tls_cert_path,
            &mut self.schema.tls_key_path,
            &mut self.schema.mtls_client_ca_cert_path,
            &mut self.schema.mtls_client_ca_key_path,
            &mut self.schema.authorized_clients_path,
            &mut self.schema.schema_path,
        ] {
            if let Some(path) = path.as_mut()
                && !path.as_os_str().is_empty()
                && path.is_relative()
            {
                *path = config_dir.join(&*path);
            }
        }
        self
    }

    /// Fold `FIRMA_AUTHORITY_`-prefixed environment overrides into the config.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidEnvironmentVariable`] when a configured
    /// duration does not use the schema's compact human-readable syntax or is
    /// zero.
    fn apply_env_overrides(mut self) -> Result<Self, ConfigError> {
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_LISTEN_ADDR") {
            self.schema.listen_addr = value;
        }
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_POLICY_DIR") {
            self.schema.policy_dir = PathBuf::from(value);
        }
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_ISSUANCE_POLICY_DIR") {
            self.schema.issuance_policy_dir = PathBuf::from(value);
        }
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_SCHEMA_PATH") {
            self.schema.schema_path = Some(PathBuf::from(value));
        }
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_REVOCATION_FILE") {
            self.schema.revocation_file = PathBuf::from(value);
        }
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_MAX_TTL") {
            self.schema.max_ttl = parse_non_zero_duration_env(
                "FIRMA_AUTHORITY_MAX_TTL",
                "authority.max_ttl",
                &value,
            )?;
        }
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_KEY_FILE") {
            self.schema.key_file = PathBuf::from(value);
        }
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_BUNDLE_TTL") {
            self.schema.bundle_ttl = parse_non_zero_duration_env(
                "FIRMA_AUTHORITY_BUNDLE_TTL",
                "authority.bundle_ttl",
                &value,
            )?;
        }
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_TLS_CERT_PATH") {
            self.schema.tls_cert_path = Some(PathBuf::from(value));
        }
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_TLS_KEY_PATH") {
            self.schema.tls_key_path = Some(PathBuf::from(value));
        }
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_MTLS_CLIENT_CA_CERT_PATH") {
            self.schema.mtls_client_ca_cert_path = Some(PathBuf::from(value));
        }
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_MTLS_CLIENT_CA_KEY_PATH") {
            self.schema.mtls_client_ca_key_path = Some(PathBuf::from(value));
        }
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_AUTHORIZED_CLIENTS_PATH") {
            self.schema.authorized_clients_path = Some(PathBuf::from(value));
        }
        Ok(self)
    }

    /// Override the listen address on the in-progress config.
    ///
    /// Used by autostart to force a loopback listener before building.
    #[must_use]
    pub fn listen_addr(mut self, addr: impl Into<String>) -> Self {
        self.schema.listen_addr = addr.into();
        self
    }

    /// Clear all TLS settings on the in-progress config.
    ///
    /// Used by autostart, which serves the Authority over loopback without TLS.
    #[must_use]
    pub fn without_tls(mut self) -> Self {
        self.schema.tls_cert_path = None;
        self.schema.tls_key_path = None;
        self.schema.mtls_client_ca_cert_path = None;
        self.schema.mtls_client_ca_key_path = None;
        self.schema.authorized_clients_path = None;
        self
    }

    /// Validate the fully-resolved config and return it.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityConfigError`] if a duration cannot be represented by
    /// the runtime's whole-second integer fields or a cross-field invariant is
    /// violated.
    pub fn build(self) -> Result<AuthorityConfig, AuthorityConfigError> {
        let config = AuthorityConfig::from_schema(self.schema)?;
        config.validate()?;
        Ok(config)
    }
}

impl Default for AuthorityConfigBuilder {
    /// Start from the schema defaults (a valid, TLS-free configuration).
    fn default() -> Self {
        Self {
            schema: schema::AuthorityConfig::default(),
        }
    }
}

fn parse_non_zero_duration_env(
    name: &'static str,
    field: &'static str,
    value: &str,
) -> Result<firma_config_schema::utils::NonZeroDuration, ConfigError> {
    let deserializer = serde::de::value::StrDeserializer::<serde::de::value::Error>::new(value);
    <firma_config_schema::utils::NonZeroDuration as serde::Deserialize>::deserialize(deserializer)
        .map_err(|error| ConfigError::InvalidEnvironmentVariable {
            name,
            field,
            reason: error.to_string(),
        })
}

impl AuthorityConfig {
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
            .apply_env_overrides()?
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
            .apply_env_overrides()?
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
            .apply_env_overrides()?
            .build()
            .map_err(|error| ConfigError::ParseError {
                path: config_path,
                reason: error.to_string(),
            })?;

        Ok(Some(config))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {reason}")]
    IoError { path: PathBuf, reason: String },
    #[error("failed to parse config file {path}: {reason}")]
    ParseError { path: PathBuf, reason: String },
    #[error("invalid {name} for {field}: {reason}")]
    InvalidEnvironmentVariable {
        name: &'static str,
        field: &'static str,
        reason: String,
    },
    #[error("{field} must be greater than zero")]
    DurationNotPositive { field: &'static str },
}

#[cfg(test)]
mod tests {
    use firma_config_loader::CONFIG_FILE_NAME;

    use super::*;

    #[test]
    fn default_config_has_sensible_values() -> anyhow::Result<()> {
        let config = AuthorityConfigBuilder::default().build()?;
        assert_eq!(config.listen_addr, "[::1]:50051");
        assert_eq!(config.max_ttl_seconds.get(), 3600);
        assert_eq!(config.bundle_ttl_seconds, 30);

        Ok(())
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
            "max_ttl = \"30m\"\ntls_cert_path = \"authority.crt\"\ntls_key_path = \"authority.key\"\n",
        )
        .unwrap();
        let c = AuthorityConfig::load_resolved(&p, tmp.path()).unwrap();
        assert_eq!(c.max_ttl_seconds.get(), 1800);
        assert_eq!(c.policy_dir, tmp.path().join("policies"));
        assert_eq!(c.tls.cert, Some(tmp.path().join("authority.crt")));
        assert_eq!(c.tls.key, Some(tmp.path().join("authority.key")));
    }

    #[test]
    fn toml_deserialization() {
        let toml_str = r#"
listen_addr = "0.0.0.0:9090"
policy_dir = "/etc/firma/policies"
max_ttl = "30m"
"#;
        let config = AuthorityConfigBuilder::from_toml_str(toml_str)
            .unwrap_or_else(|e| panic!("{e}"))
            .build()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(config.listen_addr, "0.0.0.0:9090");
        assert_eq!(config.max_ttl_seconds.get(), 1800);
        // Defaults for unspecified fields
        assert_eq!(config.bundle_ttl_seconds, 30);
    }

    #[test]
    fn authority_duration_conversion_rejects_fractional_and_out_of_range_values() {
        let mut schema = schema::AuthorityConfig {
            max_ttl: firma_config_schema::utils::NonZeroDuration::new(
                std::time::Duration::from_millis(500),
            )
            .unwrap_or_else(|error| panic!("{error}")),
            ..schema::AuthorityConfig::default()
        };
        assert!(matches!(
            AuthorityConfigBuilder::new(schema.clone()).build(),
            Err(AuthorityConfigError::DurationNotWholeSeconds {
                field: "authority.max_ttl"
            })
        ));

        schema.max_ttl = firma_config_schema::utils::NonZeroDuration::new(
            std::time::Duration::from_secs(2_147_483_648),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            AuthorityConfigBuilder::new(schema.clone()).build(),
            Err(AuthorityConfigError::DurationOutOfRange {
                field: "authority.max_ttl"
            })
        ));

        schema.max_ttl = schema::AuthorityConfig::default().max_ttl;
        schema.bundle_ttl =
            firma_config_schema::utils::NonZeroDuration::new(std::time::Duration::from_millis(500))
                .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            AuthorityConfigBuilder::new(schema.clone()).build(),
            Err(AuthorityConfigError::DurationNotWholeSeconds {
                field: "authority.bundle_ttl"
            })
        ));

        schema.bundle_ttl = firma_config_schema::utils::NonZeroDuration::new(
            std::time::Duration::from_secs(u64::from(u32::MAX) + 1),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            AuthorityConfigBuilder::new(schema).build(),
            Err(AuthorityConfigError::DurationOutOfRange {
                field: "authority.bundle_ttl"
            })
        ));
    }
}

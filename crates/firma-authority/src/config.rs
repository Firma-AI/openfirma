use firma_config_schema::authority as schema;
use firma_config_utils::NonZeroDuration;
use firma_runtime_state::RuntimeLayout;
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
    /// Mapping files streamed with the enforcement policy generation.
    pub(crate) mapping_rules_paths: Vec<PathBuf>,
    /// Path to the revocation file (one token ID per line).
    pub(crate) revocation_file: PathBuf,
    /// Strictly positive maximum token TTL in whole seconds.
    max_ttl_seconds: NonZeroU32,
    /// Path to the Ed25519 signing key file (64-byte raw or PEM).
    pub(crate) key_file: PathBuf,
    /// Strictly positive policy bundle TTL advertised to sidecars in whole seconds.
    bundle_ttl_seconds: NonZeroU32,
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

    /// Strictly positive policy bundle TTL advertised to sidecars in whole seconds.
    #[must_use]
    pub const fn bundle_ttl_seconds(&self) -> NonZeroU32 {
        self.bundle_ttl_seconds
    }

    /// TLS configuration.
    #[must_use]
    pub fn tls(&self) -> &AuthorityTlsConfig {
        &self.tls
    }
}

/// TLS posture of the Authority gRPC server.
///
/// The wire keys (`tls_cert_path`, `tls_key_path`, …) live on
/// [`schema::AuthorityConfig`] as independent options; this is their validated
/// in-memory form, where the pairing rules are structural rather than checked:
/// a half-configured server cannot be named.
#[derive(Debug, Clone, Default)]
pub enum AuthorityTlsConfig {
    /// Serve plaintext gRPC.
    ///
    /// Only [`AuthorityConfigBuilder::without_tls`] produces this: an unset
    /// pair resolves against the state directory instead.
    #[default]
    Disabled,
    /// Serve TLS with the given material.
    Enabled(AuthorityTlsMaterial),
}

/// What a caller wants of TLS before the config is resolved.
///
/// Distinct from [`AuthorityTlsConfig`], which is the *outcome*: this is the
/// request, and [`Required`](Self::Required) still has to find material to
/// become [`AuthorityTlsConfig::Enabled`].
///
/// Named rather than a `bool` because the two values are not a presence test
/// and read identically at a call site: `from_resolved_section(&resolved,
/// &state, true)` gives no hint that `true` means *plaintext*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsRequest {
    /// Serve TLS, from the configured pair or the state directory's.
    ///
    /// The default, and the only value that can fail the build for missing
    /// material: an unset pair is not a request for cleartext.
    #[default]
    Required,
    /// Serve plaintext gRPC, whatever material the host holds.
    ///
    /// Two kinds of caller ask for this: autostart, which dials loopback
    /// `http://`, and commands that only read non-TLS fields out of
    /// `[authority]` and must not fail on a host that never generated a pair.
    Disabled,
}

/// Server TLS material, plus the mTLS client trust it optionally enforces.
#[derive(Debug, Clone)]
pub struct AuthorityTlsMaterial {
    /// Path to the TLS certificate file (PEM).
    cert: PathBuf,
    /// Path to the TLS private key file (PEM).
    key: PathBuf,
    /// Client-certificate trust, when the server demands one.
    mtls: Option<AuthorityMtlsConfig>,
}

/// Client-certificate trust for Sidecar connections.
///
/// Present only on a TLS-enabled server: requiring a client certificate is
/// meaningless without a handshake to require it in.
#[derive(Debug, Clone)]
pub struct AuthorityMtlsConfig {
    /// Path to the PEM CA certificate used to verify Sidecar client
    /// certificates. The server rejects connections whose identity is not in
    /// `authorized_clients` at the TLS handshake level.
    client_ca_cert: PathBuf,
    /// Path to the TOML file listing authorized client identities (CN or DNS
    /// SAN).
    authorized_clients: PathBuf,
    /// Path to the PEM CA private key used by `firma authority
    /// issue-client-cert` to sign new Sidecar client certificates. Not loaded
    /// at server startup; only that subcommand reads this file.
    client_ca_key: Option<PathBuf>,
}

impl AuthorityTlsConfig {
    /// Server TLS material, or `None` when the Authority serves plaintext.
    #[must_use]
    pub fn material(&self) -> Option<&AuthorityTlsMaterial> {
        match self {
            Self::Disabled => None,
            Self::Enabled(material) => Some(material),
        }
    }
}

impl AuthorityTlsMaterial {
    /// Path to the PEM server certificate.
    #[must_use]
    pub fn cert(&self) -> &Path {
        &self.cert
    }

    /// Path to the PEM server private key.
    #[must_use]
    pub fn key(&self) -> &Path {
        &self.key
    }

    /// Client-certificate trust, when the server demands one.
    #[must_use]
    pub fn mtls(&self) -> Option<&AuthorityMtlsConfig> {
        self.mtls.as_ref()
    }
}

impl AuthorityMtlsConfig {
    /// Path to the PEM CA certificate Sidecar client certs are verified against.
    #[must_use]
    pub fn client_ca_cert(&self) -> &Path {
        &self.client_ca_cert
    }

    /// Path to the TOML file listing authorized client identities.
    #[must_use]
    pub(crate) fn authorized_clients(&self) -> &Path {
        &self.authorized_clients
    }

    /// Path to the PEM CA private key that signs new Sidecar client certs.
    #[must_use]
    pub fn client_ca_key(&self) -> Option<&Path> {
        self.client_ca_key.as_deref()
    }
}

/// Error validating an [`AuthorityConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityConfigError {
    /// No enforcement mapping source was selected.
    #[error("authority.mapping_rules_paths must contain at least one mapping file")]
    MissingMappingPaths,
    /// A selected mapping source has an empty path.
    #[error("authority.mapping_rules_paths[{index}] must not be empty")]
    EmptyMappingPath { index: usize },
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
    /// Only one half of the state-directory TLS pair exists on disk.
    #[error(
        "{dir} holds only one of authority.crt / authority.key; generate both with `firma config` or set tls_cert_path and tls_key_path explicitly"
    )]
    TlsMaterialIncomplete {
        /// Directory the incomplete pair was found in.
        dir: String,
    },
    /// No TLS was configured and the state directory holds no material either.
    #[error(
        "no TLS material in {dir} and none configured; generate it with `firma config`, set tls_cert_path and tls_key_path explicitly, or ask for plaintext with `firma authority --no-tls`"
    )]
    TlsMaterialMissing {
        /// Directory the material was looked for in.
        dir: String,
    },
    /// mTLS was configured without the base server TLS cert/key.
    #[error(
        "mtls_client_ca_cert_path requires tls_cert_path and tls_key_path to also be configured"
    )]
    MtlsRequiresServerTls,
    /// The client CA signing key was configured without the CA it signs for.
    #[error("mtls_client_ca_key_path requires mtls_client_ca_cert_path to also be configured")]
    MtlsIssuerKeyWithoutClientCa,
}

impl AuthorityTlsConfig {
    /// Build the TLS posture from the resolved schema fields.
    ///
    /// The caller has already resolved unset paths against the state directory,
    /// so an absent pair here means plaintext was asked for.
    fn from_schema(s: &mut schema::AuthorityConfig) -> Result<Self, AuthorityConfigError> {
        let mtls = match (
            s.mtls_client_ca_cert_path.take(),
            s.authorized_clients_path.take(),
        ) {
            (Some(client_ca_cert), Some(authorized_clients)) => Some(AuthorityMtlsConfig {
                client_ca_cert,
                authorized_clients,
                client_ca_key: s.mtls_client_ca_key_path.take(),
            }),
            (None, None) => {
                if s.mtls_client_ca_key_path.is_some() {
                    return Err(AuthorityConfigError::MtlsIssuerKeyWithoutClientCa);
                }
                None
            }
            _ => return Err(AuthorityConfigError::MtlsPairMismatch),
        };
        match (s.tls_cert_path.take(), s.tls_key_path.take()) {
            (Some(cert), Some(key)) => Ok(Self::Enabled(AuthorityTlsMaterial { cert, key, mtls })),
            (None, None) if mtls.is_none() => Ok(Self::Disabled),
            (None, None) => Err(AuthorityConfigError::MtlsRequiresServerTls),
            _ => Err(AuthorityConfigError::TlsPairMismatch),
        }
    }
}

/// The whole-second TTLs the Authority runtime works in.
#[derive(Debug, Clone, Copy)]
struct WholeSecondTtls {
    max_ttl_seconds: NonZeroU32,
    bundle_ttl_seconds: NonZeroU32,
}

impl WholeSecondTtls {
    /// Convert the schema's human-readable durations to the runtime shape.
    fn from_schema(s: &schema::AuthorityConfig) -> Result<Self, AuthorityConfigError> {
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
        let bundle_ttl_seconds = NonZeroU64::new(bundle_ttl.as_secs()).ok_or(
            AuthorityConfigError::DurationOutOfRange {
                field: "authority.bundle_ttl",
            },
        )?;
        let bundle_ttl_seconds = NonZeroU32::try_from(bundle_ttl_seconds).map_err(|_| {
            AuthorityConfigError::DurationOutOfRange {
                field: "authority.bundle_ttl",
            }
        })?;

        Ok(Self {
            max_ttl_seconds,
            bundle_ttl_seconds,
        })
    }
}

impl AuthorityConfig {
    /// Assemble the runtime config from parts the builder already validated.
    fn from_parts(
        s: schema::AuthorityConfig,
        durations: WholeSecondTtls,
        tls: AuthorityTlsConfig,
    ) -> Self {
        Self {
            listen_addr: s.listen_addr,
            policy_dir: s.policy_dir,
            issuance_policy_dir: s.issuance_policy_dir,
            schema_path: s.schema_path,
            mapping_rules_paths: s.mapping_rules_paths,
            // Both are `Some` by construction: `build` resolves every unset
            // artifact path against the state layout before converting.
            revocation_file: s.revocation_file.unwrap_or_default(),
            max_ttl_seconds: durations.max_ttl_seconds,
            key_file: s.key_file.unwrap_or_default(),
            bundle_ttl_seconds: durations.bundle_ttl_seconds,
            tls,
        }
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
        let max_ttl = NonZeroDuration::from(NonZeroU64::from(self.max_ttl_seconds));
        let bundle_ttl = NonZeroDuration::from(NonZeroU64::from(self.bundle_ttl_seconds));
        let material = self.tls.material();
        let mtls = material.and_then(AuthorityTlsMaterial::mtls);

        Ok(schema::AuthorityConfig {
            listen_addr: self.listen_addr.clone(),
            policy_dir: self.policy_dir.clone(),
            issuance_policy_dir: self.issuance_policy_dir.clone(),
            schema_path: self.schema_path.clone(),
            mapping_rules_paths: self.mapping_rules_paths.clone(),
            revocation_file: Some(self.revocation_file.clone()),
            max_ttl,
            key_file: Some(self.key_file.clone()),
            bundle_ttl,
            tls_cert_path: material.map(|m| m.cert.clone()),
            tls_key_path: material.map(|m| m.key.clone()),
            mtls_client_ca_cert_path: mtls.map(|m| m.client_ca_cert.clone()),
            mtls_client_ca_key_path: mtls.and_then(|m| m.client_ca_key.clone()),
            authorized_clients_path: mtls.map(|m| m.authorized_clients.clone()),
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
/// let config = AuthorityConfigBuilder::from_toml_str(&body, state)?
///     .rebase_defaults(config_dir)
///     .apply_env_overrides()?
///     .build()?;
/// ```
pub struct AuthorityConfigBuilder {
    schema: schema::AuthorityConfig,
    /// Layout that unset artifact paths resolve against. Taken at construction
    /// so a config can never be built without one.
    state: RuntimeLayout,
    /// Set by [`AuthorityConfigBuilder::without_tls`]. Distinct from "unset":
    /// an unset TLS pair is adopted from the state directory, a disabled one must
    /// stay plaintext no matter what material is lying around.
    tls: TlsRequest,
}

impl AuthorityConfigBuilder {
    /// Start from a schema representation (typically deserialized from TOML)
    /// and the runtime layout that unset artifact paths resolve against.
    ///
    /// `state` is a constructor parameter rather than a setter because every
    /// builder needs one and no default is safe. It is a [`RuntimeLayout`]
    /// rather than a bare path because the state directory is a
    /// process-boundary decision (`--state-dir`, then `FIRMA_STATE_DIR`, then
    /// the platform runtime directory) that the caller has already made:
    /// resolving it here would let an in-process Authority adopt whatever key
    /// and TLS material the ambient host happens to hold.
    #[must_use]
    pub fn new(schema: schema::AuthorityConfig, state: &RuntimeLayout) -> Self {
        Self {
            schema,
            state: state.clone(),
            tls: TlsRequest::default(),
        }
    }

    /// Start from an `[authority]` TOML fragment, resolving unset artifact
    /// paths against `state`.
    ///
    /// # Errors
    ///
    /// Returns the TOML deserialization error if the fragment is malformed.
    pub fn from_toml_str(contents: &str, state: &RuntimeLayout) -> Result<Self, toml::de::Error> {
        Ok(Self::new(
            toml::from_str::<schema::AuthorityConfig>(contents)?,
            state,
        ))
    }

    /// Start from a TOML file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::IoError`] if the file cannot be read, or
    /// [`ConfigError::ParseError`] if its contents are not valid TOML.
    #[cfg(test)]
    fn from_toml_file(path: &std::path::Path, state: &RuntimeLayout) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::IoError {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        Self::from_toml_str(&contents, state).map_err(|e| ConfigError::ParseError {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })
    }

    /// Re-base the config's relative resource paths against `config_dir`.
    ///
    /// `revocation_file` is deliberately excluded, as it always has been: an
    /// explicit relative value stays relative to the working directory. Only an
    /// unset one is resolved, and it resolves against the state directory in
    /// [`build`](Self::build).
    #[must_use]
    pub fn rebase_defaults(mut self, config_dir: &std::path::Path) -> Self {
        let rebase = |path: &mut PathBuf| {
            if !path.as_os_str().is_empty() && path.is_relative() {
                *path = config_dir.join(&*path);
            }
        };
        rebase(&mut self.schema.policy_dir);
        rebase(&mut self.schema.issuance_policy_dir);
        for path in &mut self.schema.mapping_rules_paths {
            rebase(path);
        }
        for path in [
            &mut self.schema.key_file,
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
            self.schema.revocation_file = Some(PathBuf::from(value));
        }
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_MAX_TTL") {
            self.schema.max_ttl = parse_non_zero_duration_env(
                "FIRMA_AUTHORITY_MAX_TTL",
                "authority.max_ttl",
                &value,
            )?;
        }
        if let Ok(value) = std::env::var("FIRMA_AUTHORITY_KEY_FILE") {
            self.schema.key_file = Some(PathBuf::from(value));
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

    /// Turn TLS off for this config, overriding explicit paths, environment
    /// overrides, and the state-directory defaults alike.
    ///
    /// Used by autostart, which serves the Authority over loopback without TLS.
    /// Recording the request and clearing the paths in [`build`](Self::build) is
    /// what makes it stick: clearing them here would leave an unset pair, which
    /// is exactly what the state-directory default fills back in, and
    /// `FIRMA_AUTHORITY_TLS_*` would repopulate them anyway — either way a host
    /// that ran `firma config` hands the autostarted Authority TLS while every
    /// client dials `http://`.
    #[must_use]
    pub fn without_tls(mut self) -> Self {
        self.tls = TlsRequest::Disabled;
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
        let Self {
            mut schema,
            state,
            tls,
        } = self;
        if schema.mapping_rules_paths.is_empty() {
            return Err(AuthorityConfigError::MissingMappingPaths);
        }
        for (index, path) in schema.mapping_rules_paths.iter().enumerate() {
            if path.as_os_str().is_empty() {
                return Err(AuthorityConfigError::EmptyMappingPath { index });
            }
        }
        // The opt-out is applied here, after `apply_env_overrides` has had its
        // say, not in `without_tls`. `FIRMA_AUTHORITY_TLS_*` runs last and would
        // otherwise repopulate the paths the opt-out just cleared, handing a
        // caller that asked for plaintext a TLS listener.
        if tls == TlsRequest::Disabled {
            clear_tls_material(&mut schema);
        }
        apply_state_dir_defaults(&mut schema, &state)?;
        let durations = WholeSecondTtls::from_schema(&schema)?;
        resolve_tls_material(&mut schema, &state, tls)?;
        let tls = AuthorityTlsConfig::from_schema(&mut schema)?;
        Ok(AuthorityConfig::from_parts(schema, durations, tls))
    }
}

/// Drop every field that would make the Authority speak TLS or demand a client
/// certificate.
///
/// Covers the mTLS trio as well as the server pair: `without_tls` is a request
/// for plaintext gRPC, and leaving an authorized-clients allow-list in place
/// would fail validation rather than serve the plaintext listener asked for.
fn clear_tls_material(schema: &mut schema::AuthorityConfig) {
    schema.tls_cert_path = None;
    schema.tls_key_path = None;
    schema.mtls_client_ca_cert_path = None;
    schema.mtls_client_ca_key_path = None;
    schema.authorized_clients_path = None;
}

/// Fill in every artifact path the operator left unset from `state`.
///
/// These are the positions `firma config` writes the material to, so a config
/// that names none of them resolves the same files a scaffolded one names
/// explicitly. TLS is resolved separately, by [`resolve_tls_material`].
fn apply_state_dir_defaults(
    schema: &mut schema::AuthorityConfig,
    state: &RuntimeLayout,
) -> Result<(), AuthorityConfigError> {
    // Report what the operator got wrong before defaulting anything. An
    // unpaired key is a misconfiguration whatever the state directory holds,
    // and "you are missing TLS material" is the wrong answer to it.
    if schema.tls_cert_path.is_some() != schema.tls_key_path.is_some() {
        return Err(AuthorityConfigError::TlsPairMismatch);
    }
    if schema.mtls_client_ca_cert_path.is_some() != schema.authorized_clients_path.is_some() {
        return Err(AuthorityConfigError::MtlsPairMismatch);
    }
    if schema.key_file.is_none() {
        schema.key_file = Some(state.authority_key());
    }
    if schema.revocation_file.is_none() {
        schema.revocation_file = Some(state.revocations());
    }
    Ok(())
}

/// Resolve the server TLS pair the operator left unset against `state`.
///
/// Leaving the pair unset is not a request for plaintext, so the state
/// directory must hold the material. Plaintext is only reachable through
/// [`TlsRequest::Disabled`], which [`AuthorityConfigBuilder::without_tls`]
/// sets: "cleared on purpose" and "never set" are otherwise the same field
/// state, and guessing between them is how a deployment that had TLS yesterday
/// silently starts accepting cleartext gRPC today.
///
/// Runs after the durations are converted, so a config that is also malformed
/// reports that first rather than sending the operator to look at a TLS
/// directory.
fn resolve_tls_material(
    schema: &mut schema::AuthorityConfig,
    state: &RuntimeLayout,
    tls: TlsRequest,
) -> Result<(), AuthorityConfigError> {
    if tls == TlsRequest::Disabled
        || schema.tls_cert_path.is_some()
        || schema.tls_key_path.is_some()
    {
        return Ok(());
    }
    let cert = state.authority_tls_certificate();
    let key = state.authority_tls_private_key();
    match (cert.is_file(), key.is_file()) {
        (true, true) => {
            schema.tls_cert_path = Some(cert);
            schema.tls_key_path = Some(key);
            Ok(())
        }
        (false, false) => Err(AuthorityConfigError::TlsMaterialMissing {
            dir: state.tls_dir().display().to_string(),
        }),
        _ => Err(AuthorityConfigError::TlsMaterialIncomplete {
            dir: state.tls_dir().display().to_string(),
        }),
    }
}

fn parse_non_zero_duration_env(
    name: &'static str,
    field: &'static str,
    value: &str,
) -> Result<NonZeroDuration, ConfigError> {
    let deserializer = serde::de::value::StrDeserializer::<serde::de::value::Error>::new(value);
    <NonZeroDuration as serde::Deserialize>::deserialize(deserializer).map_err(|error| {
        ConfigError::InvalidEnvironmentVariable {
            name,
            field,
            reason: error.to_string(),
        }
    })
}

impl AuthorityConfig {
    /// Load configuration by merging an optional TOML file with environment variable overrides.
    ///
    /// # Errors
    ///
    /// Returns an error if the config file exists but cannot be parsed.
    /// `state` pins the directory unset artifact paths default to, so a test
    /// never depends on what the developer's own runtime directory holds.
    #[cfg(test)]
    fn load(config_path: Option<&PathBuf>, state: &RuntimeLayout) -> Result<Self, ConfigError> {
        let builder = match config_path {
            Some(path) => AuthorityConfigBuilder::from_toml_file(path, state)?,
            None => AuthorityConfigBuilder::new(schema::AuthorityConfig::default(), state),
        };
        builder
            .without_tls()
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
        state: &RuntimeLayout,
    ) -> Result<Self, ConfigError> {
        AuthorityConfigBuilder::from_toml_file(file, state)?
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
    /// [`TlsRequest::Disabled`] is how a caller says "plaintext on purpose":
    /// the section carries no record of the decision, and an absent TLS pair
    /// otherwise resolves against the state directory. Callers that only read
    /// non-TLS fields pass it for the same reason — they are not about to serve
    /// gRPC, so a host without material must not fail them.
    ///
    /// `state` is resolved by the caller at its process boundary — from
    /// `--state-dir`, then `FIRMA_STATE_DIR`, then the platform default — and
    /// passed in rather than read here. Reading it inside the builder made
    /// `build()` depend on ambient host state: an in-process Authority silently
    /// adopted whatever TLS material the developer's runtime directory held,
    /// served TLS to a plaintext client, and turned fail-closed assertions into
    /// assertions that tested nothing.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ParseError`] if the section exists but cannot be
    /// deserialized.
    pub fn from_resolved_section(
        resolved: &firma_config_loader::ResolvedConfig,
        state: &RuntimeLayout,
        tls: TlsRequest,
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
        let mut builder =
            AuthorityConfigBuilder::new(schema, state).rebase_defaults(&resolved.config_dir());
        if tls == TlsRequest::Disabled {
            builder = builder.without_tls();
        }
        let config =
            builder
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
}

#[cfg(test)]
mod tests {
    use firma_config_loader::CONFIG_FILE_NAME;

    use super::*;

    /// A fixed state root for cases whose assertions do not depend on it.
    fn state_layout() -> RuntimeLayout {
        RuntimeLayout::from_root("/state")
    }

    fn configured_schema() -> schema::AuthorityConfig {
        schema::AuthorityConfig {
            mapping_rules_paths: vec!["mapping-rules.toml".into()],
            ..schema::AuthorityConfig::default()
        }
    }

    #[test]
    fn default_config_has_sensible_values() -> anyhow::Result<()> {
        let config = AuthorityConfigBuilder::new(configured_schema(), &state_layout())
            .without_tls()
            .build()?;
        assert_eq!(config.listen_addr, "[::1]:50051");
        assert_eq!(config.max_ttl_seconds.get(), 3600);
        assert_eq!(config.bundle_ttl_seconds.get(), 30);

        Ok(())
    }

    #[test]
    fn load_config_requires_mapping_sources() {
        let error = AuthorityConfig::load(None, &state_layout()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "failed to parse config file : authority.mapping_rules_paths must contain at least one mapping file"
        );
    }

    #[test]
    fn load_config_nonexistent_file_errors() {
        let path = PathBuf::from("/nonexistent/config.toml");
        let result = AuthorityConfig::load(Some(&path), &state_layout());
        assert!(result.is_err());
    }

    #[test]
    fn rebase_rewrites_the_policy_dirs() {
        let c = AuthorityConfigBuilder::new(configured_schema(), &state_layout())
            .without_tls()
            .rebase_defaults(std::path::Path::new("/cfg"))
            .build()
            .unwrap();
        assert_eq!(c.policy_dir, PathBuf::from("/cfg/policies"));
        assert_eq!(
            c.issuance_policy_dir,
            PathBuf::from("/cfg/issuance-policies")
        );
    }

    /// The artifact paths `firma config` writes into `firma.toml` are also what
    /// an unset key resolves to, so a scaffolded config and a bare one name the
    /// same files.
    #[test]
    fn unset_artifact_paths_default_to_the_state_root() {
        let c = AuthorityConfigBuilder::new(configured_schema(), &state_layout())
            .without_tls()
            .rebase_defaults(std::path::Path::new("/cfg"))
            .build()
            .unwrap();
        assert_eq!(c.key_file, PathBuf::from("/state/authority.key"));
        assert_eq!(c.revocation_file, PathBuf::from("/state/revocations.txt"));
    }

    /// An absent TLS pair is not a request for plaintext: a deployment whose
    /// state directory was wiped must say so before it serves cleartext gRPC.
    #[test]
    fn missing_state_dir_tls_material_is_rejected() {
        let state = tempfile::tempdir().unwrap();
        let error = AuthorityConfigBuilder::new(
            configured_schema(),
            &RuntimeLayout::from_root(state.path()),
        )
        .build()
        .expect_err("plaintext must be asked for explicitly");
        assert_eq!(
            error,
            AuthorityConfigError::TlsMaterialMissing {
                dir: state.path().join("tls").display().to_string(),
            }
        );
    }

    /// The same config builds once the operator opts out of TLS.
    #[test]
    fn the_plaintext_opt_out_survives_missing_material() {
        let state = tempfile::tempdir().unwrap();
        let c = AuthorityConfigBuilder::new(
            configured_schema(),
            &RuntimeLayout::from_root(state.path()),
        )
        .without_tls()
        .build()
        .unwrap();
        assert!(c.tls.material().is_none());
    }

    /// An explicit relative path still means "relative to the config file", and
    /// it wins over the state-directory default.
    #[test]
    fn an_explicit_artifact_path_overrides_the_state_dir_default() {
        let c = AuthorityConfigBuilder::new(
            schema::AuthorityConfig {
                key_file: Some(PathBuf::from("keys/authority.key")),
                revocation_file: Some(PathBuf::from("/srv/revocations.txt")),
                ..configured_schema()
            },
            &state_layout(),
        )
        .without_tls()
        .rebase_defaults(std::path::Path::new("/cfg"))
        .build()
        .unwrap();
        assert_eq!(c.key_file, PathBuf::from("/cfg/keys/authority.key"));
        assert_eq!(c.revocation_file, PathBuf::from("/srv/revocations.txt"));
    }

    #[test]
    fn rebase_rewrites_relative_non_default_paths() {
        // Consistency: a relative operator-set path is config-relative,
        // not cwd-relative, even though it is not the default sentinel.
        let c = AuthorityConfigBuilder::new(
            schema::AuthorityConfig {
                policy_dir: PathBuf::from("custom/policies"),
                schema_path: Some(PathBuf::from("schema.cedarschema")),
                ..configured_schema()
            },
            &state_layout(),
        )
        .without_tls()
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
        let c = AuthorityConfigBuilder::new(
            schema::AuthorityConfig {
                policy_dir: PathBuf::new(),
                ..configured_schema()
            },
            &state_layout(),
        )
        .without_tls()
        .rebase_defaults(std::path::Path::new("/cfg"))
        .build()
        .unwrap();
        assert_eq!(c.policy_dir, PathBuf::new());
    }

    #[test]
    fn rebase_preserves_explicit_policy_dir() {
        let c = AuthorityConfigBuilder::new(
            schema::AuthorityConfig {
                policy_dir: PathBuf::from("/explicit"),
                ..configured_schema()
            },
            &state_layout(),
        )
        .without_tls()
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
            "mapping_rules_paths = ['mapping-rules.toml']\nmax_ttl = \"30m\"\ntls_cert_path = \"authority.crt\"\ntls_key_path = \"authority.key\"\n",
        )
        .unwrap();
        let c =
            AuthorityConfig::load_resolved(&p, tmp.path(), &RuntimeLayout::from_root(tmp.path()))
                .unwrap();
        assert_eq!(c.max_ttl_seconds.get(), 1800);
        assert_eq!(c.policy_dir, tmp.path().join("policies"));
        let material = c.tls.material().expect("explicit pair enables TLS");
        assert_eq!(material.cert(), tmp.path().join("authority.crt"));
        assert_eq!(material.key(), tmp.path().join("authority.key"));
    }

    #[test]
    fn toml_deserialization() {
        let toml_str = r#"
listen_addr = "0.0.0.0:9090"
mapping_rules_paths = ["mapping-rules.toml"]
policy_dir = "/etc/firma/policies"
max_ttl = "30m"
"#;
        let config = AuthorityConfigBuilder::from_toml_str(toml_str, &state_layout())
            .unwrap_or_else(|e| panic!("{e}"))
            .without_tls()
            .build()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(config.listen_addr, "0.0.0.0:9090");
        assert_eq!(config.max_ttl_seconds.get(), 1800);
        // Defaults for unspecified fields
        assert_eq!(config.bundle_ttl_seconds.get(), 30);
    }

    #[test]
    fn authority_duration_conversion_rejects_fractional_and_out_of_range_values() {
        let mut schema = schema::AuthorityConfig {
            max_ttl: NonZeroDuration::new(std::time::Duration::from_millis(500))
                .unwrap_or_else(|error| panic!("{error}")),
            ..configured_schema()
        };
        assert!(matches!(
            AuthorityConfigBuilder::new(schema.clone(), &state_layout())
                .without_tls()
                .build(),
            Err(AuthorityConfigError::DurationNotWholeSeconds {
                field: "authority.max_ttl"
            })
        ));

        schema.max_ttl = NonZeroDuration::new(std::time::Duration::from_secs(2_147_483_648))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            AuthorityConfigBuilder::new(schema.clone(), &state_layout())
                .without_tls()
                .build(),
            Err(AuthorityConfigError::DurationOutOfRange {
                field: "authority.max_ttl"
            })
        ));

        schema.max_ttl = schema::AuthorityConfig::default().max_ttl;
        schema.bundle_ttl = NonZeroDuration::new(std::time::Duration::from_millis(500))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            AuthorityConfigBuilder::new(schema.clone(), &state_layout())
                .without_tls()
                .build(),
            Err(AuthorityConfigError::DurationNotWholeSeconds {
                field: "authority.bundle_ttl"
            })
        ));

        schema.bundle_ttl =
            NonZeroDuration::new(std::time::Duration::from_secs(u64::from(u32::MAX) + 1))
                .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            AuthorityConfigBuilder::new(schema, &state_layout())
                .without_tls()
                .build(),
            Err(AuthorityConfigError::DurationOutOfRange {
                field: "authority.bundle_ttl"
            })
        ));
    }
}

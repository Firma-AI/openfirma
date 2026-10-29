//! Sidecar credentials presented to Authority RPCs: a pre-shared key, carried
//! in request bodies and audit metadata, or the runtime credential of one
//! run, carried as a bearer in request metadata.

use std::fmt;
use std::path::{Path, PathBuf};

use firma_config_schema::sidecar::authority::SidecarCredentials as SchemaSidecarCredentials;
use firma_identifiers::RunId;
use firma_protobuf::v1::SidecarCredentials;
use tonic::metadata::{Ascii, MetadataValue};

/// The native Agent flow contract version every runtime-authenticated call
/// declares, in the `firma-agent-flow-version` metadata.
const AGENT_FLOW_VERSION_METADATA: &str = "firma-agent-flow-version";
/// The only contract version this Sidecar speaks.
const AGENT_FLOW_VERSION: &str = "1";

/// Validated source for Sidecar credentials: one pre-shared key source, or
/// one run's runtime credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarCredentialsConfig {
    /// Workspace the Sidecar belongs to.
    pub workspace_id: String,
    /// Authority-assigned Sidecar identity.
    pub sidecar_id: String,
    /// The single validated credential source.
    pub source: CredentialSource,
}

/// Mutually exclusive credential sources after schema validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialSource {
    /// Environment variable containing a pre-shared key.
    PreSharedKeyEnv(String),
    /// File containing a pre-shared key.
    PreSharedKeyFile(PathBuf),
    /// Runtime bearer environment variable and its validated run.
    Runtime { env: String, run_id: RunId },
}

/// Error validating a [`SidecarCredentialsConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SidecarCredentialsConfigError {
    /// `workspace_id` was empty.
    #[error("workspace_id must not be empty")]
    EmptyWorkspaceId,
    /// `sidecar_id` was empty.
    #[error("sidecar_id must not be empty")]
    EmptySidecarId,
    /// No credential source was set.
    #[error(
        "exactly one of pre_shared_key_env, pre_shared_key_path or runtime_credential_env must be set"
    )]
    MissingCredentialSource,
    /// More than one credential source was set.
    #[error(
        "pre_shared_key_env, pre_shared_key_path and runtime_credential_env are mutually exclusive"
    )]
    MultipleCredentialSources,
    /// `runtime_credential_env` and `run_id` were not set together.
    #[error("runtime_credential_env and run_id must be set together")]
    RuntimeCredentialAndRunMismatch,
    /// The run was not a canonical run identifier.
    #[error("run_id must be a valid RunId")]
    InvalidRunId,
}

impl TryFrom<SchemaSidecarCredentials> for SidecarCredentialsConfig {
    type Error = SidecarCredentialsConfigError;

    fn try_from(schema: SchemaSidecarCredentials) -> Result<Self, Self::Error> {
        if schema.workspace_id.trim().is_empty() {
            return Err(SidecarCredentialsConfigError::EmptyWorkspaceId);
        }
        if schema.sidecar_id.trim().is_empty() {
            return Err(SidecarCredentialsConfigError::EmptySidecarId);
        }
        let has_env = configured(schema.pre_shared_key_env.as_deref()).is_some();
        let has_path = schema
            .pre_shared_key_path
            .as_deref()
            .is_some_and(|path| !path.as_os_str().is_empty());
        let has_runtime = configured(schema.runtime_credential_env.as_deref()).is_some();
        let has_run = configured(schema.run_id.as_deref()).is_some();
        match usize::from(has_env) + usize::from(has_path) + usize::from(has_runtime) {
            1 => {}
            0 => return Err(SidecarCredentialsConfigError::MissingCredentialSource),
            _ => return Err(SidecarCredentialsConfigError::MultipleCredentialSources),
        }
        if has_runtime != has_run {
            return Err(SidecarCredentialsConfigError::RuntimeCredentialAndRunMismatch);
        }
        Ok(Self {
            workspace_id: schema.workspace_id,
            sidecar_id: schema.sidecar_id,
            source: if let Some(env) = configured(schema.runtime_credential_env.as_deref()) {
                CredentialSource::Runtime {
                    env: env.to_owned(),
                    run_id: schema
                        .run_id
                        .as_deref()
                        .ok_or(SidecarCredentialsConfigError::RuntimeCredentialAndRunMismatch)?
                        .parse()
                        .map_err(|_| SidecarCredentialsConfigError::InvalidRunId)?,
                }
            } else if let Some(env) = configured(schema.pre_shared_key_env.as_deref()) {
                CredentialSource::PreSharedKeyEnv(env.to_owned())
            } else {
                CredentialSource::PreSharedKeyFile(
                    schema
                        .pre_shared_key_path
                        .ok_or(SidecarCredentialsConfigError::MissingCredentialSource)?,
                )
            },
        })
    }
}

impl SidecarCredentialsConfig {
    /// Re-base a relative PSK file path against the config directory.
    pub fn rebase_defaults(&mut self, config_dir: &Path) {
        if let CredentialSource::PreSharedKeyFile(path) = &mut self.source
            && !path.as_os_str().is_empty()
            && path.is_relative()
        {
            *path = config_dir.join(&*path);
        }
    }

    /// Resolve the configured source into an in-memory credential.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected source cannot be read.
    pub fn resolve(&self) -> Result<SidecarCredential, String> {
        if let Some(env_name) = self.runtime_credential_env_name() {
            let value = std::env::var(env_name)
                .map_err(|_| format!("runtime credential env var {env_name} is not set"))?;
            return self.runtime_credential(&value);
        }
        self.resolve_pre_shared_key()
            .map(SidecarCredential::PreSharedKey)
    }

    /// The variable the runtime credential is read from, in runtime mode.
    #[must_use]
    pub fn runtime_credential_env_name(&self) -> Option<&str> {
        match &self.source {
            CredentialSource::Runtime { env, .. } => Some(env),
            _ => None,
        }
    }

    /// Whether this configuration authenticates one run with its
    /// runtime credential rather than an enrolled Sidecar with its key.
    #[must_use]
    pub fn uses_runtime_credential(&self) -> bool {
        self.runtime_credential_env_name().is_some()
    }

    /// The runtime credential `value`, scoped to the configured run:
    /// what [`Self::resolve`] builds from the variable, for a holder that
    /// already has the value, such as the `firma run` that activated it.
    ///
    /// # Errors
    ///
    /// Returns a message when the value is empty or cannot be carried in
    /// bearer metadata, or this configuration uses a pre-shared key.
    pub fn runtime_credential(&self, value: &str) -> Result<SidecarCredential, String> {
        let bearer = value.trim();
        if bearer.is_empty() {
            return Err("runtime credential is empty".to_string());
        }
        // Anything a header cannot carry is not a credential and fails here,
        // not on the wire.
        let mut authorization = MetadataValue::try_from(format!("Bearer {bearer}"))
            .map_err(|_| "runtime credential is not a valid bearer".to_string())?;
        authorization.set_sensitive(true);
        let CredentialSource::Runtime { run_id, .. } = &self.source else {
            return Err("credential source is not runtime".to_string());
        };
        Ok(SidecarCredential::Runtime(RuntimeCredential {
            workspace_id: self.workspace_id.clone(),
            sidecar_id: self.sidecar_id.clone(),
            run_id: *run_id,
            authorization,
        }))
    }

    fn resolve_pre_shared_key(&self) -> Result<ResolvedSidecarCredentials, String> {
        if let CredentialSource::PreSharedKeyEnv(env_name) = &self.source {
            let value = std::env::var(env_name)
                .map_err(|_| format!("pre-shared key env var {env_name} is not set"))?;
            let key = trim_trailing_newlines(value);
            if key.is_empty() {
                return Err(format!("pre-shared key env var {env_name} is empty"));
            }
            return Ok(ResolvedSidecarCredentials {
                workspace_id: self.workspace_id.clone(),
                sidecar_id: self.sidecar_id.clone(),
                pre_shared_key: RedactedPreSharedKey(key),
                source: SidecarCredentialSource::Env(env_name.clone()),
            });
        }

        let CredentialSource::PreSharedKeyFile(path) = &self.source else {
            unreachable!("PSK source selected before resolution")
        };
        let value = std::fs::read_to_string(path)
            .map_err(|error| format!("read pre-shared key file {}: {error}", path.display()))?;
        let key = trim_trailing_newlines(value);
        if key.is_empty() {
            return Err(format!("pre-shared key file {} is empty", path.display()));
        }
        Ok(ResolvedSidecarCredentials {
            workspace_id: self.workspace_id.clone(),
            sidecar_id: self.sidecar_id.clone(),
            pre_shared_key: RedactedPreSharedKey(key),
            source: SidecarCredentialSource::File(path.clone()),
        })
    }
}

/// Resolved credential source, kept for startup logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarCredentialSource {
    /// PSK was read from an environment variable.
    Env(String),
    /// PSK was read from a file.
    File(PathBuf),
}

impl SidecarCredentialSource {
    /// Return the source kind for structured logs.
    #[must_use]
    const fn kind(&self) -> &'static str {
        match self {
            Self::Env(_) => "env",
            Self::File(_) => "file",
        }
    }
}

/// The runtime credential of one run: a bearer the Authority issued at
/// activation, valid while that run is live.
#[derive(Debug, Clone)]
pub struct RuntimeCredential {
    workspace_id: String,
    sidecar_id: String,
    run_id: RunId,
    /// `Bearer <credential>`, marked sensitive so `Debug` prints it as
    /// `Sensitive` and HPACK never indexes it.
    authorization: MetadataValue<Ascii>,
}

/// How a Sidecar authenticates to the Authority.
#[derive(Debug, Clone)]
pub enum SidecarCredential {
    /// An enrolled Sidecar's pre-shared key, sent in request bodies and
    /// audit metadata.
    PreSharedKey(ResolvedSidecarCredentials),
    /// One run's runtime credential, sent as a bearer in the metadata
    /// of every call.
    Runtime(RuntimeCredential),
}

impl SidecarCredential {
    /// The Workspace the credential belongs to.
    #[must_use]
    pub(crate) fn workspace_id(&self) -> &str {
        match self {
            Self::PreSharedKey(credentials) => &credentials.workspace_id,
            Self::Runtime(credential) => &credential.workspace_id,
        }
    }

    /// The Sidecar identity the credential names.
    #[must_use]
    pub(crate) fn sidecar_id(&self) -> &str {
        match self {
            Self::PreSharedKey(credentials) => &credentials.sidecar_id,
            Self::Runtime(credential) => &credential.sidecar_id,
        }
    }

    /// The run a runtime credential is scoped to.
    #[must_use]
    pub fn run_id(&self) -> Option<&RunId> {
        match self {
            Self::PreSharedKey(_) => None,
            Self::Runtime(credential) => Some(&credential.run_id),
        }
    }

    /// The runtime credential itself, for the one holder that hands it to
    /// another process: the `firma run` that starts a run's Sidecar.
    #[must_use]
    pub fn runtime_bearer(&self) -> Option<&str> {
        match self {
            Self::PreSharedKey(_) => None,
            Self::Runtime(credential) => credential
                .authorization
                .to_str()
                .ok()?
                .strip_prefix("Bearer "),
        }
    }

    /// What the startup log names as the credential's source.
    #[must_use]
    pub(crate) fn source_kind(&self) -> &'static str {
        match self {
            Self::PreSharedKey(credentials) => credentials.source.kind(),
            Self::Runtime(_) => "runtime",
        }
    }

    /// The request body field a pre-shared key travels in; a runtime
    /// credential sends none.
    #[must_use]
    pub fn body_credentials(&self) -> Option<SidecarCredentials> {
        match self {
            Self::PreSharedKey(credentials) => Some(credentials.to_proto()),
            Self::Runtime(_) => None,
        }
    }

    /// `message` as the request `credentials` authenticates; keyless when
    /// none is configured.
    #[must_use]
    pub fn authenticated<T>(credentials: Option<&Self>, message: T) -> tonic::Request<T> {
        match credentials {
            Some(credential) => credential.request(message),
            None => tonic::Request::new(message),
        }
    }

    /// Wraps `message` in a request that carries the credential the way the
    /// Authority expects it: a runtime credential as the bearer plus the
    /// contract version in the metadata, a pre-shared key not at all (its
    /// body field is [`Self::body_credentials`]).
    #[must_use]
    fn request<T>(&self, message: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(message);
        if let Self::Runtime(credential) = self {
            let metadata = request.metadata_mut();
            metadata.insert("authorization", credential.authorization.clone());
            metadata.insert(
                AGENT_FLOW_VERSION_METADATA,
                MetadataValue::from_static(AGENT_FLOW_VERSION),
            );
        }
        request
    }
}

/// Resolved Sidecar credentials ready to attach to Authority requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSidecarCredentials {
    /// Workspace the Sidecar belongs to.
    pub(crate) workspace_id: String,
    /// Authority-assigned Sidecar identity.
    pub(crate) sidecar_id: String,
    /// Resolved pre-shared key.
    pub(crate) pre_shared_key: RedactedPreSharedKey,
    /// Source used to resolve the PSK.
    pub(crate) source: SidecarCredentialSource,
}

impl ResolvedSidecarCredentials {
    /// Convert to the generated protobuf message.
    #[must_use]
    fn to_proto(&self) -> SidecarCredentials {
        SidecarCredentials {
            workspace_id: self.workspace_id.clone(),
            sidecar_id: self.sidecar_id.clone(),
            pre_shared_key: self.pre_shared_key.expose_secret().to_string(),
        }
    }
}

/// Pre-shared key wrapper with redacted debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedPreSharedKey(String);

impl RedactedPreSharedKey {
    /// Wrap a plaintext pre-shared key.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    /// Expose the plaintext secret for the final Authority request message.
    #[must_use]
    fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RedactedPreSharedKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RedactedPreSharedKey(...)")
    }
}

/// `value` when it is set and not blank.
fn configured(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn trim_trailing_newlines(mut value: String) -> String {
    while value.ends_with('\n') || value.ends_with('\r') {
        value.pop();
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_missing_psk_source() {
        let schema = SchemaSidecarCredentials {
            workspace_id: "ws".to_string(),
            sidecar_id: "sc".to_string(),
            pre_shared_key_env: None,
            pre_shared_key_path: None,
            run_id: None,
            runtime_credential_env: None,
        };
        assert!(matches!(
            SidecarCredentialsConfig::try_from(schema),
            Err(SidecarCredentialsConfigError::MissingCredentialSource)
        ));
    }

    #[test]
    fn validate_rejects_both_psk_sources() {
        let schema = SchemaSidecarCredentials {
            workspace_id: "ws".to_string(),
            sidecar_id: "sc".to_string(),
            pre_shared_key_env: Some("FIRMA_PSK".to_string()),
            pre_shared_key_path: Some(PathBuf::from("psk")),
            run_id: None,
            runtime_credential_env: None,
        };
        assert!(matches!(
            SidecarCredentialsConfig::try_from(schema),
            Err(SidecarCredentialsConfigError::MultipleCredentialSources)
        ));
    }

    #[test]
    fn validate_rejects_empty_identity() {
        let schema = SchemaSidecarCredentials {
            workspace_id: " ".to_string(),
            sidecar_id: "sc".to_string(),
            pre_shared_key_env: Some("FIRMA_PSK".to_string()),
            pre_shared_key_path: None,
            run_id: None,
            runtime_credential_env: None,
        };
        assert!(matches!(
            SidecarCredentialsConfig::try_from(schema),
            Err(SidecarCredentialsConfigError::EmptyWorkspaceId)
        ));
    }

    #[test]
    fn file_resolution_trims_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("psk");
        std::fs::write(&path, "secret\n").unwrap();
        let config = SidecarCredentialsConfig {
            workspace_id: "ws".to_string(),
            sidecar_id: "sc".to_string(),
            source: CredentialSource::PreSharedKeyFile(path),
        };

        let SidecarCredential::PreSharedKey(resolved) = config.resolve().unwrap() else {
            panic!("a pre-shared key source resolves to a pre-shared key");
        };

        assert_eq!(resolved.pre_shared_key.expose_secret(), "secret");
        assert!(matches!(resolved.source, SidecarCredentialSource::File(_)));
    }

    #[test]
    fn file_resolution_rejects_missing_file() {
        let config = SidecarCredentialsConfig {
            workspace_id: "ws".to_string(),
            sidecar_id: "sc".to_string(),
            source: CredentialSource::PreSharedKeyFile(PathBuf::from("/no/such/firma/psk")),
        };

        assert!(
            config
                .resolve()
                .unwrap_err()
                .contains("read pre-shared key file")
        );
    }

    #[test]
    fn rebase_defaults_rebases_relative_path() {
        let mut config = SidecarCredentialsConfig {
            workspace_id: "ws".to_string(),
            sidecar_id: "sc".to_string(),
            source: CredentialSource::PreSharedKeyFile(PathBuf::from("secrets/psk")),
        };

        config.rebase_defaults(Path::new("/etc/firma"));

        assert_eq!(
            config.source,
            CredentialSource::PreSharedKeyFile(PathBuf::from("/etc/firma/secrets/psk"))
        );
    }

    #[test]
    fn debug_redacts_secret() {
        let secret = RedactedPreSharedKey("secret-value".to_string());

        let rendered = format!("{secret:?}");

        assert!(rendered.contains("RedactedPreSharedKey"));
        assert!(!rendered.contains("secret-value"));
    }
}

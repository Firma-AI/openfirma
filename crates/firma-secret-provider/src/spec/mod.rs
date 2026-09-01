//! Secret-provider integration specs: how to classify provider commands and
//! extract secrets from provider output. Callers own placeholder minting and
//! persistence for extracted values.
//!
//! A provider is either a CLI vault tool (stdout intercepted by firma-run's
//! broker via a stdio shim) or an HTTP vault (response bodies intercepted by
//! firma-sidecar's MITM path). The two shapes are deliberately distinct
//! enum variants rather than one struct with optional fields, so a config
//! mixing CLI-only and HTTP-only attributes (e.g. an HTTP entry carrying a
//! `binary_name`) cannot be represented.

use firma_config_schema::secret_provider::SecretProviderConfig;
use firma_core::SecretMatcher;
use serde::Serialize;

use crate::{
    MatcherCompiler,
    non_empty::{NonEmptyString, NonEmptyVec},
};

pub mod cli;
pub mod http;

/// A validated secret-provider integration: either a CLI vault tool or an
/// HTTP vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IntegrationSpec<Matcher> {
    /// Validated CLI integration.
    Cli(cli::CliIntegrationSpec<Matcher>),
    /// HTTP integration.
    Http(http::HttpIntegrationSpec<Matcher>),
}

/// Error returned when validating an [`SecretProviderConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrationConfigError {
    /// CLI integration validation failed.
    #[error(transparent)]
    Cli(#[from] cli::CliIntegrationConfigError),
    /// HTTP integration validation failed.
    #[error(transparent)]
    Http(#[from] http::HttpSecretProviderConfigError),
}

impl TryFrom<SecretProviderConfig> for IntegrationSpec<SecretMatcher> {
    type Error = IntegrationConfigError;

    fn try_from(config: SecretProviderConfig) -> Result<Self, Self::Error> {
        match config {
            SecretProviderConfig::Cli(config) => {
                Ok(Self::Cli(cli::CliIntegrationSpec::try_from(config)?))
            }
            SecretProviderConfig::Http(config) => {
                Ok(Self::Http(http::HttpIntegrationSpec::try_from(config)?))
            }
        }
    }
}

impl<Matcher> IntegrationSpec<Matcher> {
    /// Stable integration identity (e.g. `"bitwarden"`, `"aws-secrets-manager"`),
    /// for both origins. Consumers use it to associate extracted secrets with
    /// the integration that produced them.
    #[must_use]
    pub fn provider_id(&self) -> &str {
        match self {
            Self::Cli(spec) => spec.provider_id(),
            Self::Http(spec) => &spec.provider_id,
        }
    }

    /// Returns the CLI spec, if this is a CLI-origin provider.
    #[must_use]
    pub fn as_cli(&self) -> Option<&cli::CliIntegrationSpec<Matcher>> {
        match self {
            Self::Cli(spec) => Some(spec),
            Self::Http(_) => None,
        }
    }

    /// Returns the HTTP spec, if this is an HTTP-origin provider.
    #[must_use]
    pub fn as_http(&self) -> Option<&http::HttpIntegrationSpec<Matcher>> {
        match self {
            Self::Http(spec) => Some(spec),
            Self::Cli(_) => None,
        }
    }
}

/// Outcome of resolving a invocation's args against a spec.
/// See [`cli::CliIntegrationSpec::resolve_args`] and [`http::HttpIntegrationSpec::matcher_for`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchingResolution<'a, Matcher> {
    /// Extract and redact secrets from stdout using this matcher.
    Matcher(&'a Matcher),
    /// Known-safe invocation shape that never emits secret material; forward
    /// stdout unredacted, no matcher applied.
    PassThrough,
    /// Unrecognized invocation shape; fail closed and deny the invocation
    /// rather than risk forwarding unredacted secret material.
    Blocked,
}

/// One candidate rule for [`cli::CliIntegrationSpec`] and [`http::HttpIntegrationSpec`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MatcherRule<A, B> {
    /// Command we want to redact secret from
    SensitiveCommand(A),
    /// Command we let through without redaction
    SafeCommand(B),
    /// Command we know should be forbidden no matter what
    BlockedCommand(B),
}

impl<A, B> MatcherRule<A, B> {
    fn as_sensitive_command(&self) -> Option<&A> {
        match self {
            Self::SensitiveCommand(a) => Some(a),
            _ => None,
        }
    }

    fn as_safe_command(&self) -> Option<&B> {
        match self {
            Self::SafeCommand(b) => Some(b),
            _ => None,
        }
    }

    fn as_blocked_command(&self) -> Option<&B> {
        match self {
            Self::BlockedCommand(b) => Some(b),
            _ => None,
        }
    }
}

impl<A, B> MatcherCompiler for MatcherRule<A, B>
where
    A: MatcherCompiler,
    B: Clone,
{
    type Ok = MatcherRule<A::Ok, B>;

    fn compile(&self) -> Result<Self::Ok, crate::MatcherError> {
        match self {
            Self::SensitiveCommand(a) => Ok(MatcherRule::SensitiveCommand(a.compile()?)),
            Self::SafeCommand(b) => Ok(MatcherRule::SafeCommand(b.clone())),
            Self::BlockedCommand(b) => Ok(MatcherRule::BlockedCommand(b.clone())),
        }
    }
}

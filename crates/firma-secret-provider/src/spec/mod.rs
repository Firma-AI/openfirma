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

use firma_core::SecretMatcher;

use crate::non_empty::{NonEmptyString, NonEmptyVec};

pub mod cli;
pub mod http;

/// A resolved secret-provider integration: either a CLI vault tool or an
/// HTTP vault.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IntegrationSpec {
    Cli(cli::CliIntegrationSpec),
    Http(http::HttpIntegrationSpec),
}

impl IntegrationSpec {
    /// Stable integration identity (e.g. `"bitwarden"`, `"aws-secrets-manager"`),
    /// for both origins. Consumers use it to associate extracted secrets with
    /// the integration that produced them.
    #[must_use]
    pub fn provider_id(&self) -> &str {
        match self {
            Self::Cli(spec) => &spec.provider_id,
            Self::Http(spec) => &spec.provider_id,
        }
    }

    /// Returns the CLI spec, if this is a CLI-origin provider.
    #[must_use]
    pub fn as_cli(&self) -> Option<&cli::CliIntegrationSpec> {
        match self {
            Self::Cli(spec) => Some(spec),
            Self::Http(_) => None,
        }
    }

    /// Returns the HTTP spec, if this is an HTTP-origin provider.
    #[must_use]
    pub fn as_http(&self) -> Option<&http::HttpIntegrationSpec> {
        match self {
            Self::Http(spec) => Some(spec),
            Self::Cli(_) => None,
        }
    }
}

/// Outcome of resolving a invocation's args against a spec.
/// See [`cli::CliIntegrationSpec::resolve_args`] and [`http::HttpIntegrationSpec::matcher_for`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchingResolution<'a> {
    /// Extract and redact secrets from stdout using this matcher.
    Matcher(&'a SecretMatcher),
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

use firma_config_schema::secret_provider::http::{HttpMatcherRuleConfig, HttpSecretProviderConfig};
use firma_core::SecretMatcher;
use serde::Serialize;

use crate::{CompiledMatcher, MatcherCompiler, MatcherError, glob::glob_match};

use super::{MatcherRule, MatchingResolution, NonEmptyString};

pub type HttpMatcherRule<Matcher> = MatcherRule<PathAndMatcher<Matcher>, PathOnly>;

/// Error converting a [`HttpSecretProviderConfig`] (the concrete `firma.toml`
/// representation) into a runtime [`HttpIntegrationSpec`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpSecretProviderConfigError {
    /// A `safe_command` / `blocked_command` rule had an empty `path`.
    #[error("matcher path must not be empty")]
    EmptyPath,
}

impl TryFrom<HttpSecretProviderConfig> for HttpIntegrationSpec<SecretMatcher> {
    type Error = HttpSecretProviderConfigError;

    fn try_from(config: HttpSecretProviderConfig) -> Result<Self, Self::Error> {
        let HttpSecretProviderConfig {
            provider_id,
            host,
            matchers,
        } = config;
        let matchers = matchers
            .into_iter()
            .map(convert_http_matcher_rule)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            provider_id,
            host,
            matchers,
        })
    }
}

fn convert_http_matcher_rule(
    rule: HttpMatcherRuleConfig,
) -> Result<HttpMatcherRule<SecretMatcher>, HttpSecretProviderConfigError> {
    Ok(match rule {
        HttpMatcherRuleConfig::SensitiveCommand { path, matcher } => {
            MatcherRule::SensitiveCommand(PathAndMatcher { path, matcher })
        }
        HttpMatcherRuleConfig::SafeCommand { path } => MatcherRule::SafeCommand(PathOnly {
            path: non_empty_path(path)?,
        }),
        HttpMatcherRuleConfig::BlockedCommand { path } => MatcherRule::BlockedCommand(PathOnly {
            path: non_empty_path(path)?,
        }),
    })
}

fn non_empty_path(path: String) -> Result<NonEmptyString, HttpSecretProviderConfigError> {
    NonEmptyString::new(path).map_err(|_| HttpSecretProviderConfigError::EmptyPath)
}

/// Per-HTTP-vault behavior spec: which traffic to intercept and how to extract
/// secrets from the response body. Callers own placeholder minting and
/// persistence for extracted values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HttpIntegrationSpec<Matcher> {
    /// Stable integration identity (e.g. `"aws-secrets-manager"`).
    pub provider_id: String,
    /// Host glob pattern to match against MITM'd responses (e.g.
    /// `"secretsmanager.*.amazonaws.com"`).
    pub host: String,
    /// Candidate matchers, tried against the request path via
    /// [`HttpIntegrationSpec::matcher_for`]. A single host can return
    /// different response shapes on different endpoints (e.g. a "list
    /// secrets" path returning an array vs. a "get secret" path returning a
    /// single record), so the matcher to apply is resolved per path rather
    /// than fixed per host.
    pub matchers: Vec<HttpMatcherRule<Matcher>>,
}

impl<Matcher> HttpIntegrationSpec<Matcher> {
    /// Resolves the matcher to apply for a response observed on `path`.
    ///
    /// Follows a specific order:
    /// * first blocked commands, that should be forbidden no matter what
    /// * second sensitive commands, to apply secret redaction
    /// * third safe commands, to let through without redaction
    ///
    /// Any command not falling in any of those rules will be blocked as an
    /// extra safety measure.
    #[must_use]
    pub fn matcher_for(&self, path: &str) -> MatchingResolution<'_, Matcher> {
        // blocked commands
        if self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_blocked_command)
            .any(|rule| glob_match(&rule.path, path))
        {
            return MatchingResolution::Blocked;
        }

        // sensitive commands
        if let Some(rule) = self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_sensitive_command)
            .find(|rule| {
                rule.path
                    .as_deref()
                    .is_none_or(|glob| glob_match(glob, path))
            })
        {
            return MatchingResolution::Matcher(&rule.matcher);
        }

        // safe commands
        if self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_safe_command)
            .any(|rule| glob_match(&rule.path, path))
        {
            return MatchingResolution::PassThrough;
        }

        MatchingResolution::Blocked
    }
}

impl MatcherCompiler for HttpIntegrationSpec<SecretMatcher> {
    type Ok = HttpIntegrationSpec<CompiledMatcher>;

    fn compile(&self) -> Result<Self::Ok, MatcherError> {
        let Self {
            provider_id,
            host,
            matchers,
        } = self;

        let matchers = matchers
            .iter()
            .map(MatcherCompiler::compile)
            .collect::<Result<_, _>>()?;

        Ok(HttpIntegrationSpec {
            provider_id: provider_id.clone(),
            host: host.clone(),
            matchers,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PathAndMatcher<Matcher> {
    /// Path glob pattern (e.g. `"/v1/secrets/*"`). `None` matches any path on
    /// the spec's host and acts as the spec's fallback.
    pub path: Option<String>,
    /// How to extract `(name, value)` pairs from the tool's stdout.
    pub matcher: Matcher,
}

impl MatcherCompiler for PathAndMatcher<SecretMatcher> {
    type Ok = PathAndMatcher<CompiledMatcher>;

    fn compile(&self) -> Result<Self::Ok, MatcherError> {
        let Self { path, matcher } = self;

        let matcher = CompiledMatcher::compile(matcher)?;

        Ok(PathAndMatcher {
            path: path.clone(),
            matcher,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PathOnly {
    /// Path glob pattern (e.g. `"/v1/secrets/*"`). `None` matches any path on
    /// the spec's host and acts as the spec's fallback.
    pub path: NonEmptyString,
}

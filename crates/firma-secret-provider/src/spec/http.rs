use crate::glob::glob_match;

use super::{MatcherRule, MatchingResolution, NonEmptyString, SecretMatcher};

pub type HttpMatcherRule = MatcherRule<PathAndMatcher, PathOnly>;

/// Per-HTTP-vault behavior spec: which traffic to intercept and how to extract
/// secrets from the response body. Callers own placeholder minting and
/// persistence for extracted values.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpIntegrationSpec {
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
    pub matchers: Vec<HttpMatcherRule>,
}

impl HttpIntegrationSpec {
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
    pub fn matcher_for(&self, path: &str) -> MatchingResolution<'_> {
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PathAndMatcher {
    /// Path glob pattern (e.g. `"/v1/secrets/*"`). `None` matches any path on
    /// the spec's host and acts as the spec's fallback.
    pub path: Option<String>,
    /// How to extract `(name, value)` pairs from the tool's stdout.
    pub matcher: SecretMatcher,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PathOnly {
    /// Path glob pattern (e.g. `"/v1/secrets/*"`). `None` matches any path on
    /// the spec's host and acts as the spec's fallback.
    pub path: NonEmptyString,
}

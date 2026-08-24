//! Schema for `[[sidecar.http_secret_providers]]`.
//!
//! Concrete, non-generic representation of exactly what an operator writes in
//! `firma.toml` for an HTTP secret provider. `firma-secret-provider` converts
//! these into its runtime `HttpIntegrationSpec<SecretMatcher>` type (generic
//! over the matcher, and carrying the extraction behavior).

use serde::{Deserialize, Serialize};

use crate::secret_matcher::SecretMatcher;

/// One HTTP secret provider: which host to intercept and how to classify and
/// extract secrets from its responses.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HttpSecretProviderConfig {
    /// Stable integration identity (e.g. `"aws-secrets-manager"`).
    pub provider_id: String,
    /// Host glob pattern to match against MITM'd responses (e.g.
    /// `"secretsmanager.*.amazonaws.com"`).
    pub host: String,
    /// Candidate rules, tried against the request path. A single host can
    /// return different response shapes on different endpoints, so the rule to
    /// apply is resolved per path rather than fixed per host.
    pub matchers: Vec<HttpMatcherRuleConfig>,
}

/// One candidate rule for an [`HttpSecretProviderConfig`].
///
/// Tagged by `type` (`sensitive_command` / `safe_command` / `blocked_command`)
/// so it nests as a flat TOML table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HttpMatcherRuleConfig {
    /// Response whose body must be scanned and redacted using `matcher`.
    SensitiveCommand {
        /// Path glob pattern. `None` matches any path on the host and acts as
        /// the fallback.
        #[serde(default)]
        path: Option<String>,
        /// How to extract `(name, value)` pairs from the response body.
        matcher: SecretMatcher,
    },
    /// Known-safe path whose response never carries secrets; forwarded
    /// unredacted.
    SafeCommand {
        /// Path glob pattern. Must not be empty.
        path: String,
    },
    /// Path that must always be denied.
    BlockedCommand {
        /// Path glob pattern. Must not be empty.
        path: String,
    },
}

//! Secret-provider integration specs: how to extract secrets from a
//! provider's output and how to mint placeholder tokens for them.
//!
//! A provider is either a CLI vault tool (stdout intercepted by firma-run's
//! broker via a stdio shim) or an HTTP vault (response bodies intercepted by
//! firma-sidecar's MITM path). The two shapes are deliberately distinct
//! enum variants rather than one struct with optional fields, so a config
//! mixing CLI-only and HTTP-only attributes (e.g. an HTTP entry carrying a
//! `binary_name`) cannot be represented.

use firma_core::SecretMatcher;

/// A resolved secret-provider integration: either a CLI vault tool or an
/// HTTP vault.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IntegrationSpec {
    Cli(CliIntegrationSpec),
    Http(HttpIntegrationSpec),
}

impl IntegrationSpec {
    /// Stable integration identity (e.g. `"bitwarden"`, `"aws-secrets-manager"`).
    /// Used as the Cedar `Firma::SecretProvider` entity's id, for both origins.
    #[must_use]
    pub fn provider_id(&self) -> &str {
        match self {
            Self::Cli(spec) => &spec.provider_id,
            Self::Http(spec) => &spec.provider_id,
        }
    }

    /// Returns the CLI spec, if this is a CLI-origin provider.
    #[must_use]
    pub fn as_cli(&self) -> Option<&CliIntegrationSpec> {
        match self {
            Self::Cli(spec) => Some(spec),
            Self::Http(_) => None,
        }
    }

    /// Returns the HTTP spec, if this is an HTTP-origin provider.
    #[must_use]
    pub fn as_http(&self) -> Option<&HttpIntegrationSpec> {
        match self {
            Self::Http(spec) => Some(spec),
            Self::Cli(_) => None,
        }
    }
}

/// Per-CLI-tool behavior spec: credentials to forward, how to extract
/// secrets from stdout, and how to mint placeholder tokens for the
/// extracted values.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CliIntegrationSpec {
    /// Binary basename (e.g. `"bws"`).
    pub binary_name: String,
    /// Stable integration identity (e.g. `"bitwarden"` for the `bws` binary).
    /// Used as the Cedar `Firma::SecretProvider` entity's id — distinct from
    /// `binary_name`, which is the per-invocation executable and belongs on
    /// `resource.bin` instead.
    pub provider_id: String,
    /// Names of env vars that carry vault credentials. The broker forwards any
    /// that are present in its own environment to the subprocess.
    pub credential_env_vars: Vec<String>,
    /// How to extract `(name, value)` pairs from the tool's stdout.
    pub matcher: SecretMatcher,
    /// Template for minting placeholder tokens; `{name}` is substituted with the
    /// percent-encoded secret key.
    pub placeholder_template: String,
    /// Arg flags to strip from the shim's requested args before appending
    /// `forced_args`. Both `--flag value` (two-token) and `--flag=value`
    /// (single-token) forms are matched. Example: `vec!["--format"]`.
    pub strip_arg_flags: Vec<String>,
    /// Args appended to the subprocess command after stripping. Used to force a
    /// specific output format that the matcher expects.
    /// Example: `vec!["--format", "json"]`.
    pub forced_args: Vec<String>,
}

/// Per-HTTP-vault behavior spec: which traffic to intercept, how to extract
/// secrets from the response body, and how to mint placeholder tokens for
/// the extracted values.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpIntegrationSpec {
    /// Stable integration identity (e.g. `"aws-secrets-manager"`). Used as
    /// the Cedar `Firma::SecretProvider` entity's id.
    pub provider_id: String,
    /// Host glob pattern to match against MITM'd responses (e.g.
    /// `"secretsmanager.*.amazonaws.com"`).
    pub host: String,
    /// Optional path glob pattern. When absent, matches any path on `host`.
    pub path: Option<String>,
    /// How to extract `(name, value)` pairs from the response body.
    pub matcher: SecretMatcher,
    /// Template for minting placeholder tokens; `{name}` is substituted with the
    /// percent-encoded secret key.
    pub placeholder_template: String,
}

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
    /// Stable integration identity (e.g. `"bitwarden"`, `"aws-secrets-manager"`),
    /// for both origins. Used to key placeholder minting and to scope pushes
    /// to the broker's secret store.
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
    /// Stable integration identity (e.g. `"bitwarden"` for the `bws` binary) —
    /// distinct from `binary_name`, which is the per-invocation executable.
    pub provider_id: String,
    /// Names of env vars that carry vault credentials. The broker forwards any
    /// that are present in its own environment to the subprocess.
    pub credential_env_vars: Vec<String>,
    /// Candidate rules, tried against the invocation's args via
    /// [`CliIntegrationSpec::resolve_args`]. A single binary can emit
    /// different output shapes for different subcommands (e.g. `bws secret
    /// list` returns an array of records, `bws secret get` returns a single
    /// record), so the rule to apply is resolved per invocation rather than
    /// fixed per binary. An invocation whose args match no rule here is
    /// [`CliArgsResolution::Blocked`] — fail closed, since an unrecognized
    /// invocation shape may emit secret material this registry has no way to
    /// extract or redact.
    pub matchers: Vec<CliMatcherRule>,
    /// Arg flags to strip from the shim's requested args before appending
    /// `forced_args`. Both `--flag value` (two-token) and `--flag=value`
    /// (single-token) forms are matched. Example: `vec!["--format"]`.
    pub strip_arg_flags: Vec<String>,
    /// Args appended to the subprocess command after stripping. Used to force a
    /// specific output format that the matcher expects.
    /// Example: `vec!["--format", "json"]`.
    pub forced_args: Vec<String>,
}

impl CliIntegrationSpec {
    /// Resolves how the broker should handle an invocation with the given
    /// args: apply a matcher, forward stdout unredacted as a known-safe
    /// pass-through, or block the invocation outright.
    ///
    /// Rules with a specific `args_match` prefix are tried first, in
    /// declaration order; a rule with `args_match: None` is the fallback
    /// default. The selected rule's `matcher` decides the outcome: `Some`
    /// extracts and redacts via that matcher, `None` is a known-safe
    /// pass-through (the rule exists only to name an argv shape that never
    /// emits secret material). If no rule matches and there is no fallback,
    /// the invocation is [`CliArgsResolution::Blocked`].
    #[must_use]
    pub fn resolve_args(&self, args: &[String]) -> CliArgsResolution<'_> {
        let rule = self
            .matchers
            .iter()
            .find(|rule| {
                rule.args_match
                    .as_deref()
                    .is_some_and(|prefix| args.starts_with(prefix))
            })
            .or_else(|| self.matchers.iter().find(|rule| rule.args_match.is_none()));

        match rule {
            Some(CliMatcherRule {
                matcher: Some(matcher),
                ..
            }) => CliArgsResolution::Matcher(matcher),
            Some(CliMatcherRule { matcher: None, .. }) => CliArgsResolution::PassThrough,
            None => CliArgsResolution::Blocked,
        }
    }

    /// Validates the spec's `matchers`.
    ///
    /// Rejects a rule that combines `args_match: None` (the spec's
    /// fallback, selected when no more specific rule matches) with
    /// `matcher: None` (a pass-through, forwarding stdout unredacted with no
    /// extraction). Unlike a pass-through scoped to a specific `args_match`
    /// prefix, that combination applies to *every* invocation not caught by
    /// a more specific rule, silently defeating
    /// [`CliIntegrationSpec::resolve_args`]'s fail-closed default — almost
    /// certainly not what was intended.
    ///
    /// # Errors
    ///
    /// Returns [`CliSpecError::AmbiguousFallbackPassThrough`] if such a rule
    /// is present.
    pub fn validate(&self) -> Result<(), CliSpecError> {
        if self
            .matchers
            .iter()
            .any(|rule| rule.args_match.is_none() && rule.matcher.is_none())
        {
            return Err(CliSpecError::AmbiguousFallbackPassThrough {
                binary_name: self.binary_name.clone(),
            });
        }
        Ok(())
    }

    /// Rewrites the shim-requested args for the actual subprocess
    /// invocation: strips any `strip_arg_flags` entry (both `--flag value`
    /// and `--flag=value` forms) and appends `forced_args`.
    #[must_use]
    pub fn rewrite_args(&self, args: &[String]) -> Vec<String> {
        let mut rewritten = Vec::with_capacity(args.len() + self.forced_args.len());
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            let flag = arg.split('=').next().unwrap_or(arg.as_str());
            if self.strip_arg_flags.iter().any(|f| f == flag) {
                if !arg.contains('=') {
                    iter.next();
                }
                continue;
            }
            rewritten.push(arg.clone());
        }
        rewritten.extend(self.forced_args.iter().cloned());
        rewritten
    }
}

/// Outcome of resolving a CLI invocation's args against a
/// [`CliIntegrationSpec`]. See [`CliIntegrationSpec::resolve_args`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliArgsResolution<'a> {
    /// Extract and redact secrets from stdout using this matcher.
    Matcher(&'a SecretMatcher),
    /// Known-safe invocation shape that never emits secret material; forward
    /// stdout unredacted, no matcher applied.
    PassThrough,
    /// Unrecognized invocation shape; fail closed and deny the invocation
    /// rather than risk forwarding unredacted secret material.
    Blocked,
}

/// Errors from validating a [`CliIntegrationSpec`]. See
/// [`CliIntegrationSpec::validate`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CliSpecError {
    /// A rule combines `args_match: None` (the spec's fallback) with
    /// `matcher: None` (a pass-through), so it silently forwards every
    /// invocation not caught by a more specific rule instead of failing
    /// closed to [`CliArgsResolution::Blocked`].
    #[error(
        "{binary_name}: a matcher rule combines args_match: None (fallback) with matcher: None \
         (pass-through), which passes every unmatched invocation through unredacted instead of \
         failing closed; give the fallback rule a real matcher or remove it"
    )]
    AmbiguousFallbackPassThrough {
        /// The spec's binary name, for a useful error message.
        binary_name: String,
    },
}

/// One candidate rule for a [`CliIntegrationSpec`], scoped to invocations
/// whose args start with `args_match` (or to any invocation, if `None`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CliMatcherRule {
    /// Argv prefix (subcommand and positional args, e.g. `["secret",
    /// "get"]`) that an invocation's args must start with to select this
    /// rule. `None` matches any invocation and acts as the spec's fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_match: Option<Vec<String>>,
    /// How to extract `(name, value)` pairs from the tool's stdout. `None`
    /// marks `args_match` as a known-safe pass-through: an argv shape that
    /// never emits secret material, so stdout is forwarded unredacted with
    /// no extraction attempted. Combining this with `args_match: None` is
    /// rejected by [`CliIntegrationSpec::validate`] — see that method's docs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<SecretMatcher>,
}

/// Per-HTTP-vault behavior spec: which traffic to intercept, how to extract
/// secrets from the response body, and how to mint placeholder tokens for
/// the extracted values.
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
    /// Rules with a specific `path` glob are tried first, in declaration
    /// order; a rule with `path: None` is the fallback default. Returns
    /// `None` if no rule matches and there is no fallback.
    #[must_use]
    pub fn matcher_for(&self, path: &str) -> Option<&SecretMatcher> {
        self.matchers
            .iter()
            .find(|rule| {
                rule.path
                    .as_deref()
                    .is_some_and(|glob| glob_match(glob, path))
            })
            .or_else(|| self.matchers.iter().find(|rule| rule.path.is_none()))
            .map(|rule| &rule.matcher)
    }
}

/// One candidate matcher for a [`HttpIntegrationSpec`], scoped to requests
/// whose path matches `path` (or to any path on the spec's host, if `None`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpMatcherRule {
    /// Path glob pattern (e.g. `"/v1/secrets/*"`). `None` matches any path on
    /// the spec's host and acts as the spec's fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// How to extract `(name, value)` pairs from the response body.
    pub matcher: SecretMatcher,
}

/// Simple glob matching supporting `*` as a wildcard matching any sequence of
/// characters (including path separators).
///
/// - `*` matches anything.
/// - `/v1/secrets/*` matches `/v1/secrets/get` and `/v1/secrets/get/abc`.
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }

    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match value[pos..].find(part) {
            Some(found) => {
                if i == 0 && found != 0 {
                    return false;
                }
                pos += found + part.len();
            }
            None => return false,
        }
    }

    match parts.last() {
        Some(last) if !last.is_empty() => value.ends_with(last),
        _ => true,
    }
}

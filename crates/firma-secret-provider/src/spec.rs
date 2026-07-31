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

use crate::non_empty::NonEmptyVec;

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
    /// Follows a specific order:
    /// * first blocked commands, that should be forbidden no matter what
    /// * second sensitive commands, to apply secret redaction
    /// * third safe commands, to let through without redaction
    ///
    /// Any command not falling in any of those rules will be blocked as an
    /// extra safety measure.
    #[must_use]
    pub fn resolve_args(&self, args: &[String]) -> CliArgsResolution<'_> {
        // blocked commands
        if self
            .matchers
            .iter()
            .filter_map(CliMatcherRule::as_blocked_command)
            .any(|args_and_matcher| args.starts_with(&args_and_matcher.args_match))
        {
            return CliArgsResolution::Blocked;
        }

        // sensitive commands
        if let Some(args_and_matcher) = self
            .matchers
            .iter()
            .filter_map(CliMatcherRule::as_sensitive_command)
            .find(|args_and_matcher| args.starts_with(&args_and_matcher.args_match))
        {
            return CliArgsResolution::Matcher(&args_and_matcher.matcher);
        }

        // safe commands
        if self
            .matchers
            .iter()
            .filter_map(CliMatcherRule::as_safe_command)
            .any(|args_and_matcher| args.starts_with(&args_and_matcher.args_match))
        {
            return CliArgsResolution::PassThrough;
        }

        CliArgsResolution::Blocked
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

/// One candidate rule for a [`CliIntegrationSpec`], scoped to invocations
/// whose args start with `args_match` (or to any invocation, if `None`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CliMatcherRule {
    /// Command we want to redact secret from
    SensitiveCommand(ArgsAndMatcher),
    /// Command we let through without redaction
    SafeCommand(ArgsOnly),
    /// Command we know should be forbidden no matter what
    BlockedCommand(ArgsOnly),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArgsAndMatcher {
    /// Argv prefix (subcommand and positional args, e.g. `["secret",
    /// "get"]`) that an invocation's args must start with to select this
    /// rule.
    #[serde(default)]
    pub args_match: Vec<String>,
    /// How to extract `(name, value)` pairs from the tool's stdout.
    pub matcher: SecretMatcher,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArgsOnly {
    /// Argv prefix (subcommand and positional args, e.g. `["secret",
    /// "get"]`) that an invocation's args must start with to select this
    /// rule.
    pub args_match: NonEmptyVec<String>,
}

impl CliMatcherRule {
    fn as_sensitive_command(&self) -> Option<&ArgsAndMatcher> {
        match self {
            Self::SensitiveCommand(args_and_matcher) => Some(args_and_matcher),
            _ => None,
        }
    }

    fn as_safe_command(&self) -> Option<&ArgsOnly> {
        match self {
            Self::SafeCommand(args) => Some(args),
            _ => None,
        }
    }

    fn as_blocked_command(&self) -> Option<&ArgsOnly> {
        match self {
            Self::BlockedCommand(args) => Some(args),
            _ => None,
        }
    }
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

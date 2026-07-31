use super::{MatcherRule, MatchingResolution, NonEmptyVec, SecretMatcher};

pub type CliMatcherRule = MatcherRule<ArgsAndMatcher, ArgsOnly>;

/// Per-CLI-tool behavior spec: credentials to forward, command
/// classification, output normalization, and secret extraction from stdout.
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
    /// [`MatchingResolution::Blocked`] — fail closed, since an unrecognized
    /// invocation shape may emit secret material this registry has no way to
    /// extract or redact.
    pub matchers: Vec<CliMatcherRule>,
    /// Arg flags to strip from the shim's requested args on sensitive commands,
    /// before appending `forced_args`. Both `--flag value` (two-token) and
    /// `--flag=value` (single-token) forms are matched.
    /// Example: `vec!["--format"]`.
    pub strip_arg_flags: Vec<String>,
    /// Args appended to the subprocess command on sensitive commands after stripping.
    /// Used to force a specific output format that the matcher expects.
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
    pub fn resolve_args(&self, args: &[String]) -> MatchingResolution<'_> {
        // blocked commands
        if self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_blocked_command)
            .any(|rule| args.starts_with(&rule.args_match))
        {
            return MatchingResolution::Blocked;
        }

        // sensitive commands
        if let Some(rule) = self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_sensitive_command)
            .find(|rule| rule.args_match.is_empty() || args.starts_with(&rule.args_match))
        {
            return MatchingResolution::Matcher(&rule.matcher);
        }

        // safe commands
        if self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_safe_command)
            .any(|rule| args.starts_with(&rule.args_match))
        {
            return MatchingResolution::PassThrough;
        }

        MatchingResolution::Blocked
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

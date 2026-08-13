use super::{MatcherRule, MatchingResolution, NonEmptyVec, SecretMatcher};

/// A command-classification rule for a CLI secret provider.
pub type CliMatcherRule = MatcherRule<CommandAndMatcher, CommandPattern>;

/// A command-line option that a CLI integration needs to recognize.
///
/// ```toml
/// { name = "--format", takes_value = true }
/// { name = "--offline", takes_value = false }
/// { name = "-u", takes_value = true, allow_attached_value = true }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FlagSpec {
    /// The option's spelling, such as `--server-url` or `-u`.
    pub name: String,
    /// Whether the option consumes the following argument as its value.
    pub takes_value: bool,
    /// Whether the spelling accepts an attached value without `=`, such as
    /// `-uhttps://example.com`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_attached_value: bool,
}

impl<'de> serde::Deserialize<'de> for FlagSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawFlagSpec {
            name: String,
            takes_value: bool,
            #[serde(default)]
            allow_attached_value: bool,
        }

        let raw = RawFlagSpec::deserialize(deserializer)?;
        if raw.name.is_empty() {
            return Err(serde::de::Error::custom("option name must not be empty"));
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

impl FlagSpec {
    /// Creates a specification for an option whose value is a separate
    /// argument or follows `=`.
    #[must_use]
    pub fn value(name: &str) -> Self {
        Self {
            name: String::from(name),
            takes_value: true,
            allow_attached_value: false,
        }
    }

    /// Creates a specification for an option that takes no value.
    #[must_use]
    pub fn valueless(name: &str) -> Self {
        Self {
            name: String::from(name),
            takes_value: false,
            allow_attached_value: false,
        }
    }

    /// Creates a specification for an option that also accepts a value
    /// attached directly to its name.
    #[must_use]
    pub fn attached_value(name: &str) -> Self {
        Self {
            name: String::from(name),
            takes_value: true,
            allow_attached_value: true,
        }
    }
}

/// Whether a command pattern permits trailing positional arguments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandMatch {
    /// Only the listed command words may occur. Options may be interspersed.
    Exact,
    /// Additional positional arguments may follow the listed command words.
    #[default]
    Prefix,
}

/// Deserializable configuration for a CLI secret-provider integration.
///
/// Convert this plain representation into [`CliIntegrationSpec`] to validate
/// relationships between its option policies before use.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliIntegrationConfig {
    /// Executable basename used to select this integration.
    pub binary_name: String,
    /// Stable identifier recorded for secrets from this integration.
    pub provider_id: String,
    /// Environment variables forwarded to authenticate the provider CLI.
    pub credential_env_vars: Vec<String>,
    /// Options ignored while identifying command words. Their value arity is
    /// honored, and the options remain unchanged in the executed command.
    #[serde(default)]
    pub stripped_options: Vec<FlagSpec>,
    /// Options that make an otherwise permitted invocation unsafe. An
    /// invocation containing one is blocked rather than silently changed.
    #[serde(default)]
    pub forbidden_options: Vec<FlagSpec>,
    /// Rules that classify invocations and configure secret extraction.
    pub matchers: Vec<CliMatcherRule>,
}

/// A CLI integration configuration that has passed cross-field validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliIntegrationSpec {
    pub(crate) binary_name: String,
    pub(crate) provider_id: String,
    pub(crate) credential_env_vars: Vec<String>,
    pub(crate) stripped_options: Vec<FlagSpec>,
    pub(crate) forbidden_options: Vec<FlagSpec>,
    pub(crate) matchers: Vec<CliMatcherRule>,
}

/// Error returned when validating a [`CliIntegrationConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CliIntegrationConfigError {
    /// One option spelling has different arity or attachment behavior across
    /// integration and command scopes.
    #[error(
        "option `{name}` has conflicting definitions in integration-level and command-level stripped_options"
    )]
    ConflictingStrippedOption {
        /// Conflicting option spelling.
        name: String,
    },
}

impl TryFrom<CliIntegrationConfig> for CliIntegrationSpec {
    type Error = CliIntegrationConfigError;

    fn try_from(config: CliIntegrationConfig) -> Result<Self, Self::Error> {
        for rule in config.matchers.iter().filter_map(|matcher| match matcher {
            MatcherRule::SensitiveCommand(rule) => Some(rule),
            MatcherRule::SafeCommand(_) | MatcherRule::BlockedCommand(_) => None,
        }) {
            for integration_option in &config.stripped_options {
                if let Some(command_option) = rule
                    .stripped_options
                    .iter()
                    .find(|option| option.name == integration_option.name)
                    && command_option != integration_option
                {
                    return Err(CliIntegrationConfigError::ConflictingStrippedOption {
                        name: integration_option.name.clone(),
                    });
                }
            }
        }

        Ok(Self {
            binary_name: config.binary_name,
            provider_id: config.provider_id,
            credential_env_vars: config.credential_env_vars,
            stripped_options: config.stripped_options,
            forbidden_options: config.forbidden_options,
            matchers: config.matchers,
        })
    }
}

impl CliIntegrationSpec {
    /// Returns the executable basename used to select this integration.
    #[must_use]
    pub fn binary_name(&self) -> &str {
        &self.binary_name
    }

    /// Returns the stable provider identifier recorded for extracted secrets.
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    /// Returns the environment variables forwarded to authenticate the CLI.
    #[must_use]
    pub fn credential_env_vars(&self) -> &[String] {
        &self.credential_env_vars
    }

    /// Classifies an invocation as sensitive, safe to pass through, or
    /// blocked. Malformed recognized options fail closed.
    #[must_use]
    pub fn resolve_args(&self, args: &[String]) -> MatchingResolution<'_> {
        if contains_any_option(args, &self.forbidden_options) {
            return MatchingResolution::Blocked;
        }

        if self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_blocked_command)
            .any(|rule| {
                rule.match_args(args, &self.stripped_options, &[])
                    != CommandMatchResult::DoesNotMatch
            })
        {
            return MatchingResolution::Blocked;
        }

        for rule in self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_sensitive_command)
        {
            match rule
                .command
                .match_args(args, &self.stripped_options, &rule.stripped_options)
            {
                CommandMatchResult::Matches => {
                    return MatchingResolution::Matcher(&rule.matcher);
                }
                CommandMatchResult::Malformed => return MatchingResolution::Blocked,
                CommandMatchResult::DoesNotMatch => {}
            }
        }

        for rule in self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_safe_command)
        {
            match rule.match_args(args, &self.stripped_options, &[]) {
                CommandMatchResult::Matches => return MatchingResolution::PassThrough,
                CommandMatchResult::Malformed => return MatchingResolution::Blocked,
                CommandMatchResult::DoesNotMatch => {}
            }
        }

        MatchingResolution::Blocked
    }

    /// Normalizes a sensitive command's output options. Forbidden options are
    /// handled by [`Self::resolve_args`] and are never silently removed.
    #[must_use]
    pub fn rewrite_args(&self, args: &[String]) -> Vec<String> {
        let Some(rule) = self
            .matchers
            .iter()
            .filter_map(MatcherRule::as_sensitive_command)
            .find(|rule| {
                rule.command
                    .match_args(args, &self.stripped_options, &rule.stripped_options)
                    == CommandMatchResult::Matches
            })
        else {
            return args.to_vec();
        };

        let mut rewritten = remove_options(args, &rule.stripped_options);
        let insertion_index = rewritten
            .iter()
            .position(|arg| arg == "--")
            .unwrap_or(rewritten.len());
        rewritten.splice(
            insertion_index..insertion_index,
            rule.append_options.iter().cloned(),
        );
        rewritten
    }
}

/// A sensitive command pattern together with its extraction and output
/// normalization policy.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandAndMatcher {
    /// Pattern used to identify the command.
    #[serde(flatten)]
    pub command: CommandPattern,
    /// Matcher used to extract secrets from the normalized output.
    pub matcher: SecretMatcher,
    /// Output-shaping options skipped during matching and removed before
    /// [`Self::append_options`] is applied.
    #[serde(default)]
    pub stripped_options: Vec<FlagSpec>,
    /// Options and values added to normalize output into the expected form.
    /// They are inserted before an end-of-options (`--`) marker when present.
    #[serde(default)]
    pub append_options: Vec<String>,
}

/// Command words and the rule for matching trailing positional arguments.
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
    /// Creates a pattern that accepts trailing positional arguments.
    #[must_use]
    pub fn prefix(argv: NonEmptyVec<String>) -> Self {
        Self {
            argv,
            match_kind: CommandMatch::Prefix,
        }
    }

    /// Creates a pattern that accepts only the listed command words.
    #[must_use]
    pub fn exact(argv: NonEmptyVec<String>) -> Self {
        Self {
            argv,
            match_kind: CommandMatch::Exact,
        }
    }

    fn match_args(
        &self,
        args: &[String],
        integration_options: &[FlagSpec],
        command_options: &[FlagSpec],
    ) -> CommandMatchResult {
        command_matches(
            args,
            &self.argv,
            self.match_kind,
            integration_options,
            command_options,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandMatchResult {
    Matches,
    DoesNotMatch,
    Malformed,
}

fn contains_any_option(args: &[String], options: &[FlagSpec]) -> bool {
    args.iter()
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| options.iter().any(|option| match_option_token(arg, option)))
}

fn match_option_token(arg: &str, option: &FlagSpec) -> bool {
    let name = &option.name;
    arg == name
        || arg
            .strip_prefix(name)
            .is_some_and(|rest| rest.starts_with('='))
        || (option.allow_attached_value
            && arg.strip_prefix(name).is_some_and(|rest| !rest.is_empty()))
}

fn remove_options(args: &[String], options: &[FlagSpec]) -> Vec<String> {
    let mut rewritten = Vec::with_capacity(args.len());
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            rewritten.push(arg.clone());
            rewritten.extend(iter.cloned());
            break;
        }

        let Some(option) = options
            .iter()
            .find(|option| match_option_token(arg, option))
        else {
            rewritten.push(arg.clone());
            continue;
        };

        let has_embedded_value = arg.strip_prefix(&option.name).is_some_and(|rest| {
            rest.starts_with('=') || (!rest.is_empty() && option.allow_attached_value)
        });
        if option.takes_value && !has_embedded_value {
            iter.next();
        }
    }
    rewritten
}

fn command_matches(
    args: &[String],
    command: &[String],
    match_kind: CommandMatch,
    integration_options: &[FlagSpec],
    command_options: &[FlagSpec],
) -> CommandMatchResult {
    let mut words = Vec::new();
    let mut iter = args.iter();
    let mut options_ended = false;
    let mut malformed = false;
    while let Some(arg) = iter.next() {
        if !options_ended && arg == "--" {
            options_ended = true;
            continue;
        }

        if !options_ended
            && let Some(option) = integration_options
                .iter()
                .chain(command_options)
                .find(|option| match_option_token(arg, option))
        {
            let has_embedded_value = arg.strip_prefix(&option.name).is_some_and(|rest| {
                rest.starts_with('=') || (!rest.is_empty() && option.allow_attached_value)
            });
            if option.takes_value && !has_embedded_value {
                match iter.next() {
                    Some(value) if value != "--" => {}
                    Some(_) => {
                        malformed = true;
                        options_ended = true;
                    }
                    None => malformed = true,
                }
            }
        } else if !options_ended && arg.starts_with('-') {
            // Unknown options are left to the CLI to reject, but cannot become
            // command words for rule selection.
        } else {
            words.push(arg.as_str());
        }
    }

    let matches = match match_kind {
        CommandMatch::Exact => words.iter().copied().eq(command.iter().map(String::as_str)),
        CommandMatch::Prefix => {
            words
                .iter()
                .copied()
                .zip(command.iter().map(String::as_str))
                .all(|(actual, expected)| actual == expected)
                && words.len() >= command.len()
        }
    };

    if !matches {
        CommandMatchResult::DoesNotMatch
    } else if malformed {
        CommandMatchResult::Malformed
    } else {
        CommandMatchResult::Matches
    }
}

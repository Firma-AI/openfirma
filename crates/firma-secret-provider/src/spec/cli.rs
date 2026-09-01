use firma_config_schema::secret_provider::cli::{
    CliMatcherRuleConfig, CliSecretProviderConfig, CommandMatch, FlagSpec,
};
use firma_core::SecretMatcher;

use super::{MatcherRule, MatchingResolution, NonEmptyVec};

/// A command-classification rule for a CLI secret provider.
pub type CliMatcherRule<Matcher> = MatcherRule<CommandAndMatcher<Matcher>, CommandPattern>;

/// A CLI integration configuration that has passed cross-field validation.
///
/// Cross-field checks (empty names, `allow_attached_value` without
/// `takes_value`, conflicting [`FlagSpec`] definitions across
/// `stripped_options` / `forbidden_options` / per-command
/// `stripped_options`) are enforced by the
/// `TryFrom<CliSecretProviderConfig>` impl before this type is constructed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CliIntegrationSpec<Matcher> {
    /// Executable basename used to select this integration (e.g. `"bws"`).
    ///
    /// Matches [`SecretProviderPatch::Named`](firma_config_schema::secret_provider::SecretProviderPatch::Named)
    /// keys and the `binary_name` field of a custom CLI spec; see
    /// [`CliSecretProviderConfig::binary_name`](firma_config_schema::secret_provider::cli::CliSecretProviderConfig::binary_name).
    pub binary_name: String,
    /// Stable identifier recorded for secrets from this integration.
    ///
    /// Mirrors [`CliSecretProviderConfig::provider_id`](firma_config_schema::secret_provider::cli::CliSecretProviderConfig::provider_id).
    pub provider_id: String,
    /// Environment variables forwarded to authenticate the provider CLI.
    ///
    /// Only these names are forwarded from the broker's environment to the
    /// subprocess; see [`CliSecretProviderConfig::credential_env_vars`](firma_config_schema::secret_provider::cli::CliSecretProviderConfig::credential_env_vars).
    pub credential_env_vars: Vec<String>,
    /// Options ignored while identifying command words. Their value arity is
    /// honored, and the options remain unchanged in the executed command.
    ///
    /// Mirrors [`CliSecretProviderConfig::stripped_options`](firma_config_schema::secret_provider::cli::CliSecretProviderConfig::stripped_options).
    pub stripped_options: Vec<FlagSpec>,
    /// Options that make an otherwise permitted invocation unsafe. An
    /// invocation containing one is blocked rather than silently changed.
    ///
    /// Mirrors [`CliSecretProviderConfig::forbidden_options`](firma_config_schema::secret_provider::cli::CliSecretProviderConfig::forbidden_options).
    pub forbidden_options: Vec<FlagSpec>,
    /// Rules that classify invocations and configure secret extraction.
    ///
    /// See [`CliMatcherRule`] and [`CliSecretProviderConfig::matchers`](firma_config_schema::secret_provider::cli::CliSecretProviderConfig::matchers).
    pub matchers: Vec<CliMatcherRule<Matcher>>,
}

/// Error returned when validating a [`CliSecretProviderConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CliIntegrationConfigError {
    /// An option has no spelling.
    #[error("option name must not be empty")]
    EmptyOptionName,
    /// A command has no args.
    #[error("argv name must not be empty")]
    EmptyArgv,
    /// An option permits an attached value but does not take a value.
    #[error("option `{name}` sets allow_attached_value but does not take a value")]
    AttachedValueWithoutValue {
        /// Invalid option spelling.
        name: String,
    },
    /// One option spelling has conflicting arity or attachment definitions.
    #[error("option `{name}` has conflicting definitions")]
    ConflictingOptionDefinition {
        /// Conflicting option spelling.
        name: String,
    },
}

impl TryFrom<CliSecretProviderConfig> for CliIntegrationSpec<SecretMatcher> {
    type Error = CliIntegrationConfigError;

    fn try_from(config: CliSecretProviderConfig) -> Result<Self, Self::Error> {
        validate_consistent_options(&config.stripped_options)?;
        validate_consistent_options(&config.forbidden_options)?;
        let command_options = config.matchers.iter().flat_map(|matcher| match matcher {
            CliMatcherRuleConfig::SensitiveCommand {
                stripped_options, ..
            } => stripped_options.as_slice(),
            CliMatcherRuleConfig::SafeCommand { .. }
            | CliMatcherRuleConfig::BlockedCommand { .. } => &[],
        });
        for option in config
            .stripped_options
            .iter()
            .chain(&config.forbidden_options)
            .chain(command_options)
        {
            if option.name.is_empty() {
                return Err(CliIntegrationConfigError::EmptyOptionName);
            }
            if !option.takes_value && option.allow_attached_value {
                return Err(CliIntegrationConfigError::AttachedValueWithoutValue {
                    name: option.name.clone(),
                });
            }
        }

        for stripped_options in config.matchers.iter().filter_map(|matcher| match matcher {
            CliMatcherRuleConfig::SensitiveCommand {
                stripped_options, ..
            } => Some(stripped_options),
            CliMatcherRuleConfig::SafeCommand { .. }
            | CliMatcherRuleConfig::BlockedCommand { .. } => None,
        }) {
            validate_consistent_options(stripped_options)?;
            for integration_option in &config.stripped_options {
                if stripped_options
                    .iter()
                    .filter(|option| option.name == integration_option.name)
                    .any(|command_option| command_option != integration_option)
                {
                    return Err(CliIntegrationConfigError::ConflictingOptionDefinition {
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
            matchers: config
                .matchers
                .into_iter()
                .map(MatcherRule::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<CliMatcherRuleConfig> for CliMatcherRule<SecretMatcher> {
    type Error = CliIntegrationConfigError;

    fn try_from(value: CliMatcherRuleConfig) -> Result<Self, Self::Error> {
        match value {
            CliMatcherRuleConfig::SensitiveCommand {
                argv,
                match_kind,
                matcher,
                stripped_options,
                append_options,
            } => Ok(Self::SensitiveCommand(CommandAndMatcher {
                command: CommandPattern {
                    argv: non_empty_vec(argv)?,
                    match_kind,
                },
                matcher,
                stripped_options,
                append_options,
            })),
            CliMatcherRuleConfig::SafeCommand { argv, match_kind } => {
                Ok(Self::SafeCommand(CommandPattern {
                    argv: non_empty_vec(argv)?,
                    match_kind,
                }))
            }
            CliMatcherRuleConfig::BlockedCommand { argv, match_kind } => {
                Ok(Self::BlockedCommand(CommandPattern {
                    argv: non_empty_vec(argv)?,
                    match_kind,
                }))
            }
        }
    }
}

fn non_empty_vec(vec: Vec<String>) -> Result<NonEmptyVec<String>, CliIntegrationConfigError> {
    NonEmptyVec::new(vec).map_err(|_| CliIntegrationConfigError::EmptyArgv)
}

fn validate_consistent_options(options: &[FlagSpec]) -> Result<(), CliIntegrationConfigError> {
    for (index, option) in options.iter().enumerate() {
        if options[..index]
            .iter()
            .any(|previous| previous.name == option.name && previous != option)
        {
            return Err(CliIntegrationConfigError::ConflictingOptionDefinition {
                name: option.name.clone(),
            });
        }
    }
    Ok(())
}

impl<Matcher> CliIntegrationSpec<Matcher> {
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
    pub fn resolve_args(&self, args: &[String]) -> MatchingResolution<'_, Matcher> {
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
pub struct CommandAndMatcher<Matcher> {
    /// Pattern used to identify the command.
    #[serde(flatten)]
    pub command: CommandPattern,
    /// Matcher used to extract secrets from the normalized output.
    pub matcher: Matcher,
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

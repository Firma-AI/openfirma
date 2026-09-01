use serde::{Deserialize, Serialize};

use crate::secret_matcher::SecretMatcher;

/// Deserializable configuration for a CLI secret-provider integration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliSecretProviderConfig {
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
    pub matchers: Vec<CliMatcherRuleConfig>,
}

/// A command-line option that a CLI integration needs to recognize.
///
/// ```toml
/// { name = "--format", takes_value = true }
/// { name = "--offline", takes_value = false }
/// { name = "-u", takes_value = true, allow_attached_value = true }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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

/// One candidate rule for an [`CliSecretProviderConfig`].
///
/// Tagged by `type` (`sensitive_command` / `safe_command` / `blocked_command`)
/// so it nests as a flat TOML table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CliMatcherRuleConfig {
    /// Response whose body must be scanned and redacted using `matcher`.
    SensitiveCommand {
        /// Command words, excluding the binary name.
        argv: Vec<String>,
        /// Whether trailing positional arguments are accepted.
        #[serde(rename = "match", default)]
        match_kind: CommandMatch,
        /// Matcher used to extract secrets from the normalized output.
        matcher: SecretMatcher,
        /// Output-shaping options skipped during matching and removed before
        /// [`CliMatcherRuleConfig::SensitiveCommand::append_options`] is applied.
        #[serde(default)]
        stripped_options: Vec<FlagSpec>,
        /// Options and values added to normalize output into the expected form.
        /// They are inserted before an end-of-options (`--`) marker when present.
        #[serde(default)]
        append_options: Vec<String>,
    },
    /// Known-safe path whose response never carries secrets; forwarded
    /// unredacted.
    SafeCommand {
        /// Command words, excluding the binary name.
        argv: Vec<String>,
        /// Whether trailing positional arguments are accepted.
        #[serde(rename = "match", default)]
        match_kind: CommandMatch,
    },
    /// Path that must always be denied.
    BlockedCommand {
        /// Command words, excluding the binary name.
        argv: Vec<String>,
        /// Whether trailing positional arguments are accepted.
        #[serde(rename = "match", default)]
        match_kind: CommandMatch,
    },
}

/// Whether a command pattern permits trailing positional arguments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandMatch {
    /// Only the listed command words may occur. Options may be interspersed.
    Exact,
    /// Additional positional arguments may follow the listed command words.
    #[default]
    Prefix,
}

//! Built-in agent profiles shared across `firma-run` and the `firma` CLI.

/// The set of built-in agent profiles `firma run` recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum AgentProfile {
    /// General-purpose sandbox, no agent-specific defaults.
    Generic,
    /// `OpenAI` Codex CLI.
    Codex,
    /// Anthropic Claude Code CLI.
    #[cfg_attr(feature = "clap", value(name = "claude-code"))]
    ClaudeCode,
}

impl AgentProfile {
    /// String name used in `firma.toml` and on the CLI.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
        }
    }

    /// Parse from the string name; returns `None` for unknown profiles.
    #[must_use]
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "generic" => Some(Self::Generic),
            "codex" => Some(Self::Codex),
            "claude-code" => Some(Self::ClaudeCode),
            _ => None,
        }
    }

    /// Provider identifier used for mapping selection (`"anthropic"`, `"openai"`).
    #[must_use]
    pub fn provider(self) -> &'static str {
        match self {
            Self::Generic | Self::ClaudeCode => "anthropic",
            Self::Codex => "openai",
        }
    }

    /// Human-readable description for interactive prompts.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::Generic => "general-purpose sandbox, no agent-specific defaults",
            Self::Codex => "OpenAI Codex CLI — sets up OpenAI mapping by default",
            Self::ClaudeCode => "Anthropic Claude Code — sets up Anthropic mapping by default",
        }
    }
}

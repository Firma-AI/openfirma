//! Built-in agent profiles shared across `firma-run` and the `firma` CLI.

/// The set of built-in agent profiles `firma run` recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum AgentProfile {
    /// Anthropic Claude Code CLI.
    #[cfg_attr(feature = "clap", value(name = "claude-code", alias = "claude"))]
    ClaudeCode,
    /// `OpenAI` Codex CLI.
    Codex,
    /// GitHub Copilot CLI.
    #[cfg_attr(feature = "clap", value(name = "copilot", alias = "copilot-cli"))]
    Copilot,
    /// General-purpose sandbox, no agent-specific defaults.
    Generic,
    /// `OpenCode` terminal coding agent.
    #[cfg_attr(feature = "clap", value(name = "opencode"))]
    OpenCode,
    /// Pi terminal coding agent.
    #[cfg_attr(feature = "clap", value(name = "pi"))]
    Pi,
    /// Visual Studio Code desktop.
    #[cfg_attr(feature = "clap", value(name = "vscode", alias = "code"))]
    Vscode,
}

impl AgentProfile {
    /// String name used in `firma.toml` and on the CLI.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::Copilot => "copilot",
            Self::OpenCode => "opencode",
            Self::Pi => "pi",
            Self::Vscode => "vscode",
        }
    }

    /// Parse from the string name; returns `None` for unknown profiles.
    #[must_use]
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "generic" => Some(Self::Generic),
            "codex" => Some(Self::Codex),
            "claude-code" | "claude" => Some(Self::ClaudeCode),
            "copilot" | "copilot-cli" => Some(Self::Copilot),
            "opencode" => Some(Self::OpenCode),
            "pi" => Some(Self::Pi),
            "vscode" | "code" => Some(Self::Vscode),
            _ => None,
        }
    }

    /// Provider identifier used for mapping selection (`"anthropic"`, `"openai"`).
    #[must_use]
    pub fn provider(self) -> &'static str {
        match self {
            Self::Generic | Self::ClaudeCode | Self::OpenCode | Self::Pi => "anthropic",
            Self::Codex => "openai",
            Self::Copilot => "github",
            Self::Vscode => "vscode",
        }
    }

    /// Human-readable description for interactive prompts.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::Generic => "general-purpose sandbox, no agent-specific defaults",
            Self::Codex => "OpenAI Codex CLI — sets up OpenAI mapping by default",
            Self::ClaudeCode => "Anthropic Claude Code — sets up Anthropic mapping by default",
            Self::Copilot => {
                "GitHub Copilot CLI — sets up Copilot mapping and github MITM bypass by default"
            }
            Self::OpenCode => {
                "OpenCode terminal coding agent — model-agnostic; sets up Anthropic mapping by default"
            }
            Self::Pi => {
                "Pi terminal coding agent — model-agnostic; sets up Anthropic mapping by default"
            }
            Self::Vscode => {
                "Visual Studio Code — sets up VS Code, marketplace, account, and GitHub mapping by default"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copilot_round_trips_name_and_provider() {
        assert_eq!(AgentProfile::Copilot.as_str(), "copilot");
        assert_eq!(AgentProfile::Copilot.provider(), "github");
        assert_eq!(
            AgentProfile::from_name("copilot"),
            Some(AgentProfile::Copilot)
        );
        assert_eq!(
            AgentProfile::from_name("copilot-cli"),
            Some(AgentProfile::Copilot)
        );
    }

    #[test]
    fn vscode_round_trips_name_alias_and_provider() {
        assert_eq!(AgentProfile::Vscode.as_str(), "vscode");
        assert_eq!(AgentProfile::Vscode.provider(), "vscode");
        assert_eq!(
            AgentProfile::from_name("vscode"),
            Some(AgentProfile::Vscode)
        );
        assert_eq!(AgentProfile::from_name("code"), Some(AgentProfile::Vscode));
        assert!(
            AgentProfile::Vscode
                .description()
                .contains("Visual Studio Code")
        );
    }

    #[test]
    fn opencode_round_trips_name_and_provider() {
        assert_eq!(AgentProfile::OpenCode.as_str(), "opencode");
        assert_eq!(AgentProfile::OpenCode.provider(), "anthropic");
        assert_eq!(
            AgentProfile::from_name("opencode"),
            Some(AgentProfile::OpenCode)
        );
        assert!(AgentProfile::OpenCode.description().contains("OpenCode"));
    }

    #[test]
    fn pi_round_trips_name_and_provider() {
        assert_eq!(AgentProfile::Pi.as_str(), "pi");
        assert_eq!(AgentProfile::Pi.provider(), "anthropic");
        assert_eq!(AgentProfile::from_name("pi"), Some(AgentProfile::Pi));
        assert!(AgentProfile::Pi.description().contains("Pi"));
    }
}

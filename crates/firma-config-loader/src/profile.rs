//! Built-in agent profiles shared across `firma-run` and the `firma` CLI.

use serde::{Deserialize, Serialize};

/// The set of built-in agent profiles `firma run` recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
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
            "vscode" | "code" => Some(Self::Vscode),
            _ => None,
        }
    }

    /// Provider identifier used for mapping selection (`"anthropic"`, `"openai"`).
    #[must_use]
    pub fn provider(self) -> &'static str {
        match self {
            Self::Generic | Self::ClaudeCode => "anthropic",
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
            Self::Codex => "OpenAI Codex CLI — local mappings default to OpenAI and GitHub",
            Self::ClaudeCode => "Anthropic Claude Code — local mappings default to Anthropic",
            Self::Copilot => {
                "GitHub Copilot CLI — local mappings default to Copilot with GitHub MITM bypass"
            }
            Self::Vscode => {
                "Visual Studio Code — local mappings default to VS Code services and accounts"
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
}

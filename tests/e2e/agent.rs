#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum AgentKind {
    Claude,
    Codex,
}

impl AgentKind {
    /// Domains the agent contacts as incidental startup traffic.
    ///
    /// This traffic is incidental to enforcement scenarios and varies by
    /// platform and agent version (e.g. codex dials `files.openai.com` on
    /// macOS but not Linux), so tests filter it out of the audit trail to keep
    /// snapshots deterministic across operating systems.
    #[must_use]
    pub fn incidental_allow_domains(self) -> &'static [&'static str] {
        match self {
            Self::Claude => &["anthropic.com"],
            Self::Codex => &["openai.com", "chatgpt.com", "github.com"],
        }
    }
}

/// An agent the harness can run, optionally carrying extra CLI flags.
///
/// Flags passed via `.args()` are inserted before the subcommand so they are
/// treated as global flags by the agent binary.
#[derive(Debug, Clone)]
pub struct Agent {
    pub kind: AgentKind,
    args: Vec<String>,
}

impl Agent {
    #[must_use]
    pub fn claude() -> Self {
        Self {
            kind: AgentKind::Claude,
            args: Vec::new(),
        }
    }

    #[must_use]
    pub fn codex() -> Self {
        Self {
            kind: AgentKind::Codex,
            args: Vec::new(),
        }
    }

    /// Attach CLI flags inserted before the subcommand / prompt flag.
    #[must_use]
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn command(&self) -> &'static str {
        match self.kind {
            AgentKind::Claude => "claude",
            AgentKind::Codex => "codex",
        }
    }

    #[must_use]
    pub fn profile(&self) -> &'static str {
        match self.kind {
            AgentKind::Claude => "claude-code",
            AgentKind::Codex => "codex",
        }
    }

    pub fn prompt_args(&self, prompt: &str) -> Vec<String> {
        let mut result = self.args.clone();
        match self.kind {
            AgentKind::Claude => {
                result.push("-p".to_string());
                result.push(prompt.to_string());
            }
            AgentKind::Codex => {
                result.push("exec".to_string());
                result.push(prompt.to_string());
            }
        }
        result
    }
}

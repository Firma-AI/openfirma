//! Args for `firma config`.

use std::path::PathBuf;

use clap::{Args, ValueEnum};

static POSTURE_STRICT: &str = include_str!("../../templates/policies/strict.cedar");
static POSTURE_DEV: &str = include_str!("../../templates/policies/dev.cedar");
static POSTURE_DEV_DELETE: &str =
    include_str!("../../templates/policies/dev-with-delete-watch.cedar");

/// What component to scaffold.
#[derive(Debug, Clone, ValueEnum)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum Mode {
    /// Agent (sidecar) with a co-located local mini-authority — full stack.
    #[value(name = "agent-local")]
    AgentLocal,
    /// Agent (sidecar) connecting to an existing remote authority.
    #[value(name = "agent-remote")]
    AgentRemote,
    /// Standalone authority server only — no sidecar config generated.
    Authority,
}

impl Mode {
    pub fn description(&self) -> &'static str {
        match self {
            Self::AgentLocal => "Agent + local mini-authority (full stack, single host)",
            Self::AgentRemote => "Agent only — connects to an existing remote authority",
            Self::Authority => "Standalone authority server — no sidecar config",
        }
    }
}

/// Scaffold a new agent config directory interactively.
#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub struct InitArgs {
    /// What to configure: agent-local | agent-remote | authority.
    #[arg(long, value_enum)]
    pub mode: Option<Mode>,

    /// Agent slug used as the `agent_id` in the generated config (e.g. "my-agent").
    /// Not used in `authority` mode.
    #[arg(long, short = 'n')]
    pub name: Option<String>,

    /// Built-in agent profile written to `[run].profile` in `firma.toml`
    /// (e.g. `generic`, `codex`, `claude-code`).
    #[arg(long)]
    pub profile: Option<String>,

    /// Cedar policy posture to write under `policies/`.
    #[arg(long, value_enum)]
    pub posture: Option<Posture>,

    /// Mapping file(s) to include — may be repeated. Not used in `authority` mode.
    #[arg(long, value_enum)]
    pub mapping: Vec<Mapping>,

    /// Comma-separated extra hosts the agent is allowed to reach.
    #[arg(long)]
    pub extra_hosts: Option<String>,

    /// Capability actions requested during preflight; may be repeated or comma-separated.
    #[arg(long = "requested-action", value_delimiter = ',')]
    pub requested_actions: Vec<String>,

    /// Absolute path the agent may write to (bwrap RW mount).
    /// Defaults to the output directory.
    #[arg(long)]
    pub workspace: Option<PathBuf>,

    /// Config directory — where firma.toml, policies, and mappings are written.
    /// Defaults to `.firma` in the current directory.
    #[arg(long, short = 'o')]
    pub output_dir: Option<PathBuf>,

    /// State directory — where keys, revocations, and generated CA are written.
    /// Defaults to the platform state dir (`$FIRMA_STATE_DIR` → `$XDG_DATA_HOME/firma`).
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,

    /// Authority URL for `agent-remote` mode (e.g. `<https://authority.example.com:9443>`).
    #[arg(long)]
    pub authority_url: Option<String>,

    /// Path to the authority CA certificate (PEM) for `agent-remote` mode.
    #[arg(long)]
    pub authority_ca_cert: Option<PathBuf>,

    /// Path to the authority public key for `agent-remote` mode.
    #[arg(long)]
    pub authority_pub_key: Option<PathBuf>,

    /// Listen address for the authority gRPC server in `authority` mode.
    #[arg(long)]
    pub authority_listen: Option<String>,

    /// Print generated files to stdout without writing to disk.
    #[arg(long)]
    pub dry_run: bool,

    /// Overwrite files that already exist (default: preserve).
    #[arg(long)]
    pub force: bool,

    /// Print the posture × mapping template catalogue and exit.
    #[arg(long)]
    pub list_templates: bool,

    /// Skip all interactive prompts and use defaults or provided flags.
    #[arg(long, short = 'y')]
    pub yes: bool,
}

/// Cedar enforcement posture for `firma config`.
#[derive(Debug, Clone, ValueEnum)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum Posture {
    /// Default-deny + communication only. No code operations.
    Strict,
    /// Adds code.read/write, issues, package install. No payments or destructive ops.
    Dev,
    /// Dev posture + code.destructive allowed (local-exec / delete-watch scenarios).
    #[value(name = "dev-with-delete-watch")]
    DevWithDeleteWatch,
}

impl Posture {
    /// Cedar policy file content for this posture.
    pub fn cedar_content(&self) -> &'static str {
        match self {
            Self::Strict => POSTURE_STRICT,
            Self::Dev => POSTURE_DEV,
            Self::DevWithDeleteWatch => POSTURE_DEV_DELETE,
        }
    }

    /// Base name used for the generated Cedar policy file (`policies/{name}.cedar`).
    pub fn file_name(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Dev => "dev",
            Self::DevWithDeleteWatch => "dev-with-delete-watch",
        }
    }

    /// Human-readable description for catalogue display.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Strict => "Default-deny + communication only (no code ops)",
            Self::Dev => "Adds code.read/write, issues, package install",
            Self::DevWithDeleteWatch => {
                "Dev + code.destructive allowed (local-exec / delete-watch)"
            }
        }
    }

    /// Actions requested in the preflight token for this posture.
    pub fn requested_actions(&self) -> Vec<&'static str> {
        match self {
            Self::Strict => vec![
                "credential.read",
                "communication.external.send",
                "communication.internal.send",
            ],
            Self::Dev | Self::DevWithDeleteWatch => {
                let mut actions = vec![
                    "system.install",
                    "credential.read",
                    "code.read",
                    "code.review.read",
                    "code.review.submit",
                    "code.write",
                    "code.merge",
                    "issue.read",
                    "issue.write",
                    "security.alert.read",
                    "notification.manage",
                    "communication.external.send",
                    "communication.internal.send",
                ];
                if matches!(self, Self::DevWithDeleteWatch) {
                    actions.push("code.destructive");
                }
                actions
            }
        }
    }
}

/// Mapping file selection for `firma config`.
#[derive(Debug, Clone, ValueEnum)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum Mapping {
    /// Anthropic Claude API (api.anthropic.com).
    Anthropic,
    /// `OpenAI` API (`api.openai.com`).
    Openai,
    /// GitHub REST API — requires MITM for per-endpoint classification.
    Github,
    /// Gmail REST API — requires MITM for per-endpoint classification.
    Gmail,
    /// npm registry (registry.npmjs.org).
    Npm,
    /// `PyPI` (`pypi.org`, `files.pythonhosted.org`).
    Pypi,
    /// crates.io Rust package registry.
    Cargo,
    /// Stripe REST API (`api.stripe.com`).
    Stripe,
}

impl Mapping {
    /// Mapping name used as the file stem (`mappings/{name}.toml`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::Openai => "openai",
            Self::Github => "github",
            Self::Gmail => "gmail",
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Cargo => "cargo",
            Self::Stripe => "stripe",
        }
    }

    /// Human-readable description for catalogue display.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Anthropic => "api.anthropic.com — Anthropic Claude API (CONNECT, no MITM)",
            Self::Openai => "api.openai.com — OpenAI API (CONNECT, no MITM)",
            Self::Github => {
                "api.github.com — GitHub REST API (MITM for per-endpoint classification)"
            }
            Self::Gmail => {
                "gmail.googleapis.com — Gmail REST API (MITM for per-endpoint classification)"
            }
            Self::Npm => "registry.npmjs.org — npm package registry",
            Self::Pypi => "pypi.org, files.pythonhosted.org — PyPI",
            Self::Cargo => "crates.io, static.crates.io — Rust package registry",
            Self::Stripe => {
                "api.stripe.com — Stripe REST API (MITM optional — check SDK cert pinning first)"
            }
        }
    }

    /// Hosts that require HTTPS MITM for per-endpoint REST classification.
    pub fn mitm_hosts(&self) -> &'static [&'static str] {
        match self {
            Self::Github => &["api.github.com"],
            Self::Gmail => &["gmail.googleapis.com"],
            _ => &[],
        }
    }

    /// Static TOML content for this mapping file.
    pub fn static_content(&self) -> &'static str {
        match self {
            Self::Anthropic => include_str!("../../templates/mappings/anthropic.toml"),
            Self::Openai => include_str!("../../templates/mappings/openai.toml"),
            Self::Github => include_str!("../../templates/mappings/github.toml"),
            Self::Gmail => include_str!("../../templates/mappings/gmail.toml"),
            Self::Npm => include_str!("../../templates/mappings/npm.toml"),
            Self::Pypi => include_str!("../../templates/mappings/pypi.toml"),
            Self::Cargo => include_str!("../../templates/mappings/cargo.toml"),
            Self::Stripe => include_str!("../../templates/mappings/stripe.toml"),
        }
    }
}

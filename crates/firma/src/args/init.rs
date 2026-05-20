//! `firma init` arg struct.

use std::path::PathBuf;

use clap::Args;

/// Parsed `firma init` arguments.
///
/// Three usage shapes:
///
/// - bare `firma init` — interactive wizard for new developers.
/// - `firma init --yes` — non-interactive, env defaults only (CI / daemons).
/// - `firma init --agent codex --provider anthropic --workspace ./proj` —
///   scripted, fully specified.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Project workspace. The project-local config dir is materialized at
    /// `<workspace>/.firma/` per spec §6.2. When unset and a wizard is
    /// running, the user is prompted (default: current working directory).
    /// Has no effect if `--config-dir` or `--global` is also passed.
    #[arg(long, conflicts_with_all = ["global", "config_dir"])]
    pub workspace: Option<PathBuf>,

    /// Scaffold into the user-global config dir (resolved by the same
    /// discovery rules as `firma run`: `$FIRMA_CONFIG_DIR` →
    /// `$XDG_CONFIG_HOME/firma` → `~/.config/firma` → platform default).
    /// Mutually exclusive with `--workspace` and `--config-dir`.
    #[arg(long, conflicts_with_all = ["workspace", "config_dir"])]
    pub global: bool,

    /// Config directory (TOML config, policy dirs). Advanced override that
    /// bypasses `--workspace` and `--global`. When unset, derived from
    /// `--workspace` (project-local) or `--global` (user-global).
    #[arg(long, conflicts_with_all = ["workspace", "global"])]
    pub config_dir: Option<PathBuf>,

    /// User-global runtime state directory (keys, revocations, generated-CA,
    /// pids/logs). When unset, resolves via `FIRMA_STATE_DIR` /
    /// `$XDG_DATA_HOME/firma` (Linux) / `$XDG_RUNTIME_DIR` (legacy).
    #[arg(long, env = "FIRMA_STATE_DIR")]
    pub state_dir: Option<PathBuf>,

    /// Agent the project will run under enforcement (e.g. `codex`,
    /// `claude`, `generic`). Persisted to `[project].agent` in firma.toml.
    #[arg(long)]
    pub agent: Option<String>,

    /// Provider the agent connects to (e.g. `anthropic`, `openai`).
    /// Persisted to `[project].provider` in firma.toml.
    #[arg(long)]
    pub provider: Option<String>,

    /// Authority deployment shape: `local` (autostart a Mini Authority),
    /// or a URL like `https://firma-auth.example` for a remote authority.
    /// Persisted to `[authority]` in firma.toml.
    #[arg(long)]
    pub authority: Option<String>,

    /// Skip the interactive wizard. Use defaults for any flag not
    /// supplied. Required in non-TTY contexts (CI, container init).
    #[arg(long)]
    pub yes: bool,

    /// Overwrite existing files instead of preserving them.
    #[arg(long)]
    pub force: bool,

    /// Authority gRPC listen address (only used when authority is local).
    #[arg(long, default_value = "127.0.0.1:50051")]
    pub authority_listen: String,

    /// Sidecar HTTP proxy listen address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub sidecar_listen: String,
}

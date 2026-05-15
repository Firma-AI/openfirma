use std::path::PathBuf;

/// Error type used by `firma-run` runtime orchestration.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("invalid command: no executable was provided")]
    MissingCommand,

    #[error("failed to parse config at {path}: {reason}")]
    ConfigParse { path: PathBuf, reason: String },

    #[error("config validation failed: {0}")]
    ConfigValidation(String),

    #[error("unsupported backend {backend} on this host: {reason}")]
    UnsupportedBackend { backend: String, reason: String },

    #[error("backend error ({backend}): {reason}")]
    Backend { backend: String, reason: String },

    #[error("capability lease error: {0}")]
    Capability(String),

    #[error("failed to spawn wrapped command: {0}")]
    Spawn(String),

    #[error("failed while waiting for wrapped command: {0}")]
    Wait(String),

    #[error("internal runtime error: {0}")]
    Internal(String),

    #[error("sidecar endpoint {endpoint} is unreachable and autostart is disabled ({reason})")]
    SidecarUnreachable { endpoint: String, reason: String },

    #[error(
        "sidecar autostart did not emit 'ready' within {timeout_secs}s; see logs at {}",
        log_path.display()
    )]
    SidecarReadyTimeout {
        timeout_secs: u64,
        log_path: PathBuf,
    },

    #[error("sidecar autostart failed: {reason}; see logs at {}", log_path.display())]
    SidecarStartupFailed { reason: String, log_path: PathBuf },

    #[error("operation not supported on this platform: {reason}")]
    UnsupportedPlatform { reason: String },

    #[error("no authority configured; pass `--authority local` or `--authority <url>`")]
    MissingAuthority,

    #[error(
        "authority bootstrap declined; rerun with `--authority local` to bypass the prompt, \
         start one manually with `firma authority`, or set [authority].type in firma.toml"
    )]
    AuthorityDeclined,

    #[error(
        "stdin is not a TTY; cannot prompt for authority bootstrap. \
         Pass `--authority local` / `--authority <url>` or set [authority].type in firma.toml"
    )]
    AuthorityPromptNoTty,

    #[error(
        "authority autostart did not emit 'ready' within {timeout_secs}s; see logs at {}",
        log_path.display()
    )]
    AuthorityReadyTimeout {
        timeout_secs: u64,
        log_path: PathBuf,
    },

    #[error("authority autostart failed: {reason}; see logs at {}", log_path.display())]
    AuthorityStartupFailed { reason: String, log_path: PathBuf },

    #[error("authority unreachable at {url}: {reason}")]
    AuthorityUnreachable { url: String, reason: String },

    #[error("unknown --authority-profile `{name}`")]
    AuthorityUnknownProfile { name: String },
}

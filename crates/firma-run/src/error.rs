use std::path::PathBuf;

/// Error type used by `firma-run` runtime orchestration.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("invalid command: no executable was provided")]
    MissingCommand,

    #[error(
        "FIRMA_RUN_SANDBOX_ID is reserved for internal child propagation; unset it before starting `firma run`"
    )]
    ReservedSandboxIdEnvironment,

    #[error("failed to parse config at {path}: {reason}")]
    ConfigParse { path: PathBuf, reason: String },

    #[error("config validation failed: {0}")]
    ConfigValidation(String),

    #[error(
        "missing [sidecar.authority].agent_id in {path}; run `firma config --agent-id <AGENT_ID>` or add the registered agent TypeID to the configuration"
    )]
    MissingAgentId { path: PathBuf },

    #[error(
        "[sidecar.authority].agent_id in {path} is the execution profile '{value}', not a registered agent TypeID; migrate it with `firma config --agent-id <AGENT_ID>` and keep '{value}' under [run].profile"
    )]
    LegacyProfileAgentId { path: PathBuf, value: String },

    #[error(
        "invalid [sidecar.authority].agent_id '{value}' in {path}: expected an `agt` TypeID backed by UUIDv7; run `firma config --agent-id <AGENT_ID>`"
    )]
    InvalidAgentId { path: PathBuf, value: String },

    #[error("unsupported backend {backend} on this host: {reason}")]
    UnsupportedBackend { backend: String, reason: String },

    #[error("backend error ({backend}): {reason}")]
    Backend { backend: String, reason: String },

    #[error("profile '{profile}' is incompatible with backend '{backend}': {reason}")]
    UnsupportedProfileBackend {
        profile: String,
        backend: String,
        reason: String,
    },

    #[error("capability lease error: {0}")]
    Capability(String),

    #[error("failed to spawn wrapped command: {0}")]
    Spawn(String),

    #[error("failed while waiting for wrapped command: {0}")]
    Wait(String),

    #[error("internal runtime error: {0}")]
    Internal(String),

    #[error("run component orchestration failed: {0}")]
    RunComponentOrchestration(Box<firma_process_orchestrator::StartError<Self>>),

    #[error("run component stack shutdown failed: {0}")]
    RunStackShutdown(firma_process_orchestrator::OrchestratorError),

    #[error("{operation}; run component stack rollback failed: {rollback}")]
    RunStackPostReadyRollback {
        operation: Box<Self>,
        rollback: firma_process_orchestrator::ShutdownError,
    },

    #[error("sidecar endpoint {endpoint} is unreachable and autostart is disabled ({reason})")]
    SidecarUnreachable { endpoint: String, reason: String },

    #[error(
        "`--sidecar local` is incompatible with `--no-autostart`; \
         pass `--sidecar <tcp://...|unix:///...>` or omit `--no-autostart`"
    )]
    SidecarLocalNoAutostart,

    #[error(
        "no sidecar endpoint configured and autostart is disabled; \
         pass `--sidecar local` or `--sidecar <tcp://...|unix:///...>`"
    )]
    MissingSidecar,

    #[error("operation not supported on this platform: {reason}")]
    UnsupportedPlatform { reason: String },

    #[error(
        "no authority configured; pass `--authority local` / `--authority <url>`, \
         add an `[authority]` section, or set `[sidecar.authority].url` in firma.toml"
    )]
    MissingAuthority,

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

    #[error("authority denied capability for agent '{agent_id}': {reason} — {message}")]
    CapabilityDenied {
        agent_id: String,
        reason: String,
        message: String,
    },

    #[error(
        "authority requires approval for agent '{agent_id}' (approval '{approval_id}'); open {approval_url}"
    )]
    CapabilityPendingApproval {
        agent_id: String,
        approval_id: String,
        approval_url: String,
    },

    #[error("authority rejected unregistered agent '{agent_id}': {message}")]
    AgentNotRegistered { agent_id: String, message: String },

    #[error("authority rejected agent/profile binding for '{agent_id}': {message}")]
    AgentProfileMismatch { agent_id: String, message: String },

    #[error(
        "local authority endpoint {endpoint} is reachable but transport could not be identified as plaintext local gRPC; pass an explicit --authority http://... or https://... URL"
    )]
    AuthorityTransportAmbiguous { endpoint: String },

    #[error("unknown --authority-profile `{name}`")]
    AuthorityUnknownProfile { name: String },

    #[error("local command governance denied execution: {0}")]
    Governance(String),

    #[error(
        "no Authority is configured and stdin is not a terminal; \
         pass `--authority local` to autostart, `--authority <url>` for a remote, \
         add an `[authority]` section, or set `[sidecar.authority].url` in firma.toml"
    )]
    AuthorityBootstrapNoTty,

    #[error(
        "local Mini Authority bootstrap declined; \
         re-run with `--authority local`, run `firma authority start` as a daemon, \
         or set `[sidecar.authority].url` in firma.toml"
    )]
    AuthorityBootstrapDeclined,

    #[error(
        "backend '{backend}' provides proxy-only (non-structural) network enforcement; \
         agent egress is mediated only for cooperative HTTP clients that honor HTTP_PROXY; \
         raw sockets, proxy-env-unset children, and non-HTTP protocols may bypass the Sidecar; \
         to proceed, either: (1) switch to a structural backend (Linux bwrap), or \
         (2) pass --allow-non-structural (or set run.allow_non_structural = true in firma.toml) \
         to acknowledge the limitations of proxy-only mode"
    )]
    NonStructuralBackendRequiresOptIn { backend: String },
}

//! Error surface for `firma-process-orchestrator`.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Error type returned by process orchestration operations in this crate.
///
/// All variants carry enough context to be rendered as a single-line
/// operator-facing message. Callers should generally print
/// `format!("{err}")` and exit non-zero rather than introspect variants.
#[derive(Debug, Error)]
pub enum OrchestratorError {
    /// A component name cannot safely identify runtime-state files.
    #[error(
        "invalid component name '{name}': names must be safe cross-platform runtime-state filenames"
    )]
    InvalidComponentName {
        /// Rejected component name.
        name: String,
    },

    /// A topology contains the same component name more than once.
    #[error("duplicate component name '{name}' in stack topology")]
    DuplicateComponentName {
        /// Duplicate component name.
        name: String,
    },

    /// A resolved plan does not contain exactly one spec per topology component.
    #[error("resolved plan has {actual} component specs, but topology requires {expected}")]
    PlanCountMismatch {
        /// Number of components in the topology.
        expected: usize,
        /// Number of resolved launch specs.
        actual: usize,
    },

    /// Creating or securing the state directory failed.
    #[error(transparent)]
    StateDir(firma_fs::CreatePrivateDirError),

    /// Reading or writing shared runtime state failed.
    #[error(transparent)]
    RuntimeState(#[from] firma_runtime_state::RuntimeStateError),

    /// Another supervisor already holds the stack lock for this state dir.
    #[error("stack already running (lock held at '{path}')")]
    AlreadyRunning {
        /// Path of the lock file that is currently held.
        path: PathBuf,
    },

    /// Runtime-state cleanup could not acquire serialization without blocking.
    #[error("stack runtime state is busy at '{path}'; cleanup deferred")]
    RuntimeStateBusy {
        /// Runtime-state directory whose cleanup transaction is held elsewhere.
        path: PathBuf,
    },

    /// The persisted [`crate::StackGeneration`] is present but malformed.
    #[error("invalid stack.lock generation")]
    InvalidStackGeneration {
        /// UUID parser failure retained for diagnostics.
        #[source]
        source: uuid::Error,
    },

    /// Spawning a child component failed.
    #[error("failed to spawn '{component}': {source}")]
    Spawn {
        /// Logical component name.
        component: String,
        /// Underlying spawn / I/O error.
        #[source]
        source: io::Error,
    },

    /// A component did not become ready within the configured timeout.
    #[error("'{component}' did not become ready within {timeout_secs}s")]
    Readiness {
        /// Logical component name.
        component: String,
        /// Timeout, in seconds, that was exceeded.
        timeout_secs: u64,
    },

    /// A component exited while startup was waiting for it to become ready.
    #[error("'{component}' exited before becoming ready: {status}")]
    ReadinessProcessExited {
        /// Logical component name.
        component: String,
        /// Exit status collected from the component leader.
        status: std::process::ExitStatus,
    },

    /// One or more process targets remained present after forced termination.
    #[error("termination targets remained present after {timeout_secs}s")]
    TerminationTimeout {
        /// Internal settlement window used after hard termination.
        timeout_secs: u64,
    },

    /// A startup operation failed and its required rollback also failed.
    #[error("{operation}; rollback failed: {rollback}")]
    Rollback {
        /// Original startup or attachment failure.
        operation: Box<Self>,
        /// Failure encountered while tearing the partial stack down.
        rollback: Box<Self>,
    },

    /// Generic I/O error not classified by a more specific variant.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// OS-level failure surfaced from `platform_unix` / `platform_windows`
    /// (process-group setup, Job Object operations, signal delivery, etc).
    #[error("platform error: {0}")]
    Platform(String),
}

/// Failure returned when shutting down an in-process owned stack.
///
/// The variants distinguish uncertain process teardown from failures that
/// occur after every process target is confirmed absent. Callers that own
/// dependencies of the stack must retain them only for
/// [`Self::TeardownUncertain`].
#[derive(Debug, Error)]
pub enum ShutdownError {
    /// One or more process targets may still be live or uncollected.
    #[error(transparent)]
    TeardownUncertain(OrchestratorError),
    /// All process targets are absent, but durable runtime-state cleanup failed.
    #[error(transparent)]
    StateCleanup(OrchestratorError),
}

impl ShutdownError {
    /// Whether all owned process targets were confirmed absent.
    #[must_use]
    pub const fn processes_stopped(&self) -> bool {
        matches!(self, Self::StateCleanup(_))
    }

    /// Discard the shutdown phase while preserving the underlying error.
    #[must_use]
    pub(crate) fn into_orchestrator_error(self) -> OrchestratorError {
        match self {
            Self::TeardownUncertain(error) | Self::StateCleanup(error) => error,
        }
    }
}

/// Distinguishes caller-owned plan resolution failures from orchestration failures.
#[derive(Debug, Error)]
pub enum StartError<E> {
    /// The caller's plan resolver failed after the stack lock was acquired.
    #[error(transparent)]
    Plan(E),
    /// Generic process orchestration failed.
    #[error(transparent)]
    Orchestrator(#[from] OrchestratorError),
    /// Startup failed and explicit rollback also reported a failure.
    #[error("{operation}; rollback failed: {rollback}")]
    Rollback {
        /// Original planning or orchestration failure.
        operation: Box<Self>,
        /// Failure encountered while rolling back the partial stack.
        rollback: Box<OrchestratorError>,
    },
}

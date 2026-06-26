//! Runtime state contracts and local liveness primitives shared by `OpenFirma` crates.

pub mod error;
pub mod fs;
pub mod pidfile;
pub mod process_id;
pub mod runtime_paths;
pub mod sidecar_markers;
pub mod state_dir;
pub mod status;

mod liveness;

pub use error::{Result, RuntimeStateError};
pub use process_id::{NonZeroProcessId, ProcessIdError};
pub use runtime_paths::{capabilities_dir_from, default_runtime_dir, run_dir_from, run_entry_from};
pub use sidecar_markers::{MetadataFile, SidecarEntry, gc_stale, get, list};
pub use state_dir::resolve_state_dir;
pub use status::State;

/// Return whether `pid` appears to identify a live process.
///
/// On Unix, this reaps exited child zombies before falling back to `kill(pid, 0)`
/// for non-child processes. It is intended for local runtime-state observation,
/// not for process ownership or signaling.
#[must_use]
pub fn is_pid_alive(pid: NonZeroProcessId) -> bool {
    liveness::is_alive(pid)
}

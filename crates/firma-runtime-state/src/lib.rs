//! Runtime state contracts and local liveness primitives shared by `OpenFirma` crates.

pub mod error;
pub mod pidfile;
pub mod process_id;
pub mod runtime_paths;
mod sandbox_id;
pub mod sidecar_markers;
pub mod state_dir;
pub mod status;

pub use error::{Result, RuntimeStateError};
pub use process_id::{ChildExt, SignalProcessError, UserProcessId, UserProcessIdError};
pub use runtime_paths::{capabilities_dir_from, default_runtime_dir, run_dir_from, run_entry_from};
pub use sandbox_id::{SandboxId, SandboxIdParseError};
pub use sidecar_markers::{MetadataFile, SidecarEntry, gc_stale, get, list};
pub use state_dir::resolve_state_dir;
pub use status::State;

//! Runtime state contracts and local liveness primitives shared by `OpenFirma` crates.

pub mod error;
pub mod pidfile;
pub mod process_id;
pub mod runtime_paths;
pub mod sidecar_markers;
pub mod state_dir;
pub mod status;

pub use error::{Result, RuntimeStateError};
pub use firma_identifiers::{SandboxId, SandboxIdParseError};
pub use process_id::{ChildExt, SignalProcessError, UserProcessId};
pub use runtime_paths::{capabilities_dir_from, default_runtime_dir, run_dir_from, run_entry_from};
pub use sidecar_markers::{MetadataFile, SidecarEntry, gc_stale, get, list};
pub use state_dir::resolve_state_dir;
pub use status::State;

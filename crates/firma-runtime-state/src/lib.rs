//! Shared runtime-filesystem contracts for `OpenFirma` processes.
//!
//! This crate defines the canonical runtime layout, persisted marker schemas,
//! atomic file operations, and non-owning liveness observations. Process
//! lifecycle ownership and component-specific in-memory state remain with the
//! crates that implement those behaviors.

pub mod error;
pub mod pidfile;
pub mod process_id;
pub mod runtime_paths;
pub mod sidecar_markers;
pub mod status;

pub use error::{Result, RuntimeStateError};
pub use process_id::UserProcessId;
pub use runtime_paths::RuntimeLayout;
pub use sidecar_markers::{MetadataFile, SidecarEntry, gc_stale, get, list, publish};
pub use status::State;

/// Resolve the canonical runtime-state directory and return its root path.
///
/// Prefer [`RuntimeLayout::resolve`] when callers also need to derive paths
/// within the runtime directory.
///
/// # Errors
///
/// Returns an error when the platform has no usable runtime-directory fallback.
pub fn resolve_state_dir(flag: Option<std::path::PathBuf>) -> Result<std::path::PathBuf> {
    RuntimeLayout::resolve(flag).map(RuntimeLayout::into_root)
}

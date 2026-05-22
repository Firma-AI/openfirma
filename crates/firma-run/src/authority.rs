//! Authority bootstrap, autostart, and lifecycle (FIR-103).
//!
//! Mirrors the FIR-102 sidecar autostart structure. Subordinate modules:
//!
//! - [`config`] — user-level `firma.toml` reader.
//! - [`selection`] — resolver that combines CLI args and config into a
//!   single [`AuthoritySelection`].
//! - [`supervisor`] — `AuthoritySupervisor` spawning + scrape + Drop.
//! - [`metadata`] — per-run `authority/metadata.toml` writer.

pub mod config;
#[cfg(unix)]
pub(crate) mod metadata;
pub mod selection;
pub mod supervisor;

pub use selection::{AuthorityCli, AuthoritySelection, resolve};
pub use supervisor::{AuthoritySupervisor, DEFAULT_STARTUP_TIMEOUT_SECS, SpawnRequest};

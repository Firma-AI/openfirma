//! Authority bootstrap, autostart, and lifecycle (FIR-103).
//!
//! Mirrors the FIR-102 sidecar autostart structure. Subordinate modules:
//!
//! - [`prompt`] — TTY-aware y/N prompt trait.
//! - [`config`] — user-level `firma.toml` reader + writer.
//! - [`selection`] — resolver that combines CLI args, persisted config,
//!   and prompt I/O into a single [`AuthoritySelection`].
//! - [`supervisor`] — `AuthoritySupervisor` spawning + scrape + Drop.
//! - [`metadata`] — per-run `authority/metadata.toml` writer.

pub mod config;
#[cfg(unix)]
pub(crate) mod metadata;
pub mod prompt;
pub mod selection;
pub mod supervisor;

pub use prompt::{AuthorityPromptIo, StdAuthorityPrompt};
pub use selection::{AuthorityCli, AuthoritySelection, resolve};
pub use supervisor::{AuthoritySupervisor, DEFAULT_STARTUP_TIMEOUT_SECS, SpawnRequest};

//! Authority selection and local-launch preparation.
//!
//! Subordinate modules:
//!
//! - [`config`] — user-level `firma.toml` reader.
//! - [`selection`] — resolver that combines CLI args and config into a
//!   single [`AuthoritySelection`].
//! - [`prepare`] — local Authority configuration and launch preparation.
//! - `metadata` — per-run `authority/metadata.toml` writer.

pub mod bootstrap;
pub mod config;
#[cfg(unix)]
pub(crate) mod metadata;
#[cfg(unix)]
pub(crate) mod prepare;
pub mod prompt;
pub mod selection;

pub use prompt::{AuthorityPromptIo, StdAuthorityPrompt};

pub use selection::AuthorityCli;
pub(crate) use selection::{AuthoritySelection, resolve};

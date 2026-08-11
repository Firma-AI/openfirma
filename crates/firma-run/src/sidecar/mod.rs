#[doc(hidden)]
pub mod config;
#[cfg(unix)]
pub(crate) mod metadata;
#[cfg(unix)]
#[doc(hidden)]
pub mod prepare;
pub mod selection;

pub use selection::{SidecarCli, SidecarSelection, resolve};

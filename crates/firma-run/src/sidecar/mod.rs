#[doc(hidden)]
pub mod config;
#[cfg(unix)]
pub(crate) mod metadata;
#[cfg(unix)]
#[doc(hidden)]
pub mod prepare;
pub mod selection;
#[doc(hidden)]
pub mod supervisor;

pub use selection::{SidecarCli, SidecarSelection, resolve};

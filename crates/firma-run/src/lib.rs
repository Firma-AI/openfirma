//! Firma Run runtime wrapper.
//!
//! Provides the `firma run` command used to wrap agent processes behind a
//! sandbox backend and sidecar routing contract.

pub mod authority;
pub mod backend;
pub mod capability;
pub mod config;
pub mod dns_stub;
#[cfg(target_os = "linux")]
pub mod egress_guard;
pub mod error;
pub mod identity;
pub mod log;
pub mod mediator;
pub mod profile;
pub mod proxy_bridge;
pub mod routing;
pub mod runtime;
pub mod seccomp;
pub mod sidecar;
pub mod supervisor;

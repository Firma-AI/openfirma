//! Per-service runners dispatched by `crate::main`.

pub mod authority;
pub mod config;
pub mod dns_stub;
pub mod doctor;
#[cfg(target_os = "linux")]
pub mod egress_guarded_run;
pub mod monitor;
pub mod policy;
pub mod proxy_bridge;
pub mod run;
pub mod sidecar;
pub mod sidecar_status;
pub mod supervise;
pub mod token;

//! Per-service runners dispatched by `crate::main`.

pub mod authority;
pub mod dns_stub;
pub mod doctor;
pub mod init;
pub mod monitor;
pub mod policy;
pub mod proxy_bridge;
pub mod run;
pub mod sidecar;
pub mod sidecar_status;
pub mod supervise;
pub mod token;

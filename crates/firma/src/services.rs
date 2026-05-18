//! Per-service runners dispatched by `crate::main`.

pub mod authority;
pub mod dns_stub;
pub mod doctor;
pub mod monitor;
pub mod proxy_bridge;
pub mod run;
pub mod sidecar;
pub mod sidecar_status;
pub mod stack;
pub mod supervise;
pub mod token;

//! Deterministic full-stack CLI scenarios.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::redundant_pub_crate,
    reason = "test code: panics are acceptable test failures"
)]

mod audit;
mod harness;
mod scenarios;
mod upstream;

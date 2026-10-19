#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]
mod common;
mod locking;
mod policy;
mod redaction;
mod round_trip;
mod transitions;
#[cfg(unix)]
mod trust;

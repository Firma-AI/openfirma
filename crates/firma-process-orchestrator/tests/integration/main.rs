#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod error_boundary;
mod forced_termination;
mod ownership;
mod status_state_machine;
mod stop_forced_grandchildren;
mod stop_grandchildren;
#[cfg(unix)]
mod stop_orphaned_grandchild;
#[cfg(unix)]
mod support;

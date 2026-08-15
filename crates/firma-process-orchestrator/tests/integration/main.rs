#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[macro_use]
mod helper;
#[cfg(unix)]
mod endpoint_readiness;
mod error_boundary;
mod forced_termination;
mod ownership;
mod startup_contract;
mod status_state_machine;
#[cfg(unix)]
mod stop_dependency_order;
#[cfg(windows)]
mod stop_dependency_order_windows;
mod stop_forced_grandchildren;
mod stop_grandchildren;
#[cfg(unix)]
mod stop_orphaned_grandchild;

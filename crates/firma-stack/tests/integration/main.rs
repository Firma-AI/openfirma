#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod config_parse;
mod foreground_startup_signal;
mod ownership;
mod stale_process_group;
mod startup_rollback_orphaned_grandchild;
mod status_state_machine;
mod stop_forced_grandchildren;
mod stop_grandchildren;
#[cfg(unix)]
mod stop_orphaned_grandchild;
mod support;

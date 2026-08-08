#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod config_parse;
mod foreground_startup_signal;
mod readiness_process_exit;
mod stale_process_group;
mod startup_rollback_orphaned_grandchild;
mod support;

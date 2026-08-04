//! Process supervision and observability primitives for the firma stack.

pub mod config;
pub mod error;
pub mod shutdown_event;
pub mod start;
pub mod status;
pub mod stop;

mod detach;
mod platform;
mod readiness;
mod spawn;
mod supervisor;

pub use config::{StackConfig, resolve_stack_config};
pub use error::StackError;
pub use start::{RunningStack, StackHandle, StartMode, spawn_stack, start, supervise};
pub use status::{ComponentStatus, StackStatus, State, status};
pub use stop::{StopOutcome, stop};

#[doc(hidden)]
pub mod test_support {
    pub use firma_runtime_state::pidfile;

    /// Spawn an arbitrary command into the same process grouping used by the stack.
    ///
    /// # Errors
    ///
    /// Returns process spawn, log, or pidfile errors.
    pub fn spawn_raw_into_group(
        state_dir: &std::path::Path,
        name: &str,
        cmd: &mut std::process::Command,
    ) -> crate::error::Result<u32> {
        let mut child = spawn_raw_owned_into_group(state_dir, name, cmd)?;
        let pid = child.id();
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(pid)
    }

    /// Spawn an arbitrary grouped command while retaining its child handle.
    ///
    /// # Errors
    ///
    /// Returns process spawn, log, or pidfile errors.
    pub fn spawn_raw_owned_into_group(
        state_dir: &std::path::Path,
        name: &str,
        cmd: &mut std::process::Command,
    ) -> crate::error::Result<std::process::Child> {
        use crate::platform::{Platform, SystemPlatform};
        let group = SystemPlatform::new_group()?;
        let log_path = state_dir.join(format!("{name}.log"));
        let pidfile_path = state_dir.join(format!("{name}.pid"));
        let child = SystemPlatform::spawn_in_group(&group, cmd, &log_path)?;
        firma_runtime_state::pidfile::write(&pidfile_path, child.termination_target.stored_id())?;
        std::fs::write(state_dir.join(format!("{name}.listen")), "127.0.0.1:0\n")?;
        Ok(child.child)
    }
}

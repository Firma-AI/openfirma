//! Detached supervisor process creation.
//!
//! [`spawn_supervisor`] creates the governance process used by
//! [`crate::start::start`], but successful process creation alone does not
//! transfer direct-child collection or prove that the supervisor has attached.
//! The ownership transition therefore remains canonical in
//! [`crate::start::start`].

use std::path::Path;
use std::process::{Child, Command, Stdio};

use tracing::{debug, info};

use crate::error::{Result, StackError};

/// Spawn the hidden supervisor without inheriting terminal-bound lifetime.
///
/// Log handles and platform creation flags are rebuilt for each
/// [`spawn_detached`] attempt. A successful return means only that the
/// returned supervisor child exists; the caller retains its collection handle
/// and stack rollback authority until the attachment barrier defined by
/// [`crate::start::wait_for_supervisor_attachment`].
///
/// # Errors
///
/// Returns executable discovery, log creation, command construction, or
/// supervisor spawn errors.
pub fn spawn_supervisor(state_dir: &Path) -> Result<Child> {
    firma_runtime_state::pidfile::remove(&state_dir.join("stack.ready"))?;
    let exe = std::env::current_exe()?;
    debug!(exe = %exe.display(), state_dir = %state_dir.display(), "preparing detached supervisor");

    // The stdio handles are moved into the `Command` and consumed by a spawn
    // attempt, so build the command fresh for each attempt. On Windows this
    // also lets us retry with a different creation-flag set.
    let build = || -> Result<Command> {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(state_dir.join("supervisor.log"))?;
        let stderr_log = log.try_clone()?;

        let mut cmd = Command::new(&exe);
        cmd.args(["__supervise", "--state-dir"])
            .arg(state_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr_log));

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
            // Detach from the controlling terminal so closing the parent shell
            // does not deliver SIGHUP to the supervisor. `setsid` must run in
            // the child between fork and exec.
            #[expect(
                unsafe_code,
                reason = "CommandExt::pre_exec is required here to call setsid in the fork/exec window"
            )]
            // SAFETY: `setsid` is async-signal-safe and is the only syscall in
            // the pre-exec closure. No allocator or locks are used.
            unsafe {
                cmd.pre_exec(|| {
                    let _ = nix::unistd::setsid();
                    Ok(())
                });
            }
        }

        Ok(cmd)
    };

    let child = spawn_detached(&build)?;
    info!(pid = child.id(), "supervisor spawned");
    Ok(child)
}

/// Spawn a command produced by the supplied builder, detached from the parent.
///
/// On Windows the first attempt requests breakaway from the parent's Job
/// Object. Only an access-denied result permits a retry inside a nested Job;
/// every other failure is returned as [`StackError::Spawn`]. The nested Job
/// remains viable because this revision's stack [`crate::platform::Group`] does
/// not terminate members when its handle closes.
fn spawn_detached<F>(build: &F) -> Result<Child>
where
    F: Fn() -> Result<Command>,
{
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::{
            CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
        };

        const ERROR_ACCESS_DENIED: i32 = 5;
        let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;

        let mut cmd = build()?;
        cmd.creation_flags(base | CREATE_BREAKAWAY_FROM_JOB);
        match cmd.spawn() {
            Ok(child) => Ok(child),
            Err(source) if source.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
                debug!("breakaway-from-job denied by parent Job Object; retrying nested");
                let mut cmd = build()?;
                cmd.creation_flags(base);
                cmd.spawn().map_err(|source| StackError::Spawn {
                    component: "supervisor".into(),
                    source,
                })
            }
            Err(source) => Err(StackError::Spawn {
                component: "supervisor".into(),
                source,
            }),
        }
    }

    #[cfg(unix)]
    {
        build()?.spawn().map_err(|source| StackError::Spawn {
            component: "supervisor".into(),
            source,
        })
    }
}

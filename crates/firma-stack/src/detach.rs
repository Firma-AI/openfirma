//! Spawn the detached supervisor process.

use std::path::Path;
use std::process::{Command, Stdio};

use tracing::{debug, info};

use crate::error::{Result, StackError};

pub fn spawn_supervisor(state_dir: &Path) -> Result<()> {
    let exe = std::env::current_exe()?;
    debug!(exe = %exe.display(), state_dir = %state_dir.display(), "preparing detached supervisor");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(state_dir.join("supervisor.log"))?;
    let stderr_log = log.try_clone()?;

    let mut cmd = Command::new(exe);
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
        // does not deliver SIGHUP to the supervisor. `setsid` must run in the
        // child between fork and exec.
        #[allow(unsafe_code)]
        // SAFETY: `setsid` is async-signal-safe and is the only syscall in
        // the pre-exec closure. No allocator or locks are used.
        unsafe {
            cmd.pre_exec(|| {
                let _ = nix::unistd::setsid();
                Ok(())
            });
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::{
            CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
        };
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB);
    }

    let child = cmd.spawn().map_err(|source| StackError::Spawn {
        component: "supervisor".into(),
        source,
    })?;
    info!(pid = child.id(), "supervisor spawned");
    Ok(())
}

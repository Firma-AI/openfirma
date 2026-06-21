//! Spawn the detached supervisor process.

use std::path::Path;
use std::process::{Child, Command, Stdio};

use tracing::{debug, info};

use crate::error::{Result, StackError};

pub fn spawn_supervisor(state_dir: &Path) -> Result<()> {
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
    Ok(())
}

/// Spawn the supervisor command produced by `build`, detached from the parent.
///
/// On Windows the supervisor is first launched with
/// `CREATE_BREAKAWAY_FROM_JOB` so it survives the parent's Job Object being
/// torn down. When the parent runs inside a Job Object that does not grant
/// `JOB_OBJECT_LIMIT_BREAKAWAY_OK` — common under `cargo run`, Windows
/// Terminal, and CI runners — `CreateProcess` rejects that flag with
/// `ERROR_ACCESS_DENIED` (os error 5). In that case we retry without the
/// breakaway flag: on Windows 8+ the supervisor is then placed in a nested
/// Job Object, which still outlives the parent because the stack's Job Object
/// is created without `KILL_ON_JOB_CLOSE`.
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

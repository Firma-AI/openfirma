//! Spawn the detached supervisor without transferring component ownership.

use std::path::Path;
use std::process::{Child, Command, Stdio};

use tracing::{debug, info};

use crate::error::{Result, StackError};

/// Spawn the supervisor child retained by detached [`crate::start::start_from_plan`].
///
/// The launcher-assigned [`crate::StackGeneration`] binds this child to the
/// state it may publish and later roll back. The child creates and owns the
/// actual components; the launcher receives only the handle needed to validate
/// or abort handoff.
///
/// `config_file` is re-passed to the child through `--config` so it re-derives
/// the same plan; `firma_bin`, when present, is forwarded through `--firma-bin`
/// so the child spawns components from the same executable as the launcher.
pub fn spawn_supervisor(
    state_dir: &Path,
    config_file: &Path,
    firma_bin: Option<&Path>,
    generation: crate::StackGeneration,
) -> Result<Child> {
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
            .arg("--config")
            .arg(config_file)
            .arg("--generation")
            .arg(generation.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr_log));
        if let Some(firma_bin) = firma_bin {
            cmd.arg("--firma-bin").arg(firma_bin);
        }

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
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
                    nix::unistd::setsid()
                        .map(|_| ())
                        .map_err(std::io::Error::from)
                });
            }
        }

        Ok(cmd)
    };

    let child = spawn_detached(&build)?;
    info!(pid = child.id(), "supervisor spawned");
    Ok(child)
}

/// Spawn a freshly built supervisor command detached from the launcher.
///
/// On Windows the breakaway creation flag ensures the supervisor survives the
/// launcher's Job Object. If that Job does not grant breakaway, startup fails
/// closed: launching inside it would make detached lifetime depend on an
/// external owner-loss policy that Firma cannot inspect or control.
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

        let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;

        let mut cmd = build()?;
        cmd.creation_flags(base | CREATE_BREAKAWAY_FROM_JOB);
        cmd.spawn().map_err(|source| StackError::Spawn {
            component: "supervisor (breakaway required)".into(),
            source,
        })
    }

    #[cfg(unix)]
    {
        build()?.spawn().map_err(|source| StackError::Spawn {
            component: "supervisor".into(),
            source,
        })
    }
}

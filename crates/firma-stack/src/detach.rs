//! Detached supervisor process creation.
//!
//! [`spawn_supervisor`] creates the process that will call
//! [`crate::start::supervise_owned`] and become the concrete component owner.
//! The launcher retains this returned child until the attachment barrier in
//! [`crate::start::wait_for_supervisor_attachment`] succeeds.

use std::path::Path;
use std::process::{Child, Command, Stdio};

use tracing::{debug, info};

use crate::error::{Result, StackError};

/// Spawn the hidden owner with the complete [`crate::config::StackConfig`].
///
/// Passing the resolved configuration is an ownership requirement: the
/// supervisor, rather than the launcher, invokes [`crate::start::spawn_stack`]
/// and must therefore select the same executable and configuration file. A
/// successful return grants the launcher only ownership of the supervisor
/// child, not the components it will create.
///
/// # Errors
///
/// Returns runtime-state reset, executable discovery, log creation, command
/// construction, or supervisor spawn errors.
pub fn spawn_supervisor(state_dir: &Path, config: &crate::config::StackConfig) -> Result<Child> {
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
            .arg(&config.config_file)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr_log));
        if let Some(firma_bin) = &config.firma_bin {
            cmd.arg("--firma-bin").arg(firma_bin);
        }

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

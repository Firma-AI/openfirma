//! Cross-platform spawn helpers used by `start`.

use std::path::Path;
use std::process::Command;

use tracing::debug;

use crate::error::Result;
use crate::pidfile;
use crate::platform::{Group, Platform, SpawnedChild, SystemPlatform};

#[derive(Clone, Copy)]
pub(crate) struct SpawnRequest<'a> {
    pub(crate) name: &'a str,
    pub(crate) args: &'a [&'a str],
    pub(crate) state_dir: &'a Path,
    /// Override for the binary to invoke. When `None`, `current_exe()`
    /// is used.
    pub(crate) exe: Option<&'a Path>,
}

pub(crate) struct SpawnedComponent {
    pub(crate) pid: u32,
}

pub(crate) fn spawn_component(group: &Group, req: &SpawnRequest<'_>) -> Result<SpawnedComponent> {
    let exe: std::path::PathBuf = match req.exe {
        Some(path) => path.to_path_buf(),
        None => std::env::current_exe()?,
    };
    let log_path = req.state_dir.join(format!("{}.log", req.name));
    let pidfile_path = req.state_dir.join(format!("{}.pid", req.name));
    debug!(
        name = req.name,
        exe = %exe.display(),
        args = ?req.args,
        log = %log_path.display(),
        "spawning component"
    );

    let mut cmd = Command::new(exe);
    cmd.args(req.args);
    let SpawnedChild { pid } = SystemPlatform::spawn_in_group(group, &mut cmd, &log_path)?;
    pidfile::write(&pidfile_path, pid)?;
    debug!(name = req.name, pid, pidfile = %pidfile_path.display(), "pidfile written");
    Ok(SpawnedComponent { pid })
}

//! Demo-tui-specific process helpers used by the agent bridge.
//!
//! Stack (authority + sidecar) supervision lives in `firma-stack`. This file
//! retains only the `kill_tree` primitive needed by `crate::agent_bridge`,
//! which spawns demo agent processes outside the firma stack.

pub(crate) fn kill_tree_pub(pid: u32) {
    kill_tree(pid);
}

/// Kill the entire process group rooted at `pid`.
///
/// On Unix this sends `SIGKILL` to every process in the group. On non-Unix
/// platforms this is a no-op (the individual `child.kill()` suffices).
fn kill_tree(pid: u32) {
    #[cfg(unix)]
    {
        use std::process::{Command, Stdio};
        let _ = Command::new("kill")
            .args(["-9", &format!("-{pid}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

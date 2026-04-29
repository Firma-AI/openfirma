use anyhow::{Context, Result};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;

pub struct ManagedProcess {
    pub child: Child,
    pub output_rx: mpsc::Receiver<String>,
}

impl ManagedProcess {
    pub fn shutdown(&mut self) {
        kill_tree(self.child.id());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn spawn_with_output(cmd: &mut Command) -> Result<ManagedProcess> {
    // Put each child in its own process group so kill_tree can reach
    // any sub-children (e.g. the Python process spawned by uv).
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn process")?;

    let stdout = child.stdout.take().context("failed to capture stdout")?;
    let stderr = child.stderr.take().context("failed to capture stderr")?;

    let (tx, rx) = mpsc::channel::<String>();
    let tx_err = tx.clone();

    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            match line {
                Ok(l) => {
                    if tx_err.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    Ok(ManagedProcess {
        child,
        output_rx: rx,
    })
}

pub(crate) fn kill_tree_pub(pid: u32) {
    kill_tree(pid);
}

/// Kill the entire process group rooted at `pid`.
/// On Unix this sends SIGKILL to every process in the group.
/// On non-Unix platforms this is a no-op (the individual `child.kill()` suffices).
fn kill_tree(pid: u32) {
    #[cfg(unix)]
    {
        // Negative pgid → kill every process in the group.
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

use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
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

pub fn spawn_with_output_to_file(cmd: &mut Command, log_path: &Path) -> Result<ManagedProcess> {
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).context("failed to create process log directory")?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(log_path)
        .with_context(|| format!("failed to open process log '{}'", log_path.display()))?;
    spawn_with_output_inner(cmd, Some(Arc::new(Mutex::new(file))))
}

fn spawn_with_output_inner(
    cmd: &mut Command,
    log_file: Option<Arc<Mutex<File>>>,
) -> Result<ManagedProcess> {
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
    let stdout_log = log_file.clone();
    let stderr_log = log_file;

    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(l) => {
                    write_log_line(stdout_log.as_ref(), "stdout", &l);
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
                    write_log_line(stderr_log.as_ref(), "stderr", &l);
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

fn write_log_line(log_file: Option<&Arc<Mutex<File>>>, stream: &str, line: &str) {
    let Some(log_file) = log_file else {
        return;
    };
    let Ok(mut file) = log_file.lock() else {
        return;
    };
    let _ = writeln!(file, "[{stream}] {line}");
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

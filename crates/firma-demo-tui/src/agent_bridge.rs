use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;

pub struct AgentBridge {
    pub child: Child,
    pub output_rx: mpsc::Receiver<String>,
    stdin_tx: mpsc::SyncSender<String>,
}

impl AgentBridge {
    pub fn send_input(&self, line: String) {
        let _ = self.stdin_tx.send(line);
    }

    pub fn shutdown(&mut self) {
        crate::process_manager::kill_tree_pub(self.child.id());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for AgentBridge {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn spawn_agent(
    script: &Path,
    proxy_addr: &str,
    prompt: &str,
    extra_env: &HashMap<String, String>,
) -> Result<AgentBridge> {
    // Run uv from the demos directory so it finds examples/demos/pyproject.toml.
    let demos_dir = script
        .parent()
        .and_then(Path::parent)
        .context("cannot determine demos directory from agent script path")?;

    // Pre-install dependencies outside the proxy/sandbox to avoid tunnel errors.
    let _ = Command::new("uv")
        .arg("sync")
        .current_dir(demos_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let mut cmd = Command::new("uv");
    cmd.arg("run")
        .arg(script)
        .current_dir(demos_dir)
        .env("HTTP_PROXY", proxy_addr)
        .env("HTTPS_PROXY", proxy_addr)
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("FIRMA_DEMO_PROMPT", prompt);

    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
        .context("failed to spawn agent — is uv installed?")?;

    let stdout = child
        .stdout
        .take()
        .context("failed to capture agent stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("failed to capture agent stderr")?;
    let mut stdin = child
        .stdin
        .take()
        .context("failed to capture agent stdin")?;

    let (out_tx, out_rx) = mpsc::channel::<String>();
    let out_tx_err = out_tx.clone();
    let (in_tx, in_rx) = mpsc::sync_channel::<String>(16);

    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(l) => {
                    if out_tx.send(l).is_err() {
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
                    if out_tx_err.send(format!("[err] {l}")).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    thread::spawn(move || {
        for line in in_rx {
            if writeln!(stdin, "{line}").is_err() {
                break;
            }
            if stdin.flush().is_err() {
                break;
            }
        }
    });

    Ok(AgentBridge {
        child,
        output_rx: out_rx,
        stdin_tx: in_tx,
    })
}

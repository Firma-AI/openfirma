use anyhow::{Context, Result};
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
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn spawn_agent(script: &Path, proxy_addr: &str, prompt: &str) -> Result<AgentBridge> {
    let mut child = Command::new("uv")
        .arg("run")
        .arg(script)
        .env("HTTP_PROXY", proxy_addr)
        .env("HTTPS_PROXY", proxy_addr)
        .env("FIRMA_DEMO_PROMPT", prompt)
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

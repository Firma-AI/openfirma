use anyhow::{Context, Result, ensure};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::demo_loader::DemoManifest;
use crate::process_manager::{ManagedProcess, spawn_with_output_to_file};

pub struct DemoRuntime {
    pub authority: ManagedProcess,
    pub sidecar: ManagedProcess,
    pub audit_log_path: std::path::PathBuf,
    pub authority_log_path: std::path::PathBuf,
    pub sidecar_log_path: std::path::PathBuf,
    pub ca_cert_path: std::path::PathBuf,
}

impl DemoRuntime {
    pub fn shutdown(&mut self) {
        self.sidecar.shutdown();
        self.authority.shutdown();
    }
}

pub fn boot(manifest: &DemoManifest) -> Result<DemoRuntime> {
    let runtime_dir = manifest.root.join(".runtime");
    std::fs::create_dir_all(&runtime_dir).context("failed to create .runtime directory")?;

    provision_keys(&runtime_dir)?;

    let revocations = runtime_dir.join("revocations.txt");
    if !revocations.exists() {
        std::fs::write(&revocations, "").context("failed to create revocations.txt")?;
    }

    ensure_demo_ca_dir(&runtime_dir.join("generated-openauthority-ca"))?;

    let authority_log_path = runtime_dir.join("authority.log");
    let sidecar_log_path = runtime_dir.join("sidecar.log");

    let mut authority = spawn_with_output_to_file(
        Command::new("cargo")
            .args(["run", "--bin", "openauthority-authority", "--", "--config"])
            .arg(&manifest.authority_config),
        &authority_log_path,
    )
    .context("failed to start openauthority-authority")?;

    wait_for_authority_ready(&mut authority, &manifest.authority_config)?;

    let audit_log_path = runtime_dir.join("audit.jsonl");
    std::fs::write(&audit_log_path, "").context("failed to reset audit.jsonl")?;

    let sidecar = spawn_with_output_to_file(
        Command::new("cargo")
            .args([
                "run",
                "--bin",
                "openauthority-sidecar",
                "--",
                "--config-file",
            ])
            .arg(&manifest.sidecar_config),
        &sidecar_log_path,
    )
    .context("failed to start openauthority-sidecar")?;

    let ca_dir = runtime_dir.join("generated-openauthority-ca");
    wait_for_demo_ca_material(&ca_dir)?;

    Ok(DemoRuntime {
        authority,
        sidecar,
        audit_log_path,
        authority_log_path,
        sidecar_log_path,
        ca_cert_path: ca_dir.join("openauthority-ca.crt"),
    })
}

fn wait_for_authority_ready(authority: &mut ManagedProcess, config_path: &Path) -> Result<()> {
    let addr = read_authority_listen_addr(config_path)?;
    let deadline = Instant::now() + Duration::from_secs(60);

    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return Ok(());
        }

        if let Some(status) = authority
            .child
            .try_wait()
            .context("failed to check openauthority-authority process status")?
        {
            ensure!(
                status.success(),
                "openauthority-authority exited before listening on {addr}: {status}"
            );
        }

        ensure!(
            Instant::now() < deadline,
            "openauthority-authority did not start listening on {addr}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn read_authority_listen_addr(config_path: &Path) -> Result<SocketAddr> {
    let config = std::fs::read_to_string(config_path).with_context(|| {
        format!(
            "failed to read authority config '{}'",
            config_path.display()
        )
    })?;

    for line in config.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() == "listen_addr" {
            let value = value.trim().trim_matches('"');
            return value
                .parse()
                .with_context(|| format!("invalid authority listen_addr '{value}'"));
        }
    }

    anyhow::bail!(
        "authority config '{}' does not define listen_addr",
        config_path.display()
    );
}

fn wait_for_demo_ca_material(ca_dir: &Path) -> Result<()> {
    let cert = ca_dir.join("openauthority-ca.crt");
    let key = ca_dir.join("openauthority-ca.key");
    let deadline = Instant::now() + Duration::from_secs(60);

    loop {
        if cert.exists() && key.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            ensure!(
                cert.exists() && key.exists(),
                "openauthority-sidecar did not generate CA material at '{}' and '{}'",
                cert.display(),
                key.display()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn provision_keys(runtime_dir: &Path) -> Result<()> {
    let key_file = runtime_dir.join("authority.key");
    if !key_file.exists() {
        // Suppress output — we are inside the TUI alternate screen.
        let status = Command::new("cargo")
            .args([
                "run",
                "--bin",
                "openauthority-authority",
                "--",
                "generate-key",
                "--output",
            ])
            .arg(&key_file)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("failed to run openauthority-authority generate-key")?;
        ensure!(status.success(), "generate-key failed");
    }

    let audit_key = runtime_dir.join("audit.key");
    if !audit_key.exists() {
        std::fs::write(&audit_key, DEMO_AUDIT_KEY_PEM)
            .context("failed to write demo audit signing key")?;
    }

    Ok(())
}

fn ensure_demo_ca_dir(ca_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(ca_dir).context("failed to create openauthority-ca directory")?;
    // Always regenerate CA material on demo boot so the cert reflects current code.
    for name in ["openauthority-ca.crt", "openauthority-ca.key"] {
        let p = ca_dir.join(name);
        if p.exists() {
            std::fs::remove_file(&p)
                .with_context(|| format!("failed to remove stale {}", p.display()))?;
        }
    }
    Ok(())
}

const DEMO_AUDIT_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgS+9b9zHd22EAeg9M
bXfQcvk+kh+UDhxsRkIm8BsBd4ihRANCAARrNl5iPKSasLwfIihEcv8BeQsqAXMl
3wlh7RZmOnI0E3wNCaMKd3B7Sd/fXknJ0WmI6BsrvfidxQEAYvsndbvx
-----END PRIVATE KEY-----
";

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use firma_stack::{StackConfig, spawn_stack};

use crate::demo_loader::DemoManifest;

pub struct DemoRuntime {
    pub state_dir: PathBuf,
    pub audit_log_path: PathBuf,
    pub authority_log_path: PathBuf,
    pub sidecar_log_path: PathBuf,
    pub ca_cert_path: PathBuf,
}

impl DemoRuntime {
    pub fn shutdown(&mut self) {
        let _ = firma_stack::stop(&self.state_dir, Duration::from_secs(10));
    }
}

pub fn boot(manifest: &DemoManifest) -> Result<DemoRuntime> {
    let state_dir = manifest.root.join(".runtime");
    std::fs::create_dir_all(&state_dir).context("failed to create .runtime directory")?;

    provision_demo_assets(&state_dir)?;
    // Demo-specific: always regenerate CA material so the cert reflects current code.
    wipe_ca_dir(&state_dir.join("generated-firma-ca"))?;

    let cfg = StackConfig {
        state_dir: Some(state_dir.clone()),
        authority_config: manifest.authority_config.clone(),
        sidecar_config: manifest.sidecar_config.clone(),
        firma_bin: Some(resolve_firma_bin()?),
    };
    spawn_stack(&cfg, &state_dir).context("firma_stack::spawn_stack")?;

    Ok(DemoRuntime {
        audit_log_path: state_dir.join("audit.jsonl"),
        authority_log_path: state_dir.join("authority.log"),
        sidecar_log_path: state_dir.join("sidecar.log"),
        ca_cert_path: state_dir.join("generated-firma-ca/firma-ca.crt"),
        state_dir,
    })
}

/// Locate the `firma` binary. Demo-tui's own `current_exe()` is
/// `firma-demo-tui`, which has no `authority` / `sidecar` subcommands.
/// Look for a sibling `firma` next to it (typical `cargo` layout: both
/// live under `target/<profile>/`).
fn resolve_firma_bin() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("current_exe")?;
    let parent = exe
        .parent()
        .context("current_exe has no parent directory")?;
    let candidate = parent.join(if cfg!(windows) { "firma.exe" } else { "firma" });
    if candidate.exists() {
        return Ok(candidate);
    }
    anyhow::bail!(
        "could not locate the `firma` binary at {} \
         (run `cargo build -p firma` first)",
        candidate.display()
    );
}

fn wipe_ca_dir(ca_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(ca_dir).context("failed to create firma-ca directory")?;
    for name in ["firma-ca.crt", "firma-ca.key"] {
        let path = ca_dir.join(name);
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("failed to remove stale {}", path.display()))?;
        }
    }
    Ok(())
}

fn provision_demo_assets(runtime_dir: &Path) -> Result<()> {
    let revocations = runtime_dir.join("revocations.txt");
    if !revocations.exists() {
        std::fs::write(&revocations, "").context("failed to create revocations.txt")?;
    }

    let audit_key = runtime_dir.join("audit.key");
    if !audit_key.exists() {
        std::fs::write(&audit_key, DEMO_AUDIT_KEY_PEM)
            .context("failed to write demo audit signing key")?;
    }

    let key_file = runtime_dir.join("authority.key");
    if !key_file.exists() {
        // Suppress output — we are inside the TUI alternate screen.
        let status = Command::new("cargo")
            .args([
                "run",
                "--bin",
                "firma",
                "--",
                "authority",
                "generate-key",
                "--output",
            ])
            .arg(&key_file)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("failed to run firma authority generate-key")?;
        ensure!(status.success(), "generate-key failed");
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

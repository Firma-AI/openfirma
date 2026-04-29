use anyhow::{Context, Result, ensure};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::demo_loader::DemoManifest;
use crate::process_manager::{ManagedProcess, spawn_with_output};

pub struct DemoRuntime {
    pub authority: ManagedProcess,
    pub sidecar: ManagedProcess,
    pub audit_log_path: std::path::PathBuf,
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

    repair_demo_ca_pair(&runtime_dir.join("generated-firma-ca"))?;

    let authority = spawn_with_output(
        Command::new("cargo")
            .args(["run", "--bin", "firma-authority", "--", "--config"])
            .arg(&manifest.authority_config),
    )
    .context("failed to start firma-authority")?;

    std::thread::sleep(Duration::from_millis(800));

    let audit_log_path = runtime_dir.join("audit.jsonl");
    std::fs::write(&audit_log_path, "").context("failed to reset audit.jsonl")?;

    let sidecar = spawn_with_output(
        Command::new("cargo")
            .args(["run", "--bin", "firma-sidecar", "--", "--config-file"])
            .arg(&manifest.sidecar_config),
    )
    .context("failed to start firma-sidecar")?;

    std::thread::sleep(Duration::from_millis(800));

    Ok(DemoRuntime {
        authority,
        sidecar,
        audit_log_path,
    })
}

fn provision_keys(runtime_dir: &Path) -> Result<()> {
    let key_file = runtime_dir.join("authority.key");
    if !key_file.exists() {
        // Suppress output — we are inside the TUI alternate screen.
        let status = Command::new("cargo")
            .args([
                "run",
                "--bin",
                "firma-autority",
                "--",
                "generate-key",
                "--output",
            ])
            .arg(&key_file)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("failed to run firma-authority generate-key")?;
        ensure!(status.success(), "generate-key failed");
    }

    let audit_key = runtime_dir.join("audit.key");
    if !audit_key.exists() {
        std::fs::write(&audit_key, DEMO_AUDIT_KEY_PEM)
            .context("failed to write demo audit signing key")?;
    }

    Ok(())
}

fn repair_demo_ca_pair(ca_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(ca_dir).context("failed to create firma-ca directory")?;

    let cert = ca_dir.join("firma-ca.crt");
    let key = ca_dir.join("firma-ca.key");
    if cert.exists() != key.exists() {
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
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

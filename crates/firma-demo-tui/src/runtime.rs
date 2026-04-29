use anyhow::{Context, Result, ensure};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::demo_loader::DemoManifest;
use crate::process_manager::{ManagedProcess, spawn_with_output};

pub struct DemoRuntime {
    pub authority: ManagedProcess,
    pub sidecar: ManagedProcess,
}

impl DemoRuntime {
    pub fn shutdown(&mut self) {
        self.sidecar.shutdown();
        self.authority.shutdown();
    }
}

pub fn build_binaries() -> Result<()> {
    let status = Command::new("cargo")
        .args(["build", "-p", "firma-authority", "-p", "firma-sidecar"])
        .status()
        .context("failed to run cargo build")?;
    ensure!(status.success(), "cargo build failed");
    Ok(())
}

pub fn boot(
    manifest: &DemoManifest,
    authority_bin: &Path,
    sidecar_bin: &Path,
) -> Result<DemoRuntime> {
    let runtime_dir = manifest.root.join(".runtime");
    std::fs::create_dir_all(&runtime_dir).context("failed to create .runtime directory")?;

    provision_keys(authority_bin, &runtime_dir)?;

    let revocations = runtime_dir.join("revocations.txt");
    if !revocations.exists() {
        std::fs::write(&revocations, "").context("failed to create revocations.txt")?;
    }

    std::fs::create_dir_all(runtime_dir.join("firma-ca"))
        .context("failed to create firma-ca directory")?;

    let authority = spawn_with_output(
        Command::new(authority_bin)
            .arg("--config")
            .arg(&manifest.authority_config),
    )
    .context("failed to start firma-authority")?;

    std::thread::sleep(Duration::from_millis(800));

    let sidecar = spawn_with_output(
        Command::new(sidecar_bin)
            .arg("--config-file")
            .arg(&manifest.sidecar_config),
    )
    .context("failed to start firma-sidecar")?;

    std::thread::sleep(Duration::from_millis(800));

    Ok(DemoRuntime { authority, sidecar })
}

fn provision_keys(authority_bin: &Path, runtime_dir: &Path) -> Result<()> {
    let key_file = runtime_dir.join("authority.key");
    if !key_file.exists() {
        let status = Command::new(authority_bin)
            .args(["generate-key", "--output"])
            .arg(&key_file)
            .status()
            .context("failed to run firma-authority generate-key")?;
        ensure!(status.success(), "generate-key failed");
    }

    let audit_key = runtime_dir.join("audit.key");
    if !audit_key.exists() {
        let status = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
            ])
            .arg(&audit_key)
            .status()
            .context("failed to run openssl genpkey (is openssl installed?)")?;
        ensure!(status.success(), "openssl genpkey failed");
    }

    Ok(())
}

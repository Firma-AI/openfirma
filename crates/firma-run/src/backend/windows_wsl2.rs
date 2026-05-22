use std::process::{Child, Command};

use crate::backend::platform;
use crate::backend::{
    BackendKind, EnforcementProof, LaunchSpec, PrepareRequest, SandboxBackend, SandboxHandle,
};
use crate::config::MountSpec;
use crate::config::NetworkPolicy;
use crate::error::RunError;

/// Windows WSL2 runtime backend.
#[derive(Debug, Default)]
pub struct Wsl2Backend;

impl Wsl2Backend {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SandboxBackend for Wsl2Backend {
    fn kind(&self) -> BackendKind {
        BackendKind::Wsl2
    }

    fn prepare(&self, request: &PrepareRequest) -> Result<SandboxHandle, RunError> {
        let wsl_linux_host = cfg!(target_os = "linux") && platform::detect_wsl().is_wsl();
        if !(cfg!(target_os = "windows") || wsl_linux_host) {
            return Err(RunError::UnsupportedBackend {
                backend: BackendKind::Wsl2.to_string(),
                reason: "WSL2 backend is only available on Windows hosts or inside WSL Linux environments".to_string(),
            });
        }

        if cfg!(target_os = "windows") && !command_available("wsl.exe") {
            return Err(RunError::Backend {
                backend: BackendKind::Wsl2.to_string(),
                reason: "wsl.exe is not installed or not executable".to_string(),
            });
        }

        let runtime_dir = std::env::temp_dir()
            .join("firma-run")
            .join(&request.identity.sandbox_id);
        std::fs::create_dir_all(&runtime_dir).map_err(|error| RunError::Backend {
            backend: BackendKind::Wsl2.to_string(),
            reason: format!(
                "failed to create runtime dir {}: {error}",
                runtime_dir.display()
            ),
        })?;

        let mounts = request
            .profile
            .mounts
            .iter()
            .cloned()
            .chain(std::iter::once(MountSpec {
                source: request.working_dir.clone(),
                target: request.working_dir.clone(),
                read_only: false,
            }))
            .collect::<Vec<_>>();

        Ok(SandboxHandle {
            backend: BackendKind::Wsl2,
            runtime_dir,
            identity: request.identity.clone(),
            mounts,
            network_policy: request.profile.network.clone(),
        })
    }

    fn enforce_network(
        &self,
        _handle: &SandboxHandle,
        policy: &NetworkPolicy,
    ) -> Result<EnforcementProof, RunError> {
        Ok(EnforcementProof {
            backend: BackendKind::Wsl2,
            structural: false,
            fail_closed: policy.fail_closed,
            detail: "WSL2 backend active; command executes in default WSL distro with proxy-based mediation".to_string(),
        })
    }

    fn verify_fail_closed(
        &self,
        _handle: &SandboxHandle,
        proof: &EnforcementProof,
    ) -> Result<(), RunError> {
        if !proof.fail_closed {
            return Err(RunError::Backend {
                backend: BackendKind::Wsl2.to_string(),
                reason: "fail-closed policy is disabled".to_string(),
            });
        }
        Ok(())
    }

    fn start_agent(&self, _handle: &SandboxHandle, launch: &LaunchSpec) -> Result<Child, RunError> {
        if cfg!(target_os = "linux") && platform::detect_wsl().is_wsl() {
            let mut command = Command::new(&launch.executable);
            command.current_dir(&launch.cwd);
            command.args(&launch.args);
            command.envs(&launch.env);
            return command.spawn().map_err(|error| {
                RunError::Spawn(format!(
                    "failed to spawn command through WSL2 backend on WSL host: {error}"
                ))
            });
        }

        if !cfg!(target_os = "windows") {
            return Err(RunError::UnsupportedBackend {
                backend: BackendKind::Wsl2.to_string(),
                reason: "cannot start WSL2 backend agent on non-Windows/non-WSL host".to_string(),
            });
        }

        let env_exports = launch
            .env
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>();
        let wsl_cwd = windows_path_to_wsl(&launch.cwd)?;

        let mut command = Command::new("wsl.exe");
        command.arg("--cd").arg(wsl_cwd).arg("--exec").arg("env");
        command.args(env_exports);
        command.arg(&launch.executable);
        command.args(&launch.args);

        command.spawn().map_err(|error| {
            RunError::Spawn(format!(
                "failed to spawn command through WSL2 backend: {error}"
            ))
        })
    }

    fn teardown(&self, handle: SandboxHandle) -> Result<(), RunError> {
        remove_runtime_dir(&handle.runtime_dir);
        Ok(())
    }
}

fn command_available(binary: &str) -> bool {
    // `wsl.exe --help` returns non-zero on several Windows versions and
    // writes its usage banner to stderr, which previously leaked into
    // firma run's output and was also misread as "not installed".
    // `--status` returns 0 when WSL is installed and configured, which
    // is the actual availability question we need to answer. Silence
    // stdio so no banner reaches the user.
    Command::new(binary)
        .arg("--status")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn remove_runtime_dir(runtime_dir: &std::path::Path) {
    if runtime_dir.exists() {
        let _ = std::fs::remove_dir_all(runtime_dir);
    }
}

fn windows_path_to_wsl(path: &std::path::Path) -> Result<String, RunError> {
    let path_text = path.to_string_lossy().to_string();
    let output = Command::new("wsl.exe")
        .arg("--exec")
        .arg("wslpath")
        .arg("-a")
        .arg(&path_text)
        .output()
        .map_err(|error| RunError::Backend {
            backend: BackendKind::Wsl2.to_string(),
            reason: format!("failed to execute wslpath for cwd conversion: {error}"),
        })?;

    if !output.status.success() {
        return Err(RunError::Backend {
            backend: BackendKind::Wsl2.to_string(),
            reason: format!(
                "wslpath failed for '{}' with status {}",
                path.display(),
                output.status
            ),
        });
    }

    let converted = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if converted.is_empty() {
        return Err(RunError::Backend {
            backend: BackendKind::Wsl2.to_string(),
            reason: format!("wslpath returned empty cwd for '{}'", path.display()),
        });
    }

    Ok(converted)
}

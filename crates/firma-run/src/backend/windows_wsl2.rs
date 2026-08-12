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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wsl2HostMode {
    Windows,
    WslLinux,
    Unsupported,
}

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
        if request.profile.id == "vscode" {
            return Err(RunError::UnsupportedProfileBackend {
                profile: request.profile.id.clone(),
                backend: BackendKind::Wsl2.to_string(),
                reason: "the managed VS Code launcher runs on the Windows host rather than inside WSL; VS Code is not currently supported by the WSL2 backend"
                    .to_string(),
            });
        }

        if current_host_mode() == Wsl2HostMode::Unsupported {
            return Err(RunError::UnsupportedBackend {
                backend: BackendKind::Wsl2.to_string(),
                reason: "WSL2 backend is only available on Windows hosts or inside WSL Linux environments".to_string(),
            });
        }

        if current_host_mode() == Wsl2HostMode::Windows && !command_available("wsl.exe") {
            return Err(RunError::Backend {
                backend: BackendKind::Wsl2.to_string(),
                reason: "wsl.exe is not installed or not executable".to_string(),
            });
        }

        let runtime_dir = std::env::temp_dir()
            .join("firma-run")
            .join(request.identity.sandbox_id.to_string());
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
        // Loopback egress guard note: the seccomp connect-notify guard
        // (`crate::egress_guard`) is not wired for WSL2. Its host-side
        // supervisor is Linux-only and the WSL2 launch crosses the
        // Windows→guest boundary, so the guard would have to run inside the
        // guest with its own supervisor — a separate effort. WSL2 stays
        // proxy-only for now; loopback is not blocked here. The guard env
        // (`FIRMA_RUN_EGRESS_GUARD_SOCK`) is only set on the bwrap structural
        // path, so this backend is never silently half-wired.
        Ok(EnforcementProof {
            backend: BackendKind::Wsl2,
            structural: false,
            fail_closed: policy.fail_closed,
            detail: "WSL2 backend active; command executes in default WSL distro with proxy-based mediation".to_string(),
            network_confinement: crate::backend::NetworkConfinement::ProxyOnly,
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
        match current_host_mode() {
            Wsl2HostMode::WslLinux => {
                let mut command = build_wsl_linux_command(launch);
                command.spawn().map_err(|error| {
                    RunError::Spawn(format!(
                        "failed to spawn command through WSL2 backend on WSL host: {error}"
                    ))
                })
            }
            Wsl2HostMode::Unsupported => Err(RunError::UnsupportedBackend {
                backend: BackendKind::Wsl2.to_string(),
                reason: "cannot start WSL2 backend agent on non-Windows/non-WSL host".to_string(),
            }),
            Wsl2HostMode::Windows => {
                let wsl_cwd = windows_path_to_wsl(&launch.cwd)?;
                let mut command = build_windows_wsl_command(launch, wsl_cwd);

                command.spawn().map_err(|error| {
                    RunError::Spawn(format!(
                        "failed to spawn command through WSL2 backend: {error}"
                    ))
                })
            }
        }
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

fn current_host_mode() -> Wsl2HostMode {
    current_host_mode_from(
        cfg!(target_os = "windows"),
        cfg!(target_os = "linux"),
        platform::detect_wsl(),
    )
}

fn current_host_mode_from(
    is_windows_target: bool,
    is_linux_target: bool,
    wsl_kind: platform::WslKind,
) -> Wsl2HostMode {
    if is_windows_target {
        return Wsl2HostMode::Windows;
    }
    if is_linux_target && wsl_kind.is_wsl() {
        return Wsl2HostMode::WslLinux;
    }
    Wsl2HostMode::Unsupported
}

fn build_wsl_linux_command(launch: &LaunchSpec) -> Command {
    let mut command = Command::new(&launch.executable);
    command.current_dir(&launch.cwd);
    command.args(&launch.args);
    command.envs(&launch.env);
    command
}

fn build_windows_wsl_command(launch: &LaunchSpec, wsl_cwd: String) -> Command {
    let env_exports = launch
        .env
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    let mut command = Command::new("wsl.exe");
    command.arg("--cd").arg(wsl_cwd).arg("--exec").arg("env");
    command.args(env_exports);
    command.arg(&launch.executable);
    command.args(&launch.args);
    command
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn sample_launch() -> LaunchSpec {
        let mut env = BTreeMap::new();
        env.insert("FIRMA_TEST".to_string(), "1".to_string());
        LaunchSpec {
            executable: "/bin/echo".to_string(),
            args: vec!["hello".to_string(), "world".to_string()],
            cwd: std::path::PathBuf::from("/tmp"),
            env,
            sidecar_endpoint: crate::config::SidecarEndpoint::Tcp {
                addr: "127.0.0.1:18080".parse().expect("test sidecar addr"),
            },
            seccomp_filter_path: None,
            identity_mode: crate::config::SandboxIdentityMode::SandboxUser,
            config_file: None,
        }
    }

    #[test]
    fn host_mode_windows_takes_priority() {
        let mode = current_host_mode_from(true, true, platform::WslKind::Wsl2);
        assert_eq!(mode, Wsl2HostMode::Windows);
    }

    #[test]
    fn host_mode_wsl_linux_detected() {
        let mode = current_host_mode_from(false, true, platform::WslKind::Wsl2);
        assert_eq!(mode, Wsl2HostMode::WslLinux);
    }

    #[test]
    fn host_mode_non_wsl_linux_is_unsupported() {
        let mode = current_host_mode_from(false, true, platform::WslKind::NotWsl);
        assert_eq!(mode, Wsl2HostMode::Unsupported);
    }

    #[test]
    fn build_wsl_linux_command_keeps_exec_args_cwd() {
        let launch = sample_launch();
        let cmd = build_wsl_linux_command(&launch);
        assert_eq!(cmd.get_program().to_string_lossy(), "/bin/echo");
        let args = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(args, vec!["hello".to_string(), "world".to_string()]);
        assert_eq!(cmd.get_current_dir(), Some(std::path::Path::new("/tmp")));
    }

    #[test]
    fn windows_wsl_command_keeps_cmd_scripts_inside_wsl_launch_path() {
        let launch = LaunchSpec {
            executable: r"C:\temp\wrapper.cmd".to_string(),
            ..sample_launch()
        };
        let cmd = build_windows_wsl_command(&launch, "/mnt/c/work".to_string());
        assert_eq!(cmd.get_program().to_string_lossy(), "wsl.exe");
        let args = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(args.starts_with(&[
            "--cd".to_string(),
            "/mnt/c/work".to_string(),
            "--exec".to_string(),
            "env".to_string()
        ]));
        assert!(args.iter().any(|arg| arg == "FIRMA_TEST=1"));
        assert!(args.contains(&r"C:\temp\wrapper.cmd".to_string()));
        assert!(args.ends_with(&["hello".to_string(), "world".to_string()]));
    }
}

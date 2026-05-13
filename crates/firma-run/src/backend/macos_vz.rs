use std::fmt::Write as _;
use std::process::{Child, Command};

use crate::backend::{
    BackendKind, EnforcementProof, LaunchSpec, PrepareRequest, SandboxBackend, SandboxHandle,
};
use crate::config::MountSpec;
use crate::config::NetworkPolicy;
use crate::error::RunError;

/// macOS runtime backend.
#[derive(Debug, Default)]
pub struct VzBackend;

impl VzBackend {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SandboxBackend for VzBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Vz
    }

    fn prepare(&self, request: &PrepareRequest) -> Result<SandboxHandle, RunError> {
        if !cfg!(target_os = "macos") {
            return Err(RunError::UnsupportedBackend {
                backend: BackendKind::Vz.to_string(),
                reason: "VZ backend is only available on macOS hosts".to_string(),
            });
        }

        if !command_available("sandbox-exec") {
            return Err(RunError::Backend {
                backend: BackendKind::Vz.to_string(),
                reason: "sandbox-exec is not installed or not executable".to_string(),
            });
        }

        let runtime_dir = std::env::temp_dir()
            .join("firma-run")
            .join(&request.identity.sandbox_id);
        std::fs::create_dir_all(&runtime_dir).map_err(|error| RunError::Backend {
            backend: BackendKind::Vz.to_string(),
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
            backend: BackendKind::Vz,
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
            backend: BackendKind::Vz,
            structural: false,
            fail_closed: policy.fail_closed,
            detail: "macOS backend active; outbound mediation is currently proxy-based".to_string(),
        })
    }

    fn verify_fail_closed(
        &self,
        _handle: &SandboxHandle,
        proof: &EnforcementProof,
    ) -> Result<(), RunError> {
        if !proof.fail_closed {
            return Err(RunError::Backend {
                backend: BackendKind::Vz.to_string(),
                reason: "fail-closed policy is disabled".to_string(),
            });
        }
        Ok(())
    }

    fn start_agent(&self, _handle: &SandboxHandle, launch: &LaunchSpec) -> Result<Child, RunError> {
        if !cfg!(target_os = "macos") {
            return Err(RunError::UnsupportedBackend {
                backend: BackendKind::Vz.to_string(),
                reason: "cannot start VZ backend agent on non-macOS host".to_string(),
            });
        }

        let mut command = Command::new("sandbox-exec");
        let claude_profile = launch
            .env
            .get("FIRMA_RUN_PROFILE")
            .is_some_and(|profile| profile == "claude-code");
        let profile = if claude_profile {
            build_claude_code_sandbox_profile(launch)
        } else {
            "(version 1) (allow default)".to_string()
        };

        command.arg("-p").arg(profile);
        command.arg(&launch.executable).args(&launch.args);
        command.current_dir(&launch.cwd);

        command.envs(&launch.env);

        if claude_profile {
            let runtime_home = std::env::temp_dir()
                .join("firma-run")
                .join(
                    launch
                        .env
                        .get("FIRMA_RUN_SANDBOX_ID")
                        .cloned()
                        .unwrap_or_else(|| "claude-code".to_string()),
                )
                .display()
                .to_string();
            command.env("HOME", &runtime_home);
            command.env("XDG_CONFIG_HOME", &runtime_home);
            command.env("XDG_CACHE_HOME", &runtime_home);
        }

        command.spawn().map_err(|error| {
            RunError::Spawn(format!(
                "failed to spawn command through VZ backend: {error}"
            ))
        })
    }

    fn teardown(&self, handle: SandboxHandle) -> Result<(), RunError> {
        remove_runtime_dir(&handle.runtime_dir);
        Ok(())
    }
}

fn build_claude_code_sandbox_profile(launch: &LaunchSpec) -> String {
    let home = launch
        .env
        .get("HOME")
        .cloned()
        .or_else(|| std::env::var("HOME").ok())
        .unwrap_or_default();

    let mut profile = String::from("(version 1)\n(allow default)\n");
    if !home.is_empty() && home.starts_with('/') {
        for suffix in crate::backend::DEFAULT_SENSITIVE_HOME_SUFFIXES {
            let path = format!("{home}/{suffix}");
            let escaped = escape_sandbox_path(&path);
            let _ = write!(
                profile,
                "(deny file-read* (subpath \"{escaped}\"))\n(deny file-write* (subpath \"{escaped}\"))\n"
            );
        }
    }
    profile
}

fn escape_sandbox_path(path: &str) -> String {
    path.replace('\\', "\\\\").replace('"', "\\\"")
}

fn command_available(binary: &str) -> bool {
    // `sandbox-exec` with no args writes its usage banner to stderr and
    // exits non-zero. Probe by spawning with stdio silenced; `status()`
    // returns `Ok` whenever the binary could be launched, which is all we
    // need to assert availability.
    Command::new(binary)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

fn remove_runtime_dir(runtime_dir: &std::path::Path) {
    if runtime_dir.exists() {
        let _ = std::fs::remove_dir_all(runtime_dir);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use crate::backend::LaunchSpec;
    use crate::config::SandboxIdentityMode;

    #[test]
    fn claude_profile_denies_sensitive_home_paths() {
        let mut env = BTreeMap::new();
        env.insert("HOME".to_string(), "/Users/tester".to_string());
        env.insert("FIRMA_RUN_PROFILE".to_string(), "claude-code".to_string());
        let launch = LaunchSpec {
            executable: "/usr/bin/true".to_string(),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            env,
            identity_mode: SandboxIdentityMode::SandboxUser,
        };
        let profile = super::build_claude_code_sandbox_profile(&launch);
        assert!(profile.contains("deny file-read* (subpath \"/Users/tester/.ssh\")"));
        assert!(profile.contains("deny file-write* (subpath \"/Users/tester/.config\")"));
    }
}

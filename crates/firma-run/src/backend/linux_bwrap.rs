use std::path::PathBuf;
use std::process::{Child, Command};

use crate::backend::{
    BackendKind, EnforcementProof, LaunchSpec, PrepareRequest, SandboxBackend, SandboxHandle,
};
use crate::config::MountSpec;
use crate::config::NetworkPolicy;
use crate::config::SandboxIdentityMode;
use crate::error::RunError;

const BWRAP_ENTRYPOINT_SCRIPT: &str = include_str!("../resources/bwrap_entrypoint.sh");

/// Linux bubblewrap backend.
#[derive(Debug, Default)]
pub struct BwrapBackend;

impl BwrapBackend {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SandboxBackend for BwrapBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Bwrap
    }

    fn prepare(&self, request: &PrepareRequest) -> Result<SandboxHandle, RunError> {
        if !cfg!(target_os = "linux") {
            return Err(RunError::UnsupportedBackend {
                backend: BackendKind::Bwrap.to_string(),
                reason: "bwrap backend is only available on Linux hosts".to_string(),
            });
        }

        if !command_available("bwrap") {
            return Err(RunError::Backend {
                backend: BackendKind::Bwrap.to_string(),
                reason: "bubblewrap is not installed or not executable".to_string(),
            });
        }

        let runtime_dir = std::env::temp_dir()
            .join("firma-run")
            .join(&request.identity.sandbox_id);
        std::fs::create_dir_all(&runtime_dir).map_err(|error| RunError::Backend {
            backend: BackendKind::Bwrap.to_string(),
            reason: format!(
                "failed to create runtime dir {}: {error}",
                runtime_dir.display()
            ),
        })?;

        let mut mounts = request.profile.mounts.clone();

        if request.profile.identity_mode == SandboxIdentityMode::SandboxUser {
            let (uid, gid) = host_uid_gid()?;
            let passwd_path = runtime_dir.join("passwd");
            let group_path = runtime_dir.join("group");
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

            let passwd = format!(
                "root:x:0:0:root:/root:/bin/sh\nfirma-user:x:{uid}:{gid}:firma-user:{home}:/bin/sh\n"
            );
            let group = format!("root:x:0:\nfirma-user:x:{gid}:\nnogroup:x:65534:\n");

            std::fs::write(&passwd_path, passwd).map_err(|error| RunError::Backend {
                backend: BackendKind::Bwrap.to_string(),
                reason: format!(
                    "failed to write sandbox passwd file {}: {error}",
                    passwd_path.display()
                ),
            })?;
            std::fs::write(&group_path, group).map_err(|error| RunError::Backend {
                backend: BackendKind::Bwrap.to_string(),
                reason: format!(
                    "failed to write sandbox group file {}: {error}",
                    group_path.display()
                ),
            })?;

            mounts.push(MountSpec {
                source: passwd_path,
                target: PathBuf::from("/etc/passwd"),
                read_only: true,
            });
            mounts.push(MountSpec {
                source: group_path,
                target: PathBuf::from("/etc/group"),
                read_only: true,
            });
        }

        if request.profile.network.enforce_network_namespace {
            let resolv_conf_path = runtime_dir.join("resolv.conf");
            std::fs::write(
                &resolv_conf_path,
                "nameserver 127.0.0.1\noptions ndots:0 timeout:1 attempts:1\n",
            )
            .map_err(|error| RunError::Backend {
                backend: BackendKind::Bwrap.to_string(),
                reason: format!(
                    "failed to write sandbox resolv.conf {}: {error}",
                    resolv_conf_path.display()
                ),
            })?;

            mounts.push(MountSpec {
                source: resolv_conf_path,
                target: PathBuf::from("/etc/resolv.conf"),
                read_only: true,
            });
        }

        Ok(SandboxHandle {
            backend: BackendKind::Bwrap,
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
        let structural = policy.enforce_network_namespace;
        let detail = if structural {
            "network namespace isolation enabled with sandbox-local proxy bridge path".to_string()
        } else {
            "network namespace isolation disabled; cooperative routing mode".to_string()
        };

        Ok(EnforcementProof {
            backend: BackendKind::Bwrap,
            structural,
            fail_closed: policy.fail_closed,
            detail,
        })
    }

    fn verify_fail_closed(
        &self,
        _handle: &SandboxHandle,
        proof: &EnforcementProof,
    ) -> Result<(), RunError> {
        if !proof.fail_closed {
            return Err(RunError::Backend {
                backend: BackendKind::Bwrap.to_string(),
                reason: "fail-closed policy is disabled".to_string(),
            });
        }
        Ok(())
    }

    fn start_agent(&self, handle: &SandboxHandle, launch: &LaunchSpec) -> Result<Child, RunError> {
        if !cfg!(target_os = "linux") {
            return Err(RunError::UnsupportedBackend {
                backend: BackendKind::Bwrap.to_string(),
                reason: "cannot start bwrap agent on non-Linux host".to_string(),
            });
        }

        let mut command = Command::new("bwrap");
        command.arg("--die-with-parent");
        command.arg("--new-session");
        command.arg("--bind").arg("/").arg("/");
        command.arg("--dev").arg("/dev");
        command.arg("--chdir").arg(&launch.cwd);

        if handle.network_policy.enforce_network_namespace {
            command.arg("--unshare-net");
        }

        for mount in &handle.mounts {
            if mount.read_only {
                command
                    .arg("--ro-bind")
                    .arg(&mount.source)
                    .arg(&mount.target);
            } else {
                command.arg("--bind").arg(&mount.source).arg(&mount.target);
            }
        }

        for (key, value) in &launch.env {
            command.arg("--setenv").arg(key).arg(value);
        }

        if launch.identity_mode == SandboxIdentityMode::SandboxUser {
            command.arg("--setenv").arg("USER").arg("firma-user");
            command.arg("--setenv").arg("LOGNAME").arg("firma-user");
        }

        command.arg("--");
        if let Some(entrypoint) = maybe_write_entrypoint_script(handle, launch)? {
            command.arg("/bin/sh");
            command.arg(entrypoint);
            command.arg(&launch.executable);
            command.args(&launch.args);
        } else {
            command.arg(&launch.executable);
            command.args(&launch.args);
        }

        command.spawn().map_err(|error| {
            RunError::Spawn(format!(
                "failed to spawn wrapped command through bwrap: {error}"
            ))
        })
    }

    fn teardown(&self, handle: SandboxHandle) -> Result<(), RunError> {
        remove_runtime_dir(&handle.runtime_dir);
        Ok(())
    }
}

fn command_available(binary: &str) -> bool {
    Command::new(binary)
        .arg("--version")
        .status()
        .is_ok_and(|status| status.success())
}

fn host_uid_gid() -> Result<(u32, u32), RunError> {
    let uid = command_stdout_trimmed("id", &["-u"])?;
    let gid = command_stdout_trimmed("id", &["-g"])?;
    let uid = uid.parse::<u32>().map_err(|error| RunError::Backend {
        backend: BackendKind::Bwrap.to_string(),
        reason: format!("failed to parse host uid '{uid}': {error}"),
    })?;
    let gid = gid.parse::<u32>().map_err(|error| RunError::Backend {
        backend: BackendKind::Bwrap.to_string(),
        reason: format!("failed to parse host gid '{gid}': {error}"),
    })?;
    Ok((uid, gid))
}

fn command_stdout_trimmed(binary: &str, args: &[&str]) -> Result<String, RunError> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .map_err(|error| RunError::Backend {
            backend: BackendKind::Bwrap.to_string(),
            reason: format!("failed to execute {binary} {}: {error}", args.join(" ")),
        })?;
    if !output.status.success() {
        return Err(RunError::Backend {
            backend: BackendKind::Bwrap.to_string(),
            reason: format!(
                "command failed: {binary} {} (status {})",
                args.join(" "),
                output.status
            ),
        });
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_string())
        .map_err(|error| RunError::Backend {
            backend: BackendKind::Bwrap.to_string(),
            reason: format!(
                "command output for {binary} {} is not utf-8: {error}",
                args.join(" ")
            ),
        })
}

fn remove_runtime_dir(runtime_dir: &std::path::Path) {
    if runtime_dir.exists() {
        let _ = std::fs::remove_dir_all(runtime_dir);
    }
}

fn maybe_write_entrypoint_script(
    handle: &SandboxHandle,
    launch: &LaunchSpec,
) -> Result<Option<PathBuf>, RunError> {
    let uses_proxy_bridge = launch
        .env
        .contains_key("FIRMA_RUN_PROXY_BRIDGE_UPSTREAM_UDS");
    if !uses_proxy_bridge {
        return Ok(None);
    }

    let script_path = handle.runtime_dir.join("entrypoint.sh");
    std::fs::write(&script_path, BWRAP_ENTRYPOINT_SCRIPT).map_err(|error| RunError::Backend {
        backend: BackendKind::Bwrap.to_string(),
        reason: format!(
            "failed to write sandbox entrypoint script {}: {error}",
            script_path.display()
        ),
    })?;

    Ok(Some(script_path))
}

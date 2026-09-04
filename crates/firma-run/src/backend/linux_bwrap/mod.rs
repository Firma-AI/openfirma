mod mount;

use std::env;
use std::path::PathBuf;
use std::process::{Child, Command};
#[cfg(target_os = "linux")]
use std::{fs::File, os::fd::AsRawFd};

use firma_identifiers::SandboxId;
#[cfg(target_os = "linux")]
use nix::fcntl::{FcntlArg, FdFlag, fcntl};

use self::mount::{BwrapHardening, BwrapMountPlan};
use crate::backend::platform;
use crate::backend::{
    BackendKind, EnforcementProof, LaunchSpec, PrepareRequest, SandboxBackend, SandboxHandle,
    SandboxInfrastructureKind, SandboxMount, SandboxRuntimeLayout, SecretShimSupport, ShimTarget,
};
use crate::config::{NetworkPolicy, SandboxIdentityMode};
use crate::error::RunError;

const BWRAP_ENTRYPOINT_SCRIPT: &str = include_str!("../../resources/bwrap_entrypoint.sh");

/// Linux bubblewrap backend.
#[derive(Debug, Default)]
pub struct BwrapBackend;

impl BwrapBackend {
    #[must_use]
    pub(crate) fn new() -> Self {
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

        preflight_host_support(platform::detect_wsl(), platform::userns_restricted())?;

        if !command_available("bwrap") {
            return Err(RunError::Backend {
                backend: BackendKind::Bwrap.to_string(),
                reason: "bubblewrap is not installed or not executable".to_string(),
            });
        }

        let runtime_dir = create_bwrap_runtime_dir(&request.identity.sandbox_id)?;

        let mut mounts = request
            .profile
            .mounts
            .iter()
            .cloned()
            .map(SandboxMount::operator_provided)
            .collect::<Vec<_>>();

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

            mounts.push(SandboxMount::sandbox_infrastructure(
                SandboxInfrastructureKind::Passwd,
                passwd_path,
                PathBuf::from("/etc/passwd"),
            ));
            mounts.push(SandboxMount::sandbox_infrastructure(
                SandboxInfrastructureKind::Group,
                group_path,
                PathBuf::from("/etc/group"),
            ));
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

            // On hosts where /etc/resolv.conf is a managed symlink (e.g. WSL,
            // systemd-resolved), mount(2) follows the symlink to its canonical
            // target. We pre-resolve the chain so the bind-mount succeeds even
            // when the symlink target path differs from /etc/resolv.conf. If
            // resolution fails (broken/absent symlink) we fall back to the
            // literal path and let bwrap report any remaining mount error.
            let resolv_conf_target = resolve_resolv_conf_target();

            if resolv_conf_target != std::path::Path::new("/etc/resolv.conf") {
                // Mount at the canonical target so reads through the symlink
                // inside the sandbox see our stub-pointing content.
                mounts.push(SandboxMount::sandbox_infrastructure(
                    SandboxInfrastructureKind::ResolverConfig,
                    resolv_conf_path.clone(),
                    resolv_conf_target,
                ));
            }

            // Always mount at the literal /etc/resolv.conf path so that
            // processes that open the path directly (not via symlink) also
            // get our stub-pointing content.
            mounts.push(SandboxMount::sandbox_infrastructure(
                SandboxInfrastructureKind::ResolverConfig,
                resolv_conf_path,
                PathBuf::from("/etc/resolv.conf"),
            ));
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
            "network namespace isolation enabled with sandbox-local proxy bridge and DNS stub paths"
                .to_string()
        } else {
            "network namespace isolation disabled; cooperative routing mode".to_string()
        };
        let network_confinement = if structural {
            crate::backend::NetworkConfinement::LinuxNetworkNamespace
        } else {
            crate::backend::NetworkConfinement::ProxyOnly
        };

        Ok(EnforcementProof {
            backend: BackendKind::Bwrap,
            structural,
            fail_closed: policy.fail_closed,
            detail,
            network_confinement,
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

    fn start_agent(
        &self,
        runtime_layout: &firma_runtime_state::RuntimeLayout,
        handle: &SandboxHandle,
        launch: &LaunchSpec,
    ) -> Result<Child, RunError> {
        if !cfg!(target_os = "linux") {
            return Err(RunError::UnsupportedBackend {
                backend: BackendKind::Bwrap.to_string(),
                reason: "cannot start bwrap agent on non-Linux host".to_string(),
            });
        }

        mount::reject_symlinked_firma_dirs(launch)?;
        let hardening = BwrapHardening::from_env(&launch.env);
        let mount_plan = BwrapMountPlan::build(runtime_layout, handle, launch, &hardening)?;

        let mut command = Command::new("bwrap");
        command.arg("--die-with-parent");
        command.arg("--new-session");
        if handle.network_policy.enforce_network_namespace {
            command.arg("--unshare-net");
        }

        #[cfg(target_os = "linux")]
        #[expect(
            clippy::collection_is_never_read,
            reason = "keeps the seccomp file descriptor alive until bwrap inherits it"
        )]
        let mut _seccomp_file: Option<File> = None;
        #[cfg(target_os = "linux")]
        let seccomp_path = launch
            .seccomp_filter_path
            .as_ref()
            .map(|path| path.display().to_string());
        #[cfg(target_os = "linux")]
        if let Some(seccomp_path) = seccomp_path {
            let file = File::open(&seccomp_path).map_err(|error| RunError::Backend {
                backend: BackendKind::Bwrap.to_string(),
                reason: format!("failed to open seccomp bpf file {seccomp_path}: {error}"),
            })?;
            clear_fd_cloexec(&file)?;
            command.arg("--seccomp").arg(file.as_raw_fd().to_string());
            _seccomp_file = Some(file);
        }

        mount_plan.emit(&mut command);
        command.arg("--chdir").arg(&launch.cwd);

        for (key, value) in &launch.env {
            command.arg("--setenv").arg(key).arg(value);
        }
        command
            .arg("--setenv")
            .arg("FIRMA_RUN_RUNTIME_DIR")
            .arg(&handle.runtime_dir);

        if hardening.runtime_home_isolation() {
            let runtime_home = handle.runtime_dir.display().to_string();
            // Apply after launch.env so passthrough HOME/XDG values can't override it.
            command.arg("--setenv").arg("HOME").arg(&runtime_home);
            command
                .arg("--setenv")
                .arg("XDG_CONFIG_HOME")
                .arg(&runtime_home);
            command
                .arg("--setenv")
                .arg("XDG_CACHE_HOME")
                .arg(&runtime_home);
        }

        if launch.identity_mode == SandboxIdentityMode::SandboxUser {
            command.arg("--setenv").arg("USER").arg("firma-user");
            command.arg("--setenv").arg("LOGNAME").arg("firma-user");
        }

        command.arg("--");
        if let Some(entrypoint) = maybe_write_entrypoint_script(handle, launch)? {
            command.arg("/bin/sh");
            command.arg(entrypoint);
        }
        command.arg(&launch.executable);
        command.args(&launch.args);

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

    fn secret_shim_support(&self) -> SecretShimSupport {
        SecretShimSupport::HostBindMount {
            guest_target: ShimTarget::host(),
        }
    }
}

/// Resolve `/etc/resolv.conf` to its canonical on-disk path, following all
/// symlinks.
///
/// On hosts where `/etc/resolv.conf` is a managed symlink (e.g. WSL,
/// systemd-resolved), `mount(2)` with `MS_BIND` follows the symlink to the
/// final target. Pre-resolving here lets us provide the explicit target path to
/// bwrap, preventing bind-mount failures when the symlink points into a managed
/// location that bwrap cannot otherwise resolve.
///
/// Falls back to `/etc/resolv.conf` itself when:
/// - the path is not a symlink (nothing to resolve)
/// - `canonicalize` fails (broken symlink, permission error)
fn resolve_resolv_conf_target() -> PathBuf {
    resolve_resolv_conf_target_from(std::path::Path::new("/etc/resolv.conf"))
}

fn resolve_resolv_conf_target_from(resolv_conf: &std::path::Path) -> PathBuf {
    if !resolv_conf.is_symlink() {
        return resolv_conf.to_path_buf();
    }
    std::fs::canonicalize(resolv_conf).unwrap_or_else(|_| resolv_conf.to_path_buf())
}

fn preflight_host_support(
    wsl_kind: platform::WslKind,
    userns_sysctl: Option<String>,
) -> Result<(), RunError> {
    // WSL environments do not support unprivileged user namespaces required
    // by bubblewrap. Detect early and surface a typed, actionable error
    // instead of letting bwrap fail silently after spawning.
    if wsl_kind.is_wsl() {
        return Err(RunError::UnsupportedBackend {
            backend: BackendKind::Bwrap.to_string(),
            reason: "WSL environment detected; bubblewrap requires unprivileged user \
                     namespaces which are unavailable under WSL. \
                     Use a non-bwrap backend on this host or run `firma doctor` for \
                     a full sandbox compatibility report."
                .to_string(),
        });
    }

    // Some kernels (notably Debian/Ubuntu hardened builds) restrict
    // unprivileged user namespace creation via a sysctl. Detect and report
    // before bwrap fails without a useful message.
    if let Some(sysctl) = userns_sysctl {
        return Err(RunError::UnsupportedBackend {
            backend: BackendKind::Bwrap.to_string(),
            reason: format!(
                "user namespace creation is restricted ({sysctl}=0); {}",
                userns_remediation(&sysctl)
            ),
        });
    }

    Ok(())
}

fn userns_remediation(sysctl: &str) -> &'static str {
    if sysctl.ends_with("/kernel/unprivileged_userns_clone") {
        "enable it with: sudo sysctl -w kernel.unprivileged_userns_clone=1, or contact your system administrator"
    } else if sysctl.ends_with("/user/max_user_namespaces") {
        "raise it with: sudo sysctl -w user.max_user_namespaces=15000, or contact your system administrator"
    } else {
        "adjust this sysctl or contact your system administrator"
    }
}

#[cfg(target_os = "linux")]
fn clear_fd_cloexec(file: &File) -> Result<(), RunError> {
    let fd = file.as_raw_fd();
    let flags = fcntl(file, FcntlArg::F_GETFD).map_err(|error| RunError::Backend {
        backend: BackendKind::Bwrap.to_string(),
        reason: format!("failed to read fd flags for seccomp descriptor {fd}: {error}"),
    })?;
    let mut fd_flags = FdFlag::from_bits_truncate(flags);
    fd_flags.remove(FdFlag::FD_CLOEXEC);
    fcntl(file, FcntlArg::F_SETFD(fd_flags)).map_err(|error| RunError::Backend {
        backend: BackendKind::Bwrap.to_string(),
        reason: format!("failed to clear CLOEXEC on seccomp descriptor {fd}: {error}"),
    })?;
    Ok(())
}

fn command_available(binary: &str) -> bool {
    Command::new(binary)
        .arg("--version")
        .status()
        .is_ok_and(|status| status.success())
}

fn create_bwrap_runtime_dir(sandbox_id: &SandboxId) -> Result<PathBuf, RunError> {
    let temp_dir = env::temp_dir();
    let runtime_root = temp_dir.join("firma-run");
    firma_fs::create_private_dir_all(&runtime_root).map_err(|error| RunError::Backend {
        backend: BackendKind::Bwrap.to_string(),
        reason: format!(
            "failed to create runtime root {}: {error}",
            runtime_root.display()
        ),
    })?;
    let runtime_dir = SandboxRuntimeLayout::in_temp_dir(&temp_dir, sandbox_id).into_root();
    firma_fs::create_private_dir_all(&runtime_dir).map_err(|error| RunError::Backend {
        backend: BackendKind::Bwrap.to_string(),
        reason: format!(
            "failed to create runtime dir {}: {error}",
            runtime_dir.display()
        ),
    })?;
    Ok(runtime_dir)
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

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(target_os = "linux")]
    fn create_bwrap_runtime_dir_creates_private_sandbox_dir() {
        use std::os::unix::fs::PermissionsExt as _;

        let sandbox_id = super::SandboxId::generate();
        let runtime_dir =
            super::create_bwrap_runtime_dir(&sandbox_id).expect("create bwrap runtime dir");
        assert!(runtime_dir.is_dir(), "runtime dir should exist");
        assert_eq!(
            runtime_dir.file_name(),
            Some(std::ffi::OsStr::new(&sandbox_id.to_string()))
        );
        let mode = std::fs::metadata(&runtime_dir)
            .expect("runtime dir metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "runtime dir should not be group/world accessible"
        );

        std::fs::remove_dir_all(&runtime_dir).expect("cleanup runtime dir");
    }

    // ── resolv.conf target resolution ────────────────────────────────────────

    #[test]
    #[cfg(target_os = "linux")]
    fn resolv_conf_target_is_itself_when_not_a_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let resolv_conf = dir.path().join("resolv.conf");
        std::fs::write(&resolv_conf, "nameserver 1.1.1.1\n").expect("write resolv.conf");

        let resolved = super::resolve_resolv_conf_target_from(&resolv_conf);
        assert_eq!(resolved, resolv_conf);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn resolv_conf_target_follows_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real_file = dir.path().join("real_resolv.conf");
        std::fs::write(&real_file, "nameserver 1.1.1.1\n").expect("write real file");

        let symlink_path = dir.path().join("resolv.conf");
        std::os::unix::fs::symlink(&real_file, &symlink_path).expect("create symlink");

        let resolved = super::resolve_resolv_conf_target_from(&symlink_path);
        assert_eq!(resolved, real_file.canonicalize().expect("canon real"));
    }

    #[test]
    fn preflight_rejects_wsl() {
        let result = super::preflight_host_support(crate::backend::platform::WslKind::Wsl2, None);
        let err = result.expect_err("WSL must be rejected for bwrap");
        let message = err.to_string();
        assert!(message.contains("bwrap"));
        assert!(message.to_ascii_lowercase().contains("wsl"));
    }

    #[test]
    fn preflight_rejects_restricted_userns_with_specific_fix() {
        let result = super::preflight_host_support(
            crate::backend::platform::WslKind::NotWsl,
            Some("/proc/sys/user/max_user_namespaces".to_string()),
        );
        let err = result.expect_err("restricted userns must be rejected");
        let message = err.to_string();
        assert!(message.contains("user namespace creation is restricted"));
        assert!(message.contains("user.max_user_namespaces"));
    }

    #[test]
    fn preflight_accepts_native_host_with_userns_available() {
        let result = super::preflight_host_support(crate::backend::platform::WslKind::NotWsl, None);
        assert!(result.is_ok());
    }
}

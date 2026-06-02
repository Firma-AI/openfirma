use std::path::PathBuf;
use std::process::{Child, Command};
#[cfg(target_os = "linux")]
use std::{fs::File, os::fd::AsRawFd};

#[cfg(target_os = "linux")]
use nix::fcntl::{FcntlArg, FdFlag, fcntl};

use crate::backend::platform;
use crate::backend::{
    BackendKind, EnforcementProof, LaunchSpec, PrepareRequest, SandboxBackend, SandboxHandle,
};
use crate::config::MountSpec;
use crate::config::NetworkPolicy;
use crate::config::SandboxIdentityMode;
use crate::error::RunError;

const BWRAP_ENTRYPOINT_SCRIPT: &str = include_str!("../resources/bwrap_entrypoint.sh");
const BWRAP_ROOTFS_MODE_ENV: &str = "FIRMA_RUN_BWRAP_ROOTFS_MODE";
const BWRAP_RUNTIME_HOME_ENV: &str = "FIRMA_RUN_BWRAP_RUNTIME_HOME";
const BWRAP_MASK_HOME_PATHS_ENV: &str = "FIRMA_RUN_BWRAP_MASK_HOME_PATHS";
const BWRAP_ROOTFS_MODE_READONLY: &str = "readonly";

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

    #[allow(
        clippy::too_many_lines,
        reason = "sequential preflight checks + mount assembly read more clearly inline"
    )]
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
                mounts.push(MountSpec {
                    source: resolv_conf_path.clone(),
                    target: resolv_conf_target,
                    read_only: true,
                });
            }

            // Always mount at the literal /etc/resolv.conf path so that
            // processes that open the path directly (not via symlink) also
            // get our stub-pointing content.
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
            "network namespace isolation enabled with sandbox-local proxy bridge and DNS stub paths"
                .to_string()
        } else {
            "network namespace isolation disabled; cooperative routing mode".to_string()
        };
        let confinement_mechanism = if structural {
            crate::backend::ConfinementMechanism::LinuxNetworkNamespace
        } else {
            crate::backend::ConfinementMechanism::ProxyOnly
        };

        Ok(EnforcementProof {
            backend: BackendKind::Bwrap,
            structural,
            fail_closed: policy.fail_closed,
            detail,
            confinement_mechanism,
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
        let hardening = bwrap_hardening_from_env(&launch.env);
        if hardening.readonly_rootfs {
            command.arg("--ro-bind").arg("/").arg("/");
            command.arg("--tmpfs").arg("/tmp");
            command.arg("--tmpfs").arg("/var/tmp");
            command.arg("--bind").arg(&launch.cwd).arg(&launch.cwd);
            command
                .arg("--bind")
                .arg(&handle.runtime_dir)
                .arg(&handle.runtime_dir);
            if !hardening.runtime_home_isolation {
                bind_host_home(&mut command, launch);
            }
            mask_sensitive_paths(&mut command, launch, &hardening.mask_home_paths);
        } else {
            command.arg("--bind").arg("/").arg("/");
        }
        command.arg("--dev").arg("/dev");
        command.arg("--chdir").arg(&launch.cwd);

        if handle.network_policy.enforce_network_namespace {
            command.arg("--unshare-net");
        }

        #[cfg(target_os = "linux")]
        #[allow(clippy::collection_is_never_read)]
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
        command
            .arg("--setenv")
            .arg("FIRMA_RUN_RUNTIME_DIR")
            .arg(&handle.runtime_dir);

        if hardening.runtime_home_isolation {
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct BwrapHardening {
    readonly_rootfs: bool,
    runtime_home_isolation: bool,
    mask_home_paths: Vec<String>,
}

fn bwrap_hardening_from_env(env: &std::collections::BTreeMap<String, String>) -> BwrapHardening {
    let readonly_rootfs = env
        .get(BWRAP_ROOTFS_MODE_ENV)
        .is_some_and(|mode| mode == BWRAP_ROOTFS_MODE_READONLY);
    let runtime_home_isolation = env
        .get(BWRAP_RUNTIME_HOME_ENV)
        .is_some_and(|value| parse_truthy(value));
    let mask_home_paths = env
        .get(BWRAP_MASK_HOME_PATHS_ENV)
        .map_or_else(Vec::new, |raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        });
    BwrapHardening {
        readonly_rootfs,
        runtime_home_isolation,
        mask_home_paths,
    }
}

fn parse_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Rebind real `$HOME` writable when `runtime_home_isolation` is off.
/// Without this, `--ro-bind /` makes `$HOME` read-only and the agent hits
/// EROFS writing config/session state. `mask_home_paths` tmpfs overlays
/// applied afterward still take precedence over this bind.
fn bind_host_home(command: &mut Command, launch: &LaunchSpec) {
    let home = launch
        .env
        .get("HOME")
        .cloned()
        .or_else(|| std::env::var("HOME").ok())
        .unwrap_or_default();
    if !home.is_empty() && home.starts_with('/') {
        command.arg("--bind").arg(&home).arg(&home);
    }
}

fn mask_sensitive_paths(command: &mut Command, launch: &LaunchSpec, suffixes: &[String]) {
    let home = launch
        .env
        .get("HOME")
        .cloned()
        .or_else(|| std::env::var("HOME").ok())
        .unwrap_or_default();
    if home.is_empty() || !home.starts_with('/') {
        return;
    }

    for suffix in suffixes {
        let path = format!("{home}/{suffix}");
        if std::path::Path::new(&path).exists() {
            command.arg("--tmpfs").arg(&path);
        }
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    #[test]
    fn hardening_from_env_is_profile_driven() {
        let mut env = BTreeMap::new();
        env.insert(
            super::BWRAP_ROOTFS_MODE_ENV.to_string(),
            super::BWRAP_ROOTFS_MODE_READONLY.to_string(),
        );
        env.insert(
            super::BWRAP_RUNTIME_HOME_ENV.to_string(),
            "true".to_string(),
        );
        env.insert(
            super::BWRAP_MASK_HOME_PATHS_ENV.to_string(),
            ".ssh,.aws,.config/gcloud".to_string(),
        );
        let hardening = super::bwrap_hardening_from_env(&env);
        assert!(hardening.readonly_rootfs);
        assert!(hardening.runtime_home_isolation);
        assert_eq!(
            hardening.mask_home_paths,
            vec![
                ".ssh".to_string(),
                ".aws".to_string(),
                ".config/gcloud".to_string()
            ]
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_sensitive_paths_adds_expected_mounts() {
        let mut cmd = std::process::Command::new("bwrap");
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        std::fs::create_dir_all(home.join(".ssh")).expect("mkdir .ssh");
        std::fs::create_dir_all(home.join(".aws")).expect("mkdir .aws");
        std::fs::create_dir_all(home.join(".config").join("gcloud")).expect("mkdir .config/gcloud");

        let mut env = BTreeMap::new();
        env.insert("HOME".to_string(), home.display().to_string());
        let launch = crate::backend::LaunchSpec {
            executable: "/bin/true".to_string(),
            args: vec![],
            cwd: std::path::PathBuf::from("/tmp"),
            env,
            seccomp_filter_path: None,
            identity_mode: crate::config::SandboxIdentityMode::SandboxUser,
        };
        let suffixes = vec![
            ".ssh".to_string(),
            ".aws".to_string(),
            ".config/gcloud".to_string(),
        ];
        super::mask_sensitive_paths(&mut cmd, &launch, &suffixes);
        let rendered = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" ");

        assert!(rendered.contains(&format!("--tmpfs {}/.ssh", home.display())));
        assert!(rendered.contains(&format!("--tmpfs {}/.aws", home.display())));
        assert!(rendered.contains(&format!("--tmpfs {}/.config/gcloud", home.display())));
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

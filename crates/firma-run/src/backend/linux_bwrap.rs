use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
#[cfg(target_os = "linux")]
use std::{fs::File, os::fd::AsRawFd};

use firma_config_loader::{CONFIG_DIR_NAME, CONFIG_FILE_NAME};
use firma_identifiers::SandboxId;
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

    fn start_agent(&self, handle: &SandboxHandle, launch: &LaunchSpec) -> Result<Child, RunError> {
        if !cfg!(target_os = "linux") {
            return Err(RunError::UnsupportedBackend {
                backend: BackendKind::Bwrap.to_string(),
                reason: "cannot start bwrap agent on non-Linux host".to_string(),
            });
        }

        reject_symlinked_firma_dirs(launch)?;

        let mut command = Command::new("bwrap");
        command.arg("--die-with-parent");
        command.arg("--new-session");
        let hardening = bwrap_hardening_from_env(&launch.env);

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

        append_filesystem_layout(&mut command, handle, launch, &hardening);

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

/// Append the sandbox filesystem layout: root binds, workspace/runtime binds,
/// home handling, the `.firma/` config mask, and explicit profile/runtime
/// mounts.
///
/// Mount order is load-bearing and enforced here. bwrap is last-write-wins, so
/// the `.firma/` config mask must beat any profile mount that would re-expose
/// `firma.toml`, while still letting an intentional mount of a subpath *inside*
/// a masked `.firma/` (e.g. the `vscode` profile's `.firma/vscode/` state) poke
/// through. To satisfy both, profile mounts are partitioned by whether their
/// target lands inside a masked `.firma/`, and emitted around the mask:
///
/// 1. workspace cwd bind;
/// 2. profile mounts that are **not** a strict `.firma/` subpath re-expose (see
///    [`MountSpec::reexposes_firma_subpath`]) — this includes a broad workspace
///    bind of a *parent* of `.firma/` (e.g. the repo root) *and* a mount whose
///    target *is* a `.firma/`, neither of which may re-leak or replace the mask;
/// 3. the `.firma/` mask ([`mask_firma_dir`]), which now wins over the binds
///    above and is also projected through them so an aliased bind can't re-expose
///    the config elsewhere;
/// 4. profile mounts whose target is **strictly inside** a masked `.firma/`,
///    re-exposed on top of the mask via last-write-wins.
///
/// Reordering would either bury the vscode-style subpath mounts or re-leak
/// `firma.toml` under a workspace-parent bind.
fn append_filesystem_layout(
    command: &mut Command,
    handle: &SandboxHandle,
    launch: &LaunchSpec,
    hardening: &BwrapHardening,
) {
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
            bind_host_home(command, launch);
        }
        mask_sensitive_paths(command, launch, &hardening.mask_home_paths);
    } else {
        command.arg("--bind").arg("/").arg("/");
    }
    command.arg("--dev").arg("/dev");
    command.arg("--chdir").arg(&launch.cwd);

    if handle.network_policy.enforce_network_namespace {
        command.arg("--unshare-net");
    }

    // Partition profile mounts around the mask. A strict `.firma/` subpath
    // re-expose (e.g. the vscode state) is emitted *after* the mask; everything
    // else — a workspace-parent bind and a mount whose target *is* `.firma` —
    // is emitted *before*, so neither can re-leak nor replace the mask.
    let (inside, outside): (Vec<&MountSpec>, Vec<&MountSpec>) = handle
        .mounts
        .iter()
        .partition(|mount| mount.reexposes_firma_subpath());

    emit_mounts(command, outside.iter().copied());

    // Mask the discoverable `.firma/`, then project each mask through the outside
    // binds above so an alias mount of a `.firma`-containing tree (e.g. the
    // workspace rebound elsewhere) can't re-expose the config at the aliased path.
    let masked = mask_firma_dir(command, launch);
    project_mount_aliases(command, &outside, masked);

    emit_mounts(command, inside.iter().copied());
}

/// Emit each profile/runtime bind mount (`--ro-bind` or `--bind`) in order.
fn emit_mounts<'a>(command: &mut Command, mounts: impl Iterator<Item = &'a MountSpec>) {
    for mount in mounts {
        if mount.read_only {
            command
                .arg("--ro-bind")
                .arg(&mount.source)
                .arg(&mount.target);
        } else {
            command.arg("--bind").arg(&mount.source).arg(&mount.target);
        }
    }
}

/// tmpfs-mask every `.firma/` the agent could discover, so a compromised or
/// prompt-injected agent can't read Authority topology / `agent_id` or poison
/// enforcement config for a later `firma run`.
///
/// The sandbox binds host root, so every `.firma/` is in principle readable.
/// Rather than scan the filesystem, we mask the discovery-relevant set:
///
/// - every `.firma/` on the cwd walk-up path, via the shared
///   [`firma_config_loader::FirmaConfigCandidateAncestors`] iterator, so the mask stays
///   in lockstep with what a later run could select. The cwd candidate is masked
///   even when absent, since the cwd is bound read-write and an agent could
///   otherwise plant a higher-precedence `.firma/` there for a later run;
/// - `$HOME/.firma`, discoverable from `$HOME` and writable (home is rebound
///   read-write), so an agent can't plant a poisoned config there;
/// - the explicitly resolved `config_file`, which may sit outside the cwd
///   ancestry when set via `--config` / `FIRMA_CONFIG`.
///
/// Not covered: an agent planting a `.firma/` in a *descendant* subfolder (below
/// the run cwd, off the walk-up path) that the user later `cd`s into — a
/// discovery-time trust problem tracked separately.
///
/// Each path is `canonicalize`d before mounting to resolve any post-discovery
/// symlink swap. A residual race remains (bwrap re-resolves the destination
/// string at mount time, taking a path not an fd), not closable via bwrap's
/// API. When a `.firma/` path is itself a symlink to a differently-named
/// directory we do not tmpfs the unrelated target tree; instead we `/dev/null`
/// the `firma.toml` it exposes at the target's canonical path. Likewise, a
/// selected `firma.toml` that is a symlink has its canonical target masked, so
/// the config can't be read or written through the link's real path.
///
/// Fail closed: a `.firma/` that exists but won't canonicalize (permission,
/// `ELOOP`, race) is masked at its literal path; only `NotFound` is a no-op.
///
/// Masks are emitted after the workspace cwd bind and after profile/runtime
/// mounts that land *outside* a `.firma/`, but before mounts that land *inside*
/// one (see [`append_filesystem_layout`] and [`MountSpec::reexposes_firma_subpath`]), so
/// an intentional subpath mount can re-expose requested paths while the config
/// stays hidden even under a workspace-parent bind. A relative `config_file` is
/// resolved against the host cwd first, since bwrap destinations must be
/// absolute.
///
/// Returns the emitted mask set so the caller can project it through outside
/// binds (see [`project_mount_aliases`]).
fn mask_firma_dir(command: &mut Command, launch: &LaunchSpec) -> BTreeMap<PathBuf, MaskKind> {
    let mut masked: BTreeMap<PathBuf, MaskKind> = BTreeMap::new();

    for candidate in firma_config_loader::FirmaConfigCandidateAncestors::new(&launch.cwd, None) {
        mask_firma_dir_at(command, &candidate.config_dir, &mut masked);
    }

    // The cwd is bound read-write, so the agent can *plant* a higher-precedence
    // `.firma/` here for a later run even when none exists today. Mask the cwd
    // candidate whether or not it currently exists; writes then land in the
    // ephemeral tmpfs instead of the host bind. Ancestors above the cwd sit on
    // the read-only root bind and are not plantable, so absent ones are skipped
    // (and tmpfs-ing them there could fail `EROFS`).
    let cwd_firma = launch.cwd.join(CONFIG_DIR_NAME);
    if !cwd_firma.exists() {
        emit_tmpfs(command, cwd_firma, &mut masked);
    }

    if let Some(home_firma) = host_home_firma_dir(launch) {
        mask_firma_dir_at(command, &home_firma, &mut masked);
    }

    if let Some(config_file) = &launch.config_file {
        let config_file = if config_file.is_absolute() {
            config_file.clone()
        } else {
            launch.cwd.join(config_file)
        };

        let firma_parent = config_file.parent().filter(|parent| {
            parent.file_name().and_then(|name| name.to_str()) == Some(CONFIG_DIR_NAME)
        });
        if let Some(firma_parent) = firma_parent {
            mask_firma_dir_at(command, firma_parent, &mut masked);
        } else {
            // Bare config file whose parent is not `.firma`: hide only the file
            // (reads empty, writes fail `EROFS`) without tmpfs-ing the parent,
            // which could be the workspace root.
            mask_config_file_at(command, &config_file, &mut masked);
        }
    }

    masked
}

/// Re-apply each mask at the aliased path it acquires under an outside bind.
///
/// A profile mount that binds a `.firma`-containing tree at another target (e.g.
/// the workspace rebound elsewhere) re-exposes every masked path at
/// `target/<relative-path>`. Since these binds are emitted before the mask, the
/// aliases emitted here win via last-write-wins.
///
/// Alias paths are sandbox destinations, not host paths, so they are used
/// literally (no `canonicalize`). A mount whose source *is* a masked path (empty
/// relative) aliases it wholesale at `target`; a mount whose source *contains* a
/// masked path aliases it at `target/<relative-path>`. Only the directly-masked
/// paths are projected; aliases are not themselves re-projected through other
/// mounts.
fn project_mount_aliases(
    command: &mut Command,
    mounts: &[&MountSpec],
    mut masked: BTreeMap<PathBuf, MaskKind>,
) {
    let direct: Vec<(PathBuf, MaskKind)> = masked
        .iter()
        .map(|(path, kind)| (path.clone(), *kind))
        .collect();
    for mount in mounts {
        let Ok(source) = mount.source.canonicalize() else {
            continue;
        };
        for (path, kind) in &direct {
            let Ok(relative) = path.strip_prefix(&source) else {
                continue;
            };
            let alias = if relative.as_os_str().is_empty() {
                mount.target.clone()
            } else {
                mount.target.join(relative)
            };
            match kind {
                MaskKind::Dir => emit_tmpfs(command, alias, &mut masked),
                MaskKind::File => emit_ro_bind_null(command, alias, &mut masked),
            }
        }
    }
}

/// The host `$HOME/.firma` directory, if `$HOME` is a usable absolute path.
///
/// Resolves `HOME` the same way as [`bind_host_home`] / [`mask_sensitive_paths`]
/// (launch env first, then the process environment) so the masked path matches
/// the home actually visible in the sandbox.
fn host_home_firma_dir(launch: &LaunchSpec) -> Option<PathBuf> {
    let home = launch
        .env
        .get("HOME")
        .cloned()
        .or_else(|| std::env::var("HOME").ok())?;
    if home.is_empty() || !home.starts_with('/') {
        return None;
    }
    Some(Path::new(&home).join(CONFIG_DIR_NAME))
}

/// Refuse discoverable `.firma/` symlinks before launch.
///
/// The mask protects the selected config's read/write target, but a symlinked
/// `.firma` entry inside a writable workspace can still be unlinked and replaced
/// with a real directory, planting a higher-precedence config for the next run.
/// bwrap mount targets are paths rather than protected parent-directory file
/// descriptors, so the robust behavior is to fail closed when any `.firma`
/// directory in the discovery/mask set is itself a symlink.
fn reject_symlinked_firma_dirs(launch: &LaunchSpec) -> Result<(), RunError> {
    let mut checked = std::collections::BTreeSet::new();
    for candidate in firma_config_loader::FirmaConfigCandidateAncestors::new(&launch.cwd, None) {
        reject_symlinked_firma_dir(&candidate.config_dir, &mut checked)?;
    }

    if let Some(home_firma) = host_home_firma_dir(launch) {
        reject_symlinked_firma_dir(&home_firma, &mut checked)?;
    }

    if let Some(config_file) = &launch.config_file {
        let config_file = if config_file.is_absolute() {
            config_file.clone()
        } else {
            launch.cwd.join(config_file)
        };
        if let Some(parent) = config_file
            .parent()
            .filter(|parent| parent.file_name().and_then(OsStr::to_str) == Some(CONFIG_DIR_NAME))
        {
            reject_symlinked_firma_dir(parent, &mut checked)?;
        }
    }

    Ok(())
}

fn reject_symlinked_firma_dir(
    dir: &Path,
    checked: &mut std::collections::BTreeSet<PathBuf>,
) -> Result<(), RunError> {
    if dir.file_name().and_then(OsStr::to_str) != Some(CONFIG_DIR_NAME) {
        return Ok(());
    }
    if !checked.insert(dir.to_path_buf()) {
        return Ok(());
    }
    match std::fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(RunError::Backend {
            backend: BackendKind::Bwrap.to_string(),
            reason: format!(
                "refusing to launch bwrap sandbox because discoverable config directory {} is a symlink; use a real .firma directory or pass an explicit config file outside .firma",
                dir.display()
            ),
        }),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RunError::Backend {
            backend: BackendKind::Bwrap.to_string(),
            reason: format!(
                "failed to inspect discoverable config directory {} before masking: {error}",
                dir.display()
            ),
        }),
    }
}

/// tmpfs-mask a single `.firma/` directory, canonicalizing it first (see
/// [`mask_firma_dir`] for the TOCTOU / symlink-swap and fail-closed rationale).
///
/// The caller must pass a path whose final component is `.firma`. Behavior:
///
/// - canonicalizes to a `.firma`-named directory → tmpfs the canonical path.
///   If its `firma.toml` is itself a symlink, its canonical target lies outside
///   the tmpfs mount, so mask that target too (see [`mask_config_file_at`]);
/// - canonicalizes to a non-`.firma` directory (the `.firma` path is a symlink
///   escaping to an unrelated tree) → do not tmpfs the unrelated target, but
///   mask the `firma.toml` it exposes at the target's canonical path;
/// - `NotFound` → skip (no `.firma/` here). The one exception is the run cwd,
///   whose absent `.firma/` is masked separately (see [`mask_firma_dir`]) since
///   the cwd is bound read-write and thus *plantable*;
/// - any other canonicalize error → fail closed, tmpfs the literal path.
///
/// Deduplicates via `masked` so shared ancestors are only emitted once.
fn mask_firma_dir_at(command: &mut Command, dir: &Path, masked: &mut BTreeMap<PathBuf, MaskKind>) {
    let target = match dir.canonicalize() {
        Ok(canonical) if canonical.file_name().and_then(OsStr::to_str) != Some(CONFIG_DIR_NAME) => {
            mask_config_file_at(command, &canonical.join(CONFIG_FILE_NAME), masked);
            return;
        }
        Ok(canonical) => canonical,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(_) if dir.file_name().and_then(OsStr::to_str) != Some(CONFIG_DIR_NAME) => {
            return;
        }
        Err(_) => dir.to_path_buf(),
    };
    let config_file = target.join(CONFIG_FILE_NAME);
    if config_file.is_symlink() {
        mask_config_file_at(command, &config_file, masked);
    }
    emit_tmpfs(command, target, masked);
}

/// ro-bind `/dev/null` over a single config file at its canonical path, so reads
/// return empty and writes fail `EROFS` even when the file is reached through a
/// symlink. Canonicalizes first to defeat a post-discovery symlink swap, falling
/// back to the literal path if it does not resolve. Deduplicated via `masked`.
fn mask_config_file_at(
    command: &mut Command,
    file: &Path,
    masked: &mut BTreeMap<PathBuf, MaskKind>,
) {
    let target = file.canonicalize().unwrap_or_else(|_| file.to_path_buf());
    emit_ro_bind_null(command, target, masked);
}

/// Whether a mask hides a whole `.firma/` directory or a single config file.
/// Used to re-emit the correct bwrap primitive when projecting through aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaskKind {
    Dir,
    File,
}

/// tmpfs-mask a directory once, tracking it in `masked` for dedup/projection.
fn emit_tmpfs(command: &mut Command, target: PathBuf, masked: &mut BTreeMap<PathBuf, MaskKind>) {
    if masked.insert(target.clone(), MaskKind::Dir).is_none() {
        command.arg("--tmpfs").arg(target);
    }
}

/// ro-bind `/dev/null` over a file once, tracking it in `masked` for
/// dedup/projection.
fn emit_ro_bind_null(
    command: &mut Command,
    target: PathBuf,
    masked: &mut BTreeMap<PathBuf, MaskKind>,
) {
    if masked.insert(target.clone(), MaskKind::File).is_none() {
        command.arg("--ro-bind").arg("/dev/null").arg(target);
    }
}

fn command_available(binary: &str) -> bool {
    Command::new(binary)
        .arg("--version")
        .status()
        .is_ok_and(|status| status.success())
}

fn create_bwrap_runtime_dir(sandbox_id: &SandboxId) -> Result<PathBuf, RunError> {
    let runtime_root = std::env::temp_dir().join("firma-run");
    firma_fs::create_private_dir_all(&runtime_root).map_err(|error| RunError::Backend {
        backend: BackendKind::Bwrap.to_string(),
        reason: format!(
            "failed to create runtime root {}: {error}",
            runtime_root.display()
        ),
    })?;
    let runtime_dir = runtime_root.join(sandbox_id.to_string());
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
            sidecar_endpoint: crate::config::SidecarEndpoint::Tcp {
                addr: "127.0.0.1:18080".parse().expect("test sidecar addr"),
            },
            seccomp_filter_path: None,
            identity_mode: crate::config::SandboxIdentityMode::SandboxUser,
            config_file: None,
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

    #[cfg(target_os = "linux")]
    fn launch_with_cwd_and_config(
        cwd: std::path::PathBuf,
        config_file: Option<std::path::PathBuf>,
    ) -> crate::backend::LaunchSpec {
        // Pin HOME to a non-existent path so `host_home_firma_dir` does not fall
        // back to the test runner's real `$HOME`, whose `.firma` would make mask
        // assertions non-deterministic. Tests that exercise `$HOME/.firma`
        // masking set HOME explicitly instead.
        let mut env = BTreeMap::new();
        env.insert("HOME".to_string(), "/nonexistent-firma-home".to_string());
        launch_with_env(cwd, config_file, env)
    }

    #[cfg(target_os = "linux")]
    fn launch_with_env(
        cwd: std::path::PathBuf,
        config_file: Option<std::path::PathBuf>,
        env: BTreeMap<String, String>,
    ) -> crate::backend::LaunchSpec {
        crate::backend::LaunchSpec {
            executable: "/bin/true".to_string(),
            args: vec![],
            cwd,
            env,
            sidecar_endpoint: crate::config::SidecarEndpoint::Tcp {
                addr: "127.0.0.1:18080".parse().expect("test sidecar addr"),
            },
            seccomp_filter_path: None,
            identity_mode: crate::config::SandboxIdentityMode::SandboxUser,
            config_file,
        }
    }

    #[cfg(target_os = "linux")]
    fn rendered_args(cmd: &std::process::Command) -> Vec<String> {
        cmd.get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>()
    }

    /// Canonicalized path, matching how `mask_firma_dir` renders mount targets.
    #[cfg(target_os = "linux")]
    fn canonical(path: &std::path::Path) -> String {
        path.canonicalize()
            .expect("path should exist for canonicalization")
            .display()
            .to_string()
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_masks_dir_without_recreating_file() {
        let mut cmd = std::process::Command::new("bwrap");
        // Config discovered in a `.firma/` above the workspace cwd (walk-up).
        let temp = tempfile::tempdir().expect("tempdir");
        let firma_dir = temp.path().join(".firma");
        std::fs::create_dir_all(&firma_dir).expect("mkdir .firma");
        let config_file = firma_dir.join("firma.toml");
        std::fs::write(&config_file, "").expect("write firma.toml");
        let launch = launch_with_cwd_and_config(temp.path().to_path_buf(), Some(config_file));

        super::mask_firma_dir(&mut cmd, &launch);

        let rendered = rendered_args(&cmd).join(" ");
        assert!(rendered.contains(&format!("--tmpfs {}", canonical(&firma_dir))));
        assert!(!rendered.contains("--ro-bind /dev/null"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_masks_all_ancestor_dirs() {
        let mut cmd = std::process::Command::new("bwrap");
        // Two `.firma/` on the discovery path: the nearest (resolved) and a
        // parent that lost the walk-up race. Both must be masked, since root is
        // bound and a later `firma run` could select the parent.
        let temp = tempfile::tempdir().expect("tempdir");
        let parent_firma = temp.path().join(".firma");
        let child = temp.path().join("service");
        let child_firma = child.join(".firma");
        std::fs::create_dir_all(&parent_firma).expect("mkdir parent .firma");
        std::fs::create_dir_all(&child_firma).expect("mkdir child .firma");
        let config_file = child_firma.join("firma.toml");
        std::fs::write(&config_file, "").expect("write firma.toml");
        let launch = launch_with_cwd_and_config(child, Some(config_file));

        super::mask_firma_dir(&mut cmd, &launch);

        let rendered = rendered_args(&cmd).join(" ");
        assert!(rendered.contains(&format!("--tmpfs {}", canonical(&child_firma))));
        assert!(rendered.contains(&format!("--tmpfs {}", canonical(&parent_firma))));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_masks_firma_after_cwd_bind_and_before_mounts() {
        // Regression guard for the load-bearing ordering: the `.firma` mask must
        // land after the workspace cwd bind (so it hides workspace config) and
        // before profile mounts (so a mount like the vscode `.firma/vscode/`
        // state can re-expose a subpath via bwrap last-write-wins).
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        let firma_dir = cwd.join(".firma");
        let vscode_state = firma_dir.join("vscode");
        std::fs::create_dir_all(&vscode_state).expect("mkdir .firma/vscode");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");

        let handle = crate::backend::SandboxHandle {
            backend: crate::backend::BackendKind::Bwrap,
            runtime_dir,
            identity: crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "vscode"),
            mounts: vec![crate::config::MountSpec {
                source: vscode_state.clone(),
                target: vscode_state.clone(),
                read_only: false,
            }],
            network_policy: crate::config::NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };

        let mut env = BTreeMap::new();
        env.insert("HOME".to_string(), "/nonexistent-firma-home".to_string());
        // Readonly rootfs so the workspace cwd is bound explicitly.
        env.insert(
            super::BWRAP_ROOTFS_MODE_ENV.to_string(),
            super::BWRAP_ROOTFS_MODE_READONLY.to_string(),
        );
        let launch = launch_with_env(cwd.clone(), None, env);
        let hardening = super::bwrap_hardening_from_env(&launch.env);

        let mut cmd = std::process::Command::new("bwrap");
        super::append_filesystem_layout(&mut cmd, &handle, &launch, &hardening);

        let rendered = rendered_args(&cmd);
        let cwd_bind = rendered
            .iter()
            .position(|arg| arg == &cwd.display().to_string())
            .expect("workspace cwd bound");
        let mask = rendered
            .iter()
            .position(|arg| arg == &canonical(&firma_dir))
            .expect("firma dir masked");
        let vscode_mount = rendered
            .iter()
            .position(|arg| arg == &vscode_state.display().to_string())
            .expect("vscode mount re-exposed");
        assert!(cwd_bind < mask, "mask must follow the cwd bind");
        assert!(mask < vscode_mount, "mask must precede profile mounts");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_masks_firma_under_workspace_parent_mount() {
        // Regression guard: a profile mount that binds a *parent* of `.firma/`
        // (the workspace root, source == target, read-write — the shape of a
        // `[[run.profiles.*.mounts]]` entry re-mounting the repo) must not
        // re-leak `firma.toml`. Because its target has no `.firma` ancestor, it
        // is emitted *before* the mask, so the tmpfs over `.firma/` wins via
        // bwrap last-write-wins.
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let firma_dir = workspace.join(".firma");
        std::fs::create_dir_all(&firma_dir).expect("mkdir .firma");
        std::fs::write(firma_dir.join("firma.toml"), "").expect("write firma.toml");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");

        let handle = crate::backend::SandboxHandle {
            backend: crate::backend::BackendKind::Bwrap,
            runtime_dir,
            identity: crate::identity::RunIdentity::new(
                crate::identity::test_agent_id(),
                "claude-code",
            ),
            // Mirrors the workspace-parent bind from firma.toml.
            mounts: vec![crate::config::MountSpec {
                source: workspace.clone(),
                target: workspace.clone(),
                read_only: false,
            }],
            network_policy: crate::config::NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };

        let mut env = BTreeMap::new();
        env.insert("HOME".to_string(), "/nonexistent-firma-home".to_string());
        let launch = launch_with_env(workspace.clone(), None, env);
        let hardening = super::bwrap_hardening_from_env(&launch.env);

        let mut cmd = std::process::Command::new("bwrap");
        super::append_filesystem_layout(&mut cmd, &handle, &launch, &hardening);

        let rendered = rendered_args(&cmd);
        // The workspace-parent bind: `--bind <workspace> <workspace>`.
        let workspace_str = workspace.display().to_string();
        let workspace_mount = rendered
            .windows(3)
            .position(|win| {
                win[0] == "--bind" && win[1] == workspace_str && win[2] == workspace_str
            })
            .expect("workspace-parent mount bound");
        let mask = rendered
            .iter()
            .position(|arg| arg == &canonical(&firma_dir))
            .expect("firma dir masked");
        assert!(
            workspace_mount < mask,
            "workspace-parent mount must precede the mask so the mask hides firma.toml"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_masks_home_firma_outside_cwd_ancestry() {
        let mut cmd = std::process::Command::new("bwrap");
        // cwd is not under $HOME, so $HOME/.firma is outside the walk-up path.
        // It must still be masked: a later run from $HOME would discover it, and
        // $HOME is rebound read-write, so an agent could plant a config there.
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        let home_firma = home.join(".firma");
        std::fs::create_dir_all(&home_firma).expect("mkdir home .firma");
        let cwd = temp.path().join("srv").join("app");
        std::fs::create_dir_all(&cwd).expect("mkdir cwd");

        let mut env = BTreeMap::new();
        env.insert("HOME".to_string(), home.display().to_string());
        let launch = launch_with_env(cwd, None, env);

        super::mask_firma_dir(&mut cmd, &launch);

        let rendered = rendered_args(&cmd).join(" ");
        assert!(rendered.contains(&format!("--tmpfs {}", canonical(&home_firma))));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_fails_closed_when_canonicalize_errors() {
        let mut cmd = std::process::Command::new("bwrap");
        // A `.firma` that exists but cannot be canonicalized (here a self-
        // referential symlink → ELOOP, not NotFound). Must fail closed and mask
        // the literal path rather than leave the config exposed.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let link = cwd.join(".firma");
        std::os::unix::fs::symlink(&link, &link).expect("self-referential symlink");
        assert!(
            link.canonicalize().is_err(),
            "self-symlink should fail canonicalization"
        );

        let launch = launch_with_cwd_and_config(cwd, None);

        super::mask_firma_dir(&mut cmd, &launch);

        let rendered = rendered_args(&cmd).join(" ");
        assert!(rendered.contains(&format!("--tmpfs {}", link.display())));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_follows_symlink_swap_to_real_path() {
        let mut cmd = std::process::Command::new("bwrap");
        // A hostile workspace swaps `.firma` for a symlink after discovery. The
        // mask must land on the symlink target's real path, not the link name,
        // so the real config directory is actually hidden.
        let temp = tempfile::tempdir().expect("tempdir");
        let real_firma = temp.path().join("real").join(".firma");
        std::fs::create_dir_all(&real_firma).expect("mkdir real .firma");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let link = cwd.join(".firma");
        std::os::unix::fs::symlink(&real_firma, &link).expect("symlink .firma");

        let launch = launch_with_cwd_and_config(cwd, None);

        super::mask_firma_dir(&mut cmd, &launch);

        let rendered = rendered_args(&cmd).join(" ");
        assert!(rendered.contains(&format!("--tmpfs {}", canonical(&real_firma))));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_ignores_symlink_to_non_firma_dir() {
        let mut cmd = std::process::Command::new("bwrap");
        // `.firma` symlinked at the workspace root: canonicalizing resolves to a
        // non-`.firma` directory, so we must NOT tmpfs it (that would hide the
        // whole workspace).
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let link = cwd.join(".firma");
        std::os::unix::fs::symlink(&cwd, &link).expect("symlink .firma -> workspace");

        let launch = launch_with_cwd_and_config(cwd, None);

        super::mask_firma_dir(&mut cmd, &launch);

        let rendered = rendered_args(&cmd);
        assert!(
            rendered.iter().all(|arg| arg != "--tmpfs"),
            "must not tmpfs a symlink that resolves outside a .firma dir"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_masks_bare_file_without_tmpfsing_parent() {
        let mut cmd = std::process::Command::new("bwrap");
        // Explicit --config pointing at a bare file: parent is not `.firma`, so
        // we must NOT tmpfs the parent (it could be the workspace root); only the
        // file itself is masked. The absent cwd `.firma` is still masked to block
        // planting, but that is a sibling of the file, not the parent.
        let temp = tempfile::tempdir().expect("tempdir");
        let config_file = temp.path().join("firma.toml");
        std::fs::write(&config_file, "").expect("write firma.toml");
        let launch =
            launch_with_cwd_and_config(temp.path().to_path_buf(), Some(config_file.clone()));

        super::mask_firma_dir(&mut cmd, &launch);

        let rendered = rendered_args(&cmd);
        // The bare file is masked with /dev/null.
        assert!(
            rendered
                .join(" ")
                .contains(&format!("--ro-bind /dev/null {}", canonical(&config_file)))
        );
        // The parent (workspace root) is never tmpfs'd; only the cwd `.firma`.
        let parent = temp.path().display().to_string();
        assert!(
            !rendered
                .windows(2)
                .any(|w| w[0] == "--tmpfs" && w[1] == parent),
            "must not tmpfs the bare file's parent directory"
        );
        assert!(
            rendered
                .windows(2)
                .any(|w| w[0] == "--tmpfs"
                    && w[1] == temp.path().join(".firma").display().to_string()),
            "absent cwd `.firma` should still be masked"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_resolves_relative_config_file_against_cwd() {
        let mut cmd = std::process::Command::new("bwrap");
        // `--config ./firma.toml`: relative paths must be made absolute or bwrap
        // aborts the sandbox (fail-closed DENY) on a relative mount target.
        let temp = tempfile::tempdir().expect("tempdir");
        let config_file = temp.path().join("firma.toml");
        std::fs::write(&config_file, "").expect("write firma.toml");
        let launch = launch_with_cwd_and_config(
            temp.path().to_path_buf(),
            Some(std::path::PathBuf::from("firma.toml")),
        );

        super::mask_firma_dir(&mut cmd, &launch);

        let rendered = rendered_args(&cmd).join(" ");
        assert!(rendered.contains(&format!("--ro-bind /dev/null {}", canonical(&config_file))));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_masks_absent_cwd_candidate_to_block_planting() {
        let mut cmd = std::process::Command::new("bwrap");
        // No `.firma/` anywhere and no `--config`: the only mask is the absent
        // cwd candidate, tmpfs'd so the agent can't plant a higher-precedence
        // `.firma/` at the rw-bound cwd for a later run to select. Ancestors
        // above the cwd are absent too but not plantable, so they stay unmasked.
        let temp = tempfile::tempdir().expect("tempdir");
        let launch = launch_with_cwd_and_config(temp.path().to_path_buf(), None);

        super::mask_firma_dir(&mut cmd, &launch);

        let rendered = rendered_args(&cmd);
        assert_eq!(
            rendered,
            vec![
                "--tmpfs".to_string(),
                temp.path().join(".firma").display().to_string(),
            ],
            "only the absent cwd `.firma` is masked"
        );
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

//! Validated filesystem planning for the Linux bubblewrap backend.
//!
//! This module is the single owner of bwrap filesystem argument ordering. It
//! converts the authority-tagged mounts in [`SandboxHandle`] into an immutable plan,
//! validates their host sources, and applies the control-plane and config masks
//! before the parent backend emits the command.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use crate::backend::{
    BackendKind, LaunchSpec, SandboxHandle, SandboxInfrastructureKind, SandboxMountAuthority,
    SandboxMountPlacement,
};
use crate::config::MountSpec;
use crate::error::RunError;
use crate::trust::SidecarTrustAnchor;
use firma_config_loader::{CONFIG_DIR_NAME, CONFIG_FILE_NAME};
use firma_runtime_state::RunEntryLayout;

/// Mount table of the planning process, listing every host mount point and its
/// filesystem type.
const HOST_MOUNTINFO_PATH: &str = "/proc/self/mountinfo";
/// `mountinfo` filesystem type of a procfs instance.
const PROCFS_FS_TYPE: &str = "proc";
/// Zero-based index of the mount point in a `mountinfo` line's fixed fields.
const MOUNTINFO_MOUNT_POINT_FIELD: usize = 4;
/// Sandbox path holding the procfs of the sandbox's own PID namespace.
const SANDBOX_PROCFS_TARGET: &str = "/proc";

const BWRAP_ROOTFS_MODE_ENV: &str = "FIRMA_RUN_BWRAP_ROOTFS_MODE";
const BWRAP_RUNTIME_HOME_ENV: &str = "FIRMA_RUN_BWRAP_RUNTIME_HOME";
const BWRAP_MASK_HOME_PATHS_ENV: &str = "FIRMA_RUN_BWRAP_MASK_HOME_PATHS";
const BWRAP_ROOTFS_MODE_READONLY: &str = "readonly";

/// Filesystem-hardening settings consumed while building a bwrap mount plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BwrapHardening {
    readonly_rootfs: bool,
    runtime_home_isolation: bool,
    mask_home_paths: Vec<String>,
}

impl BwrapHardening {
    /// Resolves bwrap filesystem-hardening settings from the launch environment.
    pub(super) fn from_env(env: &BTreeMap<String, String>) -> Self {
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
        Self {
            readonly_rootfs,
            runtime_home_isolation,
            mask_home_paths,
        }
    }

    /// Whether launch environment paths must be redirected to the private
    /// sandbox runtime.
    pub(super) fn runtime_home_isolation(&self) -> bool {
        self.runtime_home_isolation
    }
}

/// Returns whether a profile environment value enables a boolean setting.
fn parse_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Immutable, validated filesystem phases passed to bwrap.
///
/// Construction is the security boundary: operator-provided and ordinary
/// framework mounts are validated against protected host paths before any
/// arguments are emitted, while the narrowly-scoped sandbox infrastructure
/// authority is checked against [`SandboxHandle::runtime_dir`].
#[derive(Debug)]
pub(super) struct BwrapMountPlan {
    /// Backend-owned baseline filesystem setup.
    layout: BwrapMountPhase,
    /// Ordinary operator and framework overlays.
    overlays: BwrapMountPhase,
    /// Configuration and sensitive-home masks.
    config_seals: BwrapMountPhase,
    /// Explicit framework subpaths restored through configuration seals.
    protected_subpaths: BwrapMountPhase,
    /// Sandbox procfs re-established over every host procfs a mount aliases.
    procfs_seals: BwrapMountPhase,
    /// Final masks over host-side control-plane state and its aliases.
    control_plane_seals: BwrapMountPhase,
    /// Restoration of the current sandbox's runtime beneath the sealed root.
    sandbox_runtime: BwrapMountPhase,
    /// Narrow backend facilities emitted only after all security seals.
    infrastructure: BwrapMountPhase,
}

/// Operations belonging to one fixed phase of a [`BwrapMountPlan`].
#[derive(Debug, Default)]
struct BwrapMountPhase {
    /// Operations emitted in insertion order within this security phase.
    steps: Vec<BwrapPlanStep>,
}

/// Prepared mount whose source has passed authority-aware path validation.
///
/// The canonical source stored here is the source later copied into the plan,
/// keeping validation and emission on the same path identity.
#[derive(Debug)]
struct ValidatedMount {
    /// Mount specification with a canonical host source.
    spec: MountSpec,
    /// Security authority retained from the prepared sandbox mount.
    authority: SandboxMountAuthority,
    /// Fixed plan layer retained from the prepared sandbox mount.
    placement: SandboxMountPlacement,
}

/// Semantic role of a mount operation in the final bwrap filesystem plan.
///
/// Roles remain attached to bind, tmpfs, and device-filesystem operations so
/// the immutable plan records why each mount exists, even though bwrap itself
/// receives only path-based arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BwrapPlanRole {
    /// Baseline sandbox filesystem layout owned by the bwrap backend.
    Layout,
    /// Mount controlled by the operator through external configuration.
    OperatorProvided,
    /// Mount introduced by an ordinary runtime integration.
    Framework,
    /// Backend-owned mount sourced from the private sandbox runtime.
    SandboxInfrastructure,
    /// Overlay that hides host configuration or control-plane state.
    Mask,
}

/// Access mode applied to a bwrap bind mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BwrapBindMode {
    /// Exposes the source without permitting writes through the mount.
    ReadOnly,
    /// Exposes the source with its host write permissions intact.
    ReadWrite,
}

/// One ordered filesystem operation emitted to bwrap.
#[derive(Debug)]
enum BwrapPlanStep {
    /// Bind-mounts a host source at a sandbox target.
    Bind {
        /// Semantic owner of the bind operation.
        role: BwrapPlanRole,
        /// Host source path passed to bwrap.
        ///
        /// Sources originating from [`ValidatedMount`] are canonical; trusted
        /// backend layout and mask sources may remain literal paths.
        source: PathBuf,
        /// Path where the source appears inside the sandbox.
        target: PathBuf,
        /// Access mode applied to the bind mount.
        mode: BwrapBindMode,
    },
    /// Mounts an empty temporary filesystem over a sandbox path.
    Tmpfs {
        /// Semantic owner of the masking or layout operation.
        role: BwrapPlanRole,
        /// Sandbox path covered by the temporary filesystem.
        target: PathBuf,
    },
    /// Creates bwrap's private device filesystem at the target path.
    Dev {
        /// Semantic owner of the device-filesystem operation.
        role: BwrapPlanRole,
        /// Sandbox path populated with the private device filesystem.
        target: PathBuf,
    },
    /// Mounts a procfs for the sandbox's own PID namespace.
    Proc {
        /// Semantic owner of the procfs operation.
        role: BwrapPlanRole,
        /// Sandbox path populated with the procfs.
        target: PathBuf,
    },
}

impl BwrapMountPlan {
    /// Creates a plan with no filesystem operations in any phase.
    fn empty() -> Self {
        Self {
            layout: BwrapMountPhase::default(),
            overlays: BwrapMountPhase::default(),
            config_seals: BwrapMountPhase::default(),
            protected_subpaths: BwrapMountPhase::default(),
            procfs_seals: BwrapMountPhase::default(),
            control_plane_seals: BwrapMountPhase::default(),
            sandbox_runtime: BwrapMountPhase::default(),
            infrastructure: BwrapMountPhase::default(),
        }
    }

    /// Builds and validates the complete filesystem plan for one launch.
    ///
    /// All runtime integrations must finish updating [`SandboxHandle::mounts`]
    /// before this boundary; afterward, the immutable plan is the sole source
    /// of filesystem arguments emitted to bwrap.
    pub(super) fn build(
        runtime_layout: &firma_runtime_state::RuntimeLayout,
        handle: &SandboxHandle,
        launch: &LaunchSpec,
        hardening: &BwrapHardening,
    ) -> Result<Self, RunError> {
        Self::build_against(
            runtime_layout,
            handle,
            launch,
            hardening,
            &HostProcfsMounts::from_host()?,
        )
    }

    /// Builds the plan against an explicit procfs inventory.
    ///
    /// Separated from [`Self::build`] so the seal can be exercised against a
    /// mount table the test controls, rather than whichever one the machine
    /// running the tests happens to have.
    fn build_against(
        runtime_layout: &firma_runtime_state::RuntimeLayout,
        handle: &SandboxHandle,
        launch: &LaunchSpec,
        hardening: &BwrapHardening,
        host_procfs: &HostProcfsMounts,
    ) -> Result<Self, RunError> {
        let control_plane_runtime =
            resolve_path_allow_missing(runtime_layout.root(), "control-plane runtime")?;
        let sandbox_runtime =
            handle
                .runtime_dir
                .canonicalize()
                .map_err(|error| RunError::Backend {
                    backend: BackendKind::Bwrap.to_string(),
                    reason: format!(
                        "failed to resolve sandbox runtime {} before planning mounts: {error}",
                        handle.runtime_dir.display()
                    ),
                })?;
        // Derived from the runtime layout rather than the launch environment:
        // an operator-supplied `SSL_CERT_FILE` could otherwise aim the CA bind
        // at a signing key elsewhere in the control-plane runtime.
        //
        // Rooted at the *resolved* control-plane path so the run entry, the
        // binds taken from it, and the mask that covers them all share one
        // spelling. Rooting it at the layout's own path would reintroduce any
        // relative or unnormalized `FIRMA_STATE_DIR` spelling, and bwrap cannot
        // create a relative bind target beneath its read-only root.
        let run_entry =
            firma_runtime_state::RuntimeLayout::from_root(control_plane_runtime.clone())
                .run_entry_layout(&handle.identity.sandbox_id);
        let runtime_paths = PlanRuntimePaths {
            control_plane: &control_plane_runtime,
            sandbox: &sandbox_runtime,
            run_entry: &run_entry,
        };
        let mounts = validate_mounts(
            handle,
            &control_plane_runtime,
            &sandbox_runtime,
            host_procfs,
        )?;
        let mut plan = Self::empty();
        append_filesystem_layout(
            &mut plan,
            handle,
            &mounts,
            &runtime_paths,
            launch,
            hardening,
            host_procfs,
        )?;
        Ok(plan)
    }

    /// Consumes the validated plan and emits its phases in the only permitted
    /// security order.
    pub(super) fn emit(self, command: &mut Command) {
        for phase in [
            self.layout,
            self.overlays,
            self.config_seals,
            self.protected_subpaths,
            self.procfs_seals,
            self.control_plane_seals,
            self.sandbox_runtime,
            self.infrastructure,
        ] {
            phase.emit(command);
        }
    }
}

impl BwrapMountPhase {
    /// Appends a bind-mount operation to this phase.
    fn bind(
        &mut self,
        role: BwrapPlanRole,
        source: impl Into<PathBuf>,
        target: impl Into<PathBuf>,
        mode: BwrapBindMode,
    ) {
        self.steps.push(BwrapPlanStep::Bind {
            role,
            source: source.into(),
            target: target.into(),
            mode,
        });
    }

    /// Appends a temporary-filesystem operation to this phase.
    fn tmpfs(&mut self, role: BwrapPlanRole, target: impl Into<PathBuf>) {
        self.steps.push(BwrapPlanStep::Tmpfs {
            role,
            target: target.into(),
        });
    }

    /// Appends creation of bwrap's private device filesystem.
    fn dev(&mut self, role: BwrapPlanRole, target: impl Into<PathBuf>) {
        self.steps.push(BwrapPlanStep::Dev {
            role,
            target: target.into(),
        });
    }

    /// Appends creation of a procfs for the sandbox's own PID namespace.
    fn proc(&mut self, role: BwrapPlanRole, target: impl Into<PathBuf>) {
        self.steps.push(BwrapPlanStep::Proc {
            role,
            target: target.into(),
        });
    }

    /// Consumes this phase and appends its operations to bwrap.
    fn emit(self, command: &mut Command) {
        for step in self.steps {
            match step {
                BwrapPlanStep::Bind {
                    role,
                    source,
                    target,
                    mode,
                } => {
                    let _ = role;
                    command.arg(match mode {
                        BwrapBindMode::ReadOnly => "--ro-bind",
                        BwrapBindMode::ReadWrite => "--bind",
                    });
                    command.arg(source).arg(target);
                }
                BwrapPlanStep::Tmpfs { role, target } => {
                    let _ = role;
                    command.arg("--tmpfs").arg(target);
                }
                BwrapPlanStep::Dev { role, target } => {
                    let _ = role;
                    command.arg("--dev").arg(target);
                }
                BwrapPlanStep::Proc { role, target } => {
                    let _ = role;
                    command.arg("--proc").arg(target);
                }
            }
        }
    }
}

/// Rebind real `$HOME` writable when `runtime_home_isolation` is off.
/// Without this, `--ro-bind /` makes `$HOME` read-only and the agent hits
/// EROFS writing config/session state. `mask_home_paths` tmpfs overlays
/// applied afterward still take precedence over this bind.
fn bind_host_home(layout: &mut BwrapMountPhase, launch: &LaunchSpec) {
    let home = launch
        .env
        .get("HOME")
        .cloned()
        .or_else(|| std::env::var("HOME").ok())
        .unwrap_or_default();
    if !home.is_empty() && home.starts_with('/') {
        layout.bind(
            BwrapPlanRole::Layout,
            &home,
            &home,
            BwrapBindMode::ReadWrite,
        );
    }
}

/// Masks configured sensitive paths beneath the host home directory when they
/// exist, avoiding mount failures for absent paths on a read-only root.
fn mask_sensitive_paths(
    config_seals: &mut BwrapMountPhase,
    launch: &LaunchSpec,
    suffixes: &[String],
) {
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
            config_seals.tmpfs(BwrapPlanRole::Mask, path);
        }
    }
}

/// Populate the fixed phases of the sandbox filesystem plan.
///
/// [`BwrapMountPlan::emit`] owns the load-bearing bwrap order. Ordinary mounts
/// always precede configuration seals. The explicit framework-protected
/// subpath capability used by VS Code follows those seals, while the final
/// control-plane seal still follows every externally sourced mount:
///
/// 1. baseline layout;
/// 2. ordinary operator and framework overlays;
/// 3. configuration and sensitive-home seals;
/// 4. explicit framework-protected subpaths;
/// 5. the sandbox procfs re-established over every aliased host procfs;
/// 6. the control-plane runtime seal;
/// 7. the private runtime for the current sandbox;
/// 8. narrowly validated sandbox infrastructure sourced from that runtime.
fn append_filesystem_layout(
    plan: &mut BwrapMountPlan,
    handle: &SandboxHandle,
    mounts: &[ValidatedMount],
    runtime_paths: &PlanRuntimePaths<'_>,
    launch: &LaunchSpec,
    hardening: &BwrapHardening,
    host_procfs: &HostProcfsMounts,
) -> Result<(), RunError> {
    if hardening.readonly_rootfs {
        plan.layout
            .bind(BwrapPlanRole::Layout, "/", "/", BwrapBindMode::ReadOnly);
        plan.layout.tmpfs(BwrapPlanRole::Layout, "/tmp");
        plan.layout.tmpfs(BwrapPlanRole::Layout, "/var/tmp");
        plan.layout.bind(
            BwrapPlanRole::Layout,
            &launch.cwd,
            &launch.cwd,
            BwrapBindMode::ReadWrite,
        );
        plan.layout.bind(
            BwrapPlanRole::SandboxInfrastructure,
            &handle.runtime_dir,
            &handle.runtime_dir,
            BwrapBindMode::ReadWrite,
        );
        if !hardening.runtime_home_isolation {
            bind_host_home(&mut plan.layout, launch);
        }
        mask_sensitive_paths(&mut plan.config_seals, launch, &hardening.mask_home_paths);
    } else {
        plan.layout
            .bind(BwrapPlanRole::Layout, "/", "/", BwrapBindMode::ReadWrite);
    }
    plan.layout.dev(BwrapPlanRole::Layout, "/dev");
    // Must follow the root bind, which would otherwise cover it with the
    // host's inherited procfs. Paired with `--unshare-pid`: the sandbox's own
    // procfs shows only its own processes, closing the
    // `/proc/<pid>/root/<host path>` alias through which an ancestor's mount
    // namespace — and with it every masked control-plane secret, including the
    // Sidecar CA signing key — stayed reachable. This covers `/proc` itself;
    // `validate_reserved_target` keeps mounts off it and
    // `project_procfs_aliases` seals every other procfs a recursive bind
    // carries into the sandbox.
    plan.layout
        .proc(BwrapPlanRole::Layout, SANDBOX_PROCFS_TARGET);

    emit_mounts(plan, mounts.iter());

    // Project each configuration seal through ordinary overlays so aliasing a
    // `.firma`-containing tree cannot expose its config at another destination.
    let masked = mask_firma_dir(&mut plan.config_seals, launch);
    let overlay_specs = mounts
        .iter()
        .filter(|mount| mount.placement == SandboxMountPlacement::Overlay)
        .map(|mount| &mount.spec)
        .collect::<Vec<_>>();
    project_mount_aliases(&mut plan.config_seals, &overlay_specs, masked);

    // A recursive bind carries the host procfs along with the tree it exposes,
    // so the layout's own `--proc` is not enough. The layout's host-root bind
    // is projected alongside the external mounts: on a host with a second
    // procfs — a leftover `mount --bind /proc /mnt/proc`, an exporter-style
    // `/host/proc`, a machine directory — that bind alone carries it into the
    // sandbox, with no operator configuration involved.
    //
    // Emitted in its own phase, after the protected-subpath capability. The
    // phases that follow cannot undo it: the control-plane seals are masks, the
    // sandbox runtime is restored from the private runtime directory, and
    // sandbox-infrastructure mounts are confined to fixed `/etc` targets by
    // `validate_infrastructure_mount`.
    let host_root_bind = MountSpec {
        source: PathBuf::from("/"),
        target: PathBuf::from("/"),
        read_only: hardening.readonly_rootfs,
    };
    let alias_specs = std::iter::once(&host_root_bind)
        .chain(mounts.iter().map(|mount| &mount.spec))
        .collect::<Vec<_>>();
    project_procfs_aliases(&mut plan.procfs_seals, &alias_specs, host_procfs)?;

    mask_control_plane_runtime(
        plan,
        mounts,
        runtime_paths.control_plane,
        runtime_paths.sandbox,
        launch,
    )?;
    mount_ca_material(
        plan,
        runtime_paths.run_entry,
        runtime_paths.control_plane,
        launch.trust_anchor.as_ref(),
    )?;
    Ok(())
}

/// Host paths that anchor one sandbox filesystem plan.
struct PlanRuntimePaths<'a> {
    /// Canonical control-plane runtime root (`FIRMA_STATE_DIR`).
    control_plane: &'a Path,
    /// Canonical private runtime for the sandbox being planned.
    sandbox: &'a Path,
    /// Layout of this run's entry inside the control-plane runtime.
    run_entry: &'a RunEntryLayout,
}

/// Hide host-side Firma runtime state from the wrapped process tree.
///
/// The read-only host-root bind prevents mutation but not disclosure. The
/// runtime root contains per-run Sidecar and Authority sockets, configuration,
/// metadata, signing keys, and capability seeds, none of which the wrapped
/// process needs. The sandbox-local bwrap runtime remains available separately
/// because the proxy bridge and egress guard require its sockets, and
/// [`mount_ca_material`] mounts the Sidecar's public CA material back over
/// this mask.
fn mask_control_plane_runtime(
    plan: &mut BwrapMountPlan,
    mounts: &[ValidatedMount],
    runtime: &Path,
    sandbox_runtime: &Path,
    launch: &LaunchSpec,
) -> Result<(), RunError> {
    let cwd = launch.cwd.canonicalize().map_err(|error| RunError::Backend {
        backend: BackendKind::Bwrap.to_string(),
        reason: format!(
            "failed to resolve sandbox working directory {} before masking control-plane runtime: {error}",
            launch.cwd.display()
        ),
    })?;
    if cwd.starts_with(runtime) {
        return Err(RunError::Backend {
            backend: BackendKind::Bwrap.to_string(),
            reason: format!(
                "sandbox working directory {} is inside the control-plane runtime {}; choose a working directory outside FIRMA_STATE_DIR",
                cwd.display(),
                runtime.display()
            ),
        });
    }

    let mut masked = BTreeMap::new();
    emit_tmpfs(
        &mut plan.control_plane_seals,
        runtime.to_path_buf(),
        &mut masked,
    );
    let specs = mounts.iter().map(|mount| &mount.spec).collect::<Vec<_>>();
    project_mount_aliases(&mut plan.control_plane_seals, &specs, masked);

    if sandbox_runtime.starts_with(runtime) {
        plan.sandbox_runtime.bind(
            BwrapPlanRole::SandboxInfrastructure,
            sandbox_runtime,
            sandbox_runtime,
            BwrapBindMode::ReadWrite,
        );
    }
    Ok(())
}

/// Mount the Sidecar's public CA material through the control-plane mask.
///
/// [`mask_control_plane_runtime`] tmpfs-masks the whole control-plane runtime,
/// but the launch environment points `SSL_CERT_FILE`, `CURL_CA_BUNDLE`,
/// `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, and `GIT_SSL_CAINFO` at CA
/// files inside it. Without this restoration the wrapped process opens an
/// unreadable trust store, silently falls back to the system roots, and every
/// MITM-intercepted handshake fails with `certificate signed by unknown
/// authority`.
///
/// Each file is bound individually and read-only. Binding
/// [`RunEntryLayout::ca_dir`] as a directory would also expose
/// [`RunEntryLayout::ca_key`] and let the wrapped process mint certificates
/// trusted by anything configured to trust the Sidecar CA.
///
/// Missing files are skipped: with HTTPS MITM disabled no CA is generated, and
/// the bundle exists only under `ca_trust_mode = "append_system_roots"`.
///
/// The launch's [`SidecarTrustAnchor`] is a cross-check, never a bind source.
/// It is resolved partly from operator-controlled variables, so honoring it
/// directly would let `FIRMA_SIDECAR_CA_CERT_PATH` aim a bind at the CA signing
/// key or any other control-plane secret. Instead, an anchor that the mask
/// hides but this run's layout does not explain fails the launch: the
/// alternative is a wrapped process that silently trusts only the host's system
/// roots while believing it trusts the Sidecar.
///
/// The cross-check accepts an anchor only if this plan actually restores it, so
/// it applies the same existence test the bind loop does. Naming a path this
/// run's layout would restore is not enough: if the file is absent, the loop
/// skips it and the anchor stays behind the mask.
fn mount_ca_material(
    plan: &mut BwrapMountPlan,
    run_entry: &RunEntryLayout,
    control_plane_runtime: &Path,
    trust_anchor: Option<&SidecarTrustAnchor>,
) -> Result<(), RunError> {
    let restored = [run_entry.ca_cert(), run_entry.ca_bundle()]
        .into_iter()
        .filter(|source| source.is_file())
        .collect::<Vec<_>>();

    if let Some(anchor) = trust_anchor {
        let anchor_path = resolve_path_allow_missing(anchor.path(), "sidecar trust anchor")?;
        if anchor_path.starts_with(control_plane_runtime)
            && !restored.iter().any(|candidate| {
                resolve_path_allow_missing(candidate, "sidecar CA material")
                    .is_ok_and(|resolved| resolved == anchor_path)
            })
        {
            return Err(RunError::Backend {
                backend: BackendKind::Bwrap.to_string(),
                reason: format!(
                    "trust anchor {} lies inside the masked control-plane runtime {} and is not CA material this run restores from {}; \
                     move an external Sidecar's CA outside FIRMA_STATE_DIR",
                    anchor_path.display(),
                    control_plane_runtime.display(),
                    run_entry.ca_dir().display()
                ),
            });
        }
    }

    for source in restored {
        plan.sandbox_runtime.bind(
            BwrapPlanRole::SandboxInfrastructure,
            source.clone(),
            source,
            BwrapBindMode::ReadOnly,
        );
    }
    Ok(())
}

/// Host mount points backed by procfs, enumerated once per plan.
///
/// The sandbox's own procfs is what keeps `/proc/<pid>/root/<host path>` from
/// walking around every mask through an ancestor's mount namespace. Two mount
/// shapes hand that alias back: a mount that lands on the sandbox procfs, and a
/// mount whose source tree contains a host procfs, since bwrap binds
/// recursively. Both are decided against this inventory.
#[derive(Debug)]
#[doc(hidden)]
pub struct HostProcfsMounts {
    /// Normalized host mount points whose filesystem type is procfs.
    points: Vec<PathBuf>,
}

impl HostProcfsMounts {
    /// Reads the planning process's own mount table.
    ///
    /// Fails the launch when the table cannot be read or parsed: a procfs set
    /// that cannot be enumerated cannot be sealed either, and every host that
    /// runs the bwrap backend has `/proc/self/mountinfo`.
    fn from_host() -> Result<Self, RunError> {
        let contents =
            std::fs::read_to_string(HOST_MOUNTINFO_PATH).map_err(|error| RunError::Backend {
                backend: BackendKind::Bwrap.to_string(),
                reason: format!(
                    "failed to read {HOST_MOUNTINFO_PATH} before planning mounts: {error}"
                ),
            })?;
        Self::from_mountinfo(&contents)
    }

    /// Collects the procfs mount points described by `mountinfo` content.
    ///
    /// Each line separates its fixed fields from the filesystem type with a
    /// ` - ` marker, and the kernel escapes spaces, tabs, newlines, and
    /// backslashes in the mount point.
    pub fn from_mountinfo(contents: &str) -> Result<Self, RunError> {
        let mut points = Vec::new();
        for line in contents.lines().filter(|line| !line.trim().is_empty()) {
            let Some((mounted, mount_source)) = line.split_once(" - ") else {
                return Err(Self::malformed(line));
            };
            let Some(fs_type) = mount_source.split_whitespace().next() else {
                return Err(Self::malformed(line));
            };
            if fs_type != PROCFS_FS_TYPE {
                continue;
            }
            let Some(mount_point) = mounted.split_whitespace().nth(MOUNTINFO_MOUNT_POINT_FIELD)
            else {
                return Err(Self::malformed(line));
            };
            points.push(normalize_absolute_path(Path::new(
                &unescape_mountinfo_field(mount_point),
            )));
        }
        points.sort();
        points.dedup();
        Ok(Self { points })
    }

    /// Whether `path` is a procfs mount point or lies beneath one.
    #[must_use]
    pub fn covers(&self, path: &Path) -> bool {
        self.points.iter().any(|point| path.starts_with(point))
    }

    /// Procfs mount points strictly beneath `source`, relative to it.
    ///
    /// These are the paths a recursive bind of `source` re-exposes inside the
    /// sandbox, each relative to that mount's target.
    fn points_under<'a>(&'a self, source: &'a Path) -> impl Iterator<Item = &'a Path> {
        self.points.iter().filter_map(move |point| {
            let relative = point.strip_prefix(source).ok()?;
            (!relative.as_os_str().is_empty()).then_some(relative)
        })
    }

    /// Fails the launch on a `mountinfo` line this parser cannot interpret.
    fn malformed(line: &str) -> RunError {
        RunError::Backend {
            backend: BackendKind::Bwrap.to_string(),
            reason: format!("failed to parse {HOST_MOUNTINFO_PATH} line '{line}'"),
        }
    }
}

/// Decodes the octal escapes the kernel writes into `mountinfo` path fields.
fn unescape_mountinfo_field(field: &str) -> String {
    let mut decoded = String::with_capacity(field.len());
    let mut rest = field;
    while let Some(escape) = rest.find('\\') {
        decoded.push_str(&rest[..escape]);
        let digits = rest.get(escape + 1..escape + 4);
        if let Some(byte) = digits.and_then(|digits| u8::from_str_radix(digits, 8).ok()) {
            decoded.push(char::from(byte));
            rest = &rest[escape + 4..];
        } else {
            decoded.push('\\');
            rest = &rest[escape + 1..];
        }
    }
    decoded.push_str(rest);
    decoded
}

/// Rejects a mount that would take a sandbox path the backend layout owns.
///
/// The layout mounts the sandbox's own procfs before any external mount is
/// emitted, so a mount landing on `/proc` — or on `/`, which re-parents the
/// whole layout — silently replaces it.
///
/// The target is resolved through every existing symlink before the comparison,
/// the way bwrap resolves a destination at mount time. A lexical check alone
/// would accept a workspace symlink pointing into the reserved set, and the
/// workspace is writable by the wrapped process, so that link is plantable — the
/// same threat [`reject_symlinked_firma_dirs`] fails closed on. The residual
/// race is also the same: bwrap re-resolves the destination string itself, and
/// its API takes a path rather than a file descriptor.
fn validate_reserved_target(target: &Path) -> Result<(), RunError> {
    let resolved = resolve_path_allow_missing(target, "mount target")?;
    if resolved != Path::new("/") && !resolved.starts_with(SANDBOX_PROCFS_TARGET) {
        return Ok(());
    }
    Err(RunError::Backend {
        backend: BackendKind::Bwrap.to_string(),
        reason: format!(
            "mount target {} resolves to {}, which is reserved for the sandbox filesystem layout; a mount there would replace the sandbox's own procfs and reopen /proc/<pid>/root onto masked host paths",
            target.display(),
            resolved.display()
        ),
    })
}

/// Resolves every prepared mount to the exact host source that will be emitted
/// and enforces the source, target, and placement constraints associated with
/// its authority.
fn validate_mounts(
    handle: &SandboxHandle,
    control_plane_runtime: &Path,
    sandbox_runtime: &Path,
    host_procfs: &HostProcfsMounts,
) -> Result<Vec<ValidatedMount>, RunError> {
    let mounts = handle
        .mounts
        .iter()
        .map(|mount| {
            let source = mount.spec().source.canonicalize().map_err(|error| {
                RunError::Backend {
                    backend: BackendKind::Bwrap.to_string(),
                    reason: format!(
                        "failed to resolve mount source {} before planning mounts: {error}",
                        mount.spec().source.display()
                    ),
                }
            })?;
            match mount.authority() {
                SandboxMountAuthority::SandboxInfrastructure(kind) => {
                    if !source.starts_with(sandbox_runtime) {
                        return Err(RunError::Backend {
                            backend: BackendKind::Bwrap.to_string(),
                            reason: format!(
                                "sandbox-infrastructure mount source {} escapes the private sandbox runtime {}",
                                source.display(),
                                sandbox_runtime.display()
                            ),
                        });
                    }
                    validate_infrastructure_mount(kind, mount.spec())?;
                }
                SandboxMountAuthority::OperatorProvided | SandboxMountAuthority::Framework => {
                    if source.starts_with(control_plane_runtime) {
                        return Err(RunError::Backend {
                            backend: BackendKind::Bwrap.to_string(),
                            reason: format!(
                                "refusing mount source {} inside the control-plane runtime {}; wrapped processes must not access FIRMA_STATE_DIR",
                                source.display(),
                                control_plane_runtime.display()
                            ),
                        });
                    }
                }
            }
            validate_reserved_target(&mount.spec().target)?;
            if host_procfs.covers(&source) {
                return Err(RunError::Backend {
                    backend: BackendKind::Bwrap.to_string(),
                    reason: format!(
                        "refusing procfs-backed mount source {}; the host procfs exposes /proc/<pid>/root, which walks around every sandbox mask",
                        source.display()
                    ),
                });
            }
            if mount.placement() == SandboxMountPlacement::FrameworkProtectedSubpath
                && (mount.authority() != SandboxMountAuthority::Framework
                    || !is_strict_firma_subpath(&mount.spec().target))
            {
                return Err(RunError::Backend {
                    backend: BackendKind::Bwrap.to_string(),
                    reason: format!(
                        "framework-protected mount target {} must be strictly inside a .firma directory",
                        mount.spec().target.display()
                    ),
                });
            }

            Ok(ValidatedMount {
                spec: MountSpec {
                    source,
                    target: mount.spec().target.clone(),
                    read_only: mount.spec().read_only,
                },
                authority: mount.authority(),
                placement: mount.placement(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_overlay_destinations(&mounts)?;
    Ok(mounts)
}

/// Rejects ambiguous destinations that cannot be linearized independently of
/// insertion order.
///
/// Ordinary parent/child overlays are valid and are later sorted from broadest
/// to most specific. Exact duplicates remain ambiguous. Protected framework
/// subpaths are deliberately narrow capabilities and may not overlap each
/// other at all.
fn validate_overlay_destinations(mounts: &[ValidatedMount]) -> Result<(), RunError> {
    let overlays = mounts
        .iter()
        .filter(|mount| {
            mount.placement == SandboxMountPlacement::Overlay
                && !matches!(
                    mount.authority,
                    SandboxMountAuthority::SandboxInfrastructure(_)
                )
        })
        .map(|mount| normalize_absolute_path(&mount.spec.target))
        .collect::<Vec<_>>();

    for (index, target) in overlays.iter().enumerate() {
        for other in overlays.iter().skip(index + 1) {
            if target == other {
                return Err(RunError::Backend {
                    backend: BackendKind::Bwrap.to_string(),
                    reason: format!(
                        "duplicate mount targets {} and {} would make sandbox contents depend on mount order",
                        target.display(),
                        other.display()
                    ),
                });
            }
        }
    }

    let protected = mounts
        .iter()
        .filter(|mount| mount.placement == SandboxMountPlacement::FrameworkProtectedSubpath)
        .map(|mount| normalize_absolute_path(&mount.spec.target))
        .collect::<Vec<_>>();
    for (index, target) in protected.iter().enumerate() {
        for other in protected.iter().skip(index + 1) {
            if target.starts_with(other) || other.starts_with(target) {
                return Err(RunError::Backend {
                    backend: BackendKind::Bwrap.to_string(),
                    reason: format!(
                        "overlapping protected framework mount targets {} and {} are not permitted",
                        target.display(),
                        other.display()
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Enforces the fixed destination and read-only contract for one backend-owned
/// infrastructure facility.
fn validate_infrastructure_mount(
    kind: SandboxInfrastructureKind,
    spec: &MountSpec,
) -> Result<(), RunError> {
    let valid_target = match kind {
        SandboxInfrastructureKind::Passwd => spec.target == Path::new("/etc/passwd"),
        SandboxInfrastructureKind::Group => spec.target == Path::new("/etc/group"),
        SandboxInfrastructureKind::ResolverConfig => {
            spec.target == Path::new("/etc/resolv.conf")
                || spec.target == super::resolve_resolv_conf_target()
        }
    };
    if spec.read_only && valid_target {
        return Ok(());
    }
    Err(RunError::Backend {
        backend: BackendKind::Bwrap.to_string(),
        reason: format!(
            "invalid {kind:?} sandbox-infrastructure mount at {}; infrastructure files must be read-only and use their designated target",
            spec.target.display()
        ),
    })
}

/// Resolve an absolute mount path through every existing symlink while
/// preserving a suffix that has not been created yet.
///
/// This keeps protected paths stable even before their final directory exists:
/// the nearest existing ancestor is canonicalized, then the normalized missing
/// components are restored beneath it.
fn resolve_path_allow_missing(path: &Path, description: &str) -> Result<PathBuf, RunError> {
    let absolute = std::path::absolute(path).map_err(|error| RunError::Backend {
        backend: BackendKind::Bwrap.to_string(),
        reason: format!(
            "failed to make {description} path {} absolute: {error}",
            path.display()
        ),
    })?;
    let normalized = normalize_absolute_path(&absolute);
    let mut missing = Vec::<OsString>::new();
    let mut candidate = normalized.as_path();

    loop {
        match candidate.canonicalize() {
            Ok(mut resolved) => {
                while let Some(component) = missing.pop() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(name) = candidate.file_name() else {
                    return Err(RunError::Backend {
                        backend: BackendKind::Bwrap.to_string(),
                        reason: format!(
                            "failed to resolve {description} path {}: no existing ancestor",
                            path.display()
                        ),
                    });
                };
                missing.push(name.to_os_string());
                let Some(parent) = candidate.parent() else {
                    return Err(RunError::Backend {
                        backend: BackendKind::Bwrap.to_string(),
                        reason: format!(
                            "failed to resolve {description} path {}: no parent",
                            path.display()
                        ),
                    });
                };
                candidate = parent;
            }
            Err(error) => {
                return Err(RunError::Backend {
                    backend: BackendKind::Bwrap.to_string(),
                    reason: format!(
                        "failed to resolve {description} path {}: {error}",
                        path.display()
                    ),
                });
            }
        }
    }
}

/// Lexically removes `.` and `..` components from an absolute path without
/// following filesystem links.
fn normalize_absolute_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized
                    .components()
                    .next_back()
                    .is_some_and(|part| matches!(part, Component::Normal(_)))
                {
                    normalized.pop();
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

/// Returns whether the normalized target is strictly beneath a `.firma`
/// directory without treating `.firma` itself as a permitted subpath.
fn is_strict_firma_subpath(target: &Path) -> bool {
    normalize_absolute_path(target)
        .ancestors()
        .skip(1)
        .any(|ancestor| ancestor.file_name().and_then(OsStr::to_str) == Some(CONFIG_DIR_NAME))
}

/// Assigns validated mounts to fixed phases, sorting ordinary overlays from
/// broadest target to most specific so their result is independent of input
/// order.
fn emit_mounts<'a>(plan: &mut BwrapMountPlan, mounts: impl Iterator<Item = &'a ValidatedMount>) {
    let mut mounts = mounts.collect::<Vec<_>>();
    mounts.sort_by(|left, right| {
        let left_target = normalize_absolute_path(&left.spec.target);
        let right_target = normalize_absolute_path(&right.spec.target);
        left_target
            .components()
            .count()
            .cmp(&right_target.components().count())
            .then_with(|| left_target.cmp(&right_target))
    });
    for mount in mounts {
        let role = match mount.authority {
            SandboxMountAuthority::OperatorProvided => BwrapPlanRole::OperatorProvided,
            SandboxMountAuthority::Framework => BwrapPlanRole::Framework,
            SandboxMountAuthority::SandboxInfrastructure(_) => BwrapPlanRole::SandboxInfrastructure,
        };
        let spec = &mount.spec;
        let mode = if spec.read_only {
            BwrapBindMode::ReadOnly
        } else {
            BwrapBindMode::ReadWrite
        };
        match (mount.authority, mount.placement) {
            (SandboxMountAuthority::SandboxInfrastructure(_), _) => {
                plan.infrastructure
                    .bind(role, &spec.source, &spec.target, mode);
            }
            (_, SandboxMountPlacement::FrameworkProtectedSubpath) => {
                plan.protected_subpaths
                    .bind(role, &spec.source, &spec.target, mode);
            }
            (_, SandboxMountPlacement::Overlay) => {
                plan.overlays.bind(role, &spec.source, &spec.target, mode);
            }
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
/// Masks are emitted after ordinary overlays but before the explicit
/// framework-protected subpath capability (see [`append_filesystem_layout`]),
/// so VS Code state remains available while operator-provided mounts cannot
/// acquire post-seal placement from their target spelling. A relative
/// `config_file` is resolved against the host cwd first, since bwrap
/// destinations must be absolute.
///
/// Returns the emitted mask set so the caller can project it through outside
/// binds (see [`project_mount_aliases`]).
fn mask_firma_dir(phase: &mut BwrapMountPhase, launch: &LaunchSpec) -> BTreeMap<PathBuf, MaskKind> {
    let mut masked: BTreeMap<PathBuf, MaskKind> = BTreeMap::new();

    for candidate in firma_config_loader::FirmaConfigCandidateAncestors::new(&launch.cwd, None) {
        mask_firma_dir_at(phase, &candidate.config_dir, &mut masked);
    }

    // The cwd is bound read-write, so the agent can *plant* a higher-precedence
    // `.firma/` here for a later run even when none exists today. Mask the cwd
    // candidate whether or not it currently exists; writes then land in the
    // ephemeral tmpfs instead of the host bind. Ancestors above the cwd sit on
    // the read-only root bind and are not plantable, so absent ones are skipped
    // (and tmpfs-ing them there could fail `EROFS`).
    let cwd_firma = launch.cwd.join(CONFIG_DIR_NAME);
    if !cwd_firma.exists() {
        emit_tmpfs(phase, cwd_firma, &mut masked);
    }

    if let Some(home_firma) = host_home_firma_dir(launch) {
        mask_firma_dir_at(phase, &home_firma, &mut masked);
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
            mask_firma_dir_at(phase, firma_parent, &mut masked);
        } else {
            // Bare config file whose parent is not `.firma`: hide only the file
            // (reads empty, writes fail `EROFS`) without tmpfs-ing the parent,
            // which could be the workspace root.
            mask_config_file_at(phase, &config_file, &mut masked);
        }
    }

    masked
}

/// Re-apply each mask at the aliased path it acquires under an ordinary overlay.
///
/// An operator-provided mount that binds a `.firma`-containing tree at another
/// target (e.g. the workspace rebound elsewhere) re-exposes every masked path at
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
    phase: &mut BwrapMountPhase,
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
                MaskKind::Dir => emit_tmpfs(phase, alias, &mut masked),
                MaskKind::File => emit_ro_bind_null(phase, alias, &mut masked),
            }
        }
    }
}

/// Re-establish the sandbox's own procfs over every host procfs a mount aliases.
///
/// bwrap binds recursively, so a mount whose source tree contains a procfs
/// mount point carries the host's procfs to `<target>/<relative>`. That alias is
/// the same door the layout closes at `/proc`: it enumerates host processes and
/// reopens `/proc/<pid>/root/<host path>` onto every masked path. Refusing such
/// mounts would break legitimate whole-tree binds, so each alias is covered with
/// a procfs for the sandbox's own PID namespace instead.
///
/// A path already inside a sealed one is skipped, not sealed again. The set
/// starts with the sandbox procfs the layout mounts, which matters on hosts that
/// bind parts of procfs onto itself: container runtimes do this for their
/// read-only paths (`/proc/sys`, `/proc/sysrq-trigger`, `/proc/irq`), and each
/// such point is reported as a procfs of its own. Sealing them individually
/// would replace the sandbox's sysctl tree with a second procfs root, or fail
/// the launch outright where the point is a file rather than a directory.
/// Points arrive sorted, so a parent is always sealed before its children.
///
/// A point the planning process cannot stat as an existing directory is skipped:
/// its alias does not exist inside the bound tree either, and bwrap would fail
/// the launch trying to create it. Only `NotFound` is a skip. Any other stat
/// error fails the launch, because a procfs that cannot be inspected is one that
/// cannot be proven sealed, while the recursive bind carries it in regardless of
/// whether this process could traverse the path.
fn project_procfs_aliases(
    phase: &mut BwrapMountPhase,
    mounts: &[&MountSpec],
    host_procfs: &HostProcfsMounts,
) -> Result<(), RunError> {
    let mut sealed = vec![PathBuf::from(SANDBOX_PROCFS_TARGET)];
    for mount in mounts {
        for relative in host_procfs.points_under(&mount.source) {
            let alias = normalize_absolute_path(&mount.target.join(relative));
            if sealed.iter().any(|covered| alias.starts_with(covered)) {
                continue;
            }
            let point = mount.source.join(relative);
            match std::fs::metadata(&point) {
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => continue,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(RunError::Backend {
                        backend: BackendKind::Bwrap.to_string(),
                        reason: format!(
                            "failed to inspect host procfs mount point {} while sealing its sandbox alias {}: {error}",
                            point.display(),
                            alias.display()
                        ),
                    });
                }
            }
            phase.proc(BwrapPlanRole::Mask, alias.clone());
            sealed.push(alias);
        }
    }
    Ok(())
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
pub(super) fn reject_symlinked_firma_dirs(launch: &LaunchSpec) -> Result<(), RunError> {
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

/// Rejects one discoverable `.firma` path when its directory entry is a
/// symlink, while deduplicating paths already inspected for the launch.
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
fn mask_firma_dir_at(
    phase: &mut BwrapMountPhase,
    dir: &Path,
    masked: &mut BTreeMap<PathBuf, MaskKind>,
) {
    let target = match dir.canonicalize() {
        Ok(canonical) if canonical.file_name().and_then(OsStr::to_str) != Some(CONFIG_DIR_NAME) => {
            mask_config_file_at(phase, &canonical.join(CONFIG_FILE_NAME), masked);
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
        mask_config_file_at(phase, &config_file, masked);
    }
    emit_tmpfs(phase, target, masked);
}

/// ro-bind `/dev/null` over a single config file at its canonical path, so reads
/// return empty and writes fail `EROFS` even when the file is reached through a
/// symlink. Canonicalizes first to defeat a post-discovery symlink swap, falling
/// back to the literal path if it does not resolve. Deduplicated via `masked`.
fn mask_config_file_at(
    phase: &mut BwrapMountPhase,
    file: &Path,
    masked: &mut BTreeMap<PathBuf, MaskKind>,
) {
    let target = file.canonicalize().unwrap_or_else(|_| file.to_path_buf());
    emit_ro_bind_null(phase, target, masked);
}

/// Whether a mask hides a whole `.firma/` directory or a single config file.
/// Used to re-emit the correct bwrap primitive when projecting through aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaskKind {
    Dir,
    File,
}

/// tmpfs-mask a directory once, tracking it in `masked` for dedup/projection.
fn emit_tmpfs(
    phase: &mut BwrapMountPhase,
    target: PathBuf,
    masked: &mut BTreeMap<PathBuf, MaskKind>,
) {
    if masked.insert(target.clone(), MaskKind::Dir).is_none() {
        phase.tmpfs(BwrapPlanRole::Mask, target);
    }
}

/// ro-bind `/dev/null` over a file once, tracking it in `masked` for
/// dedup/projection.
fn emit_ro_bind_null(
    phase: &mut BwrapMountPhase,
    target: PathBuf,
    masked: &mut BTreeMap<PathBuf, MaskKind>,
) {
    if masked.insert(target.clone(), MaskKind::File).is_none() {
        phase.bind(
            BwrapPlanRole::Mask,
            "/dev/null",
            target,
            BwrapBindMode::ReadOnly,
        );
    }
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
        let hardening = super::BwrapHardening::from_env(&env);
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
    fn hardening_from_cleared_profile_env_is_disabled() {
        let hardening = super::BwrapHardening::from_env(&BTreeMap::new());

        assert!(!hardening.readonly_rootfs);
        assert!(!hardening.runtime_home_isolation);
        assert!(hardening.mask_home_paths.is_empty());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_sensitive_paths_adds_expected_mounts() {
        let mut plan = super::BwrapMountPlan::empty();
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
            trust_anchor: None,
        };
        let suffixes = vec![
            ".ssh".to_string(),
            ".aws".to_string(),
            ".config/gcloud".to_string(),
        ];
        super::mask_sensitive_paths(&mut plan.config_seals, &launch, &suffixes);
        let rendered = rendered_plan(plan).join(" ");

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
            trust_anchor: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn rendered_args(cmd: &std::process::Command) -> Vec<String> {
        cmd.get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>()
    }

    #[cfg(target_os = "linux")]
    fn rendered_plan(plan: super::BwrapMountPlan) -> Vec<String> {
        let mut command = std::process::Command::new("bwrap");
        plan.emit(&mut command);
        rendered_args(&command)
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
        let mut plan = super::BwrapMountPlan::empty();
        // Config discovered in a `.firma/` above the workspace cwd (walk-up).
        let temp = tempfile::tempdir().expect("tempdir");
        let firma_dir = temp.path().join(".firma");
        std::fs::create_dir_all(&firma_dir).expect("mkdir .firma");
        let config_file = firma_dir.join("firma.toml");
        std::fs::write(&config_file, "").expect("write firma.toml");
        let launch = launch_with_cwd_and_config(temp.path().to_path_buf(), Some(config_file));

        super::mask_firma_dir(&mut plan.config_seals, &launch);

        let rendered = rendered_plan(plan).join(" ");
        assert!(rendered.contains(&format!("--tmpfs {}", canonical(&firma_dir))));
        assert!(!rendered.contains("--ro-bind /dev/null"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_masks_all_ancestor_dirs() {
        let mut plan = super::BwrapMountPlan::empty();
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

        super::mask_firma_dir(&mut plan.config_seals, &launch);

        let rendered = rendered_plan(plan).join(" ");
        assert!(rendered.contains(&format!("--tmpfs {}", canonical(&child_firma))));
        assert!(rendered.contains(&format!("--tmpfs {}", canonical(&parent_firma))));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_seals_firma_before_explicit_framework_subpath() {
        // The fixed phase order must seal `.firma` after ordinary layout mounts
        // and before the explicit VS Code state capability.
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
            mounts: vec![crate::backend::SandboxMount::framework_protected_subpath(
                crate::config::MountSpec {
                    source: vscode_state.clone(),
                    target: vscode_state.clone(),
                    read_only: false,
                },
            )],
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
        let hardening = super::BwrapHardening::from_env(&launch.env);
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));

        let plan = super::BwrapMountPlan::build(&runtime_layout, &handle, &launch, &hardening)
            .expect("build mount plan");

        let rendered = rendered_plan(plan);
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
        assert!(
            mask < vscode_mount,
            "mask must precede the VS Code state mount"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_masks_firma_under_workspace_parent_mount() {
        // Regression guard: an operator mount that binds a *parent* of `.firma/`
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
            mounts: vec![crate::backend::SandboxMount::operator_provided(
                crate::config::MountSpec {
                    source: workspace.clone(),
                    target: workspace.clone(),
                    read_only: false,
                },
            )],
            network_policy: crate::config::NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        };

        let mut env = BTreeMap::new();
        env.insert("HOME".to_string(), "/nonexistent-firma-home".to_string());
        let launch = launch_with_env(workspace.clone(), None, env);
        let hardening = super::BwrapHardening::from_env(&launch.env);
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));

        let plan = super::BwrapMountPlan::build(&runtime_layout, &handle, &launch, &hardening)
            .expect("build mount plan");

        let rendered = rendered_plan(plan);
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

    /// Sandbox handle with no mounts, used by the CA restoration tests.
    #[cfg(target_os = "linux")]
    fn handle_with(
        runtime_dir: std::path::PathBuf,
        identity: crate::identity::RunIdentity,
    ) -> crate::backend::SandboxHandle {
        crate::backend::SandboxHandle {
            backend: crate::backend::BackendKind::Bwrap,
            runtime_dir,
            identity,
            mounts: vec![],
            network_policy: crate::config::NetworkPolicy {
                enforce_network_namespace: false,
                fail_closed: true,
            },
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_restores_public_ca_material_over_control_plane_mask() {
        // The control-plane mask hides the whole runtime root, but the launch
        // environment aims `SSL_CERT_FILE` and friends at the run entry's CA.
        // Each public file must be restored individually and after the mask;
        // the signing key must stay hidden, so the CA directory is never bound
        // as a whole.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");

        let identity =
            crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let control_plane = temp.path().join("control-plane");
        let runtime_layout = firma_runtime_state::RuntimeLayout::from_root(control_plane.clone());
        let run_entry = runtime_layout.run_entry_layout(&identity.sandbox_id);
        std::fs::create_dir_all(run_entry.ca_dir()).expect("mkdir CA dir");
        for path in [
            run_entry.ca_cert(),
            run_entry.ca_bundle(),
            run_entry.ca_key(),
        ] {
            std::fs::write(&path, "").expect("write CA material");
        }

        let handle = handle_with(runtime_dir, identity);
        let mut launch = launch_with_cwd_and_config(cwd, None);
        launch.trust_anchor = Some(trust_anchor_for(&run_entry.ca_cert()));
        let hardening = super::BwrapHardening::from_env(&launch.env);

        let plan = super::BwrapMountPlan::build(&runtime_layout, &handle, &launch, &hardening)
            .expect("build mount plan");

        let rendered = rendered_plan(plan);
        let mask = rendered
            .iter()
            .position(|arg| arg == &canonical(&control_plane))
            .expect("control-plane runtime masked");
        for public in [run_entry.ca_cert(), run_entry.ca_bundle()] {
            let path = public.display().to_string();
            let bind = rendered
                .windows(3)
                .position(|win| win[0] == "--ro-bind" && win[1] == path && win[2] == path)
                .unwrap_or_else(|| panic!("{path} bound read-only through the mask"));
            assert!(
                mask < bind,
                "{path} must be restored after the control-plane mask"
            );
        }
        let key = run_entry.ca_key().display().to_string();
        assert!(
            !rendered.iter().any(|arg| arg == &key),
            "the CA signing key must never be exposed to the sandbox"
        );
        let ca_dir = run_entry.ca_dir().display().to_string();
        assert!(
            !rendered.iter().any(|arg| arg == &ca_dir),
            "binding the CA directory would also expose the signing key"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_skips_absent_ca_material() {
        // With HTTPS MITM disabled no CA is generated, and the bundle exists
        // only under `ca_trust_mode = "append_system_roots"`. Binding a missing
        // source would make bwrap abort the launch.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");

        let identity =
            crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));
        let run_entry = runtime_layout.run_entry_layout(&identity.sandbox_id);
        std::fs::create_dir_all(run_entry.root()).expect("mkdir run entry");

        let handle = handle_with(runtime_dir, identity);
        let launch = launch_with_cwd_and_config(cwd, None);
        let hardening = super::BwrapHardening::from_env(&launch.env);

        let plan = super::BwrapMountPlan::build(&runtime_layout, &handle, &launch, &hardening)
            .expect("build mount plan");

        let rendered = rendered_plan(plan);
        let ca_dir = run_entry.ca_dir().display().to_string();
        assert!(
            !rendered.iter().any(|arg| arg.starts_with(&ca_dir)),
            "no CA path should be bound when the material is absent: {rendered:?}"
        );
    }

    /// Resolve the trust anchor the way `firma run` does, from a certificate
    /// path published as a network override.
    #[cfg(target_os = "linux")]
    fn trust_anchor_for(cert: &std::path::Path) -> crate::trust::SidecarTrustAnchor {
        let overrides = BTreeMap::from([(
            "FIRMA_SIDECAR_CA_CERT_PATH".to_string(),
            cert.display().to_string(),
        )]);
        crate::trust::SidecarTrustAnchor::resolve(crate::config::CaTrustMode::Sole, &overrides)
            .expect("trust anchor resolves for an existing certificate")
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_mounts_procfs_after_the_root_bind() {
        // `--unshare-pid` alone leaves the host's inherited procfs in place,
        // and `/proc/<pid>/root/<host path>` walks around every mask through an
        // ancestor's mount namespace. The sandbox's own procfs must therefore
        // land after the read-only root bind that would otherwise cover it.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");

        let identity =
            crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));

        let handle = handle_with(runtime_dir, identity);
        let launch = launch_with_cwd_and_config(cwd, None);
        let hardening = super::BwrapHardening::from_env(&launch.env);

        let plan = super::BwrapMountPlan::build(&runtime_layout, &handle, &launch, &hardening)
            .expect("build mount plan");

        let rendered = rendered_plan(plan);
        let root_bind = rendered
            .windows(3)
            .position(|win| {
                (win[0] == "--ro-bind" || win[0] == "--bind") && win[1] == "/" && win[2] == "/"
            })
            .expect("host root bound");
        let procfs = rendered
            .windows(2)
            .position(|win| win[0] == "--proc" && win[1] == "/proc")
            .expect("sandbox procfs mounted");
        assert!(
            root_bind < procfs,
            "the procfs must be mounted after the root bind: {rendered:?}"
        );
    }

    /// Sandbox handle carrying one operator-provided mount, used by the
    /// procfs-seal tests.
    #[cfg(target_os = "linux")]
    fn handle_with_operator_mount(
        runtime_dir: std::path::PathBuf,
        source: std::path::PathBuf,
        target: std::path::PathBuf,
    ) -> crate::backend::SandboxHandle {
        let identity =
            crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "generic");
        crate::backend::SandboxHandle {
            mounts: vec![crate::backend::SandboxMount::operator_provided(
                crate::config::MountSpec {
                    source,
                    target,
                    read_only: true,
                },
            )],
            ..handle_with(runtime_dir, identity)
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_rejects_a_mount_over_the_sandbox_procfs() {
        // Overlays are emitted after the layout phase, so a mount landing on
        // `/proc` replaces the sandbox's own procfs with whatever it binds and
        // reopens `/proc/<pid>/root` onto every masked host path.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");
        let source = temp.path().join("payload");
        std::fs::create_dir_all(&source).expect("mkdir payload");

        let handle =
            handle_with_operator_mount(runtime_dir, source, std::path::PathBuf::from("/proc"));
        let launch = launch_with_cwd_and_config(cwd, None);
        let hardening = super::BwrapHardening::from_env(&launch.env);
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));

        let error = super::BwrapMountPlan::build(&runtime_layout, &handle, &launch, &hardening)
            .expect_err("a mount over the sandbox procfs must fail the launch");

        std::assert_matches!(
            &error,
            crate::error::RunError::Backend { backend, .. } if backend == "bwrap"
        );
        insta::assert_snapshot!(
            error.to_string(),
            @"backend error (bwrap): mount target /proc resolves to /proc, which is reserved for the sandbox filesystem layout; a mount there would replace the sandbox's own procfs and reopen /proc/<pid>/root onto masked host paths"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_rejects_a_mount_over_the_sandbox_root() {
        // A mount at `/` re-parents the sandbox over every baseline layout
        // step, including the procfs the layout mounts.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");
        let source = temp.path().join("payload");
        std::fs::create_dir_all(&source).expect("mkdir payload");

        let handle = handle_with_operator_mount(
            runtime_dir,
            source,
            // Spelled unnormalized: the reserved set is decided after `.` and
            // `..` components are removed.
            std::path::PathBuf::from("/tmp/.."),
        );
        let launch = launch_with_cwd_and_config(cwd, None);
        let hardening = super::BwrapHardening::from_env(&launch.env);
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));

        let error = super::BwrapMountPlan::build(&runtime_layout, &handle, &launch, &hardening)
            .expect_err("a mount over the sandbox root must fail the launch");

        std::assert_matches!(
            &error,
            crate::error::RunError::Backend { backend, .. } if backend == "bwrap"
        );
        insta::assert_snapshot!(
            error.to_string(),
            @"backend error (bwrap): mount target /tmp/.. resolves to /, which is reserved for the sandbox filesystem layout; a mount there would replace the sandbox's own procfs and reopen /proc/<pid>/root onto masked host paths"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_rejects_a_mount_target_symlinked_into_the_reserved_set() {
        // bwrap resolves the destination path at mount time, so a lexical check
        // would accept a link into the reserved set. The workspace is writable
        // by the wrapped process, which makes that link plantable.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");
        let source = temp.path().join("payload");
        std::fs::create_dir_all(&source).expect("mkdir payload");
        let link = cwd.join("proclink");
        std::os::unix::fs::symlink("/proc", &link).expect("plant reserved-target symlink");

        let handle = handle_with_operator_mount(runtime_dir, source, link.clone());
        let launch = launch_with_cwd_and_config(cwd, None);
        let hardening = super::BwrapHardening::from_env(&launch.env);
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));

        let error = super::BwrapMountPlan::build(&runtime_layout, &handle, &launch, &hardening)
            .expect_err("a symlinked reserved target must fail the launch");

        let message = error.to_string();
        assert!(
            message.contains(&link.display().to_string()),
            "the error must name the link the operator spelled: {message}"
        );
        // Only the temporary workspace path is nondeterministic; the assertion
        // above proves it was present before it is replaced.
        let redacted = message.replace(&link.display().to_string(), "[workspace]/proclink");
        insta::assert_snapshot!(
            redacted,
            @"backend error (bwrap): mount target [workspace]/proclink resolves to /proc, which is reserved for the sandbox filesystem layout; a mount there would replace the sandbox's own procfs and reopen /proc/<pid>/root onto masked host paths"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_rejects_a_procfs_backed_mount_source() {
        // A host procfs bound anywhere inside the sandbox is the same bypass at
        // a different path: `<target>/<pid>/root` still walks an ancestor's
        // mount namespace.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");

        let handle = handle_with_operator_mount(
            runtime_dir,
            // Spelled without `self`, whose canonical form carries the
            // planning process's own PID.
            std::path::PathBuf::from("/proc/sys/kernel"),
            temp.path().join("host-proc"),
        );
        let launch = launch_with_cwd_and_config(cwd, None);
        let hardening = super::BwrapHardening::from_env(&launch.env);
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));

        let error = super::BwrapMountPlan::build(&runtime_layout, &handle, &launch, &hardening)
            .expect_err("a procfs-backed mount source must fail the launch");

        std::assert_matches!(
            &error,
            crate::error::RunError::Backend { backend, .. } if backend == "bwrap"
        );
        insta::assert_snapshot!(
            error.to_string(),
            @"backend error (bwrap): refusing procfs-backed mount source /proc/sys/kernel; the host procfs exposes /proc/<pid>/root, which walks around every sandbox mask"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_seals_the_procfs_a_recursive_mount_aliases() {
        // bwrap binds recursively, so a mount of a tree containing `/proc`
        // re-exposes the host's procfs at `<target>/proc`. The alias must carry
        // the sandbox's own procfs, and it must be emitted after the mount that
        // creates it.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");
        let host_root_alias = cwd.join("host-root");
        std::fs::create_dir_all(&host_root_alias).expect("mkdir host root alias");

        let handle = handle_with_operator_mount(
            runtime_dir,
            std::path::PathBuf::from("/"),
            host_root_alias.clone(),
        );
        let launch = launch_with_cwd_and_config(cwd, None);
        let hardening = super::BwrapHardening::from_env(&launch.env);
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));

        let plan = super::BwrapMountPlan::build_against(
            &runtime_layout,
            &handle,
            &launch,
            &hardening,
            &host_procfs(&["/proc"]),
        )
        .expect("build mount plan");

        let rendered = rendered_plan(plan);
        let alias = host_root_alias.join("proc").display().to_string();
        let host_bind = rendered
            .iter()
            .position(|arg| arg == &host_root_alias.display().to_string())
            .expect("host root mount bound");
        let alias_procfs = rendered
            .windows(2)
            .position(|win| win[0] == "--proc" && win[1] == alias)
            .expect("aliased procfs sealed");
        assert!(
            host_bind < alias_procfs,
            "the aliased procfs must be sealed after the mount that exposes it: {rendered:?}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_seals_no_alias_for_a_procfs_free_mount() {
        // The seal is scoped to mounts that actually carry a procfs; an
        // ordinary workspace bind must keep its plan unchanged.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");

        let handle = handle_with_operator_mount(runtime_dir, cwd.clone(), cwd.clone());
        let launch = launch_with_cwd_and_config(cwd, None);
        let hardening = super::BwrapHardening::from_env(&launch.env);
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));

        let plan = super::BwrapMountPlan::build_against(
            &runtime_layout,
            &handle,
            &launch,
            &hardening,
            &host_procfs(&["/proc"]),
        )
        .expect("build mount plan");

        let rendered = rendered_plan(plan);
        let procfs_mounts = rendered.iter().filter(|arg| *arg == "--proc").count();
        assert_eq!(
            procfs_mounts, 1,
            "only the sandbox's own /proc should be mounted: {rendered:?}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_seals_a_second_host_procfs_without_any_mount() {
        // A host can carry a procfs outside `/proc`: a leftover
        // `mount --bind /proc /mnt/proc`, an exporter's `/host/proc`, a machine
        // directory. The backend's own host-root bind is recursive, so it
        // carries that procfs into the sandbox with no profile mount involved.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");
        let machine_procfs = temp.path().join("machine").join("proc");
        std::fs::create_dir_all(&machine_procfs).expect("mkdir second procfs");

        let identity =
            crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let handle = handle_with(runtime_dir, identity);
        let launch = launch_with_cwd_and_config(cwd, None);
        let hardening = super::BwrapHardening::from_env(&launch.env);
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));

        let plan = super::BwrapMountPlan::build_against(
            &runtime_layout,
            &handle,
            &launch,
            &hardening,
            &host_procfs(&["/proc", &machine_procfs.display().to_string()]),
        )
        .expect("build mount plan");

        let rendered = rendered_plan(plan);
        let sealed = rendered
            .windows(2)
            .filter(|win| win[0] == "--proc")
            .map(|win| win[1].clone())
            .collect::<Vec<_>>();
        assert_eq!(
            sealed,
            vec!["/proc".to_string(), machine_procfs.display().to_string()],
            "both the sandbox procfs and the second host procfs must be sealed, once each: {rendered:?}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_skips_a_procfs_the_host_no_longer_exposes() {
        // A mount point shadowed on the host by a later mount has no directory
        // inside the bound tree either. Asking bwrap to mount there would fail
        // the launch with `Can't mkdir` and seal nothing.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");
        let shadowed = temp.path().join("shadowed").join("proc");

        let identity =
            crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let handle = handle_with(runtime_dir, identity);
        let launch = launch_with_cwd_and_config(cwd, None);
        let hardening = super::BwrapHardening::from_env(&launch.env);
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));

        let plan = super::BwrapMountPlan::build_against(
            &runtime_layout,
            &handle,
            &launch,
            &hardening,
            &host_procfs(&["/proc", &shadowed.display().to_string()]),
        )
        .expect("build mount plan");

        let rendered = rendered_plan(plan);
        assert!(
            !rendered.contains(&shadowed.display().to_string()),
            "an unreachable procfs must not enter the plan: {rendered:?}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_seals_a_container_mount_table_once() {
        // Container runtimes bind parts of procfs onto itself for their
        // read-only paths, and the kernel reports each as a procfs of its own.
        // Sealing them individually would swap the sandbox's sysctl tree for a
        // second procfs root, and `/proc/sysrq-trigger` is a file, so bwrap
        // would fail the launch outright.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");

        let identity =
            crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let handle = handle_with(runtime_dir, identity);
        let launch = launch_with_cwd_and_config(cwd, None);
        let hardening = super::BwrapHardening::from_env(&launch.env);
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));

        let plan = super::BwrapMountPlan::build_against(
            &runtime_layout,
            &handle,
            &launch,
            &hardening,
            &host_procfs(&["/proc", "/proc/sys", "/proc/sysrq-trigger"]),
        )
        .expect("build mount plan");

        let rendered = rendered_plan(plan);
        let sealed = rendered
            .windows(2)
            .filter(|win| win[0] == "--proc")
            .map(|win| win[1].clone())
            .collect::<Vec<_>>();
        assert_eq!(
            sealed,
            vec!["/proc".to_string()],
            "a procfs nested in the sandbox procfs must not be sealed again: {rendered:?}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_skips_a_file_backed_procfs_point() {
        // `--proc` needs a directory. A point that is a file inside the bound
        // tree would fail the launch with bwrap's own `Can't mkdir`.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");
        let file_point = temp.path().join("machine-proc");
        std::fs::write(&file_point, "").expect("write file-backed procfs point");

        let identity =
            crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let handle = handle_with(runtime_dir, identity);
        let launch = launch_with_cwd_and_config(cwd, None);
        let hardening = super::BwrapHardening::from_env(&launch.env);
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));

        let plan = super::BwrapMountPlan::build_against(
            &runtime_layout,
            &handle,
            &launch,
            &hardening,
            &host_procfs(&["/proc", &file_point.display().to_string()]),
        )
        .expect("build mount plan");

        let rendered = rendered_plan(plan);
        assert!(
            !rendered.contains(&file_point.display().to_string()),
            "a file-backed procfs point must not enter the plan: {rendered:?}"
        );
    }

    /// Procfs inventory for a synthetic mount table, so plan assertions do not
    /// depend on the mount points of the machine running the tests.
    #[cfg(target_os = "linux")]
    fn host_procfs(mount_points: &[&str]) -> super::HostProcfsMounts {
        use std::fmt::Write as _;

        let mut mountinfo = String::new();
        for (index, point) in mount_points.iter().enumerate() {
            let _ = writeln!(
                mountinfo,
                "{index} 28 0:22 / {point} rw,relatime shared:14 - proc proc rw"
            );
        }
        super::HostProcfsMounts::from_mountinfo(&mountinfo).expect("parse synthetic mountinfo")
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn procfs_aliases_are_sealed_once_per_destination() {
        // Two mounts exposing the same tree at the same target would otherwise
        // stack one procfs on another.
        let mut phase = super::BwrapMountPhase::default();
        let mounts = [
            crate::config::MountSpec {
                source: std::path::PathBuf::from("/"),
                target: std::path::PathBuf::from("/mnt/host"),
                read_only: true,
            },
            crate::config::MountSpec {
                source: std::path::PathBuf::from("/"),
                target: std::path::PathBuf::from("/mnt/host"),
                read_only: true,
            },
        ];
        let specs = mounts.iter().collect::<Vec<_>>();
        let host_procfs = super::HostProcfsMounts::from_mountinfo(
            "23 28 0:22 / /proc rw,relatime shared:14 - proc proc rw\n",
        )
        .expect("parse mountinfo");

        super::project_procfs_aliases(&mut phase, &specs, &host_procfs).expect("project aliases");

        let mut command = std::process::Command::new("bwrap");
        phase.emit(&mut command);
        let rendered = rendered_args(&command);
        assert_eq!(rendered, vec!["--proc", "/mnt/host/proc"]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_rejects_a_masked_trust_anchor_outside_this_run() {
        // An external Sidecar can publish a CA that lives inside
        // `FIRMA_STATE_DIR` but not in this run's entry. The mask hides it and
        // the plan cannot restore it, so the wrapped process would open an
        // unreadable trust store and silently fall back to the system roots.
        // Failing the launch is the only honest outcome.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");

        let identity =
            crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let control_plane = temp.path().join("control-plane");
        let runtime_layout = firma_runtime_state::RuntimeLayout::from_root(control_plane.clone());
        let external_ca = control_plane.join("external-ca");
        std::fs::create_dir_all(&external_ca).expect("mkdir external CA dir");
        let external_cert = external_ca.join("firma-ca.crt");
        std::fs::write(&external_cert, "").expect("write external CA cert");

        let handle = handle_with(runtime_dir, identity);
        let mut launch = launch_with_cwd_and_config(cwd, None);
        launch.trust_anchor = Some(trust_anchor_for(&external_cert));
        let hardening = super::BwrapHardening::from_env(&launch.env);

        let error = super::BwrapMountPlan::build(&runtime_layout, &handle, &launch, &hardening)
            .expect_err("a masked, unrestorable trust anchor must fail the launch");

        std::assert_matches!(
            &error,
            crate::error::RunError::Backend { backend, .. } if backend == "bwrap"
        );
        let message = error.to_string();
        assert!(
            message.contains(&external_cert.display().to_string()),
            "the error must name the offending anchor: {message}"
        );
        assert!(
            message.contains("FIRMA_STATE_DIR"),
            "the error must tell the operator how to fix it: {message}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_rejects_a_trust_anchor_this_run_cannot_restore() {
        // The anchor names a path this run's layout owns, but the file is not
        // there — the appended bundle is written only under
        // `ca_trust_mode = "append_system_roots"`, and either file can be
        // removed between anchor resolution and planning. The bind loop skips
        // absent sources, so accepting the anchor on its spelling alone would
        // leave the wrapped process pointed at a path the mask still hides.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");

        let identity =
            crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));
        let run_entry = runtime_layout.run_entry_layout(&identity.sandbox_id);
        std::fs::create_dir_all(run_entry.ca_dir()).expect("mkdir CA dir");
        // Resolve the anchor against a real bundle, then remove it.
        std::fs::write(run_entry.ca_bundle(), "").expect("write CA bundle");
        let anchor = trust_anchor_for(&run_entry.ca_bundle());
        std::fs::remove_file(run_entry.ca_bundle()).expect("remove CA bundle");

        let handle = handle_with(runtime_dir, identity);
        let mut launch = launch_with_cwd_and_config(cwd, None);
        launch.trust_anchor = Some(anchor);
        let hardening = super::BwrapHardening::from_env(&launch.env);

        let error = super::BwrapMountPlan::build(&runtime_layout, &handle, &launch, &hardening)
            .expect_err("an anchor this run does not restore must fail the launch");

        std::assert_matches!(
            &error,
            crate::error::RunError::Backend { backend, .. } if backend == "bwrap"
        );
        let message = error.to_string();
        assert!(
            message.contains(&run_entry.ca_bundle().display().to_string()),
            "the error must name the offending anchor: {message}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_accepts_a_trust_anchor_outside_the_control_plane_runtime() {
        // An external Sidecar keeping its CA outside `FIRMA_STATE_DIR` is the
        // supported arrangement: the mask never covers that path, so there is
        // nothing to restore and nothing to reject.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");
        let external_cert = temp.path().join("firma-ca.crt");
        std::fs::write(&external_cert, "").expect("write external CA cert");

        let identity =
            crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));

        let handle = handle_with(runtime_dir, identity);
        let mut launch = launch_with_cwd_and_config(cwd, None);
        launch.trust_anchor = Some(trust_anchor_for(&external_cert));
        let hardening = super::BwrapHardening::from_env(&launch.env);

        let plan = super::BwrapMountPlan::build(&runtime_layout, &handle, &launch, &hardening)
            .expect("build mount plan");

        let rendered = rendered_plan(plan);
        assert!(
            !rendered
                .iter()
                .any(|arg| arg == &external_cert.display().to_string()),
            "an unmasked anchor needs no bind: {rendered:?}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_normalizes_ca_paths_against_the_resolved_runtime_root() {
        // bwrap resolves bind targets against its own root, so every emitted
        // path must be normalized. The plan resolves the control-plane root but
        // used to derive the run entry from the layout's raw spelling, which
        // left `..` components (or, for a relative `FIRMA_STATE_DIR`, a
        // relative path) in the CA binds while the mask covered the resolved
        // path.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");

        let identity =
            crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let control_plane = temp.path().join("control-plane");
        let resolved = firma_runtime_state::RuntimeLayout::from_root(control_plane.clone());
        std::fs::create_dir_all(resolved.run_entry_layout(&identity.sandbox_id).ca_dir())
            .expect("mkdir CA dir");
        std::fs::write(
            resolved.run_entry_layout(&identity.sandbox_id).ca_cert(),
            "",
        )
        .expect("write CA cert");

        // Same directory, spelled with a traversal component.
        let unnormalized = firma_runtime_state::RuntimeLayout::from_root(
            control_plane.join("..").join("control-plane"),
        );

        let handle = handle_with(runtime_dir, identity.clone());
        let launch = launch_with_cwd_and_config(cwd, None);
        let hardening = super::BwrapHardening::from_env(&launch.env);

        let plan = super::BwrapMountPlan::build(&unnormalized, &handle, &launch, &hardening)
            .expect("build mount plan");

        let rendered = rendered_plan(plan);
        assert!(
            rendered.iter().all(|arg| !arg.contains("/..")),
            "every emitted path must be normalized: {rendered:?}"
        );
        let cert = resolved
            .run_entry_layout(&identity.sandbox_id)
            .ca_cert()
            .display()
            .to_string();
        assert!(
            rendered.iter().any(|arg| arg == &cert),
            "the CA certificate must be bound at its resolved path: {rendered:?}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filesystem_layout_restores_only_the_current_run_ca() {
        // Run entries are siblings under `<runtime>/run`. A concurrent run's CA
        // must stay behind the mask: the plan is keyed on this sandbox's
        // identity, not on whatever CA files happen to exist.
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let runtime_dir = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime_dir).expect("mkdir runtime");

        let identity =
            crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let other = crate::identity::RunIdentity::new(crate::identity::test_agent_id(), "generic");
        let runtime_layout =
            firma_runtime_state::RuntimeLayout::from_root(temp.path().join("control-plane"));
        let run_entry = runtime_layout.run_entry_layout(&identity.sandbox_id);
        let other_entry = runtime_layout.run_entry_layout(&other.sandbox_id);
        for entry in [&run_entry, &other_entry] {
            std::fs::create_dir_all(entry.ca_dir()).expect("mkdir CA dir");
            std::fs::write(entry.ca_cert(), "").expect("write CA cert");
        }

        let handle = handle_with(runtime_dir, identity);
        let launch = launch_with_cwd_and_config(cwd, None);
        let hardening = super::BwrapHardening::from_env(&launch.env);

        let plan = super::BwrapMountPlan::build(&runtime_layout, &handle, &launch, &hardening)
            .expect("build mount plan");

        let rendered = rendered_plan(plan);
        let own_cert = run_entry.ca_cert().display().to_string();
        let other_cert = other_entry.ca_cert().display().to_string();
        assert!(
            rendered.iter().any(|arg| arg == &own_cert),
            "this run's CA certificate must be restored"
        );
        assert!(
            !rendered.iter().any(|arg| arg == &other_cert),
            "another run's CA certificate must stay behind the mask"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_masks_home_firma_outside_cwd_ancestry() {
        let mut plan = super::BwrapMountPlan::empty();
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

        super::mask_firma_dir(&mut plan.config_seals, &launch);

        let rendered = rendered_plan(plan).join(" ");
        assert!(rendered.contains(&format!("--tmpfs {}", canonical(&home_firma))));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_fails_closed_when_canonicalize_errors() {
        let mut plan = super::BwrapMountPlan::empty();
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

        super::mask_firma_dir(&mut plan.config_seals, &launch);

        let rendered = rendered_plan(plan).join(" ");
        assert!(rendered.contains(&format!("--tmpfs {}", link.display())));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_follows_symlink_swap_to_real_path() {
        let mut plan = super::BwrapMountPlan::empty();
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

        super::mask_firma_dir(&mut plan.config_seals, &launch);

        let rendered = rendered_plan(plan).join(" ");
        assert!(rendered.contains(&format!("--tmpfs {}", canonical(&real_firma))));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_ignores_symlink_to_non_firma_dir() {
        let mut plan = super::BwrapMountPlan::empty();
        // `.firma` symlinked at the workspace root: canonicalizing resolves to a
        // non-`.firma` directory, so we must NOT tmpfs it (that would hide the
        // whole workspace).
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).expect("mkdir workspace");
        let link = cwd.join(".firma");
        std::os::unix::fs::symlink(&cwd, &link).expect("symlink .firma -> workspace");

        let launch = launch_with_cwd_and_config(cwd, None);

        super::mask_firma_dir(&mut plan.config_seals, &launch);

        let rendered = rendered_plan(plan);
        assert!(
            rendered.iter().all(|arg| arg != "--tmpfs"),
            "must not tmpfs a symlink that resolves outside a .firma dir"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_masks_bare_file_without_tmpfsing_parent() {
        let mut plan = super::BwrapMountPlan::empty();
        // Explicit --config pointing at a bare file: parent is not `.firma`, so
        // we must NOT tmpfs the parent (it could be the workspace root); only the
        // file itself is masked. The absent cwd `.firma` is still masked to block
        // planting, but that is a sibling of the file, not the parent.
        let temp = tempfile::tempdir().expect("tempdir");
        let config_file = temp.path().join("firma.toml");
        std::fs::write(&config_file, "").expect("write firma.toml");
        let launch =
            launch_with_cwd_and_config(temp.path().to_path_buf(), Some(config_file.clone()));

        super::mask_firma_dir(&mut plan.config_seals, &launch);

        let rendered = rendered_plan(plan);
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
        let mut plan = super::BwrapMountPlan::empty();
        // `--config ./firma.toml`: relative paths must be made absolute or bwrap
        // aborts the sandbox (fail-closed DENY) on a relative mount target.
        let temp = tempfile::tempdir().expect("tempdir");
        let config_file = temp.path().join("firma.toml");
        std::fs::write(&config_file, "").expect("write firma.toml");
        let launch = launch_with_cwd_and_config(
            temp.path().to_path_buf(),
            Some(std::path::PathBuf::from("firma.toml")),
        );

        super::mask_firma_dir(&mut plan.config_seals, &launch);

        let rendered = rendered_plan(plan).join(" ");
        assert!(rendered.contains(&format!("--ro-bind /dev/null {}", canonical(&config_file))));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn mask_firma_dir_masks_absent_cwd_candidate_to_block_planting() {
        let mut plan = super::BwrapMountPlan::empty();
        // No `.firma/` anywhere and no `--config`: the only mask is the absent
        // cwd candidate, tmpfs'd so the agent can't plant a higher-precedence
        // `.firma/` at the rw-bound cwd for a later run to select. Ancestors
        // above the cwd are absent too but not plantable, so they stay unmasked.
        let temp = tempfile::tempdir().expect("tempdir");
        let launch = launch_with_cwd_and_config(temp.path().to_path_buf(), None);

        super::mask_firma_dir(&mut plan.config_seals, &launch);

        let rendered = rendered_plan(plan);
        assert_eq!(
            rendered,
            vec![
                "--tmpfs".to_string(),
                temp.path().join(".firma").display().to_string(),
            ],
            "only the absent cwd `.firma` is masked"
        );
    }
}

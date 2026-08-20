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
use firma_config_loader::{CONFIG_DIR_NAME, CONFIG_FILE_NAME};

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
}

impl BwrapMountPlan {
    /// Creates a plan with no filesystem operations in any phase.
    fn empty() -> Self {
        Self {
            layout: BwrapMountPhase::default(),
            overlays: BwrapMountPhase::default(),
            config_seals: BwrapMountPhase::default(),
            protected_subpaths: BwrapMountPhase::default(),
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
        handle: &SandboxHandle,
        launch: &LaunchSpec,
        hardening: &BwrapHardening,
    ) -> Result<Self, RunError> {
        let runtime_layout = firma_runtime_state::RuntimeLayout::resolve(None)
            .map_err(|error| RunError::Internal(format!("resolve runtime layout: {error}")))?;
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
        let mounts = validate_mounts(handle, &control_plane_runtime, &sandbox_runtime)?;
        let mut plan = Self::empty();
        append_filesystem_layout(
            &mut plan,
            handle,
            &mounts,
            &control_plane_runtime,
            &sandbox_runtime,
            launch,
            hardening,
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
/// 5. the control-plane runtime seal;
/// 6. the private runtime for the current sandbox;
/// 7. narrowly validated sandbox infrastructure sourced from that runtime.
fn append_filesystem_layout(
    plan: &mut BwrapMountPlan,
    handle: &SandboxHandle,
    mounts: &[ValidatedMount],
    control_plane_runtime: &Path,
    sandbox_runtime: &Path,
    launch: &LaunchSpec,
    hardening: &BwrapHardening,
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

    mask_control_plane_runtime(plan, mounts, control_plane_runtime, sandbox_runtime, launch)?;
    Ok(())
}

/// Hide host-side Firma runtime state from the wrapped process tree.
///
/// The read-only host-root bind prevents mutation but not disclosure. The
/// runtime root contains per-run Sidecar and Authority sockets, configuration,
/// metadata, signing keys, and capability seeds, none of which the wrapped
/// process needs. The sandbox-local bwrap runtime remains available separately
/// because the proxy bridge and egress guard require its sockets.
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

/// Resolves every prepared mount to the exact host source that will be emitted
/// and enforces the source, target, and placement constraints associated with
/// its authority.
fn validate_mounts(
    handle: &SandboxHandle,
    control_plane_runtime: &Path,
    sandbox_runtime: &Path,
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

        let plan =
            super::BwrapMountPlan::build(&handle, &launch, &hardening).expect("build mount plan");

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

        let plan =
            super::BwrapMountPlan::build(&handle, &launch, &hardening).expect("build mount plan");

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

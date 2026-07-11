use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use super::contract::Contract;
use super::error::{InitError, InitResult};
use super::log;

/// Guest root where the host runner's virtiofs shares are mounted.
pub const SHARE_ROOT: &str = "/firma-shares";
const MODULE_DIR: &str = "/lib/modules/firma-vz";
const PTMX_PATH: &str = "/dev/ptmx";
const PTMX_SYMLINK_SOURCE: &str = "pts/ptmx";
const REQUIRED_MODULES: &[&str] = &[
    "virtio.ko",
    "virtio_ring.ko",
    "virtio_pci_legacy_dev.ko",
    "virtio_pci_modern_dev.ko",
    "virtio_pci.ko",
    "virtio_mmio.ko",
    "virtio_blk.ko",
    "virtio_console.ko",
    "fuse.ko",
    "virtiofs.ko",
];

/// Creates a guest directory from a static path string.
pub fn create_dir(path: &str) -> InitResult<()> {
    fs::create_dir_all(path).map_err(|error| InitError::CreateDir {
        path: PathBuf::from(path),
        source: error,
    })
}

/// Creates a guest directory from a path value.
pub fn create_dir_path(path: &Path) -> InitResult<()> {
    fs::create_dir_all(path).map_err(|error| InitError::CreateDir {
        path: path.to_path_buf(),
        source: error,
    })
}

/// Mounts an early pseudo filesystem such as devtmpfs, proc, or sysfs.
pub fn mount_pseudo(
    source: &'static str,
    target: &'static str,
    file_system: &'static str,
) -> InitResult<()> {
    mount(source, target, file_system, 0).map_err(|error| InitError::MountPseudo {
        file_system,
        target,
        source: error,
    })
}

/// Mounts devpts and provides `/dev/ptmx` for guest command PTYs.
pub fn setup_pty_devices() -> InitResult<()> {
    create_dir("/dev/pts")?;
    mount_pseudo("devpts", "/dev/pts", "devpts")?;
    ensure_ptmx_symlink(
        Path::new(PTMX_SYMLINK_SOURCE),
        Path::new(PTMX_PATH),
        |path| fs::metadata(path).map(|_| ()),
        |source, target| symlink(source, target),
    )?;

    log("mounted devpts for guest command PTYs");

    Ok(())
}

/// Ensures `/dev/ptmx` exists without hiding metadata failures.
fn ensure_ptmx_symlink(
    source: &Path,
    target: &Path,
    stat_ptmx: impl FnOnce(&Path) -> io::Result<()>,
    create_symlink: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> InitResult<()> {
    match stat_ptmx(target) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_symlink(source, target).map_err(|error| InitError::CreateSymlink {
                from: source.to_path_buf(),
                to: target.to_path_buf(),
                source: error,
            })?;
        }
        Err(source) => {
            return Err(InitError::StatPtmx {
                path: target.to_path_buf(),
                source,
            });
        }
    }
    Ok(())
}

/// Mounts the runner-provided virtiofs share at the guest share root.
pub fn mount_virtiofs(tag: &str, target: &'static str) -> InitResult<()> {
    mount(tag, target, "virtiofs", libc::MS_NOSUID | libc::MS_NODEV).map_err(|error| {
        InitError::MountVirtiofs {
            tag: tag.to_string(),
            target,
            source: error,
        }
    })
}

/// Bind-mounts each contract share into its requested guest target.
pub fn mount_contract_paths(contract: &Contract) -> InitResult<()> {
    for (index, mount) in contract.mounts().iter().enumerate() {
        let source = Path::new(SHARE_ROOT).join(format!("mount{index}"));
        if !source.is_dir() {
            return Err(InitError::MissingShareSource { path: source });
        }
        bind_mount(&source, &mount.target, mount.read_only)?;
        log(&format!(
            "mounted {} at {} read_only={}",
            source.display(),
            mount.target.display(),
            mount.read_only
        ));
    }
    Ok(())
}

/// Performs a bind mount and optionally remounts it read-only.
fn bind_mount(source: &Path, target: &Path, read_only: bool) -> InitResult<()> {
    create_dir_path(target)?;
    mount_path(source, target, None, libc::MS_BIND | libc::MS_REC).map_err(|error| {
        InitError::BindMount {
            source: source.to_path_buf(),
            target: target.to_path_buf(),
            error,
        }
    })?;
    if read_only {
        mount_path(
            source,
            target,
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        )
        .map_err(|error| InitError::RemountReadOnly {
            source: source.to_path_buf(),
            target: target.to_path_buf(),
            error,
        })?;
    }
    Ok(())
}

/// Mounts string-backed paths with a string filesystem type.
fn mount(source: &str, target: &str, file_system: &str, flags: libc::c_ulong) -> io::Result<()> {
    let source = c_string(source)?;
    let target = c_string(target)?;
    let file_system = c_string(file_system)?;
    mount_raw(&source, &target, Some(&file_system), flags)
}

/// Mounts path-backed sources and targets.
fn mount_path(
    source: &Path,
    target: &Path,
    file_system: Option<&str>,
    flags: libc::c_ulong,
) -> io::Result<()> {
    let source = path_c_string(source)?;
    let target = path_c_string(target)?;
    let file_system = file_system.map(c_string).transpose()?;
    mount_raw(&source, &target, file_system.as_ref(), flags)
}

/// Calls the Linux `mount(2)` syscall.
fn mount_raw(
    source: &CString,
    target: &CString,
    file_system: Option<&CString>,
    flags: libc::c_ulong,
) -> io::Result<()> {
    let result = unsafe {
        libc::mount(
            source.as_ptr().cast(),
            target.as_ptr().cast(),
            file_system.map_or(std::ptr::null(), |value| value.as_ptr().cast()),
            flags,
            std::ptr::null(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Converts a string into a NUL-free C string for syscalls.
fn c_string(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
}

/// Converts a UTF-8 path into a NUL-free C string for syscalls.
fn path_c_string(value: &Path) -> io::Result<CString> {
    let value = value
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not UTF-8"))?;
    c_string(value)
}

/// Probes bundled virtio modules when the guest image does not build them in.
pub fn load_required_modules() {
    let summary = probe_module_bundle(Path::new(MODULE_DIR), REQUIRED_MODULES, load_module);
    log_module_probe_summary(&summary);
}

/// Probes a module bundle and returns the observed loader state.
pub fn probe_module_bundle(
    module_dir: &Path,
    modules: &[&str],
    mut load: impl FnMut(&Path) -> InitResult<ModuleLoad>,
) -> ModuleProbeSummary {
    if !module_dir.is_dir() {
        return ModuleProbeSummary::no_bundle();
    }

    let mut summary = ModuleProbeSummary::available();
    for module in modules {
        let path = module_dir.join(module);
        if !path.is_file() {
            continue;
        }

        if !summary.record(&path, load(&path)) {
            break;
        }
    }

    summary
}

/// Logs the module probe result after probing has completed.
fn log_module_probe_summary(summary: &ModuleProbeSummary) {
    match &summary.state {
        ModuleLoaderState::NoBundle => {
            log("no guest module bundle found; assuming required drivers are built in");
        }
        ModuleLoaderState::UnsupportedByKernel { module } => {
            log(&format!(
                "kernel does not implement module loading while probing {}; assuming required drivers are built in",
                module.display()
            ));
        }
        ModuleLoaderState::Available => {
            for failure in &summary.failures {
                log(&format!(
                    "optional module probe failed for {}: {}; continuing until a required device or filesystem is unavailable",
                    failure.path.display(),
                    failure.error
                ));
            }
            log(&format!(
                "module probe completed attempted={} loaded={} already_loaded={} failed={}",
                summary.attempted,
                summary.loaded,
                summary.already_loaded,
                summary.failures.len()
            ));
        }
    }
}

/// Result of probing the bundled guest modules.
#[derive(Debug, Eq, PartialEq)]
pub struct ModuleProbeSummary {
    /// Whether module loading was available, unavailable, or unnecessary.
    pub state: ModuleLoaderState,
    /// Number of module files passed to the loader.
    pub attempted: usize,
    /// Number of modules loaded successfully.
    pub loaded: usize,
    /// Number of modules the kernel reported as already loaded.
    pub already_loaded: usize,
    /// Non-fatal module loading failures.
    pub failures: Vec<ModuleProbeFailure>,
}

impl ModuleProbeSummary {
    /// Creates a summary for images that do not carry a module bundle.
    const fn no_bundle() -> Self {
        Self {
            state: ModuleLoaderState::NoBundle,
            attempted: 0,
            loaded: 0,
            already_loaded: 0,
            failures: Vec::new(),
        }
    }

    /// Creates a summary for images where module loading can be attempted.
    const fn available() -> Self {
        Self {
            state: ModuleLoaderState::Available,
            attempted: 0,
            loaded: 0,
            already_loaded: 0,
            failures: Vec::new(),
        }
    }

    /// Records one module load attempt and returns whether probing should continue.
    fn record(&mut self, path: &Path, result: InitResult<ModuleLoad>) -> bool {
        self.attempted += 1;
        match result {
            Ok(ModuleLoad::Loaded) => {
                self.loaded += 1;
                true
            }
            Ok(ModuleLoad::AlreadyLoaded) => {
                self.already_loaded += 1;
                true
            }
            Err(InitError::LoadModule { source, .. })
                if source.raw_os_error() == Some(libc::ENOSYS) =>
            {
                self.state = ModuleLoaderState::UnsupportedByKernel {
                    module: path.to_path_buf(),
                };
                false
            }
            Err(error) => {
                self.failures.push(ModuleProbeFailure {
                    path: path.to_path_buf(),
                    error: error.to_string(),
                });
                true
            }
        }
    }
}

/// Kernel module loading support observed during probing.
#[derive(Debug, Eq, PartialEq)]
pub enum ModuleLoaderState {
    /// No module bundle was present in the guest image.
    NoBundle,
    /// Module loading can be attempted.
    Available,
    /// The kernel does not implement the module loading syscall.
    UnsupportedByKernel {
        /// Module path that proved module loading is unsupported.
        module: PathBuf,
    },
}

/// Non-fatal failure observed while probing one bundled module.
#[derive(Debug, Eq, PartialEq)]
pub struct ModuleProbeFailure {
    /// Module path that failed to load.
    pub path: PathBuf,
    /// Stable display form of the typed init error.
    pub error: String,
}

/// Loads one kernel module with `finit_module(2)`.
pub fn load_module(path: &Path) -> InitResult<ModuleLoad> {
    let file = File::open(path).map_err(|error| InitError::OpenModule {
        path: path.to_path_buf(),
        source: error,
    })?;
    let params = c_string("").map_err(|error| InitError::ModuleParams { source: error })?;
    let result =
        unsafe { libc::syscall(libc::SYS_finit_module, file.as_raw_fd(), params.as_ptr(), 0) };
    if result == 0 {
        log(&format!("loaded module {}", path.display()));
        Ok(ModuleLoad::Loaded)
    } else {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EEXIST) {
            log(&format!("module already loaded {}", path.display()));
            Ok(ModuleLoad::AlreadyLoaded)
        } else {
            Err(InitError::LoadModule {
                path: path.to_path_buf(),
                source: error,
            })
        }
    }
}

/// Result of probing one bundled kernel module.
pub enum ModuleLoad {
    /// The module was loaded by this probe.
    Loaded,
    /// The kernel reported that the module was already loaded.
    AlreadyLoaded,
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::error::Error;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    #[test]
    fn ptmx_setup_leaves_existing_device_alone() -> TestResult {
        let symlink_called = Cell::new(false);

        ensure_ptmx_symlink(
            Path::new(PTMX_SYMLINK_SOURCE),
            Path::new(PTMX_PATH),
            |_target| Ok(()),
            |_source, _target| {
                symlink_called.set(true);
                Ok(())
            },
        )?;

        assert!(!symlink_called.get());

        Ok(())
    }

    #[test]
    fn ptmx_setup_creates_symlink_when_missing() -> TestResult {
        let symlink_called = Cell::new(false);

        ensure_ptmx_symlink(
            Path::new(PTMX_SYMLINK_SOURCE),
            Path::new(PTMX_PATH),
            |_target| Err(io::Error::new(io::ErrorKind::NotFound, "missing")),
            |source, target| {
                assert_eq!(source, Path::new(PTMX_SYMLINK_SOURCE));
                assert_eq!(target, Path::new(PTMX_PATH));
                symlink_called.set(true);
                Ok(())
            },
        )?;

        assert!(symlink_called.get());

        Ok(())
    }

    #[test]
    fn ptmx_setup_reports_metadata_errors() -> TestResult {
        let symlink_called = Cell::new(false);
        let result = ensure_ptmx_symlink(
            Path::new(PTMX_SYMLINK_SOURCE),
            Path::new(PTMX_PATH),
            |_target| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "permission denied",
                ))
            },
            |_source, _target| {
                symlink_called.set(true);
                Ok(())
            },
        );

        let Err(InitError::StatPtmx { path, source }) = result else {
            return Err(io::Error::other("expected StatPtmx").into());
        };

        assert_eq!(path, PathBuf::from(PTMX_PATH));
        assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
        assert!(!symlink_called.get());

        Ok(())
    }
}

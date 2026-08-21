//! Host filesystem layout for one VZ guest launch.

use std::path::PathBuf;

/// Paths shared by VZ launch preparation, execution, and result handling.
pub struct VzGuestLayout {
    runtime_dir: PathBuf,
}

impl VzGuestLayout {
    /// Create a VZ guest layout beneath the sandbox runtime directory.
    pub fn from_runtime_dir(runtime_dir: impl Into<PathBuf>) -> Self {
        Self {
            runtime_dir: runtime_dir.into(),
        }
    }

    /// Return the private directory containing VZ guest artifacts.
    pub fn guest_dir(&self) -> PathBuf {
        self.runtime_dir.join("vz-guest")
    }

    /// Return the launch contract consumed by the VZ runner.
    #[cfg(test)]
    pub fn launch_contract(&self) -> PathBuf {
        self.guest_dir().join("vz-guest-launch.json")
    }

    /// Return the log receiving the guest's serial-console output.
    #[cfg(target_os = "macos")]
    pub fn serial_log(&self) -> PathBuf {
        self.guest_dir().join("serial.log")
    }

    /// Return a guest-owned artifact named `file_name`.
    #[cfg(target_os = "macos")]
    pub fn guest_file(&self, file_name: &str) -> PathBuf {
        self.guest_dir().join(file_name)
    }

    /// Return the guest heartbeat path used for startup diagnostics.
    #[cfg(target_os = "macos")]
    pub fn heartbeat(&self) -> PathBuf {
        self.guest_file("guest-heartbeat.json")
    }

    /// Return the guest command-result path used to determine runner exit status.
    #[cfg(target_os = "macos")]
    pub fn result(&self) -> PathBuf {
        self.guest_file("guest-result.json")
    }
}

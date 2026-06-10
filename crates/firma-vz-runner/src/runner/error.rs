use thiserror::Error;

pub type RunnerResult<T> = std::result::Result<T, RunnerError>;

#[derive(Debug, Error)]
pub enum RunnerError {
    #[cfg(target_os = "macos")]
    #[error(
        "Apple Virtualization guest execution is not implemented yet; parsed contract v{version} \
         for sandbox {sandbox_id} and confirmed {bootloader_type} is available"
    )]
    AppleVzExecutionNotImplemented {
        version: u32,
        sandbox_id: String,
        bootloader_type: &'static str,
    },
    #[cfg(not(target_os = "macos"))]
    #[error("firma-vz-runner is macOS-only; parsed contract v{version} for sandbox {sandbox_id}")]
    UnsupportedHost { version: u32, sandbox_id: String },
}

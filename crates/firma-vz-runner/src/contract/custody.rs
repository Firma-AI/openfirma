use std::path::Path;

use anyhow::Result;

#[cfg(unix)]
/// Validates that a launch contract file is not group- or world-accessible.
///
/// Contract custody is checked before JSON parsing because the file may contain
/// launch context that should only be readable by the user running the sandbox.
pub fn validate_contract_file_access(path: &Path) -> Result<()> {
    use anyhow::Context;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path)
        .with_context(|| format!("stat VZ launch contract {}", path.display()))?;

    validate_contract_file_mode(path, metadata.permissions().mode())
}

#[cfg(unix)]
/// Validates a launch contract file mode without reading filesystem metadata.
///
/// This keeps the Unix permission rule testable as a pure mode check while the
/// filesystem wrapper owns the `stat` call.
pub fn validate_contract_file_mode(path: &Path, mode: u32) -> Result<()> {
    use anyhow::bail;

    if mode & 0o077 != 0 {
        bail!(
            "VZ launch contract {} must not be readable or writable by group/other",
            path.display()
        );
    }

    Ok(())
}

#[cfg(not(unix))]
/// Checks that the launch contract exists on platforms without Unix permission bits.
///
/// The current runner is macOS-only, but this keeps contract parsing buildable
/// on other hosts for tests and CI while still failing before JSON parsing when
/// the contract path is not a real filesystem entry.
pub fn validate_contract_file_access(path: &Path) -> Result<()> {
    use anyhow::Context;
    use std::fs;

    let _ = fs::metadata(path)
        .with_context(|| format!("stat VZ launch contract {}", path.display()))?;

    Ok(())
}

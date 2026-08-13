//! External editor launcher for Policy Control files.
//!
//! The editor launcher stays deliberately small. The runner owns terminal
//! suspension and re-entry; the launcher only starts the configured editor,
//! passes through the caller's stdio, and waits until it exits. Keeping those
//! responsibilities separate makes it clear that an editor session is one
//! blocking side effect in the control loop, not a second TUI mode.

use std::{
    path::Path,
    process::{Command, Stdio},
};

use crate::control::error::{EditorError, ErrorMessage};

/// Opens `path` in the operator's editor and waits for it to exit.
///
/// The editor inherits stdin, stdout, and stderr because interactive editors
/// need to own the terminal while they run. A successful return only means the
/// editor process exited cleanly. The caller still has to reload policies from
/// disk afterwards, so invalid Cedar can be reported without inventing state
/// from the editor result.
///
/// # Errors
///
/// Returns an error if the editor cannot be spawned or exits unsuccessfully.
pub fn open(path: &Path) -> Result<(), EditorError> {
    let status = editor_command(path)
        .status()
        .map_err(|error| EditorError::Launch {
            source: ErrorMessage::capture(error),
        })?;

    if !status.success() {
        return Err(EditorError::Exit {
            status: status.to_string(),
        });
    }

    Ok(())
}

#[cfg(unix)]
fn editor_command(path: &Path) -> Command {
    let mut command = Command::new("sh");
    // Run through the shell so EDITOR may include arguments such as `nvim -f`
    // or `code -w`. The policy path is passed as `$1` instead of interpolated
    // into the command string, which keeps paths with spaces out of the shell
    // quoting problem.
    command
        .arg("-c")
        .arg(r#"${EDITOR:-vi} "$1""#)
        .arg("firma-policy-control-editor")
        .arg(path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command
}

#[cfg(windows)]
fn editor_command(path: &Path) -> Command {
    let mut command = Command::new("cmd");
    // `cmd` expands EDITOR for us, while the file path travels through an
    // environment variable. That keeps the fallback command readable and avoids
    // constructing one manually quoted command line.
    command
        .arg("/C")
        .arg(
            r#"if defined EDITOR (%EDITOR% "%FIRMA_CONTROL_EDITOR_PATH%") else (notepad "%FIRMA_CONTROL_EDITOR_PATH%")"#,
        )
        .env("FIRMA_CONTROL_EDITOR_PATH", path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command
}

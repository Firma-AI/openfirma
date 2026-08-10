//! External editor launcher for Policy Control files.
//!
//! The editor launcher stays deliberately small. The runner owns terminal
//! suspension and re-entry; the launcher only starts the configured editor,
//! passes through the caller's stdio, and waits until it exits. Keeping those
//! responsibilities separate makes it clear that an editor session is one
//! blocking side effect in the control loop, not a second TUI mode.

use std::{
    ffi::{OsStr, OsString},
    path::Path,
    process::{Command, ExitStatus, Stdio},
};

use crate::control::error::{EditorError, EditorExitStatus, EditorProcessError, ErrorMessage};

#[cfg(windows)]
const EDITOR_PATH_ENV: &str = "FIRMA_CONTROL_EDITOR_PATH";
const EDITOR_ENV: &str = "FIRMA_CONTROL_EDITOR";

/// Editor command used to open a policy source file.
///
/// The command is usually read from `EDITOR`. When it is not configured, the
/// platform launch uses the local fallback editor.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Editor {
    command: Option<OsString>,
}

impl Editor {
    /// Creates an editor from an optional command.
    ///
    /// `None` keeps the platform fallback in effect. Unix falls back to `vi`;
    /// Windows falls back to Notepad.
    #[must_use]
    pub fn new(command: Option<OsString>) -> Self {
        Self { command }
    }

    /// Builds the platform-specific process launch used to open `path`.
    #[must_use]
    pub fn launch_for(&self, path: &Path) -> EditorLaunch {
        platform_launch(path, self)
    }

    /// Opens `path` and waits for the editor to exit.
    ///
    /// The editor inherits stdin, stdout, and stderr because interactive
    /// editors need to own the terminal while they run. A successful return
    /// only means the editor process exited cleanly. The caller still has to
    /// reload policies from disk afterwards.
    ///
    /// # Errors
    ///
    /// Returns an error if the editor cannot be spawned or exits
    /// unsuccessfully.
    pub fn open_with(
        &self,
        path: &Path,
        process: &mut impl EditorProcess,
    ) -> Result<(), EditorError> {
        let exit = process
            .run(self.launch_for(path))
            .map_err(|source| EditorError::Launch { source })?;

        if !exit.success() {
            return Err(EditorError::Exit {
                status: exit.status().clone(),
            });
        }

        Ok(())
    }
}

/// Inert process launch used to open a policy source file.
///
/// This value is kept separate from [`Command`] so the launch contract can be
/// inspected before any side effect happens. Only [`EditorProcess`] turns it
/// into a running process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditorLaunch {
    program: OsString,
    args: Vec<OsString>,
    envs: Vec<(OsString, Option<OsString>)>,
}

impl EditorLaunch {
    /// Creates an editor launch for `program`.
    ///
    /// Arguments and environment changes are added explicitly after creation,
    /// keeping call sites readable when a launch needs several knobs.
    #[must_use]
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            envs: Vec::new(),
        }
    }

    /// Adds arguments to this launch.
    #[must_use]
    pub fn args<I, A>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Sets an environment variable for this launch.
    #[must_use]
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.envs.push((key.into(), Some(value.into())));
        self
    }

    /// Removes an environment variable for this launch.
    #[must_use]
    pub fn remove_env(mut self, key: impl Into<OsString>) -> Self {
        self.envs.push((key.into(), None));
        self
    }

    /// Returns the program that will be passed to [`Command`].
    #[must_use]
    pub fn program(&self) -> &OsStr {
        &self.program
    }

    /// Returns the arguments that will be passed to [`Command`].
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.args
    }

    /// Returns the environment changes that will be applied to [`Command`].
    #[must_use]
    pub fn envs(&self) -> &[(OsString, Option<OsString>)] {
        &self.envs
    }

    /// Converts this launch into a process command without starting it.
    ///
    /// The command inherits stdin, stdout, and stderr because interactive
    /// editors need to own the terminal while they run.
    #[must_use]
    pub fn into_command(self) -> Command {
        let mut command = Command::new(self.program);
        command.args(self.args);
        for (key, value) in self.envs {
            match value {
                Some(value) => {
                    command.env(key, value);
                }
                None => {
                    command.env_remove(key);
                }
            }
        }

        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        command
    }
}

/// Result reported by an editor process after it started.
///
/// Start failures are represented by [`EditorProcessError`]. This type only
/// describes a process that was launched and then exited.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditorExit {
    success: bool,
    status: EditorExitStatus,
}

impl EditorExit {
    /// Creates a successful editor exit.
    #[must_use]
    pub fn successful() -> Self {
        Self {
            success: true,
            status: EditorExitStatus::new("exit status: 0"),
        }
    }

    /// Creates an unsuccessful editor exit with the rendered process status.
    #[must_use]
    pub fn unsuccessful(status: impl Into<String>) -> Self {
        Self {
            success: false,
            status: EditorExitStatus::new(status),
        }
    }

    fn from_status(status: ExitStatus) -> Self {
        Self {
            success: status.success(),
            status: EditorExitStatus::new(status.to_string()),
        }
    }

    /// Returns whether the editor process reported success.
    #[must_use]
    fn success(&self) -> bool {
        self.success
    }

    /// Returns the rendered process exit status.
    #[must_use]
    fn status(&self) -> &EditorExitStatus {
        &self.status
    }
}

/// Side-effect boundary used to run an editor launch.
///
/// Keeping process execution behind this boundary lets tests observe editor
/// behavior without spawning a real editor, while production still uses the
/// same launch value.
pub trait EditorProcess {
    /// Starts the editor process and waits for it to exit.
    ///
    /// Implementations receive an inert [`EditorLaunch`]. Production converts
    /// it into a real process, while tests can record the launch and return a
    /// deterministic exit without starting a host editor.
    ///
    /// # Errors
    ///
    /// Returns an error when the editor process cannot be started.
    fn run(&mut self, launch: EditorLaunch) -> Result<EditorExit, EditorProcessError>;
}

struct SystemEditorProcess;

impl EditorProcess for SystemEditorProcess {
    fn run(&mut self, launch: EditorLaunch) -> Result<EditorExit, EditorProcessError> {
        launch
            .into_command()
            .status()
            .map(EditorExit::from_status)
            .map_err(|error| EditorProcessError::Start {
                source: ErrorMessage::capture(error),
            })
    }
}

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
/// Returns an error if the editor cannot be started or exits unsuccessfully.
pub fn open(path: &Path) -> Result<(), EditorError> {
    let editor = Editor::new(std::env::var_os("EDITOR"));
    let mut process = SystemEditorProcess;
    editor.open_with(path, &mut process)
}

#[cfg(unix)]
fn platform_launch(path: &Path, editor: &Editor) -> EditorLaunch {
    // Run through the shell so EDITOR may include arguments such as `nvim -f`
    // or `code -w`. The policy path is passed as `$1` instead of interpolated
    // into the command string, which keeps paths with spaces out of the shell
    // quoting problem.
    EditorLaunch::new("sh")
        .args([
            OsString::from("-c"),
            OsString::from(format!("${EDITOR_ENV} \"$1\"")),
            OsString::from("firma-policy-control-editor"),
            path.as_os_str().to_owned(),
        ])
        .env(
            EDITOR_ENV,
            editor
                .command
                .clone()
                .unwrap_or_else(|| OsString::from("vi")),
        )
}

#[cfg(windows)]
fn platform_launch(path: &Path, editor: &Editor) -> EditorLaunch {
    let path = windows_editor_path(path);

    let Some(command) = editor.command.as_ref() else {
        return EditorLaunch::new("notepad").args([path]);
    };

    if !windows_editor_needs_shell(command) {
        return EditorLaunch::new(command.clone()).args([path]);
    }

    // `cmd` is used only when the configured editor is a command string rather
    // than a plain executable name. Values such as `code --wait` need shell
    // expansion, while the policy path still travels through an environment
    // variable so it is not interpolated into the command string.
    EditorLaunch::new("cmd")
        .args([
            OsString::from("/C"),
            OsString::from(format!("%{EDITOR_ENV}% \"%{EDITOR_PATH_ENV}%\"")),
        ])
        .env(EDITOR_ENV, command.clone())
        .env(EDITOR_PATH_ENV, path)
}

#[cfg(windows)]
fn windows_editor_needs_shell(command: &OsStr) -> bool {
    command.to_string_lossy().chars().any(|character| {
        character.is_whitespace()
            || matches!(
                character,
                '"' | '\'' | '&' | '|' | '<' | '>' | '^' | '%' | '(' | ')'
            )
    })
}

#[cfg(windows)]
fn windows_editor_path(path: &Path) -> OsString {
    let path = path.canonicalize().unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_or_else(|_| path.to_path_buf(), |current_dir| current_dir.join(path))
        }
    });

    normalize_windows_editor_path(&path)
}

#[cfg(windows)]
fn normalize_windows_editor_path(path: &Path) -> OsString {
    let path_text = path.as_os_str().to_string_lossy().replace('/', "\\");
    if let Some(path) = path_text.strip_prefix(r"\\?\UNC\") {
        return OsString::from(format!(r"\\{path}"));
    }

    if let Some(path) = path_text.strip_prefix(r"\\?\") {
        return OsString::from(path);
    }

    OsString::from(path_text)
}

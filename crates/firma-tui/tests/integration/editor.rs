use std::{
    ffi::{OsStr, OsString},
    path::Path,
    process::Command,
};

use firma_tui::control::{
    Editor, EditorError, EditorExit, EditorExitStatus, EditorLaunch, EditorProcess,
    EditorProcessError, ErrorMessage,
};

#[cfg(unix)]
#[test]
fn unix_editor_launch_passes_policy_path_as_shell_argument() {
    for path in [
        Path::new("/tmp/policy with spaces.cedar"),
        Path::new(r#"/tmp/policy "$HOME" 'literal'.cedar"#),
    ] {
        for editor in ["nvim -f", "code -w"] {
            let launch = Editor::new(Some(OsString::from(editor))).launch_for(path);

            assert_unix_launch_passes_path_as_argument(&launch, path);
            assert_editor_env(&launch, editor);
        }
    }
}

#[cfg(unix)]
#[test]
fn unix_editor_launch_falls_back_to_vi() {
    let launch = Editor::new(None).launch_for(Path::new("/tmp/policy.cedar"));

    assert_eq!(
        launch.envs(),
        [(
            OsString::from("FIRMA_CONTROL_EDITOR"),
            Some(OsString::from("vi")),
        )]
    );
}

#[cfg(windows)]
#[test]
fn windows_editor_launch_uses_cmd_for_configured_editor_with_args() {
    let path = Path::new(r"C:\policy with spaces.cedar");
    let launch = Editor::new(Some(OsString::from("code --wait"))).launch_for(path);
    let args = string_args(&launch);

    assert_eq!(launch.program(), "cmd");
    assert_eq!(args[0], "/C");
    assert!(args[1].contains("%FIRMA_CONTROL_EDITOR%"));
    assert!(args[1].contains("%FIRMA_CONTROL_EDITOR_PATH%"));
    assert!(!args[1].contains(&path.display().to_string()));
    assert_eq!(
        launch.envs(),
        [
            (
                OsString::from("FIRMA_CONTROL_EDITOR"),
                Some(OsString::from("code --wait")),
            ),
            (
                OsString::from("FIRMA_CONTROL_EDITOR_PATH"),
                Some(path.as_os_str().to_owned()),
            ),
        ]
    );
}

#[cfg(windows)]
#[test]
fn windows_editor_launch_uses_configured_executable_directly() {
    let path = Path::new(r"C:\policy with spaces.cedar");
    let launch = Editor::new(Some(OsString::from("notepad"))).launch_for(path);

    assert_eq!(launch.program(), "notepad");
    assert_eq!(launch.arguments(), [path.as_os_str().to_owned()]);
    assert!(launch.envs().is_empty());
}

#[cfg(windows)]
#[test]
fn windows_editor_launch_falls_back_to_notepad() {
    let path = Path::new(r"C:\policy.cedar");
    let launch = Editor::new(None).launch_for(path);

    assert_eq!(launch.program(), "notepad");
    assert_eq!(launch.arguments(), [path.as_os_str().to_owned()]);
    assert!(launch.envs().is_empty());
}

#[test]
fn editor_launch_into_command_preserves_process_shape() {
    let launch = EditorLaunch::new("editor-bin")
        .args([OsString::from("--wait"), OsString::from("policy.cedar")])
        .env("FIRMA_EDITOR_TEST_SET", "value")
        .remove_env("FIRMA_EDITOR_TEST_REMOVE");

    let command = launch.into_command();

    assert_eq!(command.get_program(), OsStr::new("editor-bin"));
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        [OsStr::new("--wait"), OsStr::new("policy.cedar")]
    );
    assert_eq!(
        command_env(&command, "FIRMA_EDITOR_TEST_SET"),
        Some(CommandEnv::Set(OsString::from("value")))
    );
    assert_eq!(
        command_env(&command, "FIRMA_EDITOR_TEST_REMOVE"),
        Some(CommandEnv::Removed)
    );
}

#[test]
fn editor_open_with_returns_ok_for_successful_exit() -> anyhow::Result<()> {
    let path = Path::new("/tmp/policy.cedar");
    let editor = Editor::new(Some(OsString::from("nano")));
    let mut process = RecordingEditorProcess::new(Ok(EditorExit::successful()));

    editor.open_with(path, &mut process)?;

    assert_eq!(recorded_launch(&process)?, &editor.launch_for(path));

    Ok(())
}

#[test]
fn editor_open_with_maps_process_launch_error() -> anyhow::Result<()> {
    let process_error = EditorProcessError::Start {
        source: ErrorMessage::new("spawn denied"),
    };
    let mut process = RecordingEditorProcess::new(Err(process_error.clone()));

    let error =
        editor_error(Editor::new(None).open_with(Path::new("/tmp/policy.cedar"), &mut process))?;

    assert_eq!(
        error,
        EditorError::Launch {
            source: process_error
        }
    );
    assert_eq!(
        error.to_string(),
        "failed to launch editor: failed to start editor process: spawn denied"
    );

    Ok(())
}

#[test]
fn editor_open_with_maps_unsuccessful_exit() -> anyhow::Result<()> {
    let mut process = RecordingEditorProcess::new(Ok(EditorExit::unsuccessful("exit status: 7")));

    let error =
        editor_error(Editor::new(None).open_with(Path::new("/tmp/policy.cedar"), &mut process))?;

    assert_eq!(
        error,
        EditorError::Exit {
            status: EditorExitStatus::new("exit status: 7"),
        }
    );
    assert_eq!(
        error.to_string(),
        "editor exited unsuccessfully: exit status: 7"
    );

    Ok(())
}

#[cfg(unix)]
fn assert_unix_launch_passes_path_as_argument(launch: &EditorLaunch, path: &Path) {
    let args = string_args(launch);

    assert_eq!(launch.program(), "sh");
    assert_eq!(args[0], "-c");
    assert_eq!(args[1], r#"$FIRMA_CONTROL_EDITOR "$1""#);
    assert_eq!(args[2], "firma-policy-control-editor");
    assert_eq!(launch.arguments()[3], path.as_os_str());
    assert!(!args[1].contains(&path.display().to_string()));
}

#[cfg(unix)]
fn assert_editor_env(launch: &EditorLaunch, editor: &str) {
    assert_eq!(
        launch.envs(),
        [(
            OsString::from("FIRMA_CONTROL_EDITOR"),
            Some(OsString::from(editor)),
        )]
    );
}

fn string_args(launch: &EditorLaunch) -> Vec<String> {
    launch
        .arguments()
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

#[derive(Debug, Eq, PartialEq)]
enum CommandEnv {
    Set(OsString),
    Removed,
}

fn command_env(command: &Command, key: &str) -> Option<CommandEnv> {
    command
        .get_envs()
        .find(|(env_key, _value)| *env_key == OsStr::new(key))
        .map(|(_key, value)| {
            value.map_or(CommandEnv::Removed, |value| {
                CommandEnv::Set(value.to_os_string())
            })
        })
}

struct RecordingEditorProcess {
    result: Result<EditorExit, EditorProcessError>,
    launches: Vec<EditorLaunch>,
}

impl RecordingEditorProcess {
    fn new(result: Result<EditorExit, EditorProcessError>) -> Self {
        Self {
            result,
            launches: Vec::new(),
        }
    }
}

impl EditorProcess for RecordingEditorProcess {
    fn run(&mut self, launch: EditorLaunch) -> Result<EditorExit, EditorProcessError> {
        self.launches.push(launch);
        self.result.clone()
    }
}

fn recorded_launch(process: &RecordingEditorProcess) -> anyhow::Result<&EditorLaunch> {
    let [launch] = process.launches.as_slice() else {
        anyhow::bail!(
            "expected one editor launch, recorded {}",
            process.launches.len()
        );
    };

    Ok(launch)
}

fn editor_error(result: Result<(), EditorError>) -> anyhow::Result<EditorError> {
    match result {
        Ok(()) => anyhow::bail!("expected editor error"),
        Err(error) => Ok(error),
    }
}

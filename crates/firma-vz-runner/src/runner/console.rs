use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use super::{RunnerError, RunnerResult};
use crate::guest::{
    GUEST_HEARTBEAT_FILE, GUEST_RESULT_FILE, GUEST_STDERR_FILE, GUEST_STDIN_FILE,
    GUEST_STDOUT_FILE, GuestResult,
};
use crate::vm::VmPlan;

const SERIAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const SERIAL_LOG_MIRROR_ENV: &str = "FIRMA_VZ_RUNNER_SERIAL_LOG_MIRROR";

/// Host-side forwarding threads attached to the VZ console.
pub struct StdioForwarders {
    serial_done: mpsc::Receiver<()>,
}

/// Host input policy for the VM serial console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialInputMode {
    /// Forward host stdin to the guest serial console.
    ForwardHostStdin,
    /// Close serial input because another transport owns host stdin.
    Closed,
}

impl StdioForwarders {
    /// Gives serial forwarding a bounded drain window before guest stdio replay.
    pub fn wait_for_serial_drain(self) {
        match self.serial_done.recv_timeout(SERIAL_DRAIN_TIMEOUT) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {
                eprintln!(
                    "firma-vz-runner: serial forwarding did not drain within {}s; continuing to guest result",
                    SERIAL_DRAIN_TIMEOUT.as_secs()
                );
            }
        }
    }
}

/// Starts host threads that bridge stdin/stdout and serial diagnostics.
pub fn spawn_stdio_forwarders(
    host_reads_from_vm: OwnedFd,
    host_writes_to_vm: OwnedFd,
    serial_log: File,
    serial_input_mode: SerialInputMode,
    mirror_serial_to_stdout: bool,
) -> StdioForwarders {
    match serial_input_mode {
        SerialInputMode::ForwardHostStdin => {
            thread::spawn(move || {
                let mut stdin = io::stdin().lock();
                let mut writer = File::from(host_writes_to_vm);
                if let Err(error) = io::copy(&mut stdin, &mut writer) {
                    eprintln!("firma-vz-runner: stdin forwarding failed: {error}");
                }
            });
        }
        SerialInputMode::Closed => {
            drop(host_writes_to_vm);
        }
    }

    let (serial_done_tx, serial_done_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = File::from(host_reads_from_vm);
        let mut serial_log = serial_log;
        let mut buffer = [0_u8; 8192];

        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    if let Err(error) = serial_log.write_all(&buffer[..read]) {
                        eprintln!("firma-vz-runner: serial log write failed: {error}");
                        break;
                    }

                    if mirror_serial_to_stdout {
                        let mut stdout = io::stdout().lock();
                        if let Err(error) = stdout.write_all(&buffer[..read]) {
                            eprintln!("firma-vz-runner: stdout forwarding failed: {error}");
                            break;
                        }
                    }
                }
                Err(error) => {
                    eprintln!("firma-vz-runner: serial forwarding failed: {error}");
                    break;
                }
            }
        }

        let _ = serial_log.flush();
        let _ = serial_done_tx.send(());
    });

    StdioForwarders {
        serial_done: serial_done_rx,
    }
}

/// Returns whether serial diagnostics should also be mirrored to host stdout.
pub fn should_mirror_serial_to_stdout(pty: bool) -> bool {
    let env_value = std::env::var(SERIAL_LOG_MIRROR_ENV).ok();
    should_mirror_serial_to_stdout_with_env(pty, env_value.as_deref())
}

/// Applies serial mirroring defaults before reading host environment state.
fn should_mirror_serial_to_stdout_with_env(pty: bool, env_value: Option<&str>) -> bool {
    if !pty {
        return true;
    }

    env_value.is_some_and(serial_log_mirror_env_enabled)
}

/// Parses the opt-in serial mirror environment value.
fn serial_log_mirror_env_enabled(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "1" | "true")
}

/// Creates the paired descriptors used for serial data flow.
pub fn create_pipe() -> RunnerResult<(OwnedFd, OwnedFd)> {
    let (read_stream, write_stream) =
        UnixStream::pair().map_err(|source| RunnerError::HostOperation {
            action: "create VM stdio socket pair",
            source,
        })?;

    Ok((read_stream.into(), write_stream.into()))
}

/// Creates the private serial log file under the runtime directory.
pub fn create_serial_log(plan: &VmPlan) -> RunnerResult<File> {
    let log_path = plan.runtime_dir.join("vz-guest").join("serial.log");
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| RunnerError::HostIo {
            action: "create serial log directory",
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let log = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&log_path)
        .map_err(|source| RunnerError::HostIo {
            action: "create serial log",
            path: log_path.clone(),
            source,
        })?;

    let mut permissions = log
        .metadata()
        .map_err(|source| RunnerError::HostIo {
            action: "stat serial log",
            path: log_path.clone(),
            source,
        })?
        .permissions();

    permissions.set_mode(0o600);

    log.set_permissions(permissions)
        .map_err(|source| RunnerError::HostIo {
            action: "set serial log permissions",
            path: log_path.clone(),
            source,
        })?;

    eprintln!("firma-vz-runner: serial log {}", log_path.display());

    Ok(log)
}

/// Captures piped host stdin into the runtime file consumed by guest init.
pub fn capture_piped_stdin(plan: &VmPlan) -> RunnerResult<()> {
    if io::stdin().is_terminal() {
        return Ok(());
    }

    let mut input = Vec::new();
    io::stdin()
        .lock()
        .read_to_end(&mut input)
        .map_err(|source| RunnerError::HostOperation {
            action: "read piped stdin for VZ guest command",
            source,
        })?;
    if input.is_empty() {
        return Ok(());
    }

    let stdin_path = guest_file_path(plan, GUEST_STDIN_FILE);
    std::fs::write(&stdin_path, input).map_err(|source| RunnerError::HostIo {
        action: "write guest stdin",
        path: stdin_path.clone(),
        source,
    })?;

    let mut permissions = std::fs::metadata(&stdin_path)
        .map_err(|source| RunnerError::HostIo {
            action: "stat guest stdin",
            path: stdin_path.clone(),
            source,
        })?
        .permissions();
    permissions.set_mode(0o600);

    std::fs::set_permissions(&stdin_path, permissions).map_err(|source| RunnerError::HostIo {
        action: "set guest stdin permissions",
        path: stdin_path.clone(),
        source,
    })?;

    eprintln!(
        "firma-vz-runner: captured piped stdin {}",
        stdin_path.display()
    );

    Ok(())
}

/// Replays guest command stdout and stderr files to the host streams.
pub fn replay_guest_stdio(plan: &VmPlan) -> RunnerResult<()> {
    replay_guest_stream(plan, GUEST_STDOUT_FILE, io::stdout().lock())?;
    replay_guest_stream(plan, GUEST_STDERR_FILE, io::stderr().lock())?;
    Ok(())
}

/// Replays one guest stream file if it exists.
fn replay_guest_stream(plan: &VmPlan, file_name: &str, mut output: impl Write) -> RunnerResult<()> {
    let path = guest_file_path(plan, file_name);
    match File::open(&path) {
        Ok(mut file) => {
            io::copy(&mut file, &mut output).map_err(|source| RunnerError::HostIo {
                action: "replay guest stream",
                path: path.clone(),
                source,
            })?;
            output.flush().map_err(|source| RunnerError::HostIo {
                action: "flush replayed guest stream",
                path: path.clone(),
                source,
            })?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(RunnerError::HostIo {
            action: "open guest stream",
            path,
            source,
        }),
    }
}

/// Builds the host path for one guest-produced runtime file.
fn guest_file_path(plan: &VmPlan, file_name: &str) -> std::path::PathBuf {
    plan.runtime_dir.join("vz-guest").join(file_name)
}

/// Reads the guest result file and converts it into the runner exit code.
pub fn read_guest_exit_code(plan: &VmPlan) -> RunnerResult<std::process::ExitCode> {
    let guest_dir = plan.runtime_dir.join("vz-guest");
    let result_path = guest_dir.join(GUEST_RESULT_FILE);
    let result = GuestResult::read(&result_path)
        .inspect_err(|_| {
            let heartbeat_path = guest_dir.join(GUEST_HEARTBEAT_FILE);
            if let Ok(heartbeat) = std::fs::read_to_string(&heartbeat_path) {
                eprintln!(
                    "firma-vz-runner: latest guest heartbeat {}:\n{}",
                    heartbeat_path.display(),
                    heartbeat.trim()
                );
            }
        })
        .map_err(|error| RunnerError::OperationFailed {
            operation: "read guest result",
            reason: format!("{error:#}"),
        })?;
    let exit_code = result
        .to_exit_code()
        .map_err(|error| RunnerError::OperationFailed {
            operation: "decode guest result",
            reason: format!("{error:#}"),
        })?;
    eprintln!("firma-vz-runner: guest result {}", result_path.display());
    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    use anyhow::Result;

    use super::*;
    use crate::test_utils::{VZ_TEST_ROOTFS_SIZE_BYTES, vm_plan_fixture};

    #[test]
    fn guest_result_file_drives_runner_exit_code() -> Result<()> {
        let (_temp, plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;
        let result_path = guest_file_path(&plan, GUEST_RESULT_FILE);
        std::fs::write(
            &result_path,
            r#"{"version":1,"status":"exited","exit_code":42,"signal":null,"error":null}"#,
        )?;

        let exit_code = read_guest_exit_code(&plan)?;

        assert_eq!(exit_code, ExitCode::from(42));
        Ok(())
    }

    #[test]
    fn replay_guest_stream_copies_runtime_file_to_host_output() -> Result<()> {
        let (_temp, plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;
        std::fs::write(guest_file_path(&plan, GUEST_STDOUT_FILE), b"guest stdout")?;
        let mut output = Vec::new();

        replay_guest_stream(&plan, GUEST_STDOUT_FILE, &mut output)?;

        assert_eq!(output, b"guest stdout");
        Ok(())
    }

    #[test]
    fn replay_guest_stream_ignores_missing_files() -> Result<()> {
        let (_temp, plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;
        let mut output = Vec::new();

        replay_guest_stream(&plan, GUEST_STDOUT_FILE, &mut output)?;

        assert!(output.is_empty());
        Ok(())
    }

    #[test]
    fn serial_mirroring_remains_enabled_for_non_pty_runs() {
        assert!(should_mirror_serial_to_stdout_with_env(false, None));
        assert!(should_mirror_serial_to_stdout_with_env(false, Some("0")));
    }

    #[test]
    fn serial_mirroring_is_opt_in_for_pty_runs() {
        assert!(!should_mirror_serial_to_stdout_with_env(true, None));
        assert!(!should_mirror_serial_to_stdout_with_env(true, Some("0")));
        assert!(!should_mirror_serial_to_stdout_with_env(
            true,
            Some("false")
        ));

        assert!(should_mirror_serial_to_stdout_with_env(true, Some("1")));
        assert!(should_mirror_serial_to_stdout_with_env(true, Some("true")));
    }
}

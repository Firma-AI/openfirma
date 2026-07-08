use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::boot::{BootNetworkMode, boot_contract_from_cmdline};
use super::command::{CommandOutcome, execute_contract};
use super::contract::{
    CommandContract, Contract, LaunchContract, MountContract, accept_contract, read_contract,
    validate_contract,
};
use super::error::{InitError, InitResult};
use super::mount::{load_required_modules, mount_contract_paths};
use super::result::{guest_result_from_command_result, write_result, write_setup_error};

type TestResult = Result<(), Box<dyn Error>>;

const VALID_CONTRACT_JSON: &str = include_str!("fixtures/valid-contract.json");

#[test]
fn boot_contract_accepts_none_network_mode() -> TestResult {
    let boot = boot_contract_from_cmdline(
        "firma.virtiofs_tag=firma-runtime \
         firma.launch_contract=/firma-shares/runtime/vz-guest-launch.json \
         firma.network=none",
    )?;

    assert_eq!(boot.network, BootNetworkMode::None);

    Ok(())
}

#[test]
fn boot_contract_rejects_missing_virtiofs_tag() -> TestResult {
    let error = expect_init_error(
        boot_contract_from_cmdline(
            "firma.launch_contract=/firma-shares/runtime/vz-guest-launch.json \
             firma.network=none",
        ),
        "boot contract should require firma.virtiofs_tag",
    )?;

    assert!(matches!(
        error,
        InitError::MissingKernelArg {
            name: "firma.virtiofs_tag",
        }
    ));

    Ok(())
}

#[test]
fn boot_contract_rejects_missing_launch_contract() -> TestResult {
    let error = expect_init_error(
        boot_contract_from_cmdline(
            "firma.virtiofs_tag=firma-runtime \
             firma.network=none",
        ),
        "boot contract should require firma.launch_contract",
    )?;

    assert!(matches!(
        error,
        InitError::MissingKernelArg {
            name: "firma.launch_contract",
        }
    ));

    Ok(())
}

#[test]
fn boot_contract_rejects_missing_network_mode() -> TestResult {
    let error = expect_init_error(
        boot_contract_from_cmdline(
            "firma.virtiofs_tag=firma-runtime \
             firma.launch_contract=/firma-shares/runtime/vz-guest-launch.json",
        ),
        "boot contract should require firma.network",
    )?;

    assert!(matches!(
        error,
        InitError::MissingKernelArg {
            name: "firma.network",
        }
    ));

    Ok(())
}

#[test]
fn boot_contract_rejects_unsupported_network_mode() -> TestResult {
    let error = expect_init_error(
        boot_contract_from_cmdline(
            "firma.virtiofs_tag=firma-runtime \
             firma.launch_contract=/firma-shares/runtime/vz-guest-launch.json \
             firma.network=nat",
        ),
        "boot contract should reject non-none network modes",
    )?;

    assert!(matches!(
        error,
        InitError::UnsupportedNetworkMode { mode } if mode == "nat"
    ));

    Ok(())
}

#[test]
fn contract_accepts_valid_contract() -> TestResult {
    validate_contract(&valid_launch_contract())?;
    Ok(())
}

#[test]
fn contract_rejects_invalid_version() -> TestResult {
    let mut contract = valid_launch_contract();
    contract.version = 2;

    let error = expect_init_error(
        validate_contract(&contract),
        "contract should reject unknown versions",
    )?;

    assert!(matches!(
        error,
        InitError::InvalidContractVersion { version: 2 }
    ));

    Ok(())
}

#[test]
fn contract_rejects_empty_executable() -> TestResult {
    let mut contract = valid_launch_contract();
    contract.command.executable = " ".to_string();

    let error = expect_init_error(
        validate_contract(&contract),
        "contract should reject empty executables",
    )?;

    assert!(matches!(error, InitError::EmptyExecutable));

    Ok(())
}

#[test]
fn contract_rejects_relative_cwd() -> TestResult {
    let mut contract = valid_launch_contract();
    contract.command.cwd = PathBuf::from("workspace");

    let error = expect_init_error(
        validate_contract(&contract),
        "contract should reject relative cwd",
    )?;

    assert!(matches!(
        error,
        InitError::RelativeCommandCwd { path } if path.as_path() == Path::new("workspace")
    ));
    Ok(())
}

#[test]
fn contract_rejects_relative_mount_target() -> TestResult {
    let mut contract = valid_launch_contract();
    let Some(mount) = contract.mounts.first_mut() else {
        return Err(io::Error::other("test contract should include a mount").into());
    };
    mount.target = PathBuf::from("workspace");

    let error = expect_init_error(
        validate_contract(&contract),
        "contract should reject relative mount targets",
    )?;

    assert!(matches!(
        error,
        InitError::RelativeMountTarget { path } if path.as_path() == Path::new("workspace")
    ));

    Ok(())
}

#[test]
fn contract_rejects_secret_env_key() -> TestResult {
    let mut contract = valid_launch_contract();
    contract.command.env.insert(
        "FIRMA_CAPABILITY_TOKEN".to_string(),
        "secret-token".to_string(),
    );

    let error = expect_init_error(
        validate_contract(&contract),
        "contract should reject secret environment keys",
    )?;

    assert!(matches!(
        error,
        InitError::SecretEnvKey {
            key: "FIRMA_CAPABILITY_TOKEN",
        }
    ));

    Ok(())
}

#[test]
fn read_contract_parses_valid_contract_json() -> TestResult {
    let temp = tempfile::tempdir()?;
    let contract_path = write_contract_json(temp.path(), &valid_contract_json()?)?;

    let contract = read_contract(&contract_path)?;

    assert_eq!(contract.version, 1);
    assert_eq!(contract.command.executable, "/bin/true");
    assert_eq!(contract.mounts.len(), 1);
    Ok(())
}

#[test]
fn read_contract_rejects_missing_path() -> TestResult {
    let temp = tempfile::tempdir()?;
    let missing = temp.path().join("missing-contract.json");

    let error = expect_init_error(
        read_contract(&missing),
        "missing contract should fail before parsing",
    )?;

    assert!(matches!(
        error,
        InitError::ContractNotVisible { path, .. } if path == missing
    ));

    Ok(())
}

#[test]
fn read_contract_rejects_directories() -> TestResult {
    let temp = tempfile::tempdir()?;

    let error = expect_init_error(
        read_contract(temp.path()),
        "directory should not be accepted as contract",
    )?;

    assert!(matches!(
        error,
        InitError::ContractNotRegularFile { path } if path == temp.path()
    ));

    Ok(())
}

#[test]
fn read_contract_rejects_malformed_json() -> TestResult {
    let temp = tempfile::tempdir()?;
    let contract_path = temp.path().join("vz-guest-launch.json");
    fs::write(&contract_path, b"{")?;

    let error = expect_init_error(
        read_contract(&contract_path),
        "malformed contract should fail during parse",
    )?;

    assert!(matches!(
        error,
        InitError::ParseContract { path, .. } if path == contract_path
    ));
    Ok(())
}

#[test]
fn read_contract_rejects_unknown_top_level_fields() -> TestResult {
    let temp = tempfile::tempdir()?;
    let mut contract = valid_contract_json()?;
    contract["unknown"] = json!(true);
    let contract_path = write_contract_json(temp.path(), &contract)?;

    let error = expect_init_error(
        read_contract(&contract_path),
        "unknown contract fields should be rejected",
    )?;

    assert!(matches!(
        error,
        InitError::ParseContract { path, .. } if path == contract_path
    ));
    Ok(())
}

#[test]
fn read_contract_rejects_unknown_nested_fields() -> TestResult {
    let temp = tempfile::tempdir()?;
    let mut contract = valid_contract_json()?;
    contract["command"]["unknown"] = json!(true);
    let contract_path = write_contract_json(temp.path(), &contract)?;

    let error = expect_init_error(
        read_contract(&contract_path),
        "unknown nested contract fields should be rejected",
    )?;

    assert!(matches!(
        error,
        InitError::ParseContract { path, .. } if path == contract_path
    ));
    Ok(())
}

#[test]
fn accept_contract_returns_validated_contract() -> TestResult {
    let temp = tempfile::tempdir()?;
    let contract_path = write_contract_json(temp.path(), &valid_contract_json()?)?;

    let contract = accept_contract(&contract_path)?;

    assert_eq!(contract.command().executable, "/bin/true");
    assert_eq!(contract.mounts().len(), 1);
    Ok(())
}

#[test]
fn accept_contract_rejects_semantically_invalid_contract() -> TestResult {
    let temp = tempfile::tempdir()?;
    let mut contract = valid_contract_json()?;
    contract["command"]["cwd"] = json!("workspace");
    let contract_path = write_contract_json(temp.path(), &contract)?;

    let error = expect_init_error(
        accept_contract(&contract_path),
        "accepted contract should still run semantic validation",
    )?;

    assert!(matches!(
        error,
        InitError::RelativeCommandCwd { path } if path.as_path() == Path::new("workspace")
    ));
    Ok(())
}

#[test]
fn execute_contract_returns_exit_code_and_creates_cwd() -> TestResult {
    let temp = tempfile::tempdir()?;
    let cwd = temp.path().join("created-cwd");
    let mut launch = valid_launch_contract();
    launch.command.executable = "/bin/sh".to_string();
    launch.command.args = vec!["-c".to_string(), "exit 7".to_string()];
    launch.command.cwd = cwd.clone();
    let contract: Contract = launch.try_into()?;

    let outcome = execute_contract(&contract)?;

    assert!(matches!(outcome, CommandOutcome::Exited(7)));
    assert!(cwd.is_dir());
    Ok(())
}

#[test]
fn execute_contract_reports_spawn_errors() -> TestResult {
    let temp = tempfile::tempdir()?;
    let missing = temp.path().join("missing-command");
    let mut launch = valid_launch_contract();
    launch.command.executable = missing.display().to_string();
    launch.command.cwd = temp.path().to_path_buf();
    let contract: Contract = launch.try_into()?;

    let error = expect_init_error(
        execute_contract(&contract),
        "missing executable should return spawn error",
    )?;

    assert!(matches!(
        error,
        InitError::SpawnCommand { executable, .. } if executable == missing.display().to_string()
    ));
    Ok(())
}

#[test]
fn write_result_writes_owner_only_guest_result() -> TestResult {
    let temp = tempfile::tempdir()?;
    let contract_path = temp.path().join("vz-guest-launch.json");
    fs::write(&contract_path, b"{}")?;

    write_result(&contract_path, &Ok(CommandOutcome::Exited(3)))?;

    let result_path = temp.path().join("guest-result.json");
    let result_json: serde_json::Value = serde_json::from_slice(&fs::read(&result_path)?)?;
    assert_eq!(
        result_json,
        json!({
            "version": 1,
            "status": "exited",
            "exit_code": 3,
            "signal": null,
            "error": null,
        })
    );
    assert_eq!(
        fs::metadata(&result_path)?.permissions().mode() & 0o777,
        0o600
    );
    assert!(!temp.path().join("guest-result.json.tmp").exists());
    Ok(())
}

#[test]
fn write_result_rejects_contract_path_without_parent() -> TestResult {
    let error = expect_init_error(
        write_result(Path::new("/"), &Ok(CommandOutcome::Exited(0))),
        "root path should not have a parent result directory",
    )?;

    assert!(matches!(error, InitError::ResultPathWithoutParent { path } if path == Path::new("/")));
    Ok(())
}

#[test]
fn write_setup_error_ignores_unmounted_runtime_share() -> TestResult {
    let temp = tempfile::tempdir()?;
    let contract_path = temp.path().join("vz-guest-launch.json");

    write_setup_error(&contract_path, &InitError::EmptyExecutable)?;

    assert!(!temp.path().join("guest-result.json").exists());
    Ok(())
}

#[test]
fn load_required_modules_accepts_images_with_builtin_drivers() -> TestResult {
    if Path::new("/lib/modules/firma-vz").is_dir() {
        return Ok(());
    }

    load_required_modules()?;
    Ok(())
}

#[test]
fn mount_contract_paths_rejects_missing_indexed_share() -> TestResult {
    if Path::new("/firma-shares/mount0").is_dir() {
        return Ok(());
    }

    let temp = tempfile::tempdir()?;
    let mut launch = valid_launch_contract();
    launch.mounts[0].target = temp.path().join("workspace");
    let contract: Contract = launch.try_into()?;

    let error = expect_init_error(
        mount_contract_paths(&contract),
        "missing indexed virtiofs share should fail before bind mount",
    )?;

    assert!(matches!(
        error,
        InitError::MissingShareSource { path } if path == Path::new("/firma-shares/mount0")
    ));
    Ok(())
}

#[test]
fn command_result_converts_to_guest_result_shape() -> TestResult {
    let exited = guest_result_from_command_result(&Ok(CommandOutcome::Exited(7)));
    assert_eq!(
        serde_json::to_value(&exited)?,
        json!({
            "version": 1,
            "status": "exited",
            "exit_code": 7,
            "signal": null,
            "error": null,
        })
    );

    let signaled = guest_result_from_command_result(&Ok(CommandOutcome::Signaled(15)));
    assert_eq!(
        serde_json::to_value(&signaled)?,
        json!({
            "version": 1,
            "status": "signaled",
            "exit_code": null,
            "signal": 15,
            "error": null,
        })
    );

    let spawn_error = guest_result_from_command_result(&Err(InitError::SpawnCommand {
        executable: "codex".to_string(),
        source: io::Error::new(io::ErrorKind::NotFound, "missing"),
    }));
    assert_eq!(
        serde_json::to_value(&spawn_error)?,
        json!({
            "version": 1,
            "status": "spawn_error",
            "exit_code": null,
            "signal": null,
            "error": "spawn command codex: missing",
        })
    );

    let setup_error = guest_result_from_command_result(&Err(InitError::EmptyExecutable));
    assert_eq!(
        serde_json::to_value(&setup_error)?,
        json!({
            "version": 1,
            "status": "setup_error",
            "exit_code": null,
            "signal": null,
            "error": "command.executable must not be empty",
        })
    );

    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn init_error_display_and_sources_are_stable() -> TestResult {
    assert_error_display(
        &InitError::CreateDir {
            path: PathBuf::from("/tmp/firma"),
            source: io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"),
        },
        "create /tmp/firma: permission denied",
        true,
    );
    assert_error_display(
        &InitError::ReadKernelCmdline {
            source: io::Error::new(io::ErrorKind::NotFound, "no such file or directory"),
        },
        "read /proc/cmdline after mounting proc failed: no such file or directory",
        true,
    );
    assert_error_display(
        &InitError::MountPseudo {
            file_system: "proc",
            target: "/proc",
            source: io::Error::new(io::ErrorKind::PermissionDenied, "operation not permitted"),
        },
        "mount proc on /proc: operation not permitted",
        true,
    );
    assert_error_display(
        &InitError::MountVirtiofs {
            tag: "firma-runtime".to_string(),
            target: "/firma-shares",
            source: io::Error::new(io::ErrorKind::NotFound, "no such device"),
        },
        "mount virtiofs tag firma-runtime on /firma-shares: no such device",
        true,
    );
    assert_error_display(
        &InitError::BindMount {
            source: PathBuf::from("/source"),
            target: PathBuf::from("/target"),
            error: io::Error::new(io::ErrorKind::InvalidInput, "invalid argument"),
        },
        "bind mount /source on /target: invalid argument",
        true,
    );
    assert_error_display(
        &InitError::RemountReadOnly {
            source: PathBuf::from("/source"),
            target: PathBuf::from("/target"),
            error: io::Error::new(io::ErrorKind::PermissionDenied, "operation not permitted"),
        },
        "remount read-only bind /source on /target: operation not permitted",
        true,
    );
    assert_error_display(
        &InitError::MissingKernelArg {
            name: "firma.network",
        },
        "missing firma.network kernel argument",
        false,
    );
    assert_error_display(
        &InitError::UnsupportedNetworkMode {
            mode: "nat".to_string(),
        },
        "unexpected firma.network=nat; current lifecycle guest expects none",
        false,
    );
    assert_error_display(
        &InitError::ContractNotVisible {
            path: PathBuf::from("/contract.json"),
            source: io::Error::new(io::ErrorKind::NotFound, "no such file or directory"),
        },
        "contract /contract.json is not visible in guest: no such file or directory",
        true,
    );
    assert_error_display(
        &InitError::ContractNotRegularFile {
            path: PathBuf::from("/contract.json"),
        },
        "contract /contract.json is not a regular file",
        false,
    );
    assert_error_display(
        &InitError::ReadContract {
            path: PathBuf::from("/contract.json"),
            source: io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"),
        },
        "read contract /contract.json: permission denied",
        true,
    );
    assert_error_display(
        &InitError::ParseContract {
            path: PathBuf::from("/contract.json"),
            source: malformed_json_error()?,
        },
        "parse contract /contract.json:",
        true,
    );
    assert_error_display(
        &InitError::InvalidContractVersion { version: 2 },
        "unsupported contract version 2",
        false,
    );
    assert_error_display(
        &InitError::EmptyExecutable,
        "command.executable must not be empty",
        false,
    );
    assert_error_display(
        &InitError::RelativeCommandCwd {
            path: PathBuf::from("workspace"),
        },
        "command.cwd must be absolute: workspace",
        false,
    );
    assert_error_display(
        &InitError::SecretEnvKey {
            key: "FIRMA_CAPABILITY_TOKEN",
        },
        "command.env contains secret key FIRMA_CAPABILITY_TOKEN",
        false,
    );
    assert_error_display(
        &InitError::RelativeMountTarget {
            path: PathBuf::from("workspace"),
        },
        "mount.target must be absolute: workspace",
        false,
    );
    assert_error_display(
        &InitError::MissingShareSource {
            path: PathBuf::from("/firma-shares/mount0"),
        },
        "missing VZ share source /firma-shares/mount0",
        false,
    );
    assert_error_display(
        &InitError::SpawnCommand {
            executable: "codex".to_string(),
            source: io::Error::new(io::ErrorKind::NotFound, "no such file or directory"),
        },
        "spawn command codex: no such file or directory",
        true,
    );
    assert_error_display(
        &InitError::CommandMissingStatus,
        "command ended without exit code or signal",
        false,
    );
    assert_error_display(
        &InitError::ResultPathWithoutParent {
            path: PathBuf::from("/"),
        },
        "contract path / has no parent for result",
        false,
    );
    assert_error_display(
        &InitError::SerializeGuestResult {
            path: PathBuf::from("/guest-result.json"),
            source: malformed_json_error()?,
        },
        "serialize guest result /guest-result.json:",
        true,
    );
    assert_error_display(
        &InitError::WriteGuestResultTemp {
            path: PathBuf::from("/guest-result.json.tmp"),
            source: io::Error::new(io::ErrorKind::ReadOnlyFilesystem, "read-only file system"),
        },
        "write guest result temp /guest-result.json.tmp: read-only file system",
        true,
    );
    assert_error_display(
        &InitError::StatGuestResultTemp {
            path: PathBuf::from("/guest-result.json.tmp"),
            source: io::Error::new(io::ErrorKind::NotFound, "no such file or directory"),
        },
        "stat guest result temp /guest-result.json.tmp: no such file or directory",
        true,
    );
    assert_error_display(
        &InitError::SetGuestResultTempPermissions {
            path: PathBuf::from("/guest-result.json.tmp"),
            source: io::Error::new(io::ErrorKind::PermissionDenied, "operation not permitted"),
        },
        "set guest result temp permissions /guest-result.json.tmp: operation not permitted",
        true,
    );
    assert_error_display(
        &InitError::RenameGuestResult {
            from: PathBuf::from("/guest-result.json.tmp"),
            to: PathBuf::from("/guest-result.json"),
            source: io::Error::new(io::ErrorKind::CrossesDevices, "cross-device link"),
        },
        "rename guest result /guest-result.json.tmp to /guest-result.json: cross-device link",
        true,
    );
    assert_error_display(
        &InitError::OpenModule {
            path: PathBuf::from("/lib/modules/firma-vz/virtio.ko"),
            source: io::Error::new(io::ErrorKind::NotFound, "no such file or directory"),
        },
        "open module /lib/modules/firma-vz/virtio.ko: no such file or directory",
        true,
    );
    assert_error_display(
        &InitError::ModuleParams {
            source: io::Error::new(io::ErrorKind::InvalidInput, "nul byte in module params"),
        },
        "create module params CString: nul byte in module params",
        true,
    );
    assert_error_display(
        &InitError::LoadModule {
            path: PathBuf::from("/lib/modules/firma-vz/virtio.ko"),
            source: io::Error::new(io::ErrorKind::InvalidData, "invalid module format"),
        },
        "load module /lib/modules/firma-vz/virtio.ko: invalid module format",
        true,
    );

    Ok(())
}

fn valid_contract_json() -> Result<serde_json::Value, Box<dyn Error>> {
    Ok(serde_json::from_str(VALID_CONTRACT_JSON)?)
}

fn write_contract_json(
    dir: &Path,
    contract: &serde_json::Value,
) -> Result<PathBuf, Box<dyn Error>> {
    let contract_path = dir.join("vz-guest-launch.json");
    fs::write(&contract_path, serde_json::to_vec(&contract)?)?;
    Ok(contract_path)
}

fn valid_launch_contract() -> LaunchContract {
    LaunchContract {
        version: 1,
        command: CommandContract {
            executable: "/bin/true".to_string(),
            args: Vec::new(),
            cwd: PathBuf::from("/workspace"),
            env: BTreeMap::new(),
        },
        mounts: vec![MountContract {
            target: PathBuf::from("/workspace"),
            read_only: false,
        }],
    }
}

fn expect_init_error<T>(
    result: InitResult<T>,
    message: &'static str,
) -> Result<InitError, Box<dyn Error>> {
    let Err(error) = result else {
        return Err(io::Error::other(message).into());
    };

    Ok(error)
}

fn assert_error_display(error: &InitError, expected: &str, has_source: bool) {
    let rendered = error.to_string();
    assert!(
        rendered.contains(expected),
        "expected {rendered:?} to contain {expected:?}"
    );
    assert_eq!(
        std::error::Error::source(&error).is_some(),
        has_source,
        "unexpected source status for {rendered:?}"
    );
}

fn malformed_json_error() -> Result<serde_json::Error, Box<dyn Error>> {
    let Err(error) = serde_json::from_str::<serde_json::Value>("{") else {
        return Err(io::Error::other("malformed JSON fixture unexpectedly parsed").into());
    };

    Ok(error)
}

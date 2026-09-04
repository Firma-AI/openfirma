use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context as _, Result, anyhow};
use serde_json::{Value, json};

const ROOT_PLACEHOLDER: &str = "${ROOT}";
const VALID_CONTRACT_JSON: &str = include_str!("../../src/contract/fixtures/valid-contract.json");

#[test]
fn rejects_implicit_runtime_share_aliasing_sensitive_ancestor() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let real_runtime = temp.path().join("real-runtime");
    let runtime_alias = temp.path().join("runtime-alias");
    std::fs::create_dir(&real_runtime)?;
    symlink(&real_runtime, &runtime_alias)?;

    let stderr = run_secret_shim_contract(
        temp.path(),
        &runtime_alias,
        &temp.path().join("safe-mount"),
        &real_runtime.join("secret-shims"),
        &temp.path().join("broker.sock"),
    )?;

    insta::assert_snapshot!(stderr, @"firma-vz-runner: writable guest share runtime source [ROOT]/runtime-alias aliases or overlaps secret_shims.shim_share_directory [ROOT]/real-runtime/secret-shims (canonical paths: [ROOT]/real-runtime, [ROOT]/real-runtime/secret-shims)\n");
    Ok(())
}

#[test]
fn rejects_writable_ancestor_of_sensitive_path() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let control = temp.path().join("control");
    let stderr = run_secret_shim_contract(
        temp.path(),
        &temp.path().join("runtime"),
        &control,
        &control.join("secret-shims"),
        &temp.path().join("broker.sock"),
    )?;

    insta::assert_snapshot!(stderr, @"firma-vz-runner: writable guest share mount0 source [ROOT]/control aliases or overlaps secret_shims.shim_share_directory [ROOT]/control/secret-shims (canonical paths: [ROOT]/control, [ROOT]/control/secret-shims)\n");
    Ok(())
}

#[test]
fn rejects_writable_ancestor_of_broker_socket() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let control = temp.path().join("control");
    let stderr = run_secret_shim_contract(
        temp.path(),
        &temp.path().join("runtime"),
        &control,
        &temp.path().join("secret-shims"),
        &control.join("broker.sock"),
    )?;

    insta::assert_snapshot!(stderr, @"firma-vz-runner: writable guest share mount0 source [ROOT]/control aliases or overlaps secret_shims.broker_socket_path [ROOT]/control/broker.sock (canonical paths: [ROOT]/control, [ROOT]/control/broker.sock)\n");
    Ok(())
}

#[test]
fn rejects_writable_descendant_of_sensitive_directory() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let shim_dir = temp.path().join("secret-shims");
    let stderr = run_secret_shim_contract(
        temp.path(),
        &temp.path().join("runtime"),
        &shim_dir.join("writable-child"),
        &shim_dir,
        &temp.path().join("broker.sock"),
    )?;

    insta::assert_snapshot!(stderr, @"firma-vz-runner: writable guest share mount0 source [ROOT]/secret-shims/writable-child aliases or overlaps secret_shims.shim_share_directory [ROOT]/secret-shims (canonical paths: [ROOT]/secret-shims/writable-child, [ROOT]/secret-shims)\n");
    Ok(())
}

#[test]
fn rejects_writable_alias_of_sensitive_directory() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let shim_dir = temp.path().join("secret-shims");
    std::fs::create_dir(&shim_dir)?;
    let shim_alias = temp.path().join("shim-alias");
    symlink(&shim_dir, &shim_alias)?;

    let stderr = run_secret_shim_contract(
        temp.path(),
        &temp.path().join("runtime"),
        &shim_alias,
        &shim_dir,
        &temp.path().join("broker.sock"),
    )?;

    insta::assert_snapshot!(stderr, @"firma-vz-runner: writable guest share mount0 source [ROOT]/shim-alias aliases or overlaps secret_shims.shim_share_directory [ROOT]/secret-shims (canonical paths: [ROOT]/secret-shims, [ROOT]/secret-shims)\n");
    Ok(())
}

#[test]
fn rejects_working_directory_like_writable_ancestor() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let stderr = run_secret_shim_contract(
        temp.path(),
        &temp.path().join("runtime"),
        temp.path(),
        &temp.path().join("control/secret-shims"),
        &temp.path().join("control/broker.sock"),
    )?;

    insta::assert_snapshot!(stderr, @"firma-vz-runner: writable guest share mount0 source [ROOT] aliases or overlaps secret_shims.shim_share_directory [ROOT]/control/secret-shims (canonical paths: [ROOT], [ROOT]/control/secret-shims)\n");
    Ok(())
}

#[test]
fn rejects_tmp_style_writable_ancestor() -> Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let stderr = run_secret_shim_contract(
        temp.path(),
        &temp.path().join("runtime"),
        Path::new("/tmp"),
        &temp.path().join("control/secret-shims"),
        &temp.path().join("control/broker.sock"),
    )?;

    insta::assert_snapshot!(stderr, @"firma-vz-runner: writable guest share mount0 source /tmp aliases or overlaps secret_shims.shim_share_directory [ROOT]/control/secret-shims (canonical paths: /tmp, [ROOT]/control/secret-shims)\n");
    Ok(())
}

#[test]
fn accepts_disjoint_writable_shares_and_sensitive_paths() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let contract_path = prepare_secret_shim_contract(
        temp.path(),
        &temp.path().join("runtime"),
        &temp.path().join("workspace"),
        &temp.path().join("control/secret-shims"),
        &temp.path().join("control/broker.sock"),
    )?;

    let output = run_validate_only(&contract_path)?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    insta::assert_snapshot!(stdout, @"validation ok: contract=checked vm_plan=checked sandbox_id=sbx_01j0000000e008000000000001 version=2\n");
    Ok(())
}

fn run_secret_shim_contract(
    root: &Path,
    runtime_dir: &Path,
    writable_mount: &Path,
    shim_dir: &Path,
    broker_socket: &Path,
) -> Result<String> {
    let contract_path =
        prepare_secret_shim_contract(root, runtime_dir, writable_mount, shim_dir, broker_socket)?;
    let output = run_validate_only(&contract_path)?;
    assert_failed(output, root)
}

fn prepare_secret_shim_contract(
    root: &Path,
    runtime_dir: &Path,
    writable_mount: &Path,
    shim_dir: &Path,
    broker_socket: &Path,
) -> Result<PathBuf> {
    write_artifacts(root)?;
    std::fs::create_dir_all(runtime_dir)?;
    std::fs::create_dir_all(writable_mount)?;
    std::fs::create_dir_all(shim_dir)?;
    let broker_parent = broker_socket
        .parent()
        .context("broker socket path must have a parent")?;
    std::fs::create_dir_all(broker_parent)?;
    std::fs::write(broker_socket, [])?;

    let mut contract: Value = serde_json::from_str(VALID_CONTRACT_JSON)?;
    let root_text = root.to_str().context("test root path must be UTF-8")?;
    replace_root_placeholder(&mut contract, root_text);
    contract["runtime_dir"] = json!(runtime_dir);
    contract["mounts"][0]["source"] = json!(writable_mount);
    contract["secret_shims"] = json!({
        "guest_target_triple": "x86_64-unknown-linux-musl",
        "provider_names": ["vault"],
        "broker_vsock_port": 18083,
        "shim_share_directory": shim_dir,
        "broker_socket_path": broker_socket,
        "guest_broker_addr": "127.0.0.1:18084",
    });

    let contract_path = runtime_dir.join("vz-guest/vz-guest-launch.json");
    let contract_parent = contract_path
        .parent()
        .context("contract path must have a parent")?;
    firma_fs::create_private_dir_all(contract_parent)?;
    firma_fs::write_private_file(&contract_path, &serde_json::to_vec_pretty(&contract)?)?;
    Ok(contract_path)
}

fn run_validate_only(contract_path: &Path) -> Result<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_firma-vz-runner"))
        .arg("--launch-contract")
        .arg(contract_path)
        .arg("--validate-only")
        .output()?)
}

fn assert_failed(output: Output, root: &Path) -> Result<String> {
    if output.status.success() {
        return Err(anyhow!("runner unexpectedly accepted overlapping paths"));
    }
    let stderr = String::from_utf8(output.stderr)?;
    let root = root.to_str().context("test root path must be UTF-8")?;
    if !stderr.contains(root) {
        return Err(anyhow!(
            "runner error did not identify a path beneath the test root"
        ));
    }
    Ok(stderr.replace(root, "[ROOT]"))
}

fn write_artifacts(root: &Path) -> Result<()> {
    for (name, size) in [
        ("firma-vz-runner", 1),
        ("vmlinuz", 1),
        ("initrd.img", 1),
        ("rootfs.img", 512),
    ] {
        let file = std::fs::File::create(root.join(name))?;
        file.set_len(size)?;
    }
    Ok(())
}

fn replace_root_placeholder(value: &mut Value, root: &str) {
    match value {
        Value::String(text) => *text = text.replace(ROOT_PLACEHOLDER, root),
        Value::Array(values) => {
            for value in values {
                replace_root_placeholder(value, root);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                replace_root_placeholder(value, root);
            }
        }
        Value::Bool(_) | Value::Null | Value::Number(_) => {}
    }
}

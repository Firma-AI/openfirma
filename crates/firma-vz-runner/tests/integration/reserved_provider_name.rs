use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, anyhow};
use serde_json::{Value, json};

const ROOT_PLACEHOLDER: &str = "${ROOT}";
const VALID_CONTRACT_JSON: &str = include_str!("../../src/contract/fixtures/valid-contract.json");

#[test]
fn accepts_former_broker_readiness_provider_name() -> Result<()> {
    let temp = tempfile::tempdir()?;
    write_artifacts(temp.path())?;
    let mut contract = contract_fixture(temp.path())?;
    add_secret_shims(&mut contract, temp.path());
    contract["secret_shims"]["provider_names"] = json!(["__firma_broker_readiness_probe__"]);

    let output = run_contract(temp.path(), &contract)?;

    if !output.status.success() {
        return Err(anyhow!(
            "runner rejected former readiness provider name: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    insta::assert_snapshot!(String::from_utf8(output.stdout)?, @"validation ok: contract=checked vm_plan=checked sandbox_id=sbx_01j0000000e008000000000001 version=2\n");
    assert_eq!(String::from_utf8(output.stderr)?, "");
    Ok(())
}

#[test]
fn rejects_duplicate_provider_before_vm_planning() -> Result<()> {
    let temp = tempfile::tempdir()?;
    write_artifacts(temp.path())?;
    let mut contract = contract_fixture(temp.path())?;
    add_secret_shims(&mut contract, temp.path());
    contract["secret_shims"]["provider_names"] = json!(["vault", "vault"]);

    let output = run_contract(temp.path(), &contract)?;

    if output.status.success() {
        return Err(anyhow!("runner unexpectedly accepted duplicate providers"));
    }
    assert_eq!(String::from_utf8(output.stdout)?, "");
    insta::assert_snapshot!(String::from_utf8(output.stderr)?, @"firma-vz-runner: secret_shims provider name must be unique: vault\n");
    Ok(())
}

#[test]
fn rejects_guest_broker_listener_collisions_before_vm_planning() -> Result<()> {
    for (addr, diagnostic) in [
        ("127.0.0.1:18080", "network.guest_http_proxy_addr"),
        ("127.0.0.1:1053", "network.guest_dns_stub_addr"),
        ("127.0.0.1:53", "guest DNS resolver listener"),
    ] {
        let temp = tempfile::tempdir()?;
        write_artifacts(temp.path())?;
        let mut contract = contract_fixture(temp.path())?;
        add_secret_shims(&mut contract, temp.path());
        contract["secret_shims"]["guest_broker_addr"] = json!(addr);

        let output = run_contract(temp.path(), &contract)?;

        if output.status.success() {
            return Err(anyhow!(
                "runner unexpectedly accepted broker collision with {diagnostic}"
            ));
        }
        assert_eq!(String::from_utf8(output.stdout)?, "");
        assert_eq!(
            String::from_utf8(output.stderr)?,
            format!(
                "firma-vz-runner: secret_shims.guest_broker_addr must be distinct from {diagnostic}\n"
            )
        );
    }
    Ok(())
}

#[test]
fn rejects_vmaddr_port_any_for_every_vsock_role() -> Result<()> {
    for field in [
        "network.vsock_sidecar_port",
        "terminal.pty_vsock_port",
        "terminal.pty_control_vsock_port",
        "secret_shims.broker_vsock_port",
    ] {
        let temp = tempfile::tempdir()?;
        write_artifacts(temp.path())?;
        let mut contract = contract_fixture(temp.path())?;
        contract["terminal"]["interactive"] = json!(true);
        contract["terminal"]["pty"] = json!(true);
        contract["terminal"]["pty_vsock_port"] = json!(18081);
        contract["terminal"]["pty_control_vsock_port"] = json!(18082);
        add_secret_shims(&mut contract, temp.path());

        match field {
            "network.vsock_sidecar_port" => {
                contract["network"]["vsock_sidecar_port"] = json!(u32::MAX);
            }
            "terminal.pty_vsock_port" => {
                contract["terminal"]["pty_vsock_port"] = json!(u32::MAX);
            }
            "terminal.pty_control_vsock_port" => {
                contract["terminal"]["pty_control_vsock_port"] = json!(u32::MAX);
            }
            "secret_shims.broker_vsock_port" => {
                contract["secret_shims"]["broker_vsock_port"] = json!(u32::MAX);
            }
            _ => return Err(anyhow!("unhandled VSOCK role {field}")),
        }

        let output = run_contract(temp.path(), &contract)?;
        if output.status.success() {
            return Err(anyhow!("runner unexpectedly accepted {field}=u32::MAX"));
        }
        assert_eq!(String::from_utf8(output.stdout)?, "");
        assert_eq!(
            String::from_utf8(output.stderr)?,
            format!(
                "firma-vz-runner: {field} must not use reserved VMADDR_PORT_ANY port 4294967295\n"
            )
        );
    }
    Ok(())
}

#[test]
fn rejects_zero_for_every_vsock_role() -> Result<()> {
    for (field, diagnostic) in [
        (
            "network.vsock_sidecar_port",
            "network.vsock_sidecar_port must be non-zero",
        ),
        (
            "terminal.pty_vsock_port",
            "terminal.pty=true requires non-zero terminal.pty_vsock_port",
        ),
        (
            "terminal.pty_control_vsock_port",
            "terminal.pty=true requires non-zero terminal.pty_control_vsock_port",
        ),
        (
            "secret_shims.broker_vsock_port",
            "secret_shims.broker_vsock_port must be non-zero",
        ),
    ] {
        let temp = tempfile::tempdir()?;
        write_artifacts(temp.path())?;
        let mut contract = contract_fixture(temp.path())?;
        contract["terminal"]["interactive"] = json!(true);
        contract["terminal"]["pty"] = json!(true);
        contract["terminal"]["pty_vsock_port"] = json!(18081);
        contract["terminal"]["pty_control_vsock_port"] = json!(18082);
        add_secret_shims(&mut contract, temp.path());

        match field {
            "network.vsock_sidecar_port" => {
                contract["network"]["vsock_sidecar_port"] = json!(0);
            }
            "terminal.pty_vsock_port" => {
                contract["terminal"]["pty_vsock_port"] = json!(0);
            }
            "terminal.pty_control_vsock_port" => {
                contract["terminal"]["pty_control_vsock_port"] = json!(0);
            }
            "secret_shims.broker_vsock_port" => {
                contract["secret_shims"]["broker_vsock_port"] = json!(0);
            }
            _ => return Err(anyhow!("unhandled VSOCK role {field}")),
        }

        let output = run_contract(temp.path(), &contract)?;
        if output.status.success() {
            return Err(anyhow!("runner unexpectedly accepted {field}=0"));
        }
        assert_eq!(String::from_utf8(output.stdout)?, "");
        assert_eq!(
            String::from_utf8(output.stderr)?,
            format!("firma-vz-runner: {diagnostic}\n")
        );
    }
    Ok(())
}

#[test]
fn reports_vsock_collisions_with_both_role_labels() -> Result<()> {
    let temp = tempfile::tempdir()?;
    write_artifacts(temp.path())?;
    let mut contract = contract_fixture(temp.path())?;
    add_secret_shims(&mut contract, temp.path());
    contract["secret_shims"]["broker_vsock_port"] =
        contract["network"]["vsock_sidecar_port"].clone();

    let output = run_contract(temp.path(), &contract)?;

    if output.status.success() {
        return Err(anyhow!(
            "runner unexpectedly accepted colliding VSOCK ports"
        ));
    }
    assert_eq!(String::from_utf8(output.stdout)?, "");
    insta::assert_snapshot!(String::from_utf8(output.stderr)?, @"firma-vz-runner: secret_shims.broker_vsock_port must be distinct from network.vsock_sidecar_port\n");
    Ok(())
}

fn contract_fixture(root: &Path) -> Result<Value> {
    let mut contract: Value = serde_json::from_str(VALID_CONTRACT_JSON)?;
    let root = root.to_str().context("test root path must be UTF-8")?;
    replace_root_placeholder(&mut contract, root);
    contract["mounts"][0]["source"] = json!(Path::new(root).join("workspace"));
    Ok(contract)
}

fn add_secret_shims(contract: &mut Value, root: &Path) {
    contract["secret_shims"] = json!({
        "guest_target_triple": "x86_64-unknown-linux-musl",
        "provider_names": ["vault"],
        "broker_vsock_port": 18083,
        "shim_share_directory": root.join("control/secret-shims"),
        "broker_socket_path": root.join("control/broker.sock"),
        "guest_broker_addr": "127.0.0.1:18084",
    });
}

fn run_contract(root: &Path, contract: &Value) -> Result<std::process::Output> {
    let runtime_dir = root.join("runtime");
    std::fs::create_dir_all(&runtime_dir)?;
    let contract_path = runtime_dir.join("vz-guest-launch.json");
    firma_fs::write_private_file(&contract_path, &serde_json::to_vec_pretty(contract)?)?;
    Ok(Command::new(env!("CARGO_BIN_EXE_firma-vz-runner"))
        .arg("--launch-contract")
        .arg(contract_path)
        .arg("--validate-only")
        .output()?)
}
fn write_artifacts(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root.join("workspace"))?;
    std::fs::create_dir_all(root.join("control/secret-shims"))?;
    std::fs::File::create(root.join("control/broker.sock"))?;
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

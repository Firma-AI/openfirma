use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, anyhow};
use serde_json::{Value, json};

const ROOT_PLACEHOLDER: &str = "${ROOT}";
const VALID_CONTRACT_JSON: &str = include_str!("../../src/contract/fixtures/valid-contract.json");

#[test]
fn rejects_reserved_broker_readiness_provider_before_vm_planning() -> Result<()> {
    let temp = tempfile::tempdir()?;
    write_artifacts(temp.path())?;

    let mut contract: Value = serde_json::from_str(VALID_CONTRACT_JSON)?;
    let root = temp
        .path()
        .to_str()
        .context("test root path must be UTF-8")?;
    replace_root_placeholder(&mut contract, root);
    contract["secret_shims"] = json!({
        "guest_target_triple": "x86_64-unknown-linux-musl",
        "provider_names": ["__firma_broker_readiness_probe__"],
        "broker_vsock_port": 18083,
        "shim_share_directory": temp.path().join("control/secret-shims"),
        "broker_socket_path": temp.path().join("control/broker.sock"),
        "guest_broker_addr": "127.0.0.1:18084",
    });

    let contract_path = temp.path().join("vz-guest-launch.json");
    firma_fs::write_private_file(&contract_path, &serde_json::to_vec_pretty(&contract)?)?;
    let output = Command::new(env!("CARGO_BIN_EXE_firma-vz-runner"))
        .arg("--launch-contract")
        .arg(&contract_path)
        .arg("--validate-only")
        .output()?;

    if output.status.success() {
        return Err(anyhow!(
            "runner unexpectedly accepted reserved provider name"
        ));
    }
    assert_eq!(String::from_utf8(output.stdout)?, "");
    insta::assert_snapshot!(String::from_utf8(output.stderr)?, @"firma-vz-runner: secret_shims provider name is reserved for internal broker readiness checks: __firma_broker_readiness_probe__\n");
    Ok(())
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

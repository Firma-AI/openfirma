use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context as _, Result, anyhow};
use serde_json::{Value, json};

const ROOT_PLACEHOLDER: &str = "${ROOT}";
const VALID_CONTRACT_JSON: &str = include_str!("../../src/contract/fixtures/valid-contract.json");

#[test]
fn rejects_malformed_sandbox_id_during_parse() -> Result<()> {
    let stderr = run_contract_with_sandbox_id("../outside")?;

    insta::assert_snapshot!(stderr, @"firma-vz-runner: parse VZ launch contract [CONTRACT]: sandbox id must start with `sbx` as prefix: `../outside` does not at line 3 column 28");
    Ok(())
}

#[test]
fn rejects_non_v7_sandbox_id_during_parse() -> Result<()> {
    let stderr = run_contract_with_sandbox_id("sbx_2n1t201rmv88eb2sj4cn248g00")?;

    insta::assert_snapshot!(stderr, @"firma-vz-runner: parse VZ launch contract [CONTRACT]: sandbox id must be backed by a UUID v7: `sbx_2n1t201rmv88eb2sj4cn248g00` is backed by a UUID v4 at line 3 column 48");
    Ok(())
}

#[test]
fn rejects_missing_sandbox_attribution_header() -> Result<()> {
    let stderr = run_contract(
        |contract| {
            contract["network"]["attribution_headers"]
                .as_object_mut()
                .ok_or_else(|| anyhow!("attribution_headers must be an object"))?
                .remove("x-firma-sandbox-id");
            Ok(())
        },
        true,
    )?;

    insta::assert_snapshot!(stderr, @"firma-vz-runner: network.attribution_headers must contain x-firma-sandbox-id");
    Ok(())
}

#[test]
fn rejects_duplicate_case_insensitive_sandbox_attribution_headers() -> Result<()> {
    let stderr = run_contract(
        |contract| {
            contract["network"]["attribution_headers"]["X-Firma-Sandbox-Id"] =
                json!("sbx_01j0000000e008000000000001");
            Ok(())
        },
        true,
    )?;

    insta::assert_snapshot!(stderr, @"firma-vz-runner: network.attribution_headers contains duplicate x-firma-sandbox-id names");
    Ok(())
}

#[test]
fn rejects_invalid_sandbox_attribution_header() -> Result<()> {
    let stderr = run_contract(
        |contract| {
            contract["network"]["attribution_headers"]["x-firma-sandbox-id"] =
                json!("sbx_2n1t201rmv88eb2sj4cn248g00");
            Ok(())
        },
        true,
    )?;

    insta::assert_snapshot!(stderr, @"firma-vz-runner: network x-firma-sandbox-id value 'sbx_2n1t201rmv88eb2sj4cn248g00' is invalid: sandbox id must be backed by a UUID v7: `sbx_2n1t201rmv88eb2sj4cn248g00` is backed by a UUID v4");
    Ok(())
}

#[test]
fn rejects_mismatched_sandbox_attribution_header() -> Result<()> {
    let stderr = run_contract(
        |contract| {
            contract["network"]["attribution_headers"]["x-firma-sandbox-id"] =
                json!("sbx_01j0000000e008000000000002");
            Ok(())
        },
        true,
    )?;

    insta::assert_snapshot!(stderr, @"firma-vz-runner: network x-firma-sandbox-id sbx_01j0000000e008000000000002 does not match contract sandbox_id sbx_01j0000000e008000000000001");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
#[test]
fn rejects_unsupported_host_after_validation() -> Result<()> {
    let stderr = run_contract(|_| Ok(()), false)?;

    insta::assert_snapshot!(stderr, @"firma-vz-runner: firma-vz-runner is macOS-only; parsed contract v2 for sandbox sbx_01j0000000e008000000000001");
    Ok(())
}

fn run_contract<F>(mutate: F, validate_only: bool) -> Result<String>
where
    F: FnOnce(&mut Value) -> Result<()>,
{
    let temp = tempfile::tempdir()?;
    write_artifacts(temp.path())?;

    let mut contract: Value = serde_json::from_str(VALID_CONTRACT_JSON)?;
    let root = temp
        .path()
        .to_str()
        .context("test contract root path must be UTF-8")?;
    replace_root_placeholder(&mut contract, root);
    mutate(&mut contract)?;

    let contract_path = write_contract(temp.path(), serde_json::to_vec_pretty(&contract)?)?;

    let mut command = Command::new(env!("CARGO_BIN_EXE_firma-vz-runner"));
    command.arg("--launch-contract").arg(&contract_path);
    if validate_only {
        command.arg("--validate-only");
    }
    let output = command.output()?;
    assert_failed(output, &contract_path)
}

fn run_contract_with_sandbox_id(sandbox_id: &str) -> Result<String> {
    let temp = tempfile::tempdir()?;
    write_artifacts(temp.path())?;

    let root = temp
        .path()
        .to_str()
        .context("test contract root path must be UTF-8")?;
    let contract = VALID_CONTRACT_JSON
        .replace(ROOT_PLACEHOLDER, root)
        .replacen("sbx_01j0000000e008000000000001", sandbox_id, 1);
    let contract_path = write_contract(temp.path(), contract)?;

    let output = Command::new(env!("CARGO_BIN_EXE_firma-vz-runner"))
        .arg("--launch-contract")
        .arg(&contract_path)
        .arg("--validate-only")
        .output()?;
    assert_failed(output, &contract_path)
}

fn assert_failed(output: Output, contract_path: &Path) -> Result<String> {
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    let contract_path = contract_path
        .to_str()
        .context("test contract path must be UTF-8")?;
    if stderr.contains(contract_path) {
        return Ok(stderr.replace(contract_path, "[CONTRACT]"));
    }
    Ok(stderr)
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

fn write_contract(root: &Path, contents: impl AsRef<[u8]>) -> Result<PathBuf> {
    let contract_path = root
        .join("runtime")
        .join("vz-guest")
        .join("vz-guest-launch.json");
    let contract_dir = contract_path
        .parent()
        .context("test contract path must have a parent")?;
    firma_fs::create_private_dir_all(contract_dir)?;
    firma_fs::write_private_file(&contract_path, contents.as_ref())?;
    Ok(contract_path)
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

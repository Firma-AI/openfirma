use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde_json::{Value, json};

use crate::contract::{Contract, ContractDocument};
#[cfg(target_os = "macos")]
use crate::vm::VmPlan;

#[cfg(target_os = "macos")]
pub const VZ_TEST_ROOTFS_SIZE_BYTES: u64 = 64 * 1024 * 1024;

pub const VALID_ROOTFS_SIZE_BYTES: u64 = 512;
pub const UNALIGNED_ROOTFS_SIZE_BYTES: u64 = 513;

const ROOT_PLACEHOLDER: &str = "${ROOT}";
const VALID_CONTRACT_JSON: &str = include_str!("contract/fixtures/valid-contract.json");

pub fn valid_contract_json(root: &Path) -> Result<Value> {
    write_artifacts(root, VALID_ROOTFS_SIZE_BYTES)?;
    std::fs::create_dir_all(root.join("runtime"))?;

    valid_contract_json_without_artifacts(root)
}

pub fn valid_contract_json_without_artifacts(root: &Path) -> Result<Value> {
    let mut json = serde_json::from_str(VALID_CONTRACT_JSON)?;
    let root = root
        .to_str()
        .context("test contract root path must be UTF-8")?;

    replace_root_placeholder(&mut json, root);
    Ok(json)
}

pub fn write_contract(root: &Path, mount_source: &Path) -> Result<PathBuf> {
    write_contract_with_rootfs_size(root, mount_source, VALID_ROOTFS_SIZE_BYTES)
}

pub fn write_contract_with_rootfs_size(
    root: &Path,
    mount_source: &Path,
    rootfs_size: u64,
) -> Result<PathBuf> {
    let runtime_dir = root.join("runtime");
    let contract_path = runtime_dir.join("vz-guest").join("vz-guest-launch.json");

    write_contract_at(
        root,
        mount_source,
        &runtime_dir,
        &contract_path,
        rootfs_size,
    )
}

pub fn write_contract_at(
    root: &Path,
    mount_source: &Path,
    runtime_dir: &Path,
    contract_path: &Path,
    rootfs_size: u64,
) -> Result<PathBuf> {
    if let Some(contract_dir) = contract_path.parent() {
        std::fs::create_dir_all(contract_dir)?;
    }

    write_artifacts(root, rootfs_size)?;

    let mut contract = valid_contract_json_without_artifacts(root)?;
    contract["runtime_dir"] = json!(runtime_dir);
    contract["mounts"][0]["source"] = json!(mount_source);

    std::fs::write(contract_path, serde_json::to_vec(&contract)?)?;

    Ok(contract_path.to_path_buf())
}

pub fn read_contract_without_custody(path: &Path) -> Result<Contract> {
    Ok(ContractDocument::read_fixture_from_path_without_custody(path)?.validate()?)
}

#[cfg(target_os = "macos")]
pub fn vm_plan_fixture(rootfs_size: u64) -> Result<(tempfile::TempDir, VmPlan)> {
    let temp = tempfile::tempdir()?;
    let contract_path = write_contract_with_rootfs_size(temp.path(), temp.path(), rootfs_size)?;
    let contract = read_contract_without_custody(&contract_path)?;
    let plan = VmPlan::from_contract(&contract)?;

    Ok((temp, plan))
}

pub fn write_artifacts(root: &Path, rootfs_size: u64) -> Result<()> {
    for artifact in ["firma-vz-runner", "vmlinuz", "initrd.img"] {
        touch(root.join(artifact), 1)?;
    }
    touch(root.join("rootfs.img"), rootfs_size)?;
    Ok(())
}

pub fn touch(path: PathBuf, size: u64) -> Result<PathBuf> {
    let file = std::fs::File::create(&path)?;
    file.set_len(size)?;
    Ok(path)
}

fn replace_root_placeholder(value: &mut Value, root: &str) {
    match value {
        Value::String(text) => {
            if text.contains(ROOT_PLACEHOLDER) {
                *text = text.replace(ROOT_PLACEHOLDER, root);
            }
        }
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

#[cfg(unix)]
pub fn make_contract_file_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
pub fn make_contract_file_owner_only(path: &Path) -> Result<()> {
    let _metadata = std::fs::metadata(path)?;
    Ok(())
}

use std::path::Path;

use anyhow::Result;
use serde_json::{Value, json};

use crate::contract::ContractDocument;

use super::VmPlanError;
use super::plan::{FIRMA_VIRTIOFS_TAG, VmPlan};

const ROOT_PLACEHOLDER: &str = "${ROOT}";
const VALID_CONTRACT_JSON: &str = include_str!("../contract/fixtures/valid-contract.json");
const VALID_ROOTFS_SIZE_BYTES: u64 = 512;
const UNALIGNED_ROOTFS_SIZE_BYTES: u64 = 513;

#[test]
fn vm_plan_exposes_contract_and_mounts_without_network_devices() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    std::fs::create_dir(&workspace)?;
    let contract_path = write_contract(temp.path(), &workspace)?;

    let contract = read_contract_without_custody(&contract_path)?;
    let plan = VmPlan::from_contract(&contract)?;

    assert_eq!(plan.network_devices.len(), 0);
    assert!(plan.runtime_dir.ends_with("runtime"));
    assert!(plan.kernel.ends_with("vmlinuz"));
    assert!(plan.initrd.ends_with("initrd.img"));
    assert!(plan.rootfs.ends_with("rootfs.img"));
    assert_eq!(plan.directory_shares.len(), 2);
    assert_eq!(plan.directory_shares[0].name, "runtime");
    assert!(plan.directory_shares[0].read_only);
    assert_eq!(plan.directory_shares[1].name, "mount0");
    assert!(!plan.directory_shares[1].read_only);
    assert!(
        plan.kernel_command_line
            .contains(&format!("firma.virtiofs_tag={FIRMA_VIRTIOFS_TAG}"))
    );
    assert!(
        plan.kernel_command_line
            .contains("firma.launch_contract=/runtime/vz-guest/vz-guest-launch.json")
    );
    assert!(plan.kernel_command_line.contains("firma.network=none"));

    Ok(())
}

#[test]
fn vm_plan_rejects_file_mount_sources() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mount_file = temp.path().join("not-a-dir");
    std::fs::write(&mount_file, "file")?;
    let contract_path = write_contract(temp.path(), &mount_file)?;

    let contract = read_contract_without_custody(&contract_path)?;
    let error = VmPlan::from_contract(&contract).err().ok_or_else(|| {
        anyhow::anyhow!("VM plan should reject file-backed virtiofs mount sources")
    })?;

    assert!(matches!(
        error,
        VmPlanError::MountSourceNotDirectory { ref path } if path == &mount_file
    ));

    Ok(())
}

#[test]
fn vm_plan_rejects_contract_outside_runtime_dir() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    std::fs::create_dir(&workspace)?;
    let runtime_dir = temp.path().join("runtime");
    let contract_path = temp.path().join("other").join("vz-guest-launch.json");
    write_contract_at(
        temp.path(),
        &workspace,
        &runtime_dir,
        &contract_path,
        VALID_ROOTFS_SIZE_BYTES,
    )?;

    let contract = read_contract_without_custody(&contract_path)?;
    let error = VmPlan::from_contract(&contract)
        .err()
        .ok_or_else(|| anyhow::anyhow!("VM plan should reject contracts outside runtime"))?;

    assert!(matches!(
        error,
        VmPlanError::ContractOutsideRuntimeDir {
            contract_path: ref actual_contract_path,
            ref runtime_dir,
        } if actual_contract_path == &contract_path && runtime_dir == runtime_dir
    ));

    Ok(())
}

#[test]
fn vm_plan_rejects_unaligned_rootfs_image() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    std::fs::create_dir(&workspace)?;
    let contract_path =
        write_contract_with_rootfs_size(temp.path(), &workspace, UNALIGNED_ROOTFS_SIZE_BYTES)?;

    let contract = read_contract_without_custody(&contract_path)?;
    let error = VmPlan::from_contract(&contract)
        .err()
        .ok_or_else(|| anyhow::anyhow!("VM plan should reject unaligned rootfs image"))?;

    assert!(matches!(
        error,
        VmPlanError::RootfsUnaligned {
            size: UNALIGNED_ROOTFS_SIZE_BYTES,
            ..
        }
    ));

    Ok(())
}

#[test]
fn vm_plan_rejects_missing_runtime_dir() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    std::fs::create_dir(&workspace)?;
    let runtime_dir = temp.path().join("runtime");
    let contract_path = runtime_dir.join("vz-guest").join("vz-guest-launch.json");
    write_contract_at(
        temp.path(),
        &workspace,
        &runtime_dir,
        &contract_path,
        VALID_ROOTFS_SIZE_BYTES,
    )?;

    let contract = read_contract_without_custody(&contract_path)?;
    std::fs::remove_dir_all(&runtime_dir)?;

    let error = VmPlan::from_contract(&contract)
        .err()
        .ok_or_else(|| anyhow::anyhow!("VM plan should reject missing runtime dir"))?;

    assert!(matches!(
        error,
        VmPlanError::RuntimeDirMissing { ref path } if path == &runtime_dir
    ));

    Ok(())
}

/// Writes a valid launch contract using the default rootfs fixture size.
fn write_contract(root: &Path, mount_source: &Path) -> Result<std::path::PathBuf> {
    let runtime_dir = root.join("runtime");
    let contract_dir = runtime_dir.join("vz-guest");
    let contract_path = contract_dir.join("vz-guest-launch.json");
    write_contract_at(
        root,
        mount_source,
        &runtime_dir,
        &contract_path,
        VALID_ROOTFS_SIZE_BYTES,
    )
}

/// Writes a valid launch contract with an explicitly sized rootfs fixture.
fn write_contract_with_rootfs_size(
    root: &Path,
    mount_source: &Path,
    rootfs_size: u64,
) -> Result<std::path::PathBuf> {
    let runtime_dir = root.join("runtime");
    let contract_dir = runtime_dir.join("vz-guest");
    let contract_path = contract_dir.join("vz-guest-launch.json");
    write_contract_at(
        root,
        mount_source,
        &runtime_dir,
        &contract_path,
        rootfs_size,
    )
}

/// Writes a launch contract fixture at an exact path and runtime directory.
fn write_contract_at(
    root: &Path,
    mount_source: &Path,
    runtime_dir: &Path,
    contract_path: &Path,
    rootfs_size: u64,
) -> Result<std::path::PathBuf> {
    if let Some(contract_dir) = contract_path.parent() {
        std::fs::create_dir_all(contract_dir)?;
    }

    write_artifacts(root, rootfs_size)?;

    let mut contract = valid_contract_json(root)?;
    contract["runtime_dir"] = json!(runtime_dir);
    contract["mounts"][0]["source"] = json!(mount_source);

    std::fs::write(contract_path, serde_json::to_vec(&contract)?)?;

    Ok(contract_path.to_path_buf())
}

/// Reads a contract fixture while deliberately skipping file custody checks.
fn read_contract_without_custody(path: &Path) -> Result<crate::contract::Contract> {
    Ok(ContractDocument::read_fixture_from_path_without_custody(path)?.validate()?)
}

/// Loads the shared valid contract fixture with its root placeholder resolved.
fn valid_contract_json(root: &Path) -> Result<Value> {
    let mut json = serde_json::from_str(VALID_CONTRACT_JSON)?;
    let root = root
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("test root path must be UTF-8"))?;

    replace_root_placeholder(&mut json, root);
    Ok(json)
}

/// Replaces all root placeholders inside a JSON value tree.
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

/// Creates host artifact files referenced by the launch contract fixture.
fn write_artifacts(root: &Path, rootfs_size: u64) -> Result<()> {
    for artifact in ["firma-vz-runner", "vmlinuz", "initrd.img", "seccomp.bpf"] {
        touch(root.join(artifact), 1)?;
    }
    touch(root.join("rootfs.img"), rootfs_size)?;
    Ok(())
}

/// Creates a file fixture with the requested byte length.
fn touch(path: std::path::PathBuf, size: u64) -> Result<std::path::PathBuf> {
    let file = std::fs::File::create(&path)?;
    file.set_len(size)?;
    Ok(path)
}

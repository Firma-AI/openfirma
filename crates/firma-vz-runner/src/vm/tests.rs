use anyhow::Result;

use crate::test_utils::{
    UNALIGNED_ROOTFS_SIZE_BYTES, VALID_ROOTFS_SIZE_BYTES, read_contract_without_custody,
    write_contract, write_contract_at, write_contract_with_rootfs_size,
};

use super::VmPlanError;
use super::plan::{FIRMA_VIRTIOFS_TAG, SocketDeviceKind, VmNetworkMode, VmPlan};

#[test]
fn vm_plan_exposes_contract_and_mounts_without_network_devices() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    std::fs::create_dir(&workspace)?;
    let contract_path = write_contract(temp.path(), &workspace)?;

    let contract = read_contract_without_custody(&contract_path)?;
    let plan = VmPlan::from_contract(&contract)?;

    assert_eq!(plan.network_devices.len(), 0);
    assert_eq!(plan.socket_devices.len(), 1);
    assert_eq!(
        plan.socket_devices[0].kind,
        SocketDeviceKind::VirtioVsockSidecar
    );
    assert_eq!(plan.socket_devices[0].sidecar_port, 18080);
    assert_eq!(
        plan.socket_devices[0].sidecar_host_addr,
        "127.0.0.1:19080".parse()?
    );
    assert_eq!(plan.network_mode, VmNetworkMode::VsockSidecar);
    assert!(plan.runtime_dir.ends_with("runtime"));
    assert!(plan.kernel.ends_with("vmlinuz"));
    assert!(plan.initrd.ends_with("initrd.img"));
    assert!(plan.rootfs.ends_with("rootfs.img"));
    assert!(!plan.interactive);
    assert!(!plan.pty);
    assert_eq!(plan.term, None);
    assert_eq!(plan.rows, None);
    assert_eq!(plan.cols, None);
    assert_eq!(plan.directory_shares.len(), 2);
    assert_eq!(plan.directory_shares[0].name, "runtime");
    assert!(!plan.directory_shares[0].read_only);
    assert_eq!(plan.directory_shares[1].name, "mount0");
    assert!(!plan.directory_shares[1].read_only);
    assert!(
        plan.kernel_command_line
            .contains(&format!("firma.virtiofs_tag={FIRMA_VIRTIOFS_TAG}"))
    );
    assert!(
        plan.kernel_command_line
            .contains("firma.launch_contract=/firma-shares/runtime/vz-guest/vz-guest-launch.json")
    );
    assert!(
        plan.kernel_command_line
            .contains("firma.network=vsock_sidecar")
    );

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

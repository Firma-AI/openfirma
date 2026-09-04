mod boot;
mod command;
mod contract;
mod error;
mod mount;
mod network;
mod result;

#[cfg(test)]
mod tests;

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use boot::{BootContract, BootNetworkMode, parse_boot_contract};
use command::execute_contract;
use contract::{Contract, SecretShimsContract, accept_contract};
use error::InitResult;
use mount::{
    SHARE_ROOT, create_dir, load_required_modules, mount_contract_paths, mount_pseudo,
    mount_virtiofs, setup_pty_devices,
};
use network::{CommandNetworkEnv, NetworkServicesPlan, start_guest_network_services};
use result::{
    GuestHeartbeatPhase, write_boot_heartbeat, write_heartbeat, write_result, write_setup_error,
};

/// Runs the guest init lifecycle and powers the VM off after completion.
pub fn main() -> ! {
    let result = run();
    if let Err(error) = &result {
        let _ = writeln!(io::stderr(), "firma-init: {error}");
    }
    power_off();
}

/// Prepares the guest, accepts the launch contract, and runs the payload.
fn run() -> InitResult<()> {
    prepare_guest_root()?;
    let boot = parse_boot_contract()?;
    prepare_runtime_share(&boot)?;
    write_boot_heartbeat(&boot.launch_contract, GuestHeartbeatPhase::RuntimeMounted)?;

    let result = run_contract(&boot);
    record_setup_error_on_failure(&boot.launch_contract, &result);

    result
}

/// Records a setup-error result when contract execution fails before completion.
fn record_setup_error_on_failure(contract_path: &Path, result: &InitResult<()>) {
    if let Err(error) = result {
        let _ = write_setup_error(contract_path, error);
    }
}

/// Mounts the pseudo filesystems required before reading boot state.
fn prepare_guest_root() -> InitResult<()> {
    create_dir("/dev")?;
    create_dir("/proc")?;
    create_dir("/sys")?;
    create_dir("/tmp")?;
    create_dir(SHARE_ROOT)?;

    mount_pseudo("devtmpfs", "/dev", "devtmpfs")?;
    setup_pty_devices()?;
    log("starting VZ guest init");
    mount_pseudo("proc", "/proc", "proc")?;
    mount_pseudo("sysfs", "/sys", "sysfs")?;
    Ok(())
}

/// Loads guest drivers and mounts the runner-provided runtime share.
fn prepare_runtime_share(boot: &BootContract) -> InitResult<()> {
    match boot.network {
        BootNetworkMode::None | BootNetworkMode::VsockSidecar => {}
    }

    load_required_modules();
    log("required module pass completed");
    mount_virtiofs(&boot.virtiofs_tag, SHARE_ROOT)
}

/// Accepts the launch contract, exposes requested mounts, and records the result.
fn run_contract(boot: &BootContract) -> InitResult<()> {
    let contract = accept_contract(&boot.launch_contract)?;
    let network_services = NetworkServicesPlan::try_from(&contract)?;
    log_accepted_contract(&contract);
    write_heartbeat(
        &boot.launch_contract,
        &contract,
        GuestHeartbeatPhase::ContractReady,
    )?;
    mount_contract_paths(&contract)?;
    write_heartbeat(
        &boot.launch_contract,
        &contract,
        GuestHeartbeatPhase::MountsReady,
    )?;
    let _network_services = start_guest_network_services(&network_services)?;

    let mut command_env = network_services.command_env().clone();
    if let Some(shims) = contract.secret_shims() {
        materialize_secret_shims(shims, &mut command_env)?;
    }

    let result = execute_contract(&boot.launch_contract, &contract, &command_env);
    write_result(&boot.launch_contract, &result)?;
    Ok(())
}

/// Materializes guest secret shim entries and injects the broker bridge address.
///
/// Creates a private directory with symlinks from each provider name to the
/// guest shim binary, then prepends that directory to PATH and injects a
/// guest-local `FIRMA_BROKER_ADDR` that reaches the host broker via VSOCK.
fn materialize_secret_shims(
    shims: &SecretShimsContract,
    command_env: &mut CommandNetworkEnv,
) -> InitResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let shim_dir = "/run/firma-secret-shims";
    create_dir(shim_dir)?;

    let guest_shim_path = find_guest_shim_binary(shims);
    if !guest_shim_path.exists() {
        return Err(error::InitError::GuestNetworkSetup {
            detail: format!(
                "secret shim binary not found at {} for target '{}'",
                guest_shim_path.display(),
                shims.guest_target_triple,
            ),
        });
    }

    std::fs::set_permissions(&guest_shim_path, std::fs::Permissions::from_mode(0o755)).map_err(
        |source| error::InitError::GuestNetworkSetup {
            detail: format!(
                "failed to chmod shim binary {}: {source}",
                guest_shim_path.display()
            ),
        },
    )?;

    for name in &shims.provider_names {
        let link_path = Path::new(shim_dir).join(name);
        std::os::unix::fs::symlink(&guest_shim_path, &link_path).map_err(|source| {
            error::InitError::GuestNetworkSetup {
                detail: format!(
                    "failed to create shim symlink {} -> {}: {source}",
                    link_path.display(),
                    guest_shim_path.display()
                ),
            }
        })?;
    }

    command_env.prepend_path(shim_dir.to_string());

    let broker_addr = format!("vsock://2:{}", shims.broker_vsock_port);
    command_env.insert("FIRMA_BROKER_ADDR", broker_addr);

    log(&format!(
        "materialized {} secret shim(s) in {} for target '{}'",
        shims.provider_names.len(),
        shim_dir,
        shims.guest_target_triple,
    ));

    Ok(())
}

/// Locates the guest shim binary within the mounted virtiofs share.
fn find_guest_shim_binary(shims: &SecretShimsContract) -> std::path::PathBuf {
    let share_name = shims
        .shim_share_directory
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let target_dir = Path::new(SHARE_ROOT).join(&share_name);
    let shim_name = format!(
        "firma-secret-shim-{}",
        shims.guest_target_triple.replace('-', "_")
    );
    target_dir.join(shim_name)
}

/// Logs the accepted launch boundary after raw contract validation has completed.
fn log_accepted_contract(contract: &Contract) {
    log(&accepted_contract_log_message(contract));
}

/// Formats the accepted launch boundary after raw contract validation has completed.
fn accepted_contract_log_message(contract: &Contract) -> String {
    let network = contract.network();
    format!(
        "accepted launch contract terminal={} interactive={} pty={} network={:?} dns={:?} \
         guest_proxy={} guest_dns={} sidecar_port={} sidecar_host={} attribution_headers={}",
        contract.terminal().mode(),
        contract.terminal().interactive(),
        contract.terminal().pty(),
        network.mode(),
        network.dns_mode(),
        network.guest_http_proxy_addr(),
        network.guest_dns_stub_addr(),
        network.vsock_sidecar_port(),
        network.sidecar_host_addr(),
        network.attribution_headers().len()
    )
}

/// Writes an init diagnostic to the guest console when available.
pub fn log(message: &str) {
    for path in ["/dev/console", "/dev/hvc0"] {
        if let Ok(mut console) = File::options().write(true).open(path) {
            let _ = writeln!(console, "firma-init: {message}");
            break;
        }
    }
    let _ = writeln!(io::stderr(), "firma-init: {message}");
}

/// Powers off the guest and parks the init process if reboot does not return.
fn power_off() -> ! {
    log("powering off guest");
    unsafe {
        libc::sync();
        let _ = libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }

    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

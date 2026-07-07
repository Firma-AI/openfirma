mod boot;
mod command;
mod contract;
mod error;
mod mount;
mod result;

#[cfg(test)]
mod tests;

use std::fs::File;
use std::io::{self, Write};
use std::thread;
use std::time::Duration;

use boot::{BootContract, BootNetworkMode, parse_boot_contract};
use command::execute_contract;
use contract::accept_contract;
use error::InitResult;
use mount::{
    SHARE_ROOT, create_dir, load_required_modules, mount_contract_paths, mount_pseudo,
    mount_virtiofs,
};
use result::{write_result, write_setup_error};

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

    let result = run_contract(&boot);
    if let Err(error) = &result {
        let _ = write_setup_error(&boot.launch_contract, error);
    }

    result
}

/// Mounts the pseudo filesystems required before reading boot state.
fn prepare_guest_root() -> InitResult<()> {
    create_dir("/dev")?;
    create_dir("/proc")?;
    create_dir("/sys")?;
    create_dir("/tmp")?;
    create_dir(SHARE_ROOT)?;

    mount_pseudo("devtmpfs", "/dev", "devtmpfs")?;
    log("starting VZ guest init");
    mount_pseudo("proc", "/proc", "proc")?;
    mount_pseudo("sysfs", "/sys", "sysfs")?;
    Ok(())
}

/// Loads guest drivers and mounts the runner-provided runtime share.
fn prepare_runtime_share(boot: &BootContract) -> InitResult<()> {
    match boot.network {
        BootNetworkMode::None => {}
    }

    load_required_modules()?;
    mount_virtiofs(&boot.virtiofs_tag, SHARE_ROOT)
}

/// Accepts the launch contract, exposes requested mounts, and records the result.
fn run_contract(boot: &BootContract) -> InitResult<()> {
    let contract = accept_contract(&boot.launch_contract)?;
    mount_contract_paths(&contract)?;
    let result = execute_contract(&contract);
    write_result(&boot.launch_contract, &result)?;
    Ok(())
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

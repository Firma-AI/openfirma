mod command_pty;
mod config;
mod lifecycle;
mod sidecar_bridge;
mod transport;

use std::process::ExitCode;

use super::console::{
    SerialInputMode, capture_piped_stdin, create_pipe, create_serial_log, read_guest_exit_code,
    replay_guest_stdio, should_mirror_serial_to_stdout, spawn_stdio_forwarders,
};
use super::{RunnerError, RunnerResult};
use crate::vm::VmPlan;

use command_pty::ensure_host_terminal_available;
use config::Vz;
use lifecycle::{install_interrupt_handler, run_virtual_machine};
use transport::VzTransportPlan;

//  --------------
// | Architecture |
//  --------------
//
// TODO: For now this is just the bedside impl for the runner boundary which proves
// the contract is parsed and accepted on macOS-only. later changes turn the
// future shape below into the VM lifecycle, guest init, sidecar transport and
// terminal paths.
//
// Future shape:
//
//                    host                                      guest
//  +--------------------------------------+     +-------------------------------+
//  | firma-run                            |     | Linux init                    |
//  |                                      |     |                               |
//  |  write contract                      |     |  mount runtime share          |
//  |  start runner                        |     |  read contract                |
//  +------------------+-------------------+     |  prove startup                |
//                     |                         |  run command                  |
//                     v                         |  write result                 |
//  +--------------------------------------+     +---------------+---------------+
//  | firma-vz-runner                      |                     |
//  |                                      |                     |
//  |  validate contract                   |<------ virtiofs -----+
//  |  build VM plan                       |
//  |  start VSOCK bridges                 |
//  |  boot VM                             |
//  |  collect result                      |
//  +------------------+-------------------+
//                     |
//                     v
//  +--------------------------------------+
//  | Apple Virtualization.framework       |
//  |                                      |
//  |  kernel + initrd + rootfs            |
//  |  virtiofs shares                     |
//  |  serial diagnostics                  |
//  |  VSOCK only, no network device       |
//  +--------------------------------------+
//
// CONTRACT:
//   Launch authority for the runner. It describes sandbox id, guest artifacts,
//   command, mounts, terminal mode, sidecar transport, and required invariants.
//
// VM PLAN:
//   Concrete Apple VZ shape derived from the contract. It owns disks, shares,
//   serial, VSOCK listeners and terminal channels. Network devices stay zero.
//
// RUNNER:
//   Owns the host lifecycle: validate, plan, boot, supervise, interrupt, stop,
//   and return the guest command exit status.
//
// GUEST INIT:
//   Owns the guest lifecycle: mount, read, prove, start helpers, run command,
//   write result, power off.
//
//  ----------------
// | Policy Traffic |
//  ----------------
//
//  command
//     |
//     v
//  127.0.0.1:proxy        VSOCK             host TCP
//  +-------------+     +----------+     +---------------+
//  | guest proxy |---->| bridge   |---->| Sidecar       |
//  +-------------+     +----------+     +---------------+
//         |
//         v
//  127.0.0.1:DNS
//  +-------------+
//  | DNS stub    |
//  +-------------+
//
// No VZ network device will be attached on this path.
// The guest can talk to the host only through runner-owned VSOCK listeners.
//
//  ------------------
// | Terminal Traffic |
//  ------------------
//
//            data bytes                         resize/signals
//  host tty  ---------->  VSOCK PTY data  ----+
//                                              |
//  host ctl  ---------->  VSOCK PTY control --+--> guest PTY
//
// Serial is diagnostics only:
//
//  kernel/init logs ---> serial ---> serial.log
//                         |
//                         +--> stdout for non-PTY runs or explicit debug mirroring
//
//  ------------------
// | Communication flow |
//  ------------------
//
//  firma-run
//     |
//     | writes vz-guest-launch.json
//     | starts firma-vz-runner
//     v
//  runner
//     |
//     | validates contract
//     | builds VM plan
//     | starts VSOCK listeners
//     | boots guest
//     v
//  guest init
//     |
//     | mounts runtime share
//     | reads contract
//     | proves invariants
//     | runs command
//     | writes guest-result.json
//     v
//  runner
//     |
//     | reads result
//     | returns exit status
//     v
//  firma-run
pub fn run(plan: &VmPlan) -> RunnerResult<ExitCode> {
    ensure_no_network_devices(plan)?;
    let transport = VzTransportPlan::try_from(plan)?;
    let command_pty_enabled = transport.command_pty_enabled();
    log_vm_plan(plan, &transport);
    if command_pty_enabled {
        ensure_host_terminal_available()?;
    } else {
        capture_piped_stdin(plan)?;
    }

    let (vm_reads_from, host_writes_to_vm) = create_pipe()?;
    let (host_reads_from_vm, vm_writes_to) = create_pipe()?;
    let serial_log = create_serial_log(plan)?;
    let serial_input_mode = if command_pty_enabled {
        SerialInputMode::Closed
    } else {
        SerialInputMode::ForwardHostStdin
    };

    let stdio_forwarders = spawn_stdio_forwarders(
        host_reads_from_vm,
        host_writes_to_vm,
        serial_log,
        serial_input_mode,
        should_mirror_serial_to_stdout(command_pty_enabled),
    );

    let interrupt_rx = install_interrupt_handler()?;
    let vz = Vz::from_plan(plan, transport, vm_reads_from, vm_writes_to)?;
    run_virtual_machine(&vz, &interrupt_rx)?;
    drop(vz);
    stdio_forwarders.wait_for_serial_drain();
    if !command_pty_enabled {
        replay_guest_stdio(plan)?;
    }

    read_guest_exit_code(plan)
}

/// Rejects plans that would attach direct VZ network devices.
fn ensure_no_network_devices(plan: &VmPlan) -> RunnerResult<()> {
    if !plan.network_devices.is_empty() {
        return Err(RunnerError::NetworkDevicesRequested {
            count: plan.network_devices.len(),
        });
    }

    Ok(())
}

/// Emits the launch summary before handing control to Apple VZ.
fn log_vm_plan(plan: &VmPlan, transport: &VzTransportPlan) {
    let command_pty = transport.command_pty();
    let command_pty_port = command_pty.map(|command_pty| command_pty.data_port().get());
    let command_pty_control_port = command_pty.map(|command_pty| command_pty.control_port().get());
    eprintln!(
        "firma-vz-runner: launching contract_version={} sandbox_id={} kernel={} initrd={} rootfs={} shares={} network_devices=0 socket_devices={} network_mode={} interactive={} pty={} pty_vsock_port={} pty_control_vsock_port={} term={} rows={} cols={}",
        plan.version(),
        plan.sandbox_id(),
        plan.kernel.display(),
        plan.initrd.display(),
        plan.rootfs.display(),
        plan.directory_shares.len(),
        transport.socket_device_count(),
        plan.network_mode.as_kernel_arg(),
        plan.interactive,
        transport.command_pty_enabled(),
        command_pty_port.map_or_else(|| "-".to_string(), |port| port.to_string()),
        command_pty_control_port.map_or_else(|| "-".to_string(), |port| port.to_string()),
        plan.term.as_deref().unwrap_or("-"),
        plan.rows
            .map_or_else(|| "-".to_string(), |rows| rows.to_string()),
        plan.cols
            .map_or_else(|| "-".to_string(), |cols| cols.to_string()),
    );
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;
    use crate::test_utils::{VZ_TEST_ROOTFS_SIZE_BYTES, vm_plan_fixture};

    #[test]
    fn runner_accepts_plan_without_network_devices() -> Result<()> {
        let (_temp, plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;

        ensure_no_network_devices(&plan)?;

        Ok(())
    }
}

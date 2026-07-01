use std::process::ExitCode;

use crate::contract::Contract;

use super::{RunnerError, RunnerResult};

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
//  kernel/init logs ---> serial ---> stdout + serial.log
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
pub fn run(contract: &Contract) -> RunnerResult<ExitCode> {
    let linux_bootloader_type = std::any::type_name::<objc2_virtualization::VZLinuxBootLoader>();
    Err(RunnerError::AppleVzExecutionNotImplemented {
        version: contract.version(),
        sandbox_id: contract.sandbox_id().to_string(),
        bootloader_type: linux_bootloader_type,
    })
}

#[cfg(test)]
mod tests {
    use anyhow::{Result, anyhow};

    use super::run;
    use crate::runner::{RunnerError, runner_test_contract};

    #[test]
    fn run_reports_apple_vz_execution_not_implemented() -> Result<()> {
        let contract = runner_test_contract()?;
        let error = run(&contract).err().ok_or_else(|| {
            anyhow!("macOS runner should report unimplemented execution after contract validation")
        })?;

        assert!(matches!(
            error,
            RunnerError::AppleVzExecutionNotImplemented {
                version: 1,
                ref sandbox_id,
                bootloader_type,
            } if sandbox_id == "sandbox-test" && bootloader_type.contains("VZLinuxBootLoader")
        ));

        Ok(())
    }
}

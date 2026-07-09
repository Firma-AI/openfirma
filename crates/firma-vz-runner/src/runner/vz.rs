use std::fmt;
use std::os::fd::{IntoRawFd, OwnedFd};
use std::path::Path;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2::{AnyThread, rc::Retained};
use objc2_foundation::{
    NSArray, NSDate, NSDefaultRunLoopMode, NSDictionary, NSError, NSFileHandle, NSRunLoop,
    NSString, NSUInteger, NSURL,
};
use objc2_virtualization::{
    VZConsoleDeviceConfiguration, VZDiskImageCachingMode, VZDiskImageStorageDeviceAttachment,
    VZDiskImageSynchronizationMode, VZEntropyDeviceConfiguration, VZFileHandleSerialPortAttachment,
    VZGenericMachineIdentifier, VZGenericPlatformConfiguration, VZLinuxBootLoader,
    VZMultipleDirectoryShare, VZSharedDirectory, VZStorageDeviceConfiguration,
    VZVirtioBlockDeviceConfiguration, VZVirtioConsoleDeviceConfiguration,
    VZVirtioConsolePortConfiguration, VZVirtioEntropyDeviceConfiguration,
    VZVirtioFileSystemDeviceConfiguration, VZVirtualMachine, VZVirtualMachineConfiguration,
    VZVirtualMachineState,
};

use super::console::{
    capture_piped_stdin, create_pipe, create_serial_log, read_guest_exit_code, replay_guest_stdio,
    spawn_stdio_forwarders,
};
use super::{RunnerError, RunnerResult};
use crate::vm::{FIRMA_VIRTIOFS_TAG, VmPlan};

const START_TIMEOUT_SECS: u64 = 60;
const START_TIMEOUT: Duration = Duration::from_secs(START_TIMEOUT_SECS);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const RUN_LOOP_TICK: Duration = Duration::from_millis(100);
const DEFAULT_CPU_COUNT: NSUInteger = 2;
const DEFAULT_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

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
pub fn run(plan: &VmPlan) -> RunnerResult<ExitCode> {
    ensure_no_network_devices(plan)?;
    log_vm_plan(plan);
    capture_piped_stdin(plan)?;

    let (vm_reads_from, host_writes_to_vm) = create_pipe()?;
    let (host_reads_from_vm, vm_writes_to) = create_pipe()?;
    let serial_log = create_serial_log(plan)?;
    let stdio_forwarders =
        spawn_stdio_forwarders(host_reads_from_vm, host_writes_to_vm, serial_log);

    let interrupt_rx = install_interrupt_handler()?;
    let vz = Vz::from_plan(plan, vm_reads_from, vm_writes_to)?;
    run_virtual_machine(&vz, &interrupt_rx)?;
    drop(vz);
    stdio_forwarders.wait_for_serial_drain();
    replay_guest_stdio(plan)?;

    read_guest_exit_code(plan)
}

/// Host-side VZ state that has passed validation and can be started.
struct Vz {
    config: Retained<VZVirtualMachineConfiguration>,
}

impl Vz {
    /// Builds the accepted VZ configuration boundary from a VM plan.
    fn from_plan(
        plan: &VmPlan,
        vm_reads_from: OwnedFd,
        vm_writes_to: OwnedFd,
    ) -> RunnerResult<Self> {
        Ok(Self {
            config: create_vm_configuration(plan, vm_reads_from, vm_writes_to)?,
        })
    }
}

/// Creates and validates the host-side Apple VZ machine configuration.
fn create_vm_configuration(
    plan: &VmPlan,
    vm_reads_from: OwnedFd,
    vm_writes_to: OwnedFd,
) -> RunnerResult<Retained<VZVirtualMachineConfiguration>> {
    let config = unsafe {
        if !VZVirtualMachine::isSupported() {
            return Err(RunnerError::VirtualizationUnsupported);
        }

        let config = VZVirtualMachineConfiguration::new();
        let platform = VZGenericPlatformConfiguration::new();
        let machine_identifier =
            VZGenericMachineIdentifier::init(VZGenericMachineIdentifier::alloc());
        platform.setMachineIdentifier(&machine_identifier);
        config.setPlatform(&platform);

        let boot_loader = create_linux_boot_loader(plan)?;
        config.setBootLoader(Some(&boot_loader));

        config.setCPUCount(clamped_cpu_count());
        config.setMemorySize(clamped_memory_size());
        configure_entropy(&config);
        configure_rootfs_storage(&config, &plan.rootfs)?;
        configure_directory_shares(&config, plan)?;
        configure_console_stdio(&config, vm_reads_from, vm_writes_to);

        config
            .validateWithError()
            .map_err(|error| RunnerError::ConfigurationValidation {
                reason: ns_error_message(&error),
            })?;

        config
    };

    Ok(config)
}

/// Builds the Linux bootloader with the planned kernel, initrd and command line.
fn create_linux_boot_loader(plan: &VmPlan) -> RunnerResult<Retained<VZLinuxBootLoader>> {
    let kernel_url = nsurl_from_path(&plan.kernel)?;
    let initrd_url = nsurl_from_path(&plan.initrd)?;
    let boot_loader =
        unsafe { VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &kernel_url) };
    unsafe {
        boot_loader.setInitialRamdiskURL(Some(&initrd_url));
        boot_loader.setCommandLine(&NSString::from_str(&plan.kernel_command_line));
    }

    Ok(boot_loader)
}

/// Adds the virtio entropy device required by the guest.
fn configure_entropy(config: &VZVirtualMachineConfiguration) {
    let entropy_device = unsafe { VZVirtioEntropyDeviceConfiguration::new() };
    let entropy_devices: Retained<NSArray<VZEntropyDeviceConfiguration>> =
        NSArray::from_retained_slice(&[Retained::into_super(entropy_device)]);

    unsafe {
        config.setEntropyDevices(&entropy_devices);
    }
}

/// Attaches the rootfs image as the guest's virtio block device.
fn configure_rootfs_storage(
    config: &VZVirtualMachineConfiguration,
    rootfs: &Path,
) -> RunnerResult<()> {
    let rootfs_url = nsurl_from_path(rootfs)?;
    let disk_attachment = unsafe {
        VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
            VZDiskImageStorageDeviceAttachment::alloc(),
            &rootfs_url,
            false,
            VZDiskImageCachingMode::Automatic,
            VZDiskImageSynchronizationMode::Full,
        )
    }
    .map_err(|error| RunnerError::ConfigurationStep {
        step: "rootfs virtio block device",
        reason: ns_error_message(&error),
    })?;

    let disk_device = unsafe {
        VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            &disk_attachment,
        )
    };

    unsafe {
        disk_device.setBlockDeviceIdentifier(&NSString::from_str("firma-rootfs"));
    }

    let storage_devices: Retained<NSArray<VZStorageDeviceConfiguration>> =
        NSArray::from_retained_slice(&[Retained::into_super(disk_device)]);

    unsafe {
        config.setStorageDevices(&storage_devices);
    }

    Ok(())
}

/// Exposes the runtime directory and declared mounts through virtiofs.
fn configure_directory_shares(
    config: &VZVirtualMachineConfiguration,
    plan: &VmPlan,
) -> RunnerResult<()> {
    let mut names = Vec::with_capacity(plan.directory_shares.len());
    let mut directories = Vec::with_capacity(plan.directory_shares.len());

    for share in &plan.directory_shares {
        let name = NSString::from_str(&share.name);
        unsafe {
            VZMultipleDirectoryShare::validateName_error(&name).map_err(|error| {
                RunnerError::ConfigurationStep {
                    step: "virtiofs share name",
                    reason: ns_error_message(&error),
                }
            })?;
        }
        names.push(name);

        let url = nsurl_from_path(&share.source)?;
        directories.push(unsafe {
            VZSharedDirectory::initWithURL_readOnly(
                VZSharedDirectory::alloc(),
                &url,
                share.read_only,
            )
        });
    }

    let name_refs = names.iter().map(|name| &**name).collect::<Vec<_>>();
    let directory_refs = directories
        .iter()
        .map(|directory| &**directory)
        .collect::<Vec<_>>();
    let share_map: Retained<NSDictionary<NSString, VZSharedDirectory>> =
        NSDictionary::from_slices(&name_refs, &directory_refs);
    let multiple_share = unsafe {
        VZMultipleDirectoryShare::initWithDirectories(VZMultipleDirectoryShare::alloc(), &share_map)
    };

    let tag = NSString::from_str(FIRMA_VIRTIOFS_TAG);
    unsafe {
        VZVirtioFileSystemDeviceConfiguration::validateTag_error(&tag).map_err(|error| {
            RunnerError::ConfigurationStep {
                step: "virtiofs tag",
                reason: ns_error_message(&error),
            }
        })?;
    }

    let sharing_device = unsafe {
        VZVirtioFileSystemDeviceConfiguration::initWithTag(
            VZVirtioFileSystemDeviceConfiguration::alloc(),
            &tag,
        )
    };

    unsafe {
        sharing_device.setShare(Some(&multiple_share));
    }

    let sharing_devices = NSArray::from_retained_slice(&[Retained::into_super(sharing_device)]);

    unsafe {
        config.setDirectorySharingDevices(&sharing_devices);
    }

    Ok(())
}

/// Connects the VZ virtio console device to host-owned file descriptors.
fn configure_console_stdio(
    config: &VZVirtualMachineConfiguration,
    vm_reads_from: OwnedFd,
    vm_writes_to: OwnedFd,
) {
    let ns_read_handle = NSFileHandle::alloc();
    let ns_read_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
        ns_read_handle,
        vm_reads_from.into_raw_fd(),
        true,
    );

    let ns_write_handle = NSFileHandle::alloc();
    let ns_write_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
        ns_write_handle,
        vm_writes_to.into_raw_fd(),
        true,
    );

    let serial_attachment = unsafe {
        VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
            VZFileHandleSerialPortAttachment::alloc(),
            Some(&ns_read_handle),
            Some(&ns_write_handle),
        )
    };

    let console_port = unsafe { VZVirtioConsolePortConfiguration::new() };
    unsafe {
        console_port.setAttachment(Some(&serial_attachment));
        console_port.setName(Some(&NSString::from_str("openfirma-console")));
        console_port.setIsConsole(true);
    }

    let console_device = unsafe { VZVirtioConsoleDeviceConfiguration::new() };

    unsafe {
        let ports = console_device.ports();
        ports.setMaximumPortCount(1);
        ports.setObject_atIndexedSubscript(Some(&console_port), 0);
    }

    let console_devices: Retained<NSArray<VZConsoleDeviceConfiguration>> =
        NSArray::from_retained_slice(&[Retained::into_super(console_device)]);

    unsafe {
        config.setConsoleDevices(&console_devices);
    }
}

/// Starts the VM and waits until the guest stops or host interruption wins.
fn run_virtual_machine(vz: &Vz, interrupt_rx: &mpsc::Receiver<()>) -> RunnerResult<()> {
    let queue = DispatchQueue::main();
    let vm = unsafe {
        VZVirtualMachine::initWithConfiguration_queue(VZVirtualMachine::alloc(), &vz.config, queue)
    };

    let (tx, rx) = mpsc::channel::<std::result::Result<(), String>>();
    let completion_handler = RcBlock::new(move |error: *mut NSError| {
        let result = if error.is_null() {
            Ok(())
        } else {
            let error = unsafe { &*error };
            Err(ns_error_message(error))
        };
        let _ = tx.send(result);
    });

    unsafe {
        vm.startWithCompletionHandler(&completion_handler);
    }

    wait_for_start(&rx)?;
    eprintln!("firma-vz-runner: VM started");

    let stop_reason = wait_for_stop(&vm, interrupt_rx)?;
    eprintln!("firma-vz-runner: VM stopped: {stop_reason}");

    Ok(())
}

/// Waits for the asynchronous VZ start callback with a bounded timeout.
fn wait_for_start(rx: &mpsc::Receiver<std::result::Result<(), String>>) -> RunnerResult<()> {
    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        pump_main_run_loop(RUN_LOOP_TICK);
        match rx.try_recv() {
            Ok(result) => {
                return result.map_err(|reason| RunnerError::StartFailed { reason });
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(RunnerError::StartCallbackDisconnected);
            }
        }
    }

    Err(RunnerError::StartTimedOut {
        timeout_secs: START_TIMEOUT_SECS,
    })
}

/// Pumps the run loop until the VM stops, errors, or an interrupt requests stop.
fn wait_for_stop(
    vm: &VZVirtualMachine,
    interrupt_rx: &mpsc::Receiver<()>,
) -> RunnerResult<VmStopReason> {
    let mut interrupt_count = 0_u8;

    loop {
        pump_main_run_loop(RUN_LOOP_TICK);

        match interrupt_rx.try_recv() {
            Ok(()) => {
                interrupt_count = interrupt_count.saturating_add(1);
                stop_after_interrupt(vm, interrupt_count)?;
            }
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => {}
        }

        let state = unsafe { vm.state() };
        if state == VZVirtualMachineState::Stopped {
            return Ok(if interrupt_count == 0 {
                VmStopReason::GuestStopped
            } else {
                VmStopReason::StoppedAfterInterrupt
            });
        }
        if state == VZVirtualMachineState::Error {
            return Err(RunnerError::VmEnteredErrorState);
        }
    }
}

/// Applies the interrupt policy: request guest stop first, then force stop.
fn stop_after_interrupt(vm: &VZVirtualMachine, interrupt_count: u8) -> RunnerResult<()> {
    if interrupt_count == 1 && unsafe { vm.canRequestStop() } {
        eprintln!("firma-vz-runner: interrupt received; requesting guest shutdown");
        unsafe {
            vm.requestStopWithError()
                .map_err(|error| RunnerError::StopRequestFailed {
                    reason: ns_error_message(&error),
                })?;
        }
        return Ok(());
    }

    if unsafe { vm.canStop() } {
        eprintln!("firma-vz-runner: interrupt received; force-stopping VM");
        stop_vm(vm).map_err(|error| RunnerError::ForceStopFailed {
            reason: error.to_string(),
        })?;
        return Ok(());
    }

    eprintln!(
        "firma-vz-runner: interrupt received but VM is not stoppable in state {}",
        vm_state_name(unsafe { vm.state() })
    );

    Ok(())
}

/// Sends an asynchronous force-stop request to the VM and waits for completion.
fn stop_vm(vm: &VZVirtualMachine) -> RunnerResult<()> {
    let (tx, rx) = mpsc::channel::<std::result::Result<(), String>>();
    let completion_handler = RcBlock::new(move |error: *mut NSError| {
        let result = if error.is_null() {
            Ok(())
        } else {
            let error = unsafe { &*error };
            Err(ns_error_message(error))
        };
        let _ = tx.send(result);
    });

    unsafe {
        vm.stopWithCompletionHandler(&completion_handler);
    }

    wait_for_operation("stop VM", &rx, STOP_TIMEOUT)
}

/// Waits for an asynchronous VZ operation callback with a caller-provided timeout.
fn wait_for_operation(
    operation: &'static str,
    rx: &mpsc::Receiver<std::result::Result<(), String>>,
    timeout: Duration,
) -> RunnerResult<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        pump_main_run_loop(RUN_LOOP_TICK);
        match rx.try_recv() {
            Ok(result) => {
                return result.map_err(|reason| RunnerError::OperationFailed { operation, reason });
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(RunnerError::OperationCallbackDisconnected { operation });
            }
        }
    }
    Err(RunnerError::OperationTimedOut {
        operation,
        timeout_secs: timeout.as_secs(),
    })
}

/// Installs the host Ctrl-C handler used to interrupt the running VM.
fn install_interrupt_handler() -> RunnerResult<mpsc::Receiver<()>> {
    let (tx, rx) = mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .map_err(|source| RunnerError::InterruptHandler { source })?;

    Ok(rx)
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
fn log_vm_plan(plan: &VmPlan) {
    eprintln!(
        "firma-vz-runner: launching contract_version={} sandbox_id={} kernel={} initrd={} rootfs={} shares={} network_devices=0",
        plan.version(),
        plan.sandbox_id(),
        plan.kernel.display(),
        plan.initrd.display(),
        plan.rootfs.display(),
        plan.directory_shares.len()
    );
}

/// Picks a CPU count inside the bounds accepted by Apple VZ.
fn clamped_cpu_count() -> NSUInteger {
    let min = unsafe { VZVirtualMachineConfiguration::minimumAllowedCPUCount() };
    let max = unsafe { VZVirtualMachineConfiguration::maximumAllowedCPUCount() };
    DEFAULT_CPU_COUNT.clamp(min, max)
}

/// Picks a memory size inside the bounds accepted by Apple VZ.
fn clamped_memory_size() -> u64 {
    let min = unsafe { VZVirtualMachineConfiguration::minimumAllowedMemorySize() };
    let max = unsafe { VZVirtualMachineConfiguration::maximumAllowedMemorySize() };
    DEFAULT_MEMORY_BYTES.clamp(min, max)
}

/// Lets the main run loop process VZ callbacks for a short interval.
fn pump_main_run_loop(duration: Duration) {
    unsafe {
        NSRunLoop::mainRunLoop().runMode_beforeDate(
            NSDefaultRunLoopMode,
            &NSDate::dateWithTimeIntervalSinceNow(duration.as_secs_f64()),
        );
    }
}

/// Converts a host filesystem path into an NSURL for VZ APIs.
fn nsurl_from_path(path: &Path) -> RunnerResult<Retained<NSURL>> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| RunnerError::HostOperation {
                action: "resolve current directory for VZ path",
                source,
            })?
            .join(path)
    };
    let string = absolute.to_str().ok_or_else(|| RunnerError::NonUtf8Path {
        path: absolute.clone(),
    })?;
    Ok(NSURL::fileURLWithPath(&NSString::from_str(string)))
}

/// Extracts a readable message from an Objective-C `NSError`.
fn ns_error_message(error: &NSError) -> String {
    error.localizedDescription().to_string()
}

/// Names VZ VM states for logs and diagnostics.
fn vm_state_name(state: VZVirtualMachineState) -> &'static str {
    match state {
        VZVirtualMachineState::Stopped => "stopped",
        VZVirtualMachineState::Running => "running",
        VZVirtualMachineState::Paused => "paused",
        VZVirtualMachineState::Error => "error",
        VZVirtualMachineState::Starting => "starting",
        VZVirtualMachineState::Pausing => "pausing",
        VZVirtualMachineState::Resuming => "resuming",
        VZVirtualMachineState::Stopping => "stopping",
        VZVirtualMachineState::Saving => "saving",
        VZVirtualMachineState::Restoring => "restoring",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmStopReason {
    GuestStopped,
    StoppedAfterInterrupt,
}

impl fmt::Display for VmStopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GuestStopped => f.write_str("guest stopped"),
            Self::StoppedAfterInterrupt => f.write_str("stopped after interrupt"),
        }
    }
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

    #[test]
    fn vm_configuration_reaches_vz_validation_without_starting_vm() -> Result<()> {
        if unsafe { !VZVirtualMachine::isSupported() } {
            eprintln!("skipping VZ configuration test because Apple VZ is unsupported");
            return Ok(());
        }

        let (_temp, plan) = vm_plan_fixture(VZ_TEST_ROOTFS_SIZE_BYTES)?;
        ensure_no_network_devices(&plan)?;

        let (vm_reads_from, _host_writes_to_vm) = create_pipe()?;
        let (_host_reads_from_vm, vm_writes_to) = create_pipe()?;
        let vz = match Vz::from_plan(&plan, vm_reads_from, vm_writes_to) {
            Ok(vz) => vz,
            Err(RunnerError::ConfigurationValidation { reason })
                if reason.contains("com.apple.security.virtualization") =>
            {
                eprintln!("skipping VZ configuration inspection because test binary is unsigned");
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };

        assert_eq!(unsafe { vz.config.storageDevices().count() }, 1);
        assert_eq!(unsafe { vz.config.directorySharingDevices().count() }, 1);
        assert_eq!(unsafe { vz.config.consoleDevices().count() }, 1);

        Ok(())
    }
}

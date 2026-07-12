use std::fmt;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2::AnyThread;
use objc2_foundation::{NSDate, NSDefaultRunLoopMode, NSError, NSRunLoop};
use objc2_virtualization::{VZVirtualMachine, VZVirtualMachineState};

use super::super::{RunnerError, RunnerResult};
use super::command_pty::{
    host_sigterm_count, install_command_pty_bridge, install_command_pty_control_bridge,
    install_sigterm_handler, record_host_sigint,
};
use super::config::{Vz, ns_error_message};
use super::sidecar_bridge::{install_vsock_bridges, preflight_sidecar_bridge};

const START_TIMEOUT_SECS: u64 = 60;
const START_TIMEOUT: Duration = Duration::from_secs(START_TIMEOUT_SECS);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const RUN_LOOP_TICK: Duration = Duration::from_millis(100);

/// Starts the VM and waits until the guest stops or host interruption wins.
pub fn run_virtual_machine(vz: &Vz, interrupt_rx: &mpsc::Receiver<()>) -> RunnerResult<()> {
    preflight_sidecar_bridge(vz.transport.sidecar())?;

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

    let _vsock_bridges = match install_vsock_bridges(&vm, vz.transport.sidecar()) {
        Ok(bridge) => bridge,
        Err(error) => {
            if unsafe { vm.canStop() } {
                let _ = stop_vm(&vm);
            }
            return Err(error);
        }
    };

    let _command_pty_bridge = match install_command_pty_bridge(&vm, vz.transport.command_pty()) {
        Ok(bridge) => bridge,
        Err(error) => {
            if unsafe { vm.canStop() } {
                let _ = stop_vm(&vm);
            }
            return Err(error);
        }
    };

    let _command_pty_control_bridge =
        match install_command_pty_control_bridge(&vm, vz.transport.command_pty()) {
            Ok(bridge) => bridge,
            Err(error) => {
                if unsafe { vm.canStop() } {
                    let _ = stop_vm(&vm);
                }
                return Err(error);
            }
        };

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
    let mut last_sigterm = host_sigterm_count();

    loop {
        pump_main_run_loop(RUN_LOOP_TICK);

        let next_sigterm = host_sigterm_count();
        if next_sigterm != last_sigterm {
            last_sigterm = next_sigterm;
            interrupt_count = interrupt_count.saturating_add(1);
            stop_after_interrupt(vm, interrupt_count)?;
        }

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
pub fn install_interrupt_handler() -> RunnerResult<mpsc::Receiver<()>> {
    let (tx, rx) = mpsc::channel();
    ctrlc::set_handler(move || {
        record_host_sigint();
        let _ = tx.send(());
    })
    .map_err(|source| RunnerError::InterruptHandler { source })?;

    install_sigterm_handler().map_err(|source| RunnerError::HostOperation {
        action: "install SIGTERM handler for VZ runner",
        source,
    })?;

    Ok(rx)
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

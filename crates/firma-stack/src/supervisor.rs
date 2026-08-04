//! Foreground ownership and detached observation loops.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::error::Result;
use crate::spawn::SpawnedComponent;
use firma_runtime_state::UserProcessId;

#[derive(Clone, Copy)]
pub struct ObservedChildren {
    pub authority_pid: UserProcessId,
    pub sidecar_pid: UserProcessId,
}

pub fn block_until_owned_exit(
    authority: &mut SpawnedComponent,
    sidecar: &mut SpawnedComponent,
) -> Result<()> {
    let stop = install_stop_handler();
    debug!(
        authority_pid = %authority.leader_pid,
        sidecar_pid = %sidecar.leader_pid,
        "foreground supervisor watching owned children"
    );

    loop {
        if stop.load(Ordering::SeqCst) {
            info!("Ctrl-C received; caller will tear stack down");
            return Ok(());
        }
        if authority.child.try_wait()?.is_some() {
            warn!(pid = %authority.leader_pid, "authority exited unexpectedly");
            return Ok(());
        }
        if sidecar.child.try_wait()?.is_some() {
            warn!(pid = %sidecar.leader_pid, "sidecar exited unexpectedly");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn block_until_observed_exit(children: ObservedChildren) -> Result<()> {
    let stop = install_stop_handler();
    debug!(
        authority_pid = %children.authority_pid,
        sidecar_pid = %children.sidecar_pid,
        "detached supervisor observing children"
    );

    loop {
        if stop.load(Ordering::SeqCst) {
            info!("Ctrl-C received; caller will tear stack down");
            return Ok(());
        }
        if !children.authority_pid.process_exists()? {
            warn!(
                pid = %children.authority_pid,
                "authority exited unexpectedly"
            );
            return Ok(());
        }
        if !children.sidecar_pid.process_exists()? {
            warn!(pid = %children.sidecar_pid, "sidecar exited unexpectedly");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn install_stop_handler() -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);
    let _ = ctrlc::set_handler(move || {
        stop_handler.store(true, Ordering::SeqCst);
    });
    stop
}

pub fn collect_in_background(
    mut authority: std::process::Child,
    mut sidecar: std::process::Child,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut authority_collected = false;
        let mut sidecar_collected = false;
        while !authority_collected || !sidecar_collected {
            if !authority_collected {
                authority_collected = !matches!(authority.try_wait(), Ok(None));
            }
            if !sidecar_collected {
                sidecar_collected = !matches!(sidecar.try_wait(), Ok(None));
            }
            if !authority_collected || !sidecar_collected {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    })
}

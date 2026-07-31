//! Foreground supervisor.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::error::Result;
use firma_runtime_state::UserProcessId;

#[derive(Clone, Copy)]
pub struct Children {
    pub authority_pid: UserProcessId,
    pub sidecar_pid: UserProcessId,
}

pub fn block_until_exit(children: Children) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);
    let _ = ctrlc::set_handler(move || {
        stop_handler.store(true, Ordering::SeqCst);
    });
    debug!(
        authority_pid = %children.authority_pid,
        sidecar_pid = %children.sidecar_pid,
        "supervisor watching children"
    );

    loop {
        if stop.load(Ordering::SeqCst) {
            info!("Ctrl-C received; caller will tear stack down");
            // Do NOT signal children here. The caller (foreground `start`,
            // or the detached `__supervise` entry) runs `stop()` next,
            // which owns the soft-then-hard signal sequence. Sending
            // SIGTERM twice in quick succession has been observed to
            // confuse tonic graceful shutdown and leave children stuck.
            return Ok(());
        }
        if children.authority_pid.reap_if_exited() || !children.authority_pid.process_exists() {
            warn!(
                pid = %children.authority_pid,
                "authority exited unexpectedly"
            );
            return Ok(());
        }
        if children.sidecar_pid.reap_if_exited() || !children.sidecar_pid.process_exists() {
            warn!(pid = %children.sidecar_pid, "sidecar exited unexpectedly");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

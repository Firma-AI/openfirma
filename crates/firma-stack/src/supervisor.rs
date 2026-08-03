//! Foreground ownership and detached observation loops.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::error::Result;
use crate::platform::TerminationTarget;
use crate::spawn::SpawnedComponent;
use firma_runtime_state::{ChildExt as _, UserProcessId};

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
    authority: SpawnedComponent,
    sidecar: SpawnedComponent,
) -> Option<std::thread::JoinHandle<()>> {
    spawn_collector(vec![authority.into(), sidecar.into()])
}

pub fn collect_child_in_background(
    child: std::process::Child,
) -> Option<std::thread::JoinHandle<()>> {
    let target = TerminationTarget::for_leader(child.process_id());
    collect_target_in_background(child, target)
}

pub fn collect_target_in_background(
    child: std::process::Child,
    target: TerminationTarget,
) -> Option<std::thread::JoinHandle<()>> {
    spawn_collector(vec![CollectedChild { child, target }])
}

pub fn collect_child_until(child: &mut std::process::Child, deadline: std::time::Instant) -> bool {
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => return false,
            Err(error) if child_was_collected_externally(&error) => return true,
            Err(error) if std::time::Instant::now() < deadline => {
                debug!(%error, "child collection probe failed; retrying");
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                debug!(%error, "child collection probe did not recover before deadline");
                return false;
            }
        }
    }
}

struct CollectedChild {
    child: std::process::Child,
    target: TerminationTarget,
}

impl From<SpawnedComponent> for CollectedChild {
    fn from(component: SpawnedComponent) -> Self {
        Self {
            child: component.child,
            target: component.termination_target,
        }
    }
}

fn spawn_collector(children: Vec<CollectedChild>) -> Option<std::thread::JoinHandle<()>> {
    let children = Arc::new(std::sync::Mutex::new(children));
    let worker_children = Arc::clone(&children);
    match std::thread::Builder::new()
        .name("firma-child-collector".into())
        .spawn(move || {
            let mut children = match worker_children.lock() {
                Ok(mut children) => std::mem::take(&mut *children),
                Err(_) => return,
            };
            while !children.is_empty() {
                children.retain_mut(|owned| match owned.child.try_wait() {
                    Ok(None) => true,
                    Ok(Some(_)) => false,
                    Err(error) if child_was_collected_externally(&error) => false,
                    Err(error) => {
                        debug!(%error, "child collection probe failed; retrying");
                        true
                    }
                });
                if !children.is_empty() {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }) {
        Ok(handle) => Some(handle),
        Err(error) => {
            warn!(%error, "could not start child collector; terminating uncollected children");
            if let Ok(mut children) = children.lock() {
                for child in children.iter_mut() {
                    let _ = child.target.signal_hard();
                    let _ = child.child.kill();
                    let _ = collect_child_until(
                        &mut child.child,
                        std::time::Instant::now() + Duration::from_secs(2),
                    );
                }
            }
            None
        }
    }
}

#[cfg(unix)]
fn child_was_collected_externally(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(nix::libc::ECHILD)
}

#[cfg(windows)]
fn child_was_collected_externally(_error: &std::io::Error) -> bool {
    false
}

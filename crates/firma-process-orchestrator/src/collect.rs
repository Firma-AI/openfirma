//! Shared direct-child collection utilities.
//!
//! These leaf helpers reap direct children without relinquishing ownership,
//! transfer them to background collector threads, and provide the fallback used
//! when collector-thread creation fails. They depend only on
//! [`crate::platform`] for termination authority and the platform-specific
//! external-collection condition, so both the high-level supervisor and the
//! low-level platform layer can share them without an inverted dependency.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, warn};

use crate::component::OwnedComponent;
use crate::platform::{Platform, SystemPlatform, TerminationTarget};
use crate::timeouts::CHILD_COLLECTION_TIMEOUT;
use firma_runtime_state::ChildExt as _;

const COLLECTION_POLL_INTERVAL: Duration = Duration::from_millis(50);
const BACKGROUND_COLLECTION_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Transfer one direct child and its leader target to a background collector.
pub fn collect_child_in_background(
    child: std::process::Child,
) -> Option<std::thread::JoinHandle<()>> {
    let target = TerminationTarget::for_leader(child.process_id());
    collect_target_in_background(child, target)
}

/// Transfer a child and explicit [`TerminationTarget`] to a background collector.
pub fn collect_target_in_background(
    child: std::process::Child,
    target: TerminationTarget,
) -> Option<std::thread::JoinHandle<()>> {
    spawn_collector(vec![CollectedChild { child, target }])
}

/// Attempt direct-child collection until a deadline without relinquishing ownership.
pub fn collect_child_until(child: &mut std::process::Child, deadline: std::time::Instant) -> bool {
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(COLLECTION_POLL_INTERVAL);
            }
            Ok(None) => return false,
            Err(error) if SystemPlatform::child_already_reaped(&error) => return true,
            Err(error) if std::time::Instant::now() < deadline => {
                debug!(%error, "child collection probe failed; retrying");
                std::thread::sleep(COLLECTION_POLL_INTERVAL);
            }
            Err(error) => {
                debug!(%error, "child collection probe did not recover before deadline");
                return false;
            }
        }
    }
}

/// Inseparable collection and termination capabilities owned by a collector.
struct CollectedChild {
    child: std::process::Child,
    target: TerminationTarget,
}

impl From<OwnedComponent> for CollectedChild {
    fn from(component: OwnedComponent) -> Self {
        let (child, target) = component.into_parts();
        Self { child, target }
    }
}

/// Transfer all children to one reaper or terminate them if transfer fails.
fn spawn_collector(children: Vec<CollectedChild>) -> Option<std::thread::JoinHandle<()>> {
    let children = Arc::new(std::sync::Mutex::new(children));
    let worker_children = Arc::clone(&children);
    match std::thread::Builder::new()
        .name("child-collector".into())
        .spawn(move || {
            let mut children = match worker_children.lock() {
                Ok(mut children) => std::mem::take(&mut *children),
                Err(_) => return,
            };
            while !children.is_empty() {
                children.retain_mut(|owned| match owned.child.try_wait() {
                    Ok(None) => true,
                    Ok(Some(_)) => false,
                    Err(error) if SystemPlatform::child_already_reaped(&error) => false,
                    Err(error) => {
                        debug!(%error, "child collection probe failed; retrying");
                        true
                    }
                });
                if !children.is_empty() {
                    std::thread::sleep(BACKGROUND_COLLECTION_POLL_INTERVAL);
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
                        std::time::Instant::now() + CHILD_COLLECTION_TIMEOUT,
                    );
                }
            }
            None
        }
    }
}

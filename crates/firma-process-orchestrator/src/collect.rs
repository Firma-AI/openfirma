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
use firma_runtime_state::ChildExt as _;

const COLLECTION_POLL_INTERVAL: Duration = Duration::from_millis(50);
const BACKGROUND_COLLECTION_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Transfer one direct child and its leader target to a background collector.
pub fn collect_child_in_background(
    child: std::process::Child,
) -> Result<std::thread::JoinHandle<()>, CollectorStartError> {
    let target = TerminationTarget::for_leader(child.process_id());
    collect_target_in_background(child, target)
}

/// Transfer a child and explicit [`TerminationTarget`] to a background collector.
pub fn collect_target_in_background(
    child: std::process::Child,
    target: TerminationTarget,
) -> Result<std::thread::JoinHandle<()>, CollectorStartError> {
    spawn_collector(CollectedChild { child, target })
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

/// Failure to transfer a child into a background collector.
///
/// The error retains both process capabilities so callers can choose an
/// appropriate synchronous fallback without losing collection responsibility.
pub struct CollectorStartError {
    source: std::io::Error,
    child: Arc<std::sync::Mutex<Option<CollectedChild>>>,
}

impl CollectorStartError {
    /// Return the operating-system error that prevented thread creation.
    pub const fn source(&self) -> &std::io::Error {
        &self.source
    }

    /// Recover the child while releasing its leader-only termination target.
    pub fn into_child(self) -> Option<std::process::Child> {
        self.take_child().map(|collected| collected.child)
    }

    /// Hard-terminate and synchronously collect the retained child.
    pub fn terminate_and_collect(self) -> std::io::Result<()> {
        let Some(mut collected) = self.take_child() else {
            return Ok(());
        };
        if let Err(error) = collected.target.signal_hard() {
            warn!(%error, "fallback child-target termination failed");
        }
        if let Err(error) = collected.child.kill() {
            debug!(%error, "fallback child termination failed");
        }
        match collected.child.wait() {
            Ok(_) => Ok(()),
            Err(error) if SystemPlatform::child_already_reaped(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn take_child(&self) -> Option<CollectedChild> {
        match self.child.lock() {
            Ok(mut child) => child.take(),
            Err(child) => child.into_inner().take(),
        }
    }
}

/// Transfer one child to a reaper while preserving ownership on failure.
fn spawn_collector(
    child: CollectedChild,
) -> Result<std::thread::JoinHandle<()>, CollectorStartError> {
    let child = Arc::new(std::sync::Mutex::new(Some(child)));
    let worker_child = Arc::clone(&child);
    std::thread::Builder::new()
        .name("child-collector".into())
        .spawn(move || {
            let child = match worker_child.lock() {
                Ok(mut child) => child.take(),
                Err(child) => child.into_inner().take(),
            };
            let Some(mut child) = child else {
                return;
            };
            loop {
                match child.child.try_wait() {
                    Ok(None) => std::thread::sleep(BACKGROUND_COLLECTION_POLL_INTERVAL),
                    Ok(Some(_)) => return,
                    Err(error) if SystemPlatform::child_already_reaped(&error) => return,
                    Err(error) => {
                        debug!(%error, "child collection probe failed; retrying");
                        std::thread::sleep(BACKGROUND_COLLECTION_POLL_INTERVAL);
                    }
                }
            }
        })
        .map_err(|source| CollectorStartError { source, child })
}

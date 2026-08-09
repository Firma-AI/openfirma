//! Shared direct-child collection utilities.
//!
//! These leaf helpers reap direct children without relinquishing ownership,
//! transfer them to background collector threads, and provide the fallback used
//! when collector-thread creation fails. They depend only on
//! [`crate::platform`] for termination authority and the platform-specific
//! external-collection condition, so both the high-level supervisor and the
//! low-level platform layer can share them without an inverted dependency.

use std::sync::{Mutex, OnceLock, mpsc};
use std::time::Duration;

use tracing::debug;

use crate::component::OwnedComponent;
use crate::platform::{Platform, SystemPlatform, TerminationTarget};
use firma_runtime_state::ChildExt as _;

const COLLECTION_POLL_INTERVAL: Duration = Duration::from_millis(50);
const BACKGROUND_COLLECTION_POLL_INTERVAL: Duration = Duration::from_millis(200);

static COLLECTOR: OnceLock<Collector> = OnceLock::new();
static COLLECTOR_INIT: Mutex<()> = Mutex::new(());

/// Process-global collection worker initialized before any managed child exists.
struct Collector {
    owner_pid: u32,
    sender: mpsc::Sender<CollectionRequest>,
}

/// Ownership payloads accepted by the persistent collector.
enum CollectionRequest {
    Child(CollectedChild),
    Components(Vec<OwnedComponent>),
}

/// Reason an initialized collector could not accept ownership.
#[derive(Debug)]
enum HandoffFailure {
    Uninitialized,
    Forked { owner_pid: u32, current_pid: u32 },
    Disconnected,
}

impl std::fmt::Display for HandoffFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uninitialized => formatter.write_str("child collector is not initialized"),
            Self::Forked {
                owner_pid,
                current_pid,
            } => write!(
                formatter,
                "child collector belongs to process {owner_pid}, not forked process {current_pid}"
            ),
            Self::Disconnected => formatter.write_str("child collector worker disconnected"),
        }
    }
}

/// Failed ownership transfer that returns the exact offered capability.
pub struct HandoffError {
    failure: HandoffFailure,
    request: CollectionRequest,
}

impl HandoffError {
    /// Describe why the persistent collector rejected ownership.
    pub fn reason(&self) -> impl std::fmt::Display + '_ {
        &self.failure
    }

    /// Recover an offered direct child.
    pub fn into_child(self) -> Option<std::process::Child> {
        match self.request {
            CollectionRequest::Child(collected) => Some(collected.child),
            CollectionRequest::Components(_) => None,
        }
    }

    /// Recover an offered component collection.
    pub fn into_components(self) -> Option<Vec<OwnedComponent>> {
        match self.request {
            CollectionRequest::Components(components) => Some(components),
            CollectionRequest::Child(_) => None,
        }
    }

    /// Deliberately retain rejected capabilities until process exit.
    pub fn forget(self) {
        std::mem::forget(self.request);
    }
}

/// Initialize the process-global collector before any managed child is spawned.
pub fn initialize_collector() -> Result<(), std::io::Error> {
    if COLLECTOR.get().is_none() {
        let _initialization = match COLLECTOR_INIT.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if COLLECTOR.get().is_none() {
            let collector = start_collector()?;
            if COLLECTOR.set(collector).is_err() {
                return Err(std::io::Error::other(
                    "child collector initialized concurrently",
                ));
            }
        }
    }
    let Some(collector) = COLLECTOR.get() else {
        return Err(std::io::Error::other(
            "child collector initialization completed without a worker",
        ));
    };
    let current_pid = std::process::id();
    if collector.owner_pid != current_pid {
        return Err(std::io::Error::other(format!(
            "child collector belongs to process {}, not forked process {current_pid}",
            collector.owner_pid
        )));
    }
    Ok(())
}

fn start_collector() -> Result<Collector, std::io::Error> {
    let (sender, receiver) = mpsc::channel();
    std::thread::Builder::new()
        .name("child-collector".into())
        .spawn(move || collect_children(&receiver))?;
    Ok(Collector {
        owner_pid: std::process::id(),
        sender,
    })
}

/// Transfer one direct child and its leader target to a background collector.
pub fn collect_child_in_background(child: std::process::Child) -> Result<(), HandoffError> {
    let request = CollectionRequest::Child(CollectedChild {
        _target: TerminationTarget::for_leader(child.process_id()),
        child,
    });
    let collector = match initialized_collector() {
        Ok(collector) => collector,
        Err(failure) => {
            return Err(HandoffError { failure, request });
        }
    };
    match collector.sender.send(request) {
        Ok(()) => Ok(()),
        Err(mpsc::SendError(request)) => Err(HandoffError {
            failure: HandoffFailure::Disconnected,
            request,
        }),
    }
}

/// Transfer owned components to the persistent collector.
pub fn collect_components_in_background(
    components: Vec<OwnedComponent>,
) -> Result<(), HandoffError> {
    let request = CollectionRequest::Components(components);
    let collector = match initialized_collector() {
        Ok(collector) => collector,
        Err(failure) => {
            return Err(HandoffError { failure, request });
        }
    };
    match collector.sender.send(request) {
        Ok(()) => Ok(()),
        Err(mpsc::SendError(request)) => Err(HandoffError {
            failure: HandoffFailure::Disconnected,
            request,
        }),
    }
}

fn initialized_collector() -> Result<&'static Collector, HandoffFailure> {
    let collector = COLLECTOR.get().ok_or(HandoffFailure::Uninitialized)?;
    let current_pid = std::process::id();
    if collector.owner_pid != current_pid {
        return Err(HandoffFailure::Forked {
            owner_pid: collector.owner_pid,
            current_pid,
        });
    }
    Ok(collector)
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
    _target: TerminationTarget,
}

impl From<OwnedComponent> for CollectedChild {
    fn from(component: OwnedComponent) -> Self {
        let (child, target) = component.into_parts();
        Self {
            child,
            _target: target,
        }
    }
}

/// Multiplex collection so one long-lived child cannot starve later handoffs.
fn collect_children(receiver: &mpsc::Receiver<CollectionRequest>) {
    let mut children = Vec::new();
    loop {
        match receiver.recv_timeout(BACKGROUND_COLLECTION_POLL_INTERVAL) {
            Ok(request) => append_request(request, &mut children),
            Err(mpsc::RecvTimeoutError::Disconnected) if children.is_empty() => return,
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {}
        }
        while let Ok(request) = receiver.try_recv() {
            append_request(request, &mut children);
        }
        children.retain_mut(|owned: &mut CollectedChild| match owned.child.try_wait() {
            Ok(None) => true,
            Ok(Some(_)) => false,
            Err(error) if SystemPlatform::child_already_reaped(&error) => false,
            Err(error) => {
                debug!(%error, "child collection probe failed; retrying");
                true
            }
        });
    }
}

fn append_request(request: CollectionRequest, children: &mut Vec<CollectedChild>) {
    match request {
        CollectionRequest::Child(child) => children.push(child),
        CollectionRequest::Components(components) => {
            children.extend(components.into_iter().map(CollectedChild::from));
        }
    }
}

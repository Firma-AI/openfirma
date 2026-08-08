//! Firma component identity and owned process capabilities.
//!
//! [`OwnedComponent`] is the canonical in-process capability: it keeps the
//! direct-child handle required for collection inseparable from the
//! [`TerminationTarget`] required to govern the complete platform scope.
//! [`ComponentName`] supplies stable command and runtime-state identity but
//! grants no process authority by itself.

use std::process::{Child, ExitStatus};

use crate::platform::{SpawnedChild, TerminationTarget};
use firma_runtime_state::UserProcessId;

/// Opaque identity of a managed process in the local Firma stack.
///
/// The name determines command selection and runtime-state file names; it does
/// not itself grant authority to signal or collect a process. This machinery is
/// agnostic to which components exist: the concrete names are supplied by the
/// caller at spawn time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentName(String);

impl ComponentName {
    /// Create a component identity from its stable name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Return the name used in commands, logs, and diagnostics.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the runtime-state file that stores this component's termination target.
    pub fn pidfile_name(&self) -> String {
        format!("{}.pid", self.0)
    }

    /// Return the runtime-state file that stores this component's listen address.
    pub fn listen_file_name(&self) -> String {
        format!("{}.listen", self.0)
    }
}

/// Plain description of one component to spawn and wait on for readiness.
///
/// This carries no configuration types or closures: the firma-specific layer
/// resolves everything eagerly and hands the generic startup loop this data.
/// `args` is the full child subcommand, e.g. `["authority", "--config",
/// "<path>"]`.
pub struct ComponentSpec {
    /// Identity used for command selection and runtime-state file names.
    pub name: ComponentName,
    /// Full child subcommand arguments passed to the component executable.
    pub args: Vec<String>,
    /// Address probed to establish this component's readiness.
    pub readiness_addr: std::net::SocketAddr,
}

/// Exclusive process capabilities for one managed stack component.
///
/// Holding this value authorizes its owner to collect the direct child and
/// signal its [`TerminationTarget`]. Private fields prevent callers from
/// accidentally separating those responsibilities before an explicit
/// [`OwnedComponent::into_parts`] transfer.
pub struct OwnedComponent {
    name: ComponentName,
    child: Child,
    leader_pid: UserProcessId,
    termination_target: TerminationTarget,
}

impl OwnedComponent {
    /// Bind a newly spawned platform child to its component identity.
    pub fn from_spawned(name: ComponentName, spawned: SpawnedChild) -> Self {
        Self {
            name,
            child: spawned.child,
            leader_pid: spawned.leader_pid,
            termination_target: spawned.termination_target,
        }
    }

    /// Bind an existing child and termination target to a component identity.
    ///
    /// This constructor is used by test scaffolding that starts processes
    /// outside the production spawn path.
    #[cfg(feature = "test-support")]
    pub(crate) fn from_child(
        name: ComponentName,
        child: Child,
        leader_pid: UserProcessId,
        termination_target: TerminationTarget,
    ) -> Self {
        Self {
            name,
            child,
            leader_pid,
            termination_target,
        }
    }

    /// Return the component's immutable identity.
    pub const fn name(&self) -> &ComponentName {
        &self.name
    }

    /// Return the original leader process ID for status and diagnostics.
    pub const fn leader_pid(&self) -> UserProcessId {
        self.leader_pid
    }

    /// Borrow the [`TerminationTarget`] without relinquishing component ownership.
    pub const fn termination_target(&self) -> &TerminationTarget {
        &self.termination_target
    }

    /// Probe and collect the leader if it exited, retaining this capability.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Block until the leader exits and collect its exit status.
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child.wait()
    }

    /// Request hard termination of the leader process only.
    ///
    /// Process-tree termination remains the responsibility of
    /// [`Self::termination_target`].
    pub fn kill_leader(&mut self) -> std::io::Result<()> {
        self.child.kill()
    }

    /// Borrow the child handle for bounded collection loops.
    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    /// Borrow collection and [`TerminationTarget`] capabilities together.
    ///
    /// This preserves their common [`OwnedComponent`] lifetime while allowing
    /// teardown to collect the child between process-scope probes.
    pub fn child_and_target(&mut self) -> (&mut Child, &TerminationTarget) {
        (&mut self.child, &self.termination_target)
    }

    /// Relinquish ownership into separate collection and termination capabilities.
    ///
    /// Callers assume responsibility for keeping the returned [`Child`] and
    /// [`TerminationTarget`] governed until both teardown and collection are
    /// complete.
    pub fn into_parts(self) -> (Child, TerminationTarget) {
        (self.child, self.termination_target)
    }
}

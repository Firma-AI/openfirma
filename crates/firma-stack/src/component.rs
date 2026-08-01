//! Firma component roles and owned process capabilities.

use std::process::{Child, ExitStatus};

use crate::platform::{SpawnedChild, TerminationTarget};
use firma_runtime_state::UserProcessId;

/// Identifies a managed process by its role in the local Firma stack.
///
/// The role determines command selection and runtime-state file names; it does
/// not itself grant authority to signal or collect a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentRole {
    /// The local policy authority process.
    Authority,
    /// The local enforcement sidecar process.
    Sidecar,
}

impl ComponentRole {
    /// Return the role name used in commands, logs, and diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::Sidecar => "sidecar",
        }
    }

    /// Return the runtime-state file that stores this role's termination target.
    pub const fn pidfile_name(self) -> &'static str {
        match self {
            Self::Authority => "authority.pid",
            Self::Sidecar => "sidecar.pid",
        }
    }

    /// Return the runtime-state file that stores this role's listen address.
    pub const fn listen_file_name(self) -> &'static str {
        match self {
            Self::Authority => "authority.listen",
            Self::Sidecar => "sidecar.listen",
        }
    }
}

/// Exclusive process capabilities for one managed stack component.
///
/// Holding this value authorizes its owner to wait for the child and signal its
/// platform termination target. The fields remain private so callers cannot
/// accidentally separate the child handle from the capability that governs it.
pub struct OwnedComponent {
    role: ComponentRole,
    child: Child,
    leader_pid: UserProcessId,
    termination_target: TerminationTarget,
}

impl OwnedComponent {
    /// Bind a newly spawned platform child to its stack role.
    pub fn from_spawned(role: ComponentRole, spawned: SpawnedChild) -> Self {
        Self {
            role,
            child: spawned.child,
            leader_pid: spawned.leader_pid,
            termination_target: spawned.termination_target,
        }
    }

    /// Bind an existing child and termination target to a stack role.
    ///
    /// This constructor is used by test scaffolding that starts processes
    /// outside the production spawn path.
    pub fn from_child(
        role: ComponentRole,
        child: Child,
        leader_pid: UserProcessId,
        termination_target: TerminationTarget,
    ) -> Self {
        Self {
            role,
            child,
            leader_pid,
            termination_target,
        }
    }

    /// Return the component's immutable stack role.
    pub const fn role(&self) -> ComponentRole {
        self.role
    }

    /// Return the original leader process ID for status and diagnostics.
    pub const fn leader_pid(&self) -> UserProcessId {
        self.leader_pid
    }

    /// Borrow the platform capability used to signal the process tree.
    pub const fn termination_target(&self) -> &TerminationTarget {
        &self.termination_target
    }

    /// Probe and collect the leader if it has exited without relinquishing ownership.
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

    /// Borrow child collection and process-tree termination capabilities together.
    pub fn child_and_target(&mut self) -> (&mut Child, &TerminationTarget) {
        (&mut self.child, &self.termination_target)
    }

    /// Relinquish component ownership into its child and termination capabilities.
    pub fn into_parts(self) -> (Child, TerminationTarget) {
        (self.child, self.termination_target)
    }
}

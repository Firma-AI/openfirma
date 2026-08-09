//! Component identity and owned process capabilities.
//!
//! [`OwnedComponent`] is the canonical in-process capability: it keeps the
//! direct-child handle required for collection inseparable from the
//! [`TerminationTarget`] required to govern the complete platform scope.
//! [`ComponentName`] supplies stable command and runtime-state identity but
//! grants no process authority by itself.

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, ExitStatus};

use crate::OrchestratorError;
use crate::platform::{SpawnedChild, TerminationTarget};
use firma_runtime_state::UserProcessId;

/// Opaque identity of a managed process in the local stack.
///
/// The name determines command selection and runtime-state file names; it does
/// not itself grant authority to signal or collect a process. This machinery is
/// agnostic to which components exist: the concrete names are supplied by the
/// caller at spawn time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentName(String);

impl ComponentName {
    /// Create a component identity from its stable name.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::InvalidComponentName`] when the name is
    /// unsafe as a cross-platform runtime-state filename.
    pub(crate) fn new(name: impl Into<String>) -> Result<Self, OrchestratorError> {
        let name = name.into();
        if !is_safe_name(&name) {
            return Err(OrchestratorError::InvalidComponentName { name });
        }
        Ok(Self(name))
    }

    /// Return the name used in commands, logs, and diagnostics.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the runtime-state file that stores this component's termination target.
    pub(crate) fn pidfile_name(&self) -> String {
        format!("{}.pid", self.0)
    }

    /// Return the runtime-state file that stores this component's listen address.
    pub(crate) fn listen_file_name(&self) -> String {
        format!("{}.listen", self.0)
    }
}

fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.ends_with(['.', ' '])
        && !is_windows_device_name(name)
        && !name.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
                )
        })
}

fn is_windows_device_name(name: &str) -> bool {
    let basename = name.split('.').next().unwrap_or(name);
    let basename = basename.to_ascii_uppercase();
    matches!(basename.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || basename
            .strip_prefix("COM")
            .or_else(|| basename.strip_prefix("LPT"))
            .is_some_and(|number| {
                matches!(
                    number,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
}

/// Plain description of one component to spawn and wait on for readiness.
///
/// The caller retains control over all command settings, including non-UTF-8
/// arguments, environment variables, and the working directory. The
/// orchestrator overrides standard I/O on every platform and native creation
/// flags on Windows. Caller-provided Windows creation flags cannot be preserved
/// through the standard library's [`Command`] API.
pub struct ComponentSpec {
    /// Fully configured command used to launch this component.
    pub command: Command,
    /// Contract used to discover and probe this component's TCP endpoint.
    pub readiness: Readiness,
}

/// Generation-scoped inputs for building one component's launch specification.
///
/// The caller decides how to pass startup-report paths to its child commands.
#[derive(Debug, Clone, Copy)]
struct ComponentContext<'a> {
    name: &'a str,
    startup_report_path: &'a Path,
}

/// Validated endpoint published by an earlier component in startup order.
#[derive(Debug)]
pub struct ReadyComponent {
    name: String,
    dial_addr: SocketAddr,
}

impl ReadyComponent {
    pub(crate) fn new(name: &str, dial_addr: SocketAddr) -> Self {
        Self {
            name: name.to_string(),
            dial_addr,
        }
    }

    /// Return the endpoint that passed publication validation and probing.
    #[must_use]
    const fn dial_addr(&self) -> SocketAddr {
        self.dial_addr
    }
}

/// Inputs for producing one complete caller-owned component specification.
///
/// The orchestrator invokes the planner once per topology component immediately
/// before spawning it. `ready_components` contains only earlier components
/// whose endpoints passed readiness and canonical publication.
#[derive(Debug)]
pub struct ComponentPlanContext<'a> {
    component: ComponentContext<'a>,
    ready_components: &'a [ReadyComponent],
}

impl<'a> ComponentPlanContext<'a> {
    pub(crate) const fn new(
        name: &'a str,
        startup_report_path: &'a Path,
        ready_components: &'a [ReadyComponent],
    ) -> Self {
        Self {
            component: ComponentContext::new(name, startup_report_path),
            ready_components,
        }
    }

    /// Return the topology identity of the component being planned.
    #[must_use]
    pub const fn name(&self) -> &'a str {
        self.component.name()
    }

    /// Describe child-published readiness for the component being planned.
    #[must_use]
    pub const fn child_published_tcp(
        &self,
        requested_addr: SocketAddr,
    ) -> ChildPublishedTcpContext<'a> {
        self.component.child_published_tcp(requested_addr)
    }

    /// Find a prior validated endpoint by topology identity.
    #[must_use]
    pub fn ready_endpoint(&self, name: &str) -> Option<SocketAddr> {
        self.ready_components
            .iter()
            .find(|component| component.name == name)
            .map(ReadyComponent::dial_addr)
    }
}

impl<'a> ComponentContext<'a> {
    const fn new(name: &'a str, startup_report_path: &'a Path) -> Self {
        Self {
            name,
            startup_report_path,
        }
    }

    /// Return the topology identity of this component.
    #[must_use]
    const fn name(&self) -> &'a str {
        self.name
    }

    /// Describe child-published readiness using this component's startup report.
    #[must_use]
    const fn child_published_tcp(
        &self,
        requested_addr: SocketAddr,
    ) -> ChildPublishedTcpContext<'a> {
        ChildPublishedTcpContext {
            requested_addr,
            startup_report_path: self.startup_report_path,
        }
    }
}

/// Borrowed child-report inputs available during post-lock plan building.
#[derive(Debug, Clone, Copy)]
pub struct ChildPublishedTcpContext<'a> {
    requested_addr: SocketAddr,
    startup_report_path: &'a Path,
}

impl<'a> ChildPublishedTcpContext<'a> {
    /// Return the generation-scoped path for the child's startup report.
    #[must_use]
    pub const fn startup_report_path(&self) -> &'a Path {
        self.startup_report_path
    }

    /// Convert the borrowed planning context into owned readiness evidence.
    #[must_use]
    pub fn into_readiness(self) -> Readiness {
        Readiness::ChildPublishedTcp(ChildPublishedTcpReadiness {
            requested_addr: self.requested_addr,
        })
    }
}

/// Owned child-publication evidence retained after the plan callback returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildPublishedTcpReadiness {
    pub(crate) requested_addr: SocketAddr,
}

/// TCP endpoint evidence required from a component during startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// Probe the configured endpoint directly.
    ConfiguredTcp(SocketAddr),
    /// Require the child to publish its effective bound endpoint before probing.
    ChildPublishedTcp(ChildPublishedTcpReadiness),
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

//! Component identity and owned process capabilities.
//!
//! [`OwnedComponent`] is the canonical in-process capability: it keeps the
//! direct-child handle required for collection inseparable from the
//! [`TerminationTarget`] required to govern the complete platform scope.
//! [`ComponentName`] supplies stable command and runtime-state identity but
//! grants no process authority by itself. See the
//! [crate-level lifecycle model](crate) for how this capability
//! moves through startup, running ownership, and collection.

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::str::FromStr;

#[cfg(unix)]
use camino::{Utf8Path, Utf8PathBuf};
#[cfg(unix)]
use std::path::PathBuf;

use crate::OrchestratorError;
use crate::platform::{SpawnedChild, TerminationTarget};
use firma_runtime_state::UserProcessId;

/// A connectable endpoint exposed by a managed component.
///
/// TCP endpoints retain their conventional bare `host:port` representation.
/// On Unix, local sockets use `unix:<path>`; the prefix makes persisted listen
/// state unambiguous and is shared by display, parsing, and status reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentEndpoint {
    /// An Internet Protocol socket endpoint.
    Tcp(SocketAddr),
    /// A Unix-domain socket filesystem path.
    #[cfg(unix)]
    Unix(UnixEndpoint),
}

/// A validated Unix-domain socket filesystem path.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixEndpoint(Utf8PathBuf);

#[cfg(unix)]
impl UnixEndpoint {
    /// Create a Unix endpoint from a UTF-8, single-line filesystem path.
    ///
    /// # Errors
    ///
    /// Returns the original path when it is empty, is not valid UTF-8, or
    /// contains a NUL or line break.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, PathBuf> {
        let path = Utf8PathBuf::from_path_buf(path.into())?;
        if path.as_str().is_empty() || path.as_str().contains(['\0', '\n', '\r']) {
            return Err(path.into_std_path_buf());
        }
        Ok(Self(path))
    }

    /// Return the validated UTF-8 socket path.
    #[must_use]
    pub(crate) fn as_path(&self) -> &Utf8Path {
        &self.0
    }

    /// Consume the endpoint and return its validated UTF-8 socket path.
    #[must_use]
    pub fn into_path(self) -> Utf8PathBuf {
        self.0
    }
}

#[cfg(unix)]
impl std::fmt::Display for UnixEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::fmt::Display for ComponentEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(addr) => addr.fmt(formatter),
            #[cfg(unix)]
            Self::Unix(path) => write!(formatter, "unix:{path}"),
        }
    }
}

impl From<SocketAddr> for ComponentEndpoint {
    fn from(addr: SocketAddr) -> Self {
        Self::Tcp(addr)
    }
}

impl FromStr for ComponentEndpoint {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        #[cfg(unix)]
        if let Some(path) = value.strip_prefix("unix:") {
            return UnixEndpoint::new(path)
                .map(Self::Unix)
                .map_err(|_| "Unix endpoint path is empty or contains a NUL or line break".into());
        }
        value
            .parse()
            .map(Self::Tcp)
            .map_err(|error| format!("invalid component endpoint: {error}"))
    }
}

impl serde::Serialize for ComponentEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for ComponentEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

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
    /// Contract used to discover and probe this component's endpoint.
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
    endpoint: ComponentEndpoint,
}

impl ReadyComponent {
    pub(crate) fn new(name: &str, endpoint: ComponentEndpoint) -> Self {
        Self {
            name: name.to_string(),
            endpoint,
        }
    }

    /// Return the endpoint that passed publication validation and probing.
    #[must_use]
    const fn endpoint(&self) -> &ComponentEndpoint {
        &self.endpoint
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
    pub fn child_published(
        &self,
        expected_endpoint: ComponentEndpoint,
    ) -> ChildPublishedContext<'a> {
        self.component.child_published(expected_endpoint)
    }

    /// Find a prior validated endpoint by topology identity.
    #[must_use]
    pub fn ready_endpoint(&self, name: &str) -> Option<&'a ComponentEndpoint> {
        self.ready_components
            .iter()
            .find(|component| component.name == name)
            .map(ReadyComponent::endpoint)
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
    fn child_published(&self, expected_endpoint: ComponentEndpoint) -> ChildPublishedContext<'a> {
        ChildPublishedContext {
            expected_endpoint,
            startup_report_path: self.startup_report_path,
        }
    }
}

/// Borrowed child-report inputs available during post-lock plan building.
#[derive(Debug, Clone)]
pub struct ChildPublishedContext<'a> {
    expected_endpoint: ComponentEndpoint,
    startup_report_path: &'a Path,
}

impl<'a> ChildPublishedContext<'a> {
    /// Return the generation-scoped path for the child's startup report.
    #[must_use]
    pub const fn startup_report_path(&self) -> &'a Path {
        self.startup_report_path
    }

    /// Convert the borrowed planning context into owned readiness evidence.
    #[must_use]
    pub fn into_readiness(self) -> Readiness {
        Readiness::ChildPublished(ChildPublishedReadiness {
            expected_endpoint: self.expected_endpoint,
        })
    }
}

/// Owned child-publication evidence retained after the plan callback returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildPublishedReadiness {
    pub(crate) expected_endpoint: ComponentEndpoint,
}

/// Endpoint evidence required from a component during startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// Probe the configured endpoint directly.
    Configured(ComponentEndpoint),
    /// Require the child to publish its effective bound endpoint before probing.
    ChildPublished(ChildPublishedReadiness),
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

//! FIR-366 regression coverage for child-process command governance.
//!
//! `firma run` currently governs the command it directly executes, but not
//! descendants that command spawns. The ignored test keeps the real bwrap,
//! local-exec allowlist, and governance-wire reproduction executable until
//! child-process governance lands. This is an execution-governance bypass, not
//! a sandbox escape: descendants remain in the same bwrap filesystem and
//! network namespaces and inherit its seccomp filters. The active companion
//! tests prove the inherited loopback seccomp perimeter, HTTP/L7 governance,
//! and selected-config filesystem mask from ungoverned children.

mod execution;
mod filesystem;
mod http;
mod network;
mod support;

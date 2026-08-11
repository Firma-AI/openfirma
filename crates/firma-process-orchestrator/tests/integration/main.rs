#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use firma_process_orchestrator::StackTopology;

pub(crate) fn topology() -> StackTopology {
    StackTopology::new(["authority", "sidecar"]).expect("valid test topology")
}

#[cfg(unix)]
mod endpoint_readiness;
mod error_boundary;
mod forced_termination;
mod ownership;
mod startup_contract;
mod status_state_machine;
#[cfg(unix)]
mod stop_dependency_order;
mod stop_forced_grandchildren;
mod stop_grandchildren;
#[cfg(unix)]
mod stop_orphaned_grandchild;
#[cfg(unix)]
mod support;

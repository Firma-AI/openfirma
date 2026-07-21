//! Shared typed identities for integration tests.

#![allow(clippy::expect_used, reason = "fixed test UUID")]

use std::sync::LazyLock;

use firma_core::AgentId;

pub fn agent_id() -> &'static AgentId {
    static AGENT_ID: LazyLock<AgentId> = LazyLock::new(|| {
        "agt_01j0000000e008000000000001"
            .parse()
            .expect("valid test agent ID")
    });
    &AGENT_ID
}

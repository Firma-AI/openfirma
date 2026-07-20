//! Shared typed identities for integration tests.

#![allow(clippy::expect_used, reason = "fixed test UUID")]

use std::sync::LazyLock;

use firma_core::AgentId;

pub fn agent_id() -> &'static AgentId {
    static AGENT_ID: LazyLock<AgentId> = LazyLock::new(|| {
        "019abcde-1234-7abc-8def-0123456789ab"
            .parse()
            .expect("valid test agent UUID")
    });
    &AGENT_ID
}

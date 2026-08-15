//! Registered-agent identity and execution-profile separation coverage.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::fs;

use firma_identifiers::AgentId;
use firma_run::error::RunError;
use firma_run::identity::{RunIdentity, read_configured_agent_id};

const AGENT_ID: &str = "agt_01j0000000e008000000000001";

#[test]
fn identity_propagates_registered_id_and_profile_separately() {
    let identity = RunIdentity::new(AGENT_ID.parse::<AgentId>().expect("agent id"), "codex");

    let env = identity.env_pairs();
    assert_eq!(
        env.get("FIRMA_AGENT_ID").map(String::as_str),
        Some(AGENT_ID)
    );
    assert_eq!(
        env.get("FIRMA_RUN_PROFILE").map(String::as_str),
        Some("codex")
    );

    let headers = identity.full_attribution_headers();
    assert_eq!(
        headers.get("x-firma-agent").map(String::as_str),
        Some(AGENT_ID)
    );
    assert_eq!(
        headers.get("x-firma-profile").map(String::as_str),
        Some("codex")
    );
}

#[test]
fn configured_agent_id_rejects_missing_legacy_and_malformed_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("firma.toml");

    fs::write(&path, "[sidecar.authority]\nurl = \"http://localhost\"\n")
        .expect("write missing config");
    assert!(matches!(
        read_configured_agent_id(&path),
        Err(RunError::MissingAgentId { .. })
    ));

    fs::write(&path, "[sidecar.authority]\nagent_id = \"codex\"\n").expect("write legacy config");
    assert!(matches!(
        read_configured_agent_id(&path),
        Err(RunError::LegacyProfileAgentId { .. })
    ));

    fs::write(&path, "[sidecar.authority]\nagent_id = \"not a TypeID\"\n")
        .expect("write malformed config");
    assert!(matches!(
        read_configured_agent_id(&path),
        Err(RunError::InvalidAgentId { .. })
    ));
}

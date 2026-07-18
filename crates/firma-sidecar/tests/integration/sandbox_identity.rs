#![allow(
    clippy::expect_used,
    reason = "integration-test fixtures fail fast when deterministic UUIDs are invalid"
)]

use std::time::Duration;

use firma_runtime_state::SandboxId;
use firma_sidecar::local_exec::handler::{
    DefaultAction, LocalExecDecision, LocalExecHandler, LocalExecHandlerConfig, LocalExecRequest,
};

fn sandbox_id(value: &str) -> SandboxId {
    value.parse().expect("valid UUID v7 fixture")
}

fn request(sandbox_id: SandboxId) -> LocalExecRequest {
    LocalExecRequest {
        action: "local.exec".to_string(),
        executable: "/usr/bin/true".to_string(),
        args: Vec::new(),
        sandbox_id,
        session_id: "session".to_string(),
        agent_id: None,
        profile: "generic".to_string(),
        hitl_mode: "sync_wait".to_string(),
        budget_state_ref: None,
        request_fingerprint: None,
        approval_token: None,
    }
}

fn handler(expected_sandbox_id: Option<SandboxId>) -> LocalExecHandler {
    LocalExecHandler::new(LocalExecHandlerConfig {
        default_action: DefaultAction::PendingHitl,
        expected_sandbox_id,
        token_ttl: Duration::from_mins(1),
        retry_after_ms: 100,
    })
}

#[test]
fn local_exec_request_rejects_malformed_sandbox_id() {
    let json = r#"{
        "action":"local.exec",
        "executable":"/usr/bin/true",
        "sandbox_id":"../outside",
        "session_id":"session",
        "profile":"generic",
        "hitl_mode":"sync_wait"
    }"#;

    assert!(serde_json::from_str::<LocalExecRequest>(json).is_err());
}

#[test]
fn local_exec_request_accepts_uuid_v7_sandbox_id() {
    let json = r#"{
        "action":"local.exec",
        "executable":"/usr/bin/true",
        "sandbox_id":"01900000-0000-7000-8000-000000000001",
        "session_id":"session",
        "profile":"generic",
        "hitl_mode":"sync_wait"
    }"#;

    let request = serde_json::from_str::<LocalExecRequest>(json).expect("valid local-exec request");
    assert_eq!(
        request.sandbox_id.to_string(),
        "01900000-0000-7000-8000-000000000001"
    );
}

#[test]
fn bound_local_exec_handler_accepts_matching_sandbox_id() {
    let id = sandbox_id("01900000-0000-7000-8000-000000000001");
    let response = handler(Some(id)).decide(&request(id));

    assert_eq!(response.decision, LocalExecDecision::PendingHitl);
    assert!(response.approval_token.is_some());
}

#[test]
fn bound_local_exec_handler_denies_mismatched_sandbox_id_before_issuing_token() {
    let expected = sandbox_id("01900000-0000-7000-8000-000000000001");
    let other = sandbox_id("01900000-0000-7000-8000-000000000002");
    let response = handler(Some(expected)).decide(&request(other));

    assert_eq!(response.decision, LocalExecDecision::Deny);
    assert!(response.approval_token.is_none());
    assert_eq!(
        response.reason.as_deref(),
        Some("sandbox identity does not match this sidecar")
    );
}

#[test]
fn unbound_local_exec_handler_accepts_valid_sandbox_id() {
    let id = sandbox_id("01900000-0000-7000-8000-000000000002");
    let response = handler(None).decide(&request(id));

    assert_eq!(response.decision, LocalExecDecision::PendingHitl);
}

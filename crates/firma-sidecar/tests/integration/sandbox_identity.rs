#![allow(
    clippy::expect_used,
    reason = "integration-test fixtures fail fast when deterministic UUIDs are invalid"
)]

use std::assert_matches;
use std::time::Duration;

use firma_runtime_state::SandboxId;
use firma_sidecar::local_exec::handler::{
    DefaultAction, LocalExecDecision, LocalExecHandler, LocalExecHandlerConfig, LocalExecRequest,
};

fn sandbox_id(value: &str) -> SandboxId {
    value.parse().expect("valid sandbox ID fixture")
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
        management_token: None,
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

    let error = serde_json::from_str::<LocalExecRequest>(json)
        .expect_err("path-like sandbox ID must be rejected");
    assert_matches!(error.classify(), serde_json::error::Category::Data);
    assert_eq!(error.line(), 4);
    assert_eq!(error.column(), 33);
}

#[test]
fn local_exec_request_accepts_sbx_typeid() {
    let json = r#"{
        "action":"local.exec",
        "executable":"/usr/bin/true",
        "sandbox_id":"sbx_01j0000000e008000000000001",
        "session_id":"session",
        "profile":"generic",
        "hitl_mode":"sync_wait"
    }"#;

    let request = serde_json::from_str::<LocalExecRequest>(json).expect("valid local-exec request");
    assert_eq!(
        request.sandbox_id.to_string(),
        "sbx_01j0000000e008000000000001"
    );
}

#[test]
fn bound_local_exec_handler_accepts_matching_sandbox_id() {
    let id = sandbox_id("sbx_01j0000000e008000000000001");
    let response = handler(Some(id)).decide(&request(id));

    assert_eq!(response.decision, LocalExecDecision::PendingHitl);
    assert!(response.approval_token.is_some());
}

#[test]
fn bound_local_exec_handler_denies_mismatched_sandbox_id_without_approval_token() {
    let expected = sandbox_id("sbx_01j0000000e008000000000001");
    let other = sandbox_id("sbx_01j0000000e008000000000002");
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
    let id = sandbox_id("sbx_01j0000000e008000000000002");
    let response = handler(None).decide(&request(id));

    assert_eq!(response.decision, LocalExecDecision::PendingHitl);
}

use firma_audit_schema::{Decision, ExecutionEvent};

fn sample_event(signature: Vec<u8>) -> ExecutionEvent {
    ExecutionEvent {
        event_id: "aevt_01j0000000e008000000000001".to_string(),
        session_id: "session-001".to_string(),
        token_id: "ctok_01j0000000e008000000000001".to_string(),
        agent_id: "agt_01j0000000e008000000000001".to_string(),
        action: "communication.external.send".to_string(),
        resource: "paste.rs/".to_string(),
        decision: Decision::Deny,
        deny_reason: "policy denied".to_string(),
        enforcement_latency_us: 420,
        context_hash: "sha256:abc123".to_string(),
        bundle_version: "local".to_string(),
        timestamp: Some(1_717_505_648_761_000_000),
        dispatch_status: 0,
        dispatch_latency_us: 0,
        response_size: 0,
        sandbox_id: String::new(),
        provenance: String::new(),
        thread_id: String::new(),
        parent_action_id: String::new(),
        signature,
    }
}

#[test]
fn decisions_use_the_audit_wire_codes() {
    for (decision, code) in [
        (Decision::Allow, 1),
        (Decision::Deny, 2),
        (Decision::Abort, 3),
        (Decision::Modify, 4),
        (Decision::StepUp, 5),
        (Decision::Defer, 6),
    ] {
        let encoded = serde_json::to_value(decision).expect("decision serializes");
        assert_eq!(encoded, code);

        let decoded: Decision = serde_json::from_value(code.into()).expect("decision deserializes");
        assert_eq!(decoded, decision);
    }
}

#[test]
fn execution_event_has_stable_json_representation() {
    let event = sample_event(vec![0x30, 0x45, 0x02, 0x21]);

    let json = serde_json::to_string(&event).expect("event serializes");
    assert_eq!(
        json,
        r#"{"event_id":"aevt_01j0000000e008000000000001","session_id":"session-001","token_id":"ctok_01j0000000e008000000000001","agent_id":"agt_01j0000000e008000000000001","action":"communication.external.send","resource":"paste.rs/","decision":2,"deny_reason":"policy denied","enforcement_latency_us":420,"context_hash":"sha256:abc123","bundle_version":"local","timestamp":1717505648761000000,"dispatch_status":0,"dispatch_latency_us":0,"response_size":0,"sandbox_id":"","provenance":"","thread_id":"","parent_action_id":"","signature":"MEUCIQ=="}"#
    );

    let decoded: ExecutionEvent = serde_json::from_str(&json).expect("event deserializes");
    assert_eq!(decoded, event);
}

#[test]
fn invalid_base64_signature_is_rejected() {
    let mut value = serde_json::to_value(sample_event(Vec::new())).expect("event serializes");
    value["signature"] = "not base64!".into();

    let error = serde_json::from_value::<ExecutionEvent>(value)
        .expect_err("invalid signature encoding must fail");

    assert!(error.is_data(), "base64 failure should be a data error");
}

#[test]
fn unknown_decision_is_rejected() {
    let error =
        serde_json::from_value::<Decision>(7.into()).expect_err("unknown decision must fail");

    assert!(error.is_data(), "unknown decision should be a data error");
}

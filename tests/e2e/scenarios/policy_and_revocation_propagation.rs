use std::time::{Duration, Instant};

use crate::audit::{AuditDecision, AuditEvent};
use crate::harness::{LiveGovernedRun, TestWorld, run_bounded};
use crate::upstream::{HttpProbe, ProbeBehavior};

const ACTION: &str = "communication.internal.send";
const RESPONSE: &str = "firma-e2e-propagation-ok\n";

#[test]
fn policy_update_denies_without_restarting_live_session_or_sidecar() {
    let world = TestWorld::new();
    let mut run = world.start_live_governed();
    let initial_identity = run.identity();
    let initial_token = assert_allowed_request(&mut run, "policy-control");

    let policy = r#"forbid (
    principal,
    action == Firma::Action::"communication.internal.send",
    resource
);
"#;
    world.add_policy("live-update-deny.cedar", policy);
    assert_eq!(
        std::fs::read_to_string(world.path("config/policies/live-update-deny.cedar"))
            .expect("read policy update stimulus"),
        policy
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    let (event, resource, denied_at) = loop {
        let nonce = format!("policy-after-{}", uuid::Uuid::new_v4().simple());
        let probe = HttpProbe::start(&nonce, ProbeBehavior::OptionalResponse(RESPONSE));
        let url = probe.url();
        let resource = probe.resource();
        let status = run.request(&nonce, &url);
        let capture = probe.finish();
        let event = run.audit_event(&nonce, Duration::from_secs(5));
        assert_eq!(run.identity(), initial_identity);
        if status == 0 {
            let capture = capture.expect("allowed propagation probe reached upstream");
            assert_eq!(capture.method, "GET");
            assert_eq!(capture.path, format!("/{nonce}"));
            assert_allowed_event(&event, &resource, &initial_token);
            assert!(
                Instant::now() < deadline,
                "policy update did not deny within the documented 30-second interval"
            );
            continue;
        }
        assert_eq!(
            status, 22,
            "policy denial must surface as curl HTTP failure"
        );
        assert!(capture.is_none(), "policy-denied request reached upstream");
        break (event, resource, Instant::now());
    };
    assert!(
        denied_at <= deadline,
        "policy update denied after the documented 30-second interval"
    );

    assert_denied_event(
        &event,
        &resource,
        &initial_token,
        ACTION,
        &format!("policy denied: policy denied action '{ACTION}' on resource '{resource}'"),
    );
    assert_eq!(run.identity(), initial_identity);
    let output = run.finish();
    assert!(output.success(), "live governed run failed:\n{output}");
}

#[test]
fn active_token_revocation_denies_without_restarting_live_session_or_sidecar() {
    let world = TestWorld::new();
    let mut run = world.start_live_governed();
    let initial_identity = run.identity();
    let token_id = assert_allowed_request(&mut run, "revocation-control");

    let mut revoke =
        world.isolated_command_in(env!("CARGO_BIN_EXE_firma"), &world.workspace_path());
    revoke
        .args(["authority", "--config"])
        .arg(world.config_path())
        .args([
            "revocations",
            "add",
            &token_id,
            "--reason",
            "e2e-active-token-revocation",
        ]);
    let revoke_output = run_bounded(&mut revoke, Duration::from_secs(10));
    assert!(
        revoke_output.success(),
        "compiled CLI revocation stimulus failed:\n{revoke_output}"
    );
    assert!(
        revoke_output
            .stdout
            .contains(&format!("revoked token: {token_id}")),
        "revocation output did not identify active token:\n{revoke_output}"
    );
    let persisted = std::fs::read_to_string(world.path("state/revocations.txt"))
        .expect("read revocation stimulus effect");
    assert!(persisted.starts_with(&format!("{token_id}\t")));
    assert!(persisted.contains("\te2e-active-token-revocation\n"));

    let deadline = Instant::now() + Duration::from_secs(1);
    let (event, resource, denied_at) = loop {
        let nonce = format!("revoked-after-{}", uuid::Uuid::new_v4().simple());
        let probe = HttpProbe::start(&nonce, ProbeBehavior::OptionalResponse(RESPONSE));
        let url = probe.url();
        let resource = probe.resource();
        let status = run.request(&nonce, &url);
        let capture = probe.finish();
        let event = run.audit_event(&nonce, Duration::from_secs(5));
        assert_eq!(run.identity(), initial_identity);
        if status == 0 {
            let capture = capture.expect("allowed revocation probe reached upstream");
            assert_eq!(capture.method, "GET");
            assert_eq!(capture.path, format!("/{nonce}"));
            assert_allowed_event(&event, &resource, &token_id);
            assert!(
                Instant::now() < deadline,
                "revocation did not deny within the documented one-second interval"
            );
            continue;
        }
        assert_eq!(
            status, 22,
            "revocation denial must surface as curl HTTP failure"
        );
        assert!(capture.is_none(), "revoked request reached upstream");
        break (event, resource, Instant::now());
    };
    assert!(
        denied_at <= deadline,
        "revocation denied after the documented one-second interval"
    );

    assert_denied_event(
        &event,
        &resource,
        "",
        "raw.http.GET",
        &format!("token revoked: token revoked: {token_id}"),
    );
    assert_eq!(run.identity(), initial_identity);
    let output = run.finish();
    assert!(output.success(), "live governed run failed:\n{output}");
}

fn assert_allowed_request(run: &mut LiveGovernedRun, phase: &str) -> String {
    let nonce = format!("{phase}-{}", uuid::Uuid::new_v4().simple());
    let probe = HttpProbe::start(&nonce, ProbeBehavior::Respond(RESPONSE));
    let url = probe.url();
    let resource = probe.resource();
    assert_eq!(run.request(&nonce, &url), 0, "positive control failed");
    let capture = probe.finish().expect("positive control reached upstream");
    assert_eq!(capture.method, "GET");
    assert_eq!(capture.path, format!("/{nonce}"));
    let event = run.audit_event(&nonce, Duration::from_secs(5));
    assert!(event.token_id.starts_with("ctok_"));
    assert_allowed_event(&event, &resource, &event.token_id);
    event.token_id
}

fn assert_allowed_event(event: &AuditEvent, resource: &str, token_id: &str) {
    assert_eq!(event.action, ACTION);
    assert_eq!(event.resource, resource);
    assert_eq!(event.decision, AuditDecision::Allow);
    assert_eq!(event.deny_reason, "");
    assert_eq!(event.token_id, token_id);
    assert_eq!(event.dispatch_status, 200);
}

fn assert_denied_event(
    event: &AuditEvent,
    resource: &str,
    audit_token_id: &str,
    action: &str,
    reason: &str,
) {
    assert_eq!(event.action, action);
    assert_eq!(event.resource, resource);
    assert_eq!(event.decision, AuditDecision::Deny);
    assert_eq!(event.deny_reason, reason);
    assert_eq!(event.token_id, audit_token_id);
    assert_eq!(event.dispatch_status, 0);
}

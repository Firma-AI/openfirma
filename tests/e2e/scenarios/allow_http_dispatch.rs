use std::time::Duration;

use crate::audit::AuditDecision;
use crate::harness::{TestWorld, isolated_command, run_bounded};
use crate::upstream::{HttpProbe, ProbeBehavior};

const RESPONSE: &str = "firma-e2e-upstream-ok\n";

#[test]
fn live_minted_capability_allows_http_dispatch() {
    let control_world = TestWorld::new();
    let control_nonce = format!("control-{}", uuid::Uuid::new_v4().simple());
    let control_server = HttpProbe::start(&control_nonce, ProbeBehavior::Respond(RESPONSE));
    let control_url = control_server.url();
    let mut control = isolated_command("curl", &control_world);
    control.args(curl_args(&control_url));
    let control_output = run_bounded(&mut control, Duration::from_secs(15));
    assert!(
        control_output.success(),
        "direct curl control failed:\n{control_output}"
    );
    assert_eq!(control_output.stdout, RESPONSE);
    let control_capture = control_server
        .finish()
        .expect("control request reached probe");
    assert_eq!(control_capture.method, "GET");
    assert_eq!(control_capture.path, format!("/{control_nonce}"));

    // The enforced phase has fresh config, state, workspace, environment, and
    // upstream capture, so neither audit records nor requests can cross phases.
    let world = TestWorld::new();
    let nonce = format!("enforced-{}", uuid::Uuid::new_v4().simple());
    let server = HttpProbe::start(&nonce, ProbeBehavior::Respond(RESPONSE));
    let url = server.url();

    let run = world.run_governed(&nonce, "curl", curl_args(&url));
    assert!(
        run.output.success(),
        "enforced firma run failed:\n{}",
        run.output
    );
    assert!(
        run.output.stdout.ends_with(RESPONSE) && run.output.stdout.matches(RESPONSE).count() == 1,
        "expected one governed upstream response:\n{}",
        run.output
    );

    let capture = server.finish().expect("governed request reached probe");
    assert_eq!(capture.method, "GET");
    assert_eq!(capture.path, format!("/{nonce}"));

    let event = run.audit_event();
    assert_eq!(event.action, "communication.internal.send");
    assert_eq!(event.resource, server_resource(&url));
    assert_eq!(event.decision, AuditDecision::Allow);
    assert_eq!(event.deny_reason, "");
    assert!(event.token_id.starts_with("ctok_"));
    assert_eq!(event.dispatch_status, 200);
}

fn server_resource(url: &str) -> &str {
    url.strip_prefix("http://").expect("test URL uses HTTP")
}

fn curl_args(url: &str) -> [&str; 6] {
    [
        "--fail-with-body",
        "--silent",
        "--show-error",
        "--max-time",
        "10",
        url,
    ]
}

use std::time::Duration;

use crate::audit::AuditDecision;
use crate::harness::{TestWorld, isolated_command, run_bounded};
use crate::upstream::{HttpProbe, ProbeBehavior};

const RESPONSE: &str = "firma-e2e-deny-control-ok\n";
const ACTION: &str = "communication.internal.send";

#[test]
fn policy_denial_blocks_http_dispatch() {
    let control_world = TestWorld::new();
    let control_nonce = format!("control-{}", uuid::Uuid::new_v4().simple());
    let control_server = HttpProbe::start(&control_nonce, ProbeBehavior::Respond(RESPONSE));
    let control_url = control_server.url();
    let mut control = isolated_command("curl", &control_world);
    control.args(curl_args(&control_url));
    let control_output = run_bounded(&mut control, Duration::from_secs(15));
    assert!(
        control_output.success(),
        "direct control failed:\n{control_output}"
    );
    assert_eq!(control_output.stdout, RESPONSE);
    let control_capture = control_server
        .finish()
        .expect("control request reached probe");
    assert_eq!(control_capture.method, "GET");
    assert_eq!(control_capture.path, format!("/{control_nonce}"));

    let world = TestWorld::new();
    let nonce = format!("denied-{}", uuid::Uuid::new_v4().simple());
    world.add_policy(
        "e2e-deny.cedar",
        r#"forbid (
    principal,
    action == Firma::Action::"communication.internal.send",
    resource
);
"#,
    );
    let server = HttpProbe::start(&nonce, ProbeBehavior::MustNotConnect);
    let url = server.url();

    let run = world.run_governed(&nonce, "curl", curl_args(&url));
    assert!(
        !run.output.success(),
        "denied curl unexpectedly succeeded:\n{}",
        run.output
    );
    assert!(server.finish().is_none(), "denied request reached probe");

    let event = run.audit_event();
    let resource = server_resource(&url);
    assert_eq!(event.action, ACTION);
    assert_eq!(event.resource, resource);
    assert_eq!(event.decision, AuditDecision::Deny);
    assert_eq!(
        event.deny_reason,
        format!("policy denied: policy denied action '{ACTION}' on resource '{resource}'")
    );
    assert!(event.token_id.starts_with("ctok_"));
    assert_eq!(event.dispatch_status, 0);
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

use crate::audit::AuditDecision;
use crate::harness::TestWorld;
use crate::upstream::{HttpProbe, ProbeBehavior};

const ACTION: &str = "communication.internal.send";

#[test]
fn connector_failure_returns_gateway_timeout() {
    let world = TestWorld::new();
    let nonce = format!("connector-failure-{}", uuid::Uuid::new_v4().simple());
    let server = HttpProbe::start(&nonce, ProbeBehavior::CloseWithoutResponse);
    let url = server.url();

    let run = world.run_governed(
        &nonce,
        "curl",
        [
            "--silent",
            "--show-error",
            "--include",
            "--max-time",
            "10",
            &url,
        ],
    );
    assert!(
        run.output.success(),
        "governed curl failed:\n{}",
        run.output
    );
    assert!(
        run.output.stdout.contains("HTTP/1.1 504 Gateway Timeout")
            && run.output.stdout.contains("CONNECTOR_FAILURE"),
        "expected a connector-failure gateway response:\n{}",
        run.output
    );

    let capture = server.finish().expect("governed request reached probe");
    assert_eq!(capture.method, "GET");
    assert_eq!(capture.path, format!("/{nonce}"));

    let event = run.audit_event();
    assert_eq!(event.action, ACTION);
    assert_eq!(event.resource, server_resource(&url));
    assert_eq!(event.decision, AuditDecision::Abort);
    assert!(event.deny_reason.starts_with("CONNECTOR_FAILURE:"));
    assert!(event.token_id.starts_with("ctok_"));
    assert_eq!(event.dispatch_status, 0);
}

fn server_resource(url: &str) -> &str {
    url.strip_prefix("http://").expect("test URL uses HTTP")
}

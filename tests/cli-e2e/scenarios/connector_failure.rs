use std::time::Duration;

use crate::audit::matching_events;
use crate::harness::{TestWorld, isolated_command, run_bounded};
use crate::upstream::FailingUpstream;

const ACTION: &str = "communication.internal.send";

#[test]
fn connector_failure_returns_gateway_timeout() {
    let world = TestWorld::new();
    let nonce = format!("connector-failure-{}", uuid::Uuid::new_v4().simple());
    world.scaffold();
    let server = FailingUpstream::start(&nonce);
    let url = server.url();
    let session = format!("sess_e2e_{}", uuid::Uuid::new_v4().simple());

    let mut command = isolated_command(env!("CARGO_BIN_EXE_firma"), &world);
    command
        .args([
            "run",
            "--profile",
            "generic",
            "--authority",
            "local",
            "--sidecar",
            "local",
            "--config",
        ])
        .arg(world.config_path())
        .args([
            "--",
            "curl",
            "--silent",
            "--show-error",
            "--include",
            "--max-time",
            "10",
            &url,
        ])
        .env("FIRMA_RUN_SESSION_ID", &session);
    let output = run_bounded(&mut command, Duration::from_mins(2));
    assert!(output.success(), "governed curl failed:\n{output}");
    assert!(
        output.stdout.contains("HTTP/1.1 504 Gateway Timeout")
            && output.stdout.contains("CONNECTOR_FAILURE"),
        "expected a connector-failure gateway response:\n{output}"
    );

    let capture = server.finish();
    assert_eq!(capture.method, "GET");
    assert_eq!(capture.path, format!("/{nonce}"));

    let events = matching_events(&world.audit_path(), &session, &nonce);
    assert_eq!(
        events.len(),
        1,
        "expected one correlated audit event: {events:#?}"
    );
    let event = &events[0];
    assert_eq!(event.session_id, session);
    assert_eq!(event.action, ACTION);
    assert_eq!(event.resource, server_resource(&url));
    assert_eq!(event.decision, 3, "serialized ABORT is numeric value 3");
    assert!(event.deny_reason.starts_with("CONNECTOR_FAILURE:"));
    assert!(event.token_id.starts_with("ctok_"));
    assert_eq!(event.dispatch_status, 0);
}

fn server_resource(url: &str) -> &str {
    url.strip_prefix("http://").expect("test URL uses HTTP")
}

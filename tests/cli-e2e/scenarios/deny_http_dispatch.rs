use std::time::Duration;

use crate::audit::matching_events;
use crate::harness::{TestWorld, isolated_command, run_bounded};
use crate::upstream::{UnreachedUpstream, Upstream};

const RESPONSE: &str = "firma-e2e-deny-control-ok\n";
const ACTION: &str = "communication.internal.send";

#[test]
fn policy_denial_blocks_http_dispatch() {
    let control_world = TestWorld::new();
    let control_nonce = format!("control-{}", uuid::Uuid::new_v4().simple());
    let control_server = Upstream::start(&control_nonce, RESPONSE);
    let control_url = control_server.url();
    let mut control = isolated_command("curl", &control_world);
    control.args(curl_args(&control_url));
    let control_output = run_bounded(&mut control, Duration::from_secs(15));
    assert!(
        control_output.success(),
        "direct control failed:\n{control_output}"
    );
    assert_eq!(control_output.stdout, RESPONSE);
    let control_capture = control_server.finish();
    assert_eq!(control_capture.method, "GET");
    assert_eq!(control_capture.path, format!("/{control_nonce}"));

    let world = TestWorld::new();
    let nonce = format!("denied-{}", uuid::Uuid::new_v4().simple());
    world.scaffold();
    world.add_policy(
        "e2e-deny.cedar",
        r#"forbid (
    principal,
    action == Firma::Action::"communication.internal.send",
    resource
);
"#,
    );
    let server = UnreachedUpstream::start(&nonce);
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
        .args(["--", "curl"])
        .args(curl_args(&url))
        .env("FIRMA_RUN_SESSION_ID", &session);
    let output = run_bounded(&mut command, Duration::from_mins(2));
    assert!(
        !output.success(),
        "denied curl unexpectedly succeeded:\n{output}"
    );
    server.finish();

    let events = matching_events(&world.audit_path(), &session, &nonce);
    assert_eq!(
        events.len(),
        1,
        "expected one correlated audit event: {events:#?}"
    );
    let event = &events[0];
    let resource = server_resource(&url);
    assert_eq!(event.session_id, session);
    assert_eq!(event.action, ACTION);
    assert_eq!(event.resource, resource);
    assert_eq!(event.decision, 2, "serialized DENY is numeric value 2");
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

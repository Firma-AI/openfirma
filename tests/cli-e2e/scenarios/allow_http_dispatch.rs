use std::time::Duration;

use crate::audit::matching_events;
use crate::harness::{TestWorld, isolated_command, run_bounded};
use crate::upstream::Upstream;

const RESPONSE: &str = "firma-e2e-upstream-ok\n";

#[test]
fn live_minted_capability_allows_http_dispatch() {
    let control_world = TestWorld::new();
    let control_nonce = format!("control-{}", uuid::Uuid::new_v4().simple());
    let control_server = Upstream::start(&control_nonce, RESPONSE);
    let control_url = control_server.url();
    let mut control = isolated_command("curl", &control_world);
    control.args(curl_args(&control_url));
    let control_output = run_bounded(&mut control, Duration::from_secs(15));
    assert!(
        control_output.success(),
        "direct curl control failed:\n{control_output}"
    );
    assert_eq!(control_output.stdout, RESPONSE);
    let control_capture = control_server.finish();
    assert_eq!(control_capture.method, "GET");
    assert_eq!(control_capture.path, format!("/{control_nonce}"));

    // The enforced phase has fresh config, state, workspace, environment, and
    // upstream capture, so neither audit records nor requests can cross phases.
    let world = TestWorld::new();
    let nonce = format!("enforced-{}", uuid::Uuid::new_v4().simple());
    world.scaffold();
    let server = Upstream::start(&nonce, RESPONSE);
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
    assert!(output.success(), "enforced firma run failed:\n{output}");
    assert!(
        output.stdout.ends_with(RESPONSE) && output.stdout.matches(RESPONSE).count() == 1,
        "expected one governed upstream response:\n{output}"
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
    assert_eq!(event.action, "communication.internal.send");
    assert_eq!(event.resource, server_resource(&url));
    assert_eq!(event.decision, 1, "serialized ALLOW is numeric value 1");
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

use std::time::Duration;

use crate::audit::AuditDecision;
use crate::harness::{TestWorld, isolated_command, run_bounded};
use crate::upstream::{HttpProbe, ProbeBehavior};

const HOST: &str = "unmapped.test";
const RESPONSE: &str = "firma-e2e-unclassified-control-ok\n";

#[test]
fn unclassified_http_intent_fails_closed() {
    let control_world = TestWorld::new();
    let control_nonce = format!("control-{}", uuid::Uuid::new_v4().simple());
    let control_server = HttpProbe::start(&control_nonce, ProbeBehavior::Respond(RESPONSE));
    let control_url = control_server.url_for_host(HOST);
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
    let nonce = format!("unclassified-{}", uuid::Uuid::new_v4().simple());
    let server = HttpProbe::start(&nonce, ProbeBehavior::MustNotConnect);
    let url = server.url_for_host(HOST);

    let run = world.run_governed(&nonce, "curl", curl_args(&url));
    assert!(
        !run.output.success(),
        "unclassified request unexpectedly succeeded:\n{}",
        run.output
    );
    assert!(
        server.finish().is_none(),
        "unclassified request reached probe"
    );

    let event = run.audit_event();
    let resource = server_resource(&url);
    let port = resource
        .strip_prefix(HOST)
        .and_then(|value| value.split('/').next())
        .expect("resource contains host and port");
    assert_eq!(event.action, "raw.http.GET");
    assert_eq!(event.resource, resource);
    assert_eq!(event.decision, AuditDecision::Deny);
    assert_eq!(
        event.deny_reason,
        format!(
            "unclassified intent: protected action could not be classified: GET /{nonce} (host: {HOST}{port})"
        )
    );
    assert_eq!(event.dispatch_status, 0);
}

fn server_resource(url: &str) -> &str {
    url.strip_prefix("http://").expect("test URL uses HTTP")
}

fn curl_args(url: &str) -> [String; 8] {
    let authority = server_resource(url)
        .split('/')
        .next()
        .expect("test URL has authority");
    [
        "--resolve".to_string(),
        format!("{authority}:127.0.0.1"),
        "--fail-with-body".to_string(),
        "--silent".to_string(),
        "--show-error".to_string(),
        "--max-time".to_string(),
        "10".to_string(),
        url.to_string(),
    ]
}

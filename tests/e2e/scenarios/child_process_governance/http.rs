use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::audit::AuditDecision;
use crate::harness::{ProcessOutput, TestWorld, run_bounded};
use crate::upstream::{HttpProbe, ProbeBehavior};

use super::support::{
    assert_only_root_governed, first_existing, patch_local_exec_allowlist, set_executable,
    shell_quote, spawn_allow_all_endpoint,
};

const HTTP_ACTION: &str = "communication.internal.send";
const HTTP_RESPONSE: &str = "CHILD-UPSTREAM-REACHED\n";

#[test]
fn ungoverned_child_http_requests_remain_l7_governed() {
    let bash = first_existing(&["/usr/bin/bash", "/bin/bash"])
        .unwrap_or_else(|| panic!("bash must be installed in the test environment"));
    let bash_canonical = std::fs::canonicalize(&bash)
        .unwrap_or_else(|e| panic!("canonicalize {}: {e}", bash.display()));

    let control_world = TestWorld::isolated();
    let control_tool = control_world.workspace_path().join("child-http-tool");
    write_child_http_tool(&control_tool);
    let control_nonce = format!("child-control-{}", uuid::Uuid::new_v4().simple());
    let control_probe = HttpProbe::start(&control_nonce, ProbeBehavior::Respond(HTTP_RESPONSE));
    let control_url = control_probe.url();
    let mut control =
        control_world.isolated_command_in(&control_tool, &control_world.workspace_path());
    control.args([&control_url, &control_nonce]);
    let control_output = run_bounded(&mut control, Duration::from_secs(15));
    assert!(
        control_output.success(),
        "child HTTP control failed:\n{control_output}"
    );
    assert_child_attempted(&control_output, &control_nonce);
    assert!(
        control_output.stdout.ends_with(HTTP_RESPONSE),
        "child HTTP control did not receive the upstream response:\n{control_output}"
    );
    let control_capture = control_probe
        .finish()
        .expect("child HTTP control must reach the probe");
    assert_eq!(control_capture.method, "GET");
    assert_eq!(control_capture.path, format!("/{control_nonce}"));

    let (allow_world, allow_governed) = child_http_world(&bash_canonical);
    let allow_tool = allow_world.workspace_path().join("child-http-tool");
    write_child_http_tool(&allow_tool);
    let allow_nonce = format!("child-allow-{}", uuid::Uuid::new_v4().simple());
    let allow_probe = HttpProbe::start(&allow_nonce, ProbeBehavior::Respond(HTTP_RESPONSE));
    let allow_url = allow_probe.url();
    let allowed = run_child_http(&allow_world, &bash, &allow_tool, &allow_url, &allow_nonce);
    assert!(
        allowed.success(),
        "allowed child HTTP request failed:\n{allowed}"
    );
    assert_child_attempted(&allowed, &allow_nonce);
    assert!(
        allowed.stdout.contains(HTTP_RESPONSE)
            && allowed.stdout.matches(HTTP_RESPONSE).count() == 1,
        "allowed child did not receive exactly one upstream response:\n{allowed}"
    );
    let allow_capture = allow_probe
        .finish()
        .expect("allowed child request must reach the probe");
    assert_eq!(allow_capture.method, "GET");
    assert_eq!(allow_capture.path, format!("/{allow_nonce}"));
    let allow_governed = allow_governed.lock().expect("lock allow governance log");
    assert_only_root_governed(&allow_governed, &bash_canonical);
    let allow_audit = allow_world.audit_event(&allow_nonce);
    assert_eq!(allow_audit.action, HTTP_ACTION);
    assert_eq!(allow_audit.resource, server_resource(&allow_url));
    assert_eq!(allow_audit.decision, AuditDecision::Allow);
    assert_eq!(allow_audit.deny_reason, "");
    assert!(allow_audit.token_id.starts_with("ctok_"));
    assert_eq!(allow_audit.dispatch_status, 200);

    let (deny_world, deny_governed) = child_http_world(&bash_canonical);
    deny_world.add_policy(
        "child-http-deny.cedar",
        r#"forbid (
    principal,
    action == Firma::Action::"communication.internal.send",
    resource
);
"#,
    );
    let deny_tool = deny_world.workspace_path().join("child-http-tool");
    write_child_http_tool(&deny_tool);
    let deny_nonce = format!("child-deny-{}", uuid::Uuid::new_v4().simple());
    let deny_probe = HttpProbe::start(&deny_nonce, ProbeBehavior::MustNotConnect);
    let deny_url = deny_probe.url();
    let denied = run_child_http(&deny_world, &bash, &deny_tool, &deny_url, &deny_nonce);
    assert!(
        !denied.success(),
        "forbidden child HTTP request unexpectedly succeeded:\n{denied}"
    );
    assert_child_attempted(&denied, &deny_nonce);
    assert!(
        deny_probe.finish().is_none(),
        "forbidden child HTTP request reached the probe"
    );
    let deny_governed = deny_governed.lock().expect("lock deny governance log");
    assert_only_root_governed(&deny_governed, &bash_canonical);
    let deny_audit = deny_world.audit_event(&deny_nonce);
    let deny_resource = server_resource(&deny_url);
    assert_eq!(deny_audit.action, HTTP_ACTION);
    assert_eq!(deny_audit.resource, deny_resource);
    assert_eq!(deny_audit.decision, AuditDecision::Deny);
    assert_eq!(
        deny_audit.deny_reason,
        format!(
            "policy denied: policy denied action '{HTTP_ACTION}' on resource '{deny_resource}'"
        )
    );
    assert!(deny_audit.token_id.starts_with("ctok_"));
    assert_eq!(deny_audit.dispatch_status, 0);
}

fn child_http_world(bash_canonical: &Path) -> (TestWorld, Arc<Mutex<Vec<String>>>) {
    let world = TestWorld::new();
    let socket_dir = world.path("sockets");
    std::fs::create_dir_all(&socket_dir).expect("create socket directory");
    let governed = Arc::new(Mutex::new(Vec::<String>::new()));
    let governance_sock = socket_dir.join("local-exec.sock");
    patch_local_exec_allowlist(
        &world.config_path(),
        &socket_dir.join("traffic.sock"),
        &governance_sock,
        bash_canonical,
    );
    spawn_allow_all_endpoint(&governance_sock, Arc::clone(&governed));
    (world, governed)
}

fn run_child_http(
    world: &TestWorld,
    bash: &Path,
    tool: &Path,
    url: &str,
    nonce: &str,
) -> ProcessOutput {
    let script = format!(
        "{tool} {url} {nonce}; child_exit=$?; echo \"ROOT OBSERVED CHILD EXIT $child_exit\"; exit \"$child_exit\"",
        tool = shell_quote(tool),
        url = shell_quote(Path::new(url)),
        nonce = shell_quote(Path::new(nonce)),
    );
    world.run_firma(
        "generic",
        Some(&world.config_path()),
        &world.workspace_path(),
        &["--sidecar", "local", "--authority", "local"],
        bash,
        ["-c", &script],
    )
}

fn assert_child_attempted(output: &ProcessOutput, nonce: &str) {
    assert!(
        output
            .stdout
            .contains(&format!("CHILD HTTP ATTEMPTED nonce={nonce}")),
        "child did not emit the correlated HTTP stimulus marker:\n{output}"
    );
}

fn server_resource(url: &str) -> &str {
    url.strip_prefix("http://").expect("test URL uses HTTP")
}

fn write_child_http_tool(path: &Path) {
    let script = r#"#!/bin/sh
echo "CHILD HTTP ATTEMPTED nonce=$2"
exec curl --fail-with-body --silent --show-error --max-time 10 "$1"
"#;
    std::fs::write(path, script).expect("write child-http-tool");
    set_executable(path);
}

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::audit::AuditDecision;
use crate::harness::{TestWorld, run_bounded};
use crate::upstream::{HttpProbe, ProbeBehavior};

use super::support::{
    assert_only_root_governed, first_existing, patch_local_exec_allowlist, set_executable,
    shell_quote, spawn_allow_all_endpoint,
};

#[test]
fn ungoverned_child_remains_network_confined() {
    let bash = first_existing(&["/usr/bin/bash", "/bin/bash"])
        .unwrap_or_else(|| panic!("bash must be installed in the test environment"));
    let bash_canonical = std::fs::canonicalize(&bash)
        .unwrap_or_else(|e| panic!("canonicalize {}: {e}", bash.display()));

    let world = TestWorld::isolated();
    let cfg_dir = world.path("config");
    let state_dir = world.state_path();
    let workspace = world.workspace_path();
    let socket_dir = world.path("sockets");
    std::fs::create_dir_all(&socket_dir).expect("create socket directory");

    let network_tool = workspace.join("network-tool");
    write_network_tool(&network_tool);

    let control_probe = HttpProbe::start(
        "child-network-control",
        ProbeBehavior::Respond("CONTROL-REACHED"),
    );
    let control_url = control_probe.url();
    let mut control_command = world.isolated_command_in(&network_tool, &workspace);
    control_command.arg(&control_url);
    let control = run_bounded(&mut control_command, Duration::from_secs(10));
    assert!(control.success(), "network-tool control failed:\n{control}");
    assert!(
        control.stdout.contains("CHILD NETWORK ATTEMPTED"),
        "network-tool control did not attempt the connection:\n{control}"
    );
    let control_capture = control_probe
        .finish()
        .expect("network-tool control must reach the HTTP probe");
    assert_eq!(control_capture.method, "GET");
    assert_eq!(control_capture.path, "/child-network-control");

    world.scaffold_config(
        "generic",
        &cfg_dir,
        &state_dir,
        Some(&workspace),
        &workspace,
    );
    let governance_sock = socket_dir.join("local-exec.sock");
    let traffic_sock = socket_dir.join("traffic.sock");
    patch_local_exec_allowlist(
        &cfg_dir.join("firma.toml"),
        &traffic_sock,
        &governance_sock,
        &bash_canonical,
    );
    let governed = Arc::new(Mutex::new(Vec::<String>::new()));
    spawn_allow_all_endpoint(&governance_sock, Arc::clone(&governed));

    let blocked_probe = HttpProbe::start("child-network-blocked", ProbeBehavior::MustNotConnect);
    let blocked_url = blocked_probe.url();
    let blocked_port = url_port(&blocked_url);
    let bash_script = format!(
        "{tool} {url}; child_exit=$?; echo \"bash-done child-exit=$child_exit\"",
        tool = shell_quote(&network_tool),
        url = shell_quote(Path::new(&blocked_url)),
    );
    let output = world.run_firma(
        "generic",
        Some(&cfg_dir.join("firma.toml")),
        &workspace,
        &["--sidecar", "local", "--authority", "local"],
        &bash,
        ["-c", &bash_script],
    );

    assert!(output.success(), "allowed bash root failed:\n{output}");
    assert!(
        output.stdout.contains("CHILD NETWORK ATTEMPTED")
            && output.stdout.contains("bash-done child-exit=23"),
        "the ungoverned child did not attempt the blocked connection:\n{output}"
    );
    assert!(
        blocked_probe.finish().is_none(),
        "the ungoverned child reached the forbidden loopback destination"
    );

    let governed = governed.lock().expect("lock governance log").clone();
    assert_only_root_governed(&governed, &bash_canonical);

    let audit = world.audit_event(&blocked_port);
    assert_eq!(audit.action, "network.loopback");
    assert_eq!(audit.resource, format!("tcp:127.0.0.1:{blocked_port}"));
    assert_eq!(audit.decision, AuditDecision::Deny);
    assert_eq!(audit.deny_reason, "loopback blocked");
    assert_eq!(audit.dispatch_status, 0);
}

fn write_network_tool(path: &Path) {
    let script = r#"#!/usr/bin/bash
echo "CHILD NETWORK ATTEMPTED url=$1"
target="${1#http://}"
host_port="${target%%/*}"
request_path="/${target#*/}"
host="${host_port%:*}"
port="${host_port##*:}"
if exec 3<>"/dev/tcp/$host/$port"; then
  printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$request_path" "$host_port" >&3
  cat <&3
  exit 0
fi
echo "CHILD NETWORK BLOCKED"
exit 23
"#;
    std::fs::write(path, script).expect("write network-tool");
    set_executable(path);
}

fn url_port(url: &str) -> String {
    url.strip_prefix("http://127.0.0.1:")
        .and_then(|remainder| remainder.split_once('/'))
        .map_or_else(
            || panic!("unexpected HTTP probe URL: {url}"),
            |(port, _)| port.to_string(),
        )
}

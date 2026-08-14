//! FIR-366 regression coverage for child-process command governance.
//!
//! `firma run` currently governs the command it directly executes, but not
//! descendants that command spawns. The ignored test keeps the real bwrap,
//! local-exec allowlist, and governance-wire reproduction executable until
//! child-process governance lands. This is an execution-governance bypass, not
//! a sandbox escape: descendants remain in the same bwrap filesystem and
//! network namespaces and inherit its seccomp filters. The active companion
//! test proves the inherited loopback seccomp perimeter by attempting a
//! forbidden connection from an ungoverned child.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::audit::AuditDecision;
use crate::harness::{ProcessOutput, TestWorld, run_bounded};
use crate::upstream::{HttpProbe, ProbeBehavior};

const FORBIDDEN_MARKER: &str = "FORBIDDEN-TOOL EXECUTED";

#[test]
#[ignore = "integration test — run with --include-ignored (regression target for FIR-366; fails until child-process governance lands)"]
fn child_process_escapes_run_governance() {
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

    let forbidden_tool = workspace.join("forbidden-tool");
    let forbidden_marker = workspace.join("forbidden-ran");
    write_forbidden_tool(&forbidden_tool, &forbidden_marker);

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

    let _ = std::fs::remove_file(&forbidden_marker);
    let scenario_a = world.run_firma(
        "generic",
        Some(&cfg_dir.join("firma.toml")),
        &workspace,
        &["--sidecar", "local", "--authority", "local"],
        &forbidden_tool,
        ["as-root"],
    );
    assert!(
        !scenario_a.success(),
        "control failed: forbidden-tool as the root command should be denied, but firma run exited 0\n{scenario_a}"
    );
    assert!(
        !forbidden_marker.exists(),
        "control failed: forbidden-tool ran as the root command despite being absent from the allowlist\n{scenario_a}"
    );

    let _ = std::fs::remove_file(&forbidden_marker);
    let bash_script = format!(
        "{tool} as-child-of-bash; echo \"bash-done exit=$?\"",
        tool = shell_quote(&forbidden_tool),
    );
    let scenario_b = world.run_firma(
        "generic",
        Some(&cfg_dir.join("firma.toml")),
        &workspace,
        &["--sidecar", "local", "--authority", "local"],
        &bash,
        ["-c", &bash_script],
    );

    assert!(
        scenario_b.stdout.contains("bash-done"),
        "the allowed bash root did not execute — `firma run` could not start the sandbox in this environment.\n{scenario_b}"
    );

    let governed = governed.lock().expect("lock governance log").clone();
    assert_only_root_governed(&governed, &bash_canonical);

    assert!(
        !forbidden_marker.exists() && !output_contains(&scenario_b, FORBIDDEN_MARKER),
        "FIR-366: the forbidden-tool child executed ungoverned under an allowed bash root.\n{scenario_b}"
    );
}

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
    let control = run_bounded(&mut control_command, std::time::Duration::from_secs(10));
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
    assert_eq!(audit.resource, format!("tcp://127.0.0.1:{blocked_port}"));
    assert_eq!(audit.decision, AuditDecision::Deny);
    assert_eq!(audit.deny_reason, "loopback blocked");
    assert_eq!(audit.dispatch_status, 0);
}

fn output_contains(output: &ProcessOutput, needle: &str) -> bool {
    output.stdout.contains(needle) || output.stderr.contains(needle)
}

fn assert_only_root_governed(governed: &[String], root: &Path) {
    assert_eq!(
        governed.len(),
        1,
        "expected exactly one governance request for the root command: {governed:?}"
    );
    let request: serde_json::Value =
        serde_json::from_str(&governed[0]).expect("governance request must be valid JSON");
    assert_eq!(request["action"], "local.exec");
    assert_eq!(request["executable"], root.to_string_lossy().as_ref());
}

fn patch_local_exec_allowlist(
    config_path: &Path,
    traffic_sock: &Path,
    governance_sock: &Path,
    bash_canonical: &Path,
) {
    let original = std::fs::read_to_string(config_path).expect("read generated firma.toml");
    let anchor = "[run.profiles.generic]\nbackend = \"bwrap\"\n";
    assert!(
        original.contains(anchor),
        "generated firma.toml did not contain the expected generic profile anchor:\n{original}"
    );
    let injected = format!(
        "{anchor}sidecar_endpoint = \"unix://{traffic}\"\n\n\
         [run.profiles.generic.sidecar_local_exec]\n\
         endpoint = \"unix://{governance}\"\n\
         timeout_ms = 2000\n\
         enforce_known_executables = true\n\
         allowed_executables = [\"{bash}\"]\n",
        traffic = traffic_sock.display(),
        governance = governance_sock.display(),
        bash = bash_canonical.display(),
    );
    std::fs::write(config_path, original.replacen(anchor, &injected, 1))
        .expect("write patched firma.toml");
}

fn write_forbidden_tool(path: &Path, marker: &Path) {
    let script = format!(
        "#!/bin/sh\necho \"{FORBIDDEN_MARKER} pid=$$ argv=$*\"\n: > {marker}\n",
        marker = shell_quote(marker),
    );
    std::fs::write(path, script).expect("write forbidden-tool");
    set_executable(path);
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

fn spawn_allow_all_endpoint(sock_path: &Path, log: Arc<Mutex<Vec<String>>>) {
    use std::os::unix::net::UnixListener;

    let _ = std::fs::remove_file(sock_path);
    let listener = UnixListener::bind(sock_path)
        .unwrap_or_else(|e| panic!("bind allow-all endpoint at {}: {e}", sock_path.display()));
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            let mut reader =
                BufReader::new(stream.try_clone().expect("clone allow-all endpoint stream"));
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() {
                log.lock()
                    .expect("lock governance log")
                    .push(line.trim().to_string());
            }
            let _ = stream.write_all(b"{\"decision\":\"allow\"}\n");
        }
    });
}

fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)
        .expect("stat forbidden-tool")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("chmod forbidden-tool");
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', r"'\''"))
}

fn url_port(url: &str) -> String {
    url.strip_prefix("http://127.0.0.1:")
        .and_then(|remainder| remainder.split_once('/'))
        .map_or_else(
            || panic!("unexpected HTTP probe URL: {url}"),
            |(port, _)| port.to_string(),
        )
}

fn first_existing(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
}

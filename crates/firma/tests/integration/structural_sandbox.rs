//! Full-stack CLI tests that require a structural sandbox.
//!
//! These tests run real wrapped commands through `firma run`; tests that only
//! exercise parsing or pre-launch failures belong in the other top-level
//! integration modules. The shared module path lets nextest select the entire
//! environment-dependent set without per-test availability checks.
//!
//! ## FIR-366 — child processes escape command-exec governance
//!
//! `firma run` governs a launch **once**, for the command it directly `exec`s.
//! Any process that command spawns runs with **no** governance decision — so a
//! tool that is *denied* as the root command can still run, ungoverned, as a
//! child of an allowed root.
//!
//! This drives the real `firma` binary through a real bwrap sandbox, a real
//! autostarted sidecar + authority, and real firma-run command governance.
//!
//! Setup: the `generic` profile's `[sidecar_local_exec]` enables the
//! client-side allowlist (`enforce_known_executables = true`) with `bash`
//! allowed and a dropped-in `forbidden-tool` **not** allowed. A tiny in-process
//! Unix-socket server stands in for a sidecar with `default_action = "allow"`,
//! speaking firma's exact local-exec wire protocol (one newline-framed JSON
//! request → `{"decision":"allow"}`); the DENY under test comes from the real
//! firma-run allowlist, not this server.
//!
//! Two facts are asserted:
//!   * **Control (passes today):** `forbidden-tool` as the *root* command is
//!     DENIED by the allowlist and never executes.
//!   * **The feature under validation (fails today):** `bash -c forbidden-tool`
//!     must NOT let the `forbidden-tool` *child* execute. Until child-process
//!     governance lands, the child runs and this assertion fails — that is the
//!     point of committing the test as a regression target.
//!
//! Marked `#[ignore]` for now until this issue is addressed.
//!
//! The reproduction is inherently Linux-only — it relies on a real bwrap
//! sandbox, a `bash` root, a Unix-socket governance endpoint, and Unix file
//! permissions — so the whole file is compiled only on `cfg(target_os =
//! "linux")`. On every other target it is an empty test target. `bash` and
//! `bwrap` are required prerequisites and their absence fails the test.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wait_timeout::ChildExt;

fn firma_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

/// Captured outcome of one governed `firma run`.
struct RunOutcome {
    exit_code: Option<i32>,
    output: String,
}

/// The forbidden marker string the dropped-in tool prints when it executes.
const FORBIDDEN_MARKER: &str = "FORBIDDEN-TOOL EXECUTED";

fn disable_host_home_masks(config_path: &Path) {
    let config = std::fs::read_to_string(config_path).expect("read scaffolded config");
    let test_config = config.replace(
        r#"FIRMA_RUN_BWRAP_MASK_HOME_PATHS = ".ssh,.gnupg,.aws,.config/gcloud,.env""#,
        r#"FIRMA_RUN_BWRAP_MASK_HOME_PATHS = """#,
    );
    assert_ne!(
        test_config, config,
        "scaffolded config should contain the default home masks"
    );
    std::fs::write(config_path, test_config).expect("disable host-specific home masks");
}

#[test]
fn run_executes_echo_after_authority_key_was_wiped() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg_dir = tmp.path().join("cfg");
    let state_dir = tmp.path().join("state");

    let status = Command::new(firma_bin())
        .args([
            "config",
            "-y",
            "--mode",
            "agent-local",
            "--profile",
            "generic",
            "--posture",
            "dev",
        ])
        .arg("--output-dir")
        .arg(&cfg_dir)
        .arg("--state-dir")
        .arg(&state_dir)
        .status()
        .expect("spawn firma config");
    assert!(status.success(), "firma config scaffold failed");

    let config_path = cfg_dir.join("firma.toml");
    disable_host_home_masks(&config_path);
    let key_file = state_dir.join("authority.key");
    assert!(key_file.is_file(), "config should have generated the key");

    std::fs::remove_file(&key_file).expect("remove authority key");
    let _ = std::fs::remove_file(state_dir.join("authority.pub"));
    assert!(!key_file.exists(), "precondition: key absent before run");

    let output = Command::new(firma_bin())
        .args(["run", "--profile", "generic"])
        .arg("--config")
        .arg(&config_path)
        .args(["--", "echo", "hello"])
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn firma run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "firma run failed (regression?):\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("hello"),
        "expected 'hello' from the sandboxed command:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        key_file.is_file(),
        "authority key should have been regenerated on demand"
    );
}

#[test]
fn run_live_minted_capability_reaches_dispatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg_dir = tmp.path().join("cfg");
    let state_dir = tmp.path().join("state");

    let status = Command::new(firma_bin())
        .args([
            "config",
            "-y",
            "--mode",
            "agent-local",
            "--profile",
            "generic",
            "--posture",
            "dev",
        ])
        .arg("--output-dir")
        .arg(&cfg_dir)
        .arg("--state-dir")
        .arg(&state_dir)
        .status()
        .expect("spawn firma config");
    assert!(status.success(), "firma config scaffold failed");

    let config_path = cfg_dir.join("firma.toml");
    disable_host_home_masks(&config_path);

    let output = Command::new(firma_bin())
        .args([
            "run",
            "--profile",
            "generic",
            "--authority",
            "local",
            "--sidecar",
            "local",
        ])
        .arg("--config")
        .arg(&config_path)
        .args([
            "--",
            "curl",
            "--silent",
            "--show-error",
            "--include",
            "--max-time",
            "10",
            "http://127.0.0.1:1/stage-one-probe",
        ])
        .env("FIRMA_STATE_DIR", &state_dir)
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn firma run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "firma run failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("HTTP/1.1 504 Gateway Timeout") && stdout.contains("CONNECTOR_FAILURE"),
        "expected dispatch failure after Stage 1 and policy admission:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let audit =
        std::fs::read_to_string(state_dir.join("audit.jsonl")).expect("read Sidecar audit output");
    let reached_dispatch = audit.lines().any(|line| {
        let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
            return false;
        };
        event["action"] == "communication.internal.send"
            && event["resource"] == "127.0.0.1:1/stage-one-probe"
            && event["token_id"]
                .as_str()
                .is_some_and(|token_id| token_id.starts_with("ctok_"))
            && event["deny_reason"]
                .as_str()
                .is_some_and(|reason| reason.starts_with("CONNECTOR_FAILURE:"))
    });
    assert!(
        reached_dispatch,
        "expected an attributed post-policy dispatch attempt; audit:\n{audit}\nstderr:\n{stderr}"
    );
}

#[test]
#[ignore = "integration test — run with --include-ignored (regression target for FIR-366; fails until child-process governance lands)"]
fn child_process_escapes_run_governance() {
    // `firma run` preflights its own host requirements and fails closed with a
    // descriptive error if bwrap is missing or the host cannot create the
    // sandbox (WSL, restricted user namespaces — see
    // `firma-run/src/backend/linux_bwrap.rs`), so the test does not re-check
    // them: a broken environment surfaces as a `firma run` failure below.
    //
    // bash is the allowed root command. The allowlist matches the *canonical*
    // executable path (runtime.rs `resolve_governed_executable`), so resolve it.
    let bash = first_existing(&["/usr/bin/bash", "/bin/bash"])
        .unwrap_or_else(|| panic!("bash must be installed in the test environment"));
    let bash_canonical = std::fs::canonicalize(&bash)
        .unwrap_or_else(|e| panic!("canonicalize {}: {e}", bash.display()));

    // ── Scratch dirs: config, state, the bwrap-mounted workspace, the socket ─
    let cfg_tmp = tempfile::tempdir().unwrap();
    let state_tmp = tempfile::tempdir().unwrap();
    let workspace_tmp = tempfile::tempdir().unwrap();
    let sock_tmp = tempfile::tempdir().unwrap();

    let cfg_dir = cfg_tmp.path().to_path_buf();
    let state_dir = state_tmp.path().to_path_buf();
    let workspace = workspace_tmp.path().to_path_buf();

    // `forbidden-tool` lives inside the writable, bwrap-mounted workspace; its
    // side effect (touching a marker file) is visible to us on the host because
    // the mount is bind-mounted at the same absolute path inside the sandbox.
    let forbidden_tool = workspace.join("forbidden-tool");
    let forbidden_marker = workspace.join("forbidden-ran");
    write_forbidden_tool(&forbidden_tool, &forbidden_marker);

    // ── A full, self-consistent firma.toml via `firma config` ────────────────
    // This bootstraps [authority] + [sidecar.*] with correctly-resolved paths
    // and a bwrap `generic` profile that mounts the workspace read-write.
    bootstrap_config(&cfg_dir, &state_dir, &workspace);

    // Patch the generic profile with the local-exec allowlist: bash allowed,
    // forbidden-tool not. A unix `sidecar_endpoint` is required purely to
    // satisfy config validation — `--sidecar local` autostart substitutes the
    // real traffic socket at runtime.
    let governance_sock = sock_tmp.path().join("local-exec.sock");
    let traffic_sock = sock_tmp.path().join("traffic.sock");
    patch_local_exec_allowlist(
        &cfg_dir.join("firma.toml"),
        &traffic_sock,
        &governance_sock,
        &bash_canonical,
    );

    // ── Allow-all local-exec governance endpoint (the sidecar stand-in) ──────
    let governed = Arc::new(Mutex::new(Vec::<String>::new()));
    spawn_allow_all_endpoint(&governance_sock, Arc::clone(&governed));

    // ── Control: forbidden-tool AS THE ROOT must be DENIED by the allowlist ──
    let _ = std::fs::remove_file(&forbidden_marker);
    let scenario_a = run_governed(
        &cfg_dir,
        &workspace,
        &[forbidden_tool.to_string_lossy().as_ref(), "as-root"],
    );
    assert_ne!(
        scenario_a.exit_code,
        Some(0),
        "control failed: forbidden-tool as the root command should be denied, \
         but firma run exited 0\n{}",
        scenario_a.output
    );
    assert!(
        !forbidden_marker.exists(),
        "control failed: forbidden-tool ran as the root command despite being \
         absent from the allowlist\n{}",
        scenario_a.output
    );

    // ── The feature under validation: an allowed root must not let a denied ──
    //    child execute ungoverned.
    let _ = std::fs::remove_file(&forbidden_marker);
    let bash_script = format!(
        "{tool} as-child-of-bash; echo \"bash-done exit=$?\"",
        tool = shell_quote(&forbidden_tool),
    );
    let scenario_b = run_governed(
        &cfg_dir,
        &workspace,
        &[bash.to_string_lossy().as_ref(), "-c", &bash_script],
    );

    // The allowed root must have actually executed — its trailing `echo` proves
    // the sandbox started and ran the script. If it is missing, `firma run`
    // could not establish the sandbox (its preflight already fails closed for
    // missing bwrap / restricted user namespaces), so fail loudly with firma's
    // own error rather than mistaking "nothing ran" for "the child was blocked".
    assert!(
        scenario_b.output.contains("bash-done"),
        "the allowed bash root did not execute — `firma run` could not start the \
         sandbox in this environment.\nfirma run exit: {:?}\n{}",
        scenario_b.exit_code,
        scenario_b.output
    );

    // Sanity: governance was consulted for the bash root exactly, never for the
    // child — the shape of the FIR-366 gap. Match the `executable` field rather
    // than the raw line, since the bash request's argv embeds the tool's path.
    let governed = governed.lock().unwrap().clone();
    let forbidden_canonical = std::fs::canonicalize(&forbidden_tool).unwrap_or(forbidden_tool);
    let bash_exec = format!("\"executable\":\"{}\"", bash_canonical.display());
    let forbidden_exec = format!("\"executable\":\"{}\"", forbidden_canonical.display());
    assert!(
        governed.iter().any(|line| line.contains(&bash_exec)),
        "expected the bash root to be submitted for governance; governance log: {governed:?}"
    );
    assert!(
        !governed.iter().any(|line| line.contains(&forbidden_exec)),
        "the forbidden-tool child should never reach governance (it escapes the \
         decision entirely); governance log: {governed:?}"
    );

    // The assertion that currently fails: the denied tool must not run as a
    // child of an allowed root. When child-process governance lands, the child
    // exec is refused and this passes.
    assert!(
        !forbidden_marker.exists() && !scenario_b.output.contains(FORBIDDEN_MARKER),
        "FIR-366: the forbidden-tool CHILD executed ungoverned under an allowed \
         bash root — `firma run` governed only the root and never the child.\n\
         firma run exit: {:?}\n{}",
        scenario_b.exit_code,
        scenario_b.output
    );
}

/// Run `firma run` with the FIR-366 config over `command`, capturing combined
/// output and exit code, with a wall-clock guard.
fn run_governed(cfg_dir: &Path, workspace: &Path, command: &[&str]) -> RunOutcome {
    let config_path = cfg_dir.join("firma.toml");

    // Send stdout and stderr to one shared file (like a shell `2>&1`). Writing
    // to a file rather than a pipe means the child can never block on a full
    // pipe buffer, so `wait_timeout` alone suffices — no draining threads. The
    // two handles are `try_clone`d so they share one file offset and interleave.
    let log = tempfile::NamedTempFile::new().expect("create firma run output file");
    let stdout = log
        .as_file()
        .try_clone()
        .expect("clone firma run output handle");
    let stderr = log
        .as_file()
        .try_clone()
        .expect("clone firma run output handle");

    let mut child = Command::new(firma_bin())
        .args(["run", "--profile", "generic", "--config"])
        .arg(&config_path)
        .args(["--sidecar", "local", "--authority", "local", "--"])
        .args(command)
        .current_dir(workspace)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .expect("spawn firma run");

    let (exit_code, timed_out) = child
        .wait_timeout(Duration::from_mins(2))
        .expect("wait firma run")
        .map_or_else(
            || {
                let _ = child.kill();
                let _ = child.wait();
                (None, true)
            },
            |status| (status.code(), false),
        );

    let mut output =
        String::from_utf8_lossy(&std::fs::read(log.path()).unwrap_or_default()).into_owned();
    if timed_out {
        output.push_str("\n[test] firma run timed out after 2 minutes and was killed");
    }

    RunOutcome { exit_code, output }
}

/// Generate a complete config (authority + sidecar + bwrap generic profile)
/// with the workspace mounted read-write.
fn bootstrap_config(cfg_dir: &Path, state_dir: &Path, workspace: &Path) {
    let output = Command::new(firma_bin())
        .args([
            "config",
            "--yes",
            "--mode",
            "agent-local",
            "--profile",
            "generic",
            "--posture",
            "dev",
            "-o",
        ])
        .arg(cfg_dir)
        .arg("--state-dir")
        .arg(state_dir)
        .args([
            "--authority-listen",
            "127.0.0.1:0",
            "--mapping",
            "anthropic",
            "--workspace",
        ])
        .arg(workspace)
        .output()
        .expect("spawn firma config");
    assert!(
        output.status.success(),
        "firma config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Insert the local-exec allowlist into `[run.profiles.generic]`: bash allowed,
/// everything else (notably the dropped-in tool) denied as a root command.
///
/// The keys are inserted immediately after `backend = "bwrap"` so the bare
/// `sidecar_endpoint` key and the `[...sidecar_local_exec]` sub-table land in
/// the profile table rather than a later array-of-tables (`mounts`).
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
    let patched = original.replacen(anchor, &injected, 1);
    std::fs::write(config_path, patched).expect("write patched firma.toml");
}

/// Write a `forbidden-tool` shell script that announces itself and touches a
/// marker file so its execution is observable on the host.
fn write_forbidden_tool(path: &Path, marker: &Path) {
    let script = format!(
        "#!/bin/sh\necho \"{FORBIDDEN_MARKER} pid=$$ argv=$*\"\n: > {marker}\n",
        marker = shell_quote(marker),
    );
    std::fs::write(path, script).expect("write forbidden-tool");
    set_executable(path);
}

/// A minimal stand-in for the sidecar local-exec endpoint: accepts a
/// newline-framed JSON request, replies `{"decision":"allow"}`, and records the
/// raw request so the test can prove which executables were governed. Detached;
/// it dies with the test process.
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
                log.lock().unwrap().push(line.trim().to_string());
            }
            let _ = stream.write_all(b"{\"decision\":\"allow\"}\n");
        }
    });
}

fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .expect("stat forbidden-tool")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("chmod forbidden-tool");
}

/// Quote a path for safe single-token use inside the `bash -c` script.
fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', r"'\''"))
}

fn first_existing(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

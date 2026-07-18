//! Integration tests for the per-run sidecar marker reader.

#![allow(
    clippy::expect_used,
    reason = "integration-test setup uses expect to fail fast on fixture construction"
)]

use std::fs;
use std::path::Path;

use firma_runtime_state::MetadataFile;

const ID_1: &str = "01900000-0000-7000-8000-000000000001";
const ID_2: &str = "01900000-0000-7000-8000-000000000002";
const ID_3: &str = "01900000-0000-7000-8000-000000000003";

fn write_marker(run_dir: &Path, sandbox_id: &str, pid: u32) {
    write_marker_with_listen(run_dir, sandbox_id, pid, None);
}

/// Write a marker, optionally recording an explicit `listen` endpoint
/// (a `host:port` pair for an `http_proxy` interceptor, or a socket path).
/// `None` omits the field, mirroring a legacy marker written before
/// FIR-195.
fn write_marker_with_listen(run_dir: &Path, sandbox_id: &str, pid: u32, listen: Option<&str>) {
    let dir = run_dir.join(sandbox_id);
    fs::create_dir_all(&dir).expect("mkdir marker dir");
    let listen_line = listen.map_or_else(String::new, |l| format!("listen = \"{l}\"\n"));
    let toml = format!(
        "sandbox_id = \"{sandbox_id}\"\n\
         agent_id = \"codex\"\n\
         session_id = \"sess-1\"\n\
         authority_url = \"https://authority.local\"\n\
         policy_bundle_version = \"deadbeef\"\n\
         pid = {pid}\n\
         started_at = \"2026-05-18T10:00:00Z\"\n\
         {listen_line}"
    );
    fs::write(dir.join("metadata.toml"), toml).expect("write metadata.toml");
}

#[test]
fn metadata_file_parses_all_fields() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let run_dir = tmp.path().join("run");
    write_marker(&run_dir, ID_1, 4242);

    let text = fs::read_to_string(run_dir.join(ID_1).join("metadata.toml")).expect("read");
    let meta: MetadataFile = toml::from_str(&text).expect("parse metadata");

    assert_eq!(meta.sandbox_id.to_string(), ID_1);
    assert_eq!(meta.agent_id, "codex");
    assert_eq!(meta.session_id, "sess-1");
    assert_eq!(meta.authority_url, "https://authority.local");
    assert_eq!(meta.policy_bundle_version, "deadbeef");
    assert_eq!(meta.pid.get(), 4242);
    assert_eq!(meta.started_at, "2026-05-18T10:00:00Z");
}

use firma_runtime_state::sidecar_markers::probe_entry;
use firma_runtime_state::status::State;

#[test]
fn live_pid_no_socket_is_unhealthy() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let run_dir = tmp.path().join("run");
    let me = std::process::id();
    write_marker(&run_dir, ID_1, me);

    let entry = probe_entry(&run_dir.join(ID_1)).expect("probe");
    assert_eq!(entry.sandbox_id, ID_1);
    assert_eq!(
        entry.pid.map(firma_runtime_state::UserProcessId::get),
        Some(me)
    );
    assert_eq!(entry.state, State::Unhealthy);
    assert_eq!(entry.listen, run_dir.join(ID_1).join("sidecar.sock"));
}

/// Spawn and immediately reap a child, returning its now-dead PID.
///
/// `is_alive` on this PID returns false (ESRCH) until the OS reuses the slot.
fn reaped_dead_pid() -> u32 {
    #[cfg(windows)]
    let mut child = std::process::Command::new("cmd")
        .args(["/C", "exit"])
        .spawn()
        .expect("spawn throwaway child");

    #[cfg(not(windows))]
    let mut child = std::process::Command::new("true")
        .spawn()
        .expect("spawn throwaway child");

    let pid = child.id();
    child.wait().expect("reap throwaway child");
    pid
}

#[test]
fn dead_pid_is_stopped() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let run_dir = tmp.path().join("run");
    write_marker(&run_dir, ID_1, reaped_dead_pid());

    let entry = probe_entry(&run_dir.join(ID_1)).expect("probe");
    assert_eq!(entry.state, State::Stopped);
}

#[cfg(unix)]
#[test]
fn exited_unreaped_child_is_stopped() {
    use std::time::{Duration, Instant};

    let tmp = tempfile::tempdir().expect("tempdir");
    let run_dir = tmp.path().join("run");
    let mut child = std::process::Command::new("true")
        .spawn()
        .expect("spawn throwaway child");
    let pid = child.id();
    write_marker(&run_dir, ID_1, pid);

    let marker_dir = run_dir.join(ID_1);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut observed = None;
    while Instant::now() < deadline {
        let entry = probe_entry(&marker_dir).expect("probe");
        observed = Some(entry.state);
        if entry.state == State::Stopped {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(observed, Some(State::Stopped));
}

#[test]
fn uptime_secs_is_some_when_pid_file_exists() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let run_dir = tmp.path().join("run");
    let me = std::process::id();
    write_marker(&run_dir, ID_1, me);

    // Write sidecar.pid so marker_uptime_secs finds a file to stat.
    let marker_dir = run_dir.join(ID_1);
    fs::write(marker_dir.join("sidecar.pid"), me.to_string()).expect("write sidecar.pid");

    let entry = probe_entry(&marker_dir).expect("probe");
    assert!(
        entry.uptime_secs.is_some(),
        "uptime_secs should be Some when sidecar.pid is present"
    );
}

#[test]
fn http_proxy_listen_with_listening_port_is_running() {
    use std::net::TcpListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let run_dir = tmp.path().join("run");
    let me = std::process::id();

    // An `http_proxy` per-run sidecar binds a loopback TCP port, not a
    // Unix socket. Keep a listener bound so the probe's connect succeeds.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let addr = listener.local_addr().expect("local addr");
    write_marker_with_listen(&run_dir, ID_1, me, Some(&addr.to_string()));

    let entry = probe_entry(&run_dir.join(ID_1)).expect("probe");
    assert_eq!(
        entry.state,
        State::Running,
        "a healthy http_proxy per-run sidecar must report Running, not Unhealthy"
    );
    assert_eq!(entry.listen, std::path::PathBuf::from(addr.to_string()));
}

#[test]
fn http_proxy_listen_with_closed_port_is_unhealthy() {
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    let tmp = tempfile::tempdir().expect("tempdir");
    let run_dir = tmp.path().join("run");
    let me = std::process::id();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let addr = listener.local_addr().expect("local addr");
    write_marker_with_listen(&run_dir, ID_1, me, Some(&addr.to_string()));
    drop(listener);

    // macOS may briefly accept TCP handshakes on a recently
    // closed port. Wait until connect() fails before probing.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(10)).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let entry = probe_entry(&run_dir.join(ID_1)).expect("probe");
    assert_eq!(entry.state, State::Unhealthy);
}

#[cfg(unix)]
#[test]
fn live_pid_with_listening_socket_is_running() {
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let run_dir = tmp.path().join("run");
    let me = std::process::id();
    let sock = std::path::PathBuf::from(format!("/tmp/firma-status-{}.sock", std::process::id()));
    let _ = fs::remove_file(&sock);
    write_marker_with_listen(
        &run_dir,
        ID_1,
        me,
        Some(sock.to_str().expect("ASCII socket path")),
    );
    let _listener = UnixListener::bind(&sock).expect("bind uds");

    let entry = probe_entry(&run_dir.join(ID_1)).expect("probe");
    assert_eq!(entry.state, State::Running);
    let _ = fs::remove_file(sock);
}

use firma_runtime_state::sidecar_markers::{gc_stale, get, list};

#[test]
fn list_skips_and_gcs_dead_markers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let runtime_dir = tmp.path();
    let run_dir = runtime_dir.join("run");
    let me = std::process::id();
    write_marker(&run_dir, ID_1, me);
    write_marker(&run_dir, ID_2, reaped_dead_pid());

    let entries = list(runtime_dir).expect("list");
    let ids: Vec<&str> = entries.iter().map(|e| e.sandbox_id.as_str()).collect();
    assert_eq!(ids, vec![ID_1]);

    assert!(!run_dir.join(ID_2).exists());
    assert!(run_dir.join(ID_1).exists());
}

#[test]
fn list_on_missing_run_dir_is_empty() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let entries = list(tmp.path()).expect("list");
    assert!(entries.is_empty());
}

#[test]
fn get_returns_single_entry_or_none() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let runtime_dir = tmp.path();
    write_marker(&runtime_dir.join("run"), ID_1, std::process::id());

    let id = ID_1.parse().expect("valid UUID v7 fixture");
    let found = get(runtime_dir, &id).expect("get");
    assert!(found.is_some());
    assert_eq!(found.expect("some").sandbox_id, ID_1);

    let missing = ID_3.parse().expect("valid UUID v7 fixture");
    assert!(get(runtime_dir, &missing).expect("get").is_none());
}

#[test]
fn marker_metadata_id_must_match_directory_name() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let run_dir = tmp.path().join("run");
    write_marker(&run_dir, ID_1, std::process::id());
    fs::rename(run_dir.join(ID_1), run_dir.join(ID_2)).expect("rename marker directory");

    let error = probe_entry(&run_dir.join(ID_2)).expect_err("mismatched marker must fail");
    assert!(matches!(
        error,
        firma_runtime_state::RuntimeStateError::MarkerIdentityMismatch { .. }
    ));
}

#[test]
fn gc_stale_returns_removed_ids() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let runtime_dir = tmp.path();
    write_marker(&runtime_dir.join("run"), ID_1, reaped_dead_pid());
    write_marker(&runtime_dir.join("run"), ID_2, std::process::id());

    let removed = gc_stale(runtime_dir).expect("gc");
    assert_eq!(removed, vec![ID_1.to_string()]);
}

/// A corrupt marker (unparseable `metadata.toml`) must be skipped by `list`
/// (not errored) and must NOT be GC'd (we never delete what we cannot read).
#[test]
fn corrupt_marker_is_not_gcd_and_skipped_by_list() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let runtime_dir = tmp.path();
    let run_dir = runtime_dir.join("run");

    // Write a corrupt marker: invalid TOML, so it can never parse.
    let bad_dir = run_dir.join("bad");
    fs::create_dir_all(&bad_dir).expect("mkdir bad");
    fs::write(bad_dir.join("metadata.toml"), "not valid toml = =").expect("write bad metadata");

    // Write a healthy live marker alongside it.
    let me = std::process::id();
    write_marker(&run_dir, ID_1, me);

    // list() must succeed and return only the good entry.
    let entries = list(runtime_dir).expect("list should succeed despite corrupt marker");
    let ids: Vec<&str> = entries.iter().map(|e| e.sandbox_id.as_str()).collect();
    assert_eq!(ids, vec![ID_1], "corrupt marker must be silently skipped");

    // The corrupt marker directory must still exist (not GC'd).
    assert!(
        run_dir.join("bad").exists(),
        "corrupt marker dir must not be deleted"
    );
}

/// `gc_stale` must leave an unparseable marker intact and not report it as removed.
#[test]
fn gc_stale_keeps_unparseable_marker() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let runtime_dir = tmp.path();
    let run_dir = runtime_dir.join("run");

    // Write a marker with invalid TOML.
    let bad_dir = run_dir.join("bad");
    fs::create_dir_all(&bad_dir).expect("mkdir bad");
    fs::write(bad_dir.join("metadata.toml"), "not valid toml = =").expect("write bad metadata");

    let removed = gc_stale(runtime_dir).expect("gc_stale should succeed");
    assert!(
        removed.is_empty(),
        "unparseable marker must not appear in removed list"
    );
    assert!(
        run_dir.join("bad").exists(),
        "unparseable marker dir must not be deleted"
    );
}

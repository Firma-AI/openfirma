//! Integration tests for the per-run sidecar marker reader.

use std::fs;
use std::path::Path;

use firma_stack::MetadataFile;

#[allow(
    clippy::expect_used,
    reason = "test helper: panics are acceptable test failures"
)]
fn write_marker(run_dir: &Path, sandbox_id: &str, pid: u32) {
    let dir = run_dir.join(sandbox_id);
    fs::create_dir_all(&dir).expect("mkdir marker dir");
    let toml = format!(
        "sandbox_id = \"{sandbox_id}\"\n\
         agent_id = \"codex\"\n\
         session_id = \"sess-1\"\n\
         authority_url = \"https://authority.local\"\n\
         policy_bundle_version = \"deadbeef\"\n\
         pid = {pid}\n\
         started_at = \"2026-05-18T10:00:00Z\"\n"
    );
    fs::write(dir.join("metadata.toml"), toml).expect("write metadata.toml");
}

#[test]
fn metadata_file_parses_all_fields() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let run_dir = tmp.path().join("run");
    write_marker(&run_dir, "abc123def", 4242);

    let text = fs::read_to_string(run_dir.join("abc123def/metadata.toml")).expect("read");
    let meta: MetadataFile = toml::from_str(&text).expect("parse metadata");

    assert_eq!(meta.sandbox_id, "abc123def");
    assert_eq!(meta.agent_id, "codex");
    assert_eq!(meta.session_id, "sess-1");
    assert_eq!(meta.authority_url, "https://authority.local");
    assert_eq!(meta.policy_bundle_version, "deadbeef");
    assert_eq!(meta.pid, 4242);
    assert_eq!(meta.started_at, "2026-05-18T10:00:00Z");
}

use firma_stack::sidecar_markers::probe_entry;
use firma_stack::status::State;

#[test]
fn live_pid_no_socket_is_unhealthy() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let run_dir = tmp.path().join("run");
    let me = std::process::id();
    write_marker(&run_dir, "live-no-sock", me);

    let entry = probe_entry(&run_dir.join("live-no-sock")).expect("probe");
    assert_eq!(entry.sandbox_id, "live-no-sock");
    assert_eq!(entry.pid, me);
    assert_eq!(entry.state, State::Unhealthy);
    assert_eq!(entry.listen, run_dir.join("live-no-sock/sidecar.sock"));
}

/// Spawn and immediately reap a child, returning its now-dead PID.
///
/// `is_alive` on this PID returns false (ESRCH) until the OS reuses the slot.
#[allow(
    clippy::expect_used,
    reason = "test helper: panics are acceptable test failures"
)]
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
    write_marker(&run_dir, "dead", reaped_dead_pid());

    let entry = probe_entry(&run_dir.join("dead")).expect("probe");
    assert_eq!(entry.state, State::Stopped);
}

#[test]
fn uptime_secs_is_some_when_pid_file_exists() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let run_dir = tmp.path().join("run");
    let me = std::process::id();
    write_marker(&run_dir, "uptime-check", me);

    // Write sidecar.pid so marker_uptime_secs finds a file to stat.
    let marker_dir = run_dir.join("uptime-check");
    fs::write(marker_dir.join("sidecar.pid"), me.to_string()).expect("write sidecar.pid");

    let entry = probe_entry(&marker_dir).expect("probe");
    assert!(
        entry.uptime_secs.is_some(),
        "uptime_secs should be Some when sidecar.pid is present"
    );
}

#[cfg(unix)]
#[test]
fn live_pid_with_listening_socket_is_running() {
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let run_dir = tmp.path().join("run");
    let me = std::process::id();
    write_marker(&run_dir, "running", me);
    let sock = run_dir.join("running/sidecar.sock");
    let _listener = UnixListener::bind(&sock).expect("bind uds");

    let entry = probe_entry(&run_dir.join("running")).expect("probe");
    assert_eq!(entry.state, State::Running);
}

use firma_stack::sidecar_markers::{gc_stale, get, list};

#[test]
fn list_skips_and_gcs_dead_markers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let runtime_dir = tmp.path();
    let run_dir = runtime_dir.join("run");
    let me = std::process::id();
    write_marker(&run_dir, "alive", me);
    write_marker(&run_dir, "dead", reaped_dead_pid());

    let entries = list(runtime_dir).expect("list");
    let ids: Vec<&str> = entries.iter().map(|e| e.sandbox_id.as_str()).collect();
    assert_eq!(ids, vec!["alive"]);

    assert!(!run_dir.join("dead").exists());
    assert!(run_dir.join("alive").exists());
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
    write_marker(&runtime_dir.join("run"), "only", std::process::id());

    let found = get(runtime_dir, "only").expect("get");
    assert!(found.is_some());
    assert_eq!(found.expect("some").sandbox_id, "only");

    assert!(get(runtime_dir, "missing").expect("get").is_none());
}

#[test]
fn gc_stale_returns_removed_ids() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let runtime_dir = tmp.path();
    write_marker(&runtime_dir.join("run"), "dead", reaped_dead_pid());
    write_marker(&runtime_dir.join("run"), "alive", std::process::id());

    let removed = gc_stale(runtime_dir).expect("gc");
    assert_eq!(removed, vec!["dead".to_string()]);
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
    write_marker(&run_dir, "good", me);

    // list() must succeed and return only the good entry.
    let entries = list(runtime_dir).expect("list should succeed despite corrupt marker");
    let ids: Vec<&str> = entries.iter().map(|e| e.sandbox_id.as_str()).collect();
    assert_eq!(ids, vec!["good"], "corrupt marker must be silently skipped");

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

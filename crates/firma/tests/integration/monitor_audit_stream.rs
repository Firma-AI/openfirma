//! `firma monitor --since 0s --json --tail` emits appended audit records
//! byte-for-byte (one `ExecutionEvent` JSON per line, unchanged).

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

const APPENDED_RECORD: &str = r#"{"event_id":"e1","session_id":"s","token_id":"t","agent_id":"demo-1","action":"github.issue.create","resource":"api.github.com/repos/x/y/issues","decision":1,"deny_reason":"","enforcement_latency_us":150,"context_hash":"","bundle_version":"","timestamp":1715177751000000000,"dispatch_status":201,"dispatch_latency_us":42000,"response_size":128,"signature":[]}"#;

#[test]
fn monitor_emits_appended_audit_line() {
    let tmp = tempfile::tempdir().expect("tmp");
    let state_dir = tmp.path();
    std::fs::write(state_dir.join("audit.jsonl"), "").expect("seed");

    let mut child = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["monitor", "--state-dir"])
        .arg(state_dir)
        .args(["--source", "audit", "--json", "--tail", "--since", "0s"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");

    std::thread::sleep(Duration::from_millis(300));
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(state_dir.join("audit.jsonl"))
        .expect("open");
    writeln!(file, "{APPENDED_RECORD}").expect("append");

    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let _ = reader.read_line(&mut line);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(
        line.trim_end(),
        APPENDED_RECORD,
        "byte-for-byte pass-through"
    );
}

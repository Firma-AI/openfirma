//! `firma monitor --since 0s --format json` emits appended audit records.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn monitor_emits_appended_audit_line() {
    let tmp = tempfile::tempdir().expect("tmp");
    let state_dir = tmp.path();
    std::fs::write(state_dir.join("audit.jsonl"), "").expect("seed");

    let mut child = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["monitor", "--state-dir"])
        .arg(state_dir)
        .args(["--source", "audit", "--format", "json", "--since", "0s"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");

    std::thread::sleep(Duration::from_millis(300));
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(state_dir.join("audit.jsonl"))
        .expect("open");
    writeln!(
        file,
        r#"{{"decision":"allow","intent":{{"action_class":"x.y"}}}}"#
    )
    .expect("append");

    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let _ = reader.read_line(&mut line);
    let _ = child.kill();
    let _ = child.wait();
    assert!(line.contains("\"source\":\"audit\""), "got: {line}");
}

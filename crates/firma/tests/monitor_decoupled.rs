//! Monitor runs against an empty state directory without crashing.

use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn monitor_tolerates_missing_files() {
    let tmp = tempfile::tempdir().expect("tmp");
    let mut child = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["monitor", "--source", "audit", "--tail", "--state-dir"])
        .arg(tmp.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");

    std::thread::sleep(Duration::from_millis(500));
    assert!(
        child.try_wait().expect("wait").is_none(),
        "monitor exited early"
    );
    let _ = child.kill();
    let _ = child.wait();
}

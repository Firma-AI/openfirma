use std::process::Command;
use std::time::{Duration, Instant};

use crate::harness::run_bounded;

#[test]
fn timeout_kills_descendants_after_parent_exits_during_grace_period() {
    let directory = tempfile::tempdir().expect("create timeout test directory");
    let marker = directory.path().join("descendant-survived");
    let mut command = Command::new("sh");
    command
        .args([
            "-c",
            r#"
trap 'exit 0' TERM
(trap '' TERM; sleep 3; touch "$1") &
while :; do sleep 1; done
"#,
            "sh",
        ])
        .arg(&marker);

    let descendant_deadline = Instant::now() + Duration::from_millis(3_100);
    let output = run_bounded(&mut command, Duration::from_millis(100));
    assert!(!output.success(), "timed-out command succeeded:\n{output}");
    std::thread::sleep(descendant_deadline.saturating_duration_since(Instant::now()));
    assert!(
        !marker.exists(),
        "TERM-ignoring descendant survived process-group cleanup"
    );
}

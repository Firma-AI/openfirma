//! Pidfile helper behavior.

use firma_runtime_state::{NonZeroProcessId, pidfile};
use tempfile::tempdir;

#[test]
fn write_then_read_pid() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("child.pid");
    pidfile::write(&path, NonZeroProcessId::new(4242).expect("non-zero pid"))
        .expect("write");
    let got = pidfile::read(&path).expect("read");
    assert_eq!(got.map(NonZeroProcessId::get), Some(4242));
}

#[test]
fn missing_pidfile_is_none() {
    let dir = tempdir().expect("dir");
    let got = pidfile::read(&dir.path().join("absent")).expect("read");
    assert_eq!(got, None);
}

#[test]
fn malformed_pidfile_is_none() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("bad.pid");
    std::fs::write(&path, "not-a-pid\n").expect("write bad");
    let got = pidfile::read(&path).expect("read");
    assert_eq!(got, None);
}

#[test]
fn zero_pidfile_is_none() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("zero.pid");
    std::fs::write(&path, "0\n").expect("write zero");
    let got = pidfile::read(&path).expect("read");
    assert_eq!(got, None);
}

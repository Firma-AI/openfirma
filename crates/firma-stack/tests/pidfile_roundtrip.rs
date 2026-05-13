//! Pidfile behavior.

use firma_stack::pidfile;
use tempfile::tempdir;

#[test]
fn roundtrip() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("x.pid");
    pidfile::write(&path, 4242).expect("write");
    let got = pidfile::read(&path).expect("read");
    assert_eq!(got, Some(4242));
}

#[test]
fn missing_returns_none() {
    let dir = tempdir().expect("dir");
    let got = pidfile::read(&dir.path().join("absent")).expect("read");
    assert_eq!(got, None);
}

#[test]
fn malformed_returns_none() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("bad.pid");
    std::fs::write(&path, "not a number").expect("write");
    let got = pidfile::read(&path).expect("read");
    assert_eq!(got, None);
}

//! Pidfile helper behavior.

use firma_runtime_state::{UserProcessId, pidfile};
use tempfile::tempdir;

#[test]
fn write_then_read_pid() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("child.pid");
    pidfile::write(&path, UserProcessId::new(4242).expect("non-zero pid")).expect("write");
    let got = pidfile::read(&path).expect("read");
    assert_eq!(got.map(UserProcessId::get), Some(4242));
}

#[test]
fn write_atomically_replaces_existing_pid() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("child.pid");
    pidfile::write(&path, UserProcessId::new(4242).expect("first pid")).expect("first write");
    pidfile::write(&path, UserProcessId::new(4343).expect("replacement pid"))
        .expect("replacement write");

    let got = pidfile::read(&path).expect("read");
    assert_eq!(got.map(UserProcessId::get), Some(4343));
}

#[test]
fn write_propagates_parent_creation_failure() {
    let dir = tempdir().expect("dir");
    let blocker = dir.path().join("not-a-directory");
    std::fs::write(&blocker, "block parent creation").expect("write blocker");

    let error = pidfile::write(
        &blocker.join("child.pid"),
        UserProcessId::new(4242).expect("pid"),
    )
    .expect_err("file ancestor must prevent parent creation");
    assert!(matches!(
        error,
        firma_runtime_state::RuntimeStateError::Io(_)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn write_propagates_tempfile_creation_failure() {
    let error = pidfile::write(
        std::path::Path::new("/proc/self/child.pid"),
        UserProcessId::new(4242).expect("pid"),
    )
    .expect_err("procfs must reject temporary pidfile creation");
    assert!(matches!(
        error,
        firma_runtime_state::RuntimeStateError::Io(_)
    ));
}

#[test]
fn write_propagates_atomic_persist_failure() {
    let dir = tempdir().expect("dir");
    let destination = dir.path().join("child.pid");
    std::fs::create_dir(&destination).expect("create destination directory");

    let error = pidfile::write(&destination, UserProcessId::new(4242).expect("pid"))
        .expect_err("pidfile must not replace a directory");
    assert!(matches!(
        error,
        firma_runtime_state::RuntimeStateError::Io(_)
    ));
}

#[test]
fn missing_pidfile_is_none() {
    let dir = tempdir().expect("dir");
    let got = pidfile::read(&dir.path().join("absent")).expect("read");
    assert_eq!(got, None);
}

#[test]
fn read_propagates_filesystem_failure() {
    let dir = tempdir().expect("dir");
    let error = pidfile::read(dir.path()).expect_err("a directory is not a pidfile");
    assert!(matches!(
        error,
        firma_runtime_state::RuntimeStateError::Io(_)
    ));
}

#[test]
fn malformed_pidfile_is_rejected() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("bad.pid");
    std::fs::write(&path, "not-a-pid\n").expect("write bad");
    let error = pidfile::read(&path).expect_err("malformed pidfile must fail");
    let firma_runtime_state::RuntimeStateError::PidfileParse {
        path: error_path,
        value,
    } = &error
    else {
        panic!("expected pidfile parse error, got {error:?}");
    };
    assert_eq!(error_path, &path);
    assert_eq!(value, "not-a-pid");
    insta::assert_snapshot!(error.to_string().replace(&*path.to_string_lossy(), "[PIDFILE]"), @"invalid pidfile '[PIDFILE]': expected a non-zero process ID, got 'not-a-pid'");
}

#[test]
fn zero_pidfile_is_rejected() {
    let dir = tempdir().expect("dir");
    let path = dir.path().join("zero.pid");
    std::fs::write(&path, "0\n").expect("write zero");
    let error = pidfile::read(&path).expect_err("zero pidfile must fail");
    assert!(matches!(
        error,
        firma_runtime_state::RuntimeStateError::PidfileParse { ref value, .. } if value == "0"
    ));
}

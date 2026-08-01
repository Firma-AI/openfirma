use firma_runtime_state::UserProcessId;

#[test]
fn current_process_exists() {
    let pid = UserProcessId::new(std::process::id()).expect("current PID");

    assert!(pid.process_exists().expect("probe current process"));
}

#[cfg(unix)]
#[test]
#[expect(
    clippy::zombie_processes,
    reason = "the test explicitly verifies and then collects a zombie child"
)]
fn reaping_is_explicit_and_process_probe_is_non_destructive() {
    use std::io::Read as _;
    use std::process::{Command, Stdio};

    let mut child = Command::new("sh")
        .args(["-c", "exit 0"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn child");
    let pid = UserProcessId::new(child.id()).expect("child PID");
    let mut stdout = child.stdout.take().expect("child stdout");
    stdout.read_to_end(&mut Vec::new()).expect("wait for EOF");

    assert!(
        pid.process_exists().expect("probe zombie"),
        "zombie should exist before reaping"
    );
    child.wait().expect("collect exited child");
    assert!(
        !pid.process_exists().expect("probe reaped child"),
        "reaped child should not exist"
    );
}

#[test]
fn rejects_zero() {
    assert_eq!(UserProcessId::new(0), None);
    insta::assert_snapshot!(UserProcessId::try_from(0).unwrap_err().to_string(), @"process id must be non-zero and fit the platform process id type");
}

#[cfg(unix)]
#[test]
fn rejects_pid_outside_unix_pid_t_range() {
    let too_large = u32::try_from(nix::libc::pid_t::MAX).expect("pid_t max fits u32") + 1;

    assert_eq!(UserProcessId::new(too_large), None);
    insta::assert_snapshot!(UserProcessId::try_from(too_large).unwrap_err().to_string(), @"process id must be non-zero and fit the platform process id type");
}

#[test]
fn conversions_match() {
    let pid = UserProcessId::try_from(42).expect("non-zero pid");

    assert_eq!(pid.get(), u32::from(pid));
}

#[test]
fn serializes_as_integer() {
    let pid = UserProcessId::try_from(42).expect("non-zero pid");
    let value = toml::Value::try_from(pid).expect("serialize pid");

    assert_eq!(value.as_integer(), Some(42));
}

#[test]
fn deserializes_from_integer() {
    let value = toml::Value::Integer(42);
    let pid: UserProcessId = value.try_into().expect("deserialize pid");

    assert_eq!(pid.get(), 42);
}

#[test]
fn deserialize_rejects_zero() {
    let value = toml::Value::Integer(0);
    let error = value.try_into::<UserProcessId>().expect_err("zero pid");

    insta::assert_snapshot!(error.to_string(), @"process id must be non-zero and fit the platform process id type");
}

#[cfg(unix)]
#[test]
fn deserialize_rejects_pid_outside_unix_pid_t_range() {
    let too_large = i64::from(nix::libc::pid_t::MAX) + 1;
    let value = toml::Value::Integer(too_large);
    let error = value
        .try_into::<UserProcessId>()
        .expect_err("out-of-range pid");

    insta::assert_snapshot!(error.to_string(), @"process id must be non-zero and fit the platform process id type");
}

use firma_runtime_state::UserProcessId;

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

    assert_eq!(pid.get(), pid.into());
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

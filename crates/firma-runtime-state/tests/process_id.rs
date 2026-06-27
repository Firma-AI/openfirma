use firma_runtime_state::UserProcessId;

#[test]
fn rejects_zero() {
    assert_eq!(UserProcessId::new(0), None);
    insta::assert_snapshot!(UserProcessId::try_from(0).unwrap_err().to_string(), @"process id must be non-zero");
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

    insta::assert_snapshot!(error.to_string(), @"invalid value: integer `0`, expected a nonzero u32");
}

//! Embedded profile registry: only `developer` ships today.

use firma_authority::profiles::{UnknownProfileError, cedar_for};

#[test]
fn developer_profile_returned_by_name() {
    let text = cedar_for("developer").expect("developer must be registered");
    assert!(text.contains("NOT INTENDED FOR PRODUCTION"));
    assert!(text.contains("forbid"));
    assert!(text.contains("// permit("));
    assert!(text.contains("firma monitor --only-deny"));
}

#[test]
fn unknown_profile_returns_typed_error() {
    let err = cedar_for("strict").expect_err("strict not yet shipped");
    let UnknownProfileError { name } = err;
    assert_eq!(name, "strict");
}

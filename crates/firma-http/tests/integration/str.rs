use std::borrow::Cow;

use firma_http::Str;

#[test]
fn does_not_allocate() {
    let s = r#""test""#;
    let res = serde_json::from_str::<Str>(s).expect("deserialize");
    std::assert_matches!(res, Str(Cow::Borrowed(_)));
}

#[test]
fn does_allocate() {
    let s = r#""\"""#;
    let res = serde_json::from_str::<Str>(s).expect("deserialize");
    std::assert_matches!(res, Str(Cow::Owned(_)));
}
